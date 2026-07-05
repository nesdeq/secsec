//! `secsec-sig` — device identity and SSHSIG signatures (`secsec-Design.md` §5, §9.6).
//!
//! A device is an Ed25519 SSH keypair; `device_id = BLAKE3(canonical pubkey)`. All signatures are
//! OpenSSH sshsig with a distinct namespace per purpose (§9.6). Ed25519-only: non-Ed25519 keys do
//! not parse, and [`DevicePublic::verify`] rejects any other key/signature algorithm (§9.6
//! downgrade guard).

#![forbid(unsafe_code)]

use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use zeroize::Zeroizing;

/// Connection-auth namespace (§9.6).
pub const NS_AUTH: &str = "secsec-auth-v1";
/// Write-authorization namespace.
pub const NS_WRITE: &str = "secsec-write-v1";
/// Read-authorization namespace.
pub const NS_READ: &str = "secsec-read-v1";
/// Commit-signing namespace.
pub const NS_COMMIT: &str = "secsec-commit-v1";
/// Head-update namespace.
pub const NS_HEAD: &str = "secsec-head-v1";
/// Roster sigchain-entry namespace.
pub const NS_ROSTER: &str = "secsec-roster-v1";

/// A 256-bit device identifier, `BLAKE3(canonical(pubkey))`.
pub type DeviceId = [u8; 32];

/// SSHSIG message hash. Ed25519 sshsig uses SHA-512 (matches `ssh-keygen -Y`).
const SIG_HASH: HashAlg = HashAlg::Sha512;

/// Errors from signing / verification / key handling.
#[derive(Debug)]
pub enum SigError {
    /// Underlying `ssh-key` error.
    Ssh(ssh_key::Error),
    /// The key or signature is not Ed25519 (Ed25519-only; §9.6 downgrade guard).
    NotEd25519,
    /// Signature verification failed (bad signature, wrong key, or wrong namespace).
    VerifyFailed,
    /// The private key is passphrase-encrypted; load it with [`DeviceKey::from_openssh_passphrase`].
    Encrypted,
    /// Decrypting an encrypted private key failed — wrong passphrase.
    BadPassphrase,
}

impl core::fmt::Display for SigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SigError::Ssh(e) => write!(f, "ssh-key: {e}"),
            SigError::NotEd25519 => f.write_str("key/signature is not Ed25519"),
            SigError::VerifyFailed => f.write_str("signature verification failed"),
            SigError::Encrypted => f.write_str("private key is passphrase-encrypted"),
            SigError::BadPassphrase => {
                f.write_str("could not decrypt private key (wrong passphrase)")
            }
        }
    }
}

impl std::error::Error for SigError {}
impl From<ssh_key::Error> for SigError {
    fn from(e: ssh_key::Error) -> Self {
        SigError::Ssh(e)
    }
}

/// `BLAKE3` over the canonical SSH binary encoding of a public key (§5).
fn device_id_of(pk: &PublicKey) -> Result<DeviceId, SigError> {
    let canon = pk.to_bytes()?; // SSH wire encoding (binds key type + key bytes)
    Ok(*blake3::hash(&canon).as_bytes())
}

/// A device's Ed25519 private key (signing + identity). Held in RAM only.
pub struct DeviceKey {
    key: PrivateKey,
}

impl DeviceKey {
    /// Generate a fresh Ed25519 device key from the OS CSPRNG.
    pub fn generate() -> Result<Self, SigError> {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)?;
        Ok(Self { key })
    }

    /// Load a device key from an **unencrypted** OpenSSH-format private key (PEM). Rejects
    /// non-Ed25519 keys, and rejects a passphrase-encrypted key with [`SigError::Encrypted`] —
    /// call [`Self::from_openssh_passphrase`] to supply the passphrase.
    pub fn from_openssh(pem: &str) -> Result<Self, SigError> {
        Self::finish(PrivateKey::from_openssh(pem)?)
    }

    /// Load an OpenSSH private key (PEM), decrypting in memory with `passphrase` if encrypted.
    /// secsec derives keys from the raw private key ([`Self::xwing_seed`], [`Self::local_seal_key`]),
    /// so an ssh-agent cannot stand in; the on-disk key is never modified.
    pub fn from_openssh_passphrase(pem: &str, passphrase: &str) -> Result<Self, SigError> {
        let key = PrivateKey::from_openssh(pem)?;
        let key = if key.is_encrypted() {
            key.decrypt(passphrase)
                .map_err(|_| SigError::BadPassphrase)?
        } else {
            key
        };
        Self::finish(key)
    }

    /// Validate a parsed private key: reject one that is still encrypted (no passphrase supplied) or
    /// not Ed25519, then wrap it.
    fn finish(key: PrivateKey) -> Result<Self, SigError> {
        if key.is_encrypted() {
            return Err(SigError::Encrypted);
        }
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(SigError::NotEd25519);
        }
        Ok(Self { key })
    }

    /// This device's public half.
    #[must_use]
    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            key: self.key.public_key().clone(),
        }
    }

    /// This device's id.
    pub fn device_id(&self) -> Result<DeviceId, SigError> {
        device_id_of(self.key.public_key())
    }

    /// The raw Ed25519 private seed. Zeroized on drop. Private to the crate.
    fn ed25519_seed(&self) -> Result<Zeroizing<[u8; 32]>, SigError> {
        match self.key.key_data() {
            KeypairData::Ed25519(kp) => Ok(Zeroizing::new(kp.private.to_bytes())),
            _ => Err(SigError::NotEd25519),
        }
    }

    /// The X25519 secret scalar (Ed25519→X25519 map, §8.3): raw clamped `SHA-512(seed)[..32]` —
    /// the §8.5 `device_ed25519_scalar_clamped`. NOT `SigningKey::to_scalar()` (that reduces mod
    /// the group order, which clamping would then corrupt). Zeroized on drop.
    pub(crate) fn x25519_secret(&self) -> Result<Zeroizing<[u8; 32]>, SigError> {
        use sha2::{Digest, Sha512};
        let seed = self.ed25519_seed()?;
        let h = Sha512::digest(seed.as_slice());
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&h[..32]);
        // RFC 7748 X25519 clamp.
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        Ok(k)
    }

    /// The §8.5 local-seal key, derived from the **private** clamped scalar (never the public key —
    /// §8.5 note). Re-derived at startup, never stored; seals the local frontier file (§9.8).
    pub fn local_seal_key(&self) -> Result<Zeroizing<[u8; 32]>, SigError> {
        let scalar = self.x25519_secret()?;
        Ok(Zeroizing::new(blake3::derive_key(
            "secsec-local-seal-v1",
            scalar.as_slice(),
        )))
    }

    /// The X-Wing decapsulation-key seed (§8.3/§17), re-derived at runtime (no extra stored
    /// material, §1). MUST derive from the raw Ed25519 **seed**, never the clamped scalar — the
    /// scalar is quantum-recoverable from the public key, which would void the PQ property (the
    /// full argument is §8.3). The X-Wing public is published in the roster so granters can wrap.
    pub fn xwing_seed(&self) -> Result<Zeroizing<[u8; 32]>, SigError> {
        let seed = self.ed25519_seed()?;
        Ok(Zeroizing::new(blake3::derive_key(
            "secsec-xwing-seed-v1",
            seed.as_slice(),
        )))
    }

    /// SSHSIG-sign `msg` under `namespace`, returning the PEM-encoded signature bytes.
    pub fn sign(&self, namespace: &str, msg: &[u8]) -> Result<Vec<u8>, SigError> {
        let sig = self.key.sign(namespace, SIG_HASH, msg)?;
        Ok(sig.to_pem(LineEnding::LF)?.into_bytes())
    }
}

/// A device's public key.
#[derive(Clone)]
pub struct DevicePublic {
    key: PublicKey,
}

impl DevicePublic {
    /// Parse an OpenSSH public key (`ssh-ed25519 AAAA… [comment]`). Rejects non-Ed25519.
    pub fn from_openssh(s: &str) -> Result<Self, SigError> {
        let key: PublicKey = s.parse()?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(SigError::NotEd25519);
        }
        Ok(Self { key })
    }

    /// The canonical SSH binary encoding of this key (the bytes hashed for `device_id`).
    pub fn to_canonical(&self) -> Result<Vec<u8>, SigError> {
        Ok(self.key.to_bytes()?)
    }

    /// Parse a key from its canonical SSH binary encoding (inverse of [`Self::to_canonical`]).
    /// Rejects non-Ed25519 keys. Used to reconstruct a device pubkey from a sigchain entry.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, SigError> {
        let key = PublicKey::from_bytes(bytes)?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(SigError::NotEd25519);
        }
        Ok(Self { key })
    }

    /// This key's device id.
    pub fn device_id(&self) -> Result<DeviceId, SigError> {
        device_id_of(&self.key)
    }

    /// The OpenSSH SHA-256 key fingerprint (`SHA256:…`, exactly what `ssh-keygen -lf key.pub` prints),
    /// for identifying a device to a human (e.g. in `secsec devices`).
    pub fn ssh_fingerprint(&self) -> Result<String, SigError> {
        Ok(self.key.fingerprint(HashAlg::Sha256).to_string())
    }

    /// Verify an SSHSIG (PEM bytes) over `msg` under `namespace`.
    ///
    /// Returns `Ok(())` only if the key **and** the signature are Ed25519 (the §9.6 algorithm
    /// pin), the namespace matches, and the signature is cryptographically valid over `msg`.
    pub fn verify(&self, namespace: &str, msg: &[u8], sig_pem: &[u8]) -> Result<(), SigError> {
        if self.key.algorithm() != Algorithm::Ed25519 {
            return Err(SigError::NotEd25519);
        }
        let pem = core::str::from_utf8(sig_pem).map_err(|_| SigError::VerifyFailed)?;
        let sig = SshSig::from_pem(pem)?;
        if sig.algorithm() != Algorithm::Ed25519 {
            return Err(SigError::NotEd25519);
        }
        self.key
            .verify(namespace, msg, &sig)
            .map_err(|_| SigError::VerifyFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_stable_and_key_bound() {
        let k = DeviceKey::generate().unwrap();
        let id1 = k.device_id().unwrap();
        let id2 = k.public().device_id().unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);

        let other = DeviceKey::generate().unwrap();
        assert_ne!(id1, other.device_id().unwrap());
    }

    #[test]
    fn sign_verify_round_trip() {
        let k = DeviceKey::generate().unwrap();
        let pk = k.public();
        let msg = b"canonical commit bytes";
        let sig = k.sign(NS_COMMIT, msg).unwrap();
        assert!(pk.verify(NS_COMMIT, msg, &sig).is_ok());
    }

    #[test]
    fn wrong_namespace_is_rejected() {
        // Domain separation (§9.6): a commit signature must not verify as a head signature.
        let k = DeviceKey::generate().unwrap();
        let pk = k.public();
        let msg = b"bytes";
        let sig = k.sign(NS_COMMIT, msg).unwrap();
        assert!(matches!(
            pk.verify(NS_HEAD, msg, &sig),
            Err(SigError::VerifyFailed)
        ));
    }

    #[test]
    fn tampered_message_and_wrong_key_rejected() {
        let k = DeviceKey::generate().unwrap();
        let pk = k.public();
        let sig = k.sign(NS_ROSTER, b"entry").unwrap();
        assert!(matches!(
            pk.verify(NS_ROSTER, b"entrz", &sig),
            Err(SigError::VerifyFailed)
        ));

        let other = DeviceKey::generate().unwrap().public();
        assert!(matches!(
            other.verify(NS_ROSTER, b"entry", &sig),
            Err(SigError::VerifyFailed)
        ));
    }

    #[test]
    fn local_seal_key_is_private_derived_and_per_device() {
        let a = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let ka = a.local_seal_key().unwrap();
        // deterministic for a given device.
        assert_eq!(*ka, *a.local_seal_key().unwrap());
        // distinct per device.
        assert_ne!(*ka, *b.local_seal_key().unwrap());
        // §8.5: derived from the PRIVATE scalar via derive_key, so it differs from that scalar.
        assert_ne!(ka.as_slice(), a.x25519_secret().unwrap().as_slice());
    }

    #[test]
    fn xwing_seed_is_private_derived_per_device_and_distinct_from_seal_key() {
        let a = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let sa = a.xwing_seed().unwrap();
        // deterministic for a given device (re-derived at runtime, never stored).
        assert_eq!(*sa, *a.xwing_seed().unwrap());
        // distinct per device.
        assert_ne!(*sa, *b.xwing_seed().unwrap());
        // §8.3: from the PRIVATE scalar, and domain-separated from the local-seal key and the scalar.
        assert_ne!(sa.as_slice(), a.x25519_secret().unwrap().as_slice());
        assert_ne!(sa.as_slice(), a.local_seal_key().unwrap().as_slice());
    }

    #[test]
    fn canonical_public_round_trips() {
        let k = DeviceKey::generate().unwrap();
        let pk = k.public();
        let canon = pk.to_canonical().unwrap();
        let reparsed = DevicePublic::from_canonical(&canon).unwrap();
        assert_eq!(reparsed.device_id().unwrap(), pk.device_id().unwrap());
        assert_eq!(reparsed.to_canonical().unwrap(), canon);
    }

    #[test]
    fn openssh_public_round_trips_and_matches_id() {
        let k = DeviceKey::generate().unwrap();
        let pk = k.public();
        let opensshd = pk.key.to_openssh().unwrap();
        let reparsed = DevicePublic::from_openssh(&opensshd).unwrap();
        assert_eq!(reparsed.device_id().unwrap(), pk.device_id().unwrap());
    }

    /// A passphrase-encrypted `id_ed25519`: `from_openssh` refuses it with a clear `Encrypted` (not a
    /// later confusing sign failure), `from_openssh_passphrase` decrypts it in memory and yields a
    /// fully usable key (same id, and it can sign), and a wrong passphrase is `BadPassphrase`.
    #[test]
    fn encrypted_key_loads_only_with_the_right_passphrase() {
        let k = DeviceKey::generate().unwrap();
        let id = k.device_id().unwrap();
        // Encrypt the same key under a passphrase and serialize it as an OpenSSH PEM.
        let encrypted_pem = k
            .key
            .encrypt(&mut rand_core::OsRng, b"correct horse")
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap();

        // The plain loader refuses an encrypted key up front rather than failing later at sign time.
        assert!(matches!(
            DeviceKey::from_openssh(&encrypted_pem),
            Err(SigError::Encrypted)
        ));
        // Wrong passphrase → BadPassphrase.
        assert!(matches!(
            DeviceKey::from_openssh_passphrase(&encrypted_pem, "wrong"),
            Err(SigError::BadPassphrase)
        ));
        // Right passphrase → the genuine key: same id, and the genuine key signs.
        let dk = DeviceKey::from_openssh_passphrase(&encrypted_pem, "correct horse").unwrap();
        assert_eq!(dk.device_id().unwrap(), id);
        let sig = dk.sign(NS_AUTH, b"connection-auth payload").unwrap();
        assert!(dk
            .public()
            .verify(NS_AUTH, b"connection-auth payload", &sig)
            .is_ok());
        // The keyslot-decap seed is derivable too (the agent-can't-do-this material).
        assert!(dk.xwing_seed().is_ok());
    }

    /// An unencrypted key still loads through `from_openssh_passphrase` (the passphrase is ignored).
    #[test]
    fn passphrase_loader_is_a_noop_for_unencrypted_keys() {
        let k = DeviceKey::generate().unwrap();
        let pem = k.key.to_openssh(LineEnding::LF).unwrap();
        let dk = DeviceKey::from_openssh_passphrase(&pem, "ignored").unwrap();
        assert_eq!(dk.device_id().unwrap(), k.device_id().unwrap());
    }
}
