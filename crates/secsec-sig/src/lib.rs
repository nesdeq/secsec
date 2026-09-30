//! Device identity and Ed25519-only SSHSIG signatures with disjoint namespaces (`secsec-Design.md` §5, §9.6).

#![forbid(unsafe_code)]

use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use zeroize::{Zeroize, Zeroizing};

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

/// Decoder bound on a stored SSHSIG PEM (an Ed25519 SSHSIG is a few hundred bytes).
pub const MAX_SIG_LEN: usize = 4096;

/// A 256-bit device identifier, `BLAKE3(canonical(pubkey))`.
pub type DeviceId = [u8; 32];

/// SSHSIG message hash; Ed25519 sshsig uses SHA-512, matching `ssh-keygen -Y`.
const SIG_HASH: HashAlg = HashAlg::Sha512;

const L_LOCAL_SEAL_V1: &str = "secsec-local-seal-v1";
const L_LOCAL_SEAL_V2: &str = "secsec-local-seal-v2";
const L_XWING_SEED: &str = "secsec-xwing-seed-v1";

/// Errors from signing / verification / key handling.
#[derive(Debug)]
pub enum SigError {
    /// Underlying `ssh-key` error.
    Ssh(ssh_key::Error),
    /// The key or signature is not Ed25519 (§9.6 downgrade guard).
    NotEd25519,
    /// Signature verification failed (bad signature, wrong key, or wrong namespace).
    VerifyFailed,
    /// The private key is passphrase-encrypted; use [`DeviceKey::from_openssh_passphrase`].
    Encrypted,
    /// Decrypting an encrypted private key failed: wrong passphrase.
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
    let canon = pk.to_bytes()?;
    Ok(*blake3::hash(&canon).as_bytes())
}

/// `BLAKE3::derive_key(label, material)` through a hasher that is wiped afterwards.
fn derive_secret(label: &'static str, material: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(label);
    h.update(material);
    let out = Zeroizing::new(*h.finalize().as_bytes());
    h.zeroize();
    out
}

/// A device's Ed25519 private key (signing + identity), RAM-only.
pub struct DeviceKey {
    key: PrivateKey,
}

impl DeviceKey {
    /// Generate a fresh Ed25519 device key from the OS CSPRNG.
    pub fn generate() -> Result<Self, SigError> {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)?;
        Ok(Self { key })
    }

    /// Load an unencrypted OpenSSH Ed25519 private key; an encrypted one is [`SigError::Encrypted`].
    pub fn from_openssh(pem: &str) -> Result<Self, SigError> {
        Self::finish(PrivateKey::from_openssh(pem)?)
    }

    /// Load an OpenSSH private key, decrypting it in memory with `passphrase` if encrypted.
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

    /// Reject a still-encrypted or non-Ed25519 key, then wrap it.
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

    /// The raw Ed25519 private seed, zeroized on drop.
    fn ed25519_seed(&self) -> Result<Zeroizing<[u8; 32]>, SigError> {
        match self.key.key_data() {
            KeypairData::Ed25519(kp) => Ok(Zeroizing::new(kp.private.to_bytes())),
            _ => Err(SigError::NotEd25519),
        }
    }

    /// The RFC 7748 clamped scalar `clamp(SHA-512(seed)[..32])`, the legacy §8.5 v1 seal-key material.
    pub(crate) fn x25519_secret(&self) -> Result<Zeroizing<[u8; 32]>, SigError> {
        use sha2::{Digest, Sha512};
        let seed = self.ed25519_seed()?;
        let mut h = Sha512::digest(seed.as_slice());
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&h[..32]);
        h.as_mut_slice().zeroize();
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        Ok(k)
    }

    /// The §8.5 local-seal key, `derive_key("secsec-local-seal-v2", ed25519_seed)`; never stored.
    pub fn local_seal_key(&self) -> Result<Zeroizing<[u8; 32]>, SigError> {
        let seed = self.ed25519_seed()?;
        Ok(derive_secret(L_LOCAL_SEAL_V2, seed.as_slice()))
    }

    /// The legacy v1 local-seal key from the clamped scalar, read-only for migrating an older frontier.
    pub fn local_seal_key_v1(&self) -> Result<Zeroizing<[u8; 32]>, SigError> {
        let scalar = self.x25519_secret()?;
        Ok(derive_secret(L_LOCAL_SEAL_V1, scalar.as_slice()))
    }

    /// The X-Wing seed `derive_key("secsec-xwing-seed-v1", ed25519_seed)`: from the seed, never the scalar (§8.3).
    pub fn xwing_seed(&self) -> Result<Zeroizing<[u8; 32]>, SigError> {
        let seed = self.ed25519_seed()?;
        Ok(derive_secret(L_XWING_SEED, seed.as_slice()))
    }

    /// SSHSIG-sign `msg` under `namespace`, returning the PEM signature bytes.
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
    /// Parse an OpenSSH public key line; non-Ed25519 keys are rejected.
    pub fn from_openssh(s: &str) -> Result<Self, SigError> {
        let key: PublicKey = s.parse()?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(SigError::NotEd25519);
        }
        Ok(Self { key })
    }

    /// The canonical SSH binary encoding (the bytes hashed for `device_id`).
    pub fn to_canonical(&self) -> Result<Vec<u8>, SigError> {
        Ok(self.key.to_bytes()?)
    }

    /// Parse a canonical SSH binary encoding; non-Ed25519 keys are rejected.
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

    /// The OpenSSH `SHA256:…` fingerprint, as `ssh-keygen -lf` prints it.
    pub fn ssh_fingerprint(&self) -> Result<String, SigError> {
        Ok(self.key.fingerprint(HashAlg::Sha256).to_string())
    }

    /// Verify an SSHSIG PEM over `msg` under `namespace`; key and signature must both be Ed25519 (§9.6).
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

    /// An ECDSA P-256 public key line (`ssh-keygen -t ecdsa`).
    const ECDSA_PUB: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMAnHXqj55Pi210x5jnzbYqV1zZiMDvor3vEKt6BSEnvT6I7d+eCJGdKphnm+qy8U5Xmv6vIxeplij1Y1oK+ODo= fixture";
    /// A genuine ECDSA SSHSIG over `b"secsec-negative-test"` in the roster namespace (`ssh-keygen -Y sign`).
    const ECDSA_SIG: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE
EEwCcdeqPnk+LbXTHmOfNtipXXNmIwO+ive8Qq3oFISe9Pojt354IkZ0qmGeb6rLxTlea/
q8jF6mWKPVjWgr44OgAAABBzZWNzZWMtcm9zdGVyLXYxAAAAAAAAAAZzaGE1MTIAAABlAA
AAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABKAAAAIQDONDZBkYBAWv2YiWCZCaKzvsaohfYq
jwtaOf6o3XL0/gAAACEAm1karib5Z/RLAGSfMV8WWFmH+40gEPTCdd+lY7gG6TY=
-----END SSH SIGNATURE-----
";

    #[test]
    fn device_id_is_stable_and_key_bound() {
        let k = DeviceKey::generate().unwrap();
        let id1 = k.device_id().unwrap();
        let id2 = k.public().device_id().unwrap();
        assert_eq!(id1, id2);
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
        assert!(sig.len() <= MAX_SIG_LEN);
    }

    /// §9.6 domain separation: a commit signature never verifies as a head signature.
    #[test]
    fn wrong_namespace_is_rejected() {
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

    /// §9.6 algorithm pin: a non-Ed25519 public key never parses as a device key.
    #[test]
    fn non_ed25519_public_key_is_rejected() {
        assert!(DevicePublic::from_openssh(ECDSA_PUB).is_err());
    }

    /// §9.6 algorithm pin: a genuine non-Ed25519 SSHSIG fails against an Ed25519 key, never verifies.
    #[test]
    fn non_ed25519_signature_is_rejected() {
        let pk = DeviceKey::generate().unwrap().public();
        let res = pk.verify(NS_ROSTER, b"secsec-negative-test", ECDSA_SIG.as_bytes());
        assert!(matches!(
            res,
            Err(SigError::NotEd25519 | SigError::Ssh(_) | SigError::VerifyFailed)
        ));
        assert!(res.is_err());
        // Garbage PEM and non-UTF-8 bytes are rejected, never a panic.
        assert!(pk.verify(NS_ROSTER, b"x", b"not a signature").is_err());
        assert!(pk.verify(NS_ROSTER, b"x", &[0xff, 0xfe]).is_err());
    }

    #[test]
    fn local_seal_keys_are_private_derived_and_per_device() {
        let a = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let ka = a.local_seal_key().unwrap();
        assert_eq!(*ka, *a.local_seal_key().unwrap());
        assert_ne!(*ka, *b.local_seal_key().unwrap());
        // v2 is seed-derived and differs from the legacy scalar-derived v1 and from the scalar itself.
        assert_ne!(*ka, *a.local_seal_key_v1().unwrap());
        assert_ne!(ka.as_slice(), a.x25519_secret().unwrap().as_slice());
    }

    #[test]
    fn xwing_seed_is_private_derived_per_device_and_distinct_from_seal_key() {
        let a = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let sa = a.xwing_seed().unwrap();
        assert_eq!(*sa, *a.xwing_seed().unwrap());
        assert_ne!(*sa, *b.xwing_seed().unwrap());
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

    /// An encrypted key loads only with the right passphrase; the plain loader refuses it up front.
    #[test]
    fn encrypted_key_loads_only_with_the_right_passphrase() {
        let k = DeviceKey::generate().unwrap();
        let id = k.device_id().unwrap();
        let encrypted_pem = k
            .key
            .encrypt(&mut rand_core::OsRng, b"correct horse")
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap();

        assert!(matches!(
            DeviceKey::from_openssh(&encrypted_pem),
            Err(SigError::Encrypted)
        ));
        assert!(matches!(
            DeviceKey::from_openssh_passphrase(&encrypted_pem, "wrong"),
            Err(SigError::BadPassphrase)
        ));
        let dk = DeviceKey::from_openssh_passphrase(&encrypted_pem, "correct horse").unwrap();
        assert_eq!(dk.device_id().unwrap(), id);
        let sig = dk.sign(NS_AUTH, b"connection-auth payload").unwrap();
        assert!(dk
            .public()
            .verify(NS_AUTH, b"connection-auth payload", &sig)
            .is_ok());
        assert!(dk.xwing_seed().is_ok());
    }

    /// An unencrypted key loads through the passphrase loader; the passphrase is ignored.
    #[test]
    fn passphrase_loader_is_a_noop_for_unencrypted_keys() {
        let k = DeviceKey::generate().unwrap();
        let pem = k.key.to_openssh(LineEnding::LF).unwrap();
        let dk = DeviceKey::from_openssh_passphrase(&pem, "ignored").unwrap();
        assert_eq!(dk.device_id().unwrap(), k.device_id().unwrap());
    }
}
