//! `secsec-sig` — device identity and SSHSIG signatures (`finaldesign.md` §5, §9.6).
//!
//! A device is an **Ed25519** SSH keypair. Its `device_id` is `BLAKE3` over the canonical SSH
//! public-key encoding, so the id is cryptographically bound to the key (§5). All signatures are
//! OpenSSH "sshsig" with a **distinct namespace** per purpose (§9.6); the namespace is carried in
//! the signature and checked on verify, so a signature for one purpose is invalid for any other.
//!
//! v1 is **Ed25519-only**: this crate enables only `ssh-key`'s `ed25519` feature, so non-Ed25519
//! keys do not parse, and [`DevicePublic::verify`] additionally rejects any non-Ed25519 key or
//! signature algorithm (the §9.6 downgrade guard).

#![forbid(unsafe_code)]

use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
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
/// Grant-attestation namespace.
pub const NS_GRANT: &str = "secsec-grant-v1";

/// A 256-bit device identifier, `BLAKE3(canonical(pubkey))`.
pub type DeviceId = [u8; 32];

/// SSHSIG message hash. Ed25519 sshsig uses SHA-512 (matches `ssh-keygen -Y`).
const SIG_HASH: HashAlg = HashAlg::Sha512;

/// Errors from signing / verification / key handling.
#[derive(Debug)]
pub enum SigError {
    /// Underlying `ssh-key` error.
    Ssh(ssh_key::Error),
    /// The key or signature is not Ed25519 (v1 is Ed25519-only; §9.6 downgrade guard).
    NotEd25519,
    /// Signature verification failed (bad signature, wrong key, or wrong namespace).
    VerifyFailed,
    /// Ed25519 → X25519 key conversion failed (malformed key point).
    KeyConversion,
}

impl core::fmt::Display for SigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SigError::Ssh(e) => write!(f, "ssh-key: {e}"),
            SigError::NotEd25519 => f.write_str("key/signature is not Ed25519"),
            SigError::VerifyFailed => f.write_str("signature verification failed"),
            SigError::KeyConversion => f.write_str("Ed25519 to X25519 conversion failed"),
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

    /// Load a device key from an OpenSSH-format private key (PEM). Rejects non-Ed25519 keys.
    pub fn from_openssh(pem: &str) -> Result<Self, SigError> {
        let key = PrivateKey::from_openssh(pem)?;
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

    /// This device's X25519 secret scalar (the Ed25519→X25519 / `age` map): the **raw clamped**
    /// `SHA-512(seed)[..32]` used for keyslot ECDH (§8.3). Also the `device_ed25519_scalar_clamped`
    /// of §8.5. Zeroized on drop.
    ///
    /// Note: this is the raw clamped value, *not* `SigningKey::to_scalar()` — the latter reduces
    /// mod the group order, which X25519 clamping would then corrupt.
    pub fn x25519_secret(&self) -> Result<Zeroizing<[u8; 32]>, SigError> {
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

    /// This device's X25519 public key (Montgomery-u of the Ed25519 public point).
    pub fn x25519_public(&self) -> Result<[u8; 32], SigError> {
        self.public().x25519_public()
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

    /// This key's device id.
    pub fn device_id(&self) -> Result<DeviceId, SigError> {
        device_id_of(&self.key)
    }

    fn ed25519_public_bytes(&self) -> Result<[u8; 32], SigError> {
        match self.key.key_data() {
            KeyData::Ed25519(pk) => Ok(pk.0),
            _ => Err(SigError::NotEd25519),
        }
    }

    /// This key's X25519 public key (Montgomery-u of the Ed25519 public point), for keyslot ECDH.
    pub fn x25519_public(&self) -> Result<[u8; 32], SigError> {
        let ed = self.ed25519_public_bytes()?;
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(&ed).map_err(|_| SigError::KeyConversion)?;
        Ok(vk.to_montgomery().to_bytes())
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
    fn x25519_conversion_consistent_and_dh_agrees() {
        use x25519_dalek::{PublicKey as XPub, StaticSecret};
        let a = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let a_sec = StaticSecret::from(*a.x25519_secret().unwrap());
        let b_sec = StaticSecret::from(*b.x25519_secret().unwrap());
        let a_pub = a.x25519_public().unwrap();
        let b_pub = b.x25519_public().unwrap();
        // The X25519 public derived from our converted secret must equal our converted public —
        // this is the correctness condition the age/ssh-to-age conversion relies on.
        assert_eq!(XPub::from(&a_sec).as_bytes(), &a_pub);
        assert_eq!(XPub::from(&b_sec).as_bytes(), &b_pub);
        // ECDH agrees in both directions.
        let ab = a_sec.diffie_hellman(&XPub::from(b_pub));
        let ba = b_sec.diffie_hellman(&XPub::from(a_pub));
        assert_eq!(ab.as_bytes(), ba.as_bytes());
    }

    #[test]
    fn openssh_public_round_trips_and_matches_id() {
        let k = DeviceKey::generate().unwrap();
        let pk = k.public();
        let opensshd = pk.key.to_openssh().unwrap();
        let reparsed = DevicePublic::from_openssh(&opensshd).unwrap();
        assert_eq!(reparsed.device_id().unwrap(), pk.device_id().unwrap());
    }
}
