//! Hybrid post-quantum keyslot — **X-Wing** (`finaldesign.md` §17).
//!
//! Wraps `master_key_g` to a device under the X-Wing KEM (ML-KEM-768 ⊕ X25519), so the harvestable
//! asymmetric keyslot wrap is PQ-secure (the symmetric data plane is already PQ-safe). The combiner is
//! **label-first** per ePrint 2024/039 §3 / draft-connolly-cfrg-xwing-kem-10 §4.1:
//!
//! ```text
//! ss = SHA3-256( XWingLabel(6) ‖ ss_MLKEM(32) ‖ ss_X25519(32) ‖ ct_X(32) ‖ pk_X(32) )
//! keyslot_ct = ct_MLKEM(1088) ‖ ct_X(32)                                    // 1120 bytes
//! ```
//!
//! ML-KEM-768 keys are stored in **`(d, z)` seed form** (a 64-byte seed; the expanded keypair is
//! derived at runtime via [`libcrux_ml_kem`], FIPS 203 §7.1) — required to avoid MAL-BIND-K-CT /
//! MAL-BIND-K-PK failures (Schmieg, ePrint 2024/523). The X-Wing shared secret then keys the §9.4 CTX
//! committing AEAD to wrap the master key; authenticity rests on the §7 `mk_commit` check, not the wrap.
//!
//! ## ⚠ Conformance gate (§17, normative)
//!
//! This is the **construction**; it is **NOT yet conformance-verified**. §17 MANDATES verifying
//! byte-identical shared secrets against the ePrint 2024/039 §A test vectors before any implementation
//! is accepted as conformant, and the spec pins draft-10 (label-first) — both must be confirmed before
//! this keyslot is enabled (via a `SetMinAlgo` bump). [`xwing_kat`] is the placeholder for that vector;
//! it is `#[ignore]`d until the published vectors are wired in. The internal round-trip / `mk_commit` /
//! tamper tests below prove the construction is self-consistent, not that it matches the standard.

#![forbid(unsafe_code)]

use libcrux_ml_kem::mlkem768;
use secsec_canon::Writer;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as XPub, StaticSecret};
use zeroize::Zeroizing;

/// X-Wing 6-byte domain label `XWingLabel` (ePrint 2024/039 §3): `\\.//^\\` — placed **first** in the
/// combiner input.
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// ML-KEM-768 ciphertext length (§17).
pub const ML_KEM_CT_LEN: usize = 1088;
/// ML-KEM-768 public-key length.
pub const ML_KEM_PK_LEN: usize = 1184;
/// ML-KEM-768 keygen seed (`d ‖ z`) length (FIPS 203 §7.1).
pub const ML_KEM_SEED_LEN: usize = 64;
/// X25519 key length.
pub const X_LEN: usize = 32;
/// X-Wing keyslot ciphertext length: `ct_MLKEM ‖ ct_X`.
pub const XWING_CT_LEN: usize = ML_KEM_CT_LEN + X_LEN;

/// Errors from the X-Wing keyslot.
#[derive(Debug, PartialEq, Eq)]
pub enum PqError {
    /// The keyslot blob / ciphertext / public key was the wrong length.
    Malformed,
    /// The CTX AEAD failed to open (wrong recipient key or tampered blob).
    Aead,
    /// The recovered key did not match `mk_commit_g` (§7/§8.3).
    CommitMismatch,
    /// OS RNG failure.
    Rng,
}

impl core::fmt::Display for PqError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PqError::Malformed => f.write_str("malformed X-Wing keyslot"),
            PqError::Aead => f.write_str("X-Wing keyslot AEAD open failed"),
            PqError::CommitMismatch => f.write_str("recovered key fails mk_commit (§8.3)"),
            PqError::Rng => f.write_str("OS RNG failure"),
        }
    }
}
impl std::error::Error for PqError {}

/// A device's X-Wing **secret** key: the ML-KEM-768 `(d,z)` seed plus the X25519 static secret. Stored
/// in seed form (§17); the expanded ML-KEM keypair is derived on demand. Zeroized on drop.
pub struct XWingSecret {
    mlkem_seed: Zeroizing<[u8; ML_KEM_SEED_LEN]>,
    x25519: StaticSecret,
}

/// A device's X-Wing **public** key: the ML-KEM-768 encapsulation key + the X25519 public key.
#[derive(Clone)]
pub struct XWingPublic {
    mlkem_pk: [u8; ML_KEM_PK_LEN],
    x25519_pk: [u8; X_LEN],
}

impl XWingSecret {
    /// Generate a fresh X-Wing keypair (OS CSPRNG). Returns `(secret, public)`.
    pub fn generate() -> Result<(Self, XWingPublic), PqError> {
        let mut seed = Zeroizing::new([0u8; ML_KEM_SEED_LEN]);
        getrandom::fill(seed.as_mut_slice()).map_err(|_| PqError::Rng)?;
        let mut xsk = [0u8; X_LEN];
        getrandom::fill(&mut xsk).map_err(|_| PqError::Rng)?;
        let x25519 = StaticSecret::from(xsk);

        let kp = mlkem768::generate_key_pair(*seed);
        let public = XWingPublic {
            mlkem_pk: *kp.pk(),
            x25519_pk: XPub::from(&x25519).to_bytes(),
        };
        Ok((
            Self {
                mlkem_seed: seed,
                x25519,
            },
            public,
        ))
    }

    /// This secret's public key.
    #[must_use]
    pub fn public(&self) -> XWingPublic {
        let kp = mlkem768::generate_key_pair(*self.mlkem_seed);
        XWingPublic {
            mlkem_pk: *kp.pk(),
            x25519_pk: XPub::from(&self.x25519).to_bytes(),
        }
    }
}

impl XWingPublic {
    /// Serialize as `mlkem_pk(1184) ‖ x25519_pk(32)` (the form published for a device).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(ML_KEM_PK_LEN + X_LEN);
        v.extend_from_slice(&self.mlkem_pk);
        v.extend_from_slice(&self.x25519_pk);
        v
    }

    /// Parse from [`Self::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, PqError> {
        if b.len() != ML_KEM_PK_LEN + X_LEN {
            return Err(PqError::Malformed);
        }
        let mut mlkem_pk = [0u8; ML_KEM_PK_LEN];
        mlkem_pk.copy_from_slice(&b[..ML_KEM_PK_LEN]);
        let mut x25519_pk = [0u8; X_LEN];
        x25519_pk.copy_from_slice(&b[ML_KEM_PK_LEN..]);
        Ok(Self {
            mlkem_pk,
            x25519_pk,
        })
    }
}

/// The X-Wing combiner (§17): `ss = SHA3-256(label ‖ ss_MLKEM ‖ ss_X25519 ‖ ct_X ‖ pk_X)`.
fn combine(
    ss_mlkem: &[u8; 32],
    ss_x25519: &[u8; 32],
    ct_x: &[u8; X_LEN],
    pk_x: &[u8; X_LEN],
) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(XWING_LABEL);
    h.update(ss_mlkem);
    h.update(ss_x25519);
    h.update(ct_x);
    h.update(pk_x);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&h.finalize());
    out
}

/// X-Wing encapsulate to `recipient`: returns `(keyslot_ct, ss)` where `keyslot_ct = ct_MLKEM ‖ ct_X`
/// and `ss` is the 32-byte shared secret (§17).
fn encapsulate(recipient: &XWingPublic) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), PqError> {
    // ML-KEM encaps.
    let mut enc_rand = [0u8; 32];
    getrandom::fill(&mut enc_rand).map_err(|_| PqError::Rng)?;
    let pk = mlkem768::MlKem768PublicKey::from(recipient.mlkem_pk);
    let (ct_m, ss_m) = mlkem768::encapsulate(&pk, enc_rand);

    // X25519 encaps: ephemeral key; ct_X = ephemeral public; ss_X = DH(eph, pk_X).
    let mut eph = [0u8; X_LEN];
    getrandom::fill(&mut eph).map_err(|_| PqError::Rng)?;
    let eph = StaticSecret::from(eph);
    let ct_x = XPub::from(&eph).to_bytes();
    let pk_x = recipient.x25519_pk;
    let ss_x = eph.diffie_hellman(&XPub::from(pk_x)).to_bytes();

    let ss = combine(&ss_m, &ss_x, &ct_x, &pk_x);

    let mut keyslot_ct = Vec::with_capacity(XWING_CT_LEN);
    keyslot_ct.extend_from_slice(ct_m.as_slice());
    keyslot_ct.extend_from_slice(&ct_x);
    Ok((keyslot_ct, ss))
}

/// X-Wing decapsulate with `secret` from `keyslot_ct = ct_MLKEM ‖ ct_X`: returns `ss` (§17).
fn decapsulate(secret: &XWingSecret, keyslot_ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, PqError> {
    if keyslot_ct.len() != XWING_CT_LEN {
        return Err(PqError::Malformed);
    }
    let (ct_m_bytes, ct_x_bytes) = keyslot_ct.split_at(ML_KEM_CT_LEN);
    let mut ct_m_arr = [0u8; ML_KEM_CT_LEN];
    ct_m_arr.copy_from_slice(ct_m_bytes);
    let ct_m = mlkem768::MlKem768Ciphertext::from(ct_m_arr);
    let kp = mlkem768::generate_key_pair(*secret.mlkem_seed);
    let ss_m = mlkem768::decapsulate(kp.private_key(), &ct_m);

    let mut ct_x = [0u8; X_LEN];
    ct_x.copy_from_slice(ct_x_bytes);
    let ss_x = secret.x25519.diffie_hellman(&XPub::from(ct_x)).to_bytes();
    let pk_x = XPub::from(&secret.x25519).to_bytes();

    Ok(combine(&ss_m, &ss_x, &ct_x, &pk_x))
}

/// `info = "secsec-keyslot-v1" ‖ device_id ‖ le32(gen)` (§8.3) — the AEAD AD binding the keyslot to one
/// device + generation.
fn keyslot_ad(device_id: &[u8; 32], gen: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(b"secsec-keyslot-v1").raw(device_id).u32(gen);
    w.finish()
}

/// Wrap `master_key` (generation-`gen` bytes) to `recipient`'s X-Wing key (§8.3/§17). Returns the
/// keyslot blob `xwing_ct(1120) ‖ ctx_tag(32) ‖ ct(32)`.
pub fn wrap_pq(
    master_key: &[u8; 32],
    gen: u32,
    device_id: &[u8; 32],
    recipient: &XWingPublic,
) -> Result<Vec<u8>, PqError> {
    let (keyslot_ct, ss) = encapsulate(recipient)?;
    let ad = keyslot_ad(device_id, gen);
    let (ctx_tag, ct) = secsec_aead::seal(&ss, &ad, master_key);
    let mut out = Vec::with_capacity(XWING_CT_LEN + 32 + ct.len());
    out.extend_from_slice(&keyslot_ct);
    out.extend_from_slice(&ctx_tag);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap an X-Wing keyslot with `secret`, verifying the recovered key against `expected_mk_commit`
/// (§7/§8.3). Returns the generation-`gen` [`secsec_kdf::MasterKey`].
pub fn unwrap_pq(
    keyslot: &[u8],
    gen: u32,
    device_id: &[u8; 32],
    secret: &XWingSecret,
    expected_mk_commit: &[u8; 32],
) -> Result<secsec_kdf::MasterKey, PqError> {
    if keyslot.len() != XWING_CT_LEN + 32 + 32 {
        return Err(PqError::Malformed);
    }
    let (xwing_ct, rest) = keyslot.split_at(XWING_CT_LEN);
    let (tag_bytes, ct) = rest.split_at(32);
    let mut ctx_tag = [0u8; 32];
    ctx_tag.copy_from_slice(tag_bytes);

    let ss = decapsulate(secret, xwing_ct)?;
    let ad = keyslot_ad(device_id, gen);
    let pt = secsec_aead::open(&ss, &ad, &ctx_tag, ct).map_err(|_| PqError::Aead)?;
    if pt.len() != 32 {
        return Err(PqError::Malformed);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&pt);
    let mk = secsec_kdf::MasterKey::new(gen, *key);
    if mk.mk_commit() != *expected_mk_commit {
        return Err(PqError::CommitMismatch);
    }
    Ok(mk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secsec_kdf::MasterKey;

    const MK: [u8; 32] = [0x42; 32];
    const DID: [u8; 32] = [0x11; 32];
    const GEN: u32 = 1;

    fn mk_commit() -> [u8; 32] {
        MasterKey::new(GEN, MK).mk_commit()
    }

    #[test]
    fn xwing_kem_round_trips() {
        // the bare KEM: encaps then decaps must agree on the shared secret.
        let (sk, pk) = XWingSecret::generate().unwrap();
        let (ct, ss_enc) = encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), XWING_CT_LEN);
        let ss_dec = decapsulate(&sk, &ct).unwrap();
        assert_eq!(
            *ss_enc, *ss_dec,
            "X-Wing encaps/decaps shared secret must agree"
        );
    }

    #[test]
    fn keyslot_wrap_unwrap_recovers_master_key() {
        let (sk, pk) = XWingSecret::generate().unwrap();
        let blob = wrap_pq(&MK, GEN, &DID, &pk).unwrap();
        assert_eq!(blob.len(), XWING_CT_LEN + 32 + 32);
        let mk = unwrap_pq(&blob, GEN, &DID, &sk, &mk_commit()).unwrap();
        assert_eq!(mk.generation(), GEN);
        assert_eq!(mk.mk_commit(), mk_commit());
    }

    #[test]
    fn rejects_wrong_recipient_tamper_and_commit() {
        let (sk, pk) = XWingSecret::generate().unwrap();
        let blob = wrap_pq(&MK, GEN, &DID, &pk).unwrap();

        // `.err()` drops the Ok(MasterKey) (which has no Debug) and compares the error.
        // a different recipient cannot decaps to the same ss → AEAD fails.
        let (other_sk, _) = XWingSecret::generate().unwrap();
        assert_eq!(
            unwrap_pq(&blob, GEN, &DID, &other_sk, &mk_commit()).err(),
            Some(PqError::Aead)
        );
        // wrong device_id (AD mismatch) → AEAD fails.
        assert_eq!(
            unwrap_pq(&blob, GEN, &[0x99; 32], &sk, &mk_commit()).err(),
            Some(PqError::Aead)
        );
        // tampered ciphertext → AEAD fails.
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            unwrap_pq(&bad, GEN, &DID, &sk, &mk_commit()).err(),
            Some(PqError::Aead)
        );
        // a keyslot for a DIFFERENT master key opens but fails mk_commit (§8.3 anti-forgery).
        let fake = wrap_pq(&[0x77; 32], GEN, &DID, &pk).unwrap();
        assert_eq!(
            unwrap_pq(&fake, GEN, &DID, &sk, &mk_commit()).err(),
            Some(PqError::CommitMismatch)
        );
    }

    #[test]
    fn public_round_trips() {
        let (_sk, pk) = XWingSecret::generate().unwrap();
        let parsed = XWingPublic::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(parsed.to_bytes(), pk.to_bytes());
        assert!(matches!(
            XWingPublic::from_bytes(b"short"),
            Err(PqError::Malformed)
        ));
    }

    /// §17 CONFORMANCE GATE: byte-identical X-Wing shared secret vs the ePrint 2024/039 §A test
    /// vectors. **Required before this keyslot is enabled** (`SetMinAlgo`). Ignored until the published
    /// vectors (and the draft-10 vs draft-06 decision) are wired in.
    #[test]
    #[ignore = "needs ePrint 2024/039 §A published vectors (§17 conformance gate)"]
    fn xwing_kat() {
        // TODO: load the draft-10 / ePrint 2024/039 Appendix A vectors and assert the combiner output
        // byte-for-byte (deterministic encaps with the vector's seeds).
    }
}
