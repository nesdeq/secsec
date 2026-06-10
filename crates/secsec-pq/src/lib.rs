//! Hybrid post-quantum keyslot — **X-Wing** (`secsec-Design.md` §17).
//!
//! Wraps `master_key_g` to a device under the X-Wing KEM (ML-KEM-768 ⊕ X25519), so the harvestable
//! asymmetric keyslot wrap is PQ-secure (the symmetric data plane is already PQ-safe). This is a
//! **byte-faithful** X-Wing per draft-connolly-cfrg-xwing-kem-10 / ePrint 2024/039:
//!
//! ```text
//! // key generation (draft-10 §6 expandDecapsulationKey): a single 32-byte seed `sk`
//! expanded = SHAKE256(sk, 96)
//! (d, z)   = expanded[0:32], expanded[32:64]   // ML-KEM-768 KeyGen_internal seed
//! sk_X     = expanded[64:96]                    // X25519 static secret
//!
//! // combiner (draft-10 §6 Combiner) — the XWingLabel is placed **LAST**:
//! ss = SHA3-256( ss_MLKEM(32) ‖ ss_X25519(32) ‖ ct_X(32) ‖ pk_X(32) ‖ XWingLabel(6) )
//! keyslot_ct = ct_MLKEM(1088) ‖ ct_X(32)                                       // 1120 bytes
//! ```
//!
//! The X-Wing secret key is the 32-byte `sk` seed alone; the ML-KEM `(d,z)` seed and the X25519
//! secret are *derived* from it (FIPS 203 §7.1 seed form for ML-KEM, required to avoid
//! MAL-BIND-K-CT / MAL-BIND-K-PK failures — Schmieg, ePrint 2024/523). The X-Wing shared secret then
//! keys the §9.4 CTX committing AEAD to wrap the master key; authenticity rests on the §7 `mk_commit`
//! check, not the wrap.
//!
//! ## Conformance (§17, normative)
//!
//! [`xwing_kat`] asserts a byte-identical shared secret against the draft-10 Appendix C test vector
//! (the published `(seed, eseed) → ss`), exercising keygen, encapsulation, and the combiner end to
//! end against the formally-verified [`libcrux_ml_kem`] ML-KEM-768 and X25519. §17 mandates this
//! gate "before any implementation is accepted as conformant"; it runs in normal CI (not `#[ignore]`d).

#![forbid(unsafe_code)]

use libcrux_ml_kem::mlkem768;
use secsec_canon::Writer;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as XPub, StaticSecret};
use zeroize::Zeroizing;

/// X-Wing 6-byte domain label `XWingLabel` (draft-10 §6): the ASCII `\.//^\`, placed **last** in the
/// combiner input.
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// X-Wing decapsulation-key seed length: a single 32-byte secret (draft-10 §6).
pub const XWING_SEED_LEN: usize = 32;
/// ML-KEM-768 ciphertext length (§17).
pub const ML_KEM_CT_LEN: usize = 1088;
/// ML-KEM-768 public-key length.
pub const ML_KEM_PK_LEN: usize = 1184;
/// ML-KEM-768 keygen seed (`d ‖ z`) length (FIPS 203 §7.1).
pub const ML_KEM_SEED_LEN: usize = 64;
/// X25519 key length.
pub const X_LEN: usize = 32;
/// X-Wing encapsulation seed length: `m(32) ‖ ek_X(32)` (draft-10 §6 EncapsulateDerand).
pub const XWING_ESEED_LEN: usize = 64;
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
    /// The FIPS 203 §7.1 keypair consistency check failed at key generation (§17; fatal).
    Keygen,
}

impl core::fmt::Display for PqError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PqError::Malformed => f.write_str("malformed X-Wing keyslot"),
            PqError::Aead => f.write_str("X-Wing keyslot AEAD open failed"),
            PqError::CommitMismatch => f.write_str("recovered key fails mk_commit (§8.3)"),
            PqError::Rng => f.write_str("OS RNG failure"),
            PqError::Keygen => {
                f.write_str("ML-KEM keypair consistency check failed (FIPS 203 §7.1)")
            }
        }
    }
}
impl std::error::Error for PqError {}

/// A device's X-Wing **secret** key: the single 32-byte decapsulation-key seed `sk` (draft-10 §6).
/// The ML-KEM `(d,z)` seed and the X25519 static secret are derived from it on demand via
/// [`expand`]. Zeroized on drop.
pub struct XWingSecret {
    seed: Zeroizing<[u8; XWING_SEED_LEN]>,
}

/// A device's X-Wing **public** key: the ML-KEM-768 encapsulation key + the X25519 public key.
#[derive(Clone)]
pub struct XWingPublic {
    mlkem_pk: [u8; ML_KEM_PK_LEN],
    x25519_pk: [u8; X_LEN],
}

/// `expandDecapsulationKey(sk)` (draft-10 §6): `SHAKE256(sk, 96)` → `(d‖z) = [0:64]` (the ML-KEM-768
/// keygen seed) and `sk_X = [64:96]` (the X25519 static secret). Returns the derived ML-KEM seed and
/// the X25519 secret; both are zeroizing.
fn expand(seed: &[u8; XWING_SEED_LEN]) -> (Zeroizing<[u8; ML_KEM_SEED_LEN]>, StaticSecret) {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut x = sha3::Shake256::default();
    x.update(seed);
    let mut reader = x.finalize_xof();
    let mut expanded = Zeroizing::new([0u8; 96]);
    reader.read(expanded.as_mut_slice());

    let mut mlkem_seed = Zeroizing::new([0u8; ML_KEM_SEED_LEN]);
    mlkem_seed.copy_from_slice(&expanded[..ML_KEM_SEED_LEN]);
    let mut xsk = Zeroizing::new([0u8; X_LEN]);
    xsk.copy_from_slice(&expanded[ML_KEM_SEED_LEN..]);
    // StaticSecret::from copies the bytes; X25519 clamps the scalar at use (RFC 7748), matching
    // X-Wing's `X25519(sk_X, …)`. `xsk` is zeroized on drop.
    (mlkem_seed, StaticSecret::from(*xsk))
}

impl XWingSecret {
    /// Generate a fresh X-Wing keypair (OS CSPRNG): draw the 32-byte seed, then run the FIPS 203 §7.1
    /// keypair consistency check (§17, normative — failure is fatal). Returns `(secret, public)`.
    pub fn generate() -> Result<(Self, XWingPublic), PqError> {
        let mut seed = Zeroizing::new([0u8; XWING_SEED_LEN]);
        getrandom::fill(seed.as_mut_slice()).map_err(|_| PqError::Rng)?;
        let secret = Self { seed };
        let public = secret.public();
        secret.pairwise_consistency_check()?;
        Ok((secret, public))
    }

    /// Construct from a stored 32-byte X-Wing seed — key **loading** (a recovered decapsulation key,
    /// or the §17 conformance vector), not key generation, so the §7.1 consistency check (a
    /// key-generation step) is not re-run.
    #[must_use]
    pub fn from_seed(seed: [u8; XWING_SEED_LEN]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    /// This secret's public key (re-derives the ML-KEM + X25519 public keys from the seed).
    #[must_use]
    pub fn public(&self) -> XWingPublic {
        let (mlkem_seed, x25519) = expand(&self.seed);
        let kp = mlkem768::generate_key_pair(*mlkem_seed);
        XWingPublic {
            mlkem_pk: *kp.pk(),
            x25519_pk: XPub::from(&x25519).to_bytes(),
        }
    }

    /// FIPS 203 §7.1 pairwise consistency check (§17): the freshly-generated ML-KEM keypair must
    /// encapsulate/decapsulate to the same shared secret. Catches a faulty keygen / RNG before the
    /// key is ever used. The X25519 half is checked structurally by [`expand`] deriving the public
    /// from the secret.
    fn pairwise_consistency_check(&self) -> Result<(), PqError> {
        let (mlkem_seed, _x) = expand(&self.seed);
        let kp = mlkem768::generate_key_pair(*mlkem_seed);
        let mut coins = [0u8; 32];
        getrandom::fill(&mut coins).map_err(|_| PqError::Rng)?;
        let pk = mlkem768::MlKem768PublicKey::from(*kp.pk());
        let (ct, ss_e) = mlkem768::encapsulate(&pk, coins);
        let ss_d = mlkem768::decapsulate(kp.private_key(), &ct);
        if ss_e != ss_d {
            return Err(PqError::Keygen);
        }
        Ok(())
    }
}

impl XWingPublic {
    /// Serialize as `mlkem_pk(1184) ‖ x25519_pk(32)` (the 1216-byte form published for a device).
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

/// The X-Wing combiner (draft-10 §6): `ss = SHA3-256(ss_MLKEM ‖ ss_X25519 ‖ ct_X ‖ pk_X ‖ XWingLabel)`.
/// The label is **last**.
fn combine(
    ss_mlkem: &[u8; 32],
    ss_x25519: &[u8; 32],
    ct_x: &[u8; X_LEN],
    pk_x: &[u8; X_LEN],
) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(ss_mlkem);
    h.update(ss_x25519);
    h.update(ct_x);
    h.update(pk_x);
    h.update(XWING_LABEL);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&h.finalize());
    out
}

/// X-Wing `EncapsulateDerand(pk, eseed)` (draft-10 §6) with the explicit 64-byte `eseed`: `m =
/// eseed[0:32]` is the ML-KEM encapsulation randomness, `ek_X = eseed[32:64]` is the X25519 ephemeral
/// secret. Returns `(keyslot_ct = ct_MLKEM ‖ ct_X, ss)`. Deterministic in `eseed` — the conformance
/// vector and the per-op randomized [`encapsulate`] both route through here.
fn encapsulate_derand(
    recipient: &XWingPublic,
    eseed: &[u8; XWING_ESEED_LEN],
) -> (Vec<u8>, Zeroizing<[u8; 32]>) {
    // ML-KEM encaps with m = eseed[0:32].
    let mut m = Zeroizing::new([0u8; 32]);
    m.copy_from_slice(&eseed[..32]);
    let pk = mlkem768::MlKem768PublicKey::from(recipient.mlkem_pk);
    let (ct_m, ss_m) = mlkem768::encapsulate(&pk, *m);

    // X25519 ephemeral with ek_X = eseed[32:64]: ct_X = ephemeral public; ss_X = DH(ek_X, pk_X).
    let mut ek_x = Zeroizing::new([0u8; X_LEN]);
    ek_x.copy_from_slice(&eseed[32..]);
    let eph = StaticSecret::from(*ek_x);
    let ct_x = XPub::from(&eph).to_bytes();
    let pk_x = recipient.x25519_pk;
    let ss_x = eph.diffie_hellman(&XPub::from(pk_x)).to_bytes();

    let ss = combine(&ss_m, &ss_x, &ct_x, &pk_x);

    let mut keyslot_ct = Vec::with_capacity(XWING_CT_LEN);
    keyslot_ct.extend_from_slice(ct_m.as_slice());
    keyslot_ct.extend_from_slice(&ct_x);
    (keyslot_ct, ss)
}

/// X-Wing encapsulate to `recipient` with fresh OS-CSPRNG `eseed`: returns `(keyslot_ct, ss)` (§17).
fn encapsulate(recipient: &XWingPublic) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), PqError> {
    let mut eseed = Zeroizing::new([0u8; XWING_ESEED_LEN]);
    getrandom::fill(eseed.as_mut_slice()).map_err(|_| PqError::Rng)?;
    Ok(encapsulate_derand(recipient, &eseed))
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
    let (mlkem_seed, x25519) = expand(&secret.seed);
    let kp = mlkem768::generate_key_pair(*mlkem_seed);
    let ss_m = mlkem768::decapsulate(kp.private_key(), &ct_m);

    let mut ct_x = [0u8; X_LEN];
    ct_x.copy_from_slice(ct_x_bytes);
    let ss_x = x25519.diffie_hellman(&XPub::from(ct_x)).to_bytes();
    let pk_x = XPub::from(&x25519).to_bytes();

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

/// Unwrap an X-Wing keyslot to the **raw** 32-byte master key, **without** the `mk_commit` check —
/// for the §8.1 cold-start bootstrap, where the commitment lives inside the still-encrypted sigchain
/// (the fold verifies it). Every other caller MUST use [`unwrap_pq`], which checks the commitment.
pub fn unwrap_pq_raw(
    keyslot: &[u8],
    gen: u32,
    device_id: &[u8; 32],
    secret: &XWingSecret,
) -> Result<Zeroizing<[u8; 32]>, PqError> {
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
    Ok(key)
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
    let key = unwrap_pq_raw(keyslot, gen, device_id, secret)?;
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

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
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
        assert_eq!(pk.to_bytes().len(), ML_KEM_PK_LEN + X_LEN); // 1216
        assert!(matches!(
            XWingPublic::from_bytes(b"short"),
            Err(PqError::Malformed)
        ));
    }

    /// §17 CONFORMANCE GATE: byte-identical X-Wing shared secret vs the published draft-10 Appendix C
    /// test vector (the first vector; `seed`/`eseed` → `ss`). Asserting `ss` exercises keygen
    /// (SHAKE256 seed-expand → ML-KEM `(d,z)` + X25519 `sk_X`), `EncapsulateDerand`, and the
    /// label-**last** combiner end to end against the formally-verified ML-KEM-768. This is what makes
    /// the keyslot *conformant* X-Wing rather than a self-consistent look-alike.
    #[test]
    fn xwing_kat() {
        let seed: [u8; XWING_SEED_LEN] =
            unhex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
                .try_into()
                .unwrap();
        let eseed: [u8; XWING_ESEED_LEN] = unhex(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2\
             35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        )
        .try_into()
        .unwrap();
        let expected_ss = unhex("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384");

        let sk = XWingSecret::from_seed(seed);
        let pk = sk.public();
        // Encapsulate with the vector's eseed and assert the shared secret matches byte-for-byte.
        let (ct, ss_enc) = encapsulate_derand(&pk, &eseed);
        assert_eq!(
            &ss_enc[..],
            &expected_ss[..],
            "X-Wing encaps shared secret must match the draft-10 vector (combiner/keygen conformance)"
        );
        // And decapsulation recovers the same shared secret from the produced ciphertext.
        let ss_dec = decapsulate(&sk, &ct).unwrap();
        assert_eq!(&ss_dec[..], &expected_ss[..]);
    }
}
