//! Hybrid post-quantum keyslot: byte-faithful X-Wing (ML-KEM-768 ⊕ X25519, draft-connolly-cfrg-xwing-kem-10) wrapping the master key (`secsec-Design.md` §8.3, §17).

#![forbid(unsafe_code)]

use libcrux_ml_kem::mlkem768;
use secsec_canon::Writer;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as XPub, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// X-Wing domain label `\.//^\`, placed last in the combiner (draft-10 §6).
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// X-Wing decapsulation-key seed length (draft-10 §6).
pub const XWING_SEED_LEN: usize = 32;
/// ML-KEM-768 ciphertext length (§17).
pub(crate) const ML_KEM_CT_LEN: usize = 1088;
/// ML-KEM-768 encapsulation-key length.
pub(crate) const ML_KEM_PK_LEN: usize = 1184;
/// ML-KEM-768 keygen seed `d ‖ z` length (FIPS 203 §7.1).
pub(crate) const ML_KEM_SEED_LEN: usize = 64;
/// X25519 key length.
pub(crate) const X_LEN: usize = 32;
/// X-Wing encapsulation seed `m(32) ‖ ek_X(32)` length (draft-10 §6).
pub(crate) const XWING_ESEED_LEN: usize = 64;
/// X-Wing ciphertext length `ct_MLKEM ‖ ct_X`.
pub(crate) const XWING_CT_LEN: usize = ML_KEM_CT_LEN + X_LEN;
/// Keyslot body length `xwing_ct ‖ ctx_tag(32) ‖ ct(32)`.
pub const KEYSLOT_BODY_LEN: usize = XWING_CT_LEN + 32 + 32;

/// Errors from the X-Wing keyslot.
#[derive(Debug, PartialEq, Eq)]
pub enum PqError {
    /// Wrong-length or invalid keyslot, ciphertext, or public key.
    Malformed,
    /// The CTX AEAD failed to open (wrong recipient key or tampered blob).
    Aead,
    /// OS RNG failure.
    Rng,
    /// The FIPS 203 §7.1 pairwise consistency check failed (§17; fatal).
    Keygen,
}

impl core::fmt::Display for PqError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PqError::Malformed => f.write_str("malformed X-Wing keyslot or public key"),
            PqError::Aead => f.write_str("X-Wing keyslot AEAD open failed"),
            PqError::Rng => f.write_str("OS RNG failure"),
            PqError::Keygen => {
                f.write_str("ML-KEM keypair consistency check failed (FIPS 203 §7.1)")
            }
        }
    }
}
impl std::error::Error for PqError {}

/// An ML-KEM-768 decapsulation key, scrubbed on drop (libcrux types do not zeroize themselves).
struct MlKemSk(mlkem768::MlKem768PrivateKey);

impl Drop for MlKemSk {
    fn drop(&mut self) {
        self.0[0..].zeroize();
    }
}

/// Expand the ML-KEM seed into `(scrubbed private key, public key bytes)`.
fn mlkem_keypair(mlkem_seed: &[u8; ML_KEM_SEED_LEN]) -> (MlKemSk, [u8; ML_KEM_PK_LEN]) {
    let (sk, pk) = mlkem768::generate_key_pair(*mlkem_seed).into_parts();
    (MlKemSk(sk), *pk.as_slice())
}

/// A device's X-Wing secret: the single 32-byte decapsulation seed `sk` (draft-10 §6), zeroized on drop.
pub struct XWingSecret {
    seed: Zeroizing<[u8; XWING_SEED_LEN]>,
}

/// A device's X-Wing public key: the ML-KEM-768 encapsulation key and the X25519 public key.
#[derive(Clone)]
pub struct XWingPublic {
    mlkem_pk: [u8; ML_KEM_PK_LEN],
    x25519_pk: [u8; X_LEN],
}

/// `expandDecapsulationKey(sk)` (draft-10 §6): `SHAKE256(sk, 96)` → ML-KEM seed `[0:64]`, X25519 secret `[64:96]`.
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
    // X25519 clamps at use (RFC 7748), matching X-Wing's `X25519(sk_X, …)`.
    (mlkem_seed, StaticSecret::from(*xsk))
}

impl XWingSecret {
    /// Generate a fresh keypair from the OS CSPRNG, running the §7.1 consistency check.
    pub fn generate() -> Result<(Self, XWingPublic), PqError> {
        let mut seed = Zeroizing::new([0u8; XWING_SEED_LEN]);
        getrandom::fill(seed.as_mut_slice()).map_err(|_| PqError::Rng)?;
        Self::from_seed(*seed)
    }

    /// Expand a 32-byte seed into `(secret, public)`, running the FIPS 203 §7.1 check every time (§17).
    pub fn from_seed(seed: [u8; XWING_SEED_LEN]) -> Result<(Self, XWingPublic), PqError> {
        let secret = Self {
            seed: Zeroizing::new(seed),
        };
        let public = secret.public();
        secret.pairwise_consistency_check(&public)?;
        Ok((secret, public))
    }

    /// Re-derive the ML-KEM and X25519 public keys from the seed.
    fn public(&self) -> XWingPublic {
        let (mlkem_seed, x25519) = expand(&self.seed);
        let (_sk, mlkem_pk) = mlkem_keypair(&mlkem_seed);
        XWingPublic {
            mlkem_pk,
            x25519_pk: XPub::from(&x25519).to_bytes(),
        }
    }

    /// FIPS 203 §7.1: the expanded pair must round-trip an encapsulation, and the public key must validate.
    fn pairwise_consistency_check(&self, public: &XWingPublic) -> Result<(), PqError> {
        let (mlkem_seed, _x) = expand(&self.seed);
        let (sk, pk_bytes) = mlkem_keypair(&mlkem_seed);
        let pk = mlkem768::MlKem768PublicKey::from(pk_bytes);
        if pk_bytes != public.mlkem_pk || !mlkem768::validate_public_key(&pk) {
            return Err(PqError::Keygen);
        }
        let mut coins = Zeroizing::new([0u8; 32]);
        getrandom::fill(coins.as_mut_slice()).map_err(|_| PqError::Rng)?;
        let (ct, ss_e) = mlkem768::encapsulate(&pk, *coins);
        let ss_e = Zeroizing::new(ss_e);
        let ss_d = Zeroizing::new(mlkem768::decapsulate(&sk.0, &ct));
        if *ss_e != *ss_d {
            return Err(PqError::Keygen);
        }
        Ok(())
    }
}

impl XWingPublic {
    /// Serialize as `mlkem_pk(1184) ‖ x25519_pk(32)`, the form published in the roster.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(ML_KEM_PK_LEN + X_LEN);
        v.extend_from_slice(&self.mlkem_pk);
        v.extend_from_slice(&self.x25519_pk);
        v
    }

    /// Parse [`Self::to_bytes`], rejecting a wrong length or an ML-KEM key failing FIPS 203 §7.2 validation.
    pub fn from_bytes(b: &[u8]) -> Result<Self, PqError> {
        if b.len() != ML_KEM_PK_LEN + X_LEN {
            return Err(PqError::Malformed);
        }
        let mut mlkem_pk = [0u8; ML_KEM_PK_LEN];
        mlkem_pk.copy_from_slice(&b[..ML_KEM_PK_LEN]);
        if !mlkem768::validate_public_key(&mlkem768::MlKem768PublicKey::from(mlkem_pk)) {
            return Err(PqError::Malformed);
        }
        let mut x25519_pk = [0u8; X_LEN];
        x25519_pk.copy_from_slice(&b[ML_KEM_PK_LEN..]);
        Ok(Self {
            mlkem_pk,
            x25519_pk,
        })
    }
}

/// X-Wing combiner `SHA3-256(ss_MLKEM ‖ ss_X25519 ‖ ct_X ‖ pk_X ‖ XWingLabel)` (draft-10 §6, label last).
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
    let mut digest = h.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    out
}

/// `EncapsulateDerand(pk, eseed)` (draft-10 §6): `m = eseed[0:32]`, `ek_X = eseed[32:64]`.
fn encapsulate_derand(
    recipient: &XWingPublic,
    eseed: &[u8; XWING_ESEED_LEN],
) -> (Vec<u8>, Zeroizing<[u8; 32]>) {
    let mut m = Zeroizing::new([0u8; 32]);
    m.copy_from_slice(&eseed[..32]);
    let pk = mlkem768::MlKem768PublicKey::from(recipient.mlkem_pk);
    let (ct_m, ss_m) = mlkem768::encapsulate(&pk, *m);
    let ss_m = Zeroizing::new(ss_m);

    let mut ek_x = Zeroizing::new([0u8; X_LEN]);
    ek_x.copy_from_slice(&eseed[32..]);
    let eph = StaticSecret::from(*ek_x);
    let ct_x = XPub::from(&eph).to_bytes();
    let pk_x = recipient.x25519_pk;
    let ss_x = Zeroizing::new(eph.diffie_hellman(&XPub::from(pk_x)).to_bytes());

    let ss = combine(&ss_m, &ss_x, &ct_x, &pk_x);

    let mut keyslot_ct = Vec::with_capacity(XWING_CT_LEN);
    keyslot_ct.extend_from_slice(ct_m.as_slice());
    keyslot_ct.extend_from_slice(&ct_x);
    (keyslot_ct, ss)
}

/// Encapsulate to `recipient` with a fresh OS-CSPRNG `eseed` (§17).
fn encapsulate(recipient: &XWingPublic) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), PqError> {
    let mut eseed = Zeroizing::new([0u8; XWING_ESEED_LEN]);
    getrandom::fill(eseed.as_mut_slice()).map_err(|_| PqError::Rng)?;
    Ok(encapsulate_derand(recipient, &eseed))
}

/// Decapsulate `ct_MLKEM ‖ ct_X` with `secret` (§17).
fn decapsulate(secret: &XWingSecret, keyslot_ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, PqError> {
    if keyslot_ct.len() != XWING_CT_LEN {
        return Err(PqError::Malformed);
    }
    let (ct_m_bytes, ct_x_bytes) = keyslot_ct.split_at(ML_KEM_CT_LEN);
    let mut ct_m_arr = [0u8; ML_KEM_CT_LEN];
    ct_m_arr.copy_from_slice(ct_m_bytes);
    let ct_m = mlkem768::MlKem768Ciphertext::from(ct_m_arr);
    let (mlkem_seed, x25519) = expand(&secret.seed);
    let (sk, _pk) = mlkem_keypair(&mlkem_seed);
    let ss_m = Zeroizing::new(mlkem768::decapsulate(&sk.0, &ct_m));

    let mut ct_x = [0u8; X_LEN];
    ct_x.copy_from_slice(ct_x_bytes);
    let ss_x = Zeroizing::new(x25519.diffie_hellman(&XPub::from(ct_x)).to_bytes());
    let pk_x = XPub::from(&x25519).to_bytes();

    Ok(combine(&ss_m, &ss_x, &ct_x, &pk_x))
}

/// Keyslot AEAD AD `"secsec-keyslot-v1" ‖ device_id ‖ le32(gen)` (§8.3).
fn keyslot_ad(device_id: &[u8; 32], gen: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(b"secsec-keyslot-v1").raw(device_id).u32(gen);
    w.finish()
}

/// Wrap a generation-`gen` master key to `recipient`: returns `xwing_ct(1120) ‖ ctx_tag(32) ‖ ct(32)`.
pub fn wrap_pq(
    master_key: &[u8; 32],
    gen: u32,
    device_id: &[u8; 32],
    recipient: &XWingPublic,
) -> Result<Vec<u8>, PqError> {
    let (keyslot_ct, ss) = encapsulate(recipient)?;
    let ad = keyslot_ad(device_id, gen);
    let (ctx_tag, ct) = secsec_aead::seal(secsec_aead::UniqueKey::new(&ss), &ad, master_key);
    let mut out = Vec::with_capacity(KEYSLOT_BODY_LEN);
    out.extend_from_slice(&keyslot_ct);
    out.extend_from_slice(&ctx_tag);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap a keyslot body to the raw master key; authenticity is the caller's `mk_commit` check (§7).
pub fn unwrap_pq_raw(
    keyslot: &[u8],
    gen: u32,
    device_id: &[u8; 32],
    secret: &XWingSecret,
) -> Result<Zeroizing<[u8; 32]>, PqError> {
    if keyslot.len() != KEYSLOT_BODY_LEN {
        return Err(PqError::Malformed);
    }
    let (xwing_ct, rest) = keyslot.split_at(XWING_CT_LEN);
    let (tag_bytes, ct) = rest.split_at(32);
    let mut ctx_tag = [0u8; 32];
    ctx_tag.copy_from_slice(tag_bytes);

    let ss = decapsulate(secret, xwing_ct)?;
    let ad = keyslot_ad(device_id, gen);
    let pt = Zeroizing::new(secsec_aead::open(&ss, &ad, &ctx_tag, ct).map_err(|_| PqError::Aead)?);
    if pt.len() != 32 {
        return Err(PqError::Malformed);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&pt);
    Ok(key)
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
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn xwing_kem_round_trips() {
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
        assert_eq!(blob.len(), KEYSLOT_BODY_LEN);
        let key = unwrap_pq_raw(&blob, GEN, &DID, &sk).unwrap();
        assert_eq!(*key, MK, "recovers the wrapped master key");
        assert_eq!(MasterKey::new(GEN, *key).mk_commit(), mk_commit());
    }

    #[test]
    fn rejects_wrong_recipient_and_tamper() {
        let (sk, pk) = XWingSecret::generate().unwrap();
        let blob = wrap_pq(&MK, GEN, &DID, &pk).unwrap();

        let (other_sk, _) = XWingSecret::generate().unwrap();
        assert_eq!(
            unwrap_pq_raw(&blob, GEN, &DID, &other_sk).err(),
            Some(PqError::Aead)
        );
        assert_eq!(
            unwrap_pq_raw(&blob, GEN, &[0x99; 32], &sk).err(),
            Some(PqError::Aead)
        );
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            unwrap_pq_raw(&bad, GEN, &DID, &sk).err(),
            Some(PqError::Aead)
        );
        // A keyslot wrapping a different master key still opens; rejection is the fold's mk_commit check.
        let fake = wrap_pq(&[0x77; 32], GEN, &DID, &pk).unwrap();
        assert!(unwrap_pq_raw(&fake, GEN, &DID, &sk).is_ok());
    }

    #[test]
    fn public_round_trips_and_validates() {
        let (_sk, pk) = XWingSecret::generate().unwrap();
        let parsed = XWingPublic::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(parsed.to_bytes(), pk.to_bytes());
        assert_eq!(pk.to_bytes().len(), ML_KEM_PK_LEN + X_LEN);
        assert!(matches!(
            XWingPublic::from_bytes(b"short"),
            Err(PqError::Malformed)
        ));
        // An ML-KEM encapsulation key with out-of-range coefficients fails FIPS 203 §7.2 validation.
        let mut bad = pk.to_bytes();
        bad[..384].fill(0xFF);
        assert!(matches!(
            XWingPublic::from_bytes(&bad),
            Err(PqError::Malformed)
        ));
    }

    /// The device path re-derives from a stored seed and runs the §7.1 check, reproducing the same public key.
    #[test]
    fn from_seed_is_deterministic_and_checked() {
        let (a, pa) = XWingSecret::from_seed([0x07; 32]).unwrap();
        let (_b, pb) = XWingSecret::from_seed([0x07; 32]).unwrap();
        assert_eq!(pa.to_bytes(), pb.to_bytes());
        let blob = wrap_pq(&MK, GEN, &DID, &pb).unwrap();
        assert_eq!(*unwrap_pq_raw(&blob, GEN, &DID, &a).unwrap(), MK);
    }

    /// §17 conformance gate: byte-identical shared secret vs the draft-10 Appendix C vector.
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

        let (sk, pk) = XWingSecret::from_seed(seed).unwrap();
        let (ct, ss_enc) = encapsulate_derand(&pk, &eseed);
        assert_eq!(
            &ss_enc[..],
            &expected_ss[..],
            "X-Wing encaps shared secret must match the draft-10 vector (combiner/keygen conformance)"
        );
        let ss_dec = decapsulate(&sk, &ct).unwrap();
        assert_eq!(&ss_dec[..], &expected_ss[..]);
    }
}
