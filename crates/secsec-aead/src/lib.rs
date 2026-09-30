//! Fully-committing (CMT-4) CTX AEAD over RFC 8439 ChaCha20-Poly1305, plus the §9.8 fresh-nonce variant (`secsec-Design.md` §9.4).

#![forbid(unsafe_code)]

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use poly1305::universal_hash::{KeyInit, UniversalHash};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Fixed all-zero 96-bit nonce; sound only because every [`seal`] key is unique (§9.4).
const NONCE: [u8; 12] = [0u8; 12];

/// Domain-separation label for the CTX commitment (§9.4).
const CTX_LABEL: &[u8] = b"secsec-ctx-v1";

/// The 32-byte CTX commitment tag, stored in place of the raw Poly1305 tag.
pub type CtxTag = [u8; 32];

/// A key used for exactly one [`seal`] ever; each `UniqueKey::new` is a proof site for that contract.
#[derive(Clone, Copy)]
pub struct UniqueKey<'a>(&'a [u8; 32]);

impl<'a> UniqueKey<'a> {
    /// Assert `key` is bound to one sealing (a content address, a per-seal random salt, or a fresh KEM secret).
    #[must_use]
    pub fn new(key: &'a [u8; 32]) -> Self {
        Self(key)
    }
}

/// A 96-bit nonce never paired with the accompanying key before or after (the [`seal_mut`] contract, §9.8).
#[derive(Clone, Copy)]
pub struct FreshNonce<'a>(&'a [u8; 12]);

impl<'a> FreshNonce<'a> {
    /// Assert `nonce` was drawn from the OS CSPRNG for this one write; never a counter.
    #[must_use]
    pub fn new(nonce: &'a [u8; 12]) -> Self {
        Self(nonce)
    }
}

/// Authentication failure; deliberately opaque, and no plaintext is produced on failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("secsec-aead: authentication failed")
    }
}

impl std::error::Error for AeadError {}

/// RFC 8439 §2.8 tag `MAC(aad ‖ pad16 ‖ ct ‖ pad16 ‖ le64|aad| ‖ le64|ct|)` under the block-0 one-time key.
fn poly1305_aead_tag(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new_from_slice(otk).expect("32-byte poly1305 key");
    mac.update_padded(aad);
    mac.update_padded(ct);
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    mac.update_padded(&lengths);
    let block = mac.finalize();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&block);
    tag
}

/// The CTX commitment `BLAKE3::keyed_hash(key, "secsec-ctx-v1" ‖ AD ‖ T)`; the keyed hasher is wiped.
fn ctx_commit(key: &[u8; 32], ad: &[u8], t: &[u8; 16]) -> CtxTag {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(CTX_LABEL);
    h.update(ad);
    h.update(t);
    let out = *h.finalize().as_bytes();
    h.zeroize();
    out
}

/// Seal `plaintext` under a [`UniqueKey`] with AD `ad`, returning `(ctx_tag, ciphertext)`.
#[must_use]
pub fn seal(key: UniqueKey<'_>, ad: &[u8], plaintext: &[u8]) -> (CtxTag, Vec<u8>) {
    let key = key.0;
    let mut cipher = ChaCha20::new_from_slices(key, &NONCE).expect("32-byte key / 12-byte nonce");
    let mut otk = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(&mut *otk);
    cipher.seek(64u64);
    let mut ct = plaintext.to_vec();
    cipher.apply_keystream(&mut ct);

    let t = poly1305_aead_tag(&otk, ad, &ct);
    let ctx_tag = ctx_commit(key, ad, &t);
    (ctx_tag, ct)
}

/// Three-phase open (§9.4): recompute `T`, constant-time compare the commitment, only then decrypt.
pub fn open(
    key: &[u8; 32],
    ad: &[u8],
    ctx_tag: &CtxTag,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let mut cipher = ChaCha20::new_from_slices(key, &NONCE).expect("32-byte key / 12-byte nonce");
    let mut otk = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(&mut *otk);

    let t = poly1305_aead_tag(&otk, ad, ciphertext);
    let expected = ctx_commit(key, ad, &t);
    if !bool::from(ctx_tag[..].ct_eq(&expected[..])) {
        return Err(AeadError);
    }
    cipher.seek(64u64);
    let mut pt = ciphertext.to_vec();
    cipher.apply_keystream(&mut pt);
    Ok(pt)
}

/// The §9.8 mutable-object AEAD: plain RFC 8439 under a [`FreshNonce`], raw tag returned, not key-committing.
#[must_use]
pub fn seal_mut(
    key: &[u8; 32],
    nonce: FreshNonce<'_>,
    ad: &[u8],
    plaintext: &[u8],
) -> ([u8; 16], Vec<u8>) {
    let nonce = nonce.0;
    let mut cipher = ChaCha20::new_from_slices(key, nonce).expect("32-byte key / 12-byte nonce");
    let mut otk = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(&mut *otk);
    cipher.seek(64u64);
    let mut ct = plaintext.to_vec();
    cipher.apply_keystream(&mut ct);
    let tag = poly1305_aead_tag(&otk, ad, &ct);
    (tag, ct)
}

/// Open a [`seal_mut`] ciphertext: constant-time tag check, then decrypt.
pub fn open_mut(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ad: &[u8],
    tag: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let mut cipher = ChaCha20::new_from_slices(key, nonce).expect("32-byte key / 12-byte nonce");
    let mut otk = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(&mut *otk);
    let expected = poly1305_aead_tag(&otk, ad, ciphertext);
    if !bool::from(tag[..].ct_eq(&expected[..])) {
        return Err(AeadError);
    }
    cipher.seek(64u64);
    let mut pt = ciphertext.to_vec();
    cipher.apply_keystream(&mut pt);
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn round_trip() {
        let key = [9u8; 32];
        let ad = b"FRAME||id";
        let pt = b"the quick brown fox";
        let (tag, ct) = seal(UniqueKey::new(&key), ad, pt);
        assert_ne!(&ct[..], &pt[..], "ciphertext must differ from plaintext");
        assert_eq!(open(&key, ad, &tag, &ct).unwrap(), pt);
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let key = [3u8; 32];
        let (tag, ct) = seal(UniqueKey::new(&key), b"", b"");
        assert!(ct.is_empty());
        assert_eq!(open(&key, b"", &tag, &ct).unwrap(), b"");
    }

    /// Our keystream + Poly1305 tag equal the audited `chacha20poly1305` crate (anchors `ctx_kat`).
    #[test]
    fn ciphertext_and_tag_match_reference() {
        use chacha20poly1305::aead::AeadInPlace;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _};

        let key = [0x42u8; 32];
        let ad: &[u8] = b"some associated data of odd length!!";
        let pt: &[u8] = b"plaintext that is not a multiple of sixteen bytes long";

        let mut cipher = ChaCha20::new_from_slices(&key, &NONCE).unwrap();
        let mut otk = [0u8; 32];
        cipher.apply_keystream(&mut otk);
        cipher.seek(64u64);
        let mut my_ct = pt.to_vec();
        cipher.apply_keystream(&mut my_ct);
        let my_t = poly1305_aead_tag(&otk, ad, &my_ct);

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let mut ref_ct = pt.to_vec();
        let ref_tag = cipher
            .encrypt_in_place_detached((&NONCE).into(), ad, &mut ref_ct)
            .unwrap();

        assert_eq!(my_ct, ref_ct, "ciphertext differs from reference");
        assert_eq!(&my_t[..], ref_tag.as_slice(), "tag differs from reference");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = [1u8; 32];
        let ad = b"ad";
        let (tag, mut ct) = seal(UniqueKey::new(&key), ad, b"important bytes");
        ct[0] ^= 0x01;
        assert_eq!(open(&key, ad, &tag, &ct), Err(AeadError));
    }

    #[test]
    fn tampered_ad_rejected() {
        let key = [1u8; 32];
        let (tag, ct) = seal(UniqueKey::new(&key), b"ad-one", b"important bytes");
        assert_eq!(open(&key, b"ad-two", &tag, &ct), Err(AeadError));
    }

    #[test]
    fn tampered_tag_rejected() {
        let key = [1u8; 32];
        let ad = b"ad";
        let (mut tag, ct) = seal(UniqueKey::new(&key), ad, b"important bytes");
        tag[0] ^= 0x01;
        assert_eq!(open(&key, ad, &tag, &ct), Err(AeadError));
    }

    /// CMT-4: a sealed blob opens under no key but its own.
    #[test]
    fn committing_distinct_key_cannot_open() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let ad = b"ad";
        let (tag, ct) = seal(UniqueKey::new(&k1), ad, b"secret");
        assert_eq!(open(&k1, ad, &tag, &ct).unwrap(), b"secret");
        assert_eq!(open(&k2, ad, &tag, &ct), Err(AeadError));
    }

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Frozen CTX KAT, mirrored in `vectors/secsec-kat-v1.txt [aead]`.
    #[test]
    fn ctx_kat() {
        let key = [0x42u8; 32];
        let ad: &[u8] = b"secsec-aead-kat-ad";
        let pt: &[u8] = b"secsec aead kat plaintext";
        let (ctx_tag, ct) = seal(UniqueKey::new(&key), ad, pt);
        assert_eq!(
            hx(&ctx_tag),
            "03f2eb3d9adf7ce304751d18f32d02e9e169bf00cbea129e2a46cdfa3a141273"
        );
        assert_eq!(
            hx(&ct),
            "2a03875878d713ac89c03014944edc98cecbc5b0c4e1c1648b"
        );
        assert_eq!(open(&key, ad, &ctx_tag, &ct).unwrap(), pt);
    }

    #[test]
    fn mut_round_trip() {
        let key = [7u8; 32];
        let nonce = [0x11u8; 12];
        let ad = b"FRAME||H";
        let (tag, ct) = seal_mut(&key, FreshNonce::new(&nonce), ad, b"head plaintext");
        assert_eq!(
            open_mut(&key, &nonce, ad, &tag, &ct).unwrap(),
            b"head plaintext"
        );
    }

    /// `seal_mut` equals the reference RFC 8439 AEAD byte-for-byte.
    #[test]
    fn mut_matches_reference() {
        use chacha20poly1305::aead::AeadInPlace;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _};

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let ad: &[u8] = b"associated data";
        let pt: &[u8] = b"plaintext of arbitrary, non-block-aligned length!";

        let (my_tag, my_ct) = seal_mut(&key, FreshNonce::new(&nonce), ad, pt);

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let mut ref_ct = pt.to_vec();
        let ref_tag = cipher
            .encrypt_in_place_detached((&nonce).into(), ad, &mut ref_ct)
            .unwrap();

        assert_eq!(my_ct, ref_ct, "ciphertext differs from reference");
        assert_eq!(
            &my_tag[..],
            ref_tag.as_slice(),
            "tag differs from reference"
        );
    }

    #[test]
    fn mut_rejects_tamper_wrong_nonce_key_ad() {
        let key = [7u8; 32];
        let nonce = [0x11u8; 12];
        let ad = b"ad";
        let (tag, ct) = seal_mut(&key, FreshNonce::new(&nonce), ad, b"secret head");

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert_eq!(open_mut(&key, &nonce, ad, &tag, &bad_ct), Err(AeadError));
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        assert_eq!(open_mut(&key, &nonce, ad, &bad_tag, &ct), Err(AeadError));
        assert_eq!(open_mut(&key, &[0x99; 12], ad, &tag, &ct), Err(AeadError));
        assert_eq!(open_mut(&[8u8; 32], &nonce, ad, &tag, &ct), Err(AeadError));
        assert_eq!(
            open_mut(&key, &nonce, b"other-ad", &tag, &ct),
            Err(AeadError)
        );
    }

    /// A fresh nonce changes the ciphertext of the same plaintext, and both open.
    #[test]
    fn mut_fresh_nonce_changes_ciphertext() {
        let key = [7u8; 32];
        let ad = b"ad";
        let pt = b"same plaintext, two writes";
        let (t1, c1) = seal_mut(&key, FreshNonce::new(&[1u8; 12]), ad, pt);
        let (t2, c2) = seal_mut(&key, FreshNonce::new(&[2u8; 12]), ad, pt);
        assert_ne!(c1, c2, "different nonce must give different ciphertext");
        assert_eq!(open_mut(&key, &[1u8; 12], ad, &t1, &c1).unwrap(), pt);
        assert_eq!(open_mut(&key, &[2u8; 12], ad, &t2, &c2).unwrap(), pt);
    }

    proptest! {
        #[test]
        fn prop_round_trip(key: [u8; 32], ad in proptest::collection::vec(any::<u8>(), 0..64),
                           pt in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let (tag, ct) = seal(UniqueKey::new(&key), &ad, &pt);
            prop_assert_eq!(open(&key, &ad, &tag, &ct).unwrap(), pt);
        }

        #[test]
        fn prop_wrong_key_rejected(k1: [u8; 32], k2: [u8; 32],
                                   pt in proptest::collection::vec(any::<u8>(), 0..256)) {
            prop_assume!(k1 != k2);
            let (tag, ct) = seal(UniqueKey::new(&k1), b"ad", &pt);
            prop_assert_eq!(open(&k2, b"ad", &tag, &ct), Err(AeadError));
        }

        #[test]
        fn prop_flip_any_ct_byte_rejected(key: [u8; 32],
                                          pt in proptest::collection::vec(any::<u8>(), 1..256),
                                          idx: usize, bit in 0u8..8) {
            let (tag, mut ct) = seal(UniqueKey::new(&key), b"ad", &pt);
            let i = idx % ct.len();
            ct[i] ^= 1 << bit;
            prop_assert_eq!(open(&key, b"ad", &tag, &ct), Err(AeadError));
        }
    }
}
