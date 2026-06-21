//! `secsec-aead` — the fully-committing (CMT-4) per-object AEAD of `secsec-Design.md` §9.4: the
//! CTX construction (Chan & Rogaway) over RFC 8439 ChaCha20-Poly1305, composed here directly from
//! the `chacha20` and `poly1305` primitives.
//!
//! ```text
//! nonce   = 0                                   // sound ONLY because `key` is unique per object
//! ct, T   = ChaCha20Poly1305_raw(key, 0, AD, plaintext)   // T = raw 16-byte Poly1305 tag
//! ctx_tag = BLAKE3::keyed_hash(key, "secsec-ctx-v1" ‖ AD ‖ T)
//! stored  = ctx_tag(32) ‖ ct                    // T is NOT stored
//! ```
//!
//! Open recomputes `T` from `(AD, ct)`, constant-time-compares the recomputed `ctx_tag`, and only
//! then decrypts (full procedure: §9.4). **Contract:** `key` MUST be unique per sealed object —
//! never [`seal`] twice with the same key. The caller owns key zeroization (§18); this crate
//! zeroizes only its Poly1305 one-time key. [`seal_mut`]/[`open_mut`] are the §9.8 mutable-object
//! variant: plain RFC 8439 with a caller-supplied **fresh nonce per write**, not key-committing.

#![forbid(unsafe_code)]

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use poly1305::universal_hash::{KeyInit, UniversalHash};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Fixed all-zero 96-bit nonce. Sound only because `key` is unique per object (§9.4).
const NONCE: [u8; 12] = [0u8; 12];

/// Domain-separation label for the CTX commitment (§9.4).
const CTX_LABEL: &[u8] = b"secsec-ctx-v1";

/// The 32-byte CTX commitment tag, stored in place of the raw Poly1305 tag.
pub type CtxTag = [u8; 32];

/// Authentication failure on [`open`]. Deliberately opaque: it never reveals *which* check failed
/// (commitment mismatch is the only observable outcome), and decryption never runs on failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("secsec-aead: authentication failed")
    }
}

impl std::error::Error for AeadError {}

/// RFC 8439 §2.8 AEAD tag over `(aad, ct)`: `MAC(aad ‖ pad16 ‖ ct ‖ pad16 ‖ le64|aad| ‖ le64|ct|)`,
/// where the MAC key is the Poly1305 one-time key derived from ChaCha20 block 0.
fn poly1305_aead_tag(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new_from_slice(otk).expect("32-byte poly1305 key");
    mac.update_padded(aad); // aad ‖ zero-pad to 16
    mac.update_padded(ct); //  ct  ‖ zero-pad to 16
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    mac.update_padded(&lengths); // exactly one block, no padding added
    let block = mac.finalize();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&block);
    tag
}

/// The CTX commitment: `BLAKE3::keyed_hash(key, "secsec-ctx-v1" ‖ AD ‖ T)`.
fn ctx_commit(key: &[u8; 32], ad: &[u8], t: &[u8; 16]) -> CtxTag {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(CTX_LABEL);
    h.update(ad);
    h.update(t);
    *h.finalize().as_bytes()
}

/// Seal `plaintext` under a **unique per-object** `key` (the crate-doc contract) with AD `ad`.
/// Returns `(ctx_tag, ciphertext)`; the raw Poly1305 tag is folded into `ctx_tag`, never stored.
#[must_use]
pub fn seal(key: &[u8; 32], ad: &[u8], plaintext: &[u8]) -> (CtxTag, Vec<u8>) {
    let mut cipher = ChaCha20::new_from_slices(key, &NONCE).expect("32-byte key / 12-byte nonce");
    // Block 0 -> Poly1305 one-time key (RFC 8439 §2.6); zeroized on drop.
    let mut otk = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(&mut *otk);
    // Message keystream begins at block 1.
    cipher.seek(64u64);
    let mut ct = plaintext.to_vec();
    cipher.apply_keystream(&mut ct);

    let t = poly1305_aead_tag(&otk, ad, &ct);
    let ctx_tag = ctx_commit(key, ad, &t);
    (ctx_tag, ct)
}

/// Open a sealed object: recompute `T` over `(ad, ct)`, constant-time-compare the commitment, and
/// only on a match decrypt (§9.4 three-phase open). Mismatch ⇒ [`AeadError`], no plaintext.
pub fn open(
    key: &[u8; 32],
    ad: &[u8],
    ctx_tag: &CtxTag,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let mut cipher = ChaCha20::new_from_slices(key, &NONCE).expect("32-byte key / 12-byte nonce");
    // Block 0 -> one-time key; zeroized on drop.
    let mut otk = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(&mut *otk);

    // 1. Recompute T over (ad, ciphertext) — no plaintext produced yet.
    let t = poly1305_aead_tag(&otk, ad, ciphertext);
    // 2. Recompute the commitment and compare in constant time.
    let expected = ctx_commit(key, ad, &t);
    if !bool::from(ctx_tag[..].ct_eq(&expected[..])) {
        return Err(AeadError);
    }
    // 3. Only now decrypt: reuse the same cipher, advanced to block 1.
    cipher.seek(64u64);
    let mut pt = ciphertext.to_vec();
    cipher.apply_keystream(&mut pt);
    Ok(pt)
}

/// The §9.8 mutable-object AEAD: plain RFC 8439 ChaCha20-Poly1305, raw tag stored. **Contract:**
/// the caller MUST pass a fresh OS-CSPRNG nonce on every call with a given `key` — `(key, nonce)`
/// reuse is catastrophic. Not key-committing; authenticity rests on the object's signature (§9.8).
#[must_use]
pub fn seal_mut(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ad: &[u8],
    plaintext: &[u8],
) -> ([u8; 16], Vec<u8>) {
    let mut cipher = ChaCha20::new_from_slices(key, nonce).expect("32-byte key / 12-byte nonce");
    let mut otk = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(&mut *otk);
    cipher.seek(64u64);
    let mut ct = plaintext.to_vec();
    cipher.apply_keystream(&mut ct);
    let tag = poly1305_aead_tag(&otk, ad, &ct);
    (tag, ct)
}

/// Open a [`seal_mut`] ciphertext: recompute the Poly1305 tag over `(ad, ct)`, constant-time compare
/// to `tag`, and only on a match decrypt. Any mismatch returns [`AeadError`] with no plaintext.
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
        let (tag, ct) = seal(&key, ad, pt);
        assert_ne!(&ct[..], &pt[..], "ciphertext must differ from plaintext");
        assert_eq!(open(&key, ad, &tag, &ct).unwrap(), pt);
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let key = [3u8; 32];
        let (tag, ct) = seal(&key, b"", b"");
        assert!(ct.is_empty());
        assert_eq!(open(&key, b"", &tag, &ct).unwrap(), b"");
    }

    /// Our raw keystream + Poly1305 tag must match the audited `chacha20poly1305` crate exactly —
    /// this anchors the ciphertext half of the frozen `ctx_kat` against an external reference.
    #[test]
    fn ciphertext_and_tag_match_reference() {
        use chacha20poly1305::aead::AeadInPlace;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _};

        let key = [0x42u8; 32];
        let ad: &[u8] = b"some associated data of odd length!!";
        let pt: &[u8] = b"plaintext that is not a multiple of sixteen bytes long";

        // ours: derive one-time key (block 0), encrypt from block 1, MAC.
        let mut cipher = ChaCha20::new_from_slices(&key, &NONCE).unwrap();
        let mut otk = [0u8; 32];
        cipher.apply_keystream(&mut otk);
        cipher.seek(64u64);
        let mut my_ct = pt.to_vec();
        cipher.apply_keystream(&mut my_ct);
        let my_t = poly1305_aead_tag(&otk, ad, &my_ct);

        // reference, same key, nonce = 0.
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
        let (tag, mut ct) = seal(&key, ad, b"important bytes");
        ct[0] ^= 0x01;
        assert_eq!(open(&key, ad, &tag, &ct), Err(AeadError));
    }

    #[test]
    fn tampered_ad_rejected() {
        let key = [1u8; 32];
        let (tag, ct) = seal(&key, b"ad-one", b"important bytes");
        assert_eq!(open(&key, b"ad-two", &tag, &ct), Err(AeadError));
    }

    #[test]
    fn tampered_tag_rejected() {
        let key = [1u8; 32];
        let ad = b"ad";
        let (mut tag, ct) = seal(&key, ad, b"important bytes");
        tag[0] ^= 0x01;
        assert_eq!(open(&key, ad, &tag, &ct), Err(AeadError));
    }

    /// CMT-4: a sealed blob must not open under any key other than the one that sealed it.
    #[test]
    fn committing_distinct_key_cannot_open() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let ad = b"ad";
        let (tag, ct) = seal(&k1, ad, b"secret");
        assert_eq!(open(&k1, ad, &tag, &ct).unwrap(), b"secret");
        assert_eq!(open(&k2, ad, &tag, &ct), Err(AeadError));
    }

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Frozen CTX KAT, mirrored in `vectors/secsec-kat-v1.txt [aead]`. Pins the committing-AEAD
    /// wire output (`ctx_tag ‖ ct`) for fixed `(key, ad, plaintext)` so any change to the
    /// construction is caught against the committed vector.
    #[test]
    fn ctx_kat() {
        let key = [0x42u8; 32];
        let ad: &[u8] = b"secsec-aead-kat-ad";
        let pt: &[u8] = b"secsec aead kat plaintext";
        let (ctx_tag, ct) = seal(&key, ad, pt);
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

    // ---- §9.8 mutable-object AEAD (seal_mut / open_mut) ----

    #[test]
    fn mut_round_trip() {
        let key = [7u8; 32];
        let nonce = [0x11u8; 12];
        let ad = b"FRAME||H";
        let (tag, ct) = seal_mut(&key, &nonce, ad, b"head plaintext");
        assert_eq!(
            open_mut(&key, &nonce, ad, &tag, &ct).unwrap(),
            b"head plaintext"
        );
    }

    /// `seal_mut` is plain RFC 8439 ChaCha20-Poly1305 — must match the audited reference crate
    /// byte-for-byte for the same key/nonce/ad/plaintext (ciphertext and detached tag).
    #[test]
    fn mut_matches_reference() {
        use chacha20poly1305::aead::AeadInPlace;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _};

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let ad: &[u8] = b"associated data";
        let pt: &[u8] = b"plaintext of arbitrary, non-block-aligned length!";

        let (my_tag, my_ct) = seal_mut(&key, &nonce, ad, pt);

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
        let (tag, ct) = seal_mut(&key, &nonce, ad, b"secret head");

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

    /// The whole point of the mutable construction: a fresh nonce yields a different ciphertext for
    /// the same plaintext under the same key (no keystream reuse), yet both open correctly.
    #[test]
    fn mut_fresh_nonce_changes_ciphertext() {
        let key = [7u8; 32];
        let ad = b"ad";
        let pt = b"same plaintext, two writes";
        let (t1, c1) = seal_mut(&key, &[1u8; 12], ad, pt);
        let (t2, c2) = seal_mut(&key, &[2u8; 12], ad, pt);
        assert_ne!(c1, c2, "different nonce must give different ciphertext");
        assert_eq!(open_mut(&key, &[1u8; 12], ad, &t1, &c1).unwrap(), pt);
        assert_eq!(open_mut(&key, &[2u8; 12], ad, &t2, &c2).unwrap(), pt);
    }

    proptest! {
        #[test]
        fn prop_round_trip(key: [u8; 32], ad in proptest::collection::vec(any::<u8>(), 0..64),
                           pt in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let (tag, ct) = seal(&key, &ad, &pt);
            prop_assert_eq!(open(&key, &ad, &tag, &ct).unwrap(), pt);
        }

        #[test]
        fn prop_wrong_key_rejected(k1: [u8; 32], k2: [u8; 32],
                                   pt in proptest::collection::vec(any::<u8>(), 0..256)) {
            prop_assume!(k1 != k2);
            let (tag, ct) = seal(&k1, b"ad", &pt);
            prop_assert_eq!(open(&k2, b"ad", &tag, &ct), Err(AeadError));
        }

        #[test]
        fn prop_flip_any_ct_byte_rejected(key: [u8; 32],
                                          pt in proptest::collection::vec(any::<u8>(), 1..256),
                                          idx: usize, bit in 0u8..8) {
            let (tag, mut ct) = seal(&key, b"ad", &pt);
            let i = idx % ct.len();
            ct[i] ^= 1 << bit;
            prop_assert_eq!(open(&key, b"ad", &tag, &ct), Err(AeadError));
        }
    }
}
