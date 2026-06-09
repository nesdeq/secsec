//! `secsec-aead` — the per-object **fully-committing (CMT-4)** AEAD of `finaldesign.md` §9.4,
//! built as the CTX construction (Chan & Rogaway, ESORICS 2022) over ChaCha20-Poly1305.
//!
//! # Construction
//!
//! ```text
//! nonce   = 0                                   // safe ONLY because `key` is unique per object
//! ct, T   = ChaCha20Poly1305_raw(key, 0, AD, plaintext)   // T = raw 16-byte Poly1305 tag
//! ctx_tag = BLAKE3::keyed_hash(key, "secsec-ctx-v1" ‖ AD ‖ T)
//! stored  = ctx_tag(32) ‖ ct                    // T is NOT stored
//! ```
//!
//! On open, `T` is **recomputed** from `(AD, ct)` (it depends only on the ciphertext and AD, not
//! the plaintext), `ctx_tag` is recomputed and compared in constant time, and only then is the
//! ciphertext decrypted. There is no stored `T` and the high-level AEAD "open" is never used.
//!
//! `ctx_tag` binds the key, the associated data, and — via `T` — the plaintext, so no ciphertext
//! opens under two distinct `(key, AD)` pairs (CMT-4). This closes partitioning-oracle /
//! invisible-salamander attacks across the multi-generation, multi-recipient surface.
//!
//! # Contract
//!
//! `key` is `k_obj` from §9.4 and **MUST be unique per sealed object**. The 96-bit nonce is fixed
//! at zero; that is sound *only* under this uniqueness (a unique key ⇒ a unique keystream). Never
//! call [`seal`] twice with the same `key` and different plaintext. Key *lifecycle* (zeroization
//! of `key` itself) is owned by the caller / key-management layer (§18); this crate zeroizes only
//! its own secret transient (the Poly1305 one-time key).
//!
//! `AD` here is `FRAME ‖ id` (a fixed 43-byte string in secsec). The commitment input
//! `"secsec-ctx-v1" ‖ AD ‖ T` is unambiguous because the label is a fixed prefix and `T` is a
//! fixed 16-byte suffix, so the triple `(AD, T)` is recovered injectively.

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

/// Seal `plaintext` under a unique per-object `key` with associated data `ad`.
///
/// Returns `(ctx_tag, ciphertext)`. The raw Poly1305 tag is folded into `ctx_tag` and discarded —
/// it is never stored. The blob layout (§9.1) places `ctx_tag` before `ciphertext`.
///
/// See the crate docs for the **uniqueness contract** on `key`.
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

/// Open a sealed object. Recomputes the Poly1305 tag over `(ad, ciphertext)` **without decrypting**,
/// recomputes the commitment, compares it to `ctx_tag` in constant time, and only on a match
/// decrypts and returns the plaintext. Any mismatch returns [`AeadError`] with no plaintext released.
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

    /// Cross-check: our raw ChaCha20 keystream (block 1+) and our RFC 8439 Poly1305 tag must match
    /// the audited reference `chacha20poly1305` crate exactly. This validates that our hand-rolled
    /// tag framing is RFC-correct (the fiddly part of building CTX from raw primitives); it is what
    /// independently anchors the *ciphertext* half of the frozen `ctx_kat` vector — only the 32-byte
    /// BLAKE3 commitment tag in that KAT is a self-captured golden value.
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
