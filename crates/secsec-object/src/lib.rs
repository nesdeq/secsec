//! `secsec-object` — content addressing, authenticated seal/open, chunk padding (`secsec-Design.md`
//! §9.2, §9.4, §9.7).
//!
//! `id = BLAKE3::keyed_hash(id_key[gen][type], FRAME ‖ path_salt ‖ plaintext)` (§9.2). On fetch,
//! substitution is caught three independent ways: AEAD/CTX tag, expected-FRAME match (§18), and id
//! re-derivation from the recovered plaintext.

#![forbid(unsafe_code)]

use secsec_frame::{aead_ad, assemble_blob, parse_blob, Frame, FrameError, ObjType, FRAME_LEN};
use secsec_kdf::{obj_key, MasterKey, MasterKeys};
use subtle::ConstantTimeEq;

/// A 256-bit content address.
pub type Id = [u8; 32];

/// Per-path random salt (§9.2/§9.7). Objects outside the path hierarchy (commits, heads, sigchain
/// entries) use [`ZERO_SALT`].
pub type PathSalt = [u8; 16];

/// The fixed salt for non-path objects (§9.2).
pub const ZERO_SALT: PathSalt = [0u8; 16];

/// Chunk-size padding policy (§9.7). Padding blurs the stored ciphertext size so the server cannot
/// read the true chunk-boundary sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Padding {
    /// No padding — stored size equals plaintext size (opt-out; convergent/space-saving).
    None,
    /// Pad to the next power-of-two ≥ `len + 1` (ISO/IEC 7816-4: `0x80` then zeros). Default;
    /// ≤2× overhead; reduces the boundary signal (§9.7).
    #[default]
    PowerOfTwo,
}

/// Errors from opening / verifying an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjError {
    /// FRAME / blob-structure error (bad magic, mismatch with expected FRAME, bounds, …).
    Frame(FrameError),
    /// AEAD authentication failed (wrong key, tampered ciphertext/AD/tag).
    Auth,
    /// The id re-derived from the recovered plaintext did not match the requested id (§9.2).
    IdMismatch,
    /// Reversible chunk padding was malformed.
    BadPadding,
    /// The object's authenticated `FRAME.gen` had no master key in the resolver — the caller lacks
    /// that generation's key (peel the §8.2 DATA key-history), or it is a forged generation.
    UnknownGeneration(u32),
}

impl core::fmt::Display for ObjError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ObjError::Frame(e) => write!(f, "frame: {e}"),
            ObjError::Auth => f.write_str("authentication failed"),
            ObjError::IdMismatch => f.write_str("content-address mismatch"),
            ObjError::BadPadding => f.write_str("malformed chunk padding"),
            ObjError::UnknownGeneration(g) => {
                write!(
                    f,
                    "no master key for object generation {g} (peel §8.2 keyhist)"
                )
            }
        }
    }
}

impl std::error::Error for ObjError {}

impl From<FrameError> for ObjError {
    fn from(e: FrameError) -> Self {
        ObjError::Frame(e)
    }
}

/// The §9.2 content address over `FRAME ‖ path_salt ‖ plaintext`, keyed by `id_key[gen][type]`.
#[must_use]
pub(crate) fn content_id(id_key: &[u8; 32], frame: &Frame, path_salt: &PathSalt, plaintext: &[u8]) -> Id {
    let mut h = blake3::Hasher::new_keyed(id_key);
    h.update(&frame.encode());
    h.update(path_salt);
    h.update(plaintext);
    *h.finalize().as_bytes()
}

/// Seal `plaintext` as an object of `obj_type` under `mk`, returning `(id, blob)`.
///
/// `plaintext` is the exact bytes to store (already padded by [`pad_chunk`] for chunk objects).
/// Determinism (same plaintext + gen + type + path_salt ⇒ same id ⇒ same blob) preserves dedup.
#[must_use]
pub fn seal_object(
    mk: &MasterKey,
    obj_type: ObjType,
    path_salt: &PathSalt,
    plaintext: &[u8],
) -> (Id, Vec<u8>) {
    let frame = Frame::v1(mk.generation(), obj_type);
    let id_key = mk.id_key(obj_type.as_u8());
    let id = content_id(&id_key, &frame, path_salt, plaintext);

    let enc_key = mk.enc_key(obj_type.as_u8());
    let k_obj = obj_key(&enc_key, &id);
    let ad = aead_ad(&frame, &id);
    let (ctx_tag, ct) = secsec_aead::seal(&k_obj, &ad, plaintext);
    let blob = assemble_blob(&frame, &ctx_tag, &ct);
    (id, blob)
}

/// Open and fully verify a fetched `blob` requested by `requested_id`: expected-FRAME match (§18),
/// AEAD/CTX tag under the id-derived key, and id re-derivation from the plaintext (§9.2).
/// `path_salt` comes from the parent tree ([`ZERO_SALT`] for non-path objects).
pub fn open_object<K: MasterKeys>(
    keys: &K,
    obj_type: ObjType,
    path_salt: &PathSalt,
    requested_id: &Id,
    blob: &[u8],
) -> Result<Vec<u8>, ObjError> {
    // Resolve the blob's generation against the key ring (§8.2); parse_blob still enforces equality.
    let head = blob
        .get(..FRAME_LEN)
        .ok_or(ObjError::Frame(FrameError::ShortBlob))?;
    let g = Frame::decode(head)?.gen;
    let mk = keys.for_gen(g).ok_or(ObjError::UnknownGeneration(g))?;
    let frame = Frame::v1(mk.generation(), obj_type);
    let (ctx_tag, ct) = parse_blob(blob, &frame)?; // (1) FRAME == expected, bounds

    let enc_key = mk.enc_key(obj_type.as_u8());
    let k_obj = obj_key(&enc_key, requested_id);
    let ad = aead_ad(&frame, requested_id);
    let plaintext = secsec_aead::open(&k_obj, &ad, ctx_tag, ct).map_err(|_| ObjError::Auth)?; // (2)

    // (3) re-derive id from the recovered plaintext and constant-time compare.
    let id_key = mk.id_key(obj_type.as_u8());
    let recomputed = content_id(&id_key, &frame, path_salt, &plaintext);
    if !bool::from(recomputed.ct_eq(requested_id)) {
        return Err(ObjError::IdMismatch);
    }
    Ok(plaintext)
}

/// Apply the §9.7 padding policy to a chunk plaintext (reversible).
#[must_use]
pub fn pad_chunk(data: &[u8], policy: Padding) -> Vec<u8> {
    match policy {
        Padding::None => data.to_vec(),
        Padding::PowerOfTwo => {
            let target = (data.len() + 1).next_power_of_two();
            let mut v = Vec::with_capacity(target);
            v.extend_from_slice(data);
            v.push(0x80); // ISO/IEC 7816-4: a single set byte ...
            v.resize(target, 0x00); // ... then zeros to the bucket.
            v
        }
    }
}

/// Strip the §9.7 padding applied by [`pad_chunk`] under the same `policy`.
pub fn unpad_chunk(padded: &[u8], policy: Padding) -> Result<&[u8], ObjError> {
    match policy {
        Padding::None => Ok(padded),
        Padding::PowerOfTwo => {
            let mut end = padded.len();
            while end > 0 && padded[end - 1] == 0x00 {
                end -= 1;
            }
            if end == 0 || padded[end - 1] != 0x80 {
                return Err(ObjError::BadPadding);
            }
            Ok(&padded[..end - 1])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> MasterKey {
        MasterKey::new(1, [0x44; 32])
    }

    #[test]
    fn content_id_sensitivity() {
        let m = mk();
        let idk = m.id_key(ObjType::Chunk.as_u8());
        let frame = Frame::v1(1, ObjType::Chunk);
        let a = content_id(&idk, &frame, &[1u8; 16], b"hello");
        // same inputs -> same id
        assert_eq!(a, content_id(&idk, &frame, &[1u8; 16], b"hello"));
        // path_salt changes the id (per-path salt, §9.2)
        assert_ne!(a, content_id(&idk, &frame, &[2u8; 16], b"hello"));
        // plaintext changes the id
        assert_ne!(a, content_id(&idk, &frame, &[1u8; 16], b"world"));
        // a different object type's frame/id_key changes the id
        let idk_t = m.id_key(ObjType::Tree.as_u8());
        let frame_t = Frame::v1(1, ObjType::Tree);
        assert_ne!(a, content_id(&idk_t, &frame_t, &[1u8; 16], b"hello"));
    }

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Frozen object-plane KAT, mirrored in `vectors/secsec-kat-v1.txt [object]`. Uses
    /// `master_key=[0x11;32]` (the kdf vector key) so the whole vector chain is self-consistent:
    /// a `Chunk` at `gen=1`, `path_salt=[0x01;16]`, plaintext `b"object-plane-kat"`.
    #[test]
    fn object_kat() {
        let m = MasterKey::new(1, [0x11; 32]);
        let salt = [0x01u8; 16];
        let (id, blob) = seal_object(&m, ObjType::Chunk, &salt, b"object-plane-kat");
        assert_eq!(
            hx(&id),
            "7e4b0ee5fbd6047722f1576005bd0b64f25e33b2ea772a9a19679066efc3d285"
        );
        assert_eq!(
            hx(&blob),
            "737365630101010000000093396520adcd7b6c1be2b70da845c23b38eae085e64b6c2143dd3158a62cc9d2c61b3694585207be869bf7f23c68da21"
        );
        // and it opens back to the plaintext (full three-way verify).
        assert_eq!(
            open_object(&m, ObjType::Chunk, &salt, &id, &blob).unwrap(),
            b"object-plane-kat"
        );
    }

    #[test]
    fn seal_open_round_trip_chunk_and_nonpath() {
        let m = mk();
        // a chunk with a per-path salt
        let salt = [9u8; 16];
        let (id, blob) = seal_object(&m, ObjType::Chunk, &salt, b"chunk bytes");
        assert_eq!(
            open_object(&m, ObjType::Chunk, &salt, &id, &blob).unwrap(),
            b"chunk bytes"
        );

        // a non-path object (commit) with ZERO_SALT
        let (cid, cblob) = seal_object(&m, ObjType::Commit, &ZERO_SALT, b"commit bytes");
        assert_eq!(
            open_object(&m, ObjType::Commit, &ZERO_SALT, &cid, &cblob).unwrap(),
            b"commit bytes"
        );
        assert_ne!(id, cid);
    }

    #[test]
    fn determinism_preserves_dedup() {
        let m = mk();
        let salt = [3u8; 16];
        let (id1, blob1) = seal_object(&m, ObjType::Chunk, &salt, b"same");
        let (id2, blob2) = seal_object(&m, ObjType::Chunk, &salt, b"same");
        assert_eq!(id1, id2);
        assert_eq!(blob1, blob2); // identical => deduplicable
    }

    #[test]
    fn open_rejects_tamper_and_wrong_id() {
        let m = mk();
        let salt = [0u8; 16];
        let (id, blob) = seal_object(&m, ObjType::Chunk, &salt, b"secret chunk");

        // flip a ciphertext byte -> AEAD auth fails
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            open_object(&m, ObjType::Chunk, &salt, &id, &bad),
            Err(ObjError::Auth)
        );

        // request a different id than the blob actually is -> wrong per-object key -> auth fails
        let mut other = id;
        other[0] ^= 0x01;
        assert_eq!(
            open_object(&m, ObjType::Chunk, &salt, &other, &blob),
            Err(ObjError::Auth)
        );

        // a blob whose FRAME claims a different generation -> the resolver has no key for it (§8.2);
        // a member who *did* hold gen 1 would pass a key ring containing it and read it fine.
        let m2 = MasterKey::new(2, [0x44; 32]);
        assert!(matches!(
            open_object(&m2, ObjType::Chunk, &salt, &id, &blob),
            Err(ObjError::UnknownGeneration(1))
        ));
    }

    #[test]
    fn padding_round_trips_edge_cases() {
        for case in [
            &b""[..],
            &b"x"[..],
            &[0x00][..],
            &[0x80][..],
            &[0x00, 0x00][..],
            &[0x80, 0x00, 0x00][..],
            &vec![0xABu8; 16 * 1024][..],
            &vec![0u8; 65537][..], // just over a power of two
        ] {
            let padded = pad_chunk(case, Padding::PowerOfTwo);
            assert!(
                padded.len().is_power_of_two(),
                "bucket must be a power of two"
            );
            assert!(padded.len() > case.len());
            assert_eq!(unpad_chunk(&padded, Padding::PowerOfTwo).unwrap(), case);
        }
        // None policy is identity.
        assert_eq!(pad_chunk(b"abc", Padding::None), b"abc");
        assert_eq!(unpad_chunk(b"abc", Padding::None).unwrap(), b"abc");
    }

    #[test]
    fn unpad_rejects_garbage() {
        // all zeros: no 0x80 delimiter
        assert_eq!(
            unpad_chunk(&[0u8; 8], Padding::PowerOfTwo),
            Err(ObjError::BadPadding)
        );
        assert_eq!(
            unpad_chunk(&[], Padding::PowerOfTwo),
            Err(ObjError::BadPadding)
        );
    }

    /// Full file path: chunk (keyed FastCDC) -> pad -> seal -> open -> unpad -> reassemble.
    #[test]
    fn file_round_trip_through_object_plane() {
        let m = mk();
        let cdc = secsec_chunk::Chunker::with_defaults(&m.cdc_seed());
        // deterministic pseudo-random "file"
        let mut hh = blake3::Hasher::new();
        hh.update(b"file");
        let mut xof = hh.finalize_xof();
        let mut file = vec![0u8; 1024 * 1024];
        xof.fill(&mut file);

        let salt = [7u8; 16];
        let mut reassembled = Vec::new();
        for chunk in cdc.chunks(&file) {
            let padded = pad_chunk(chunk, Padding::PowerOfTwo);
            let (id, blob) = seal_object(&m, ObjType::Chunk, &salt, &padded);
            // fetch-and-verify
            let got = open_object(&m, ObjType::Chunk, &salt, &id, &blob).unwrap();
            let unpadded = unpad_chunk(&got, Padding::PowerOfTwo).unwrap();
            reassembled.extend_from_slice(unpadded);
        }
        assert_eq!(reassembled, file);
    }
}
