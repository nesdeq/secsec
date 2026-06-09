//! `secsec-frame` — object framing, type tags, and decoder bounds (`finaldesign.md` §9.1, §19).
//!
//! Every stored object is `blob = FRAME ‖ ctx_tag(32) ‖ ciphertext`, where
//! `FRAME = MAGIC(4) ‖ format_version(u8) ‖ algo_id(u8) ‖ gen(u32) ‖ type(u8)` (11 bytes).
//!
//! The `FRAME` doubles as the AEAD associated data (`AD = FRAME ‖ id`, §9.4), so framing,
//! key derivation (`type`/`gen` feed `secsec-kdf`), and the committing AEAD are bound together.
//!
//! Two hard rules from the spec are enforced here:
//! - **Don't trust attacker-set FRAME fields** (§18): [`parse_blob`] takes the `Frame` the client
//!   *expects* for the id it requested and rejects any blob whose decoded FRAME differs.
//! - **Bounds before allocation** (§9.1/§19): sizes are range-checked before any work.

#![forbid(unsafe_code)]

use core::fmt;
use secsec_canon::{Reader, Writer};

/// 4-byte object magic.
pub const MAGIC: [u8; 4] = *b"ssec";

/// Current on-disk format version.
pub const FORMAT_VERSION_V1: u8 = 1;
/// Compile-time format-version floor (§16): anything below this is rejected outright.
pub const MIN_FORMAT_VERSION: u8 = 1;

/// `algo_id` for the classical suite (ChaCha20-Poly1305 CTX AEAD; X25519/HPKE keyslots).
pub const ALGO_CLASSICAL_V1: u8 = 1;
/// Compile-time algorithm floor (§16): `algo_id` below this is rejected as a downgrade.
pub const MIN_ALGO_ID: u8 = 1;

/// Encoded FRAME length in bytes.
pub const FRAME_LEN: usize = 11;
/// CTX commitment-tag length in bytes (matches `secsec_aead::CtxTag`).
pub const CTX_TAG_LEN: usize = 32;
/// Content-address / id length in bytes.
pub const ID_LEN: usize = 32;

// §19 normative decoder bounds (enforced before allocation).
/// Maximum size of any single stored object, in bytes.
pub const MAX_BLOB_SIZE: usize = 16 * 1024 * 1024;
/// Maximum tree nesting depth.
pub const MAX_TREE_DEPTH: usize = 64;
/// Maximum directory fan-out (entries per tree node).
pub const MAX_TREE_FANOUT: usize = 65_536;
/// Maximum size of a single roster sigchain entry, in bytes.
pub const MAX_ROSTER_ENTRY_SIZE: usize = 4 * 1024;
/// Maximum number of elements in any decoded list field.
pub const MAX_LIST_ELEMENTS: usize = 4_096;

/// The object `type` byte. Feeds `enc_key[g][t]` / `id_key[g][t]` (§9.5) and the FRAME.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    /// Content-defined file slice.
    Chunk = 0,
    /// Directory listing.
    Tree = 1,
    /// Snapshot commit.
    Commit = 2,
    /// Signed per-ref head pointer.
    Head = 3,
    /// Roster sigchain entry.
    RosterEntry = 4,
    /// Per-device master-key wrap.
    Keyslot = 5,
    /// Data key-history wrap (§8.2).
    Keyhist = 6,
    /// Roster-key history wrap (§8.2).
    RosterKeyhist = 7,
    /// Recovery keyslot (§8.6).
    Recovery = 8,
}

impl ObjType {
    /// The wire `type` byte.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a `type` byte; `None` for an unknown value.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Chunk,
            1 => Self::Tree,
            2 => Self::Commit,
            3 => Self::Head,
            4 => Self::RosterEntry,
            5 => Self::Keyslot,
            6 => Self::Keyhist,
            7 => Self::RosterKeyhist,
            8 => Self::Recovery,
            _ => return None,
        })
    }
}

/// A decoded object FRAME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// Format version.
    pub format_version: u8,
    /// Algorithm-suite id.
    pub algo_id: u8,
    /// Master-key generation `g`.
    pub gen: u32,
    /// Object type.
    pub obj_type: ObjType,
}

impl Frame {
    /// A FRAME at the current version + classical algorithm suite.
    #[must_use]
    pub fn v1(gen: u32, obj_type: ObjType) -> Self {
        Self {
            format_version: FORMAT_VERSION_V1,
            algo_id: ALGO_CLASSICAL_V1,
            gen,
            obj_type,
        }
    }

    /// Encode to the fixed 11-byte FRAME.
    #[must_use]
    pub fn encode(&self) -> [u8; FRAME_LEN] {
        let mut w = Writer::with_capacity(FRAME_LEN);
        w.raw(&MAGIC)
            .u8(self.format_version)
            .u8(self.algo_id)
            .u32(self.gen)
            .u8(self.obj_type.as_u8());
        let v = w.finish();
        let mut out = [0u8; FRAME_LEN];
        out.copy_from_slice(&v);
        out
    }

    /// Decode and validate an 11-byte FRAME: magic, the compile-time version/algorithm floor
    /// (§16), and a known object type. `bytes` must be exactly [`FRAME_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Frame, FrameError> {
        let mut r = Reader::new(bytes);
        let magic = r.raw(4).map_err(|_| FrameError::Truncated)?;
        if magic != MAGIC.as_slice() {
            return Err(FrameError::BadMagic);
        }
        let format_version = r.u8().map_err(|_| FrameError::Truncated)?;
        if format_version < MIN_FORMAT_VERSION || format_version > FORMAT_VERSION_V1 {
            return Err(FrameError::UnsupportedFormatVersion(format_version));
        }
        let algo_id = r.u8().map_err(|_| FrameError::Truncated)?;
        if algo_id < MIN_ALGO_ID || algo_id != ALGO_CLASSICAL_V1 {
            return Err(FrameError::UnsupportedAlgo(algo_id));
        }
        let gen = r.u32().map_err(|_| FrameError::Truncated)?;
        let t = r.u8().map_err(|_| FrameError::Truncated)?;
        let obj_type = ObjType::from_u8(t).ok_or(FrameError::UnknownType(t))?;
        r.finish().map_err(|_| FrameError::Truncated)?;
        Ok(Frame {
            format_version,
            algo_id,
            gen,
            obj_type,
        })
    }
}

/// The associated data for the per-object AEAD (§9.4): `FRAME ‖ id` (fixed 43 bytes).
#[must_use]
pub fn aead_ad(frame: &Frame, id: &[u8; ID_LEN]) -> [u8; FRAME_LEN + ID_LEN] {
    let mut ad = [0u8; FRAME_LEN + ID_LEN];
    ad[..FRAME_LEN].copy_from_slice(&frame.encode());
    ad[FRAME_LEN..].copy_from_slice(id);
    ad
}

/// Assemble a stored blob: `FRAME ‖ ctx_tag(32) ‖ ciphertext`.
#[must_use]
pub fn assemble_blob(frame: &Frame, ctx_tag: &[u8; CTX_TAG_LEN], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_LEN + CTX_TAG_LEN + ct.len());
    out.extend_from_slice(&frame.encode());
    out.extend_from_slice(ctx_tag);
    out.extend_from_slice(ct);
    out
}

/// Parse a stored blob into `(ctx_tag, ciphertext)`, enforcing the §19 size bound **before** any
/// work and verifying the decoded FRAME equals `expected` (§18 — never trust server-supplied FRAME
/// fields; the client derives `expected` from the `(gen, type)` it requested).
pub fn parse_blob<'a>(
    bytes: &'a [u8],
    expected: &Frame,
) -> Result<(&'a [u8; CTX_TAG_LEN], &'a [u8]), FrameError> {
    if bytes.len() > MAX_BLOB_SIZE {
        return Err(FrameError::BlobTooLarge {
            len: bytes.len(),
            max: MAX_BLOB_SIZE,
        });
    }
    if bytes.len() < FRAME_LEN + CTX_TAG_LEN {
        return Err(FrameError::ShortBlob);
    }
    let frame = Frame::decode(&bytes[..FRAME_LEN])?;
    if &frame != expected {
        return Err(FrameError::FrameMismatch);
    }
    let ctx_tag: &[u8; CTX_TAG_LEN] = bytes[FRAME_LEN..FRAME_LEN + CTX_TAG_LEN]
        .try_into()
        .expect("slice is exactly CTX_TAG_LEN");
    let ct = &bytes[FRAME_LEN + CTX_TAG_LEN..];
    Ok((ctx_tag, ct))
}

/// Errors from FRAME / blob decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// FRAME magic did not match.
    BadMagic,
    /// Format version below the floor or above what this build understands.
    UnsupportedFormatVersion(u8),
    /// Algorithm id below the floor or not in the supported set (downgrade guard, §16).
    UnsupportedAlgo(u8),
    /// Unknown object `type` byte.
    UnknownType(u8),
    /// FRAME bytes were truncated.
    Truncated,
    /// Blob exceeded the §19 maximum object size.
    BlobTooLarge {
        /// Observed length.
        len: usize,
        /// Maximum permitted (`MAX_BLOB_SIZE`).
        max: usize,
    },
    /// Blob is too short to contain a FRAME and a commitment tag.
    ShortBlob,
    /// Decoded FRAME did not equal the FRAME the client expected (§18).
    FrameMismatch,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::BadMagic => f.write_str("bad object magic"),
            FrameError::UnsupportedFormatVersion(v) => write!(f, "unsupported format_version {v}"),
            FrameError::UnsupportedAlgo(a) => write!(f, "unsupported algo_id {a}"),
            FrameError::UnknownType(t) => write!(f, "unknown object type {t}"),
            FrameError::Truncated => f.write_str("truncated FRAME"),
            FrameError::BlobTooLarge { len, max } => {
                write!(f, "blob length {len} exceeds maximum {max}")
            }
            FrameError::ShortBlob => f.write_str("blob too short for FRAME + commitment tag"),
            FrameError::FrameMismatch => f.write_str("decoded FRAME does not match expected FRAME"),
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_encode_kat() {
        // Frame::v1(gen=1, Chunk) = "ssec" ‖ 01 ‖ 01 ‖ 01000000 ‖ 00
        let f = Frame::v1(1, ObjType::Chunk);
        assert_eq!(
            f.encode(),
            [0x73, 0x73, 0x65, 0x63, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(f.encode().len(), FRAME_LEN);
    }

    #[test]
    fn frame_round_trip_all_types() {
        for t in [
            ObjType::Chunk,
            ObjType::Tree,
            ObjType::Commit,
            ObjType::Head,
            ObjType::RosterEntry,
            ObjType::Keyslot,
            ObjType::Keyhist,
            ObjType::RosterKeyhist,
            ObjType::Recovery,
        ] {
            let f = Frame::v1(42, t);
            assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
        }
    }

    #[test]
    fn decode_rejects_bad_magic_version_algo_type() {
        let mut f = Frame::v1(1, ObjType::Chunk).encode();
        f[0] ^= 0xFF;
        assert_eq!(Frame::decode(&f), Err(FrameError::BadMagic));

        let mut f = Frame::v1(1, ObjType::Chunk).encode();
        f[4] = 0; // format_version below floor
        assert_eq!(
            Frame::decode(&f),
            Err(FrameError::UnsupportedFormatVersion(0))
        );

        let mut f = Frame::v1(1, ObjType::Chunk).encode();
        f[5] = 2; // unknown algo
        assert_eq!(Frame::decode(&f), Err(FrameError::UnsupportedAlgo(2)));

        let mut f = Frame::v1(1, ObjType::Chunk).encode();
        f[10] = 99; // unknown type
        assert_eq!(Frame::decode(&f), Err(FrameError::UnknownType(99)));
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(Frame::decode(&[0u8; 10]), Err(FrameError::BadMagic)); // magic mismatch first
        let mut short = Frame::v1(1, ObjType::Chunk).encode().to_vec();
        short.pop();
        assert_eq!(Frame::decode(&short), Err(FrameError::Truncated));
        let mut long = Frame::v1(1, ObjType::Chunk).encode().to_vec();
        long.push(0);
        assert_eq!(Frame::decode(&long), Err(FrameError::Truncated)); // trailing byte
    }

    #[test]
    fn parse_blob_enforces_bounds_and_frame_match() {
        let frame = Frame::v1(3, ObjType::Chunk);
        let tag = [7u8; CTX_TAG_LEN];
        let blob = assemble_blob(&frame, &tag, b"ciphertext");
        let (got_tag, got_ct) = parse_blob(&blob, &frame).unwrap();
        assert_eq!(got_tag, &tag);
        assert_eq!(got_ct, b"ciphertext");

        // §18: a blob whose FRAME says a different generation must be rejected.
        let wrong_expected = Frame::v1(4, ObjType::Chunk);
        assert_eq!(
            parse_blob(&blob, &wrong_expected),
            Err(FrameError::FrameMismatch)
        );

        // too short
        assert_eq!(parse_blob(&[0u8; 5], &frame), Err(FrameError::ShortBlob));
    }

    /// End-to-end object-plane crypto: derive key (kdf) → AD = FRAME‖id → seal (aead) →
    /// assemble blob → parse blob (with expected FRAME) → open. And a tampered FRAME must break it.
    #[test]
    fn object_plane_round_trip() {
        let mk = secsec_kdf::MasterKey::new(1, [0x55; 32]);
        let frame = Frame::v1(1, ObjType::Chunk);
        let id = [0xABu8; ID_LEN];
        let enc = mk.enc_key(frame.obj_type.as_u8());
        let k_obj = secsec_kdf::obj_key(&enc, &id);

        let ad = aead_ad(&frame, &id);
        let (tag, ct) = secsec_aead::seal(&k_obj, &ad, b"file chunk contents");
        let blob = assemble_blob(&frame, &tag, &ct);

        let (got_tag, got_ct) = parse_blob(&blob, &frame).unwrap();
        let pt = secsec_aead::open(&k_obj, &aead_ad(&frame, &id), got_tag, got_ct).unwrap();
        assert_eq!(pt, b"file chunk contents");

        // Flip a FRAME byte in the stored blob: parse rejects it (FRAME mismatch) before the AEAD
        // would even be consulted — and even if forced through, the AD would differ and open fails.
        let mut bad = blob.clone();
        bad[6] ^= 0x01; // a gen byte
        assert!(parse_blob(&bad, &frame).is_err());
    }
}
