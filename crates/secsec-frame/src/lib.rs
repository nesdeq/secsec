//! Object framing, type tags, and the §19 decoder bounds (`secsec-Design.md` §9.1, §19).

#![forbid(unsafe_code)]

use core::fmt;
use secsec_canon::{Reader, Writer};

/// 4-byte object magic.
pub(crate) const MAGIC: [u8; 4] = *b"ssec";

/// Format version of every object type except salted roster entries.
pub(crate) const FORMAT_VERSION_V1: u8 = 1;
/// Format version of a salted roster entry (§9.5); readers still accept v1 entries.
pub(crate) const FORMAT_VERSION_V2: u8 = 2;
/// Compile-time format-version floor (§16).
pub(crate) const MIN_FORMAT_VERSION: u8 = 1;
/// Highest format version this build decodes.
pub(crate) const MAX_FORMAT_VERSION: u8 = FORMAT_VERSION_V2;

/// FRAME `algo_id` of the CTX object suite (§9.4), a namespace separate from the keyslot KEM id (§8.3).
pub(crate) const ALGO_V1: u8 = 1;
/// Compile-time algorithm floor (§16).
pub const MIN_ALGO_ID: u8 = 1;

/// Encoded FRAME length in bytes.
pub const FRAME_LEN: usize = 11;
/// CTX commitment-tag length in bytes (matches `secsec_aead::CtxTag`).
pub const CTX_TAG_LEN: usize = 32;
/// Content-address / id length in bytes.
pub const ID_LEN: usize = 32;

/// Maximum size of any single stored object, in bytes (§19).
pub const MAX_BLOB_SIZE: usize = 16 * 1024 * 1024;
/// Maximum tree nesting depth (§19).
pub const MAX_TREE_DEPTH: usize = 64;
/// Maximum directory fan-out, entries per tree node (§19).
pub const MAX_TREE_FANOUT: usize = 65_536;
/// Maximum size of a single roster sigchain entry, in bytes (§19).
pub const MAX_ROSTER_ENTRY_SIZE: usize = 4 * 1024;
/// Maximum number of elements in any decoded list field (§19).
pub const MAX_LIST_ELEMENTS: usize = 4_096;
/// Maximum tree entry name length in bytes (§19).
pub const MAX_NAME_LEN: usize = 4_096;
/// Maximum chunk ids per file: exactly what a [`MAX_BLOB_SIZE`] tree can hold at [`ID_LEN`] bytes each.
pub const MAX_CHUNKS_PER_FILE: usize = MAX_BLOB_SIZE / ID_LEN;

/// The object `type` byte; feeds `enc_key[g][t]` / `id_key[g][t]` (§9.5) and the FRAME.
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
    /// Data key-history wrap (§8.2).
    Keyhist = 6,
    /// Roster-key history wrap (§8.2).
    RosterKeyhist = 7,
}

impl ObjType {
    /// The wire `type` byte.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a `type` byte; `None` for an unknown value.
    #[must_use]
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Chunk,
            1 => Self::Tree,
            2 => Self::Commit,
            3 => Self::Head,
            4 => Self::RosterEntry,
            6 => Self::Keyhist,
            7 => Self::RosterKeyhist,
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
    /// A format-v1 FRAME at the current AEAD suite.
    #[must_use]
    pub fn v1(gen: u32, obj_type: ObjType) -> Self {
        Self {
            format_version: FORMAT_VERSION_V1,
            algo_id: ALGO_V1,
            gen,
            obj_type,
        }
    }

    /// A format-v2 FRAME at the current AEAD suite (salted roster entries, §9.5).
    #[must_use]
    pub fn v2(gen: u32, obj_type: ObjType) -> Self {
        Self {
            format_version: FORMAT_VERSION_V2,
            ..Self::v1(gen, obj_type)
        }
    }

    /// Whether this FRAME carries the v2 format version.
    #[must_use]
    pub fn is_v2(&self) -> bool {
        self.format_version == FORMAT_VERSION_V2
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

    /// Decode and validate exactly [`FRAME_LEN`] bytes: magic, version/algorithm floors (§16), known type.
    pub fn decode(bytes: &[u8]) -> Result<Frame, FrameError> {
        let mut r = Reader::new(bytes);
        let magic = r.raw(4).map_err(|_| FrameError::Truncated)?;
        if magic != MAGIC.as_slice() {
            return Err(FrameError::BadMagic);
        }
        let format_version = r.u8().map_err(|_| FrameError::Truncated)?;
        if !(MIN_FORMAT_VERSION..=MAX_FORMAT_VERSION).contains(&format_version) {
            return Err(FrameError::UnsupportedFormatVersion(format_version));
        }
        let algo_id = r.u8().map_err(|_| FrameError::Truncated)?;
        if algo_id < MIN_ALGO_ID || algo_id != ALGO_V1 {
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

/// The per-object AEAD associated data (§9.4): `FRAME ‖ id`.
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

/// Split a stored blob into `(ctx_tag, ciphertext)` after the size bound and an exact match against `expected` (§18).
pub fn parse_blob<'a>(
    bytes: &'a [u8],
    expected: &Frame,
) -> Result<(&'a [u8; CTX_TAG_LEN], &'a [u8]), FrameError> {
    let rest = parse_frame_prefix(bytes, expected)?;
    if rest.len() < CTX_TAG_LEN {
        return Err(FrameError::ShortBlob);
    }
    let (tag, ct) = rest.split_at(CTX_TAG_LEN);
    let ctx_tag: &[u8; CTX_TAG_LEN] = tag.try_into().expect("slice is exactly CTX_TAG_LEN");
    Ok((ctx_tag, ct))
}

/// Check the size bound and that the leading FRAME equals `expected` (§18); returns the bytes after it.
pub fn parse_frame_prefix<'a>(bytes: &'a [u8], expected: &Frame) -> Result<&'a [u8], FrameError> {
    if bytes.len() > MAX_BLOB_SIZE {
        return Err(FrameError::BlobTooLarge {
            len: bytes.len(),
            max: MAX_BLOB_SIZE,
        });
    }
    if bytes.len() < FRAME_LEN {
        return Err(FrameError::ShortBlob);
    }
    if &Frame::decode(&bytes[..FRAME_LEN])? != expected {
        return Err(FrameError::FrameMismatch);
    }
    Ok(&bytes[FRAME_LEN..])
}

/// Errors from FRAME / blob decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// FRAME magic did not match.
    BadMagic,
    /// Format version below the floor or above what this build understands.
    UnsupportedFormatVersion(u8),
    /// Algorithm id below the floor or not in the supported set (§16).
    UnsupportedAlgo(u8),
    /// Unknown object `type` byte.
    UnknownType(u8),
    /// FRAME bytes were truncated or had trailing bytes.
    Truncated,
    /// Blob exceeded the §19 maximum object size.
    BlobTooLarge {
        /// Observed length.
        len: usize,
        /// Maximum permitted (`MAX_BLOB_SIZE`).
        max: usize,
    },
    /// Blob too short for its FRAME and tag.
    ShortBlob,
    /// Decoded FRAME differs from the FRAME the client expected (§18).
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
        let f = Frame::v1(1, ObjType::Chunk);
        assert_eq!(
            f.encode(),
            [0x73, 0x73, 0x65, 0x63, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(f.encode().len(), FRAME_LEN);
        let v2 = Frame::v2(1, ObjType::RosterEntry);
        assert_eq!(v2.encode()[4], FORMAT_VERSION_V2);
        assert!(v2.is_v2());
    }

    #[test]
    fn frame_round_trip_all_types_and_versions() {
        for t in [
            ObjType::Chunk,
            ObjType::Tree,
            ObjType::Commit,
            ObjType::Head,
            ObjType::RosterEntry,
            ObjType::Keyhist,
            ObjType::RosterKeyhist,
        ] {
            for f in [Frame::v1(42, t), Frame::v2(42, t)] {
                assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
            }
        }
    }

    #[test]
    fn decode_rejects_bad_magic_version_algo_type() {
        let mut f = Frame::v1(1, ObjType::Chunk).encode();
        f[0] ^= 0xFF;
        assert_eq!(Frame::decode(&f), Err(FrameError::BadMagic));

        let mut f = Frame::v1(1, ObjType::Chunk).encode();
        f[4] = 0;
        assert_eq!(
            Frame::decode(&f),
            Err(FrameError::UnsupportedFormatVersion(0))
        );
        f[4] = MAX_FORMAT_VERSION + 1;
        assert_eq!(
            Frame::decode(&f),
            Err(FrameError::UnsupportedFormatVersion(MAX_FORMAT_VERSION + 1))
        );

        let mut f = Frame::v1(1, ObjType::Chunk).encode();
        f[5] = 2;
        assert_eq!(Frame::decode(&f), Err(FrameError::UnsupportedAlgo(2)));

        let mut f = Frame::v1(1, ObjType::Chunk).encode();
        f[10] = 99;
        assert_eq!(Frame::decode(&f), Err(FrameError::UnknownType(99)));
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(Frame::decode(&[0u8; 10]), Err(FrameError::BadMagic));
        let mut short = Frame::v1(1, ObjType::Chunk).encode().to_vec();
        short.pop();
        assert_eq!(Frame::decode(&short), Err(FrameError::Truncated));
        let mut long = Frame::v1(1, ObjType::Chunk).encode().to_vec();
        long.push(0);
        assert_eq!(Frame::decode(&long), Err(FrameError::Truncated));
    }

    #[test]
    fn parse_blob_enforces_bounds_and_frame_match() {
        let frame = Frame::v1(3, ObjType::Chunk);
        let tag = [7u8; CTX_TAG_LEN];
        let blob = assemble_blob(&frame, &tag, b"ciphertext");
        let (got_tag, got_ct) = parse_blob(&blob, &frame).unwrap();
        assert_eq!(got_tag, &tag);
        assert_eq!(got_ct, b"ciphertext");

        // §18: another generation, or the same frame at another format version, is a mismatch.
        assert_eq!(
            parse_blob(&blob, &Frame::v1(4, ObjType::Chunk)),
            Err(FrameError::FrameMismatch)
        );
        assert_eq!(
            parse_blob(&blob, &Frame::v2(3, ObjType::Chunk)),
            Err(FrameError::FrameMismatch)
        );
        assert_eq!(parse_blob(&[0u8; 5], &frame), Err(FrameError::ShortBlob));
        assert_eq!(
            parse_blob(&blob[..FRAME_LEN + 4], &frame),
            Err(FrameError::ShortBlob)
        );
    }

    /// kdf key → AD = FRAME‖id → seal → assemble → parse → open; a tampered FRAME breaks it.
    #[test]
    fn object_plane_round_trip() {
        let mk = secsec_kdf::MasterKey::new(1, [0x55; 32]);
        let frame = Frame::v1(1, ObjType::Chunk);
        let id = [0xABu8; ID_LEN];
        let enc = mk.enc_key(frame.obj_type.as_u8());
        let k_obj = secsec_kdf::obj_key(&enc, &id);

        let ad = aead_ad(&frame, &id);
        let (tag, ct) = secsec_aead::seal(
            secsec_aead::UniqueKey::new(&k_obj),
            &ad,
            b"file chunk contents",
        );
        let blob = assemble_blob(&frame, &tag, &ct);

        let (got_tag, got_ct) = parse_blob(&blob, &frame).unwrap();
        let pt = secsec_aead::open(&k_obj, &aead_ad(&frame, &id), got_tag, got_ct).unwrap();
        assert_eq!(pt, b"file chunk contents");

        let mut bad = blob.clone();
        bad[6] ^= 0x01;
        assert!(parse_blob(&bad, &frame).is_err());
    }
}
