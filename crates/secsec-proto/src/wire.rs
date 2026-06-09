//! Wire messages for the server API (`finaldesign.md` §11 handshake, §12 RPC). Strict, bounded
//! canonical codecs for the handshake hellos and the request/response types.
//!
//! Every length-prefixed field is bounded by its §19 limit **before allocation** (alloc-bomb guard),
//! and decode is exhausted via [`secsec_canon::Reader::finish`] (no trailing bytes). The transport
//! frames these payloads on QUIC streams (length-prefixed); that framing + the auth wrapper live in
//! the transport/handshake layer.

use crate::server::limits::MAX_HAS_IDS;
use secsec_canon::{CanonError, Reader, Writer};
use secsec_frame::{MAX_BLOB_SIZE, MAX_ROSTER_ENTRY_SIZE};

/// A 256-bit id / hash.
pub type Id = [u8; 32];

/// Errors decoding a wire message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Unknown message tag.
    BadTag(u8),
    /// A `has`/list count exceeded its §19 cap.
    TooLarge,
    /// Strict canonical decode failed (truncation, over-long field, trailing bytes).
    Canon(CanonError),
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::BadTag(t) => write!(f, "unknown wire tag {t}"),
            WireError::TooLarge => f.write_str("list field exceeds its §19 cap"),
            WireError::Canon(e) => write!(f, "canon: {e}"),
        }
    }
}
impl std::error::Error for WireError {}
impl From<CanonError> for WireError {
    fn from(e: CanonError) -> Self {
        WireError::Canon(e)
    }
}

fn read32(r: &mut Reader<'_>) -> Result<Id, WireError> {
    let mut out = [0u8; 32];
    out.copy_from_slice(r.raw(32)?);
    Ok(out)
}

/// The §11 client hello: protocol version + the client's handshake nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// `secsec_version`.
    pub version: u16,
    /// OS-CSPRNG client nonce.
    pub client_nonce: [u8; 32],
}

impl ClientHello {
    /// Canonical encoding `version(u16) ‖ client_nonce(32)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.version).raw(&self.client_nonce);
        w.finish()
    }

    /// Strictly decode a client hello.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        let client_nonce = read32(&mut r)?;
        r.finish()?;
        Ok(Self {
            version,
            client_nonce,
        })
    }
}

/// The §11 server hello: version + server nonce + `host_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// `secsec_version`.
    pub version: u16,
    /// OS-CSPRNG server nonce (single-use challenge).
    pub server_nonce: [u8; 32],
    /// `BLAKE3(SPKI)` of the pinned host key (§11).
    pub host_id: [u8; 32],
}

impl ServerHello {
    /// Canonical encoding `version(u16) ‖ server_nonce(32) ‖ host_id(32)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.version)
            .raw(&self.server_nonce)
            .raw(&self.host_id);
        w.finish()
    }

    /// Strictly decode a server hello.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        let server_nonce = read32(&mut r)?;
        let host_id = read32(&mut r)?;
        r.finish()?;
        Ok(Self {
            version,
            server_nonce,
            host_id,
        })
    }
}

/// A server-API request (§12). The per-op authorization signature ([`crate::WriteAuth`] /
/// [`crate::ReadAuth`]) wraps this on the wire; here is just the operation payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Fetch a blob by id.
    Get {
        /// The content address to fetch.
        id: Id,
    },
    /// Existence check for a batch of ids (≤ [`MAX_HAS_IDS`]).
    Has {
        /// The ids to check, in request order.
        ids: Vec<Id>,
    },
    /// Store an object (idempotent by id).
    Put {
        /// Content address.
        id: Id,
        /// Declared size (server rejects `> 16 MiB` before reading the body).
        declared_size: u32,
        /// The object blob.
        blob: Vec<u8>,
    },
    /// Atomic ref CAS: swap `/refs/<ref_h>` from `old_head` to `new_head` (the new head blob attached).
    CasHead {
        /// Keyed-hash ref name.
        ref_h: Id,
        /// Expected current head id.
        old_head: Id,
        /// New head id.
        new_head: Id,
        /// The new head blob to store.
        new_blob: Vec<u8>,
    },
    /// Append a sigchain entry (the encrypted entry blob).
    RosterAppend {
        /// The stored roster-entry blob.
        entry: Vec<u8>,
    },
}

const T_GET: u8 = 0;
const T_HAS: u8 = 1;
const T_PUT: u8 = 2;
const T_CAS: u8 = 3;
const T_ROSTER: u8 = 4;

impl Request {
    /// Canonical encoding (tag-prefixed).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Request::Get { id } => {
                w.u8(T_GET).raw(id);
            }
            Request::Has { ids } => {
                w.u8(T_HAS).u32(ids.len() as u32);
                for id in ids {
                    w.raw(id);
                }
            }
            Request::Put {
                id,
                declared_size,
                blob,
            } => {
                w.u8(T_PUT).raw(id).u32(*declared_size).bytes(blob);
            }
            Request::CasHead {
                ref_h,
                old_head,
                new_head,
                new_blob,
            } => {
                w.u8(T_CAS)
                    .raw(ref_h)
                    .raw(old_head)
                    .raw(new_head)
                    .bytes(new_blob);
            }
            Request::RosterAppend { entry } => {
                w.u8(T_ROSTER).bytes(entry);
            }
        }
        w.finish()
    }

    /// Strictly decode a request, enforcing every §19 bound before allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let req = match r.u8()? {
            T_GET => Request::Get {
                id: read32(&mut r)?,
            },
            T_HAS => {
                let n = r.u32()? as usize;
                if n > MAX_HAS_IDS {
                    return Err(WireError::TooLarge);
                }
                let mut ids = Vec::with_capacity(n);
                for _ in 0..n {
                    ids.push(read32(&mut r)?);
                }
                Request::Has { ids }
            }
            T_PUT => Request::Put {
                id: read32(&mut r)?,
                declared_size: r.u32()?,
                blob: r.bytes(MAX_BLOB_SIZE)?.to_vec(),
            },
            T_CAS => Request::CasHead {
                ref_h: read32(&mut r)?,
                old_head: read32(&mut r)?,
                new_head: read32(&mut r)?,
                new_blob: r.bytes(MAX_BLOB_SIZE)?.to_vec(),
            },
            T_ROSTER => Request::RosterAppend {
                entry: r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec(),
            },
            other => return Err(WireError::BadTag(other)),
        };
        r.finish()?;
        Ok(req)
    }
}

/// A server error code returned to the client (§12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// The key owns no keyslot (not a rostered device) (§12).
    NotEnrolled,
    /// Per-op authorization failed (bad signature / stale nonce).
    BadAuth,
    /// A rate limit or quota was exceeded (§19).
    RateLimit,
    /// A `has`/`gc` batch exceeded its cap (§12).
    TooManyIds,
    /// `cas-head` lost the compare-and-swap race.
    CasConflict,
    /// Malformed request.
    BadRequest,
    /// Internal server/storage error.
    Internal,
}

/// A server-API response (§12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// `get` result: the blob, or `None` if absent.
    Blob(Option<Vec<u8>>),
    /// `has` result: one bool per requested id, in order.
    Exists(Vec<bool>),
    /// The write op (`put`/`cas-head`/`roster-append`) was accepted.
    Ok,
    /// The op was rejected with this code.
    Err(ErrorCode),
}

const R_BLOB: u8 = 0;
const R_EXISTS: u8 = 1;
const R_OK: u8 = 2;
const R_ERR: u8 = 3;

fn code_to_u8(c: ErrorCode) -> u8 {
    match c {
        ErrorCode::NotEnrolled => 0,
        ErrorCode::BadAuth => 1,
        ErrorCode::RateLimit => 2,
        ErrorCode::TooManyIds => 3,
        ErrorCode::CasConflict => 4,
        ErrorCode::BadRequest => 5,
        ErrorCode::Internal => 6,
    }
}
fn code_from_u8(v: u8) -> Result<ErrorCode, WireError> {
    Ok(match v {
        0 => ErrorCode::NotEnrolled,
        1 => ErrorCode::BadAuth,
        2 => ErrorCode::RateLimit,
        3 => ErrorCode::TooManyIds,
        4 => ErrorCode::CasConflict,
        5 => ErrorCode::BadRequest,
        6 => ErrorCode::Internal,
        other => return Err(WireError::BadTag(other)),
    })
}

impl Response {
    /// Canonical encoding (tag-prefixed).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Response::Blob(None) => {
                w.u8(R_BLOB).u8(0);
            }
            Response::Blob(Some(b)) => {
                w.u8(R_BLOB).u8(1).bytes(b);
            }
            Response::Exists(bits) => {
                w.u8(R_EXISTS).u32(bits.len() as u32);
                for b in bits {
                    w.u8(u8::from(*b));
                }
            }
            Response::Ok => {
                w.u8(R_OK);
            }
            Response::Err(c) => {
                w.u8(R_ERR).u8(code_to_u8(*c));
            }
        }
        w.finish()
    }

    /// Strictly decode a response.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let resp = match r.u8()? {
            R_BLOB => match r.u8()? {
                0 => Response::Blob(None),
                1 => Response::Blob(Some(r.bytes(MAX_BLOB_SIZE)?.to_vec())),
                other => return Err(WireError::BadTag(other)),
            },
            R_EXISTS => {
                let n = r.u32()? as usize;
                if n > MAX_HAS_IDS {
                    return Err(WireError::TooLarge);
                }
                let mut bits = Vec::with_capacity(n);
                for _ in 0..n {
                    bits.push(r.u8()? != 0);
                }
                Response::Exists(bits)
            }
            R_OK => Response::Ok,
            R_ERR => Response::Err(code_from_u8(r.u8()?)?),
            other => return Err(WireError::BadTag(other)),
        };
        r.finish()?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trips() {
        let c = ClientHello {
            version: 1,
            client_nonce: [0xC1; 32],
        };
        assert_eq!(ClientHello::decode(&c.encode()).unwrap(), c);
        let s = ServerHello {
            version: 1,
            server_nonce: [0x5e; 32],
            host_id: [0x40; 32],
        };
        assert_eq!(ServerHello::decode(&s.encode()).unwrap(), s);
    }

    #[test]
    fn request_round_trips_every_variant() {
        let reqs = [
            Request::Get { id: [1; 32] },
            Request::Has {
                ids: vec![[2; 32], [3; 32]],
            },
            Request::Put {
                id: [4; 32],
                declared_size: 11,
                blob: b"hello world".to_vec(),
            },
            Request::CasHead {
                ref_h: [5; 32],
                old_head: [6; 32],
                new_head: [7; 32],
                new_blob: b"head".to_vec(),
            },
            Request::RosterAppend {
                entry: b"entry-bytes".to_vec(),
            },
        ];
        for req in reqs {
            assert_eq!(Request::decode(&req.encode()).unwrap(), req);
        }
    }

    #[test]
    fn response_round_trips_every_variant() {
        let resps = [
            Response::Blob(None),
            Response::Blob(Some(b"blob".to_vec())),
            Response::Exists(vec![true, false, true]),
            Response::Ok,
            Response::Err(ErrorCode::CasConflict),
            Response::Err(ErrorCode::NotEnrolled),
        ];
        for resp in resps {
            assert_eq!(Response::decode(&resp.encode()).unwrap(), resp);
        }
    }

    #[test]
    fn decode_rejects_bad_tag_and_trailing_bytes() {
        assert_eq!(Request::decode(&[0xFF]), Err(WireError::BadTag(0xFF)));
        let mut bytes = Request::Get { id: [1; 32] }.encode();
        bytes.push(0x00);
        assert!(matches!(
            Request::decode(&bytes),
            Err(WireError::Canon(CanonError::TrailingBytes { .. }))
        ));
    }

    #[test]
    fn has_count_over_cap_is_rejected_before_alloc() {
        // a `has` claiming more than MAX_HAS_IDS ids must be rejected on the count, not allocated.
        let mut w = Writer::new();
        w.u8(T_HAS).u32((MAX_HAS_IDS + 1) as u32);
        assert_eq!(Request::decode(&w.finish()), Err(WireError::TooLarge));
    }

    #[test]
    fn put_blob_over_max_is_rejected() {
        // claim a blob length far over MAX_BLOB_SIZE; canon rejects on the length prefix.
        let mut w = Writer::new();
        w.u8(T_PUT).raw(&[0u8; 32]).u32(0).u32(u32::MAX); // bytes() length prefix = u32::MAX
        assert!(matches!(
            Request::decode(&w.finish()),
            Err(WireError::Canon(CanonError::LengthExceedsMax { .. }))
        ));
    }
}
