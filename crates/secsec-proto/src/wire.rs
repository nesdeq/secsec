//! Wire messages for the handshake (§11) and the RPC surface (§12): strict, bounded canonical codecs.

use crate::server::limits::MAX_HAS_IDS;
use crate::PUSH_ID_LEN;
use secsec_canon::{CanonError, Reader, Writer};
use secsec_frame::{MAX_BLOB_SIZE, MAX_LIST_ELEMENTS, MAX_ROSTER_ENTRY_SIZE};
use secsec_sig::MAX_SIG_LEN;

/// A 256-bit id / hash.
pub type Id = [u8; 32];

/// Maximum canonical device-pubkey length (an Ed25519 SSH encoding is 51 bytes).
pub(crate) const MAX_PUBKEY: usize = 1024;
/// Maximum encoded `Request`: a 16 MiB blob plus envelope.
pub const MAX_REQUEST_LEN: usize = MAX_BLOB_SIZE + 4096;
/// Maximum encoded `Response`: a 16 MiB blob plus envelope.
pub const MAX_RESPONSE_LEN: usize = MAX_BLOB_SIZE + 4096;

/// The largest genesis [`Request::RosterBatch`]: one entry and one keyslot, nothing else.
const GENESIS_BATCH_MAX: usize = 1
    + 32
    + 4
    + (4 + MAX_ROSTER_ENTRY_SIZE)
    + 4
    + (32 + 4 + 4 + MAX_ROSTER_ENTRY_SIZE)
    + 1
    + 1
    + 4
    + 1;
/// The largest [`Request::PairPut`].
const PAIR_PUT_MAX: usize = 1 + 32 + 4 + MAX_ROSTER_ENTRY_SIZE;
const _: () = assert!(PAIR_PUT_MAX <= GENESIS_BATCH_MAX);
/// The largest [`AuthedRequest`] a key without a keyslot can send (pairing or the genesis batch).
pub const MAX_UNENROLLED_AUTHED_LEN: usize = 4 + MAX_SIG_LEN + 4 + GENESIS_BATCH_MAX;
/// The largest [`AuthedRequest`] any key can send.
pub const MAX_AUTHED_LEN: usize = 4 + MAX_SIG_LEN + 4 + MAX_REQUEST_LEN;

/// Errors decoding or validating a wire message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Unknown message tag.
    BadTag(u8),
    /// A list count exceeded its §19 cap.
    TooLarge,
    /// A field exceeded its bound on the write side.
    FieldTooLong,
    /// Strict canonical decode failed.
    Canon(CanonError),
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::BadTag(t) => write!(f, "unknown wire tag {t}"),
            WireError::TooLarge => f.write_str("list field exceeds its §19 cap"),
            WireError::FieldTooLong => f.write_str("field exceeds its §19 bound"),
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

fn read_push_id(r: &mut Reader<'_>) -> Result<[u8; PUSH_ID_LEN], WireError> {
    let mut out = [0u8; PUSH_ID_LEN];
    out.copy_from_slice(r.raw(PUSH_ID_LEN)?);
    Ok(out)
}

/// A strict `0`/`1` presence byte.
fn read_flag(r: &mut Reader<'_>) -> Result<bool, WireError> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        t => Err(WireError::BadTag(t)),
    }
}

/// A `u32` list count bounded by `max` before anything is allocated.
fn read_count(r: &mut Reader<'_>, max: usize) -> Result<usize, WireError> {
    let n = r.u32()? as usize;
    if n > max {
        return Err(WireError::TooLarge);
    }
    Ok(n)
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
    /// Encoded length.
    pub const LEN: usize = 2 + 32;

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
    /// Encoded length.
    pub const LEN: usize = 2 + 32 + 32;

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

/// One keyslot carried by a [`Request::RosterBatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyslotPut {
    /// Owner device id.
    pub device_id: Id,
    /// Generation the keyslot wraps.
    pub gen: u32,
    /// Opaque `algo_id ‖ body` keyslot (§8.3).
    pub blob: Vec<u8>,
}

/// A head swap carried by a [`Request::RosterBatch`] (the revoke-time re-sign, §8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadPut {
    /// Keyed-hash ref name.
    pub ref_h: Id,
    /// Expected `BLAKE3` of the current head blob.
    pub old_head: Id,
    /// The new head blob.
    pub new_blob: Vec<u8>,
}

/// A server-API request (§12); the per-op signature wraps it as an [`AuthedRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Fetch a blob by id.
    Get {
        /// The content address.
        id: Id,
    },
    /// Durable existence for up to [`MAX_HAS_IDS`] ids.
    Has {
        /// The ids, in request order.
        ids: Vec<Id>,
    },
    /// Stage an object under an in-flight push until its `cas-head` promotes it (§15).
    Put {
        /// Content address.
        id: Id,
        /// Declared size, rejected above 16 MiB before the body is used.
        declared_size: u32,
        /// The per-attempt push id (§15).
        push_id: [u8; PUSH_ID_LEN],
        /// The object blob.
        blob: Vec<u8>,
    },
    /// Atomic ref CAS promoting `promote`'s staging in the same transaction (§12, §15).
    CasHead {
        /// Keyed-hash ref name.
        ref_h: Id,
        /// Expected `BLAKE3` of the current head blob (all-zero = absent).
        old_head: Id,
        /// `BLAKE3` of `new_blob`.
        new_head: Id,
        /// The push whose staging this swap promotes.
        promote: [u8; PUSH_ID_LEN],
        /// The new head blob.
        new_blob: Vec<u8>,
    },
    /// Every roster-side write of one sigchain operation, atomic under the tip CAS (§8.1, §8.4, §12).
    RosterBatch {
        /// `BLAKE3` of the current tip entry blob, or all-zero for genesis.
        old_tip: Id,
        /// Sealed entry blobs appended in order.
        entries: Vec<Vec<u8>>,
        /// Keyslots written.
        keyslots: Vec<KeyslotPut>,
        /// Data key-history wrap `(g, wrap)`; one the chain has rotated past is never replaced.
        keyhist: Option<(u32, Vec<u8>)>,
        /// Roster-key-history wrap `(g, wrap)`; one the chain has rotated past is never replaced.
        roster_keyhist: Option<(u32, Vec<u8>)>,
        /// Devices whose keyslots at every generation are deleted.
        revoke: Vec<Id>,
        /// Optional head swap under its own CAS.
        head: Option<HeadPut>,
    },
    /// Fetch the head blob at `/refs/<ref_h>` (§13).
    GetRef {
        /// `H = keyed_hash(ref_name_key, ref_name)`.
        ref_h: Id,
    },
    /// Fetch the sigchain entry at `/roster/<seq>` (§13), absent past the tip.
    GetRosterEntry {
        /// Sigchain sequence number.
        seq: u64,
    },
    /// Fetch `/keyslots/<device_id>/<gen>` (§13).
    GetKeyslot {
        /// `device_id = BLAKE3(canonical(pubkey))`.
        device_id: Id,
        /// Master-key generation.
        gen: u32,
    },
    /// Retention prune (§15): delete `dead` iff the server's heads and roster length still equal the claimed ones.
    Prune {
        /// Durable object ids to delete (≤ [`MAX_HAS_IDS`]).
        dead: Vec<Id>,
        /// The client's view of `all_heads_hash`.
        all_heads_hash: [u8; 32],
        /// The client's view of the number of sigchain entries.
        roster_len: u64,
    },
    /// Fetch `/roster-keyhist/<gen>` (§8.2).
    GetRosterKeyhist {
        /// Generation.
        gen: u32,
    },
    /// Fetch `/keyhist/<gen>` (§8.2).
    GetKeyhist {
        /// Generation.
        gen: u32,
    },
    /// Post a code-MAC'd blob to the pairing mailbox (§7); allowed pre-enrollment.
    PairPut {
        /// Slot id `derive_key(label, code)`.
        slot: Id,
        /// The opaque pairing message.
        blob: Vec<u8>,
    },
    /// Take (read and remove) a pairing mailbox slot (§7); allowed pre-enrollment.
    PairGet {
        /// Slot id.
        slot: Id,
    },
}

const T_GET: u8 = 0;
const T_HAS: u8 = 1;
const T_PUT: u8 = 2;
const T_CAS: u8 = 3;
const T_BATCH: u8 = 4;
const T_GETREF: u8 = 5;
const T_GETROSTER: u8 = 6;
const T_GETKEYSLOT: u8 = 7;
const T_PRUNE: u8 = 8;
const T_GETRKH: u8 = 9;
const T_GETKH: u8 = 10;
const T_PAIRPUT: u8 = 12;
const T_PAIRGET: u8 = 13;

fn write_wrap(w: &mut Writer, wrap: &Option<(u32, Vec<u8>)>) {
    match wrap {
        None => {
            w.u8(0);
        }
        Some((g, blob)) => {
            w.u8(1).u32(*g).bytes(blob);
        }
    }
}

fn read_wrap(r: &mut Reader<'_>) -> Result<Option<(u32, Vec<u8>)>, WireError> {
    Ok(if read_flag(r)? {
        Some((r.u32()?, r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec()))
    } else {
        None
    })
}

impl Request {
    /// Canonical encoding (tag-prefixed); call [`Self::validate`] first on anything built locally.
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
                push_id,
                blob,
            } => {
                w.u8(T_PUT)
                    .raw(id)
                    .u32(*declared_size)
                    .raw(push_id)
                    .bytes(blob);
            }
            Request::CasHead {
                ref_h,
                old_head,
                new_head,
                promote,
                new_blob,
            } => {
                w.u8(T_CAS)
                    .raw(ref_h)
                    .raw(old_head)
                    .raw(new_head)
                    .raw(promote)
                    .bytes(new_blob);
            }
            Request::RosterBatch {
                old_tip,
                entries,
                keyslots,
                keyhist,
                roster_keyhist,
                revoke,
                head,
            } => {
                w.u8(T_BATCH).raw(old_tip).u32(entries.len() as u32);
                for e in entries {
                    w.bytes(e);
                }
                w.u32(keyslots.len() as u32);
                for k in keyslots {
                    w.raw(&k.device_id).u32(k.gen).bytes(&k.blob);
                }
                write_wrap(&mut w, keyhist);
                write_wrap(&mut w, roster_keyhist);
                w.u32(revoke.len() as u32);
                for d in revoke {
                    w.raw(d);
                }
                match head {
                    None => {
                        w.u8(0);
                    }
                    Some(h) => {
                        w.u8(1).raw(&h.ref_h).raw(&h.old_head).bytes(&h.new_blob);
                    }
                }
            }
            Request::GetRef { ref_h } => {
                w.u8(T_GETREF).raw(ref_h);
            }
            Request::GetRosterEntry { seq } => {
                w.u8(T_GETROSTER).u64(*seq);
            }
            Request::GetKeyslot { device_id, gen } => {
                w.u8(T_GETKEYSLOT).raw(device_id).u32(*gen);
            }
            Request::Prune {
                dead,
                all_heads_hash,
                roster_len,
            } => {
                w.u8(T_PRUNE).u32(dead.len() as u32);
                for id in dead {
                    w.raw(id);
                }
                w.raw(all_heads_hash).u64(*roster_len);
            }
            Request::GetRosterKeyhist { gen } => {
                w.u8(T_GETRKH).u32(*gen);
            }
            Request::GetKeyhist { gen } => {
                w.u8(T_GETKH).u32(*gen);
            }
            Request::PairPut { slot, blob } => {
                w.u8(T_PAIRPUT).raw(slot).bytes(blob);
            }
            Request::PairGet { slot } => {
                w.u8(T_PAIRGET).raw(slot);
            }
        }
        w.finish()
    }

    /// Write-side bounds, identical to the decoder's: a request that passes always decodes on the server.
    pub fn validate(&self) -> Result<(), WireError> {
        let within = |ok: bool| {
            if ok {
                Ok(())
            } else {
                Err(WireError::FieldTooLong)
            }
        };
        match self {
            Request::Has { ids } => {
                if ids.len() > MAX_HAS_IDS {
                    return Err(WireError::TooLarge);
                }
            }
            Request::Prune { dead, .. } => {
                if dead.len() > MAX_HAS_IDS {
                    return Err(WireError::TooLarge);
                }
            }
            Request::Put { blob, .. } => within(blob.len() <= MAX_BLOB_SIZE)?,
            Request::CasHead { new_blob, .. } => within(new_blob.len() <= MAX_BLOB_SIZE)?,
            Request::PairPut { blob, .. } => within(blob.len() <= MAX_ROSTER_ENTRY_SIZE)?,
            Request::RosterBatch {
                entries,
                keyslots,
                keyhist,
                roster_keyhist,
                revoke,
                head,
                ..
            } => {
                if entries.len() > MAX_LIST_ELEMENTS
                    || keyslots.len() > MAX_LIST_ELEMENTS
                    || revoke.len() > MAX_LIST_ELEMENTS
                {
                    return Err(WireError::TooLarge);
                }
                within(entries.iter().all(|e| e.len() <= MAX_ROSTER_ENTRY_SIZE))?;
                within(
                    keyslots
                        .iter()
                        .all(|k| k.blob.len() <= MAX_ROSTER_ENTRY_SIZE),
                )?;
                within(
                    [keyhist, roster_keyhist]
                        .into_iter()
                        .flatten()
                        .all(|(_, b)| b.len() <= MAX_ROSTER_ENTRY_SIZE),
                )?;
                within(
                    head.as_ref()
                        .is_none_or(|h| h.new_blob.len() <= MAX_BLOB_SIZE),
                )?;
            }
            _ => {}
        }
        within(self.encode().len() <= MAX_REQUEST_LEN)
    }

    /// Strictly decode a request, enforcing every §19 bound before allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let req = match r.u8()? {
            T_GET => Request::Get {
                id: read32(&mut r)?,
            },
            T_HAS => {
                let n = read_count(&mut r, MAX_HAS_IDS)?;
                let mut ids = Vec::with_capacity(n.min(r.remaining() / 32));
                for _ in 0..n {
                    ids.push(read32(&mut r)?);
                }
                Request::Has { ids }
            }
            T_PUT => Request::Put {
                id: read32(&mut r)?,
                declared_size: r.u32()?,
                push_id: read_push_id(&mut r)?,
                blob: r.bytes(MAX_BLOB_SIZE)?.to_vec(),
            },
            T_CAS => Request::CasHead {
                ref_h: read32(&mut r)?,
                old_head: read32(&mut r)?,
                new_head: read32(&mut r)?,
                promote: read_push_id(&mut r)?,
                new_blob: r.bytes(MAX_BLOB_SIZE)?.to_vec(),
            },
            T_BATCH => {
                let old_tip = read32(&mut r)?;
                let n = read_count(&mut r, MAX_LIST_ELEMENTS)?;
                let mut entries = Vec::with_capacity(n.min(r.remaining() / 4));
                for _ in 0..n {
                    entries.push(r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec());
                }
                let n = read_count(&mut r, MAX_LIST_ELEMENTS)?;
                let mut keyslots = Vec::with_capacity(n.min(r.remaining() / 40));
                for _ in 0..n {
                    keyslots.push(KeyslotPut {
                        device_id: read32(&mut r)?,
                        gen: r.u32()?,
                        blob: r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec(),
                    });
                }
                let keyhist = read_wrap(&mut r)?;
                let roster_keyhist = read_wrap(&mut r)?;
                let n = read_count(&mut r, MAX_LIST_ELEMENTS)?;
                let mut revoke = Vec::with_capacity(n.min(r.remaining() / 32));
                for _ in 0..n {
                    revoke.push(read32(&mut r)?);
                }
                let head = if read_flag(&mut r)? {
                    Some(HeadPut {
                        ref_h: read32(&mut r)?,
                        old_head: read32(&mut r)?,
                        new_blob: r.bytes(MAX_BLOB_SIZE)?.to_vec(),
                    })
                } else {
                    None
                };
                Request::RosterBatch {
                    old_tip,
                    entries,
                    keyslots,
                    keyhist,
                    roster_keyhist,
                    revoke,
                    head,
                }
            }
            T_GETREF => Request::GetRef {
                ref_h: read32(&mut r)?,
            },
            T_GETROSTER => Request::GetRosterEntry { seq: r.u64()? },
            T_GETKEYSLOT => Request::GetKeyslot {
                device_id: read32(&mut r)?,
                gen: r.u32()?,
            },
            T_PRUNE => {
                let n = read_count(&mut r, MAX_HAS_IDS)?;
                let mut dead = Vec::with_capacity(n.min(r.remaining() / 32));
                for _ in 0..n {
                    dead.push(read32(&mut r)?);
                }
                Request::Prune {
                    dead,
                    all_heads_hash: read32(&mut r)?,
                    roster_len: r.u64()?,
                }
            }
            T_GETRKH => Request::GetRosterKeyhist { gen: r.u32()? },
            T_GETKH => Request::GetKeyhist { gen: r.u32()? },
            T_PAIRPUT => Request::PairPut {
                slot: read32(&mut r)?,
                blob: r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec(),
            },
            T_PAIRGET => Request::PairGet {
                slot: read32(&mut r)?,
            },
            other => return Err(WireError::BadTag(other)),
        };
        r.finish()?;
        Ok(req)
    }
}

/// A server error code (§12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// The key owns no keyslot (§12).
    NotEnrolled,
    /// Per-op authorization failed (bad signature or stale nonce).
    BadAuth,
    /// A rate limit or quota was exceeded (§19).
    RateLimit,
    /// A `has`/`prune` batch exceeded its cap (§12).
    TooManyIds,
    /// A compare-and-swap lost (`cas-head`, the roster tip, or the prune head-binding, §15).
    CasConflict,
    /// Malformed request.
    BadRequest,
    /// Internal server/storage error.
    Internal,
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ErrorCode::NotEnrolled => "this device is not enrolled in the repo",
            ErrorCode::BadAuth => "per-op authorization failed",
            ErrorCode::RateLimit => "rate limit or quota exceeded",
            ErrorCode::TooManyIds => "too many ids in one request",
            ErrorCode::CasConflict => "compare-and-swap conflict",
            ErrorCode::BadRequest => "malformed request",
            ErrorCode::Internal => "server internal error",
        })
    }
}

/// A server-API response (§12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// A fetched blob, or `None` if absent.
    Blob(Option<Vec<u8>>),
    /// One bool per `has` id, in order.
    Exists(Vec<bool>),
    /// A write op was accepted.
    Ok,
    /// The op was rejected.
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
            R_BLOB => {
                if read_flag(&mut r)? {
                    Response::Blob(Some(r.bytes(MAX_BLOB_SIZE)?.to_vec()))
                } else {
                    Response::Blob(None)
                }
            }
            R_EXISTS => {
                let n = read_count(&mut r, MAX_HAS_IDS)?;
                let mut bits = Vec::with_capacity(n.min(r.remaining()));
                for _ in 0..n {
                    bits.push(read_flag(&mut r)?);
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

/// The client's connection-auth message (§11): canonical pubkey + `secsec-auth-v1` signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuth {
    /// Canonical SSH encoding of the client's device public key.
    pub pubkey: Vec<u8>,
    /// SSHSIG over the §9.6 `secsec-auth-v1` payload.
    pub sig: Vec<u8>,
}

impl ClientAuth {
    /// Maximum encoded length.
    pub const MAX_LEN: usize = 4 + MAX_PUBKEY + 4 + MAX_SIG_LEN;

    /// Canonical encoding `bytes(pubkey) ‖ bytes(sig)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.pubkey).bytes(&self.sig);
        w.finish()
    }

    /// Strictly decode, bounding the pubkey and signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let pubkey = r.bytes(MAX_PUBKEY)?.to_vec();
        let sig = r.bytes(MAX_SIG_LEN)?.to_vec();
        r.finish()?;
        Ok(Self { pubkey, sig })
    }
}

/// One RPC on the wire: the per-op signature and the request (§12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthedRequest {
    /// The per-op `secsec-write-v1` / `secsec-read-v1` signature.
    pub op_sig: Vec<u8>,
    /// The operation.
    pub request: Request,
}

impl AuthedRequest {
    /// Canonical encoding `bytes(op_sig) ‖ bytes(request)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.op_sig).bytes(&self.request.encode());
        w.finish()
    }

    /// Strictly decode, bounding the signature and request.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let op_sig = r.bytes(MAX_SIG_LEN)?.to_vec();
        let req_bytes = r.bytes(MAX_REQUEST_LEN)?;
        let request = Request::decode(req_bytes)?;
        r.finish()?;
        Ok(Self { op_sig, request })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch() -> Request {
        Request::RosterBatch {
            old_tip: [8; 32],
            entries: vec![b"e1".to_vec(), b"e2".to_vec()],
            keyslots: vec![KeyslotPut {
                device_id: [3; 32],
                gen: 2,
                blob: b"ks".to_vec(),
            }],
            keyhist: Some((1, b"kh".to_vec())),
            roster_keyhist: None,
            revoke: vec![[4; 32]],
            head: Some(HeadPut {
                ref_h: [5; 32],
                old_head: [6; 32],
                new_blob: b"head".to_vec(),
            }),
        }
    }

    #[test]
    fn hello_round_trips_with_fixed_lengths() {
        let c = ClientHello {
            version: 1,
            client_nonce: [0xC1; 32],
        };
        assert_eq!(c.encode().len(), ClientHello::LEN);
        assert_eq!(ClientHello::decode(&c.encode()).unwrap(), c);
        let s = ServerHello {
            version: 1,
            server_nonce: [0x5e; 32],
            host_id: [0x40; 32],
        };
        assert_eq!(s.encode().len(), ServerHello::LEN);
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
                push_id: [0xab; 16],
                blob: b"hello world".to_vec(),
            },
            Request::CasHead {
                ref_h: [5; 32],
                old_head: [6; 32],
                new_head: [7; 32],
                promote: [0xcd; 16],
                new_blob: b"head".to_vec(),
            },
            batch(),
            Request::GetRef { ref_h: [9; 32] },
            Request::GetRosterEntry { seq: 7 },
            Request::GetKeyslot {
                device_id: [10; 32],
                gen: 3,
            },
            Request::Prune {
                dead: vec![[11; 32], [12; 32]],
                all_heads_hash: [0x44; 32],
                roster_len: 9,
            },
            Request::GetRosterKeyhist { gen: 2 },
            Request::GetKeyhist { gen: 5 },
            Request::PairPut {
                slot: [13; 32],
                blob: b"pair".to_vec(),
            },
            Request::PairGet { slot: [14; 32] },
        ];
        for req in reqs {
            req.validate().unwrap();
            assert_eq!(Request::decode(&req.encode()).unwrap(), req);
        }
    }

    #[test]
    fn response_round_trips_and_rejects_non_canonical_flags() {
        for resp in [
            Response::Blob(None),
            Response::Blob(Some(b"blob".to_vec())),
            Response::Exists(vec![true, false, true]),
            Response::Ok,
            Response::Err(ErrorCode::CasConflict),
            Response::Err(ErrorCode::NotEnrolled),
        ] {
            assert_eq!(Response::decode(&resp.encode()).unwrap(), resp);
        }
        let mut bytes = Response::Exists(vec![true]).encode();
        *bytes.last_mut().unwrap() = 2;
        assert_eq!(Response::decode(&bytes), Err(WireError::BadTag(2)));
        assert_eq!(Response::decode(&[R_BLOB, 7]), Err(WireError::BadTag(7)));
    }

    #[test]
    fn client_auth_and_authed_request_round_trip() {
        let ca = ClientAuth {
            pubkey: b"ssh-ed25519-canonical-bytes".to_vec(),
            sig: b"sshsig-pem".to_vec(),
        };
        assert!(ca.encode().len() <= ClientAuth::MAX_LEN);
        assert_eq!(ClientAuth::decode(&ca.encode()).unwrap(), ca);
        let ar = AuthedRequest {
            op_sig: b"write-auth-sig".to_vec(),
            request: batch(),
        };
        assert_eq!(AuthedRequest::decode(&ar.encode()).unwrap(), ar);
    }

    #[test]
    fn decode_rejects_bad_tag_trailing_bytes_and_removed_ops() {
        assert_eq!(Request::decode(&[0xFF]), Err(WireError::BadTag(0xFF)));
        assert_eq!(Request::decode(&[11]), Err(WireError::BadTag(11)));
        let mut bytes = Request::Get { id: [1; 32] }.encode();
        bytes.push(0x00);
        assert!(matches!(
            Request::decode(&bytes),
            Err(WireError::Canon(CanonError::TrailingBytes { .. }))
        ));
    }

    #[test]
    fn list_counts_over_cap_are_rejected_before_alloc() {
        let mut w = Writer::new();
        w.u8(T_HAS).u32((MAX_HAS_IDS + 1) as u32);
        assert_eq!(Request::decode(&w.finish()), Err(WireError::TooLarge));
        let mut w = Writer::new();
        w.u8(T_BATCH)
            .raw(&[0; 32])
            .u32((MAX_LIST_ELEMENTS + 1) as u32);
        assert_eq!(Request::decode(&w.finish()), Err(WireError::TooLarge));
        assert_eq!(
            Request::Has {
                ids: vec![[0; 32]; MAX_HAS_IDS + 1]
            }
            .validate(),
            Err(WireError::TooLarge)
        );
    }

    #[test]
    fn put_blob_over_max_is_rejected_both_ways() {
        let mut w = Writer::new();
        w.u8(T_PUT)
            .raw(&[0u8; 32])
            .u32(0)
            .raw(&[0u8; 16])
            .u32(u32::MAX);
        assert!(matches!(
            Request::decode(&w.finish()),
            Err(WireError::Canon(CanonError::LengthExceedsMax { .. }))
        ));
        let big = Request::PairPut {
            slot: [0; 32],
            blob: vec![0; MAX_ROSTER_ENTRY_SIZE + 1],
        };
        assert_eq!(big.validate(), Err(WireError::FieldTooLong));
    }

    /// The unenrolled frame cap fits the largest genesis batch and pairing message it must carry.
    #[test]
    fn unenrolled_cap_fits_genesis_and_pairing() {
        let genesis = Request::RosterBatch {
            old_tip: [0; 32],
            entries: vec![vec![0; MAX_ROSTER_ENTRY_SIZE]],
            keyslots: vec![KeyslotPut {
                device_id: [0; 32],
                gen: 1,
                blob: vec![0; MAX_ROSTER_ENTRY_SIZE],
            }],
            keyhist: None,
            roster_keyhist: None,
            revoke: vec![],
            head: None,
        };
        for req in [
            genesis,
            Request::PairPut {
                slot: [0; 32],
                blob: vec![0; MAX_ROSTER_ENTRY_SIZE],
            },
        ] {
            let ar = AuthedRequest {
                op_sig: vec![0; MAX_SIG_LEN],
                request: req,
            };
            assert!(ar.encode().len() <= MAX_UNENROLLED_AUTHED_LEN);
        }
    }
}
