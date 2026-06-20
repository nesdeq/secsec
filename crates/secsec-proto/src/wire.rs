//! Wire messages for the server API (`secsec-Design.md` §11 handshake, §12 RPC). Strict, bounded
//! canonical codecs for the handshake hellos and the request/response types.
//!
//! Every length-prefixed field is bounded by its §19 limit **before allocation** (alloc-bomb guard),
//! and decode is exhausted via [`secsec_canon::Reader::finish`] (no trailing bytes). The transport
//! frames these payloads on QUIC streams (length-prefixed); that framing + the auth wrapper live in
//! the transport/handshake layer.

use crate::server::limits::MAX_HAS_IDS;
use crate::PUSH_ID_LEN;
use secsec_canon::{CanonError, Reader, Writer};
use secsec_frame::{MAX_BLOB_SIZE, MAX_ROSTER_ENTRY_SIZE};

/// A 256-bit id / hash.
pub type Id = [u8; 32];

/// Maximum canonical device-pubkey length (Ed25519 SSH encoding is ~51 bytes; bounded generously).
pub const MAX_PUBKEY: usize = 1024;
/// Maximum SSHSIG length (a PEM SSHSIG is well under this).
pub const MAX_SIG: usize = MAX_ROSTER_ENTRY_SIZE;
/// Maximum encoded `Request` length: a 16 MiB `put` blob plus envelope overhead.
pub const MAX_REQUEST_LEN: usize = MAX_BLOB_SIZE + 4096;

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

fn read_push_id(r: &mut Reader<'_>) -> Result<[u8; PUSH_ID_LEN], WireError> {
    let mut out = [0u8; PUSH_ID_LEN];
    out.copy_from_slice(r.raw(PUSH_ID_LEN)?);
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
    /// Stage an object under an in-flight push (idempotent by id). The object is held in `STAGING`
    /// until this push's `cas-head` promotes it; it is not durably stored on its own.
    Put {
        /// Content address.
        id: Id,
        /// Declared size (server rejects `> 16 MiB` before reading the body).
        declared_size: u32,
        /// The per-attempt push id this object is staged under (§15).
        push_id: [u8; PUSH_ID_LEN],
        /// The object blob.
        blob: Vec<u8>,
    },
    /// Atomic ref CAS with staged-object promotion: swap `/refs/<ref_h>` from `old_head` to `new_head`
    /// (the new head blob attached) and, in the same transaction, promote every object staged under
    /// `promote` to durable storage (§15) — so a durable head never references a non-durable object.
    CasHead {
        /// Keyed-hash ref name.
        ref_h: Id,
        /// Expected current head id.
        old_head: Id,
        /// New head id.
        new_head: Id,
        /// The push whose staged objects this swap promotes.
        promote: [u8; PUSH_ID_LEN],
        /// The new head blob to store.
        new_blob: Vec<u8>,
    },
    /// Append a sigchain entry, CAS-guarded by the current `/roster-head` tip (§8.1).
    RosterAppend {
        /// `BLAKE3` of the current tip entry blob the client built on, or [`secsec_frame`]'s
        /// all-zero sentinel for the genesis append (the server CASes on this).
        old_tip: Id,
        /// The stored (encrypted) roster-entry blob.
        entry: Vec<u8>,
    },
    /// Fetch the current stored head blob at `/refs/<ref_h>` (§13). A read op; the server returns the
    /// opaque §9.8 head blob (or absent) and never learns the ref name behind `ref_h`.
    GetRef {
        /// Keyed-hash ref name `H = BLAKE3::keyed_hash(ref_name_key, ref_name)`.
        ref_h: Id,
    },
    /// Fetch a sigchain entry blob at `/roster/<seq>` (§13) — cold-start fold (§8.1). Absent past the
    /// tip, so the client reads `seq = 0, 1, …` until `None`.
    GetRosterEntry {
        /// Sigchain sequence number.
        seq: u64,
    },
    /// Fetch a device's keyslot blob at `/keyslots/<device_id>/<gen>` (§13) — cold-start unwrap (§8.1).
    GetKeyslot {
        /// `device_id = BLAKE3(canonical(pubkey))`.
        device_id: Id,
        /// Master-key generation.
        gen: u32,
    },
    /// Client-driven retention prune (§15): delete the durable objects in `dead` that retention has
    /// dropped — no kept version references them. The `secsec-write-v1` `args_hash` binds `dead`, the server's
    /// current `all_heads_hash`, and `roster_seq` (a head-binding compare-and-swap; see
    /// [`crate::prune`]), so a concurrent `cas-head`/`roster-append` rejects the prune rather than
    /// deleting an object a reverted head now references. `dead` is capped at [`MAX_HAS_IDS`] per call;
    /// the client batches a larger delete-set (each batch is independently CAS-guarded).
    Prune {
        /// The durable object ids to delete.
        dead: Vec<Id>,
        /// The client's view of the server's `all_heads_hash` — the CAS token (§15).
        all_heads_hash: [u8; 32],
        /// The client's view of the current sigchain tip sequence.
        roster_seq: u64,
    },
    /// Fetch the roster-key-history wrap at `/roster-keyhist/<gen>` (§8.2) — for rotation-era cold-start
    /// (peeling `roster_key_g` across generations). A read op; the server returns the opaque wrap.
    GetRosterKeyhist {
        /// The generation whose wrap is requested.
        gen: u32,
    },
    /// Fetch the DATA key-history wrap at `/keyhist/<gen>` (§8.2) — peeling `master_key_g` across
    /// generations so a current member can read pre-rotation **object** content. A read op; the server
    /// returns the opaque wrap.
    GetKeyhist {
        /// The generation whose wrap is requested.
        gen: u32,
    },
    /// Store a device's keyslot blob at `/keyslots/<device_id>/<gen>` (§13) — the network half of
    /// enrollment (`init`/`grant`/`rotate` writing a member's keyslot). A write op; the keyslot is an
    /// opaque wrap the recipient authenticates against `mk_commit` (§7), so the server cannot forge a
    /// valid one.
    PutKeyslot {
        /// `device_id = BLAKE3(canonical(pubkey))` of the keyslot owner.
        device_id: Id,
        /// Master-key generation the keyslot wraps.
        gen: u32,
        /// The opaque `algo_id ‖ body` keyslot blob (§8.3).
        blob: Vec<u8>,
    },
    /// Post an opaque blob to the transient **pairing mailbox** slot `slot` (§7 invite onboarding). The
    /// slot is `BLAKE3::derive_key(label, invite_code)`, so only parties holding the code address it; the blob is
    /// MAC'd under the code, so the server (which never learns the code) only relays it. Allowed
    /// **pre-enrollment** (a joining device owns no keyslot yet) and aggressively rate-limited + TTL'd.
    PairPut {
        /// Mailbox slot id (a hash of the invite code + a direction label).
        slot: Id,
        /// The opaque, code-MAC'd pairing message.
        blob: Vec<u8>,
    },
    /// Read the transient pairing mailbox slot `slot` (`None` if empty/expired). Pre-enrollment allowed.
    PairGet {
        /// Mailbox slot id.
        slot: Id,
    },
    /// Store a DATA key-history wrap at `/keyhist/<gen>` (§8.2) — the network half of rotation.
    PutKeyhist {
        /// The generation whose wrap is written.
        gen: u32,
        /// The opaque wrap blob.
        blob: Vec<u8>,
    },
    /// Store a roster-key-history wrap at `/roster-keyhist/<gen>` (§8.2) — the network half of rotation.
    PutRosterKeyhist {
        /// The generation whose wrap is written.
        gen: u32,
        /// The opaque wrap blob.
        blob: Vec<u8>,
    },
    /// Delete a device's keyslot at `/keyslots/<device_id>/<gen>` (§8.4 revocation, over the wire).
    DeleteKeyslot {
        /// `device_id` of the keyslot to delete.
        device_id: Id,
        /// The generation whose keyslot is removed.
        gen: u32,
    },
}

const T_GET: u8 = 0;
const T_HAS: u8 = 1;
const T_PUT: u8 = 2;
const T_CAS: u8 = 3;
const T_ROSTER: u8 = 4;
const T_GETREF: u8 = 5;
const T_GETROSTER: u8 = 6;
const T_GETKEYSLOT: u8 = 7;
const T_PRUNE: u8 = 8;
const T_GETRKH: u8 = 9;
const T_GETKH: u8 = 10;
const T_PUTKEYSLOT: u8 = 11;
const T_PAIRPUT: u8 = 12;
const T_PAIRGET: u8 = 13;
const T_PUTKEYHIST: u8 = 14;
const T_PUTRKH: u8 = 15;
const T_DELKEYSLOT: u8 = 16;

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
            Request::RosterAppend { old_tip, entry } => {
                w.u8(T_ROSTER).raw(old_tip).bytes(entry);
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
                roster_seq,
            } => {
                w.u8(T_PRUNE).u32(dead.len() as u32);
                for id in dead {
                    w.raw(id);
                }
                w.raw(all_heads_hash).u64(*roster_seq);
            }
            Request::GetRosterKeyhist { gen } => {
                w.u8(T_GETRKH).u32(*gen);
            }
            Request::GetKeyhist { gen } => {
                w.u8(T_GETKH).u32(*gen);
            }
            Request::PutKeyslot {
                device_id,
                gen,
                blob,
            } => {
                w.u8(T_PUTKEYSLOT).raw(device_id).u32(*gen).bytes(blob);
            }
            Request::PairPut { slot, blob } => {
                w.u8(T_PAIRPUT).raw(slot).bytes(blob);
            }
            Request::PairGet { slot } => {
                w.u8(T_PAIRGET).raw(slot);
            }
            Request::PutKeyhist { gen, blob } => {
                w.u8(T_PUTKEYHIST).u32(*gen).bytes(blob);
            }
            Request::PutRosterKeyhist { gen, blob } => {
                w.u8(T_PUTRKH).u32(*gen).bytes(blob);
            }
            Request::DeleteKeyslot { device_id, gen } => {
                w.u8(T_DELKEYSLOT).raw(device_id).u32(*gen);
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
                // Pre-allocate no more than the remaining input can hold (each id is 32 bytes), so a
                // lying count cannot force a large allocation ahead of a truncated body.
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
            T_ROSTER => Request::RosterAppend {
                old_tip: read32(&mut r)?,
                entry: r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec(),
            },
            T_GETREF => Request::GetRef {
                ref_h: read32(&mut r)?,
            },
            T_GETROSTER => Request::GetRosterEntry { seq: r.u64()? },
            T_GETKEYSLOT => Request::GetKeyslot {
                device_id: read32(&mut r)?,
                gen: r.u32()?,
            },
            T_PRUNE => {
                let n = r.u32()? as usize;
                if n > MAX_HAS_IDS {
                    return Err(WireError::TooLarge);
                }
                // Cap the pre-allocation to what the remaining input can hold (32 bytes per id), so a
                // lying count cannot force a large allocation ahead of a truncated body.
                let mut dead = Vec::with_capacity(n.min(r.remaining() / 32));
                for _ in 0..n {
                    dead.push(read32(&mut r)?);
                }
                Request::Prune {
                    dead,
                    all_heads_hash: read32(&mut r)?,
                    roster_seq: r.u64()?,
                }
            }
            T_GETRKH => Request::GetRosterKeyhist { gen: r.u32()? },
            T_GETKH => Request::GetKeyhist { gen: r.u32()? },
            T_PUTKEYSLOT => Request::PutKeyslot {
                device_id: read32(&mut r)?,
                gen: r.u32()?,
                blob: r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec(),
            },
            T_PAIRPUT => Request::PairPut {
                slot: read32(&mut r)?,
                blob: r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec(),
            },
            T_PAIRGET => Request::PairGet {
                slot: read32(&mut r)?,
            },
            T_PUTKEYHIST => Request::PutKeyhist {
                gen: r.u32()?,
                blob: r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec(),
            },
            T_PUTRKH => Request::PutRosterKeyhist {
                gen: r.u32()?,
                blob: r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec(),
            },
            T_DELKEYSLOT => Request::DeleteKeyslot {
                device_id: read32(&mut r)?,
                gen: r.u32()?,
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
    /// A write op (`put`/`cas-head`/`roster-append`/`prune`) was accepted.
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

/// The client's connection-auth message (§11): its canonical device public key plus the
/// `secsec-auth-v1` signature over the handshake. The server verifies the signature against the
/// presented key and checks that key owns a keyslot (§12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuth {
    /// Canonical SSH encoding of the client's device public key.
    pub pubkey: Vec<u8>,
    /// SSHSIG over the §9.6 `secsec-auth-v1` payload.
    pub sig: Vec<u8>,
}

impl ClientAuth {
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
        let sig = r.bytes(MAX_SIG)?.to_vec();
        r.finish()?;
        Ok(Self { pubkey, sig })
    }
}

/// A per-op request with its authorization signature (§12): the wire form of one RPC.
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
        let op_sig = r.bytes(MAX_SIG)?.to_vec();
        let req_bytes = r.bytes(MAX_REQUEST_LEN)?;
        let request = Request::decode(req_bytes)?;
        r.finish()?;
        Ok(Self { op_sig, request })
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
            Request::RosterAppend {
                old_tip: [8; 32],
                entry: b"entry-bytes".to_vec(),
            },
            Request::GetRef { ref_h: [9; 32] },
            Request::GetRosterEntry { seq: 7 },
            Request::GetKeyslot {
                device_id: [10; 32],
                gen: 3,
            },
            Request::Prune {
                dead: vec![[11; 32], [12; 32]],
                all_heads_hash: [0x44; 32],
                roster_seq: 9,
            },
            Request::GetRosterKeyhist { gen: 2 },
            Request::GetKeyhist { gen: 5 },
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
    fn client_auth_and_authed_request_round_trip() {
        let ca = ClientAuth {
            pubkey: b"ssh-ed25519-canonical-bytes".to_vec(),
            sig: b"sshsig-pem".to_vec(),
        };
        assert_eq!(ClientAuth::decode(&ca.encode()).unwrap(), ca);

        let ar = AuthedRequest {
            op_sig: b"write-auth-sig".to_vec(),
            request: Request::Put {
                id: [9; 32],
                declared_size: 3,
                push_id: [0; 16],
                blob: b"abc".to_vec(),
            },
        };
        assert_eq!(AuthedRequest::decode(&ar.encode()).unwrap(), ar);
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
        w.u8(T_PUT).raw(&[0u8; 32]).u32(0).raw(&[0u8; 16]).u32(u32::MAX); // bytes() prefix = u32::MAX
        assert!(matches!(
            Request::decode(&w.finish()),
            Err(WireError::Canon(CanonError::LengthExceedsMax { .. }))
        ));
    }
}
