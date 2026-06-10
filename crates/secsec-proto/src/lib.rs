//! `secsec-proto` — per-operation authorization for the server API (`secsec-Design.md` §12, §9.6).
//!
//! **Every** repo operation — including reads — requires a per-op signature from a key that owns a
//! keyslot (a rostered device); connection-level auth alone is not enough (§12). This crate builds
//! the two signed payloads and the per-op `args_hash` that binds the exact operation:
//!
//! - **Write** ops (`put`, `cas-head`, `roster-append`, `gc`): sign under [`secsec_sig::NS_WRITE`]
//!   over `op ‖ args_hash ‖ session_transcript ‖ server_nonce` (§9.6). The server supplies only the
//!   fresh single-use `server_nonce`; the client constructs `op`/`args`.
//! - **Read** ops (`get`, `has`): sign under [`secsec_sig::NS_READ`] over
//!   `op ‖ args_hash ‖ session_transcript`. No `server_nonce` — `session_transcript` provides
//!   per-connection freshness (§9.6).
//!
//! The `args_hash` per op is the normative §12 binding: `put`/`cas-head`/`roster-append`/`get`/`has`
//! here, and `gc`'s §15 serialization (`keep_set_hash`, `all_heads_hash`, `args_gc`) in [`gc`]. The
//! GC *executor* (keep-set traversal, generation/grace sweep) is the hardened-GC work of M6.

#![forbid(unsafe_code)]

pub mod gc;
pub mod receipt;
pub mod server;
pub mod wire;

use secsec_canon::Writer;
use secsec_sig::{DeviceKey, DevicePublic, NS_READ, NS_WRITE};

/// A 256-bit id / hash.
pub type Id = [u8; 32];

/// Op labels (§12). These appear both inside the relevant `args_hash` and in the signed payload.
pub mod op {
    /// Store an object.
    pub const PUT: &str = "put";
    /// Atomic ref CAS.
    pub const CAS_HEAD: &str = "cas-head";
    /// Append a roster sigchain entry.
    pub const ROSTER_APPEND: &str = "roster-append";
    /// Client-driven GC sweep.
    pub const GC: &str = "gc";
    /// Fetch a blob.
    pub const GET: &str = "get";
    /// Existence check.
    pub const HAS: &str = "has";
    /// Fetch the current stored head blob for a ref (`/refs/<H>`, §13).
    pub const GET_REF: &str = "get-ref";
    /// Fetch a sigchain entry blob by sequence (`/roster/<seq>`, §13) — for cold-start fold (§8.1).
    pub const GET_ROSTER: &str = "get-roster";
    /// Fetch a device's keyslot blob (`/keyslots/<device_id>/<g>`, §13) — for cold-start unwrap (§8.1).
    pub const GET_KEYSLOT: &str = "get-keyslot";
    /// Store a device's keyslot blob (`/keyslots/<device_id>/<g>`, §13) — the network half of enrollment.
    pub const PUT_KEYSLOT: &str = "put-keyslot";
    /// Post to the transient pairing mailbox (§7 invite onboarding); allowed pre-enrollment.
    pub const PAIR_PUT: &str = "pair-put";
    /// Read the transient pairing mailbox (§7 invite onboarding); allowed pre-enrollment.
    pub const PAIR_GET: &str = "pair-get";
    /// Fetch a roster-key-history wrap (`/roster-keyhist/<g>`, §8.2) — for rotation-era cold-start.
    pub const GET_ROSTER_KEYHIST: &str = "get-roster-keyhist";
    /// Fetch a DATA key-history wrap (`/keyhist/<g>`, §8.2) — peeling `master_key_g` for old objects.
    pub const GET_KEYHIST: &str = "get-keyhist";
}

fn blake3_of(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// `args_hash` for `put` (§12): `BLAKE3(canonical("put" ‖ id ‖ le32(declared_size)))`.
#[must_use]
pub fn args_put(id: &Id, declared_size: u32) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(op::PUT.as_bytes()).raw(id).u32(declared_size);
    blake3_of(&w.finish())
}

/// `args_hash` for `cas-head` (§12): `BLAKE3(canonical("cas-head" ‖ ref_H ‖ old_head_id ‖ new_head_id))`.
#[must_use]
pub fn args_cas_head(ref_h: &Id, old_head_id: &Id, new_head_id: &Id) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(op::CAS_HEAD.as_bytes())
        .raw(ref_h)
        .raw(old_head_id)
        .raw(new_head_id);
    blake3_of(&w.finish())
}

/// `args_hash` for `roster-append` (§12): `BLAKE3(canonical("roster-append" ‖ BLAKE3(canonical(entry))))`,
/// where `entry_bytes` is the canonical encoding of the sigchain entry.
#[must_use]
pub fn args_roster_append(entry_bytes: &[u8]) -> [u8; 32] {
    let entry_hash = blake3_of(entry_bytes);
    let mut w = Writer::new();
    w.raw(op::ROSTER_APPEND.as_bytes()).raw(&entry_hash);
    blake3_of(&w.finish())
}

/// `args_hash` for a read op (§9.6): `BLAKE3(canonical(op ‖ ids))`, binding the exact requested ids
/// in request order. `op` is [`op::GET`] or [`op::HAS`].
#[must_use]
pub fn args_read(op: &str, ids: &[Id]) -> [u8; 32] {
    let mut w = Writer::new();
    w.bytes(op.as_bytes()).u64(ids.len() as u64);
    for id in ids {
        w.raw(id);
    }
    blake3_of(&w.finish())
}

/// `args_hash` for `get-roster` (§9.6/§12): `BLAKE3(canonical("get-roster" ‖ le64(seq)))`, binding
/// the exact sigchain sequence requested.
#[must_use]
pub fn args_get_roster(seq: u64) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(op::GET_ROSTER.as_bytes()).u64(seq);
    blake3_of(&w.finish())
}

/// `args_hash` for `get-keyslot` (§9.6/§12): `BLAKE3(canonical("get-keyslot" ‖ device_id ‖ le32(gen)))`,
/// binding the exact keyslot (device, generation) requested.
#[must_use]
pub fn args_get_keyslot(device_id: &Id, gen: u32) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(op::GET_KEYSLOT.as_bytes()).raw(device_id).u32(gen);
    blake3_of(&w.finish())
}

/// `args_hash` for `put-keyslot` (§9.6/§12): `BLAKE3(canonical("put-keyslot" ‖ device_id ‖ le32(gen)
/// ‖ BLAKE3(blob)))`, binding the exact keyslot (device, generation, content) being written.
#[must_use]
pub fn args_put_keyslot(device_id: &Id, gen: u32, blob: &[u8]) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(op::PUT_KEYSLOT.as_bytes())
        .raw(device_id)
        .u32(gen)
        .raw(&blake3_of(blob));
    blake3_of(&w.finish())
}

/// `args_hash` for the pairing mailbox ops (§7): `BLAKE3(canonical(op ‖ slot))`. The blob itself is
/// MAC'd under the invite code end-to-end, so the per-op signature only proves the connecting key
/// holds its private SSH key (pre-enrollment), not authorization.
#[must_use]
pub fn args_pair(op_label: &str, slot: &Id) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(op_label.as_bytes()).raw(slot);
    blake3_of(&w.finish())
}

/// The op label, recomputed `args_hash`, and whether it is a write op, for a request (§12). Both the
/// client (to sign) and the server (to verify) call this so neither can disagree on the binding.
#[must_use]
pub fn op_and_args(req: &wire::Request) -> (&'static str, [u8; 32], bool) {
    use wire::Request;
    match req {
        Request::Get { id } => (op::GET, args_read(op::GET, &[*id]), false),
        Request::Has { ids } => (op::HAS, args_read(op::HAS, ids), false),
        // A read keyed by the ref hash (bound like a single-id read), §13/§9.6.
        Request::GetRef { ref_h } => (op::GET_REF, args_read(op::GET_REF, &[*ref_h]), false),
        // Cold-start bootstrap reads (§8.1): roster entry by seq, keyslot by (device, gen).
        Request::GetRosterEntry { seq } => (op::GET_ROSTER, args_get_roster(*seq), false),
        Request::GetKeyslot { device_id, gen } => {
            (op::GET_KEYSLOT, args_get_keyslot(device_id, *gen), false)
        }
        Request::GetRosterKeyhist { gen } => {
            // bound like get-roster but on a generation index.
            let mut w = Writer::new();
            w.raw(op::GET_ROSTER_KEYHIST.as_bytes()).u32(*gen);
            (op::GET_ROSTER_KEYHIST, blake3_of(&w.finish()), false)
        }
        Request::GetKeyhist { gen } => {
            // bound like get-roster-keyhist but on the DATA key-history generation index.
            let mut w = Writer::new();
            w.raw(op::GET_KEYHIST.as_bytes()).u32(*gen);
            (op::GET_KEYHIST, blake3_of(&w.finish()), false)
        }
        // gc's real args_hash binds the SERVER's all_heads_hash/roster_seq/put_epoch (a §15
        // compare-and-swap), so it is computed in the server's gc handler and the client's gc driver,
        // NOT here. `handle` dispatches Gc before reaching op_and_args; this keep_set+gc_gen-only
        // binding is never the gc authorization source.
        Request::Gc { keep_set, gc_gen } => {
            let mut w = Writer::new();
            w.raw(op::GC.as_bytes())
                .raw(&gc::keep_set_hash(keep_set))
                .u64(*gc_gen);
            (op::GC, blake3_of(&w.finish()), true)
        }
        Request::Put {
            id, declared_size, ..
        } => (op::PUT, args_put(id, *declared_size), true),
        Request::CasHead {
            ref_h,
            old_head,
            new_head,
            ..
        } => (op::CAS_HEAD, args_cas_head(ref_h, old_head, new_head), true),
        Request::RosterAppend { entry, .. } => (op::ROSTER_APPEND, args_roster_append(entry), true),
        Request::PutKeyslot {
            device_id,
            gen,
            blob,
        } => (
            op::PUT_KEYSLOT,
            args_put_keyslot(device_id, *gen, blob),
            true,
        ),
        // Pairing ops are read-auth (signed by the connecting key, no server_nonce); the server
        // dispatches them before the enrollment check (§7 invite onboarding).
        Request::PairPut { slot, .. } => (op::PAIR_PUT, args_pair(op::PAIR_PUT, slot), false),
        Request::PairGet { slot } => (op::PAIR_GET, args_pair(op::PAIR_GET, slot), false),
    }
}

/// Errors from per-op authorization.
#[derive(Debug)]
pub enum ProtoError {
    /// The per-op signature did not verify (bad sig, wrong key, or any bound field altered).
    BadSignature,
    /// Signing/key error.
    Sig(secsec_sig::SigError),
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtoError::BadSignature => f.write_str("per-op authorization signature invalid"),
            ProtoError::Sig(e) => write!(f, "sig: {e}"),
        }
    }
}
impl std::error::Error for ProtoError {}
impl From<secsec_sig::SigError> for ProtoError {
    fn from(e: secsec_sig::SigError) -> Self {
        ProtoError::Sig(e)
    }
}

/// A write-op authorization (§9.6 `secsec-write-v1`). The server supplies `server_nonce`; the client
/// constructs `op`/`args_hash`.
#[derive(Clone, Copy)]
pub struct WriteAuth<'a> {
    /// The op label ([`op::PUT`] / [`op::CAS_HEAD`] / [`op::ROSTER_APPEND`] / [`op::GC`]).
    pub op: &'a str,
    /// The per-op `args_hash`.
    pub args_hash: [u8; 32],
    /// The connection's session transcript (§11).
    pub session_transcript: [u8; 32],
    /// The server's fresh single-use challenge.
    pub server_nonce: [u8; 32],
}

impl WriteAuth<'_> {
    /// The signed payload `op ‖ args_hash ‖ session_transcript ‖ server_nonce` (§9.6), canonically
    /// encoded (length-prefixed op label, fixed-width remainder).
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(self.op.as_bytes())
            .raw(&self.args_hash)
            .raw(&self.session_transcript)
            .raw(&self.server_nonce);
        w.finish()
    }

    /// Sign the write-auth payload under `NS_WRITE`.
    pub fn sign(&self, device: &DeviceKey) -> Result<Vec<u8>, ProtoError> {
        Ok(device.sign(NS_WRITE, &self.message())?)
    }

    /// Verify against `pubkey` (resolved from the roster; the server also enforces keyslot ownership
    /// and `server_nonce` freshness, §12).
    pub fn verify(&self, pubkey: &DevicePublic, sig: &[u8]) -> Result<(), ProtoError> {
        pubkey
            .verify(NS_WRITE, &self.message(), sig)
            .map_err(|_| ProtoError::BadSignature)
    }
}

/// A read-op authorization (§9.6 `secsec-read-v1`). No `server_nonce` — `session_transcript`
/// provides per-connection freshness.
#[derive(Clone, Copy)]
pub struct ReadAuth<'a> {
    /// The op label ([`op::GET`] / [`op::HAS`]).
    pub op: &'a str,
    /// The per-op `args_hash` ([`args_read`]).
    pub args_hash: [u8; 32],
    /// The connection's session transcript (§11).
    pub session_transcript: [u8; 32],
}

impl ReadAuth<'_> {
    /// The signed payload `op ‖ args_hash ‖ session_transcript` (§9.6).
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(self.op.as_bytes())
            .raw(&self.args_hash)
            .raw(&self.session_transcript);
        w.finish()
    }

    /// Sign the read-auth payload under `NS_READ`.
    pub fn sign(&self, device: &DeviceKey) -> Result<Vec<u8>, ProtoError> {
        Ok(device.sign(NS_READ, &self.message())?)
    }

    /// Verify against `pubkey`.
    pub fn verify(&self, pubkey: &DevicePublic, sig: &[u8]) -> Result<(), ProtoError> {
        pubkey
            .verify(NS_READ, &self.message(), sig)
            .map_err(|_| ProtoError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secsec_sig::NS_AUTH;

    #[test]
    fn args_hashes_are_deterministic_and_sensitive() {
        let id = [0x11; 32];
        assert_eq!(args_put(&id, 100), args_put(&id, 100));
        assert_ne!(args_put(&id, 100), args_put(&id, 101)); // declared_size bound
        assert_ne!(args_put(&id, 100), args_put(&[0x12; 32], 100)); // id bound

        // distinct ops never collide even on similar inputs.
        assert_ne!(args_cas_head(&id, &[1; 32], &[2; 32]), args_put(&id, 0));
        assert_ne!(
            args_cas_head(&id, &[1; 32], &[2; 32]),
            args_cas_head(&id, &[2; 32], &[1; 32]) // old/new order bound
        );
        assert_ne!(
            args_roster_append(b"entry-a"),
            args_roster_append(b"entry-b")
        );
    }

    #[test]
    fn args_read_binds_op_ids_and_order() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(args_read(op::GET, &[a, b]), args_read(op::GET, &[a, b]));
        assert_ne!(args_read(op::GET, &[a, b]), args_read(op::HAS, &[a, b])); // op bound
        assert_ne!(args_read(op::GET, &[a, b]), args_read(op::GET, &[b, a])); // order bound
        assert_ne!(args_read(op::GET, &[a]), args_read(op::GET, &[a, b])); // count bound
                                                                           // a count-prefix (not just concatenation) prevents [a]+[b..] aliasing a single id, etc.
        assert_ne!(args_read(op::GET, &[a, b]), args_read(op::GET, &[]));
    }

    #[test]
    fn get_ref_is_a_read_op_bound_to_ref_hash() {
        let (op, args, is_write) = op_and_args(&wire::Request::GetRef { ref_h: [7u8; 32] });
        assert_eq!(op, op::GET_REF);
        assert!(!is_write, "reading a head is a read op (secsec-read-v1)");
        assert_eq!(args, args_read(op::GET_REF, &[[7u8; 32]]));
        // a different ref hash gives a different binding; the op label is distinct from `get`.
        let (_, other, _) = op_and_args(&wire::Request::GetRef { ref_h: [8u8; 32] });
        assert_ne!(args, other);
        assert_ne!(args, args_read(op::GET, &[[7u8; 32]]));
    }

    #[test]
    fn write_auth_round_trip_and_binding() {
        let dev = DeviceKey::generate().unwrap();
        let base = WriteAuth {
            op: op::PUT,
            args_hash: args_put(&[0xAB; 32], 42),
            session_transcript: [0x7a; 32],
            server_nonce: [0x5e; 32],
        };
        let sig = base.sign(&dev).unwrap();
        assert!(base.verify(&dev.public(), &sig).is_ok());

        // every field is bound.
        for altered in [
            WriteAuth { op: op::GC, ..base },
            WriteAuth {
                args_hash: [0; 32],
                ..base
            },
            WriteAuth {
                session_transcript: [0; 32],
                ..base
            },
            WriteAuth {
                server_nonce: [0; 32],
                ..base
            },
        ] {
            assert!(matches!(
                altered.verify(&dev.public(), &sig),
                Err(ProtoError::BadSignature)
            ));
        }
        // wrong signer.
        let other = DeviceKey::generate().unwrap().public();
        assert!(base.verify(&other, &sig).is_err());
    }

    #[test]
    fn read_auth_round_trip_and_no_nonce() {
        let dev = DeviceKey::generate().unwrap();
        let base = ReadAuth {
            op: op::GET,
            args_hash: args_read(op::GET, &[[0xCD; 32]]),
            session_transcript: [0x7a; 32],
        };
        let sig = base.sign(&dev).unwrap();
        assert!(base.verify(&dev.public(), &sig).is_ok());

        let tampered = ReadAuth {
            args_hash: [0; 32],
            ..base
        };
        assert!(tampered.verify(&dev.public(), &sig).is_err());
    }

    #[test]
    fn write_and_read_namespaces_are_disjoint() {
        // a write-auth signature must not verify as read-auth or connection-auth, and vice versa
        // (§9.6 cross-protocol guard) — even when the message bytes happen to coincide.
        let dev = DeviceKey::generate().unwrap();
        let msg = b"identical-bytes";
        let w = dev.sign(NS_WRITE, msg).unwrap();
        assert!(dev.public().verify(NS_WRITE, msg, &w).is_ok());
        assert!(dev.public().verify(NS_READ, msg, &w).is_err());
        assert!(dev.public().verify(NS_AUTH, msg, &w).is_err());
    }
}
