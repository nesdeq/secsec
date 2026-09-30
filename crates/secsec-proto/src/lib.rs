//! Per-operation authorization for the server API: `args_hash` bindings and write/read-auth signatures (`secsec-Design.md` §9.6, §12).

#![forbid(unsafe_code)]

pub mod prune;
pub mod server;
pub mod wire;

use secsec_canon::Writer;
use secsec_sig::{DeviceKey, DevicePublic, NS_READ, NS_WRITE};

/// A 256-bit id / hash.
pub type Id = [u8; 32];

/// A per-attempt `push_id` length, in bytes (§15).
pub const PUSH_ID_LEN: usize = 16;

/// Op labels (§12), length-prefixed inside every `args_hash` and the signed payload.
pub mod op {
    /// Stage an object.
    pub const PUT: &str = "put";
    /// Atomic ref CAS.
    pub const CAS_HEAD: &str = "cas-head";
    /// Atomic roster-side batch (entries, keyslots, key histories, revocations, head re-sign).
    pub const ROSTER_BATCH: &str = "roster-batch";
    /// Retention prune (§15).
    pub const PRUNE: &str = "prune";
    /// Fetch a blob.
    pub const GET: &str = "get";
    /// Existence check.
    pub const HAS: &str = "has";
    /// Fetch a head blob.
    pub const GET_REF: &str = "get-ref";
    /// Fetch a sigchain entry.
    pub const GET_ROSTER: &str = "get-roster";
    /// Fetch a keyslot.
    pub const GET_KEYSLOT: &str = "get-keyslot";
    /// Post to the pairing mailbox (§7).
    pub const PAIR_PUT: &str = "pair-put";
    /// Take from the pairing mailbox (§7).
    pub const PAIR_GET: &str = "pair-get";
    /// Fetch a roster-key-history wrap.
    pub const GET_ROSTER_KEYHIST: &str = "get-roster-keyhist";
    /// Fetch a data key-history wrap.
    pub const GET_KEYHIST: &str = "get-keyhist";
}

fn blake3_of(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// `BLAKE3(canonical(op ‖ fields))` with `op` length-prefixed, the form of every `args_hash` (§12).
fn args(op_label: &str, fields: impl FnOnce(&mut Writer)) -> [u8; 32] {
    let mut w = Writer::new();
    w.bytes(op_label.as_bytes());
    fields(&mut w);
    blake3_of(&w.finish())
}

/// `args_hash` for a read of `ids` (§9.6): `op ‖ le64(n) ‖ ids`, order-bound.
#[must_use]
pub(crate) fn args_read(op_label: &str, ids: &[Id]) -> [u8; 32] {
    args(op_label, |w| {
        w.u64(ids.len() as u64);
        for id in ids {
            w.raw(id);
        }
    })
}

/// The op label, recomputed `args_hash`, and write flag for a request; client and server share it (§12).
#[must_use]
pub fn op_and_args(req: &wire::Request) -> (&'static str, [u8; 32], bool) {
    use wire::Request;
    match req {
        Request::Get { id } => (op::GET, args_read(op::GET, &[*id]), false),
        Request::Has { ids } => (op::HAS, args_read(op::HAS, ids), false),
        Request::GetRef { ref_h } => (op::GET_REF, args_read(op::GET_REF, &[*ref_h]), false),
        Request::GetRosterEntry { seq } => (
            op::GET_ROSTER,
            args(op::GET_ROSTER, |w| {
                w.u64(*seq);
            }),
            false,
        ),
        Request::GetKeyslot { device_id, gen } => (
            op::GET_KEYSLOT,
            args(op::GET_KEYSLOT, |w| {
                w.raw(device_id).u32(*gen);
            }),
            false,
        ),
        Request::GetRosterKeyhist { gen } => (
            op::GET_ROSTER_KEYHIST,
            args(op::GET_ROSTER_KEYHIST, |w| {
                w.u32(*gen);
            }),
            false,
        ),
        Request::GetKeyhist { gen } => (
            op::GET_KEYHIST,
            args(op::GET_KEYHIST, |w| {
                w.u32(*gen);
            }),
            false,
        ),
        // The client's claimed state is what it signs; the server honours it only if it still holds (§15).
        Request::Prune {
            dead,
            all_heads_hash,
            roster_len,
        } => (
            op::PRUNE,
            prune::args_prune(&prune::dead_set_hash(dead), all_heads_hash, *roster_len),
            true,
        ),
        Request::Put {
            id,
            declared_size,
            push_id,
            ..
        } => (
            op::PUT,
            args(op::PUT, |w| {
                w.raw(id).u32(*declared_size).raw(push_id);
            }),
            true,
        ),
        Request::CasHead {
            ref_h,
            old_head,
            new_head,
            promote,
            ..
        } => (
            op::CAS_HEAD,
            args(op::CAS_HEAD, |w| {
                w.raw(ref_h).raw(old_head).raw(new_head).raw(promote);
            }),
            true,
        ),
        Request::RosterBatch { .. } => (
            op::ROSTER_BATCH,
            args(op::ROSTER_BATCH, |w| {
                w.raw(&blake3_of(&req.encode()));
            }),
            true,
        ),
        // Pairing is read-auth (no nonce), dispatched before the enrollment check (§7).
        Request::PairPut { slot, .. } => (
            op::PAIR_PUT,
            args(op::PAIR_PUT, |w| {
                w.raw(slot);
            }),
            false,
        ),
        Request::PairGet { slot } => (
            op::PAIR_GET,
            args(op::PAIR_GET, |w| {
                w.raw(slot);
            }),
            false,
        ),
    }
}

/// Errors from per-op authorization.
#[derive(Debug)]
pub enum ProtoError {
    /// The per-op signature did not verify.
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

/// A write authorization (`secsec-write-v1`): the server supplies `server_nonce`, the client `op`/`args_hash`.
#[derive(Clone, Copy)]
pub struct WriteAuth<'a> {
    /// The op label.
    pub op: &'a str,
    /// The per-op `args_hash`.
    pub args_hash: [u8; 32],
    /// The connection's session transcript (§11).
    pub session_transcript: [u8; 32],
    /// The server's per-stream challenge.
    pub server_nonce: [u8; 32],
}

impl WriteAuth<'_> {
    /// The signed payload `op ‖ args_hash ‖ session_transcript ‖ server_nonce` (§9.6).
    #[must_use]
    pub(crate) fn message(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(self.op.as_bytes())
            .raw(&self.args_hash)
            .raw(&self.session_transcript)
            .raw(&self.server_nonce);
        w.finish()
    }

    /// Sign under `NS_WRITE`.
    pub fn sign(&self, device: &DeviceKey) -> Result<Vec<u8>, ProtoError> {
        Ok(device.sign(NS_WRITE, &self.message())?)
    }

    /// Verify against `pubkey`.
    pub fn verify(&self, pubkey: &DevicePublic, sig: &[u8]) -> Result<(), ProtoError> {
        pubkey
            .verify(NS_WRITE, &self.message(), sig)
            .map_err(|_| ProtoError::BadSignature)
    }
}

/// A read authorization (`secsec-read-v1`): no nonce, the transcript gives per-connection freshness.
#[derive(Clone, Copy)]
pub struct ReadAuth<'a> {
    /// The op label.
    pub op: &'a str,
    /// The per-op `args_hash`.
    pub args_hash: [u8; 32],
    /// The connection's session transcript (§11).
    pub session_transcript: [u8; 32],
}

impl ReadAuth<'_> {
    /// The signed payload `op ‖ args_hash ‖ session_transcript` (§9.6).
    #[must_use]
    pub(crate) fn message(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(self.op.as_bytes())
            .raw(&self.args_hash)
            .raw(&self.session_transcript);
        w.finish()
    }

    /// Sign under `NS_READ`.
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
    use wire::Request;

    fn put(id: Id, size: u32, push: [u8; PUSH_ID_LEN]) -> [u8; 32] {
        op_and_args(&Request::Put {
            id,
            declared_size: size,
            push_id: push,
            blob: vec![],
        })
        .1
    }

    fn cas(old: Id, new: Id, promote: [u8; PUSH_ID_LEN]) -> [u8; 32] {
        op_and_args(&Request::CasHead {
            ref_h: [0x11; 32],
            old_head: old,
            new_head: new,
            promote,
            new_blob: vec![],
        })
        .1
    }

    #[test]
    fn args_hashes_bind_every_field() {
        let id = [0x11; 32];
        let p = [0u8; PUSH_ID_LEN];
        assert_eq!(put(id, 100, p), put(id, 100, p));
        assert_ne!(put(id, 100, p), put(id, 101, p));
        assert_ne!(put(id, 100, p), put([0x12; 32], 100, p));
        assert_ne!(put(id, 100, p), put(id, 100, [1; PUSH_ID_LEN]));
        assert_ne!(cas([1; 32], [2; 32], p), cas([2; 32], [1; 32], p));
        assert_ne!(
            cas([1; 32], [2; 32], p),
            cas([1; 32], [2; 32], [9; PUSH_ID_LEN])
        );
        // The put blob itself is bound by the id (content address), not the args hash.
        let with_blob = op_and_args(&Request::Put {
            id,
            declared_size: 100,
            push_id: p,
            blob: b"x".to_vec(),
        })
        .1;
        assert_eq!(with_blob, put(id, 100, p));
    }

    #[test]
    fn roster_batch_binds_its_whole_encoding() {
        let batch = |revoke: Vec<Id>| Request::RosterBatch {
            old_tip: [1; 32],
            entries: vec![b"e".to_vec()],
            keyslots: vec![],
            keyhist: None,
            roster_keyhist: None,
            revoke,
            head: None,
        };
        let (op_label, a, is_write) = op_and_args(&batch(vec![]));
        assert_eq!(op_label, op::ROSTER_BATCH);
        assert!(is_write);
        assert_ne!(a, op_and_args(&batch(vec![[2; 32]])).1);
    }

    #[test]
    fn args_read_binds_op_ids_and_order() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(args_read(op::GET, &[a, b]), args_read(op::GET, &[a, b]));
        assert_ne!(args_read(op::GET, &[a, b]), args_read(op::HAS, &[a, b]));
        assert_ne!(args_read(op::GET, &[a, b]), args_read(op::GET, &[b, a]));
        assert_ne!(args_read(op::GET, &[a]), args_read(op::GET, &[a, b]));
        assert_ne!(args_read(op::GET, &[a, b]), args_read(op::GET, &[]));
    }

    #[test]
    fn get_ref_is_a_read_op_bound_to_ref_hash() {
        let (op_label, a, is_write) = op_and_args(&Request::GetRef { ref_h: [7u8; 32] });
        assert_eq!(op_label, op::GET_REF);
        assert!(!is_write);
        assert_eq!(a, args_read(op::GET_REF, &[[7u8; 32]]));
        assert_ne!(a, op_and_args(&Request::GetRef { ref_h: [8u8; 32] }).1);
        assert_ne!(a, args_read(op::GET, &[[7u8; 32]]));
    }

    #[test]
    fn write_auth_round_trip_and_binding() {
        let dev = DeviceKey::generate().unwrap();
        let base = WriteAuth {
            op: op::PUT,
            args_hash: put([0xAB; 32], 42, [0u8; PUSH_ID_LEN]),
            session_transcript: [0x7a; 32],
            server_nonce: [0x5e; 32],
        };
        let sig = base.sign(&dev).unwrap();
        assert!(base.verify(&dev.public(), &sig).is_ok());
        for altered in [
            WriteAuth {
                op: op::PRUNE,
                ..base
            },
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
        assert!(base
            .verify(&DeviceKey::generate().unwrap().public(), &sig)
            .is_err());
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
        let dev = DeviceKey::generate().unwrap();
        let msg = b"identical-bytes";
        let w = dev.sign(NS_WRITE, msg).unwrap();
        assert!(dev.public().verify(NS_WRITE, msg, &w).is_ok());
        assert!(dev.public().verify(NS_READ, msg, &w).is_err());
        assert!(dev.public().verify(NS_AUTH, msg, &w).is_err());
    }
}
