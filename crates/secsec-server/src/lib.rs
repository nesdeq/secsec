//! `secsec-server` — the server request handler (`finaldesign.md` §12, §19). The §12 authorization
//! pipeline a `secsec serve` loop runs for every per-op request, over the content-addressed object
//! store ([`secsec_store::Store`]):
//!
//! 1. **keyslot existence** — the connecting key must own a keyslot (be rostered); else `not-enrolled`;
//! 2. **per-op authorization** — verify the `secsec-write-v1` / `secsec-read-v1` signature over the
//!    op's `args_hash` + the session transcript (+ `server_nonce` for writes), recomputing `args_hash`
//!    from the request so the client can't lie about what it signed;
//! 3. **nonce freshness** — consume the `server_nonce` exactly once (writes), defeating replay;
//! 4. **limits** — per-key write byte-rate + burst and storage quota (§19), the `has` id cap;
//! 5. **execute** — against the blob store.
//!
//! The server is **blind**: it stores opaque blobs by id and never verifies or reads their content
//! (content-addressing is re-checked by *clients* on fetch, §9.2). This slice handles the object ops
//! (`get`/`has`/`put`); `cas-head`/`roster-append` need mutable ref/sigchain storage and land with
//! the store extensions (their auth is still verified here).
//!
//! The handler is pure and clock-injected (`now`), so the whole §12 pipeline is unit-testable by
//! calling [`Server::handle`] directly — no sockets.

#![forbid(unsafe_code)]

use secsec_proto::server::{limits, NonceStore, StorageQuota, TokenBucket};
use secsec_proto::wire::{ErrorCode, Request, Response};
use secsec_proto::{
    args_cas_head, args_put, args_read, args_roster_append, op, ReadAuth, WriteAuth,
};
use secsec_sig::{DeviceId, DevicePublic};
use secsec_store::Store;
use std::collections::HashMap;

/// One authenticated per-op request, as resolved by the connection-auth + framing layers: the
/// connection's authenticated public key, the operation, its per-op signature, the session
/// transcript, and (for writes) the `server_nonce` the client signed.
pub struct Incoming<'a> {
    /// The public key that completed connection auth on this connection.
    pub pubkey: &'a DevicePublic,
    /// The requested operation.
    pub request: Request,
    /// The per-op `secsec-write-v1` / `secsec-read-v1` signature.
    pub op_sig: Vec<u8>,
    /// The connection's session transcript (§11).
    pub session_transcript: [u8; 32],
    /// The `server_nonce` the client signed (writes only; `None` for reads).
    pub server_nonce: Option<[u8; 32]>,
}

/// The server's per-op handler state. The §12 keyslot-existence check reads the keyslot store
/// directly (`/keyslots/<device_id>/*`).
pub struct Server {
    store: Store,
    nonces: NonceStore,
    write_buckets: HashMap<DeviceId, TokenBucket>,
    quotas: HashMap<DeviceId, StorageQuota>,
}

impl Server {
    /// Build a handler over `store`.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self {
            store,
            nonces: NonceStore::default(),
            write_buckets: HashMap::new(),
            quotas: HashMap::new(),
        }
    }

    /// Borrow the underlying object + keyslot store (e.g. for enrollment writes by the orchestration
    /// layer, or `keyslot_exists` queries).
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Issue a fresh `server_nonce` challenge (the caller draws it from the OS CSPRNG and sends it to
    /// the client). It is honoured once, within the §19 TTL.
    pub fn issue_nonce(&mut self, nonce: [u8; 32], now: u64) {
        self.nonces.issue(nonce, now);
    }

    fn write_bucket(&mut self, d: DeviceId, now: u64) -> &mut TokenBucket {
        self.write_buckets.entry(d).or_insert_with(|| {
            TokenBucket::new(
                limits::WRITE_BURST_BYTES,
                limits::WRITE_RATE_BYTES_PER_SEC,
                now,
            )
        })
    }

    fn quota(&mut self, d: DeviceId) -> &mut StorageQuota {
        self.quotas
            .entry(d)
            .or_insert_with(|| StorageQuota::new(limits::PER_KEY_STORAGE_QUOTA))
    }

    /// Run the §12 pipeline for one request and return the response.
    pub fn handle(&mut self, inc: Incoming<'_>, now: u64) -> Response {
        // (1) keyslot existence: the connecting key must be rostered.
        let device_id = match inc.pubkey.device_id() {
            Ok(d) => d,
            Err(_) => return Response::Err(ErrorCode::BadRequest),
        };
        // keyslot presence only (no decryption) — a store error fails closed.
        if !self.store.keyslot_exists(&device_id).unwrap_or(false) {
            return Response::Err(ErrorCode::NotEnrolled);
        }

        // (2) per-op authorization: recompute args_hash from the request and verify the signature.
        let (op_label, args_hash, is_write) = op_and_args(&inc.request);
        if is_write {
            let Some(nonce) = inc.server_nonce else {
                return Response::Err(ErrorCode::BadAuth);
            };
            let wa = WriteAuth {
                op: op_label,
                args_hash,
                session_transcript: inc.session_transcript,
                server_nonce: nonce,
            };
            if wa.verify(inc.pubkey, &inc.op_sig).is_err() {
                return Response::Err(ErrorCode::BadAuth);
            }
            // (3) nonce freshness: consume exactly once (after verifying the sig binds it).
            if !self.nonces.consume(&nonce, now) {
                return Response::Err(ErrorCode::BadAuth);
            }
        } else {
            let ra = ReadAuth {
                op: op_label,
                args_hash,
                session_transcript: inc.session_transcript,
            };
            if ra.verify(inc.pubkey, &inc.op_sig).is_err() {
                return Response::Err(ErrorCode::BadAuth);
            }
        }

        // (4 + 5) limits + execute.
        match inc.request {
            Request::Get { id } => match self.store.get(&id) {
                Ok(blob) => Response::Blob(blob),
                Err(_) => Response::Err(ErrorCode::Internal),
            },
            Request::Has { ids } => {
                if ids.len() > limits::MAX_HAS_IDS {
                    return Response::Err(ErrorCode::TooManyIds);
                }
                match self.store.has(&ids) {
                    Ok(bits) => Response::Exists(bits),
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            Request::Put {
                id,
                declared_size,
                blob,
            } => {
                if blob.len() != declared_size as usize {
                    return Response::Err(ErrorCode::BadRequest);
                }
                // write byte-rate limit (§19: 100 MB/s sustained, 1 GiB burst).
                if !self
                    .write_bucket(device_id, now)
                    .try_take(blob.len() as u64, now)
                {
                    return Response::Err(ErrorCode::RateLimit);
                }
                // storage quota — only charge a genuinely new object (put is idempotent by id).
                let present = self.store.has(&[id]).map(|b| b[0]).unwrap_or(false);
                if !present && !self.quota(device_id).try_add(blob.len() as u64) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                match self.store.put(&id, &blob) {
                    Ok(_) => Response::Ok,
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            // ref / sigchain storage lands with the store extensions; their auth was verified above.
            Request::CasHead { .. } | Request::RosterAppend { .. } => {
                Response::Err(ErrorCode::Internal)
            }
        }
    }
}

/// The op label, recomputed `args_hash`, and write/read class for a request (§12).
fn op_and_args(req: &Request) -> (&'static str, [u8; 32], bool) {
    match req {
        Request::Get { id } => (op::GET, args_read(op::GET, &[*id]), false),
        Request::Has { ids } => (op::HAS, args_read(op::HAS, ids), false),
        Request::Put {
            id, declared_size, ..
        } => (op::PUT, args_put(id, *declared_size), true),
        Request::CasHead {
            ref_h,
            old_head,
            new_head,
            ..
        } => (op::CAS_HEAD, args_cas_head(ref_h, old_head, new_head), true),
        Request::RosterAppend { entry } => (op::ROSTER_APPEND, args_roster_append(entry), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secsec_sig::DeviceKey;

    fn server() -> (Server, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("objs.redb")).unwrap();
        (Server::new(store), dir)
    }

    /// Enroll `dev` by writing it a keyslot (the §12 keyslot-existence backing).
    fn enroll(s: &Server, dev: &DeviceKey) {
        s.store()
            .put_keyslot(&dev.device_id().unwrap(), 1, b"keyslot")
            .unwrap();
    }

    /// Sign a read request as `dev` would.
    fn read_req(dev: &DeviceKey, request: Request, transcript: [u8; 32]) -> Incoming<'_> {
        let (op_label, args_hash, _) = op_and_args(&request);
        let ra = ReadAuth {
            op: op_label,
            args_hash,
            session_transcript: transcript,
        };
        let sig = ra.sign(dev).unwrap();
        Incoming {
            pubkey: Box::leak(Box::new(dev.public())),
            request,
            op_sig: sig,
            session_transcript: transcript,
            server_nonce: None,
        }
    }

    /// Sign a write request as `dev` would, with `nonce`.
    fn write_req(
        dev: &DeviceKey,
        request: Request,
        transcript: [u8; 32],
        nonce: [u8; 32],
    ) -> Incoming<'_> {
        let (op_label, args_hash, _) = op_and_args(&request);
        let wa = WriteAuth {
            op: op_label,
            args_hash,
            session_transcript: transcript,
            server_nonce: nonce,
        };
        let sig = wa.sign(dev).unwrap();
        Incoming {
            pubkey: Box::leak(Box::new(dev.public())),
            request,
            op_sig: sig,
            session_transcript: transcript,
            server_nonce: Some(nonce),
        }
    }

    const T: [u8; 32] = [0x7a; 32];

    #[test]
    fn unenrolled_key_is_rejected() {
        let (mut s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        let resp = s.handle(read_req(&dev, Request::Get { id: [1; 32] }, T), 0);
        assert_eq!(resp, Response::Err(ErrorCode::NotEnrolled));
    }

    #[test]
    fn put_then_get_round_trip() {
        let (mut s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let id = [0x22; 32];
        let blob = b"object-bytes".to_vec();

        // put (needs a freshly-issued nonce).
        let nonce = [0x01; 32];
        s.issue_nonce(nonce, 0);
        let put = Request::Put {
            id,
            declared_size: blob.len() as u32,
            blob: blob.clone(),
        };
        assert_eq!(s.handle(write_req(&dev, put, T, nonce), 0), Response::Ok);

        // get it back.
        let got = s.handle(read_req(&dev, Request::Get { id }, T), 0);
        assert_eq!(got, Response::Blob(Some(blob)));
        // absent id -> None.
        assert_eq!(
            s.handle(read_req(&dev, Request::Get { id: [0x99; 32] }, T), 0),
            Response::Blob(None)
        );
    }

    #[test]
    fn bad_signature_is_rejected() {
        let (mut s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        // tamper the signature.
        let mut inc = read_req(&dev, Request::Get { id: [1; 32] }, T);
        *inc.op_sig.last_mut().unwrap() ^= 0x01;
        assert_eq!(s.handle(inc, 0), Response::Err(ErrorCode::BadAuth));
    }

    #[test]
    fn forged_args_are_rejected() {
        // a request whose fields differ from what was signed must fail (server recomputes args_hash).
        let (mut s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let mut inc = read_req(&dev, Request::Get { id: [1; 32] }, T);
        // swap the requested id after signing.
        inc.request = Request::Get { id: [2; 32] };
        assert_eq!(s.handle(inc, 0), Response::Err(ErrorCode::BadAuth));
    }

    #[test]
    fn write_nonce_is_single_use() {
        let (mut s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let nonce = [0x05; 32];
        s.issue_nonce(nonce, 0);
        let put = Request::Put {
            id: [3; 32],
            declared_size: 1,
            blob: vec![0u8],
        };
        // first use ok.
        assert_eq!(
            s.handle(write_req(&dev, put.clone(), T, nonce), 0),
            Response::Ok
        );
        // replay with the same nonce -> rejected (single-use).
        assert_eq!(
            s.handle(write_req(&dev, put, T, nonce), 0),
            Response::Err(ErrorCode::BadAuth)
        );
    }

    #[test]
    fn write_without_issued_nonce_is_rejected() {
        let (mut s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        // never issued -> consume fails.
        let put = Request::Put {
            id: [4; 32],
            declared_size: 1,
            blob: vec![0u8],
        };
        assert_eq!(
            s.handle(write_req(&dev, put, T, [0xAA; 32]), 0),
            Response::Err(ErrorCode::BadAuth)
        );
    }

    #[test]
    fn put_declared_size_mismatch_is_bad_request() {
        let (mut s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let nonce = [0x06; 32];
        s.issue_nonce(nonce, 0);
        let put = Request::Put {
            id: [5; 32],
            declared_size: 99, // lies about the size
            blob: vec![0u8; 3],
        };
        assert_eq!(
            s.handle(write_req(&dev, put, T, nonce), 0),
            Response::Err(ErrorCode::BadRequest)
        );
    }

    #[test]
    fn has_over_cap_is_rejected() {
        let (mut s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let ids = vec![[0u8; 32]; limits::MAX_HAS_IDS + 1];
        assert_eq!(
            s.handle(read_req(&dev, Request::Has { ids }, T), 0),
            Response::Err(ErrorCode::TooManyIds)
        );
    }
}
