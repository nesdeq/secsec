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
//! (content-addressing is re-checked by *clients* on fetch, §9.2). `get`/`has`/`put`/`cas-head`/
//! `roster-append` are all executed; the mutable ops CAS on a `BLAKE3` of the stored (encrypted) tip
//! blob (§12, blind-server). `gc` (§15) is the remaining op and lands with the hardened-GC work (M6).
//!
//! The handler is pure and clock-injected (`now`), so the whole §12 pipeline is unit-testable by
//! calling [`Server::handle`] directly — no sockets.

#![forbid(unsafe_code)]

pub mod serve;

use secsec_proto::server::{limits, NonceStore, StorageQuota, TokenBucket, WindowCounter};
use secsec_proto::wire::{ErrorCode, Request, Response};
use secsec_proto::{gc, op, op_and_args, ReadAuth, WriteAuth};
use secsec_sig::{DeviceId, DevicePublic};
use secsec_store::Store;
use std::collections::{BTreeSet, HashMap};

/// One hour, in seconds — the `gc` rate-limit window (§19: 4 gc calls / key / hour).
const GC_WINDOW_SECS: u64 = 3600;

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

/// The brief, mutable rate-limit / replay state — the only thing that needs synchronizing between
/// concurrent requests. Held behind a fast `std::sync::Mutex` and locked only for the duration of a
/// counter update (no I/O, no `await`), so it never blocks the redb store, which is itself
/// transactional and accessed lock-free.
#[derive(Default)]
struct ServerState {
    nonces: NonceStore,
    write_buckets: HashMap<DeviceId, TokenBucket>,
    quotas: HashMap<DeviceId, StorageQuota>,
    gc_calls: HashMap<DeviceId, WindowCounter>,
}

impl ServerState {
    fn gc_record(&mut self, d: DeviceId, now: u64) -> bool {
        self.gc_calls
            .entry(d)
            .or_insert_with(|| WindowCounter::new(GC_WINDOW_SECS, limits::MAX_GC_CALLS_PER_HOUR))
            .try_record(now)
    }

    fn take_write(&mut self, d: DeviceId, n: u64, now: u64) -> bool {
        self.write_buckets
            .entry(d)
            .or_insert_with(|| {
                TokenBucket::new(
                    limits::WRITE_BURST_BYTES,
                    limits::WRITE_RATE_BYTES_PER_SEC,
                    now,
                )
            })
            .try_take(n, now)
    }

    fn add_quota(&mut self, d: DeviceId, n: u64) -> bool {
        self.quotas
            .entry(d)
            .or_insert_with(|| StorageQuota::new(limits::PER_KEY_STORAGE_QUOTA))
            .try_add(n)
    }
}

/// The server's per-op handler. The §12 keyslot-existence check and all object ops read/write the
/// redb store **without a lock** (redb is transactional); only the small replay/rate-limit
/// [`ServerState`] is mutex-guarded. `handle` takes `&self`, so the whole server is shared via
/// `Arc<Server>` and serves requests concurrently.
pub struct Server {
    store: Store,
    state: std::sync::Mutex<ServerState>,
    /// Optional host receipt key + this server's `host_id` (§15 signed receipts). `None` ⇒ receipts
    /// are returned unsigned (all-zero pubkey/signature).
    receipts: Option<(ed25519_dalek::SigningKey, [u8; 32])>,
}

impl Server {
    /// Build a handler over `store` (receipts unsigned).
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self {
            store,
            state: std::sync::Mutex::new(ServerState::default()),
            receipts: None,
        }
    }

    /// Enable §15 **signed arrival receipts**: `receipt_seed` is the host's 32-byte Ed25519 receipt
    /// key seed, `host_id` is this server's `host_id` (`BLAKE3` of its pinned SPKI). Each `put` then
    /// returns a receipt signed over `id ‖ host_id ‖ arrival_gen ‖ put_epoch ‖ ts`.
    #[must_use]
    pub fn with_receipts(mut self, receipt_seed: &[u8; 32], host_id: [u8; 32]) -> Self {
        self.receipts = Some((ed25519_dalek::SigningKey::from_bytes(receipt_seed), host_id));
        self
    }

    /// Borrow the underlying object + keyslot store (e.g. for enrollment writes by the orchestration
    /// layer, or `keyslot_exists` queries).
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Issue a fresh `server_nonce` challenge (the caller draws it from the OS CSPRNG and sends it to
    /// the client). It is honoured once, within the §19 TTL.
    pub fn issue_nonce(&self, nonce: [u8; 32], now: u64) {
        self.state
            .lock()
            .expect("server state")
            .nonces
            .issue(nonce, now);
    }

    fn consume_nonce(&self, nonce: &[u8; 32], now: u64) -> bool {
        self.state
            .lock()
            .expect("server state")
            .nonces
            .consume(nonce, now)
    }

    fn take_write(&self, d: DeviceId, n: u64, now: u64) -> bool {
        self.state
            .lock()
            .expect("server state")
            .take_write(d, n, now)
    }

    fn add_quota(&self, d: DeviceId, n: u64) -> bool {
        self.state.lock().expect("server state").add_quota(d, n)
    }

    fn gc_allow(&self, d: DeviceId, now: u64) -> bool {
        self.state.lock().expect("server state").gc_record(d, now)
    }

    /// Build the §15 `Stored` receipt, signed by the host receipt key when configured ([`with_receipts`];
    /// else all-zero pubkey/signature).
    fn receipt(&self, id: &[u8; 32], arrival_gen: u64, put_epoch: u64, now: u64) -> Response {
        let (receipt_pubkey, signature) = match &self.receipts {
            Some((key, host_id)) => (
                secsec_proto::receipt::receipt_public(key),
                secsec_proto::receipt::sign_receipt(key, id, host_id, arrival_gen, put_epoch, now),
            ),
            None => ([0u8; 32], [0u8; 64]),
        };
        Response::Stored {
            arrival_gen,
            put_epoch,
            ts: now,
            receipt_pubkey,
            signature,
        }
    }

    /// Run the §12 pipeline for one request and return the response.
    pub fn handle(&self, inc: Incoming<'_>, now: u64) -> Response {
        // (1) keyslot existence: the connecting key must be rostered.
        let device_id = match inc.pubkey.device_id() {
            Ok(d) => d,
            Err(_) => return Response::Err(ErrorCode::BadRequest),
        };
        // keyslot presence only (no decryption) — a store error fails closed.
        if !self.store.keyslot_exists(&device_id).unwrap_or(false) {
            return Response::Err(ErrorCode::NotEnrolled);
        }

        // gc has a state-dependent args_hash (§15 compare-and-swap), so it is authorized separately
        // from the generic op_and_args path below.
        if matches!(inc.request, Request::Gc { .. }) {
            return self.handle_gc(inc, device_id, now);
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
            if !self.consume_nonce(&nonce, now) {
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
            Request::GetRef { ref_h } => match self.store.get_ref(&ref_h) {
                Ok(blob) => Response::Blob(blob),
                Err(_) => Response::Err(ErrorCode::Internal),
            },
            Request::GetRosterEntry { seq } => match self.store.get_roster_entry(seq) {
                Ok(blob) => Response::Blob(blob),
                Err(_) => Response::Err(ErrorCode::Internal),
            },
            Request::GetKeyslot { device_id, gen } => match self.store.get_keyslot(&device_id, gen)
            {
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
                if !self.take_write(device_id, blob.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                // storage quota — only charge a genuinely new object (put is idempotent by id).
                let present = self.store.has(&[id]).map(|b| b[0]).unwrap_or(false);
                if !present && !self.add_quota(device_id, blob.len() as u64) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                // Store, then return the §15 arrival receipt (the object's arrival generation + the
                // server's current global put_epoch) so the client can derive gc_gen and bind the gc CAS.
                match self.store.put(&id, &blob) {
                    Ok(_) => match (self.store.arrival_epoch(&id), self.store.put_epoch()) {
                        (Ok(Some(arrival_gen)), Ok(put_epoch)) => {
                            self.receipt(&id, arrival_gen, put_epoch, now)
                        }
                        _ => Response::Err(ErrorCode::Internal),
                    },
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            Request::CasHead {
                ref_h,
                old_head,
                new_head,
                new_blob,
            } => {
                // The attached new head blob must hash to the signed new_head (§12 cas-head semantics).
                if *blake3::hash(&new_blob).as_bytes() != new_head {
                    return Response::Err(ErrorCode::BadRequest);
                }
                if !self.take_write(device_id, new_blob.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                // Atomic compare-and-swap on the server-visible blob hash (blind server, §12).
                match self.store.cas_ref(&ref_h, &old_head, &new_blob) {
                    Ok(true) => Response::Ok,
                    Ok(false) => Response::Err(ErrorCode::CasConflict),
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            Request::RosterAppend { old_tip, entry } => {
                if !self.take_write(device_id, entry.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                // Append CAS-guarded by the /roster-head tip (§8.1): a racing append loses.
                match self.store.append_roster(&old_tip, &entry) {
                    Ok(Some(_seq)) => Response::Ok,
                    Ok(None) => Response::Err(ErrorCode::CasConflict),
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            // gc is dispatched before this match (state-dependent auth, §15); never reached here.
            Request::Gc { .. } => Response::Err(ErrorCode::Internal),
        }
    }

    /// The §15 `gc` pipeline. The `args_hash` is recomputed from the **server's** current mutable state
    /// (`all_heads_hash` over the stored head blobs, `roster_seq`, `put_epoch`); verifying the client's
    /// `secsec-write-v1` signature over that message **is** the compare-and-swap — a concurrent
    /// `cas-head`/`roster-append`/`put` changes a bound value, so the recomputed message differs and the
    /// signature fails (`BadAuth`), aborting the sweep rather than deleting against stale state.
    fn handle_gc(&self, inc: Incoming<'_>, device_id: DeviceId, now: u64) -> Response {
        let Request::Gc { keep_set, gc_gen } = inc.request else {
            return Response::Err(ErrorCode::Internal);
        };
        if keep_set.len() > limits::MAX_GC_KEEP_SET_IDS {
            return Response::Err(ErrorCode::TooManyIds);
        }
        let Some(nonce) = inc.server_nonce else {
            return Response::Err(ErrorCode::BadAuth);
        };

        // Recompute args_gc from the server's current state.
        let (refs, roster_len, put_epoch) = match (
            self.store.ref_blob_hashes(),
            self.store.roster_len(),
            self.store.put_epoch(),
        ) {
            (Ok(r), Ok(n), Ok(p)) => (r, n, p),
            _ => return Response::Err(ErrorCode::Internal),
        };
        let roster_seq = roster_len.saturating_sub(1);
        let args_hash = gc::args_gc(
            &gc::keep_set_hash(&keep_set),
            gc_gen,
            &gc::all_heads_hash(&refs),
            roster_seq,
            put_epoch,
        );

        let wa = WriteAuth {
            op: op::GC,
            args_hash,
            session_transcript: inc.session_transcript,
            server_nonce: nonce,
        };
        if wa.verify(inc.pubkey, &inc.op_sig).is_err() {
            // Bad signature OR the client's view of all_heads_hash/roster_seq/put_epoch != the
            // server's (a concurrent mutation since the client computed it) — the §15 CAS failed.
            return Response::Err(ErrorCode::BadAuth);
        }
        if !self.consume_nonce(&nonce, now) {
            return Response::Err(ErrorCode::BadAuth);
        }
        // §19: at most 4 gc calls per key per hour — rejected before any object scan.
        if !self.gc_allow(device_id, now) {
            return Response::Err(ErrorCode::RateLimit);
        }

        let keep: BTreeSet<[u8; 32]> = keep_set.into_iter().collect();
        match self.store.gc(&keep, gc_gen) {
            Ok(_deleted) => Response::Ok,
            Err(_) => Response::Err(ErrorCode::Internal),
        }
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
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        let resp = s.handle(read_req(&dev, Request::Get { id: [1; 32] }, T), 0);
        assert_eq!(resp, Response::Err(ErrorCode::NotEnrolled));
    }

    #[test]
    fn put_then_get_round_trip() {
        let (s, _d) = server();
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
        assert!(matches!(
            s.handle(write_req(&dev, put, T, nonce), 0),
            Response::Stored { .. }
        ));

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
        let (s, _d) = server();
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
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let mut inc = read_req(&dev, Request::Get { id: [1; 32] }, T);
        // swap the requested id after signing.
        inc.request = Request::Get { id: [2; 32] };
        assert_eq!(s.handle(inc, 0), Response::Err(ErrorCode::BadAuth));
    }

    #[test]
    fn write_nonce_is_single_use() {
        let (s, _d) = server();
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
        assert!(matches!(
            s.handle(write_req(&dev, put.clone(), T, nonce), 0),
            Response::Stored { .. }
        ));
        // replay with the same nonce -> rejected (single-use).
        assert_eq!(
            s.handle(write_req(&dev, put, T, nonce), 0),
            Response::Err(ErrorCode::BadAuth)
        );
    }

    #[test]
    fn write_without_issued_nonce_is_rejected() {
        let (s, _d) = server();
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
        let (s, _d) = server();
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
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let ids = vec![[0u8; 32]; limits::MAX_HAS_IDS + 1];
        assert_eq!(
            s.handle(read_req(&dev, Request::Has { ids }, T), 0),
            Response::Err(ErrorCode::TooManyIds)
        );
    }

    #[test]
    fn cas_head_first_write_conflict_and_blob_mismatch() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let ref_h = [0x33; 32];
        let blob = b"head-blob-v1".to_vec();
        let new_head = *blake3::hash(&blob).as_bytes();
        let cas = |old: [u8; 32], nh: [u8; 32], b: Vec<u8>| Request::CasHead {
            ref_h,
            old_head: old,
            new_head: nh,
            new_blob: b,
        };

        // first write (expect-absent) succeeds.
        let n1 = [0x10; 32];
        s.issue_nonce(n1, 0);
        assert_eq!(
            s.handle(
                write_req(&dev, cas([0; 32], new_head, blob.clone()), T, n1),
                0
            ),
            Response::Ok
        );

        // a second expect-absent now loses the CAS.
        let n2 = [0x11; 32];
        s.issue_nonce(n2, 0);
        assert_eq!(
            s.handle(
                write_req(&dev, cas([0; 32], new_head, blob.clone()), T, n2),
                0
            ),
            Response::Err(ErrorCode::CasConflict)
        );

        // a swap to the correct expected-old (= BLAKE3 of the stored blob) succeeds.
        let n3 = [0x12; 32];
        s.issue_nonce(n3, 0);
        let v2 = b"head-blob-v2".to_vec();
        let v2_head = *blake3::hash(&v2).as_bytes();
        assert_eq!(
            s.handle(write_req(&dev, cas(new_head, v2_head, v2), T, n3), 0),
            Response::Ok
        );

        // attached blob not matching the signed new_head -> BadRequest.
        let n4 = [0x13; 32];
        s.issue_nonce(n4, 0);
        assert_eq!(
            s.handle(
                write_req(&dev, cas([0; 32], [0xAB; 32], b"x".to_vec()), T, n4),
                0
            ),
            Response::Err(ErrorCode::BadRequest)
        );
    }

    #[test]
    fn roster_append_chains_and_rejects_race() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let append = |old_tip: [u8; 32], entry: Vec<u8>| Request::RosterAppend { old_tip, entry };

        // genesis append (expect-absent).
        let n1 = [0x20; 32];
        s.issue_nonce(n1, 0);
        assert_eq!(
            s.handle(
                write_req(&dev, append([0; 32], b"genesis".to_vec()), T, n1),
                0
            ),
            Response::Ok
        );

        // a racing genesis (still expect-absent) loses the CAS.
        let n2 = [0x21; 32];
        s.issue_nonce(n2, 0);
        assert_eq!(
            s.handle(
                write_req(&dev, append([0; 32], b"genesis2".to_vec()), T, n2),
                0
            ),
            Response::Err(ErrorCode::CasConflict)
        );

        // append seq 1 on the correct tip succeeds.
        let tip0 = *blake3::hash(b"genesis").as_bytes();
        let n3 = [0x22; 32];
        s.issue_nonce(n3, 0);
        assert_eq!(
            s.handle(write_req(&dev, append(tip0, b"entry1".to_vec()), T, n3), 0),
            Response::Ok
        );
    }
}
