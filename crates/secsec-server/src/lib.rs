//! `secsec-server` — the §12 per-op request handler over the content-addressed store
//! (`secsec-Design.md` §12, §19). Pipeline: keyslot existence → per-op signature over the recomputed
//! `args_hash` + session transcript (+ single-use `server_nonce` for writes) → §19 limits → execute.
//! The server is **blind**: blobs are opaque (clients re-check content addresses on fetch, §9.2),
//! a push stages objects and the winning `cas-head` atomically promotes them, and `prune` is a
//! compare-and-swap against the server's head/roster state (§15). The handler is pure and
//! clock-injected (`now`) — [`Server::handle`] unit-tests, no sockets.

#![forbid(unsafe_code)]

pub mod serve;

use secsec_frame::MAX_BLOB_SIZE;
use secsec_proto::server::{limits, Limits, NonceStore, StorageQuota, TokenBucket, WindowCounter};
use secsec_proto::wire::{ErrorCode, Request, Response};
use secsec_proto::{op, op_and_args, prune, ReadAuth, WriteAuth};
use secsec_sig::{DeviceId, DevicePublic};
use secsec_store::Store;
use std::collections::{BTreeSet, HashMap};

/// Pairing-mailbox entry TTL (§7 invite onboarding): the agreed invite lifetime (~10 minutes). An
/// unclaimed pairing slot is evicted after this; an invite is single-use and short-lived.
const PAIR_TTL_SECS: u64 = 600;
/// Anti-abuse cap on concurrent pairing-mailbox slots (each ≤ `MAX_ROSTER_ENTRY_SIZE`, TTL-evicted).
const MAX_PAIR_SLOTS: usize = 256;

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

/// The mutable rate-limit / replay state, behind a fast `std::sync::Mutex` locked only for counter
/// updates (no I/O, no `await`); the redb store is transactional and accessed lock-free.
#[derive(Default)]
struct ServerState {
    nonces: NonceStore,
    write_buckets: HashMap<DeviceId, TokenBucket>,
    read_buckets: HashMap<DeviceId, TokenBucket>,
    quotas: HashMap<DeviceId, StorageQuota>,
    /// Per-connection-identity sigchain-append counter (§8.1: ≤ 60 roster-appends per key per hour).
    sigchain_calls: HashMap<DeviceId, WindowCounter>,
    /// §7 invite-onboarding mailbox: `slot → (blob, expiry)`. Transient, never persisted, TTL-evicted.
    pairing: HashMap<[u8; 32], (Vec<u8>, u64)>,
    /// Live concurrent connections per authenticated key (§19: ≤ `MAX_CONCURRENT_CONNS_PER_KEY`).
    conn_counts: HashMap<DeviceId, u32>,
}

impl ServerState {
    /// Post to a pairing slot (evicting expired entries first); `false` if the mailbox is full.
    fn pair_put(&mut self, slot: [u8; 32], blob: Vec<u8>, now: u64) -> bool {
        self.pairing.retain(|_, (_, exp)| *exp > now);
        if self.pairing.len() >= MAX_PAIR_SLOTS && !self.pairing.contains_key(&slot) {
            return false;
        }
        self.pairing.insert(slot, (blob, now + PAIR_TTL_SECS));
        true
    }

    /// Read a pairing slot (`None` if empty/expired), evicting expired entries.
    fn pair_get(&mut self, slot: &[u8; 32], now: u64) -> Option<Vec<u8>> {
        self.pairing.retain(|_, (_, exp)| *exp > now);
        self.pairing.get(slot).map(|(b, _)| b.clone())
    }

    fn take_write(&mut self, d: DeviceId, n: u64, now: u64, rate: u64) -> bool {
        self.write_buckets
            .entry(d)
            .or_insert_with(|| TokenBucket::new(limits::WRITE_BURST_BYTES, rate, now))
            .try_take(n, now)
    }

    /// Per-key read byte-rate (configurable; default 200 MB/s sustained). The burst reuses the §19
    /// write-burst constant (1 GiB ≥ MAX_BLOB_SIZE) so a single object always fits and an initial
    /// clone is never starved; only sustained egress is bounded.
    fn take_read(&mut self, d: DeviceId, n: u64, now: u64, rate: u64) -> bool {
        self.read_buckets
            .entry(d)
            .or_insert_with(|| TokenBucket::new(limits::WRITE_BURST_BYTES, rate, now))
            .try_take(n, now)
    }

    /// Record a roster-append for the per-connection-identity hourly cap (§8.1: ≤ 60/key/hour).
    fn sigchain_record(&mut self, d: DeviceId, now: u64) -> bool {
        self.sigchain_calls
            .entry(d)
            .or_insert_with(|| {
                WindowCounter::new(
                    limits::HOUR_SECS,
                    limits::MAX_SIGCHAIN_ENTRIES_PER_CONN_PER_HOUR,
                )
            })
            .try_record(now)
    }

    /// Refund a slot charged by [`sigchain_record`](Self::sigchain_record) when the append lost the
    /// tip CAS — a benign racer must not burn one of its 60/hr slots (§8.1).
    fn sigchain_refund(&mut self, d: DeviceId) {
        if let Some(w) = self.sigchain_calls.get_mut(&d) {
            w.refund();
        }
    }

    fn add_quota(&mut self, d: DeviceId, n: u64, cap: u64) -> bool {
        if cap == 0 {
            return true; // unlimited (the default, §15)
        }
        self.quotas
            .entry(d)
            .or_insert_with(|| StorageQuota::new(cap))
            .try_add(n)
    }

    /// Return `n` reserved bytes to a key's cap — used when a charged `cas-head` then lost its CAS, so
    /// a benign racer is not permanently charged for objects it never promoted.
    fn release_quota(&mut self, d: DeviceId, n: u64) {
        if let Some(q) = self.quotas.get_mut(&d) {
            q.release(n);
        }
    }
}

/// The server's per-op handler. Object ops hit the redb store lock-free (redb is transactional);
/// only [`ServerState`] is mutex-guarded. `handle` takes `&self`, so the server is shared via
/// `Arc<Server>` and serves requests concurrently.
pub struct Server {
    store: Store,
    state: std::sync::Mutex<ServerState>,
    /// Operator-tunable runtime limits (§19 `secsec.config`); default to the §19 normative values.
    limits: Limits,
    /// The **mandatory** connection allow-list (the operator's `authorized_keys`), re-read per
    /// connection so adding a key needs no restart. Gates who can talk at all, including pairing
    /// (§7); membership/decryption is the separate crypto roster + keyslots (§8).
    authorized: Authorized,
}

/// The server's connection allow-list source (§11/§12).
pub enum Authorized {
    /// Allow any authenticated key to connect (tests / in-process backends only).
    Any,
    /// A fixed set of permitted device ids.
    Static(BTreeSet<DeviceId>),
    /// Re-read `~/.ssh/authorized_keys` (the OpenSSH `authorized_keys` file) on every check, so the
    /// operator can add/remove devices live. Unreadable ⇒ deny (fail closed).
    File(std::path::PathBuf),
}

/// Parse an OpenSSH `authorized_keys` file body into the set of permitted Ed25519 device ids
/// (`device_id = BLAKE3(canonical(pubkey))`). Comment/blank/non-Ed25519 lines are skipped.
#[must_use]
pub fn parse_authorized_keys(body: &str) -> BTreeSet<DeviceId> {
    let mut set = BTreeSet::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(id) = DevicePublic::from_openssh(line).and_then(|pk| pk.device_id()) {
            set.insert(id);
        }
    }
    set
}

impl Server {
    /// Build a handler over `store` with default limits and an open allow-list (tighten with
    /// [`with_limits`](Self::with_limits) / [`with_authorized_file`](Self::with_authorized_file)).
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self {
            store,
            state: std::sync::Mutex::new(ServerState::default()),
            limits: Limits::default(),
            authorized: Authorized::Any,
        }
    }

    /// Apply operator-tuned runtime limits (§19 `secsec.config`); unset values keep their §19 defaults.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The configured per-source-IP new-connection rate (the serve accept loop enforces it, §19).
    #[must_use]
    pub fn conn_rate_per_sec(&self) -> u64 {
        self.limits.conn_rate_per_sec
    }

    /// Restrict connections to a fixed device-id set (for tests / in-process backends).
    #[must_use]
    pub fn with_authorized(mut self, authorized: BTreeSet<DeviceId>) -> Self {
        self.authorized = Authorized::Static(authorized);
        self
    }

    /// Gate connections on the operator's `authorized_keys` **file**, re-read per connection so adding
    /// a device takes effect with no restart. This is the mandatory `secsec serve` configuration.
    #[must_use]
    pub fn with_authorized_file(mut self, path: std::path::PathBuf) -> Self {
        self.authorized = Authorized::File(path);
        self
    }

    /// Whether `device_id` is permitted to connect. `File` is re-read on each call (unreadable ⇒ deny).
    #[must_use]
    pub fn is_authorized(&self, device_id: &DeviceId) -> bool {
        match &self.authorized {
            Authorized::Any => true,
            Authorized::Static(set) => set.contains(device_id),
            Authorized::File(path) => std::fs::read_to_string(path)
                .map(|body| parse_authorized_keys(&body).contains(device_id))
                .unwrap_or(false),
        }
    }

    /// Borrow the underlying object + keyslot store (e.g. for enrollment writes by the orchestration
    /// layer, or `keyslot_exists` queries).
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Reclaim in-flight pushes idle past `ttl_secs` (§15). The serve loop drives this on a background
    /// interval so abandoned staging cannot accumulate on a server that no client is actively pushing
    /// to. Returns the number of pushes reclaimed.
    pub fn reclaim_staging(&self, now: u64, ttl_secs: u64) -> Result<u64, secsec_store::StoreError> {
        self.store.reclaim_staging(now, ttl_secs)
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
            .take_write(d, n, now, self.limits.write_rate)
    }

    fn add_quota(&self, d: DeviceId, n: u64) -> bool {
        self.state
            .lock()
            .expect("server state")
            .add_quota(d, n, self.limits.storage_cap)
    }

    fn release_quota(&self, d: DeviceId, n: u64) {
        self.state
            .lock()
            .expect("server state")
            .release_quota(d, n);
    }

    fn take_read(&self, d: DeviceId, n: u64, now: u64) -> bool {
        self.state
            .lock()
            .expect("server state")
            .take_read(d, n, now, self.limits.read_rate)
    }

    fn sigchain_allow(&self, d: DeviceId, now: u64) -> bool {
        self.state
            .lock()
            .expect("server state")
            .sigchain_record(d, now)
    }

    fn sigchain_refund(&self, d: DeviceId) {
        self.state.lock().expect("server state").sigchain_refund(d);
    }

    /// Reserve a concurrent-connection slot for `d` (§19: ≤ `MAX_CONCURRENT_CONNS_PER_KEY` per
    /// authenticated key). Returns `true` if reserved (the caller MUST [`release_conn`](Self::release_conn)
    /// on disconnect, e.g. via [`ConnGuard`]); `false` if the key is already at its cap.
    #[must_use]
    pub fn acquire_conn(&self, d: DeviceId) -> bool {
        let max = self.limits.max_conns_per_key;
        let mut st = self.state.lock().expect("server state");
        let n = st.conn_counts.entry(d).or_insert(0);
        if u64::from(*n) >= max {
            false
        } else {
            *n += 1;
            true
        }
    }

    /// Release a slot reserved by [`acquire_conn`](Self::acquire_conn).
    pub fn release_conn(&self, d: DeviceId) {
        let mut st = self.state.lock().expect("server state");
        if let Some(n) = st.conn_counts.get_mut(&d) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.conn_counts.remove(&d);
            }
        }
    }

    /// Charge a read against the §19 per-key read byte-rate; `RateLimit` when the bucket is
    /// exhausted.
    fn read_charged(
        &self,
        d: DeviceId,
        blob: Result<Option<Vec<u8>>, secsec_store::StoreError>,
        now: u64,
    ) -> Response {
        match blob {
            Ok(b) => {
                let n = b.as_ref().map_or(0, Vec::len) as u64;
                if !self.take_read(d, n, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                Response::Blob(b)
            }
            Err(_) => Response::Err(ErrorCode::Internal),
        }
    }

    fn pair_put(&self, slot: [u8; 32], blob: Vec<u8>, now: u64) -> bool {
        self.state
            .lock()
            .expect("server state")
            .pair_put(slot, blob, now)
    }

    fn pair_get(&self, slot: &[u8; 32], now: u64) -> Option<Vec<u8>> {
        self.state.lock().expect("server state").pair_get(slot, now)
    }

    /// §7 pairing mailbox, dispatched **pre-enrollment** (a joiner owns no keyslot yet). Read-auth
    /// proves the connecting key; the payload is MAC'd under the invite code end to end and slot ids
    /// are `BLAKE3::derive_key(label, code)`, so the blind server only relays + TTLs.
    fn handle_pair(&self, inc: Incoming<'_>, now: u64) -> Response {
        let (op_label, args_hash, _) = op_and_args(&inc.request);
        let ra = ReadAuth {
            op: op_label,
            args_hash,
            session_transcript: inc.session_transcript,
        };
        if ra.verify(inc.pubkey, &inc.op_sig).is_err() {
            return Response::Err(ErrorCode::BadAuth);
        }
        let device_id = match inc.pubkey.device_id() {
            Ok(d) => d,
            Err(_) => return Response::Err(ErrorCode::BadRequest),
        };
        match inc.request {
            Request::PairPut { slot, blob } => {
                // Rate-limit posts via the connecting key's write bucket (anti-mailbox-flood).
                if !self.take_write(device_id, blob.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                if self.pair_put(slot, blob, now) {
                    Response::Ok
                } else {
                    Response::Err(ErrorCode::RateLimit)
                }
            }
            Request::PairGet { slot } => Response::Blob(self.pair_get(&slot, now)),
            _ => Response::Err(ErrorCode::Internal),
        }
    }

    /// Run the §12 pipeline for one request and return the response.
    pub fn handle(&self, inc: Incoming<'_>, now: u64) -> Response {
        // (0) Pairing mailbox (§7 invite onboarding): allowed PRE-enrollment (a joining device owns no
        // keyslot yet), so dispatch it before the keyslot-existence check.
        if matches!(
            inc.request,
            Request::PairPut { .. } | Request::PairGet { .. }
        ) {
            return self.handle_pair(inc, now);
        }

        // (1) keyslot existence: the connecting key must be rostered, with the genesis-bootstrap
        // exception below. (Connection-level access via authorized_keys is enforced up in `serve`.)
        let device_id = match inc.pubkey.device_id() {
            Ok(d) => d,
            Err(_) => return Response::Err(ErrorCode::BadRequest),
        };
        // keyslot presence only (no decryption) — a store error fails closed.
        if !self.store.keyslot_exists(&device_id).unwrap_or(false) {
            // Genesis exception (§7/§12): while the roster is empty, the first device may write the
            // genesis sigchain entry and ITS OWN keyslot only — `owner == device_id` stops an
            // unenrolled key squatting a keyslot for an arbitrary device_id.
            let genesis_bootstrap = self.store.roster_len().map(|n| n == 0).unwrap_or(false)
                && match &inc.request {
                    Request::RosterAppend { .. } => true,
                    Request::PutKeyslot {
                        device_id: owner, ..
                    } => *owner == device_id,
                    _ => false,
                };
            if !genesis_bootstrap {
                return Response::Err(ErrorCode::NotEnrolled);
            }
        }

        // prune has a state-dependent args_hash (§15 compare-and-swap), so it is authorized separately
        // from the generic op_and_args path below.
        if matches!(inc.request, Request::Prune { .. }) {
            return self.handle_prune(inc, now);
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
            // Reads are charged against the §19 per-key read byte-rate (200 MB/s sustained).
            Request::Get { id } => self.read_charged(device_id, self.store.get(&id), now),
            Request::GetRef { ref_h } => {
                self.read_charged(device_id, self.store.get_ref(&ref_h), now)
            }
            Request::GetRosterEntry { seq } => {
                self.read_charged(device_id, self.store.get_roster_entry(seq), now)
            }
            Request::GetKeyslot {
                device_id: owner,
                gen,
            } => self.read_charged(device_id, self.store.get_keyslot(&owner, gen), now),
            Request::GetRosterKeyhist { gen } => {
                self.read_charged(device_id, self.store.get_roster_keyhist(gen), now)
            }
            Request::GetKeyhist { gen } => {
                self.read_charged(device_id, self.store.get_keyhist(gen), now)
            }
            Request::Has { ids } => {
                if ids.len() > limits::MAX_HAS_IDS {
                    return Response::Err(ErrorCode::TooManyIds);
                }
                if !self.take_read(device_id, (ids.len() * 32) as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                match self.store.has(&ids) {
                    Ok(bits) => Response::Exists(bits),
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            Request::Put {
                id,
                declared_size,
                push_id,
                blob,
            } => {
                // §11/§12 normative: MUST reject declared_size > 16 MiB outright (the wire decoder
                // already caps the actual blob).
                if declared_size as usize > MAX_BLOB_SIZE {
                    return Response::Err(ErrorCode::BadRequest);
                }
                if blob.len() != declared_size as usize {
                    return Response::Err(ErrorCode::BadRequest);
                }
                // write byte-rate limit (§19: 100 MB/s sustained, 1 GiB burst). The per-key storage
                // cap is charged at promote (cas-head), so abandoned staging is never charged.
                if !self.take_write(device_id, blob.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                // Stage the object under this push; a winning cas-head promotes it durably (§15).
                match self.store.stage(&push_id, &id, &blob, now) {
                    Ok(()) => Response::Ok,
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            Request::CasHead {
                ref_h,
                old_head,
                new_head,
                promote,
                new_blob,
            } => {
                // The attached new head blob must hash to the signed new_head (§12 cas-head semantics).
                if *blake3::hash(&new_blob).as_bytes() != new_head {
                    return Response::Err(ErrorCode::BadRequest);
                }
                if !self.take_write(device_id, new_blob.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                // Charge the per-key cap (§15) on the bytes this push would make durable, BEFORE
                // promoting, so an over-cap promote is rejected rather than committed. A lost CAS
                // promotes nothing, so its reservation is refunded.
                let promote_bytes = self.store.staged_bytes(&promote).unwrap_or(0);
                if promote_bytes > 0 && !self.add_quota(device_id, promote_bytes) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                // Atomic compare-and-swap on the server-visible blob hash, promoting this push's staged
                // objects in the same transaction (blind server, §15/§12).
                match self.store.cas_ref(&ref_h, &old_head, &new_blob, &promote) {
                    Ok(outcome) if outcome.swapped => Response::Ok,
                    Ok(_) => {
                        self.release_quota(device_id, promote_bytes);
                        Response::Err(ErrorCode::CasConflict)
                    }
                    Err(_) => {
                        self.release_quota(device_id, promote_bytes);
                        Response::Err(ErrorCode::Internal)
                    }
                }
            }
            Request::RosterAppend { old_tip, entry } => {
                if !self.take_write(device_id, entry.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                // §8.1 server-enforced volume limits: ≤ 60 appends/key/hour + a total chain cap.
                if !self.sigchain_allow(device_id, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                match self.store.roster_len() {
                    Ok(n) if n >= limits::MAX_TOTAL_SIGCHAIN => {
                        return Response::Err(ErrorCode::RateLimit);
                    }
                    Ok(_) => {}
                    Err(_) => return Response::Err(ErrorCode::Internal),
                }
                // Append CAS-guarded by the /roster-head tip (§8.1): a racing append loses.
                match self.store.append_roster(&old_tip, &entry) {
                    Ok(Some(_seq)) => Response::Ok,
                    // A CAS loss didn't grow the chain — refund so a benign race can't exhaust the
                    // hourly budget and block a retried revocation (§8.1).
                    Ok(None) => {
                        self.sigchain_refund(device_id);
                        Response::Err(ErrorCode::CasConflict)
                    }
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            // Enrollment write (§7/§8.4): opaque blob; authenticity is the recipient's `mk_commit`
            // check, not the server's.
            Request::PutKeyslot {
                device_id: owner_id,
                gen,
                blob,
            } => {
                if !self.take_write(device_id, blob.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                match self.store.put_keyslot(&owner_id, gen, &blob) {
                    Ok(()) => Response::Ok,
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            // The network half of rotation (§8.2/§8.4): an enrolled member writes the key-history wraps
            // and deletes revoked keyslots. All opaque; authenticity rests on the roster fold.
            Request::PutKeyhist { gen, blob } => {
                if !self.take_write(device_id, blob.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                match self.store.put_keyhist(gen, &blob) {
                    Ok(()) => Response::Ok,
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            Request::PutRosterKeyhist { gen, blob } => {
                if !self.take_write(device_id, blob.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                match self.store.put_roster_keyhist(gen, &blob) {
                    Ok(()) => Response::Ok,
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            Request::DeleteKeyslot {
                device_id: owner_id,
                gen,
            } => match self.store.delete_keyslot(&owner_id, gen) {
                Ok(_) => Response::Ok,
                Err(_) => Response::Err(ErrorCode::Internal),
            },
            // prune is dispatched before this match (state-dependent auth, §15); never reached here.
            Request::Prune { .. } => Response::Err(ErrorCode::Internal),
            // Pairing ops are dispatched at the top of `handle` (pre-enrollment); never reached here.
            Request::PairPut { .. } | Request::PairGet { .. } => Response::Err(ErrorCode::Internal),
        }
    }

    /// §15 `prune`: `args_hash` is recomputed from the **server's** current head/roster state
    /// (`all_heads_hash` / `roster_seq`), so verifying the client's signature over it **is** the
    /// head-binding compare-and-swap — a concurrent `cas-head`/`roster-append` changes the recomputed
    /// message and the prune aborts (`BadAuth`) instead of deleting an object a reverted head now
    /// references. On success the `dead` set is removed from durable storage.
    fn handle_prune(&self, inc: Incoming<'_>, now: u64) -> Response {
        let Request::Prune { dead, .. } = &inc.request else {
            return Response::Err(ErrorCode::Internal);
        };
        if dead.len() > limits::MAX_HAS_IDS {
            return Response::Err(ErrorCode::TooManyIds);
        }
        let Some(nonce) = inc.server_nonce else {
            return Response::Err(ErrorCode::BadAuth);
        };

        // Recompute args_prune from the server's CURRENT head/roster state — this IS the CAS.
        let (refs, roster_len) = match (self.store.ref_blob_hashes(), self.store.roster_len()) {
            (Ok(r), Ok(n)) => (r, n),
            _ => return Response::Err(ErrorCode::Internal),
        };
        let roster_seq = roster_len.saturating_sub(1);
        let args_hash = prune::args_prune(
            &prune::dead_set_hash(dead),
            &prune::all_heads_hash(&refs),
            roster_seq,
        );

        let wa = WriteAuth {
            op: op::PRUNE,
            args_hash,
            session_transcript: inc.session_transcript,
            server_nonce: nonce,
        };
        if wa.verify(inc.pubkey, &inc.op_sig).is_err() {
            // Bad signature OR a stale client view of the bound state — the §15 CAS failed.
            return Response::Err(ErrorCode::BadAuth);
        }
        if !self.consume_nonce(&nonce, now) {
            return Response::Err(ErrorCode::BadAuth);
        }

        match self.store.delete_objects(dead) {
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

    /// Promote the objects staged under `push` to durable storage by advancing a throwaway ref under
    /// it (each push gets a unique ref so the expect-absent swap always wins).
    fn promote(s: &Server, dev: &DeviceKey, push: [u8; 16]) {
        let ref_h = *blake3::hash(&push).as_bytes();
        let blob = b"head".to_vec();
        let new_head = *blake3::hash(&blob).as_bytes();
        let nonce = [0xfe; 32];
        s.issue_nonce(nonce, 0);
        let cas = Request::CasHead {
            ref_h,
            old_head: [0u8; 32],
            new_head,
            promote: push,
            new_blob: blob,
        };
        assert_eq!(s.handle(write_req(dev, cas, T, nonce), 0), Response::Ok);
    }

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
            push_id: [0xaa; 16],
            blob: blob.clone(),
        };
        assert_eq!(s.handle(write_req(&dev, put, T, nonce), 0), Response::Ok);
        // promote the staged object durable by advancing a ref under the same push.
        promote(&s, &dev, [0xaa; 16]);

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
            push_id: [0xbb; 16],
            blob: vec![0u8],
        };
        // first use ok.
        assert_eq!(s.handle(write_req(&dev, put.clone(), T, nonce), 0), Response::Ok);
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
            push_id: [0; 16],
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
            push_id: [0; 16],
            blob: vec![0u8; 3],
        };
        assert_eq!(
            s.handle(write_req(&dev, put, T, nonce), 0),
            Response::Err(ErrorCode::BadRequest)
        );
    }

    #[test]
    fn put_declared_size_over_max_is_rejected() {
        // §11/§12: a `declared_size` over 16 MiB is rejected outright, before the size-match check.
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let nonce = [0x07; 32];
        s.issue_nonce(nonce, 0);
        let put = Request::Put {
            id: [6; 32],
            declared_size: u32::MAX, // > 16 MiB
            push_id: [0; 16],
            blob: vec![0u8; 8],
        };
        assert_eq!(
            s.handle(write_req(&dev, put, T, nonce), 0),
            Response::Err(ErrorCode::BadRequest)
        );
    }

    #[test]
    fn genesis_putkeyslot_must_target_own_device() {
        // On an empty repo, the genesis exception lets an unenrolled key write only ITS OWN keyslot —
        // not squat one for an arbitrary device_id.
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap(); // unenrolled; roster empty
        let other = [0x55; 32];

        let n1 = [0x40; 32];
        s.issue_nonce(n1, 0);
        let put_other = Request::PutKeyslot {
            device_id: other,
            gen: 1,
            blob: b"ks".to_vec(),
        };
        assert_eq!(
            s.handle(write_req(&dev, put_other, T, n1), 0),
            Response::Err(ErrorCode::NotEnrolled),
            "genesis exception must not let an unenrolled key write another device's keyslot"
        );

        // Its OWN keyslot during genesis is permitted.
        let n2 = [0x41; 32];
        s.issue_nonce(n2, 0);
        let put_own = Request::PutKeyslot {
            device_id: dev.device_id().unwrap(),
            gen: 1,
            blob: b"ks".to_vec(),
        };
        assert_eq!(s.handle(write_req(&dev, put_own, T, n2), 0), Response::Ok);
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
            promote: [0u8; 16],
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
    fn concurrent_connection_cap_per_key() {
        let (s, _d) = server();
        let d = DeviceKey::generate().unwrap().device_id().unwrap();
        let max = limits::MAX_CONCURRENT_CONNS_PER_KEY;
        // up to the cap acquire; the next is refused.
        for _ in 0..max {
            assert!(s.acquire_conn(d));
        }
        assert!(!s.acquire_conn(d), "over the per-key concurrency cap");
        // releasing one frees a slot.
        s.release_conn(d);
        assert!(s.acquire_conn(d));
        // a different key is independent.
        let d2 = DeviceKey::generate().unwrap().device_id().unwrap();
        assert!(s.acquire_conn(d2));
        // releasing back to zero is clean (no underflow, entry removed).
        for _ in 0..max {
            s.release_conn(d);
        }
        s.release_conn(d); // extra release is a harmless no-op
        assert!(s.acquire_conn(d));
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
