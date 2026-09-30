//! The §12 per-op request handler over the blind store (`secsec-Design.md` §12, §15, §19), pure and clock-injected.

#![forbid(unsafe_code)]

pub mod serve;

use secsec_frame::MAX_BLOB_SIZE;
use secsec_proto::prune;
use secsec_proto::server::{limits, Limits, StorageQuota, TokenBucket, WindowCounter};
use secsec_proto::wire::{ErrorCode, Request, Response};
use secsec_proto::{op_and_args, ReadAuth, WriteAuth};
use secsec_sig::{DeviceId, DevicePublic};
use secsec_store::{HeadSwap, KeyslotWrite, RosterBatch, Store, ABSENT_HEAD};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Pairing-mailbox slot lifetime `PAIR_TTL` (§7, §19).
const PAIR_TTL_SECS: u64 = 600;
/// Concurrent pairing slots, server-wide (§19).
const MAX_PAIR_SLOTS: usize = 256;

/// The per-stream challenge a write signs, with the time it was issued (§11, §19 TTL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuedNonce {
    /// The OS-CSPRNG nonce sent on the stream.
    pub nonce: [u8; 32],
    /// Issue time, unix seconds.
    pub issued_at: u64,
}

/// One authenticated request as the serve loop resolved it.
pub struct Incoming<'a> {
    /// The key that completed connection auth.
    pub pubkey: &'a DevicePublic,
    /// The operation.
    pub request: Request,
    /// The per-op signature.
    pub op_sig: Vec<u8>,
    /// The connection's session transcript (§11).
    pub session_transcript: [u8; 32],
    /// This stream's challenge (every stream gets one; only writes sign it).
    pub server_nonce: Option<IssuedNonce>,
}

/// Rate-limit and mailbox state behind one short-held mutex (no I/O under the lock).
#[derive(Default)]
struct ServerState {
    write_buckets: HashMap<DeviceId, TokenBucket>,
    read_buckets: HashMap<DeviceId, TokenBucket>,
    quotas: HashMap<DeviceId, StorageQuota>,
    sigchain_calls: HashMap<DeviceId, WindowCounter>,
    /// §7 mailbox `slot → (blob, expiry)`: in memory, TTL-evicted, taken on read.
    pairing: HashMap<[u8; 32], (Vec<u8>, u64)>,
    conn_counts: HashMap<DeviceId, u32>,
    /// Connections holding a server-wide [`Admission`].
    open_conns: u64,
}

impl ServerState {
    fn pair_put(&mut self, slot: [u8; 32], blob: Vec<u8>, now: u64) -> bool {
        self.pairing.retain(|_, (_, exp)| *exp > now);
        if self.pairing.len() >= MAX_PAIR_SLOTS && !self.pairing.contains_key(&slot) {
            return false;
        }
        self.pairing.insert(slot, (blob, now + PAIR_TTL_SECS));
        true
    }

    /// Take a slot: a pairing message is delivered once, then gone (§7 single use).
    fn pair_take(&mut self, slot: &[u8; 32], now: u64) -> Option<Vec<u8>> {
        self.pairing.retain(|_, (_, exp)| *exp > now);
        self.pairing.remove(slot).map(|(b, _)| b)
    }

    fn take_write(&mut self, d: DeviceId, n: u64, now: u64, rate: u64) -> bool {
        self.write_buckets
            .entry(d)
            .or_insert_with(|| TokenBucket::new(limits::WRITE_BURST_BYTES, rate, now))
            .try_take(n, now)
    }

    /// Reads share the write burst (≥ the object cap, so one object always fits); only sustained egress is bounded.
    fn take_read(&mut self, d: DeviceId, n: u64, now: u64, rate: u64) -> bool {
        self.read_buckets
            .entry(d)
            .or_insert_with(|| TokenBucket::new(limits::WRITE_BURST_BYTES, rate, now))
            .try_take(n, now)
    }

    fn sigchain_record(&mut self, d: DeviceId, n: u64, now: u64) -> bool {
        self.sigchain_calls
            .entry(d)
            .or_insert_with(|| {
                WindowCounter::new(
                    limits::HOUR_SECS,
                    limits::MAX_SIGCHAIN_ENTRIES_PER_CONN_PER_HOUR,
                )
            })
            .try_record_n(now, n)
    }

    fn sigchain_refund(&mut self, d: DeviceId, n: u64) {
        if let Some(w) = self.sigchain_calls.get_mut(&d) {
            w.refund(n);
        }
    }

    fn add_quota(&mut self, d: DeviceId, n: u64, cap: u64) -> bool {
        if cap == 0 {
            return true;
        }
        self.quotas
            .entry(d)
            .or_insert_with(|| StorageQuota::new(cap))
            .try_add(n)
    }

    fn release_quota(&mut self, d: DeviceId, n: u64) {
        if let Some(q) = self.quotas.get_mut(&d) {
            q.release(n);
        }
    }

    /// Forget idle per-key state (full buckets, empty windows) and expired mailbox slots; quotas persist for the session.
    fn sweep_idle(&mut self, now: u64) {
        self.write_buckets.retain(|_, b| !b.is_full(now));
        self.read_buckets.retain(|_, b| !b.is_full(now));
        self.sigchain_calls.retain(|_, w| w.count(now) > 0);
        self.pairing.retain(|_, (_, exp)| *exp > now);
    }
}

/// The connection allow-list source (§11).
pub(crate) enum Authorized {
    /// Any authenticated key (in-process tests only).
    Any,
    /// The operator's `authorized_keys`, re-parsed whenever its size or mtime changes; unreadable denies.
    File {
        path: std::path::PathBuf,
        cache: std::sync::Mutex<Option<(AuthStamp, BTreeSet<DeviceId>)>>,
    },
}

/// The `(mtime, len)` a parsed `authorized_keys` was read at.
type AuthStamp = (Option<std::time::SystemTime>, u64);

/// Parse an OpenSSH `authorized_keys` body into the permitted Ed25519 device ids; other lines are skipped.
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

/// The per-op handler; object ops hit the transactional store directly, only [`ServerState`] is locked.
pub struct Server {
    store: Store,
    state: std::sync::Mutex<ServerState>,
    limits: Limits,
    authorized: Authorized,
}

impl Server {
    /// A handler with default limits and an OPEN allow-list; networked use MUST call [`Self::with_authorized_file`].
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self {
            store,
            state: std::sync::Mutex::new(ServerState::default()),
            limits: Limits::default(),
            authorized: Authorized::Any,
        }
    }

    /// Apply operator-tuned runtime limits (§19).
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The per-source-IP new-connection rate the accept loop enforces (§19).
    #[must_use]
    pub fn conn_rate_per_sec(&self) -> u64 {
        self.limits.conn_rate_per_sec
    }

    /// Gate connections on the operator's `authorized_keys` file (the mandatory `serve` configuration, §11).
    #[must_use]
    pub fn with_authorized_file(mut self, path: std::path::PathBuf) -> Self {
        self.authorized = Authorized::File {
            path,
            cache: std::sync::Mutex::new(None),
        };
        self
    }

    /// Whether `device_id` may connect; the file is re-parsed when it changes and denies when unreadable.
    #[must_use]
    pub fn is_authorized(&self, device_id: &DeviceId) -> bool {
        match &self.authorized {
            Authorized::Any => true,
            Authorized::File { path, cache } => {
                let Ok(meta) = std::fs::metadata(path) else {
                    return false;
                };
                let stamp = (meta.modified().ok(), meta.len());
                let mut cache = cache.lock().expect("authorized cache");
                if cache.as_ref().map(|(s, _)| *s) != Some(stamp) {
                    let Ok(body) = std::fs::read_to_string(path) else {
                        *cache = None;
                        return false;
                    };
                    *cache = Some((stamp, parse_authorized_keys(&body)));
                }
                cache
                    .as_ref()
                    .is_some_and(|(_, set)| set.contains(device_id))
            }
        }
    }

    /// Borrow the store (tests).
    #[cfg(test)]
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Whether `device_id` owns a keyslot; a store error is `Err`, never "enrolled" (§12).
    pub fn is_enrolled(&self, device_id: &DeviceId) -> Result<bool, secsec_store::StoreError> {
        self.store.keyslot_exists(device_id)
    }

    /// Reclaim pushes idle past `ttl_secs` (§15) and forget idle rate-limit state; driven by the serve loop's timer.
    pub fn reclaim(&self, now: u64, ttl_secs: u64) -> Result<u64, secsec_store::StoreError> {
        self.state.lock().expect("server state").sweep_idle(now);
        self.store.reclaim_staging(now, ttl_secs)
    }

    fn with_state<T>(&self, f: impl FnOnce(&mut ServerState) -> T) -> T {
        f(&mut self.state.lock().expect("server state"))
    }

    fn take_write(&self, d: DeviceId, n: u64, now: u64) -> bool {
        let rate = self.limits.write_rate;
        self.with_state(|s| s.take_write(d, n, now, rate))
    }

    fn take_read(&self, d: DeviceId, n: u64, now: u64) -> bool {
        let rate = self.limits.read_rate;
        self.with_state(|s| s.take_read(d, n, now, rate))
    }

    /// Reserve a concurrent-connection slot for `d` (§19); release it via [`Self::release_conn`].
    #[must_use]
    pub(crate) fn acquire_conn(&self, d: DeviceId) -> bool {
        let max = self.limits.max_conns_per_key;
        self.with_state(|st| {
            let n = st.conn_counts.entry(d).or_insert(0);
            if u64::from(*n) >= max {
                false
            } else {
                *n += 1;
                true
            }
        })
    }

    /// Release a slot from [`Self::acquire_conn`].
    pub(crate) fn release_conn(&self, d: DeviceId) {
        self.with_state(|st| {
            if let Some(n) = st.conn_counts.get_mut(&d) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    st.conn_counts.remove(&d);
                }
            }
        });
    }

    /// Admit one connection under the server-wide cap (§19), taken before its handshake; `None` when full.
    #[must_use]
    pub fn admit(self: &Arc<Self>) -> Option<Admission> {
        let max = self.limits.max_connections;
        let admitted = self.with_state(|st| {
            if st.open_conns >= max {
                false
            } else {
                st.open_conns += 1;
                true
            }
        });
        admitted.then(|| Admission(Arc::clone(self)))
    }

    /// Serve a read, charged against the per-key read rate.
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

    /// Verify the per-op signature over the recomputed `args_hash`; a write must also be inside its nonce's TTL.
    fn authorize(&self, inc: &Incoming<'_>, now: u64) -> Result<(), ErrorCode> {
        let (op_label, args_hash, is_write) = op_and_args(&inc.request);
        let ok = if is_write {
            let Some(n) = inc.server_nonce else {
                return Err(ErrorCode::BadAuth);
            };
            if now < n.issued_at || now.saturating_sub(n.issued_at) >= limits::SERVER_NONCE_TTL_SECS
            {
                return Err(ErrorCode::BadAuth);
            }
            WriteAuth {
                op: op_label,
                args_hash,
                session_transcript: inc.session_transcript,
                server_nonce: n.nonce,
            }
            .verify(inc.pubkey, &inc.op_sig)
            .is_ok()
        } else {
            ReadAuth {
                op: op_label,
                args_hash,
                session_transcript: inc.session_transcript,
            }
            .verify(inc.pubkey, &inc.op_sig)
            .is_ok()
        };
        if ok {
            Ok(())
        } else {
            Err(ErrorCode::BadAuth)
        }
    }

    /// The genesis exception (§7, §12): an unenrolled key may send exactly the genesis batch, only onto an empty roster.
    fn is_genesis_batch(&self, req: &Request, device_id: &DeviceId) -> Result<bool, ErrorCode> {
        let Request::RosterBatch {
            old_tip,
            entries,
            keyslots,
            keyhist,
            roster_keyhist,
            revoke,
            head,
        } = req
        else {
            return Ok(false);
        };
        let shape = *old_tip == ABSENT_HEAD
            && entries.len() == 1
            && keyslots.len() == 1
            && keyslots[0].device_id == *device_id
            && keyhist.is_none()
            && roster_keyhist.is_none()
            && revoke.is_empty()
            && head.is_none();
        if !shape {
            return Ok(false);
        }
        self.store
            .roster_len()
            .map(|n| n == 0)
            .map_err(|_| ErrorCode::Internal)
    }

    /// Run the §12 pipeline for one request.
    pub(crate) fn handle(&self, inc: Incoming<'_>, now: u64) -> Response {
        let device_id = match inc.pubkey.device_id() {
            Ok(d) => d,
            Err(_) => return Response::Err(ErrorCode::BadRequest),
        };
        // (0) The pairing mailbox runs before enrollment: a joiner owns no keyslot yet (§7).
        if matches!(
            inc.request,
            Request::PairPut { .. } | Request::PairGet { .. }
        ) {
            if let Err(c) = self.authorize(&inc, now) {
                return Response::Err(c);
            }
            return self.handle_pair(inc.request, device_id, now);
        }

        // (1) Keyslot existence, fail closed, with the bounded genesis exception.
        match self.store.keyslot_exists(&device_id) {
            Ok(true) => {}
            Ok(false) => match self.is_genesis_batch(&inc.request, &device_id) {
                Ok(true) => {}
                Ok(false) => return Response::Err(ErrorCode::NotEnrolled),
                Err(c) => return Response::Err(c),
            },
            Err(_) => return Response::Err(ErrorCode::Internal),
        }

        // (2) Per-op authorization.
        if let Err(c) = self.authorize(&inc, now) {
            return Response::Err(c);
        }

        // (3) Limits, then execute.
        match inc.request {
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
                if declared_size as usize > MAX_BLOB_SIZE || blob.len() != declared_size as usize {
                    return Response::Err(ErrorCode::BadRequest);
                }
                if !self.take_write(device_id, blob.len() as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
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
            } => self.handle_cas(
                device_id, ref_h, old_head, new_head, promote, &new_blob, now,
            ),
            Request::RosterBatch {
                old_tip,
                entries,
                keyslots,
                keyhist,
                roster_keyhist,
                revoke,
                head,
            } => {
                if entries.is_empty() {
                    return Response::Err(ErrorCode::BadRequest);
                }
                let bytes: usize = entries.iter().map(Vec::len).sum::<usize>()
                    + keyslots.iter().map(|k| k.blob.len()).sum::<usize>()
                    + head.as_ref().map_or(0, |h| h.new_blob.len());
                if !self.take_write(device_id, bytes as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                let n = entries.len() as u64;
                match self.store.roster_len() {
                    Ok(len) if len.saturating_add(n) > limits::MAX_TOTAL_SIGCHAIN => {
                        return Response::Err(ErrorCode::RateLimit);
                    }
                    Ok(_) => {}
                    Err(_) => return Response::Err(ErrorCode::Internal),
                }
                if !self.with_state(|s| s.sigchain_record(device_id, n, now)) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                let ks: Vec<KeyslotWrite<'_>> = keyslots
                    .iter()
                    .map(|k| KeyslotWrite {
                        device_id: k.device_id,
                        gen: k.gen,
                        blob: &k.blob,
                    })
                    .collect();
                let batch = RosterBatch {
                    expected_tip: old_tip,
                    entries: &entries,
                    keyslots: &ks,
                    keyhist: keyhist.as_ref().map(|(g, b)| (*g, b.as_slice())),
                    roster_keyhist: roster_keyhist.as_ref().map(|(g, b)| (*g, b.as_slice())),
                    revoke: &revoke,
                    head: head.as_ref().map(|h| HeadSwap {
                        ref_h: h.ref_h,
                        expected_old: h.old_head,
                        new_blob: &h.new_blob,
                    }),
                };
                match self.store.roster_batch(&batch) {
                    Ok(Some(_)) => Response::Ok,
                    // A lost CAS grew nothing: refund, so a benign race never exhausts a retried revocation's budget.
                    Ok(None) => {
                        self.with_state(|s| s.sigchain_refund(device_id, n));
                        Response::Err(ErrorCode::CasConflict)
                    }
                    Err(_) => {
                        self.with_state(|s| s.sigchain_refund(device_id, n));
                        Response::Err(ErrorCode::Internal)
                    }
                }
            }
            Request::Prune {
                dead,
                all_heads_hash,
                roster_len,
            } => {
                if dead.len() > limits::MAX_HAS_IDS {
                    return Response::Err(ErrorCode::TooManyIds);
                }
                // The signed claim is honoured only if it still describes the store, inside the delete's own txn (§15).
                match self.store.prune_if(&dead, |refs, len| {
                    prune::all_heads_hash(refs) == all_heads_hash && len == roster_len
                }) {
                    Ok(true) => Response::Ok,
                    Ok(false) => Response::Err(ErrorCode::CasConflict),
                    Err(_) => Response::Err(ErrorCode::Internal),
                }
            }
            Request::PairPut { .. } | Request::PairGet { .. } => Response::Err(ErrorCode::Internal),
        }
    }

    /// `cas-head` (§12, §15): charge the per-key cap on what would become durable, refund what did not.
    #[allow(clippy::too_many_arguments)]
    fn handle_cas(
        &self,
        device_id: DeviceId,
        ref_h: [u8; 32],
        old_head: [u8; 32],
        new_head: [u8; 32],
        promote: [u8; 16],
        new_blob: &[u8],
        now: u64,
    ) -> Response {
        if *blake3::hash(new_blob).as_bytes() != new_head {
            return Response::Err(ErrorCode::BadRequest);
        }
        if !self.take_write(device_id, new_blob.len() as u64, now) {
            return Response::Err(ErrorCode::RateLimit);
        }
        let Ok(staged) = self.store.staged_bytes(&promote) else {
            return Response::Err(ErrorCode::Internal);
        };
        let cap = self.limits.storage_cap;
        if staged > 0 && !self.with_state(|s| s.add_quota(device_id, staged, cap)) {
            return Response::Err(ErrorCode::RateLimit);
        }
        match self.store.cas_ref(&ref_h, &old_head, new_blob, &promote) {
            Ok(outcome) if outcome.swapped => {
                let unused = staged.saturating_sub(outcome.promoted_bytes);
                self.with_state(|s| s.release_quota(device_id, unused));
                Response::Ok
            }
            Ok(_) => {
                self.with_state(|s| s.release_quota(device_id, staged));
                Response::Err(ErrorCode::CasConflict)
            }
            Err(_) => {
                self.with_state(|s| s.release_quota(device_id, staged));
                Response::Err(ErrorCode::Internal)
            }
        }
    }

    /// The §7 mailbox: posts charge the write rate, takes the read rate; the server only relays and TTLs.
    fn handle_pair(&self, request: Request, device_id: DeviceId, now: u64) -> Response {
        match request {
            Request::PairPut { slot, blob } => {
                if !self.take_write(device_id, (32 + blob.len()) as u64, now) {
                    return Response::Err(ErrorCode::RateLimit);
                }
                if self.with_state(|s| s.pair_put(slot, blob, now)) {
                    Response::Ok
                } else {
                    Response::Err(ErrorCode::RateLimit)
                }
            }
            Request::PairGet { slot } => {
                let got = self.with_state(|s| s.pair_take(&slot, now));
                let n = 32 + got.as_ref().map_or(0, Vec::len) as u64;
                if !self.take_read(device_id, n, now) {
                    // Put it back: a rate-limited read must not destroy the message.
                    if let Some(b) = got {
                        self.with_state(|s| s.pair_put(slot, b, now));
                    }
                    return Response::Err(ErrorCode::RateLimit);
                }
                Response::Blob(got)
            }
            _ => Response::Err(ErrorCode::Internal),
        }
    }
}

/// A server-wide connection slot from [`Server::admit`], freed when dropped.
pub struct Admission(Arc<Server>);

impl Drop for Admission {
    fn drop(&mut self) {
        self.0
            .with_state(|st| st.open_conns = st.open_conns.saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secsec_proto::wire::{HeadPut, KeyslotPut};
    use secsec_sig::DeviceKey;

    fn server() -> (Server, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("objs.redb")).unwrap();
        (Server::new(store), dir)
    }

    fn enroll(s: &Server, dev: &DeviceKey) {
        s.store()
            .put_keyslot(&dev.device_id().unwrap(), 1, b"keyslot")
            .unwrap();
    }

    const T: [u8; 32] = [0x7a; 32];
    const NOW: u64 = 1_000;

    fn read_req(dev: &DeviceKey, request: Request) -> Incoming<'static> {
        let (op_label, args_hash, _) = op_and_args(&request);
        let sig = ReadAuth {
            op: op_label,
            args_hash,
            session_transcript: T,
        }
        .sign(dev)
        .unwrap();
        Incoming {
            pubkey: Box::leak(Box::new(dev.public())),
            request,
            op_sig: sig,
            session_transcript: T,
            server_nonce: None,
        }
    }

    fn write_req_at(dev: &DeviceKey, request: Request, issued_at: u64) -> Incoming<'static> {
        let nonce = [0x5e; 32];
        let (op_label, args_hash, _) = op_and_args(&request);
        let sig = WriteAuth {
            op: op_label,
            args_hash,
            session_transcript: T,
            server_nonce: nonce,
        }
        .sign(dev)
        .unwrap();
        Incoming {
            pubkey: Box::leak(Box::new(dev.public())),
            request,
            op_sig: sig,
            session_transcript: T,
            server_nonce: Some(IssuedNonce { nonce, issued_at }),
        }
    }

    fn write_req(dev: &DeviceKey, request: Request) -> Incoming<'static> {
        write_req_at(dev, request, NOW)
    }

    fn put(id: [u8; 32], blob: &[u8], push: [u8; 16]) -> Request {
        Request::Put {
            id,
            declared_size: blob.len() as u32,
            push_id: push,
            blob: blob.to_vec(),
        }
    }

    /// Promote `push`'s staging by advancing a throwaway ref under it.
    fn promote(s: &Server, dev: &DeviceKey, push: [u8; 16]) {
        let blob = b"head".to_vec();
        let cas = Request::CasHead {
            ref_h: *blake3::hash(&push).as_bytes(),
            old_head: [0u8; 32],
            new_head: *blake3::hash(&blob).as_bytes(),
            promote: push,
            new_blob: blob,
        };
        assert_eq!(s.handle(write_req(dev, cas), NOW), Response::Ok);
    }

    fn batch(old_tip: [u8; 32], entries: &[&[u8]], keyslots: Vec<KeyslotPut>) -> Request {
        Request::RosterBatch {
            old_tip,
            entries: entries.iter().map(|e| e.to_vec()).collect(),
            keyslots,
            keyhist: None,
            roster_keyhist: None,
            revoke: vec![],
            head: None,
        }
    }

    #[test]
    fn unenrolled_key_is_rejected() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        assert_eq!(
            s.handle(read_req(&dev, Request::Get { id: [1; 32] }), NOW),
            Response::Err(ErrorCode::NotEnrolled)
        );
    }

    #[test]
    fn put_then_get_round_trip() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let id = [0x22; 32];
        assert_eq!(
            s.handle(write_req(&dev, put(id, b"object-bytes", [0xaa; 16])), NOW),
            Response::Ok
        );
        promote(&s, &dev, [0xaa; 16]);
        assert_eq!(
            s.handle(read_req(&dev, Request::Get { id }), NOW),
            Response::Blob(Some(b"object-bytes".to_vec()))
        );
        assert_eq!(
            s.handle(read_req(&dev, Request::Get { id: [0x99; 32] }), NOW),
            Response::Blob(None)
        );
    }

    #[test]
    fn bad_or_forged_signatures_are_rejected() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let mut inc = read_req(&dev, Request::Get { id: [1; 32] });
        *inc.op_sig.last_mut().unwrap() ^= 0x01;
        assert_eq!(s.handle(inc, NOW), Response::Err(ErrorCode::BadAuth));
        let mut inc = read_req(&dev, Request::Get { id: [1; 32] });
        inc.request = Request::Get { id: [2; 32] };
        assert_eq!(s.handle(inc, NOW), Response::Err(ErrorCode::BadAuth));
    }

    /// A write outside its stream challenge's TTL, or without one, is refused (§19).
    #[test]
    fn write_nonce_must_be_fresh() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let stale = write_req_at(&dev, put([3; 32], &[0], [0xbb; 16]), NOW - 60);
        assert_eq!(s.handle(stale, NOW), Response::Err(ErrorCode::BadAuth));
        let future = write_req_at(&dev, put([3; 32], &[0], [0xbb; 16]), NOW + 1);
        assert_eq!(s.handle(future, NOW), Response::Err(ErrorCode::BadAuth));
        let mut none = write_req(&dev, put([3; 32], &[0], [0xbb; 16]));
        none.server_nonce = None;
        assert_eq!(s.handle(none, NOW), Response::Err(ErrorCode::BadAuth));
        let fresh = write_req_at(&dev, put([3; 32], &[0], [0xbb; 16]), NOW - 59);
        assert_eq!(s.handle(fresh, NOW), Response::Ok);
    }

    #[test]
    fn put_size_rules() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let lie = Request::Put {
            id: [5; 32],
            declared_size: 99,
            push_id: [0; 16],
            blob: vec![0u8; 3],
        };
        assert_eq!(
            s.handle(write_req(&dev, lie), NOW),
            Response::Err(ErrorCode::BadRequest)
        );
        let huge = Request::Put {
            id: [6; 32],
            declared_size: u32::MAX,
            push_id: [0; 16],
            blob: vec![0u8; 8],
        };
        assert_eq!(
            s.handle(write_req(&dev, huge), NOW),
            Response::Err(ErrorCode::BadRequest)
        );
    }

    /// §7/§12: the genesis exception admits exactly the genesis batch, with the key's own keyslot, onto an empty roster.
    #[test]
    fn genesis_exception_is_exact() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        let me = dev.device_id().unwrap();
        let ks = |d: [u8; 32]| KeyslotPut {
            device_id: d,
            gen: 1,
            blob: b"ks".to_vec(),
        };
        for bad in [
            batch(ABSENT_HEAD, &[b"g"], vec![ks([0x55; 32])]),
            batch(ABSENT_HEAD, &[b"g", b"x"], vec![ks(me)]),
            batch(ABSENT_HEAD, &[b"g"], vec![ks(me), ks([0x56; 32])]),
            batch([1; 32], &[b"g"], vec![ks(me)]),
            Request::Get { id: [1; 32] },
        ] {
            let inc = if matches!(bad, Request::Get { .. }) {
                read_req(&dev, bad)
            } else {
                write_req(&dev, bad)
            };
            assert_eq!(s.handle(inc, NOW), Response::Err(ErrorCode::NotEnrolled));
        }
        assert_eq!(
            s.handle(
                write_req(&dev, batch(ABSENT_HEAD, &[b"g"], vec![ks(me)])),
                NOW
            ),
            Response::Ok
        );
        // With a repository in place, a second key's genesis attempt is no exception.
        let other = DeviceKey::generate().unwrap();
        let oid = other.device_id().unwrap();
        assert_eq!(
            s.handle(
                write_req(&other, batch(ABSENT_HEAD, &[b"g2"], vec![ks(oid)])),
                NOW
            ),
            Response::Err(ErrorCode::NotEnrolled)
        );
    }

    #[test]
    fn has_over_cap_is_rejected() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let ids = vec![[0u8; 32]; limits::MAX_HAS_IDS + 1];
        assert_eq!(
            s.handle(read_req(&dev, Request::Has { ids }), NOW),
            Response::Err(ErrorCode::TooManyIds)
        );
    }

    #[test]
    fn cas_head_first_write_conflict_and_blob_mismatch() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let cas = |old: [u8; 32], nh: [u8; 32], b: Vec<u8>| Request::CasHead {
            ref_h: [0x33; 32],
            old_head: old,
            new_head: nh,
            promote: [0u8; 16],
            new_blob: b,
        };
        let blob = b"head-blob-v1".to_vec();
        let h1 = *blake3::hash(&blob).as_bytes();
        assert_eq!(
            s.handle(write_req(&dev, cas([0; 32], h1, blob.clone())), NOW),
            Response::Ok
        );
        assert_eq!(
            s.handle(write_req(&dev, cas([0; 32], h1, blob)), NOW),
            Response::Err(ErrorCode::CasConflict)
        );
        let v2 = b"head-blob-v2".to_vec();
        let h2 = *blake3::hash(&v2).as_bytes();
        assert_eq!(
            s.handle(write_req(&dev, cas(h1, h2, v2)), NOW),
            Response::Ok
        );
        assert_eq!(
            s.handle(
                write_req(&dev, cas([0; 32], [0xAB; 32], b"x".to_vec())),
                NOW
            ),
            Response::Err(ErrorCode::BadRequest)
        );
    }

    /// A finite cap is charged only for what a promote actually made durable.
    #[test]
    fn quota_charges_only_promoted_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let s = Server::new(Store::open(dir.path().join("q.redb")).unwrap()).with_limits(Limits {
            storage_cap: 10,
            ..Limits::default()
        });
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let d = dev.device_id().unwrap();
        s.store()
            .stage(&[7; 16], &[1; 32], b"eight!!!", NOW)
            .unwrap();
        s.store().stage(&[7; 16], &[2; 32], b"two", NOW).unwrap();
        // Another push makes one staged object durable first; it is never charged twice.
        s.store().put(&[1; 32], b"eight!!!").unwrap();
        let blob = b"h".to_vec();
        let cas = Request::CasHead {
            ref_h: [9; 32],
            old_head: [0; 32],
            new_head: *blake3::hash(&blob).as_bytes(),
            promote: [7; 16],
            new_blob: blob,
        };
        assert_eq!(s.handle(write_req(&dev, cas), NOW), Response::Ok);
        let used = s.with_state(|st| st.quotas.get(&d).map(StorageQuota::used));
        assert_eq!(used, Some(3), "only the 3 newly durable bytes are charged");
    }

    fn prune_req(
        dev: &DeviceKey,
        dead: Vec<[u8; 32]>,
        ahh: [u8; 32],
        roster_len: u64,
    ) -> Incoming<'static> {
        write_req(
            dev,
            Request::Prune {
                dead,
                all_heads_hash: ahh,
                roster_len,
            },
        )
    }

    /// §15: a prune signed over a stale view is a typed CasConflict and deletes nothing.
    #[test]
    fn prune_is_bound_to_the_servers_own_head_and_roster_state() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        enroll(&s, &dev);
        let id = [0x70; 32];
        assert_eq!(
            s.handle(write_req(&dev, put(id, b"data", [0xcc; 16])), NOW),
            Response::Ok
        );
        promote(&s, &dev, [0xcc; 16]);
        assert_eq!(
            s.handle(prune_req(&dev, vec![id], [0xAB; 32], 0), NOW),
            Response::Err(ErrorCode::CasConflict)
        );
        assert!(s.store().get(&id).unwrap().is_some());
        let ahh = prune::all_heads_hash(&s.store().ref_blob_hashes().unwrap());
        assert_eq!(
            s.handle(prune_req(&dev, vec![id], ahh, 1), NOW),
            Response::Err(ErrorCode::CasConflict),
            "an empty roster is length 0, never 1"
        );
        assert_eq!(
            s.handle(prune_req(&dev, vec![id], ahh, 0), NOW),
            Response::Ok
        );
        assert!(s.store().get(&id).unwrap().is_none());
    }

    #[test]
    fn concurrent_connection_cap_per_key() {
        let (s, _d) = server();
        let d = DeviceKey::generate().unwrap().device_id().unwrap();
        let max = limits::MAX_CONCURRENT_CONNS_PER_KEY;
        for _ in 0..max {
            assert!(s.acquire_conn(d));
        }
        assert!(!s.acquire_conn(d));
        s.release_conn(d);
        assert!(s.acquire_conn(d));
        let d2 = DeviceKey::generate().unwrap().device_id().unwrap();
        assert!(s.acquire_conn(d2));
        for _ in 0..max {
            s.release_conn(d);
        }
        s.release_conn(d);
        assert!(s.acquire_conn(d));
    }

    /// The server-wide cap holds a slot per admission until its guard drops, and defaults to the §19 value.
    #[test]
    fn server_wide_connection_cap() {
        let (s, _d) = server();
        assert_eq!(s.limits.max_connections, limits::MAX_CONNECTIONS);
        let s = Arc::new(s.with_limits(Limits {
            max_connections: 2,
            ..Limits::default()
        }));
        let a = s.admit().unwrap();
        let b = s.admit().unwrap();
        assert!(s.admit().is_none());
        drop(a);
        let c = s.admit().unwrap();
        assert!(s.admit().is_none());
        drop((b, c));
        assert_eq!(s.with_state(|st| st.open_conns), 0);
        assert!(s.admit().is_some());
    }

    /// Batches chain on the tip, a stale tip conflicts, and a conflict refunds the hourly budget.
    #[test]
    fn roster_batch_chains_rejects_races_and_refunds() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        let me = dev.device_id().unwrap();
        let genesis = batch(
            ABSENT_HEAD,
            &[b"genesis"],
            vec![KeyslotPut {
                device_id: me,
                gen: 1,
                blob: b"ks".to_vec(),
            }],
        );
        assert_eq!(s.handle(write_req(&dev, genesis), NOW), Response::Ok);
        let tip0 = *blake3::hash(b"genesis").as_bytes();
        assert_eq!(
            s.handle(write_req(&dev, batch(tip0, &[b"e1", b"e2"], vec![])), NOW),
            Response::Ok
        );
        let used = s.with_state(|st| st.sigchain_calls.get_mut(&me).unwrap().count(NOW));
        for _ in 0..3 {
            assert_eq!(
                s.handle(write_req(&dev, batch(tip0, &[b"racer"], vec![])), NOW),
                Response::Err(ErrorCode::CasConflict)
            );
        }
        let after = s.with_state(|st| st.sigchain_calls.get_mut(&me).unwrap().count(NOW));
        assert_eq!(used, after, "lost CASes cost no sigchain budget");
        assert_eq!(
            s.handle(write_req(&dev, batch(tip0, &[], vec![])), NOW),
            Response::Err(ErrorCode::BadRequest)
        );
    }

    /// §8.4: a revoke batch deletes every generation's keyslot of the revoked device and re-signs the head atomically.
    #[test]
    fn revoke_batch_unenrolls_every_generation() {
        let (s, _d) = server();
        let dev = DeviceKey::generate().unwrap();
        let victim = DeviceKey::generate().unwrap();
        let vid = victim.device_id().unwrap();
        let genesis = RosterBatch {
            expected_tip: ABSENT_HEAD,
            entries: &[b"g".to_vec()],
            keyslots: &[],
            keyhist: None,
            roster_keyhist: None,
            revoke: &[],
            head: None,
        };
        assert_eq!(s.store().roster_batch(&genesis).unwrap(), Some(0));
        enroll(&s, &dev);
        s.store().put_keyslot(&vid, 1, b"v1").unwrap();
        s.store().put_keyslot(&vid, 2, b"v2").unwrap();
        s.store()
            .cas_ref(&[4; 32], &ABSENT_HEAD, b"old-head", &[0; 16])
            .unwrap();
        let req = Request::RosterBatch {
            old_tip: *blake3::hash(b"g").as_bytes(),
            entries: vec![b"revoke".to_vec(), b"rotate".to_vec()],
            keyslots: vec![],
            keyhist: Some((1, b"kh".to_vec())),
            roster_keyhist: Some((1, b"rkh".to_vec())),
            revoke: vec![vid],
            head: Some(HeadPut {
                ref_h: [4; 32],
                old_head: *blake3::hash(b"old-head").as_bytes(),
                new_blob: b"resigned".to_vec(),
            }),
        };
        assert_eq!(s.handle(write_req(&dev, req), NOW), Response::Ok);
        assert!(!s.store().keyslot_exists(&vid).unwrap());
        assert_eq!(
            s.handle(read_req(&victim, Request::Get { id: [1; 32] }), NOW),
            Response::Err(ErrorCode::NotEnrolled)
        );
        assert_eq!(
            s.store().get_ref(&[4; 32]).unwrap().as_deref(),
            Some(&b"resigned"[..])
        );
    }

    /// §7: a mailbox slot is delivered once; a second take finds it empty.
    #[test]
    fn pairing_slot_is_single_use() {
        let (s, _d) = server();
        let joiner = DeviceKey::generate().unwrap();
        let host = DeviceKey::generate().unwrap();
        assert_eq!(
            s.handle(
                read_req(
                    &joiner,
                    Request::PairPut {
                        slot: [1; 32],
                        blob: b"msg".to_vec()
                    }
                ),
                NOW
            ),
            Response::Ok
        );
        assert_eq!(
            s.handle(read_req(&host, Request::PairGet { slot: [1; 32] }), NOW),
            Response::Blob(Some(b"msg".to_vec()))
        );
        assert_eq!(
            s.handle(read_req(&host, Request::PairGet { slot: [1; 32] }), NOW),
            Response::Blob(None)
        );
    }

    /// The allow-list follows file edits without a restart and denies when the file is unreadable.
    #[test]
    fn authorized_file_is_reread_on_change_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized_keys");
        let a = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let line = |d: &DeviceKey| format!("{}\n", ssh_line(d));
        std::fs::write(&path, line(&a)).unwrap();
        let s = Server::new(Store::open(dir.path().join("s.redb")).unwrap())
            .with_authorized_file(path.clone());
        assert!(s.is_authorized(&a.device_id().unwrap()));
        assert!(!s.is_authorized(&b.device_id().unwrap()));
        std::fs::write(&path, format!("{}{}", line(&a), line(&b))).unwrap();
        assert!(s.is_authorized(&b.device_id().unwrap()));
        std::fs::remove_file(&path).unwrap();
        assert!(!s.is_authorized(&a.device_id().unwrap()));
    }

    /// An OpenSSH public-key line for `d`.
    fn ssh_line(d: &DeviceKey) -> String {
        let canon = d.public().to_canonical().unwrap();
        let b64 = base64_encode(&canon);
        format!("ssh-ed25519 {b64} test")
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}
