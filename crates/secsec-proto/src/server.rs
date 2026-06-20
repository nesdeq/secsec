//! Server-side enforcement policy (`secsec-Design.md` §11, §12, §19), pure and clock-injected
//! (every method takes `now`) so it is testable without sockets: [`NonceStore`] (single-use nonce
//! replay defense), [`TokenBucket`] (byte rates), [`WindowCounter`] (per-hour caps),
//! [`StorageQuota`]. Keyslot-existence enforcement lives with the store (§12).

use std::collections::{HashMap, VecDeque};

/// Normative §19 limit constants (server MUST enforce).
pub mod limits {
    /// `server_nonce` time-to-live, seconds (§19): single-use within this window.
    pub const SERVER_NONCE_TTL_SECS: u64 = 60;
    /// Max ids in a single `has()` or `prune` batch (§12/§19); the client batches larger sets.
    pub const MAX_HAS_IDS: usize = 1_024;
    /// Max sigchain entries per authenticated connection identity per hour (§19).
    pub const MAX_SIGCHAIN_ENTRIES_PER_CONN_PER_HOUR: u64 = 60;
    /// Max total sigchain length (§19, configurable default).
    pub const MAX_TOTAL_SIGCHAIN: u64 = 10_000;
    /// Per-key storage quota, bytes — 10 GiB default (§19).
    pub const PER_KEY_STORAGE_QUOTA: u64 = 10 * 1024 * 1024 * 1024;
    /// Per-key sustained write rate, bytes/sec — 100 MB/s (§19, decimal MB).
    pub const WRITE_RATE_BYTES_PER_SEC: u64 = 100_000_000;
    /// Per-key write burst, bytes — 1 GiB (§19).
    pub const WRITE_BURST_BYTES: u64 = 1024 * 1024 * 1024;
    /// Per-key sustained read rate, bytes/sec — 200 MB/s (§19, decimal MB).
    pub const READ_RATE_BYTES_PER_SEC: u64 = 200_000_000;
    /// New connections/sec per source IP (§19).
    pub const CONN_RATE_PER_SEC: u64 = 10;
    /// Concurrent connections per authenticated key (§19).
    pub const MAX_CONCURRENT_CONNS_PER_KEY: u64 = 3;
    /// One hour, in seconds (window for the per-hour caps).
    pub const HOUR_SECS: u64 = 3_600;
}

/// Operator-tunable server limits (`secsec-Design.md` §7 `secsec.config`), defaulting to the §19
/// normative values. Only values that are safe to change live here; everything that must be uniform
/// across peers or that bounds an attacker (decoder bounds, nonce TTL, sigchain caps, the burst that
/// guarantees a single object always fits) stays compiled-in.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Per-key sustained write rate, bytes/sec.
    pub write_rate: u64,
    /// Per-key sustained read rate, bytes/sec.
    pub read_rate: u64,
    /// New connections/sec per source IP.
    pub conn_rate_per_sec: u64,
    /// Concurrent connections per authenticated key.
    pub max_conns_per_key: u64,
    /// Per-key cumulative new-write cap, bytes — `0` means unlimited (the default, §6).
    pub storage_cap: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            write_rate: limits::WRITE_RATE_BYTES_PER_SEC,
            read_rate: limits::READ_RATE_BYTES_PER_SEC,
            conn_rate_per_sec: limits::CONN_RATE_PER_SEC,
            max_conns_per_key: limits::MAX_CONCURRENT_CONNS_PER_KEY,
            storage_cap: 0,
        }
    }
}

/// `server_nonce` freshness + single-use store (§11). The server [`issue`](Self::issue)s a fresh
/// random nonce per challenge; a returned auth signature is only honoured if its nonce
/// [`consume`](Self::consume)s successfully — issued, unexpired, and not already used.
#[derive(Debug, Clone)]
pub struct NonceStore {
    ttl: u64,
    /// nonce → expiry (unix seconds). Presence = issued & not yet consumed.
    live: HashMap<[u8; 32], u64>,
    /// Last time expired nonces were swept (amortized housekeeping; see [`issue`](Self::issue)).
    last_evict: u64,
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new(limits::SERVER_NONCE_TTL_SECS)
    }
}

impl NonceStore {
    /// A store with an explicit TTL (use [`Default`] for the §19 60-second TTL).
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl: ttl_secs,
            live: HashMap::new(),
            last_evict: 0,
        }
    }

    /// Record a freshly-issued OS-CSPRNG `nonce`, valid until `now + ttl`. Issue also sweeps expired
    /// entries once per TTL window — never-consumed nonces (reads, abandoned writes) would otherwise
    /// grow the live set unboundedly.
    pub fn issue(&mut self, nonce: [u8; 32], now: u64) {
        if now.saturating_sub(self.last_evict) >= self.ttl {
            self.evict_expired(now);
            self.last_evict = now;
        }
        self.live.insert(nonce, now.saturating_add(self.ttl));
    }

    /// Consume `nonce`: returns `true` iff it was issued, has not expired at `now`, and has not been
    /// consumed before — and removes it (single-use). Any replay or expiry returns `false`.
    pub fn consume(&mut self, nonce: &[u8; 32], now: u64) -> bool {
        match self.live.get(nonce) {
            Some(&expiry) if now < expiry => {
                self.live.remove(nonce);
                true
            }
            // expired-but-present: drop it and reject.
            Some(_) => {
                self.live.remove(nonce);
                false
            }
            None => false,
        }
    }

    /// Drop all expired nonces (periodic housekeeping; bounds memory).
    pub fn evict_expired(&mut self, now: u64) {
        self.live.retain(|_, &mut expiry| now < expiry);
    }

    /// Number of live (issued, unconsumed, unexpired-at-last-eviction) nonces.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.live.len()
    }
}

/// A token-bucket rate limiter (§19 byte/connection rates): `capacity` is the burst, `refill_per_sec`
/// the sustained rate. Tokens accrue with elapsed time up to `capacity`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u64,
    refill_per_sec: u64,
    tokens: u64,
    last: u64,
}

impl TokenBucket {
    /// A full bucket at time `now`.
    #[must_use]
    pub fn new(capacity: u64, refill_per_sec: u64, now: u64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            tokens: capacity,
            last: now,
        }
    }

    fn refill(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.last);
        if elapsed > 0 {
            let added = elapsed.saturating_mul(self.refill_per_sec);
            self.tokens = self.tokens.saturating_add(added).min(self.capacity);
            self.last = now;
        }
    }

    /// Refill for elapsed time, then take `amount` if available. Returns `true` if allowed.
    pub fn try_take(&mut self, amount: u64, now: u64) -> bool {
        self.refill(now);
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    /// Current token count (after refilling to `now`).
    pub fn available(&mut self, now: u64) -> u64 {
        self.refill(now);
        self.tokens
    }
}

/// A rolling-window event counter (§19 per-hour caps): at most `max` events within any trailing
/// `window` seconds.
#[derive(Debug, Clone)]
pub struct WindowCounter {
    window: u64,
    max: u64,
    events: VecDeque<u64>,
}

impl WindowCounter {
    /// At most `max` events per trailing `window` seconds.
    #[must_use]
    pub fn new(window_secs: u64, max: u64) -> Self {
        Self {
            window: window_secs,
            max,
            events: VecDeque::new(),
        }
    }

    fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.window);
        while let Some(&front) = self.events.front() {
            if front < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Record an event at `now` if it keeps the window within `max`; returns `true` if recorded,
    /// `false` if the cap is already reached (the event is rejected, not recorded).
    pub fn try_record(&mut self, now: u64) -> bool {
        self.prune(now);
        if (self.events.len() as u64) < self.max {
            self.events.push_back(now);
            true
        } else {
            false
        }
    }

    /// Undo the most recent [`try_record`](Self::try_record) — for an op that was counted but did no
    /// work (e.g. lost a downstream CAS). Pops the latest event; no-op if empty.
    pub fn refund(&mut self) {
        self.events.pop_back();
    }

    /// Events currently within the trailing window (after pruning to `now`).
    pub fn count(&mut self, now: u64) -> u64 {
        self.prune(now);
        self.events.len() as u64
    }
}

/// Per-key **new-write** quota for one server session (§11/§19): an anti-flood cap on bytes a key
/// introduces, reset on restart. A dedup store has no durable per-key byte ownership — durable disk
/// limits are the operator's filesystem quota (§11). Idempotent re-puts are not charged.
#[derive(Debug, Clone)]
pub struct StorageQuota {
    limit: u64,
    used: u64,
}

impl StorageQuota {
    /// A quota of `limit` bytes (use [`limits::PER_KEY_STORAGE_QUOTA`] for the §19 default).
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    /// Reserve `amount` bytes if it fits under the limit; returns `true` if allowed.
    pub fn try_add(&mut self, amount: u64) -> bool {
        match self.used.checked_add(amount) {
            Some(new) if new <= self.limit => {
                self.used = new;
                true
            }
            _ => false,
        }
    }

    /// Release `amount` bytes (e.g. after GC).
    pub fn release(&mut self, amount: u64) {
        self.used = self.used.saturating_sub(amount);
    }

    /// Bytes currently in use.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_fresh_consume_replay_and_expiry() {
        let mut s = NonceStore::new(60);
        let n = [7u8; 32];
        // unissued nonce is rejected.
        assert!(!s.consume(&n, 100));
        // issue, then consume once.
        s.issue(n, 100);
        assert!(s.consume(&n, 110));
        // replay (already consumed) is rejected.
        assert!(!s.consume(&n, 111));

        // expiry: issued at 100, ttl 60 -> expires at 160.
        let m = [8u8; 32];
        s.issue(m, 100);
        assert!(!s.consume(&m, 160), "at/after expiry must reject");
        // and it was dropped.
        assert!(!s.consume(&m, 100));
    }

    #[test]
    fn nonce_evicts_expired() {
        let mut s = NonceStore::new(60);
        s.issue([1; 32], 100);
        s.issue([2; 32], 200);
        s.evict_expired(170); // [1] expired (160), [2] expires at 260
        assert_eq!(s.live_count(), 1);
        assert!(s.consume(&[2; 32], 170));
    }

    /// `issue` must amortize eviction so never-consumed nonces (read streams, abandoned writes) cannot
    /// accumulate without bound: once a TTL window has elapsed, the next issue sweeps the expired set.
    #[test]
    fn issue_bounds_live_set_across_ttl_windows() {
        let mut s = NonceStore::new(60);
        // A burst of nonces issued at t=0 that are never consumed.
        for i in 0..100u32 {
            let mut n = [0u8; 32];
            n[..4].copy_from_slice(&i.to_le_bytes());
            s.issue(n, 0);
        }
        assert_eq!(s.live_count(), 100);
        // Issuing again within the same TTL window does not sweep (entries still valid).
        s.issue([0xAA; 32], 30);
        assert_eq!(s.live_count(), 101);
        // Past the TTL window, the next issue sweeps every now-expired nonce — the set stays bounded.
        s.issue([0xBB; 32], 200);
        assert_eq!(
            s.live_count(),
            1,
            "expired nonces are swept on issue past the TTL window"
        );
    }

    #[test]
    fn token_bucket_burst_refill_and_deny() {
        // capacity 1000, refill 100/s.
        let mut b = TokenBucket::new(1000, 100, 0);
        assert!(b.try_take(1000, 0)); // drain the burst
        assert!(!b.try_take(1, 0)); // empty -> deny
        assert!(b.try_take(500, 5)); // 5s -> +500 tokens, take 500
        assert!(!b.try_take(1, 5)); // empty again
                                    // refill caps at capacity (100s would add 10_000 but max is 1000).
        assert_eq!(b.available(200), 1000);
    }

    #[test]
    fn window_counter_caps_per_window() {
        // gc: 4 per hour.
        let mut w = WindowCounter::new(limits::HOUR_SECS, 4);
        for t in [0, 10, 20, 30] {
            assert!(w.try_record(t), "first 4 allowed");
        }
        assert!(!w.try_record(40), "5th within the hour denied");
        // after the window slides past the early events, capacity frees up.
        assert!(w.try_record(3601), "event at 3601 prunes the t=0 event");
        assert_eq!(w.count(3601), 4); // t in {10,20,30,3601}
    }

    #[test]
    fn window_counter_refund_returns_a_slot() {
        let mut w = WindowCounter::new(limits::HOUR_SECS, 2);
        assert!(w.try_record(0));
        assert!(w.try_record(0));
        assert!(!w.try_record(0), "cap reached");
        w.refund(); // e.g. the recorded op then lost a CAS
        assert!(w.try_record(0), "a refunded slot is reusable");
        assert_eq!(w.count(0), 2);
        // refund on an empty counter is a harmless no-op.
        let mut e = WindowCounter::new(60, 1);
        e.refund();
        assert_eq!(e.count(0), 0);
    }

    #[test]
    fn storage_quota_accumulates_and_releases() {
        let mut q = StorageQuota::new(1000);
        assert!(q.try_add(600));
        assert!(!q.try_add(500), "600+500 > 1000 denied");
        assert!(q.try_add(400)); // 600+400 = 1000 exactly
        assert_eq!(q.used(), 1000);
        q.release(400);
        assert!(q.try_add(300));
        assert_eq!(q.used(), 900);
    }

    #[test]
    fn limits_match_spec_19() {
        // spot-check the normative §19 values.
        assert_eq!(limits::SERVER_NONCE_TTL_SECS, 60);
        assert_eq!(limits::MAX_HAS_IDS, 1024);
        assert_eq!(limits::MAX_SIGCHAIN_ENTRIES_PER_CONN_PER_HOUR, 60);
        assert_eq!(limits::PER_KEY_STORAGE_QUOTA, 10 * 1024 * 1024 * 1024);
    }
}
