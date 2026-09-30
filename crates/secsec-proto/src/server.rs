//! Server enforcement policy, pure and clock-injected: byte-rate buckets, windowed caps, per-key quota (`secsec-Design.md` §12, §19).

/// Normative §19 limit constants (server MUST enforce).
pub mod limits {
    /// `server_nonce` time-to-live, seconds: a write must arrive within this of its stream's challenge.
    pub const SERVER_NONCE_TTL_SECS: u64 = 60;
    /// Max ids in one `has()` or `prune` batch.
    pub const MAX_HAS_IDS: usize = 1_024;
    /// Max sigchain entries appended per authenticated key per hour.
    pub const MAX_SIGCHAIN_ENTRIES_PER_CONN_PER_HOUR: u64 = 60;
    /// Max total sigchain length.
    pub const MAX_TOTAL_SIGCHAIN: u64 = 10_000;
    /// Per-key sustained write rate, bytes/sec (100 MB/s).
    pub const WRITE_RATE_BYTES_PER_SEC: u64 = 100_000_000;
    /// Per-key write burst, bytes (1 GiB, above the 16 MiB object cap).
    pub const WRITE_BURST_BYTES: u64 = 1024 * 1024 * 1024;
    /// Per-key sustained read rate, bytes/sec (200 MB/s).
    pub const READ_RATE_BYTES_PER_SEC: u64 = 200_000_000;
    /// New connections/sec per source IP.
    pub const CONN_RATE_PER_SEC: u64 = 10;
    /// Concurrent connections per authenticated key.
    pub const MAX_CONCURRENT_CONNS_PER_KEY: u64 = 3;
    /// Concurrent connections server-wide, handshakes in flight included.
    pub const MAX_CONNECTIONS: u64 = 256;
    /// One hour, in seconds.
    pub const HOUR_SECS: u64 = 3_600;
}

/// Operator-tunable server limits (§19 `secsec.config`), defaulting to the normative values.
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
    /// Concurrent connections server-wide, handshakes in flight included.
    pub max_connections: u64,
    /// Per-key new-write cap per server session, bytes; `0` = unlimited.
    pub storage_cap: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            write_rate: limits::WRITE_RATE_BYTES_PER_SEC,
            read_rate: limits::READ_RATE_BYTES_PER_SEC,
            conn_rate_per_sec: limits::CONN_RATE_PER_SEC,
            max_conns_per_key: limits::MAX_CONCURRENT_CONNS_PER_KEY,
            max_connections: limits::MAX_CONNECTIONS,
            storage_cap: 0,
        }
    }
}

/// A token bucket: `capacity` is the burst, `refill_per_sec` the sustained rate.
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

    /// Refill to `now`, then take `amount` if available.
    pub fn try_take(&mut self, amount: u64, now: u64) -> bool {
        self.refill(now);
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    /// Whether the bucket has refilled to capacity by `now` (idle, safe to forget).
    pub fn is_full(&mut self, now: u64) -> bool {
        self.refill(now);
        self.tokens == self.capacity
    }
}

/// At most `max` events in any trailing `window` seconds: an event at `t` expires at `t + window`.
#[derive(Debug, Clone)]
pub struct WindowCounter {
    window: u64,
    max: u64,
    events: std::collections::VecDeque<u64>,
}

impl WindowCounter {
    /// At most `max` events per trailing `window_secs`.
    #[must_use]
    pub fn new(window_secs: u64, max: u64) -> Self {
        Self {
            window: window_secs,
            max,
            events: std::collections::VecDeque::new(),
        }
    }

    fn prune(&mut self, now: u64) {
        while let Some(&front) = self.events.front() {
            if front.saturating_add(self.window) <= now {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Record `n` events at `now` if all fit under `max`; records nothing otherwise.
    pub fn try_record_n(&mut self, now: u64, n: u64) -> bool {
        self.prune(now);
        if (self.events.len() as u64).saturating_add(n) <= self.max {
            self.events.extend(std::iter::repeat_n(now, n as usize));
            true
        } else {
            false
        }
    }

    /// Record one event (see [`Self::try_record_n`]).
    pub fn try_record(&mut self, now: u64) -> bool {
        self.try_record_n(now, 1)
    }

    /// Undo the `n` most recent records (an op that was counted but did no work).
    pub fn refund(&mut self, n: u64) {
        for _ in 0..n {
            self.events.pop_back();
        }
    }

    /// Events within the trailing window at `now`.
    pub fn count(&mut self, now: u64) -> u64 {
        self.prune(now);
        self.events.len() as u64
    }
}

/// Per-key new-write quota for one server session (§15), charged at promote; finite limits only.
#[derive(Debug, Clone)]
pub struct StorageQuota {
    limit: u64,
    used: u64,
}

impl StorageQuota {
    /// A finite cap of `limit` bytes.
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    /// Reserve `amount` bytes if it fits.
    pub fn try_add(&mut self, amount: u64) -> bool {
        match self.used.checked_add(amount) {
            Some(new) if new <= self.limit => {
                self.used = new;
                true
            }
            _ => false,
        }
    }

    /// Release `amount` reserved bytes.
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
    fn token_bucket_burst_refill_deny_and_idle() {
        let mut b = TokenBucket::new(1000, 100, 0);
        assert!(b.is_full(0));
        assert!(b.try_take(1000, 0));
        assert!(!b.try_take(1, 0));
        assert!(!b.is_full(0));
        assert!(b.try_take(500, 5));
        assert!(!b.try_take(1, 5));
        assert!(b.is_full(200), "refill caps at capacity");
    }

    #[test]
    fn window_counter_caps_per_window_exactly() {
        let mut w = WindowCounter::new(limits::HOUR_SECS, 4);
        for t in [0, 10, 20, 30] {
            assert!(w.try_record(t));
        }
        assert!(!w.try_record(40));
        // An event at t expires exactly at t + window.
        assert!(!w.try_record(3599));
        assert!(w.try_record(3600), "the t=0 event expired at 3600");
        assert_eq!(w.count(3600), 4);
    }

    #[test]
    fn window_counter_records_and_refunds_batches() {
        let mut w = WindowCounter::new(limits::HOUR_SECS, 5);
        assert!(w.try_record_n(0, 3));
        assert!(!w.try_record_n(0, 3), "all-or-nothing");
        assert_eq!(w.count(0), 3);
        w.refund(3);
        assert_eq!(w.count(0), 0);
        assert!(w.try_record_n(0, 5));
        let mut e = WindowCounter::new(60, 1);
        e.refund(1);
        assert_eq!(e.count(0), 0);
    }

    #[test]
    fn storage_quota_accumulates_and_releases() {
        let mut q = StorageQuota::new(1000);
        assert!(q.try_add(600));
        assert!(!q.try_add(500));
        assert!(q.try_add(400));
        assert_eq!(q.used(), 1000);
        q.release(400);
        assert!(q.try_add(300));
        assert_eq!(q.used(), 900);
    }

    #[test]
    fn limits_match_spec_19() {
        assert_eq!(limits::SERVER_NONCE_TTL_SECS, 60);
        assert_eq!(limits::MAX_HAS_IDS, 1024);
        assert_eq!(limits::MAX_SIGCHAIN_ENTRIES_PER_CONN_PER_HOUR, 60);
        assert_eq!(limits::MAX_CONNECTIONS, 256);
    }
}
