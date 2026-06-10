//! §7 enrollment rate-limiting — the grant-attempt log (`secsec-Design.md` §7, §19).
//!
//! The granting device E MUST allow at most [`MAX_GRANT_SESSIONS_PER_HOUR`] SAS/grant sessions per
//! `D_pubkey` per rolling hour, tracked in **E's local state**, independent of sigchain operations
//! (§7). This bounds a relay's blind-guess attempts against the ~20-bit SAS: without it, a relay that
//! substitutes a key gets one guess per session and could retry freely; the cap makes grinding
//! infeasible. The store of attempts is a plain local text log (`device_id_hex unix_secs` per line) —
//! not secret (device ids are public) and local-only, so it needs no encryption.

use secsec_sig::DeviceId;

/// §19: at most this many SAS/grant sessions per `D_pubkey` per rolling hour.
pub const MAX_GRANT_SESSIONS_PER_HOUR: usize = 5;
/// §19: the rolling window, in seconds.
pub const GRANT_WINDOW_SECS: u64 = 3600;

/// The per-`D_pubkey` rate limit was hit (§7): `count` in-window attempts already exist for `device`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantRateLimited {
    /// The device whose enrollment was rate-limited.
    pub device: DeviceId,
    /// In-window attempts already recorded for it.
    pub count: usize,
}

impl core::fmt::Display for GrantRateLimited {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "grant rate limit: {} sessions for this device in the last hour (max {}); §7",
            self.count, MAX_GRANT_SESSIONS_PER_HOUR
        )
    }
}
impl std::error::Error for GrantRateLimited {}

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parse a grant-attempt log: one `device_id_hex unix_secs` per line; malformed lines are skipped.
#[must_use]
pub fn parse_log(s: &str) -> Vec<(DeviceId, u64)> {
    let mut out = Vec::new();
    for line in s.lines() {
        let mut it = line.split_whitespace();
        let (Some(id_hex), Some(ts_s), None) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if id_hex.len() != 64 {
            continue;
        }
        let Ok(ts) = ts_s.parse::<u64>() else {
            continue;
        };
        let mut id = [0u8; 32];
        let ok = (0..32).all(|i| {
            u8::from_str_radix(&id_hex[i * 2..i * 2 + 2], 16)
                .map(|b| id[i] = b)
                .is_ok()
        });
        if ok {
            out.push((id, ts));
        }
    }
    out
}

/// Serialize a grant-attempt log (inverse of [`parse_log`]).
#[must_use]
pub fn serialize_log(attempts: &[(DeviceId, u64)]) -> String {
    let mut s = String::new();
    for (id, ts) in attempts {
        s.push_str(&hx(id));
        s.push(' ');
        s.push_str(&ts.to_string());
        s.push('\n');
    }
    s
}

/// Decide whether a new grant attempt for `device` at `now` is allowed (§7), given the prior
/// `attempts`. Prunes to the trailing [`GRANT_WINDOW_SECS`]; if `device` already has
/// [`MAX_GRANT_SESSIONS_PER_HOUR`] in-window attempts, returns [`GrantRateLimited`]. Otherwise returns
/// the pruned-plus-this-attempt list for the caller to persist.
pub fn record_grant_attempt(
    attempts: &[(DeviceId, u64)],
    device: &DeviceId,
    now: u64,
) -> Result<Vec<(DeviceId, u64)>, GrantRateLimited> {
    let cutoff = now.saturating_sub(GRANT_WINDOW_SECS);
    let mut kept: Vec<(DeviceId, u64)> = attempts
        .iter()
        .copied()
        .filter(|(_, t)| *t >= cutoff)
        .collect();
    let count = kept.iter().filter(|(id, _)| id == device).count();
    if count >= MAX_GRANT_SESSIONS_PER_HOUR {
        return Err(GrantRateLimited {
            device: *device,
            count,
        });
    }
    kept.push((*device, now));
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: DeviceId = [0xAA; 32];
    const OTHER: DeviceId = [0xBB; 32];

    #[test]
    fn caps_at_five_per_hour_per_device() {
        let mut log: Vec<(DeviceId, u64)> = Vec::new();
        let now = 1_000_000u64;
        // five attempts allowed, accumulating.
        for i in 0..MAX_GRANT_SESSIONS_PER_HOUR {
            log = record_grant_attempt(&log, &D, now + i as u64).unwrap();
        }
        assert_eq!(log.len(), 5);
        // the sixth within the hour is rejected.
        let err = record_grant_attempt(&log, &D, now + 10).unwrap_err();
        assert_eq!(err.device, D);
        assert_eq!(err.count, 5);
        // a *different* device is unaffected.
        assert!(record_grant_attempt(&log, &OTHER, now + 10).is_ok());
    }

    #[test]
    fn window_slides_and_old_attempts_prune() {
        let base = 1_000_000u64;
        let log: Vec<(DeviceId, u64)> = (0..5).map(|i| (D, base + i)).collect(); // ts base..base+4
                                                                                 // far enough out that the cutoff (later - window) passes the newest entry → all five prune.
        let later = base + GRANT_WINDOW_SECS + 5;
        let updated = record_grant_attempt(&log, &D, later).unwrap();
        assert_eq!(
            updated.len(),
            1,
            "old attempts pruned, only the new one remains"
        );
        assert_eq!(updated[0], (D, later));
    }

    #[test]
    fn log_round_trips_and_skips_garbage() {
        let attempts = vec![(D, 100u64), (OTHER, 200u64)];
        let s = serialize_log(&attempts);
        assert_eq!(parse_log(&s), attempts);
        // garbage lines are skipped, valid ones kept.
        let mixed = format!("{s}not-hex 5\nzz 9\n{}\n", hx(&D)); // last line missing ts
        assert_eq!(parse_log(&mixed), attempts);
    }
}
