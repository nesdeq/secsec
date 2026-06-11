//! Client-driven garbage collection (`secsec-Design.md` §15). The client is the sole GC driver: it
//! computes the **keep-set** (the reachable object closure over the rostered heads), picks a safe
//! **`gc_gen`** from its own signed arrival receipts (never a server-asserted counter), binds its view
//! of the server's mutable state (`all_heads_hash`/`roster_seq`/`put_epoch`), and sends the sweep — a
//! compare-and-swap the server can only execute if nothing changed since (§15).
//!
//! Retention is **keep-everything** by default; a `gc` is explicit and opt-in. GC **fails safe**: if
//! any object in the keep-set traversal is unavailable, [`secsec_snapshot::reachable_objects`] errors
//! and no sweep is issued.

use crate::{fetch_head, ClientError, GcOutcome, Receipt, Remote};
use secsec_kdf::MasterKeys;
use secsec_object::Id;
use secsec_proto::gc::all_heads_hash;
use secsec_snapshot::reachable_objects;
use secsec_store::Store;
use secsec_sync::ref_hash;
use std::collections::BTreeMap;

/// The §19 GC grace window: recent arrivals (`local_receipt_time ≥ now − GC_GRACE_WINDOW`) are
/// shielded from collection, covering multi-day offline peers. Normative value, §15/§19.
pub const GC_GRACE_WINDOW_SECS: u64 = 48 * 60 * 60;

/// Choose a safe `gc_gen` from arrival `receipts` (§15): the **largest** `arrival_gen` such that
/// **every** object at that generation (and below) was received before the grace cutoff
/// (`local_time < now − GC_GRACE_WINDOW`). `receipts` is `(arrival_gen, local_receipt_time)` per
/// object, recorded when the receipt arrived (the client's own clock, never the server's `timestamp`).
/// Returns 0 (sweep nothing) if no generation is fully past the grace window.
#[must_use]
pub fn gc_gen_from_receipts(receipts: &[(u64, u64)], now: u64) -> u64 {
    let cutoff = now.saturating_sub(GC_GRACE_WINDOW_SECS);
    // The youngest local_receipt_time seen at each arrival generation.
    let mut newest_at_gen: BTreeMap<u64, u64> = BTreeMap::new();
    for &(gen, t) in receipts {
        let e = newest_at_gen.entry(gen).or_insert(0);
        *e = (*e).max(t);
    }
    // Walk generations ascending; stop at the first whose newest receipt is NOT yet past the grace
    // cutoff — gc_gen is the highest fully-aged generation below it.
    let mut gc_gen = 0;
    for (&gen, &newest) in &newest_at_gen {
        if newest < cutoff {
            gc_gen = gen;
        } else {
            break;
        }
    }
    gc_gen
}

/// The highest `put_epoch` carried in any arrival receipt — the client's view of the server's global
/// `put_epoch`, which the §15 GC compare-and-swap binds (§15). 0 if no receipts.
#[must_use]
pub fn put_epoch_from_receipts(receipts: &[(Id, Receipt)]) -> u64 {
    receipts.iter().map(|(_, r)| r.put_epoch).max().unwrap_or(0)
}

/// A persisted per-object arrival record (§15): the object's `arrival_gen`, the **local** time the
/// client first recorded its receipt (the client's own clock — never the server's `timestamp`, §15/§22),
/// and the highest `put_epoch` observed for it. The receipt log is the client's durable GC state across
/// runs; it is the input to [`gc_gen_from_log`]/[`put_epoch_from_log`]. Not secret — object ids are
/// public and the file is local-only — so it is stored as plain text, like the §7 grant log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptRecord {
    /// The generation the object first landed at (its arrival `put_epoch`).
    pub arrival_gen: u64,
    /// The client-local time the receipt was first recorded (the aging clock for `gc_gen`).
    pub first_local_time: u64,
    /// The highest server global `put_epoch` observed for this object.
    pub put_epoch: u64,
}

fn id_hex(id: &Id) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_id(hex: &str) -> Option<Id> {
    if hex.len() != 64 {
        return None;
    }
    let mut id = [0u8; 32];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(id)
}

/// Parse a receipt log: one `id_hex arrival_gen first_local_time put_epoch` per line; malformed lines
/// are skipped. Inverse of [`serialize_receipt_log`].
#[must_use]
pub fn parse_receipt_log(s: &str) -> BTreeMap<Id, ReceiptRecord> {
    let mut out = BTreeMap::new();
    for line in s.lines() {
        let mut it = line.split_whitespace();
        let (Some(id_h), Some(gen_s), Some(t_s), Some(pe_s), None) =
            (it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        let (Some(id), Ok(arrival_gen), Ok(first_local_time), Ok(put_epoch)) = (
            parse_id(id_h),
            gen_s.parse::<u64>(),
            t_s.parse::<u64>(),
            pe_s.parse::<u64>(),
        ) else {
            continue;
        };
        out.insert(
            id,
            ReceiptRecord {
                arrival_gen,
                first_local_time,
                put_epoch,
            },
        );
    }
    out
}

/// Serialize a receipt log (inverse of [`parse_receipt_log`]); deterministic (ids are `BTreeMap`-sorted).
#[must_use]
pub fn serialize_receipt_log(log: &BTreeMap<Id, ReceiptRecord>) -> String {
    let mut s = String::new();
    for (id, r) in log {
        s.push_str(&id_hex(id));
        s.push_str(&format!(
            " {} {} {}\n",
            r.arrival_gen, r.first_local_time, r.put_epoch
        ));
    }
    s
}

/// Merge fresh arrival `receipts` (from a sync) into the persisted `log` at client-local time `now`.
/// A first-seen object records `first_local_time = now` (its aging clock); a re-seen object keeps its
/// original `first_local_time` and `arrival_gen` (re-pushing an idempotent object does not reset its
/// age) but advances `put_epoch` to the max observed (the client's view of the server's global epoch).
pub fn merge_receipts(log: &mut BTreeMap<Id, ReceiptRecord>, receipts: &[(Id, Receipt)], now: u64) {
    for (id, r) in receipts {
        log.entry(*id)
            .and_modify(|rec| rec.put_epoch = rec.put_epoch.max(r.put_epoch))
            .or_insert(ReceiptRecord {
                arrival_gen: r.arrival_gen,
                first_local_time: now,
                put_epoch: r.put_epoch,
            });
    }
}

/// Choose a safe `gc_gen` from the persisted receipt `log` at client-local time `now` (see
/// [`gc_gen_from_receipts`]): the highest generation all of whose objects aged past the grace window.
#[must_use]
pub fn gc_gen_from_log(log: &BTreeMap<Id, ReceiptRecord>, now: u64) -> u64 {
    let receipts: Vec<(u64, u64)> = log
        .values()
        .map(|r| (r.arrival_gen, r.first_local_time))
        .collect();
    gc_gen_from_receipts(&receipts, now)
}

/// The client's view of the server's current global `put_epoch` from the persisted `log` — the max
/// observed (a lower bound; if the server has advanced since, the §15 GC CAS aborts and the client
/// re-syncs then retries). 0 if the log is empty.
#[must_use]
pub fn put_epoch_from_log(log: &BTreeMap<Id, ReceiptRecord>) -> u64 {
    log.values().map(|r| r.put_epoch).max().unwrap_or(0)
}

/// Run a §15 GC sweep against `remote`. `ref_names` are the refs whose heads anchor the keep-set
/// (their reachable closures are kept); `gc_gen` is the client-chosen generation (see
/// [`gc_gen_from_receipts`]); `roster_seq`/`put_epoch` are the client's current view (bound into the
/// CAS). Fetches each head, builds the keep-set from the local store (**fail-safe** on a missing
/// object), computes `all_heads_hash` from the fetched head blobs, and issues the sweep. Returns the
/// [`GcOutcome`] ([`GcOutcome::CasConflict`] if the server's state moved — re-read and retry).
pub async fn gc_collect<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    ref_names: &[&str],
    gc_gen: u64,
    roster_seq: u64,
    put_epoch: u64,
) -> Result<GcOutcome, ClientError> {
    // Heads + ref names are current-generation; the keep-set closure may span generations (§8.2).
    let rnk = keys.current().ref_name_key();
    let mut head_commits: Vec<Id> = Vec::new();
    let mut heads: Vec<(Id, [u8; 32])> = Vec::new();

    for name in ref_names {
        let ref_h = ref_hash(&rnk, name);
        // Fetch the raw head blob (for the all_heads_hash token) and open it (for its commit).
        if let Some((head, _sig, blob)) = fetch_head(remote, keys.current(), name).await? {
            head_commits.push(head.commit_id);
            heads.push((ref_h, *blake3::hash(&blob).as_bytes()));
        }
    }

    // Keep-set = reachable closure over all rostered heads (fail-safe on a missing object, §15).
    let keep = reachable_objects(keys, store, &head_commits)?;
    let keep_vec: Vec<Id> = keep.into_iter().collect();
    let ahh = all_heads_hash(&heads);

    Ok(remote
        .gc(keep_vec, gc_gen, &ahh, roster_seq, put_epoch)
        .await?)
}

/// Keep-everything sweep of the client's **own** object cache — the local mirror of the server's §15
/// sweep, so both ends prune identically. Delete every object **unreachable** from `head` (the orphans
/// left by cas-conflict retries and aborted pushes), keeping the full reachable history. Unlike the
/// server sweep there is **no grace window**: this cache serves only the local device, so anything
/// unreachable from our head is pure garbage. Returns the number of objects dropped. **Fail-safe**: if
/// the reachable closure can't be built (a missing object), it errors and deletes nothing.
pub fn local_sweep<K: MasterKeys>(keys: &K, store: &Store, head: &Id) -> Result<u64, ClientError> {
    let keep = reachable_objects(keys, store, &[*head])?;
    Ok(store.gc(&keep, u64::MAX)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_gen_picks_highest_fully_aged_generation() {
        let now = 1_000_000u64;
        let old = now - GC_GRACE_WINDOW_SECS - 100; // past the grace cutoff
        let recent = now - 10; // inside the grace window

        // gens 1,2 fully aged; gen 3 has a recent receipt → gc_gen = 2 (don't sweep 3 or above).
        let receipts = [(1, old), (1, old), (2, old), (3, recent), (4, old)];
        assert_eq!(gc_gen_from_receipts(&receipts, now), 2);

        // nothing aged → 0 (sweep nothing).
        assert_eq!(gc_gen_from_receipts(&[(1, recent), (2, recent)], now), 0);

        // all aged → the highest generation.
        assert_eq!(
            gc_gen_from_receipts(&[(1, old), (2, old), (3, old)], now),
            3
        );

        // a recent receipt at gen 1 blocks everything, even if gen 2 is old (can't sweep past a
        // not-yet-aged lower generation).
        assert_eq!(gc_gen_from_receipts(&[(1, recent), (2, old)], now), 0);

        // empty → 0.
        assert_eq!(gc_gen_from_receipts(&[], now), 0);
    }

    #[test]
    fn put_epoch_is_the_max_receipt() {
        let r = |p| Receipt::unsigned(1, p);
        let receipts = [([1; 32], r(3)), ([2; 32], r(7)), ([3; 32], r(5))];
        assert_eq!(put_epoch_from_receipts(&receipts), 7);
        assert_eq!(put_epoch_from_receipts(&[]), 0);
    }

    #[test]
    fn receipt_log_merges_round_trips_and_drives_gc_gen() {
        let now = 1_000_000u64;
        let old = now - GC_GRACE_WINDOW_SECS - 100;
        let mut log = BTreeMap::new();

        // first sync at `old`: two objects at gen 1, one at gen 2.
        let first = [
            ([1u8; 32], Receipt::unsigned(1, 5)),
            ([2u8; 32], Receipt::unsigned(1, 5)),
            ([3u8; 32], Receipt::unsigned(2, 6)),
        ];
        merge_receipts(&mut log, &first, old);
        assert_eq!(log.len(), 3);
        assert_eq!(log[&[1u8; 32]].first_local_time, old);

        // a later sync re-pushes object 1 (idempotent) at a newer epoch: age is preserved, epoch rises.
        merge_receipts(&mut log, &[([1u8; 32], Receipt::unsigned(1, 9))], now);
        assert_eq!(
            log[&[1u8; 32]].first_local_time, old,
            "age not reset on re-push"
        );
        assert_eq!(log[&[1u8; 32]].put_epoch, 9, "epoch advanced");
        assert_eq!(put_epoch_from_log(&log), 9);

        // text round-trips exactly, and a garbage line is skipped.
        let text = serialize_receipt_log(&log);
        assert_eq!(parse_receipt_log(&text), log);
        let mixed = format!("{text}garbage line here\nzz 1 2 3\n");
        assert_eq!(parse_receipt_log(&mixed), log);

        // both gens aged past the window → gc_gen = 2.
        assert_eq!(gc_gen_from_log(&log, now), 2);
        // a recent receipt at gen 2 would block sweeping it.
        merge_receipts(&mut log, &[([4u8; 32], Receipt::unsigned(2, 9))], now);
        assert_eq!(
            gc_gen_from_log(&log, now),
            1,
            "recent gen-2 arrival shields gen 2"
        );
    }
}
