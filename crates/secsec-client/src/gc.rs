//! Client-driven garbage collection (`finaldesign.md` §15). The client is the sole GC driver: it
//! computes the **keep-set** (the reachable object closure over the rostered heads), picks a safe
//! **`gc_gen`** from its own signed arrival receipts (never a server-asserted counter), binds its view
//! of the server's mutable state (`all_heads_hash`/`roster_seq`/`put_epoch`), and sends the sweep — a
//! compare-and-swap the server can only execute if nothing changed since (§15).
//!
//! Retention is **keep-everything** by default; a `gc` is explicit and opt-in. GC **fails safe**: if
//! any object in the keep-set traversal is unavailable, [`secsec_snapshot::reachable_objects`] errors
//! and no sweep is issued.

use crate::{fetch_head, ClientError, GcOutcome, Receipt, Remote};
use secsec_kdf::MasterKey;
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

/// Run a §15 GC sweep against `remote`. `ref_names` are the refs whose heads anchor the keep-set
/// (their reachable closures are kept); `gc_gen` is the client-chosen generation (see
/// [`gc_gen_from_receipts`]); `roster_seq`/`put_epoch` are the client's current view (bound into the
/// CAS). Fetches each head, builds the keep-set from the local store (**fail-safe** on a missing
/// object), computes `all_heads_hash` from the fetched head blobs, and issues the sweep. Returns the
/// [`GcOutcome`] ([`GcOutcome::CasConflict`] if the server's state moved — re-read and retry).
pub async fn gc_collect<R: Remote>(
    remote: &R,
    store: &Store,
    mk: &MasterKey,
    ref_names: &[&str],
    gc_gen: u64,
    roster_seq: u64,
    put_epoch: u64,
) -> Result<GcOutcome, ClientError> {
    let rnk = mk.ref_name_key();
    let mut head_commits: Vec<Id> = Vec::new();
    let mut heads: Vec<(Id, [u8; 32])> = Vec::new();

    for name in ref_names {
        let ref_h = ref_hash(&rnk, name);
        // Fetch the raw head blob (for the all_heads_hash token) and open it (for its commit).
        if let Some((head, _sig, blob)) = fetch_head(remote, mk, name).await? {
            head_commits.push(head.commit_id);
            heads.push((ref_h, *blake3::hash(&blob).as_bytes()));
        }
    }

    // Keep-set = reachable closure over all rostered heads (fail-safe on a missing object, §15).
    let keep = reachable_objects(mk, store, &head_commits)?;
    let keep_vec: Vec<Id> = keep.into_iter().collect();
    let ahh = all_heads_hash(&heads);

    Ok(remote
        .gc(keep_vec, gc_gen, &ahh, roster_seq, put_epoch)
        .await?)
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
        let r = |p| Receipt {
            arrival_gen: 1,
            put_epoch: p,
        };
        let receipts = [([1; 32], r(3)), ([2; 32], r(7)), ([3; 32], r(5))];
        assert_eq!(put_epoch_from_receipts(&receipts), 7);
        assert_eq!(put_epoch_from_receipts(&[]), 0);
    }
}
