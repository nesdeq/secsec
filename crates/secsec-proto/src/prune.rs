//! Retention-prune serialization (`secsec-Design.md` §5): the canonical hashes binding a `prune` call
//! to the client's view of the server's mutable head/roster state. Verifying the client's signature
//! over `args_prune` IS a compare-and-swap — a concurrent `cas-head`/`roster-append` moves the value
//! the server recomputes, so the prune is rejected rather than deleting against stale state. Inputs
//! are order-canonicalized here, so two clients naming the same delete-set agree.

use crate::{op, Id};
use secsec_canon::Writer;

/// `all_heads_hash = BLAKE3(le64(n) ‖ (ref_H ‖ head_blob_hash)…)` over all active refs, sorted by
/// `ref_H`. MUST use the blob hash — the server-visible token it can recompute — never the encrypted
/// `head_version`. Duplicate ref hashes fold.
#[must_use]
pub fn all_heads_hash(heads: &[(Id, [u8; 32])]) -> [u8; 32] {
    let mut sorted: Vec<(Id, [u8; 32])> = heads.to_vec();
    sorted.sort_by_key(|p| p.0);
    sorted.dedup_by(|a, b| a.0 == b.0);
    let mut w = Writer::new();
    w.u64(sorted.len() as u64);
    for (ref_h, head_blob_hash) in &sorted {
        w.raw(ref_h).raw(head_blob_hash);
    }
    *blake3::hash(&w.finish()).as_bytes()
}

/// `dead_set_hash = BLAKE3(le64(count) ‖ id[0] ‖ … ‖ id[count-1])` with the ids **deduplicated and
/// sorted** ascending byte-lexicographically. The delete-set is a set, so duplicates fold.
#[must_use]
pub fn dead_set_hash(ids: &[Id]) -> [u8; 32] {
    let mut sorted: Vec<Id> = ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut w = Writer::new();
    w.u64(sorted.len() as u64);
    for id in &sorted {
        w.raw(id);
    }
    *blake3::hash(&w.finish()).as_bytes()
}

/// `args_hash` for `prune` (§5/§12): `BLAKE3(canonical("prune" ‖ dead_set_hash ‖ all_heads_hash ‖
/// roster_seq))`. Binding `all_heads_hash`/`roster_seq` makes `prune` a compare-and-swap against the
/// server's current head/roster state — a concurrent `cas-head`/`roster-append` changes the
/// recomputed message and the prune is rejected, rather than deleting an object a reverted head now
/// references.
#[must_use]
pub fn args_prune(dead_set_hash: &[u8; 32], all_heads_hash: &[u8; 32], roster_seq: u64) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(op::PRUNE.as_bytes())
        .raw(dead_set_hash)
        .raw(all_heads_hash)
        .u64(roster_seq);
    *blake3::hash(&w.finish()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_heads_hash_is_order_invariant_and_binds_blob_hashes() {
        let r1 = ([0x10; 32], [0x05; 32]);
        let r2 = ([0x20; 32], [0x09; 32]);
        let base = all_heads_hash(&[r1, r2]);
        assert_eq!(base, all_heads_hash(&[r2, r1])); // order-invariant
        assert_ne!(base, all_heads_hash(&[([0x10; 32], [0x06; 32]), r2])); // a head-blob change differs
        assert_ne!(base, all_heads_hash(&[r1])); // a missing ref differs
    }

    #[test]
    fn dead_set_hash_is_order_and_dup_invariant() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let base = dead_set_hash(&[a, b, c]);
        assert_eq!(base, dead_set_hash(&[c, a, b])); // order-invariant
        assert_eq!(base, dead_set_hash(&[a, b, c, a, b])); // duplicates fold
        assert_ne!(base, dead_set_hash(&[a, b])); // a different set differs
        assert_ne!(base, dead_set_hash(&[]));
    }

    #[test]
    fn args_prune_binds_every_field() {
        let dsh = dead_set_hash(&[[1; 32], [2; 32]]);
        let ahh = all_heads_hash(&[([3; 32], [1; 32])]);
        let base = args_prune(&dsh, &ahh, 4);
        assert_eq!(base, args_prune(&dsh, &ahh, 4));
        assert_ne!(base, args_prune(&dsh, &ahh, 5)); // roster_seq
        assert_ne!(base, args_prune(&[0; 32], &ahh, 4)); // dead_set_hash
        assert_ne!(base, args_prune(&dsh, &[0; 32], 4)); // all_heads_hash
    }
}
