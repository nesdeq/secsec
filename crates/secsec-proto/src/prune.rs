//! Retention-prune hashes binding a `prune` to the server's head/roster state (`secsec-Design.md` §15).

use crate::{op, Id};
use secsec_canon::Writer;

/// `all_heads_hash = BLAKE3(le64(n) ‖ (ref_H ‖ head_blob_hash)…)` over the refs sorted by `(ref_H, blob_hash)`, exact duplicates folded.
#[must_use]
pub fn all_heads_hash(heads: &[(Id, [u8; 32])]) -> [u8; 32] {
    let mut sorted: Vec<(Id, [u8; 32])> = heads.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut w = Writer::new();
    w.u64(sorted.len() as u64);
    for (ref_h, head_blob_hash) in &sorted {
        w.raw(ref_h).raw(head_blob_hash);
    }
    *blake3::hash(&w.finish()).as_bytes()
}

/// `dead_set_hash = BLAKE3(le64(count) ‖ id…)` over the ids sorted ascending and deduplicated.
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

/// `args_hash` for `prune`: `BLAKE3(canonical("prune" ‖ dead_set_hash ‖ all_heads_hash ‖ le64(roster_len)))`.
#[must_use]
pub fn args_prune(
    dead_set_hash: &[u8; 32],
    all_heads_hash: &[u8; 32],
    roster_len: u64,
) -> [u8; 32] {
    let mut w = Writer::new();
    w.bytes(op::PRUNE.as_bytes())
        .raw(dead_set_hash)
        .raw(all_heads_hash)
        .u64(roster_len);
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
        assert_eq!(base, all_heads_hash(&[r2, r1]));
        assert_ne!(base, all_heads_hash(&[([0x10; 32], [0x06; 32]), r2]));
        assert_ne!(base, all_heads_hash(&[r1]));
        assert_eq!(base, all_heads_hash(&[r1, r2, r1]), "exact duplicates fold");
        // Two blobs for one ref hash both count, whatever the input order.
        let r1b = ([0x10; 32], [0x07; 32]);
        assert_eq!(all_heads_hash(&[r1, r1b]), all_heads_hash(&[r1b, r1]));
        assert_ne!(all_heads_hash(&[r1, r1b]), all_heads_hash(&[r1]));
    }

    #[test]
    fn dead_set_hash_is_order_and_dup_invariant() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let base = dead_set_hash(&[a, b, c]);
        assert_eq!(base, dead_set_hash(&[c, a, b]));
        assert_eq!(base, dead_set_hash(&[a, b, c, a, b]));
        assert_ne!(base, dead_set_hash(&[a, b]));
        assert_ne!(base, dead_set_hash(&[]));
    }

    /// Every field is bound, and an empty roster (0) never equals a one-entry roster (1).
    #[test]
    fn args_prune_binds_every_field() {
        let dsh = dead_set_hash(&[[1; 32], [2; 32]]);
        let ahh = all_heads_hash(&[([3; 32], [1; 32])]);
        let base = args_prune(&dsh, &ahh, 4);
        assert_eq!(base, args_prune(&dsh, &ahh, 4));
        assert_ne!(base, args_prune(&dsh, &ahh, 5));
        assert_ne!(base, args_prune(&[0; 32], &ahh, 4));
        assert_ne!(base, args_prune(&dsh, &[0; 32], 4));
        assert_ne!(args_prune(&dsh, &ahh, 0), args_prune(&dsh, &ahh, 1));
    }
}
