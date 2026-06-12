//! §15 GC serialization hashes: the canonical encodings binding a `gc` call to the client's view of
//! the server's mutable state (the compare-and-swap). Inputs are order-canonicalized here, so two
//! clients with the same logical set agree.

use crate::{op, Id};
use secsec_canon::Writer;

/// `keep_set_hash = BLAKE3(le64(count) ‖ id[0] ‖ … ‖ id[count-1])` with ids **deduplicated and
/// sorted** ascending byte-lexicographically (§15). The keep-set is a set, so duplicates are folded.
#[must_use]
pub fn keep_set_hash(ids: &[Id]) -> [u8; 32] {
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

/// `all_heads_hash = BLAKE3(le64(n) ‖ (ref_H ‖ head_blob_hash)…)` over all active refs, sorted by
/// `ref_H` (§15). MUST use the blob hash — the server-visible token it can recompute — never the
/// encrypted `head_version`. Duplicate ref hashes fold.
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

/// `args_hash` for `gc` (§12/§15):
/// `BLAKE3(canonical("gc" ‖ keep_set_hash ‖ gc_gen ‖ all_heads_hash ‖ roster_seq ‖ put_epoch))`.
/// Binding `all_heads_hash`/`roster_seq`/`put_epoch` makes `gc` a compare-and-swap against the
/// server's current mutable state — a concurrent `cas-head`/`roster-append`/`put` fails it (§15).
#[must_use]
pub fn args_gc(
    keep_set_hash: &[u8; 32],
    gc_gen: u64,
    all_heads_hash: &[u8; 32],
    roster_seq: u64,
    put_epoch: u64,
) -> [u8; 32] {
    let mut w = Writer::new();
    w.raw(op::GC.as_bytes())
        .raw(keep_set_hash)
        .u64(gc_gen)
        .raw(all_heads_hash)
        .u64(roster_seq)
        .u64(put_epoch);
    *blake3::hash(&w.finish()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn keep_set_hash_is_order_and_dup_invariant() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let base = keep_set_hash(&[a, b, c]);
        // different input order, same set -> same hash.
        assert_eq!(base, keep_set_hash(&[c, a, b]));
        // duplicates folded.
        assert_eq!(base, keep_set_hash(&[a, b, c, a, b]));
        // a different set differs.
        assert_ne!(base, keep_set_hash(&[a, b]));
        assert_ne!(base, keep_set_hash(&[]));
    }

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
    fn args_gc_binds_every_field() {
        let ksh = keep_set_hash(&[[1; 32], [2; 32]]);
        let ahh = all_heads_hash(&[([3; 32], [1; 32])]);
        let base = args_gc(&ksh, 7, &ahh, 4, 100);
        assert_eq!(base, args_gc(&ksh, 7, &ahh, 4, 100));
        assert_ne!(base, args_gc(&ksh, 8, &ahh, 4, 100)); // gc_gen
        assert_ne!(base, args_gc(&ksh, 7, &ahh, 5, 100)); // roster_seq
        assert_ne!(base, args_gc(&ksh, 7, &ahh, 4, 101)); // put_epoch
        assert_ne!(base, args_gc(&[0; 32], 7, &ahh, 4, 100)); // keep_set_hash
        assert_ne!(base, args_gc(&ksh, 7, &[0; 32], 4, 100)); // all_heads_hash
    }

    /// Frozen KAT, mirrored in `vectors/secsec-kat-v1.txt [gc]`.
    #[test]
    fn gc_kat() {
        // keep-set {0x01*32, 0x02*32}; one head (ref=0x03*32, head_blob_hash=0x04*32); gc_gen=2,
        // roster_seq=4, put_epoch=10.
        let ksh = keep_set_hash(&[[1; 32], [2; 32]]);
        let ahh = all_heads_hash(&[([3; 32], [4; 32])]);
        assert_eq!(
            hx(&ksh),
            "836c1e9f709d36a0835175b92cd71f65efdc00110bd0cc60b7dd876dfafdbf80"
        );
        assert_eq!(
            hx(&ahh),
            "46ce83ca882351a884ac0dc037f9befce2d084cf83ff0534cb1c056d3fc55835"
        );
        assert_eq!(
            hx(&args_gc(&ksh, 2, &ahh, 4, 10)),
            "3de0fa63d87bdfb22b9e4df2a4cb5b8d9e636eb966f7f254514645c0eec3690a"
        );
    }
}
