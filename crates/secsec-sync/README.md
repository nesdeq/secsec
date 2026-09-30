# secsec-sync

The sync plane (`secsec-Design.md` §8.5, §10): the per-ref **Head**, the commit DAG, the per-path
three-way merge, the rollback gates, and the sealed local frontier. Pure and **storage-free**: the
merge works on an in-memory `Node` tree, so all of §10's logic is testable without a store.

The **Head** is the per-ref, mutable, **signed and encrypted** pointer at `/refs/<H>`:

- **signed** under `NS_HEAD` over `ref ‖ commit_id ‖ head_version ‖ roster_seq ‖ prev_head` (§9.6),
  verified against the RFP-anchored roster (§8);
- **encrypted** with the §9.8 fresh-nonce AEAD under the current generation's `head_key_g`, AD
  `FRAME ‖ H`, hiding the ref→commit linkage and the counters; a reader resolves the blob's
  `FRAME.gen` through its key ring;
- stored at `H = BLAKE3::keyed_hash(ref_name_key, ref_name)`, where `ref_name_key` derives from
  generation 1, so the path does not move on rotation and the server never sees the ref name.

Rollback or replay of an old head is caught by the `head_version` high-water per signing device and
the other gates in [`rollback`] (§8.5, §10).

## Public API

- Head: `build_head`, `sign_head` / `verify_head`, `seal_head` / `open_head`, `head_id`, `ref_hash`,
  `random_nonce`, `Head`, `HeadError`, `HEAD_NONCE_LEN`, `NO_PREV_HEAD`, `Id`, `RefHash`.
- `dag`: `is_ancestor`, `new_commits`, `lowest_common_ancestors`, `ParentMap`, `Id`; every traversal
  tolerates cycles.
- `merge`: `three_way_merge` (content by chunk list, modes merged three ways, keep-both copies named
  `name.conflict-<label>.ext` with a `-2`, `-3`, … suffix on a collision, truncated to the name
  bound), `Node`, `Merge`, `Conflict`, `ConflictKind`, `PathSalt`.
- `rollback`: `check_gates` (gate 1 `roster_seq`, gate 2a per-device commit versions with this
  device's own history exempt, gate 2b the signer's `head_version`; a DAG missing metadata fails
  closed), `evaluate_merge` (the ancestor no-op, then the gates, then fast-forward or merge),
  `SyncFrontier` (`observe`, `observe_head`, `with_heads_of` for the pre-push seal), `seal_frontier` /
  `open_frontier` (the §8.5 sealed state), `CommitMeta`, `MergeDecision`, `MergeReject`,
  `FrontierError`.
- `rollback::SiblingHead` is `#[non_exhaustive]`: `SiblingHead::verified(members, head, sig)` is the
  only way to build one, so the gates cannot be reached with a head no member signed.

The storage bridge that loads `Node`s from stored trees and re-seals a merge lives in
`secsec-engine`.
