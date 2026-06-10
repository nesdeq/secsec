# secsec-sync

The sync plane (`secsec-Design.md` §10): the per-ref **Head**, the commit DAG, the per-path three-way
merge, and the rollback-aware merge gates + fork detection. Pure and **storage-free** — it operates
on an in-memory `Node` tree, so all of §10's logic is exhaustively testable without a store.

The **Head** is the per-ref, mutable, **signed + encrypted** pointer at `/refs/<H>`:

- **signed** under `NS_HEAD` over `ref ‖ commit_id ‖ head_version ‖ roster_seq ‖ prev_head` (§9.6) —
  authenticity, verified against the RFP-anchored roster (§8);
- **encrypted** with the §9.8 mutable-object AEAD (fresh nonce per write) under `head_key_g`,
  AD = `FRAME ‖ H` — confidentiality of the ref→commit linkage and the counters;
- stored at `/refs/<H>`, `H = BLAKE3::keyed_hash(ref_name_key, ref_name)` — the server never sees the
  ref name.

The head is **mutable**, so it uses the fresh-nonce §9.8 construction, not the content-addressed
`nonce=0` AEAD of §9.4. Rollback/replay of an old head is caught by the per-ref `head_version`
frontier and HWM checks (§8.5, [`rollback`]).

## Public API

- Head: `build_head`, `sign_head` / `verify_head`, `seal_head` / `open_head`, `head_id`,
  `is_head_successor`, `ref_hash`, `random_nonce`, `Head`, `HEAD_*`/`MAX_REF_NAME` constants.
- Frontier seal (§8.5): `seal_frontier` / `open_frontier`.
- `dag` — `ancestors`, `is_ancestor`, `incomparable`, `common_ancestors`, `lowest_common_ancestors`,
  `CommitMeta`.
- `merge` — `three_way_merge`, `Node`, `Merge`, `Conflict`, `ConflictKind`.
- `rollback` — `evaluate_merge` (the roster_seq / version / `head_version` HWM gates), `observe`,
  `fork_check`, `MergeDecision`, `MergeReject`, `ForkStatus`.

The storage bridge that materializes `Node`s and re-seals the merge lives in `secsec-engine`.
