# secsec-engine

Sync orchestration — the bridge between stored objects and the pure merge (`secsec-Design.md` §10).

`secsec-sync::merge` operates on an in-memory `Node` tree; this crate materializes a stored tree into
`Node`s (`load_nodes`), runs the three-way merge, and re-seals the result back into the store
(`seal_nodes`) — preserving each file's chunk list and `path_salt` (so chunk ids still re-verify,
§9.2) and each subdir's advisory mode. Keeping the merge logic storage-free in `secsec-sync` and the
store-touching bridge here keeps each side small and separately testable.

`reconcile` ties them together: given the three commit trees (common ancestor `base`, `ours`,
`theirs`), it produces a single merged tree in the store and the conflict list, with no silent data
loss (divergent files are kept-both, §10). The rollback **gates** that decide *whether* to merge at
all (the roster_seq / version / `head_version` frontiers) live in `secsec-sync::rollback` and are
applied by the caller before invoking this.

## Public API

- `reconcile(base, ours, theirs, …) -> Reconciled` — three-way merge over stored trees → merged tree
  id + conflicts.
- `merge_heads(...) -> SyncPlan` — the rollback-gated merge decision + the authored two-parent merge
  commit (`SyncAction`: `Merged` / `AlreadyHave` / `FastForward`).
- `load_nodes` / `seal_nodes` — materialize / re-seal the `Node` tree.
- `load_commit_dag` — load a commit DAG's parents + metadata for the ancestry checks.
- `CommitAuthor`, `Reconciled`, `SyncPlan`, `EngineError`, `MergeError`, `PathSalt`.

All readers are generic over `MasterKeys` (cross-generation reads, §8.2).
