# secsec-engine

Sync orchestration — the bridge between stored objects and the pure merge (`secsec-Design.md` §10).

`secsec-sync::merge` operates on an in-memory `Node` tree; this crate materializes a stored tree into
`Node`s (`load_nodes`), runs the three-way merge, and re-seals the result back into the store
(`seal_nodes`) — preserving each file's chunk list and `path_salt` (so chunk ids still re-verify,
§9.2) and each subdir's advisory mode. Keeping the merge logic storage-free in `secsec-sync` and the
store-touching bridge here keeps each side small and separately testable.

`merge_heads` ties them together: given our head and a sibling head, it loads the commit DAG, runs the
rollback **gates** (the roster_seq / version / `head_version` frontiers in `secsec-sync::rollback`),
and — on a genuine divergence — reconciles the LCA / `ours` / `theirs` trees into a single merged tree
in the store and authors the signed two-parent merge commit, with no silent data loss (divergent files
are kept-both, §10). The tree-level three-way merge over stored nodes is the internal `merge_node_maps`
helper.

## Public API

- `merge_heads(...) -> SyncPlan` — the rollback-gated merge decision + the authored two-parent merge
  commit (`SyncAction`: `Merged` / `AlreadyHave` / `FastForward`).
- `load_commit_dag` — load a commit DAG's parents + metadata for the ancestry checks.
- `CommitAuthor`, `Reconciled`, `SyncPlan`, `SyncAction`, `EngineError`, `MergeError`, `PathSalt`.

(Materializing/re-sealing the `Node` tree — `load_nodes` / `seal_nodes` — is crate-internal.)

All readers are generic over `MasterKeys` (cross-generation reads, §8.2).
