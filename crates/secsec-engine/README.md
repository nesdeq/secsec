# secsec-engine

The bridge between stored objects and the pure merge, plus sibling acceptance (`secsec-Design.md`
§10).

`secsec-sync::merge` works on an in-memory `Node` tree; this crate loads a stored tree into `Node`s,
runs the three-way merge, and re-seals the result into the store, keeping each file's chunk list and
`path_salt` (so chunk ids still re-verify, §9.2) and each directory's salt (so two devices merging the
same states seal the same tree). Keeping the merge storage-free in `secsec-sync` and the
store-touching bridge here keeps each side small and separately testable.

`accept_sibling` decides what a fetched head means: it loads the commit DAG over both heads, treats a
sibling already in our history as a no-op *before* any gate, verifies every commit new to us against
its author among `ever_members` (P3), runs the rollback gates, and returns the advanced frontier.
`merge_accepted` then fast-forwards, or on a genuine divergence merges the trees against the
lowest-id lowest common ancestor (an empty base, flagged `base_missing`, when that tree is gone) and
authors the signed two-parent merge commit, with divergent paths kept both ways.

## Public API

- `accept_sibling(frontier, our_head, sibling, local_device, ever_members, keys, store) -> Accepted`
  (`decision`, `frontier`, `new`, `parents`, `meta`).
- `merge_accepted(accepted, our_head, sibling, author, keys, store) -> SyncAction` (`AlreadyHave` /
  `FastForward` / `Merged { commit_id, conflicts, base_missing }`).
- `merge_heads`: the two in one call, returning a `SyncPlan` (`action`, `frontier`).
- `merge_base`, `load_commit_dag` (parents and gate metadata; a missing commit is an error, since
  commits are never pruned), `verify_commits`.
- `CommitAuthor`, `EngineError`, `MergeError` (`Rollback` is a §10 alarm), `PathSalt`.

The sibling's head signature is established before it reaches here: `SiblingHead::verified` is its
only constructor. (`load_nodes` and `seal_nodes` are crate-internal.) Every reader is generic over
`MasterKeys` (cross-generation reads, §8.2).
