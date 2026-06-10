# secsec-snapshot

The object graph and directory snapshot/restore (`secsec-Design.md` §6, §9.2).

A snapshot is a `Commit` pointing at a root `Tree`; trees list files (chunk-id lists) and subtrees,
content-addressed via [`secsec_object`]. `snapshot_tree` walks a directory, chunks files with keyed
FastCDC, and seals every chunk/tree into a `Store`; `seal_signed_commit` wraps the root tree in an
SSHSIG-signed `Commit` (commits are **always** signed, §9.6). On the read side `open_signed_commit`
fetches+verifies a commit and `restore_commit_tree` walks the tree back — `get`ting each object,
opening it with the full §9.2 three-way verification, un-padding, and rebuilding the directory
byte-for-byte.

**Per-path salts (§9.2/§9.7).** Each file's chunks and each subtree are addressed with a 16-byte
`path_salt`; a tree stores the salt of each child and the commit stores the root tree's salt, so the
id re-verification on restore is meaningful. A path's salt is generated once (first sync) and is
**constant across all versions** (§9.7) — `snapshot_tree` reuses each path's salt from the prior
tree, so an unchanged file re-chunks to identical ids. That stability is a correctness requirement of
the incremental-upload and three-way-merge model, not an optimization.

## Public API

- `snapshot_tree(dir, mk, store, prev)` — incrementally snapshot a directory into the store.
- `seal_signed_commit` / `open_signed_commit` / `sign_commit` / `verify_commit` — the signed `Commit`.
- `restore_commit_tree` / `restore_tree_into` / `load_tree` / `seal_tree` — materialize trees.
- `reachable_objects` — the reachable object closure (the GC keep-set / push closure).
- `Commit`, `Tree`, `Entry`, `MAX_NAME`, `SnapError`.

All tree-reading functions are generic over `MasterKeys` (cross-generation reads, §8.2).
