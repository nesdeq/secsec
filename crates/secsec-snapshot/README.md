# secsec-snapshot

The object graph and directory snapshot and restore (`secsec-Design.md` §6, §9.2, §10).

A snapshot is a `Commit` pointing at a root `Tree`; trees list files (chunk-id lists) and subtrees,
content-addressed through `secsec-object`. `snapshot_tree` walks a directory, chunks files with the
keyed chunker, pads and seals every chunk and tree into a `Store`, and returns the root;
`seal_signed_commit` wraps the root in an SSHSIG-signed `Commit` (commits are always signed, §9.6).
On the read side every object is opened with the full §9.2 three-way verification.

**Per-path salts (§9.2, §9.7).** Each file's chunks and each subtree are addressed with a 16-byte
`path_salt`; a tree stores each child's salt and the commit stores the root's. A path's salt is
generated once and reused from the prior tree, so an unchanged file keeps identical chunk ids across
versions (and across rotations). On first contact the head's tree seeds the salts, so identical files
get identical ids on every device.

**What a snapshot tracks (§6).** Regular files and directories whose names are safe tree entry names;
symlinks, special files, unsafe names, and `.secsec-tmp-*` restore temps are skipped. A file needing
more chunk ids than the §19 cap, or a file or directory that cannot be read, is reported in `skipped`
and keeps its previous entry, since an omitted name reads as a deletion everywhere else; an entry
this OS cannot create rides forward unchanged. A directory past the fan-out or object cap is an error.

**How restore reconciles (§10).** `restore_tree_into` reconciles the folder to a tree against this
device's own snapshot of it: it deletes only entries that snapshot tracked and that are unchanged
since (size and nanosecond mtime), keeps everything it never tracked (a lone macOS `Icon\r` goes only
with a folder deleted or replaced upstream), leaves a file whose content upstream left alone as it is,
and writes an incoming version beside a local edit as a keep-both copy. Files are written through a
fsynced same-directory temp and renamed into place; a symlink in the way is unlinked, never followed;
setuid, setgid, and sticky bits are dropped; a file never exceeds its declared size. `restore_path` is
the explicit `secsec restore`: it overwrites one path, confined to the destination root.

## Public API

- Snapshot: `snapshot_tree(dir, keys, store, prior, memo) -> Snapshot` (`root`, `salt`, `skipped`),
  `Prior` (the prior tree and whether its size and mtime fast path applies), `SnapshotMemo` (paths
  already found oversized), `is_materializable(name)`, `TMP_PREFIX`.
- Commits: `seal_signed_commit`, `open_signed_commit`, `verified_commit`, `verify_commit` (the signer
  must be the named author); `sign_commit` is crate-internal, so sealing always signs.
- Trees: `load_tree`, `seal_tree` (the same §19 bounds as a snapshot), `verified_tree`,
  `verify_chunk`, `tree_closure` (the ids under a tree, skipping known subtrees).
- Restore: `restore_tree_into(target, ours, keys, store, dest, label) -> RestoreReport`
  (`conflicts`, `skipped`), `restore_commit_tree` (labels keep-both copies by the commit's author and
  id), `restore_path`.
- History: `resolve_path` / `PathNode`, `path_chunks` (the chunks one path needs, skip-missing),
  `changed_paths` (files whose content differs between two trees), `reachable_objects` (strict on the
  head's own tree, skip-missing on pruned ancestors), `hex12`.
- `Commit`, `Tree`, `Entry`, `SnapError`.

Every reader is generic over `MasterKeys` (cross-generation reads, §8.2).
