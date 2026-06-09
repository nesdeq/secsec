//! `secsec-engine` — sync orchestration (`finaldesign.md` §10).
//!
//! This crate is the bridge between the stored object graph ([`secsec_snapshot`]) and the pure,
//! storage-free three-way merge ([`secsec_sync::merge`]). The merge operates on an in-memory
//! [`Node`] tree; the engine materializes a stored tree into `Node`s ([`load_nodes`]), runs the
//! merge, and re-seals the result back into the store ([`seal_nodes`]) — preserving each file's
//! chunk list and `path_salt` (so chunk ids still re-verify, §9.2) and each subdir's advisory mode.
//!
//! [`reconcile`] ties them together: given the three commit trees (common ancestor `base`, `ours`,
//! `theirs`), it produces a single merged tree in the store and the conflict list, with no silent
//! data loss (divergent files are kept-both, §10). The rollback **gates** that decide *whether* to
//! merge at all (roster_seq / version / head_version frontiers) live in [`secsec_sync::rollback`]
//! and are applied by the caller before invoking this.

#![forbid(unsafe_code)]

use secsec_kdf::MasterKey;
use secsec_object::Id;
use secsec_snapshot::{Entry, SnapError, Tree};
use secsec_store::Store;
use secsec_sync::merge::{three_way_merge, Conflict, Node};
use std::collections::BTreeMap;

/// Maximum directory nesting the engine will materialize, matching the snapshot producer's cap
/// (`secsec_frame::MAX_TREE_DEPTH`). Trees are content-addressed (acyclic by construction); this
/// bounds stack depth against a maliciously deep chain from an untrusted store.
const MAX_TREE_DEPTH: usize = secsec_frame::MAX_TREE_DEPTH;

/// A 16-byte per-path salt (§9.2).
pub type PathSalt = [u8; 16];

/// Errors from the sync engine.
#[derive(Debug)]
pub enum EngineError {
    /// Underlying snapshot/object/store error.
    Snap(SnapError),
    /// Directory nesting exceeded [`MAX_TREE_DEPTH`].
    DepthExceeded,
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EngineError::Snap(e) => write!(f, "snapshot: {e}"),
            EngineError::DepthExceeded => f.write_str("tree nesting too deep"),
        }
    }
}
impl std::error::Error for EngineError {}
impl From<SnapError> for EngineError {
    fn from(e: SnapError) -> Self {
        EngineError::Snap(e)
    }
}

/// Materialize the stored tree `(tree_id, tree_salt)` into an in-memory [`Node`] map (the merge
/// model), recursing into subtrees. Each level is fetched, opened (content address re-verified,
/// §9.2), and decoded by [`secsec_snapshot::load_tree`]. A missing object surfaces as
/// [`SnapError::Missing`]; the engine adds only the depth bound.
pub fn load_nodes(
    tree_id: &Id,
    tree_salt: &PathSalt,
    mk: &MasterKey,
    store: &Store,
) -> Result<BTreeMap<String, Node>, EngineError> {
    load_nodes_inner(tree_id, tree_salt, mk, store, 0)
}

fn load_nodes_inner(
    tree_id: &Id,
    tree_salt: &PathSalt,
    mk: &MasterKey,
    store: &Store,
    depth: usize,
) -> Result<BTreeMap<String, Node>, EngineError> {
    if depth > MAX_TREE_DEPTH {
        return Err(EngineError::DepthExceeded);
    }
    let tree = secsec_snapshot::load_tree(tree_id, tree_salt, mk, store)?;
    let mut out = BTreeMap::new();
    for entry in tree.entries {
        match entry {
            Entry::File {
                name,
                mode,
                mtime,
                size,
                path_salt,
                chunks,
            } => {
                out.insert(
                    name,
                    Node::File {
                        mode,
                        mtime,
                        size,
                        path_salt,
                        chunks,
                    },
                );
            }
            Entry::Dir {
                name,
                mode,
                mtime,
                subtree,
                subtree_salt,
            } => {
                let children = load_nodes_inner(&subtree, &subtree_salt, mk, store, depth + 1)?;
                out.insert(
                    name,
                    Node::Dir {
                        mode,
                        mtime,
                        children,
                    },
                );
            }
        }
    }
    Ok(out)
}

/// Seal an in-memory [`Node`] map back into the store as a tree object, recursing into subdirs
/// (children sealed first so each `Entry::Dir` records its subtree's id+salt). Files reuse their
/// existing `chunks` and `path_salt` (the chunks already live in the store from one of the merge
/// sides; nothing is re-chunked), so the produced tree restores byte-identically. Returns the root
/// tree's `(id, salt)`.
pub fn seal_nodes(
    nodes: &BTreeMap<String, Node>,
    mk: &MasterKey,
    store: &Store,
) -> Result<(Id, PathSalt), EngineError> {
    // BTreeMap iteration is name-sorted, matching the canonical snapshot tree order.
    let mut entries: Vec<Entry> = Vec::with_capacity(nodes.len());
    for (name, node) in nodes {
        match node {
            Node::File {
                mode,
                mtime,
                size,
                path_salt,
                chunks,
            } => entries.push(Entry::File {
                name: name.clone(),
                mode: *mode,
                mtime: *mtime,
                size: *size,
                path_salt: *path_salt,
                chunks: chunks.clone(),
            }),
            Node::Dir {
                mode,
                mtime,
                children,
            } => {
                let (subtree, subtree_salt) = seal_nodes(children, mk, store)?;
                entries.push(Entry::Dir {
                    name: name.clone(),
                    mode: *mode,
                    mtime: *mtime,
                    subtree,
                    subtree_salt,
                });
            }
        }
    }
    Ok(secsec_snapshot::seal_tree(&Tree { entries }, mk, store)?)
}

/// The outcome of [`reconcile`]: the merged tree's address in the store, and the conflicts that were
/// resolved keep-both (empty for a clean merge).
#[derive(Debug, Clone)]
pub struct Reconciled {
    /// Merged root tree content id.
    pub root_tree: Id,
    /// Merged root tree path salt.
    pub root_salt: PathSalt,
    /// Keep-both conflicts, in path order.
    pub conflicts: Vec<Conflict>,
}

/// Three-way reconcile of two divergent commit trees against their common ancestor, materializing the
/// merged tree into `store`. `base`/`ours`/`theirs` are `(root_tree_id, root_salt)` of the merge-base
/// commit and the two heads; `their_label` is the keep-both suffix for the incoming side
/// (`<device>-<commit_id_hex12>`, §10). The chunks of both sides must already be present in `store`.
pub fn reconcile(
    base: (&Id, &PathSalt),
    ours: (&Id, &PathSalt),
    theirs: (&Id, &PathSalt),
    their_label: &str,
    mk: &MasterKey,
    store: &Store,
) -> Result<Reconciled, EngineError> {
    let b = load_nodes(base.0, base.1, mk, store)?;
    let o = load_nodes(ours.0, ours.1, mk, store)?;
    let t = load_nodes(theirs.0, theirs.1, mk, store)?;
    let merged = three_way_merge(&b, &o, &t, their_label);
    let (root_tree, root_salt) = seal_nodes(&merged.tree, mk, store)?;
    Ok(Reconciled {
        root_tree,
        root_salt,
        conflicts: merged.conflicts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> MasterKey {
        MasterKey::new(1, [0x77; 32])
    }

    fn read_tree(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        fn walk(dir: &std::path::Path, prefix: &str, out: &mut Vec<(String, Vec<u8>)>) {
            let mut names: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap())
                .collect();
            names.sort_by_key(std::fs::DirEntry::file_name);
            for e in names {
                let name = e.file_name().to_str().unwrap().to_owned();
                let path = e.path();
                let rel = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                if path.is_dir() {
                    walk(&path, &rel, out);
                } else {
                    out.push((rel, std::fs::read(&path).unwrap()));
                }
            }
        }
        walk(root, "", &mut out);
        out
    }

    #[test]
    fn node_tree_round_trips_through_store() {
        let dir = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let m = mk();

        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b.bin"), [3u8; 9000]).unwrap();

        let (root_tree, root_salt) =
            secsec_snapshot::snapshot_tree(src.path(), &m, &store, None).unwrap();
        // load to the merge model, re-seal it unchanged, restore — must be byte-identical.
        let nodes = load_nodes(&root_tree, &root_salt, &m, &store).unwrap();
        let (id2, salt2) = seal_nodes(&nodes, &m, &store).unwrap();
        secsec_snapshot::restore_tree_into(&id2, &salt2, &m, &store, dst.path()).unwrap();

        assert_eq!(read_tree(src.path()), read_tree(dst.path()));
    }

    #[test]
    fn reconcile_merges_divergent_trees_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let m = mk();

        // base: {keep, shared}; ours adds "ours-only" + edits "shared"; theirs edits "shared"
        // differently (a real conflict) and edits "keep" (one-sided, taken).
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("keep"), b"k0").unwrap();
        std::fs::write(base.path().join("shared"), b"s0").unwrap();

        let ours = tempfile::tempdir().unwrap();
        std::fs::write(ours.path().join("keep"), b"k0").unwrap();
        std::fs::write(ours.path().join("shared"), b"sOURS").unwrap();
        std::fs::write(ours.path().join("ours-only"), b"new").unwrap();

        let theirs = tempfile::tempdir().unwrap();
        std::fs::write(theirs.path().join("keep"), b"kEDIT").unwrap();
        std::fs::write(theirs.path().join("shared"), b"sTHEIRS").unwrap();

        // base is the common ancestor; ours and theirs each descend from it, so unchanged paths reuse
        // base's salts (§9.7) and the merge can recognize them as unchanged (real sync topology).
        let b = secsec_snapshot::snapshot_tree(base.path(), &m, &store, None).unwrap();
        let o =
            secsec_snapshot::snapshot_tree(ours.path(), &m, &store, Some((&b.0, &b.1))).unwrap();
        let t =
            secsec_snapshot::snapshot_tree(theirs.path(), &m, &store, Some((&b.0, &b.1))).unwrap();

        let r = reconcile(
            (&b.0, &b.1),
            (&o.0, &o.1),
            (&t.0, &t.1),
            "devB-abc123",
            &m,
            &store,
        )
        .unwrap();

        // exactly one conflict: "shared".
        assert_eq!(r.conflicts.len(), 1);
        assert_eq!(r.conflicts[0].path, "shared");

        // materialize and check the on-disk reconciled tree.
        let out = tempfile::tempdir().unwrap();
        secsec_snapshot::restore_tree_into(&r.root_tree, &r.root_salt, &m, &store, out.path())
            .unwrap();
        let files: BTreeMap<String, Vec<u8>> = read_tree(out.path()).into_iter().collect();

        assert_eq!(files.get("keep").unwrap(), b"kEDIT"); // one-sided edit taken
        assert_eq!(files.get("ours-only").unwrap(), b"new"); // one-sided add taken
        assert_eq!(files.get("shared").unwrap(), b"sOURS"); // ours keeps the name
        assert_eq!(
            files.get("shared.conflict-devB-abc123").unwrap(),
            b"sTHEIRS"
        ); // theirs kept-both
        assert_eq!(files.len(), 4, "no data lost, nothing extra");
    }
}
