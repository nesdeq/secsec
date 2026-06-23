//! `secsec-engine` — the bridge between the stored object graph ([`secsec_snapshot`]) and the pure
//! three-way merge ([`secsec_sync::merge`]), `secsec-Design.md` §10: materialize stored trees into
//! [`Node`]s, merge, re-seal the result (chunk lists + salts preserved so ids re-verify, §9.2), and
//! author the signed merge commit. The rollback gates live in [`secsec_sync::rollback`].

#![forbid(unsafe_code)]

use secsec_kdf::{MasterKey, MasterKeys};
use secsec_object::Id;
use secsec_sig::{DeviceKey, SigError};
use secsec_snapshot::{Commit, Entry, SnapError, Tree};
use secsec_store::Store;
use secsec_sync::dag::{lowest_common_ancestors, ParentMap};
use secsec_sync::merge::{three_way_merge, Conflict, Node};
use secsec_sync::rollback::{
    evaluate_merge, CommitMeta, MergeDecision, MergeReject, SiblingHead, SyncFrontier,
};
use std::collections::BTreeMap;

/// Maximum directory nesting the engine materializes (= the §19 producer cap; bounds stack depth
/// against a maliciously deep chain).
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

/// Materialize the stored tree into an in-memory [`Node`] map, recursing into subtrees (each level
/// §9.2-verified). A missing object surfaces as [`SnapError::Missing`].
pub(crate) fn load_nodes<K: MasterKeys>(
    tree_id: &Id,
    tree_salt: &PathSalt,
    keys: &K,
    store: &Store,
) -> Result<BTreeMap<String, Node>, EngineError> {
    load_nodes_inner(tree_id, tree_salt, keys, store, 0)
}

fn load_nodes_inner<K: MasterKeys>(
    tree_id: &Id,
    tree_salt: &PathSalt,
    keys: &K,
    store: &Store,
    depth: usize,
) -> Result<BTreeMap<String, Node>, EngineError> {
    if depth >= MAX_TREE_DEPTH {
        return Err(EngineError::DepthExceeded);
    }
    let tree = secsec_snapshot::load_tree(tree_id, tree_salt, keys, store)?;
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
                let children = load_nodes_inner(&subtree, &subtree_salt, keys, store, depth + 1)?;
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

/// Seal a [`Node`] map back into the store (children first). Files reuse their `chunks` and
/// `path_salt` — nothing is re-chunked, so the tree restores byte-identically. Returns `(id, salt)`.
pub(crate) fn seal_nodes(
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

/// The outcome of a three-way merge: the merged tree's address in the store, and the conflicts that
/// were resolved keep-both (empty for a clean merge).
#[derive(Debug, Clone)]
pub struct Reconciled {
    /// Merged root tree content id.
    pub root_tree: Id,
    /// Merged root tree path salt.
    pub root_salt: PathSalt,
    /// Keep-both conflicts, in path order.
    pub conflicts: Vec<Conflict>,
}

/// The merge core over already-materialized node maps: three-way merge then re-seal under the current
/// generation.
fn merge_node_maps<K: MasterKeys>(
    base: &BTreeMap<String, Node>,
    ours: &BTreeMap<String, Node>,
    theirs: &BTreeMap<String, Node>,
    their_label: &str,
    keys: &K,
    store: &Store,
) -> Result<Reconciled, EngineError> {
    let merged = three_way_merge(base, ours, theirs, their_label);
    let (root_tree, root_salt) = seal_nodes(&merged.tree, keys.current(), store)?;
    Ok(Reconciled {
        root_tree,
        root_salt,
        conflicts: merged.conflicts,
    })
}

// ---- §10 merge orchestration: DAG load → rollback gates → signed merge commit ----

/// Errors from the merge orchestration.
#[derive(Debug)]
pub enum MergeError {
    /// Store/snapshot/object error.
    Engine(EngineError),
    /// A rollback gate rejected the sibling — a **security event** to alarm on (§10), not a normal
    /// failure: the server presented a head that would roll back the persisted frontier.
    Rollback(MergeReject),
    /// Commit-signing/key error.
    Sig(SigError),
}
impl core::fmt::Display for MergeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MergeError::Engine(e) => write!(f, "{e}"),
            MergeError::Rollback(r) => write!(f, "rollback rejected: {r:?}"),
            MergeError::Sig(e) => write!(f, "sig: {e}"),
        }
    }
}
impl std::error::Error for MergeError {}
impl From<EngineError> for MergeError {
    fn from(e: EngineError) -> Self {
        MergeError::Engine(e)
    }
}
impl From<SnapError> for MergeError {
    fn from(e: SnapError) -> Self {
        MergeError::Engine(EngineError::Snap(e))
    }
}
impl From<SigError> for MergeError {
    fn from(e: SigError) -> Self {
        MergeError::Sig(e)
    }
}

/// Load the parent-DAG + per-commit gate metadata reachable from `heads` (each commit §9.2-verified
/// from `store`). A missing ancestor errors, so the gates never run on a truncated history.
pub fn load_commit_dag<K: MasterKeys>(
    heads: &[Id],
    keys: &K,
    store: &Store,
) -> Result<(ParentMap, BTreeMap<Id, CommitMeta>), EngineError> {
    let mut parents = ParentMap::new();
    let mut meta: BTreeMap<Id, CommitMeta> = BTreeMap::new();
    let mut work: Vec<Id> = heads.to_vec();
    while let Some(c) = work.pop() {
        if parents.contains_key(&c) {
            continue;
        }
        let (commit, _sig) = secsec_snapshot::open_signed_commit(&c, keys, store)?;
        meta.insert(
            c,
            CommitMeta {
                device_id: commit.device_id,
                version: commit.version,
            },
        );
        for p in &commit.parents {
            if !parents.contains_key(p) {
                work.push(*p);
            }
        }
        parents.insert(c, commit.parents);
    }
    Ok((parents, meta))
}

/// The local device's authorship for a merge commit it produces.
pub struct CommitAuthor<'a> {
    /// Signing key (must be a roster member; becomes the commit's `device_id`).
    pub device: &'a DeviceKey,
    /// This device's next strictly-increasing commit `version` (§8.5/§10).
    pub version: u64,
    /// The roster sequence the merge is performed under.
    pub roster_seq: u64,
    /// Advisory author timestamp.
    pub ts: u64,
}

/// What [`merge_heads`] decided to do with the sibling.
#[derive(Debug, Clone)]
pub enum SyncAction {
    /// The sibling is already in our history — nothing to do.
    AlreadyHave,
    /// Our head is an ancestor of the sibling — adopt the sibling commit as the new head (no new
    /// commit is authored; the caller advances its ref to `commit_id`).
    FastForward {
        /// The sibling commit to fast-forward to.
        commit_id: Id,
    },
    /// A real three-way merge produced a new signed merge commit (two parents).
    Merged {
        /// The new merge commit id (already sealed+signed in the store).
        commit_id: Id,
        /// Keep-both conflicts resolved during the merge (empty for a clean merge).
        conflicts: Vec<Conflict>,
    },
}

/// The outcome of [`merge_heads`]: the action plus the advanced frontier. Per §8.5 the caller MUST
/// seal `frontier` locally **before** writing the new head/commit to any remote.
#[derive(Debug, Clone)]
pub struct SyncPlan {
    /// What to do with the ref.
    pub action: SyncAction,
    /// The frontier after observing the sibling (monotonic; seal before writing, §8.5).
    pub frontier: SyncFrontier,
}

/// First 6 bytes of an id as 12 lowercase hex chars (the keep-both label component, §10).
fn hex12(b: &[u8; 32]) -> String {
    b[..6].iter().map(|x| format!("{x:02x}")).collect()
}

/// Drive the §10 rollback-aware merge of one sibling head: load the DAG, run the gates (rejection =
/// [`MergeError::Rollback`], an alarm), and on Merge reconcile against the lowest common ancestor
/// and author a signed merge commit. Precondition: the caller signature-verified the sibling head and
/// its tip commit against the roster (§9.6); ancestor commits are authenticated transitively by the
/// member-signed head plus content-addressing (§9.2).
pub fn merge_heads<K: MasterKeys>(
    frontier: &SyncFrontier,
    our_head_commit: &Id,
    sibling: &SiblingHead,
    author: CommitAuthor<'_>,
    keys: &K,
    store: &Store,
) -> Result<SyncPlan, MergeError> {
    let (parents, meta) = load_commit_dag(&[*our_head_commit, sibling.commit_id], keys, store)?;
    let local_device = author.device.device_id()?;
    let decision = evaluate_merge(
        frontier,
        our_head_commit,
        sibling,
        &local_device,
        &parents,
        &meta,
    )
    .map_err(MergeError::Rollback)?;

    // The frontier advances by observing the sibling regardless of fast-forward vs merge (§10/§8.5).
    let mut new_frontier = frontier.clone();
    new_frontier.observe(sibling, &parents, &meta);

    let action = match decision {
        MergeDecision::AlreadyHave => SyncAction::AlreadyHave,
        MergeDecision::FastForward => SyncAction::FastForward {
            commit_id: sibling.commit_id,
        },
        MergeDecision::Merge => {
            // Materialize ours and theirs; base is the LCA's tree, or empty for disjoint histories.
            // On a criss-cross (several LCAs) any single base is safe — keep-both never loses data.
            let lcas = lowest_common_ancestors(&parents, our_head_commit, &sibling.commit_id);
            let base_map = match lcas.iter().next() {
                Some(base_id) => {
                    let (bc, _) = secsec_snapshot::open_signed_commit(base_id, keys, store)?;
                    // The LCA commit is kept (I4), but its tree content may be pruned beyond retention;
                    // an empty ancestor still merges correctly (keep-both on divergence, no data loss).
                    match load_nodes(&bc.root_tree, &bc.root_salt, keys, store) {
                        Ok(nodes) => nodes,
                        Err(EngineError::Snap(SnapError::Missing(_))) => BTreeMap::new(),
                        Err(e) => return Err(e.into()),
                    }
                }
                None => BTreeMap::new(),
            };
            let (oc, _) = secsec_snapshot::open_signed_commit(our_head_commit, keys, store)?;
            let (tc, _) = secsec_snapshot::open_signed_commit(&sibling.commit_id, keys, store)?;
            let ours_map = load_nodes(&oc.root_tree, &oc.root_salt, keys, store)?;
            let theirs_map = load_nodes(&tc.root_tree, &tc.root_salt, keys, store)?;

            let label = format!(
                "{}-{}",
                hex12(&sibling.device_id),
                hex12(&sibling.commit_id)
            );
            let rec = merge_node_maps(&base_map, &ours_map, &theirs_map, &label, keys, store)?;

            // Author the merge commit: two parents (ours, theirs), our device, our next version, and
            // last_seen_head = the sibling we merged (§10).
            let commit = Commit {
                root_tree: rec.root_tree,
                root_salt: rec.root_salt,
                parents: vec![*our_head_commit, sibling.commit_id],
                device_id: author.device.device_id()?,
                version: author.version,
                roster_seq: author.roster_seq,
                last_seen_head: sibling.commit_id,
                ts: author.ts,
            };
            let commit_id =
                secsec_snapshot::seal_signed_commit(keys.current(), store, author.device, &commit)?;
            SyncAction::Merged {
                commit_id,
                conflicts: rec.conflicts,
            }
        }
    };
    Ok(SyncPlan {
        action,
        frontier: new_frontier,
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

    use secsec_sig::DeviceKey;

    /// Snapshot `dir` (descending from `prev`), then seal a signed commit for it; returns the commit
    /// id and its `(root_tree, salt)`.
    #[allow(clippy::too_many_arguments)]
    fn commit_dir(
        dir: &std::path::Path,
        prev: Option<(&Id, &PathSalt)>,
        device: &DeviceKey,
        version: u64,
        parents: Vec<Id>,
        last_seen: Id,
        mk: &MasterKey,
        store: &Store,
    ) -> (Id, Id, PathSalt) {
        let (rt, rs) = secsec_snapshot::snapshot_tree(dir, mk, store, prev).unwrap();
        let commit = Commit {
            root_tree: rt,
            root_salt: rs,
            parents,
            device_id: device.device_id().unwrap(),
            version,
            roster_seq: 0,
            last_seen_head: last_seen,
            ts: 0,
        };
        let id = secsec_snapshot::seal_signed_commit(mk, store, device, &commit).unwrap();
        (id, rt, rs)
    }

    #[test]
    fn merge_heads_reconciles_divergent_branches_into_signed_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let m = mk();
        let dev_a = DeviceKey::generate().unwrap();
        let dev_b = DeviceKey::generate().unwrap();

        // base (A): {keep:k0, shared:s0}
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("keep"), b"k0").unwrap();
        std::fs::write(base.path().join("shared"), b"s0").unwrap();
        let (base_id, bt, bs) =
            commit_dir(base.path(), None, &dev_a, 1, vec![], [0u8; 32], &m, &store);

        // ours (A): edit shared, add ours-only — descends from base.
        let ours = tempfile::tempdir().unwrap();
        std::fs::write(ours.path().join("keep"), b"k0").unwrap();
        std::fs::write(ours.path().join("shared"), b"sOURS").unwrap();
        std::fs::write(ours.path().join("ours-only"), b"x").unwrap();
        let (ours_id, _, _) = commit_dir(
            ours.path(),
            Some((&bt, &bs)),
            &dev_a,
            2,
            vec![base_id],
            base_id,
            &m,
            &store,
        );

        // theirs (B): edit shared differently (conflict) + edit keep (one-sided) — descends from base.
        let theirs = tempfile::tempdir().unwrap();
        std::fs::write(theirs.path().join("keep"), b"kEDIT").unwrap();
        std::fs::write(theirs.path().join("shared"), b"sTHEIRS").unwrap();
        let (theirs_id, _, _) = commit_dir(
            theirs.path(),
            Some((&bt, &bs)),
            &dev_b,
            1,
            vec![base_id],
            base_id,
            &m,
            &store,
        );

        // A merges B's head.
        let sibling = SiblingHead {
            device_id: dev_b.device_id().unwrap(),
            head_version: 1,
            roster_seq: 0,
            commit_id: theirs_id,
        };
        let author = CommitAuthor {
            device: &dev_a,
            version: 3,
            roster_seq: 0,
            ts: 0,
        };
        let plan = merge_heads(
            &SyncFrontier::default(),
            &ours_id,
            &sibling,
            author,
            &m,
            &store,
        )
        .unwrap();

        let SyncAction::Merged {
            commit_id,
            conflicts,
        } = plan.action
        else {
            panic!("expected a real merge")
        };
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, "shared");

        // the merge commit is A-signed, two parents, version 3, last_seen = theirs.
        let (mc, sig) = secsec_snapshot::open_signed_commit(&commit_id, &m, &store).unwrap();
        secsec_snapshot::verify_commit(&dev_a.public(), &mc, &sig).unwrap();
        assert_eq!(mc.parents, vec![ours_id, theirs_id]);
        assert_eq!(mc.version, 3);
        assert_eq!(mc.last_seen_head, theirs_id);

        // restored merged tree: keep-both + one-sided edits, no data lost.
        let out = tempfile::tempdir().unwrap();
        secsec_snapshot::restore_commit_tree(&mc, &m, &store, out.path()).unwrap();
        let files: BTreeMap<String, Vec<u8>> = read_tree(out.path()).into_iter().collect();
        assert_eq!(files.get("keep").unwrap(), b"kEDIT");
        assert_eq!(files.get("ours-only").unwrap(), b"x");
        assert_eq!(files.get("shared").unwrap(), b"sOURS");
        let ckey = format!(
            "shared.conflict-{}-{}",
            hex12(&dev_b.device_id().unwrap()),
            hex12(&theirs_id)
        );
        assert_eq!(files.get(&ckey).unwrap(), b"sTHEIRS");
        assert_eq!(files.len(), 4);

        // frontier advanced: B's head_version observed.
        assert_eq!(
            plan.frontier
                .head_version_hwm
                .get(&dev_b.device_id().unwrap()),
            Some(&1)
        );
    }

    #[test]
    fn merge_heads_fast_forwards_and_detects_already_have() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let m = mk();
        let dev_a = DeviceKey::generate().unwrap();

        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("f"), b"0").unwrap();
        let (base_id, bt, bs) =
            commit_dir(base.path(), None, &dev_a, 1, vec![], [0u8; 32], &m, &store);

        let next = tempfile::tempdir().unwrap();
        std::fs::write(next.path().join("f"), b"1").unwrap();
        let (next_id, _, _) = commit_dir(
            next.path(),
            Some((&bt, &bs)),
            &dev_a,
            2,
            vec![base_id],
            base_id,
            &m,
            &store,
        );

        let author = || CommitAuthor {
            device: &dev_a,
            version: 9,
            roster_seq: 0,
            ts: 0,
        };

        // our head = base; sibling = next (descends from base) → fast-forward.
        let sib_next = SiblingHead {
            device_id: dev_a.device_id().unwrap(),
            head_version: 2,
            roster_seq: 0,
            commit_id: next_id,
        };
        let plan = merge_heads(
            &SyncFrontier::default(),
            &base_id,
            &sib_next,
            author(),
            &m,
            &store,
        )
        .unwrap();
        assert!(matches!(
            plan.action,
            SyncAction::FastForward { commit_id } if commit_id == next_id
        ));

        // our head = next; sibling = base (an ancestor) → already have.
        let sib_base = SiblingHead {
            device_id: dev_a.device_id().unwrap(),
            head_version: 1,
            roster_seq: 0,
            commit_id: base_id,
        };
        let plan = merge_heads(
            &SyncFrontier::default(),
            &next_id,
            &sib_base,
            author(),
            &m,
            &store,
        )
        .unwrap();
        assert!(matches!(plan.action, SyncAction::AlreadyHave));
    }

    #[test]
    fn merge_heads_rejects_roster_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let m = mk();
        let dev_a = DeviceKey::generate().unwrap();
        let dev_b = DeviceKey::generate().unwrap();

        // base, then our commit and a DIVERGENT sibling commit — gate 1 only applies to genuinely new
        // sibling state (a sibling we already hold short-circuits to AlreadyHave, not a rollback).
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("f"), b"0").unwrap();
        let (base_id, bt, bs) =
            commit_dir(base.path(), None, &dev_a, 1, vec![], [0u8; 32], &m, &store);
        let ours = tempfile::tempdir().unwrap();
        std::fs::write(ours.path().join("f"), b"a").unwrap();
        let (ours_id, _, _) = commit_dir(
            ours.path(),
            Some((&bt, &bs)),
            &dev_a,
            2,
            vec![base_id],
            base_id,
            &m,
            &store,
        );
        let theirs = tempfile::tempdir().unwrap();
        std::fs::write(theirs.path().join("f"), b"b").unwrap();
        let (theirs_id, _, _) = commit_dir(
            theirs.path(),
            Some((&bt, &bs)),
            &dev_b,
            1,
            vec![base_id],
            base_id,
            &m,
            &store,
        );

        // frontier roster_seq=5; the divergent sibling presents roster_seq=4 → gate 1 alarm.
        let frontier = SyncFrontier {
            roster_seq: 5,
            ..Default::default()
        };
        let sibling = SiblingHead {
            device_id: dev_b.device_id().unwrap(),
            head_version: 1,
            roster_seq: 4,
            commit_id: theirs_id,
        };
        let author = CommitAuthor {
            device: &dev_a,
            version: 3,
            roster_seq: 4,
            ts: 0,
        };
        let err = merge_heads(&frontier, &ours_id, &sibling, author, &m, &store).unwrap_err();
        assert!(matches!(
            err,
            MergeError::Rollback(MergeReject::RosterRollback {
                sibling: 4,
                frontier: 5
            })
        ));
    }
}
