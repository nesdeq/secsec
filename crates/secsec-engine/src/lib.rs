//! Bridge between the stored object graph and the pure three-way merge, plus sibling acceptance (`secsec-Design.md` §10).

#![forbid(unsafe_code)]

use secsec_kdf::{MasterKey, MasterKeys};
use secsec_object::Id;
use secsec_sig::{DeviceId, DeviceKey, DevicePublic, SigError};
use secsec_snapshot::{Commit, Entry, SnapError, Tree};
use secsec_store::Store;
use secsec_sync::dag::{is_ancestor, lowest_common_ancestors, new_commits, ParentMap};
use secsec_sync::merge::{three_way_merge, Conflict, Node};
use secsec_sync::rollback::{
    check_gates, CommitMeta, MergeDecision, MergeReject, SiblingHead, SyncFrontier,
};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum directory nesting materialized (the §19 cap; bounds recursion).
const MAX_TREE_DEPTH: usize = secsec_frame::MAX_TREE_DEPTH;

/// A 16-byte per-path salt (§9.2).
pub type PathSalt = [u8; 16];

/// Errors from the engine.
#[derive(Debug)]
pub enum EngineError {
    /// Snapshot/object/store error.
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

/// Materialize a stored tree into [`Node`]s, each level verified (§9.2).
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
                        salt: subtree_salt,
                        children,
                    },
                );
            }
        }
    }
    Ok(out)
}

/// Seal a [`Node`] map (children first) under `salt`, reusing every file's chunks and every dir's salt.
pub(crate) fn seal_nodes(
    nodes: &BTreeMap<String, Node>,
    salt: &PathSalt,
    mk: &MasterKey,
    store: &Store,
    path: &str,
) -> Result<Id, EngineError> {
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
                salt: sub_salt,
                children,
            } => {
                let sub_path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}/{name}")
                };
                let subtree = seal_nodes(children, sub_salt, mk, store, &sub_path)?;
                entries.push(Entry::Dir {
                    name: name.clone(),
                    mode: *mode,
                    mtime: *mtime,
                    subtree,
                    subtree_salt: *sub_salt,
                });
            }
        }
    }
    Ok(secsec_snapshot::seal_tree(
        &Tree { entries },
        salt,
        mk,
        store,
        path,
    )?)
}

/// Errors from sibling acceptance and merge.
#[derive(Debug)]
pub enum MergeError {
    /// Store/snapshot/object error.
    Engine(EngineError),
    /// A rollback gate rejected the sibling: a §10 security alarm, not a routine failure.
    Rollback(MergeReject),
    /// A new commit names an author who was never a member (P3).
    NotMember(DeviceId),
    /// A new commit's signature did not verify against its author (P3).
    BadCommitSignature(Id),
    /// Commit-signing/key error.
    Sig(SigError),
}
impl core::fmt::Display for MergeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MergeError::Engine(e) => write!(f, "{e}"),
            MergeError::Rollback(r) => write!(f, "rollback rejected: {r:?}"),
            MergeError::NotMember(_) => {
                f.write_str("a fetched commit is authored by a device that was never a member")
            }
            MergeError::BadCommitSignature(_) => {
                f.write_str("a fetched commit's signature is invalid")
            }
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

/// Load the parent DAG and gate metadata reachable from `heads`; a missing commit errors (commits are never pruned, I4).
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
        work.extend(commit.parents.iter().filter(|p| !parents.contains_key(*p)));
        parents.insert(c, commit.parents);
    }
    Ok((parents, meta))
}

/// Verify every commit in `ids` against its author among `ever_members` (P3: members past and present).
pub fn verify_commits<K: MasterKeys>(
    ids: &BTreeSet<Id>,
    ever_members: &BTreeMap<DeviceId, DevicePublic>,
    keys: &K,
    store: &Store,
) -> Result<(), MergeError> {
    for id in ids {
        let (commit, sig) = secsec_snapshot::open_signed_commit(id, keys, store)?;
        let author = ever_members
            .get(&commit.device_id)
            .ok_or(MergeError::NotMember(commit.device_id))?;
        secsec_snapshot::verify_commit(author, &commit, &sig)
            .map_err(|_| MergeError::BadCommitSignature(*id))?;
    }
    Ok(())
}

/// A sibling that passed signature verification and the §10 gates.
#[derive(Debug, Clone)]
pub struct Accepted {
    /// How it relates to our head (`FastForward` for a clone with no head).
    pub decision: MergeDecision,
    /// The advanced frontier (roster/head high-waters, and the new commits' version high-waters).
    pub frontier: SyncFrontier,
    /// The commits new to this device.
    pub new: BTreeSet<Id>,
    /// The DAG covering both histories.
    pub parents: ParentMap,
    /// Gate metadata for the DAG.
    pub meta: BTreeMap<Id, CommitMeta>,
}

/// Verify and gate `sibling` against `our_head` (`None` = clone): new commits are signature-checked before any gate reads them.
pub fn accept_sibling<K: MasterKeys>(
    frontier: &SyncFrontier,
    our_head: Option<&Id>,
    sibling: &SiblingHead,
    local_device: &DeviceId,
    ever_members: &BTreeMap<DeviceId, DevicePublic>,
    keys: &K,
    store: &Store,
) -> Result<Accepted, MergeError> {
    let heads: Vec<Id> = our_head
        .into_iter()
        .copied()
        .chain(std::iter::once(sibling.commit_id))
        .collect();
    let (parents, meta) = load_commit_dag(&heads, keys, store)?;
    // A sibling already in our history is a no-op, never a rollback (checked before the gates, §10).
    if let Some(ours) = our_head {
        if is_ancestor(&parents, &sibling.commit_id, ours) {
            return Ok(Accepted {
                decision: MergeDecision::AlreadyHave,
                frontier: frontier.clone(),
                new: BTreeSet::new(),
                parents,
                meta,
            });
        }
    }
    let new = new_commits(&parents, our_head, &sibling.commit_id);
    verify_commits(&new, ever_members, keys, store)?;
    check_gates(frontier, sibling, local_device, &new, &meta).map_err(MergeError::Rollback)?;
    let decision = match our_head {
        None => MergeDecision::FastForward,
        Some(ours) if is_ancestor(&parents, ours, &sibling.commit_id) => MergeDecision::FastForward,
        Some(_) => MergeDecision::Merge,
    };
    let mut advanced = frontier.clone();
    advanced.observe(sibling, &new, &meta);
    Ok(Accepted {
        decision,
        frontier: advanced,
        new,
        parents,
        meta,
    })
}

/// The local device's authorship for a merge commit.
pub struct CommitAuthor<'a> {
    /// Signing key (a member; becomes the commit's `device_id`).
    pub device: &'a DeviceKey,
    /// This device's next commit `version`.
    pub version: u64,
    /// The roster sequence the merge is written under.
    pub roster_seq: u64,
    /// Advisory timestamp.
    pub ts: u64,
}

/// What [`merge_heads`] decided.
#[derive(Debug, Clone)]
pub enum SyncAction {
    /// The sibling is already in our history.
    AlreadyHave,
    /// Our head is an ancestor of the sibling: adopt `commit_id`.
    FastForward {
        /// The sibling commit.
        commit_id: Id,
    },
    /// A three-way merge produced a new signed two-parent commit.
    Merged {
        /// The merge commit id (sealed + signed in the store).
        commit_id: Id,
        /// Keep-both conflicts.
        conflicts: Vec<Conflict>,
        /// The common ancestor's tree was missing, so the merge ran against an empty base (deletions can resurface).
        base_missing: bool,
    },
}

/// The outcome of [`merge_heads`]: the action and the advanced frontier (seal before publishing, §8.5).
#[derive(Debug, Clone)]
pub struct SyncPlan {
    /// What to do with the ref.
    pub action: SyncAction,
    /// The frontier after observing the sibling.
    pub frontier: SyncFrontier,
}

/// The merge base every device picks for `a` and `b`: the lowest-id lowest common ancestor, `None` for disjoint histories.
#[must_use]
pub fn merge_base(parents: &ParentMap, a: &Id, b: &Id) -> Option<Id> {
    lowest_common_ancestors(parents, a, b).into_iter().next()
}

/// Act on an accepted sibling: adopt it, keep ours, or three-way merge into a signed two-parent commit.
pub fn merge_accepted<K: MasterKeys>(
    accepted: &Accepted,
    our_head_commit: &Id,
    sibling: &SiblingHead,
    author: CommitAuthor<'_>,
    keys: &K,
    store: &Store,
) -> Result<SyncAction, MergeError> {
    match accepted.decision {
        MergeDecision::AlreadyHave => return Ok(SyncAction::AlreadyHave),
        MergeDecision::FastForward => {
            return Ok(SyncAction::FastForward {
                commit_id: sibling.commit_id,
            })
        }
        MergeDecision::Merge => {}
    }
    // A missing base tree merges against an empty base and says so.
    let (base_map, base_missing) =
        match merge_base(&accepted.parents, our_head_commit, &sibling.commit_id) {
            Some(base_id) => {
                let (bc, _) = secsec_snapshot::open_signed_commit(&base_id, keys, store)?;
                match load_nodes(&bc.root_tree, &bc.root_salt, keys, store) {
                    Ok(nodes) => (nodes, false),
                    Err(EngineError::Snap(SnapError::Missing(_))) => (BTreeMap::new(), true),
                    Err(e) => return Err(e.into()),
                }
            }
            None => (BTreeMap::new(), false),
        };
    let (oc, _) = secsec_snapshot::open_signed_commit(our_head_commit, keys, store)?;
    let (tc, _) = secsec_snapshot::open_signed_commit(&sibling.commit_id, keys, store)?;
    let ours_map = load_nodes(&oc.root_tree, &oc.root_salt, keys, store)?;
    let theirs_map = load_nodes(&tc.root_tree, &tc.root_salt, keys, store)?;

    let label = format!(
        "{}-{}",
        secsec_snapshot::hex12(&sibling.device_id),
        secsec_snapshot::hex12(&sibling.commit_id)
    );
    let merged = three_way_merge(&base_map, &ours_map, &theirs_map, &label);
    let root_tree = seal_nodes(&merged.tree, &oc.root_salt, keys.current(), store, "")?;
    let commit = Commit {
        root_tree,
        root_salt: oc.root_salt,
        parents: vec![*our_head_commit, sibling.commit_id],
        device_id: author.device.device_id()?,
        version: author.version,
        roster_seq: author.roster_seq,
        last_seen_head: sibling.commit_id,
        ts: author.ts,
    };
    let commit_id =
        secsec_snapshot::seal_signed_commit(keys.current(), store, author.device, &commit)?;
    Ok(SyncAction::Merged {
        commit_id,
        conflicts: merged.conflicts,
        base_missing,
    })
}

/// [`accept_sibling`] then [`merge_accepted`] in one step.
pub fn merge_heads<K: MasterKeys>(
    frontier: &SyncFrontier,
    our_head_commit: &Id,
    sibling: &SiblingHead,
    ever_members: &BTreeMap<DeviceId, DevicePublic>,
    author: CommitAuthor<'_>,
    keys: &K,
    store: &Store,
) -> Result<SyncPlan, MergeError> {
    let local_device = author.device.device_id()?;
    let accepted = accept_sibling(
        frontier,
        Some(our_head_commit),
        sibling,
        &local_device,
        ever_members,
        keys,
        store,
    )?;
    let action = merge_accepted(&accepted, our_head_commit, sibling, author, keys, store)?;
    Ok(SyncPlan {
        action,
        frontier: accepted.frontier,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secsec_snapshot::{Prior, SnapshotMemo};

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

    fn snap(
        dir: &std::path::Path,
        prev: Option<(&Id, &PathSalt)>,
        store: &Store,
    ) -> (Id, PathSalt) {
        let s = secsec_snapshot::snapshot_tree(
            dir,
            &mk(),
            store,
            prev.map(|(root, salt)| Prior {
                root,
                salt,
                fast_path: true,
            }),
            &mut SnapshotMemo::default(),
        )
        .unwrap();
        (s.root, s.salt)
    }

    /// Load → re-seal unchanged → restore is byte-identical and re-seals to the same root id.
    #[test]
    fn node_tree_round_trips_through_store_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let m = mk();

        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b.bin"), [3u8; 9000]).unwrap();

        let (root_tree, root_salt) = snap(src.path(), None, &store);
        let nodes = load_nodes(&root_tree, &root_salt, &m, &store).unwrap();
        let id2 = seal_nodes(&nodes, &root_salt, &m, &store, "").unwrap();
        assert_eq!(
            id2, root_tree,
            "salts ride along, so a re-seal is deterministic"
        );
        secsec_snapshot::restore_tree_into((&id2, &root_salt), None, &m, &store, dst.path(), "L")
            .unwrap();
        assert_eq!(read_tree(src.path()), read_tree(dst.path()));
    }

    use secsec_sig::DeviceKey;

    fn members(devs: &[&DeviceKey]) -> BTreeMap<DeviceId, DevicePublic> {
        devs.iter()
            .map(|d| (d.device_id().unwrap(), d.public()))
            .collect()
    }

    /// A sibling head genuinely signed by `dev`, built through the verifying constructor.
    fn sibling(dev: &DeviceKey, commit: Id, head_version: u64, roster_seq: u64) -> SiblingHead {
        let mut head = secsec_sync::build_head("main", commit, roster_seq, None).unwrap();
        head.head_version = head_version;
        let sig = secsec_sync::sign_head(dev, &head).unwrap();
        SiblingHead::verified(&members(&[dev]), &head, &sig).expect("signed by a member")
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_dir(
        dir: &std::path::Path,
        prev: Option<(&Id, &PathSalt)>,
        device: &DeviceKey,
        version: u64,
        parents: Vec<Id>,
        last_seen: Id,
        store: &Store,
    ) -> (Id, Id, PathSalt) {
        let (rt, rs) = snap(dir, prev, store);
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
        let id = secsec_snapshot::seal_signed_commit(&mk(), store, device, &commit).unwrap();
        (id, rt, rs)
    }

    #[test]
    fn merge_heads_reconciles_divergent_branches_into_signed_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let m = mk();
        let dev_a = DeviceKey::generate().unwrap();
        let dev_b = DeviceKey::generate().unwrap();

        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("keep"), b"k0").unwrap();
        std::fs::write(base.path().join("shared"), b"s0").unwrap();
        std::fs::write(base.path().join("gone"), b"g").unwrap();
        let (base_id, bt, bs) = commit_dir(base.path(), None, &dev_a, 1, vec![], [0u8; 32], &store);

        let ours = tempfile::tempdir().unwrap();
        std::fs::write(ours.path().join("keep"), b"k0").unwrap();
        std::fs::write(ours.path().join("shared"), b"sOURS").unwrap();
        std::fs::write(ours.path().join("ours-only"), b"x").unwrap();
        std::fs::write(ours.path().join("gone"), b"g").unwrap();
        let (ours_id, _, _) = commit_dir(
            ours.path(),
            Some((&bt, &bs)),
            &dev_a,
            2,
            vec![base_id],
            base_id,
            &store,
        );

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
            &store,
        );

        let author = CommitAuthor {
            device: &dev_a,
            version: 3,
            roster_seq: 0,
            ts: 0,
        };
        let plan = merge_heads(
            &SyncFrontier::default(),
            &ours_id,
            &sibling(&dev_b, theirs_id, 1, 0),
            &members(&[&dev_a, &dev_b]),
            author,
            &m,
            &store,
        )
        .unwrap();

        let SyncAction::Merged {
            commit_id,
            conflicts,
            base_missing,
        } = plan.action
        else {
            panic!("expected a real merge")
        };
        assert!(!base_missing);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, "shared");

        let (mc, sig) = secsec_snapshot::open_signed_commit(&commit_id, &m, &store).unwrap();
        secsec_snapshot::verify_commit(&dev_a.public(), &mc, &sig).unwrap();
        assert_eq!(mc.parents, vec![ours_id, theirs_id]);
        assert_eq!(mc.version, 3);
        assert_eq!(mc.last_seen_head, theirs_id);

        let out = tempfile::tempdir().unwrap();
        secsec_snapshot::restore_commit_tree(&mc, &commit_id, None, &m, &store, out.path())
            .unwrap();
        let files: BTreeMap<String, Vec<u8>> = read_tree(out.path()).into_iter().collect();
        assert_eq!(files.get("keep").unwrap(), b"kEDIT");
        assert_eq!(files.get("ours-only").unwrap(), b"x");
        assert_eq!(files.get("shared").unwrap(), b"sOURS");
        assert!(!files.contains_key("gone"), "theirs' deletion applies");
        let ckey = format!(
            "shared.conflict-{}-{}",
            secsec_snapshot::hex12(&dev_b.device_id().unwrap()),
            secsec_snapshot::hex12(&theirs_id)
        );
        assert_eq!(files.get(&ckey).unwrap(), b"sTHEIRS");
        assert_eq!(files.len(), 4);
        assert_eq!(
            plan.frontier
                .head_version_hwm
                .get(&dev_b.device_id().unwrap()),
            Some(&1)
        );
        assert_eq!(
            plan.frontier
                .commit_version_hwm
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
        let (base_id, bt, bs) = commit_dir(base.path(), None, &dev_a, 1, vec![], [0u8; 32], &store);
        let next = tempfile::tempdir().unwrap();
        std::fs::write(next.path().join("f"), b"1").unwrap();
        let (next_id, _, _) = commit_dir(
            next.path(),
            Some((&bt, &bs)),
            &dev_a,
            2,
            vec![base_id],
            base_id,
            &store,
        );
        let author = || CommitAuthor {
            device: &dev_a,
            version: 9,
            roster_seq: 0,
            ts: 0,
        };
        let plan = merge_heads(
            &SyncFrontier::default(),
            &base_id,
            &sibling(&dev_a, next_id, 2, 0),
            &members(&[&dev_a]),
            author(),
            &m,
            &store,
        )
        .unwrap();
        assert!(matches!(
            plan.action,
            SyncAction::FastForward { commit_id } if commit_id == next_id
        ));
        let plan = merge_heads(
            &SyncFrontier::default(),
            &next_id,
            &sibling(&dev_a, base_id, 1, 0),
            &members(&[&dev_a]),
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

        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("f"), b"0").unwrap();
        let (base_id, bt, bs) = commit_dir(base.path(), None, &dev_a, 1, vec![], [0u8; 32], &store);
        let ours = tempfile::tempdir().unwrap();
        std::fs::write(ours.path().join("f"), b"a").unwrap();
        let (ours_id, _, _) = commit_dir(
            ours.path(),
            Some((&bt, &bs)),
            &dev_a,
            2,
            vec![base_id],
            base_id,
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
            &store,
        );
        let frontier = SyncFrontier {
            roster_seq: 5,
            ..Default::default()
        };
        let err = merge_heads(
            &frontier,
            &ours_id,
            &sibling(&dev_b, theirs_id, 1, 4),
            &members(&[&dev_a, &dev_b]),
            CommitAuthor {
                device: &dev_a,
                version: 3,
                roster_seq: 4,
                ts: 0,
            },
            &m,
            &store,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            MergeError::Rollback(MergeReject::RosterRollback {
                sibling: 4,
                frontier: 5
            })
        ));
    }

    /// A forged ancestor claiming another device's id with a huge version never reaches the high-waters.
    #[test]
    fn forged_ancestor_commit_is_rejected_before_the_gates() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let m = mk();
        let honest = DeviceKey::generate().unwrap();
        let mallory = DeviceKey::generate().unwrap();

        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("f"), b"0").unwrap();
        let (base_id, bt, bs) =
            commit_dir(base.path(), None, &honest, 1, vec![], [0u8; 32], &store);

        // Mallory seals a commit claiming to be `honest` at u64::MAX, signed with Mallory's own key.
        let (rt, rs) = snap(base.path(), Some((&bt, &bs)), &store);
        let forged = Commit {
            root_tree: rt,
            root_salt: rs,
            parents: vec![base_id],
            device_id: honest.device_id().unwrap(),
            version: u64::MAX,
            roster_seq: 0,
            last_seen_head: base_id,
            ts: 0,
        };
        let sig = mallory
            .sign(secsec_sig::NS_COMMIT, b"not the commit")
            .unwrap();
        let forged_id = secsec_snapshot::__seal_commit_with_sig(&m, &store, &forged, &sig).unwrap();

        let tip = tempfile::tempdir().unwrap();
        std::fs::write(tip.path().join("f"), b"tip").unwrap();
        let (tip_id, _, _) = commit_dir(
            tip.path(),
            Some((&bt, &bs)),
            &mallory,
            1,
            vec![forged_id],
            forged_id,
            &store,
        );
        let err = accept_sibling(
            &SyncFrontier::default(),
            Some(&base_id),
            &sibling(&mallory, tip_id, 1, 0),
            &honest.device_id().unwrap(),
            &members(&[&honest, &mallory]),
            &m,
            &store,
        )
        .unwrap_err();
        assert!(matches!(err, MergeError::BadCommitSignature(id) if id == forged_id));
    }

    /// A commit by a since-revoked device verifies through `ever_members`; an unknown author never does.
    #[test]
    fn historical_author_verifies_unknown_author_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let revoked = DeviceKey::generate().unwrap();
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"x").unwrap();
        let (c, _, _) = commit_dir(src.path(), None, &revoked, 1, vec![], [0u8; 32], &store);
        let ids = BTreeSet::from([c]);
        assert!(verify_commits(&ids, &members(&[&revoked]), &mk(), &store).is_ok());
        let stranger = DeviceKey::generate().unwrap();
        assert!(matches!(
            verify_commits(&ids, &members(&[&stranger]), &mk(), &store),
            Err(MergeError::NotMember(_))
        ));
    }
}
