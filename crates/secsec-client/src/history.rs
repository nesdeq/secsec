//! Repository history — the read side of `secsec log` / `secsec log <path>` (`secsec-Design.md` §10).
//!
//! The full history is already retained (keep-everything GC, and the head's whole ancestor chain is
//! reachable) and readable across rotations (the caller passes a peeled key ring). This module walks
//! the commit DAG over the existing object plane — no protocol, crypto, or server change.
//!
//! [`fetch_history`] brings the commit + tree objects local (skipping chunk blobs — listing and
//! diffing only need the tree structure, and the diff compares chunk-id *lists*, not content).
//! [`repo_log`] lists commits newest-first with the files each changed vs its first parent;
//! [`path_history`] lists the versions of one file/folder. The restore side is
//! [`secsec_snapshot::restore_path`], driven by the CLI.

use crate::{ClientError, Remote};
use secsec_kdf::MasterKeys;
use secsec_object::{Id, PathSalt};
use secsec_sig::DeviceId;
use secsec_snapshot::{
    changed_paths, load_tree, open_signed_commit, resolve_path, Commit, Entry, PathNode, SnapError,
};
use secsec_store::Store;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

enum Work {
    Commit(Id),
    Tree(Id, PathSalt),
}

/// Fetch every commit + tree reachable from `head_commit` into `store` — **not** the chunk blobs, which
/// history listing/diffing never needs. Verifies each object on arrival (§9.2). A missing object is
/// [`ClientError::MissingRemote`]; already-present objects are skipped.
pub async fn fetch_history<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    head_commit: &Id,
) -> Result<(), ClientError> {
    let mut seen: BTreeSet<Id> = BTreeSet::new();
    let mut work = vec![Work::Commit(*head_commit)];
    while let Some(item) = work.pop() {
        let id = match &item {
            Work::Commit(id) | Work::Tree(id, _) => *id,
        };
        if !seen.insert(id) {
            continue;
        }
        if store.get(&id)?.is_none() {
            let blob = remote
                .get_blob(&id)
                .await?
                .ok_or(ClientError::MissingRemote(id))?;
            store.put(&id, &blob)?;
        }
        match item {
            Work::Commit(_) => {
                let (commit, _sig) = open_signed_commit(&id, keys, store)?;
                for p in &commit.parents {
                    work.push(Work::Commit(*p));
                }
                work.push(Work::Tree(commit.root_tree, commit.root_salt));
            }
            Work::Tree(_, salt) => {
                let tree = load_tree(&id, &salt, keys, store)?;
                for e in tree.entries {
                    if let Entry::Dir {
                        subtree,
                        subtree_salt,
                        ..
                    } = e
                    {
                        work.push(Work::Tree(subtree, subtree_salt));
                    }
                }
            }
        }
    }
    Ok(())
}

/// A commit in the log: who, when, and which files it changed vs its first parent.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// The commit's content id.
    pub commit_id: Id,
    /// The authoring device.
    pub device_id: DeviceId,
    /// The author's per-device version.
    pub version: u64,
    /// Author-asserted timestamp (advisory).
    pub ts: u64,
    /// Parent commit ids (2 = a merge).
    pub parents: Vec<Id>,
    /// File paths whose content changed vs the first parent (empty = a metadata-only / merge commit).
    pub changed: Vec<String>,
}

/// All commits reachable from `head` in newest-first **topological** order — a child always precedes
/// its parents; ties are broken by timestamp then id (Kahn's algorithm over the commit DAG). Topology
/// is authoritative; the advisory timestamp only orders independent branches.
fn topo_order<K: MasterKeys>(keys: &K, store: &Store, head: &Id) -> Result<Vec<Id>, ClientError> {
    let mut parents: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    let mut ts: BTreeMap<Id, u64> = BTreeMap::new();
    let mut stack = vec![*head];
    while let Some(cid) = stack.pop() {
        if parents.contains_key(&cid) {
            continue;
        }
        let (commit, _sig) = open_signed_commit(&cid, keys, store)?;
        ts.insert(cid, commit.ts);
        for p in &commit.parents {
            if !parents.contains_key(p) {
                stack.push(*p);
            }
        }
        parents.insert(cid, commit.parents.clone());
    }
    // children[node] = number of commits that list `node` as a parent (incoming edges).
    let mut children: BTreeMap<Id, usize> = parents.keys().map(|k| (*k, 0)).collect();
    for ps in parents.values() {
        for p in ps {
            *children.entry(*p).or_insert(0) += 1;
        }
    }
    // Ready = commits with no remaining children; pop the newest (max ts, then id) each step.
    let mut ready: BinaryHeap<(u64, Id)> = children
        .iter()
        .filter(|(_, c)| **c == 0)
        .map(|(k, _)| (*ts.get(k).unwrap_or(&0), *k))
        .collect();
    let mut order = Vec::with_capacity(parents.len());
    while let Some((_, cid)) = ready.pop() {
        order.push(cid);
        if let Some(ps) = parents.get(&cid) {
            for p in ps {
                if let Some(c) = children.get_mut(p) {
                    *c -= 1;
                    if *c == 0 {
                        ready.push((*ts.get(p).unwrap_or(&0), *p));
                    }
                }
            }
        }
    }
    Ok(order)
}

/// All commit ids reachable from `head_commit`, newest-first (topological) — for resolving a
/// commit-id prefix in `secsec restore <path> <id>`.
pub fn commit_ids<K: MasterKeys>(
    keys: &K,
    store: &Store,
    head_commit: &Id,
) -> Result<Vec<Id>, ClientError> {
    topo_order(keys, store, head_commit)
}

/// Fetch only the chunk blobs needed to materialize `path` from `commit` (the trees are assumed
/// already local via [`fetch_history`]). For a file: its chunks; for a directory: every chunk under
/// it. So restoring one file from a large repo does not download the whole snapshot.
pub async fn fetch_path_content<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    commit: &Commit,
    path: &str,
) -> Result<(), ClientError> {
    let node = resolve_path(keys, store, &commit.root_tree, &commit.root_salt, path)?
        .ok_or_else(|| ClientError::Snap(SnapError::PathNotFound(path.to_string())))?;
    let mut chunk_ids: Vec<Id> = Vec::new();
    match node {
        PathNode::File { chunks, .. } => chunk_ids = chunks,
        PathNode::Dir {
            subtree,
            subtree_salt,
        } => {
            let mut work = vec![(subtree, subtree_salt)];
            while let Some((tid, tsalt)) = work.pop() {
                for e in load_tree(&tid, &tsalt, keys, store)?.entries {
                    match e {
                        Entry::File { chunks, .. } => chunk_ids.extend(chunks),
                        Entry::Dir {
                            subtree,
                            subtree_salt,
                            ..
                        } => work.push((subtree, subtree_salt)),
                    }
                }
            }
        }
    }
    for cid in &chunk_ids {
        if store.get(cid)?.is_none() {
            let blob = remote
                .get_blob(cid)
                .await?
                .ok_or(ClientError::MissingRemote(*cid))?;
            store.put(cid, &blob)?;
        }
    }
    Ok(())
}

/// Restore `path` from `commit_id` into `dest_root` (the working folder root): fetch just that path's
/// chunks, then write the historic file/folder over the current copy (`secsec restore`). The caller
/// lets the normal commit-on-change sync propagate it to other devices.
pub async fn restore<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    commit_id: &Id,
    path: &str,
    dest_root: &std::path::Path,
) -> Result<(), ClientError> {
    let (commit, _sig) = open_signed_commit(commit_id, keys, store)?;
    fetch_path_content(remote, store, keys, &commit, path).await?;
    secsec_snapshot::restore_path(keys, store, &commit, path, dest_root)?;
    Ok(())
}

/// The whole-repo change log: every commit newest-first, with the files it changed vs its first parent.
pub fn repo_log<K: MasterKeys>(
    keys: &K,
    store: &Store,
    head_commit: &Id,
) -> Result<Vec<LogEntry>, ClientError> {
    let order = topo_order(keys, store, head_commit)?;
    let mut out = Vec::with_capacity(order.len());
    for cid in order {
        let (commit, _sig) = open_signed_commit(&cid, keys, store)?;
        let parent_tree = match commit.parents.first() {
            Some(p) => {
                let (pc, _) = open_signed_commit(p, keys, store)?;
                Some((pc.root_tree, pc.root_salt))
            }
            None => None,
        };
        let changed = changed_paths(
            keys,
            store,
            parent_tree.as_ref().map(|(t, s)| (t, s)),
            Some((&commit.root_tree, &commit.root_salt)),
        )?;
        out.push(LogEntry {
            commit_id: cid,
            device_id: commit.device_id,
            version: commit.version,
            ts: commit.ts,
            parents: commit.parents.clone(),
            changed,
        });
    }
    Ok(out)
}

/// One version of a tracked path: the commit where it changed, and whether it exists / is a directory.
#[derive(Debug, Clone)]
pub struct PathVersion {
    /// The commit at which `path`'s content changed.
    pub commit_id: Id,
    /// The authoring device.
    pub device_id: DeviceId,
    /// Author timestamp (advisory).
    pub ts: u64,
    /// Whether `path` exists at this version (`false` = it was deleted here).
    pub present: bool,
    /// Whether `path` is a directory at this version.
    pub is_dir: bool,
}

/// Content identity of a resolved path (a file's chunk list, or a dir's subtree id; `None` if absent).
/// Mode/mtime are excluded, so a pure `touch` is not counted as a new version.
fn content_key(node: &Option<PathNode>) -> Option<Vec<Id>> {
    match node {
        Some(PathNode::File { chunks, .. }) => Some(chunks.clone()),
        Some(PathNode::Dir { subtree, .. }) => Some(vec![*subtree]),
        None => None,
    }
}

/// The version history of one `path` (file or folder): the commits where its content changed, newest
/// first. A commit is a version iff `path`'s content there differs from its first parent.
pub fn path_history<K: MasterKeys>(
    keys: &K,
    store: &Store,
    head_commit: &Id,
    path: &str,
) -> Result<Vec<PathVersion>, ClientError> {
    let order = topo_order(keys, store, head_commit)?;
    let mut out = Vec::new();
    for cid in order {
        let (commit, _sig) = open_signed_commit(&cid, keys, store)?;
        let cur = resolve_path(keys, store, &commit.root_tree, &commit.root_salt, path)?;
        let parent = match commit.parents.first() {
            Some(p) => {
                let (pc, _) = open_signed_commit(p, keys, store)?;
                resolve_path(keys, store, &pc.root_tree, &pc.root_salt, path)?
            }
            None => None,
        };
        if content_key(&cur) != content_key(&parent) {
            out.push(PathVersion {
                commit_id: cid,
                device_id: commit.device_id,
                ts: commit.ts,
                present: cur.is_some(),
                is_dir: matches!(cur, Some(PathNode::Dir { .. })),
            });
        }
    }
    Ok(out)
}
