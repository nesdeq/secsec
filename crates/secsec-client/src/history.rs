//! Repository history for `secsec log` and `secsec restore` (`secsec-Design.md` §10, §15): verified commits and trees, chunks on demand.

use crate::{fetch_commits, fetch_tree, ClientError, Remote, Walk};
use secsec_kdf::MasterKeys;
use secsec_object::{Id, PathSalt};
use secsec_sig::{DeviceId, DevicePublic};
use secsec_snapshot::{
    changed_paths, load_tree, open_signed_commit, resolve_path, Commit, Entry, PathNode, SnapError,
};
use secsec_store::Store;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

/// Bring `head_commit`'s history local: every commit, signature-checked against `ever_members`, and every tree it still has.
pub async fn fetch_history<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    ever_members: &BTreeMap<DeviceId, DevicePublic>,
    head_commit: &Id,
) -> Result<(), ClientError> {
    fetch_commits(remote, store, keys, head_commit).await?;
    let ids = topo_order(keys, store, head_commit)?;
    let all: BTreeSet<Id> = ids.iter().copied().collect();
    secsec_engine::verify_commits(&all, ever_members, keys, store)?;
    for cid in &ids {
        let (c, _) = open_signed_commit(cid, keys, store)?;
        match fetch_tree(remote, store, keys, &c.root_tree, &c.root_salt, Walk::Trees).await {
            Ok(_) => {}
            // A tree the server no longer holds is skipped; only the head's own tree is required.
            Err(ClientError::MissingRemote(_)) if cid != head_commit => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A commit in the log: who, when, and which files it changed against its first parent.
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
    /// Parent commit ids (two for a merge).
    pub parents: Vec<Id>,
    /// File paths whose content changed against the first parent.
    pub changed: Vec<String>,
}

/// Commits reachable from `head`, newest first in topological order (children before parents, ties by timestamp then id).
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
        stack.extend(commit.parents.iter().filter(|p| !parents.contains_key(*p)));
        parents.insert(cid, commit.parents);
    }
    let mut children: BTreeMap<Id, usize> = parents.keys().map(|k| (*k, 0)).collect();
    for ps in parents.values() {
        for p in ps {
            *children.entry(*p).or_insert(0) += 1;
        }
    }
    let mut ready: BinaryHeap<(u64, Id)> = children
        .iter()
        .filter(|(_, c)| **c == 0)
        .map(|(k, _)| (*ts.get(k).unwrap_or(&0), *k))
        .collect();
    let mut order = Vec::with_capacity(parents.len());
    while let Some((_, cid)) = ready.pop() {
        order.push(cid);
        for p in parents.get(&cid).into_iter().flatten() {
            if let Some(c) = children.get_mut(p) {
                *c -= 1;
                if *c == 0 {
                    ready.push((*ts.get(p).unwrap_or(&0), *p));
                }
            }
        }
    }
    Ok(order)
}

/// Every commit id reachable from `head_commit`, newest first (resolves `secsec restore` id prefixes).
pub fn commit_ids<K: MasterKeys>(
    keys: &K,
    store: &Store,
    head_commit: &Id,
) -> Result<Vec<Id>, ClientError> {
    topo_order(keys, store, head_commit)
}

/// Fetch, verified, only the chunks that materialize `path` in `commit` (trees are already local).
async fn fetch_path_content<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    commit: &Commit,
    path: &str,
) -> Result<(), ClientError> {
    let node = match resolve_path(keys, store, &commit.root_tree, &commit.root_salt, path) {
        Ok(Some(n)) => n,
        Ok(None) => return Err(SnapError::PathNotFound(path.to_string()).into()),
        // A spine absent from the store: restore_path reports it.
        Err(SnapError::Missing(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut chunks: Vec<(Id, PathSalt)> = Vec::new();
    match node {
        PathNode::File {
            chunks: cs,
            path_salt,
            ..
        } => chunks.extend(cs.into_iter().map(|c| (c, path_salt))),
        PathNode::Dir {
            subtree,
            subtree_salt,
        } => {
            let mut work = vec![(subtree, subtree_salt)];
            while let Some((tid, tsalt)) = work.pop() {
                for e in load_tree(&tid, &tsalt, keys, store)?.entries {
                    match e {
                        Entry::File {
                            chunks: cs,
                            path_salt,
                            ..
                        } => chunks.extend(cs.into_iter().map(|c| (c, path_salt))),
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
    for (cid, salt) in &chunks {
        if store.get(cid)?.is_some() {
            continue;
        }
        // Chunks pruned beyond retention are left for restore_path to report.
        let Some(blob) = remote.get_blob(cid).await? else {
            continue;
        };
        secsec_snapshot::verify_chunk(keys, cid, salt, &blob)?;
        store.put(cid, &blob)?;
    }
    Ok(())
}

/// `secsec restore`: write `path` as of `commit_id` into `dest_root`, overwriting the current copy.
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

/// The whole-repo change log, newest first.
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

/// One version of a tracked path.
#[derive(Debug, Clone)]
pub struct PathVersion {
    /// The commit at which the path changed.
    pub commit_id: Id,
    /// The authoring device.
    pub device_id: DeviceId,
    /// Author timestamp (advisory).
    pub ts: u64,
    /// Whether the path exists at this version (`false`: deleted here).
    pub present: bool,
    /// Whether the path is a directory at this version.
    pub is_dir: bool,
}

/// Content identity of a resolved path: a file's chunk list or a directory's subtree id; mode and mtime are excluded.
fn content_key(node: &Option<PathNode>) -> Option<Vec<Id>> {
    match node {
        Some(PathNode::File { chunks, .. }) => Some(chunks.clone()),
        Some(PathNode::Dir { subtree, .. }) => Some(vec![*subtree]),
        None => None,
    }
}

/// A path at a commit: resolved (present or absent) or unknowable because its trees are gone.
enum PathState {
    Resolved(Option<PathNode>),
    Pruned,
}

fn resolve_state<K: MasterKeys>(
    keys: &K,
    store: &Store,
    root_tree: &Id,
    root_salt: &PathSalt,
    path: &str,
) -> Result<PathState, ClientError> {
    match resolve_path(keys, store, root_tree, root_salt, path) {
        Ok(node) => Ok(PathState::Resolved(node)),
        Err(SnapError::Missing(_)) => Ok(PathState::Pruned),
        Err(e) => Err(e.into()),
    }
}

/// One path's versions, newest first: commits where its content differs from the first parent; unknowable ones are skipped.
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
        let PathState::Resolved(cur) =
            resolve_state(keys, store, &commit.root_tree, &commit.root_salt, path)?
        else {
            continue;
        };
        let parent = match commit.parents.first() {
            Some(p) => {
                let (pc, _) = open_signed_commit(p, keys, store)?;
                resolve_state(keys, store, &pc.root_tree, &pc.root_salt, path)?
            }
            None => PathState::Resolved(None),
        };
        // Past an unknowable parent (its trees absent), the oldest version still resolvable is listed.
        let changed = match parent {
            PathState::Resolved(p) => content_key(&cur) != content_key(&p),
            PathState::Pruned => cur.is_some(),
        };
        if changed {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testmem::{roster_of, MemRemote};
    use crate::{push_head, push_objects};
    use secsec_kdf::MasterKey;
    use secsec_sig::DeviceKey;
    use secsec_snapshot::{seal_signed_commit, snapshot_tree, Prior, SnapshotMemo};

    /// Log, path history, and a single-file restore over a fresh store; a commit by a non-member is refused.
    #[tokio::test]
    async fn log_path_history_and_restore() {
        let dir = tempfile::tempdir().unwrap();
        let m = MasterKey::new(1, [0x21; 32]);
        let dev = DeviceKey::generate().unwrap();
        let r = MemRemote::new(Store::open(dir.path().join("r.redb")).unwrap());
        let a = Store::open(dir.path().join("a.redb")).unwrap();
        let work = tempfile::tempdir().unwrap();
        let mut prev: Option<(Id, Commit)> = None;
        let mut head: Option<(secsec_sync::Head, Vec<u8>)> = None;
        for v in 1..=3u64 {
            std::fs::write(work.path().join("f.txt"), format!("version {v}")).unwrap();
            let snap = snapshot_tree(
                work.path(),
                &m,
                &a,
                prev.as_ref().map(|(_, c)| Prior {
                    root: &c.root_tree,
                    salt: &c.root_salt,
                    fast_path: false,
                }),
                &mut SnapshotMemo::default(),
            )
            .unwrap();
            let commit = Commit {
                root_tree: snap.root,
                root_salt: snap.salt,
                parents: prev.iter().map(|(id, _)| *id).collect(),
                device_id: dev.device_id().unwrap(),
                version: v,
                roster_seq: 0,
                last_seen_head: [0; 32],
                ts: v,
            };
            let id = seal_signed_commit(&m, &a, &dev, &commit).unwrap();
            push_objects(
                &r,
                &a,
                &m,
                &id,
                prev.as_ref().map(|(p, _)| p),
                &[v as u8; 16],
            )
            .await
            .unwrap();
            let pushed = push_head(
                &r,
                &m,
                &dev,
                "main",
                id,
                0,
                head.as_ref().map(|(h, b)| (h, b.as_slice())),
                &[v as u8; 16],
            )
            .await
            .unwrap();
            head = Some(pushed);
            prev = Some((id, commit));
        }
        let tip = prev.unwrap().0;
        let roster = roster_of(&[&dev]);
        let fresh = Store::open(dir.path().join("h.redb")).unwrap();
        fetch_history(&r, &fresh, &m, &roster.ever_members, &tip)
            .await
            .unwrap();
        let log = repo_log(&m, &fresh, &tip).unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].commit_id, tip);
        assert_eq!(log[0].changed, vec!["f.txt".to_string()]);
        let hist = path_history(&m, &fresh, &tip, "f.txt").unwrap();
        assert_eq!(hist.len(), 3);
        let oldest = hist.last().unwrap().commit_id;
        let out = tempfile::tempdir().unwrap();
        restore(&r, &fresh, &m, &oldest, "f.txt", out.path())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(out.path().join("f.txt")).unwrap(),
            b"version 1"
        );

        let stranger = roster_of(&[&DeviceKey::generate().unwrap()]);
        let other = Store::open(dir.path().join("o.redb")).unwrap();
        assert!(matches!(
            fetch_history(&r, &other, &m, &stranger.ever_members, &tip).await,
            Err(ClientError::Merge(secsec_engine::MergeError::NotMember(_)))
        ));
    }
}
