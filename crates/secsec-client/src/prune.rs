//! Cache hygiene and bounded history (`secsec-Design.md` §15): retention drops chunks only; commits and trees are kept.

use crate::{fetch_verified_head, ClientError, Remote};
use secsec_kdf::MasterKeys;
use secsec_object::Id;
use secsec_proto::server::limits::MAX_HAS_IDS;
use secsec_roster::State;
use secsec_snapshot::{changed_paths, open_signed_commit, path_chunks, reachable_objects};
use secsec_store::Store;
use secsec_sync::ref_hash;
use std::collections::{BTreeMap, BTreeSet};

/// Drop every object of this device's own cache that `head` does not reach; fail-safe, returns the count dropped.
pub fn local_sweep<K: MasterKeys>(keys: &K, store: &Store, head: &Id) -> Result<u64, ClientError> {
    let keep = reachable_objects(keys, store, head)?;
    Ok(store.retain(&keep)?)
}

/// Keep the head and each file's last `keep` versions, deleting other chunks here and on the server under the §15 CAS; `Ok(false)` retries later.
pub async fn prune_history<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    roster: &State,
    ref_name: &str,
    keep: usize,
) -> Result<bool, ClientError> {
    if keep == 0 {
        return Ok(true);
    }
    let Some(rh) = fetch_verified_head(remote, keys, &roster.members, ref_name).await? else {
        return Ok(true);
    };
    let head = rh.head.commit_id;
    crate::history::fetch_history(remote, store, keys, &roster.ever_members, &head).await?;

    let (hc, _) = open_signed_commit(&head, keys, store)?;
    let mut keep_set: BTreeSet<Id> =
        path_chunks(keys, store, &hc.root_tree, &hc.root_salt, "")?.unwrap_or_default();
    let mut all: BTreeSet<Id> = keep_set.clone();
    let mut kept: BTreeMap<String, usize> = BTreeMap::new();
    for cid in crate::history::commit_ids(keys, store, &head)? {
        let (commit, _) = open_signed_commit(&cid, keys, store)?;
        if let Some(c) = path_chunks(keys, store, &commit.root_tree, &commit.root_salt, "")? {
            all.extend(c);
        }
        let parent = match commit.parents.first() {
            Some(p) => Some(open_signed_commit(p, keys, store)?.0),
            None => None,
        };
        let changed = changed_paths(
            keys,
            store,
            parent.as_ref().map(|p| (&p.root_tree, &p.root_salt)),
            Some((&commit.root_tree, &commit.root_salt)),
        )?;
        for path in changed {
            let n = kept.entry(path.clone()).or_insert(0);
            if *n < keep {
                *n += 1;
                if let Some(c) =
                    path_chunks(keys, store, &commit.root_tree, &commit.root_salt, &path)?
                {
                    keep_set.extend(c);
                }
            }
        }
    }

    let dead: Vec<Id> = all.difference(&keep_set).copied().collect();
    if dead.is_empty() {
        return Ok(true);
    }
    // Local first: a chunk the head still needs is refetched on demand, so a lost server CAS costs nothing.
    store.delete_objects(&dead)?;
    let rnk = keys.ref_name_key();
    let ahh = secsec_proto::prune::all_heads_hash(&[(
        ref_hash(&rnk, ref_name),
        *blake3::hash(&rh.blob).as_bytes(),
    )]);
    let roster_len = roster.tip_seq.saturating_add(1);
    for batch in dead.chunks(MAX_HAS_IDS) {
        if !remote.prune(batch, &ahh, roster_len).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::{init_repo_remote, open_repo_remote};
    use crate::testmem::MemRemote;
    use crate::{fetch_closure, fetch_head, push_head, push_objects};
    use secsec_kdf::MasterKey;
    use secsec_sig::DeviceKey;
    use secsec_snapshot::{seal_signed_commit, snapshot_tree, Commit, Prior, SnapshotMemo};

    #[test]
    fn local_sweep_keeps_reachable_and_drops_orphans() {
        let d = tempfile::tempdir().unwrap();
        let store = Store::open(d.path().join("s.redb")).unwrap();
        let m = MasterKey::new(1, [0x55; 32]);
        let dev = DeviceKey::generate().unwrap();
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"data").unwrap();
        let snap =
            snapshot_tree(src.path(), &m, &store, None, &mut SnapshotMemo::default()).unwrap();
        let commit = Commit {
            root_tree: snap.root,
            root_salt: snap.salt,
            parents: vec![],
            device_id: dev.device_id().unwrap(),
            version: 1,
            roster_seq: 0,
            last_seen_head: [0; 32],
            ts: 0,
        };
        let head = seal_signed_commit(&m, &store, &dev, &commit).unwrap();
        let reachable = store.object_count().unwrap();
        store.put(&[0xee; 32], b"orphan").unwrap();
        assert_eq!(local_sweep(&m, &store, &head).unwrap(), 1);
        assert_eq!(store.object_count().unwrap(), reachable);
    }

    /// Publish `versions` fully distinct versions of one file into an initialized repo.
    async fn history(
        r: &MemRemote,
        cache: &Store,
        versions: u8,
    ) -> (DeviceKey, MasterKey, State, Vec<Id>) {
        let dev = DeviceKey::generate().unwrap();
        let rfp = init_repo_remote(r, &dev, 0).await.unwrap();
        let (m, st, _) = open_repo_remote(r, &dev, &rfp, None).await.unwrap();
        let work = tempfile::tempdir().unwrap();
        let mut prev: Option<(Id, Commit)> = None;
        let mut head: Option<(secsec_sync::Head, Vec<u8>)> = None;
        let mut commits = Vec::new();
        for v in 1..=versions {
            let mut data = vec![0u8; 200 * 1024];
            getrandom::fill(&mut data).unwrap();
            std::fs::write(work.path().join("f.bin"), &data).unwrap();
            let snap = snapshot_tree(
                work.path(),
                &m,
                cache,
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
                version: u64::from(v),
                roster_seq: 0,
                last_seen_head: [0; 32],
                ts: u64::from(v),
            };
            let id = seal_signed_commit(&m, cache, &dev, &commit).unwrap();
            push_objects(r, cache, &m, &id, prev.as_ref().map(|(p, _)| p), &[v; 16])
                .await
                .unwrap();
            head = Some(
                push_head(
                    r,
                    &m,
                    &dev,
                    "main",
                    id,
                    0,
                    head.as_ref().map(|(h, b)| (h, b.as_slice())),
                    &[v; 16],
                )
                .await
                .unwrap(),
            );
            prev = Some((id, commit));
            commits.push(id);
        }
        (dev, m, st, commits)
    }

    /// Retention drops superseded chunks only; commits and trees stay, so a second prune and `log` walk the whole history.
    #[tokio::test]
    async fn prune_keeps_last_versions_and_every_commit_and_tree() {
        let d = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(d.path().join("r.redb")).unwrap());
        let cache = Store::open(d.path().join("c.redb")).unwrap();
        let (_dev, m, st, commits) = history(&r, &cache, 4).await;
        let before = r.store.object_count().unwrap();
        assert!(prune_history(&r, &cache, &m, &st, "main", 2).await.unwrap());
        let after = r.store.object_count().unwrap();
        assert!(
            after < before,
            "superseded chunks are pruned ({before} -> {after})"
        );
        for c in &commits {
            let (commit, _) = open_signed_commit(c, &m, &cache).unwrap();
            assert!(r.store.get(c).unwrap().is_some(), "commits are kept");
            assert!(
                r.store.get(&commit.root_tree).unwrap().is_some(),
                "trees are kept"
            );
        }
        assert!(prune_history(&r, &cache, &m, &st, "main", 2).await.unwrap());
        let (head, _, _) = fetch_head(&r, &m, "main").await.unwrap().unwrap();
        let fresh = Store::open(d.path().join("fresh.redb")).unwrap();
        fetch_closure(&r, &fresh, &m, &head.commit_id)
            .await
            .unwrap();
        crate::history::fetch_history(&r, &fresh, &m, &st.ever_members, &head.commit_id)
            .await
            .unwrap();
        let log = crate::history::repo_log(&m, &fresh, &head.commit_id).unwrap();
        assert_eq!(log.len(), 4);
        let hist = crate::history::path_history(&m, &fresh, &head.commit_id, "f.bin").unwrap();
        assert_eq!(
            hist.len(),
            4,
            "trees are kept, so every version stays listed"
        );
    }

    /// A prune signed over a stale roster length is refused by the server and deletes nothing there.
    #[tokio::test]
    async fn prune_against_a_moved_roster_is_retried_later() {
        let d = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(d.path().join("r.redb")).unwrap());
        let cache = Store::open(d.path().join("c.redb")).unwrap();
        let (_dev, m, mut st, _) = history(&r, &cache, 3).await;
        let before = r.store.object_count().unwrap();
        st.tip_seq += 1;
        assert!(!prune_history(&r, &cache, &m, &st, "main", 1).await.unwrap());
        assert_eq!(r.store.object_count().unwrap(), before);
    }
}
