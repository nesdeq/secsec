//! Client cache hygiene (`secsec-Design.md` §15). [`local_sweep`] drops objects in the client's own
//! object cache that are no longer reachable from the synced head — orphans left by cas-conflict
//! retries or aborted pushes. (Bounded server-side history retention — `prune_history` — is added
//! here in the retention layer.)

use crate::{fetch_head, ClientError, Remote};
use secsec_kdf::MasterKeys;
use secsec_object::Id;
use secsec_proto::server::limits::MAX_HAS_IDS;
use secsec_snapshot::{changed_paths, open_signed_commit, path_content, reachable_objects};
use secsec_store::Store;
use secsec_sync::ref_hash;
use std::collections::{BTreeMap, BTreeSet};

/// Keep-only-reachable sweep of the client's **own** object cache: delete every object unreachable
/// from `head`. The cache serves only this device, so there is no grace window. **Fail-safe** — an
/// unbuildable closure errors and deletes nothing. Returns the number of objects dropped.
pub fn local_sweep<K: MasterKeys>(keys: &K, store: &Store, head: &Id) -> Result<u64, ClientError> {
    let keep = reachable_objects(keys, store, &[*head])?;
    Ok(store.retain(&keep)?)
}

/// Bound history to the last `keep` versions per file (§15): keep the head's full current content plus,
/// for each file, the content of its last `keep` changing-versions; delete everything else. The dead
/// set is dropped from the local cache, then deleted on the server under a head-binding compare-and-swap
/// (a concurrent `cas-head`/`roster-append` rejects the prune, so a reverted head's content is never
/// deleted). `keep == 0` keeps everything. Commit objects are never pruned, so `secsec log` and the
/// parent-graph walk always stay whole; only superseded tree/chunk content is dropped.
pub async fn prune_history<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    ref_name: &str,
    keep: usize,
    roster_seq: u64,
) -> Result<(), ClientError> {
    if keep == 0 {
        return Ok(());
    }
    let Some((head, _sig, head_blob)) = fetch_head(remote, keys, ref_name).await? else {
        return Ok(());
    };
    // Bring all commits + trees local (chunk ids ride in the trees; chunk blobs are not fetched).
    crate::history::fetch_history(remote, store, keys, &head.commit_id).await?;

    // KEEP = the head's full current closure ∪ each file's last `keep` changing-versions' content.
    // ALL  = every tree/chunk reachable from any commit's tree. DEAD = ALL − KEEP (no commits, I4).
    let (head_commit, _) = open_signed_commit(&head.commit_id, keys, store)?;
    let mut keep_set: BTreeSet<Id> =
        path_content(keys, store, &head_commit.root_tree, &head_commit.root_salt, "")?
            .unwrap_or_default();
    let mut all: BTreeSet<Id> = keep_set.clone();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();

    for cid in crate::history::commit_ids(keys, store, &head.commit_id)? {
        let (commit, _) = open_signed_commit(&cid, keys, store)?;
        if let Some(content) =
            path_content(keys, store, &commit.root_tree, &commit.root_salt, "")?
        {
            all.extend(content);
        }
        let parent = match commit.parents.first() {
            Some(p) => {
                let (pc, _) = open_signed_commit(p, keys, store)?;
                Some((pc.root_tree, pc.root_salt))
            }
            None => None,
        };
        let changed = changed_paths(
            keys,
            store,
            parent.as_ref().map(|(t, s)| (t, s)),
            Some((&commit.root_tree, &commit.root_salt)),
        )?;
        for path in changed {
            let count = seen.entry(path.clone()).or_insert(0);
            if *count < keep {
                *count += 1;
                if let Some(content) =
                    path_content(keys, store, &commit.root_tree, &commit.root_salt, &path)?
                {
                    keep_set.extend(content);
                }
            }
        }
    }

    let dead: Vec<Id> = all.difference(&keep_set).copied().collect();
    if dead.is_empty() {
        return Ok(());
    }

    // Drop locally first (symmetric), then delete on the server under the head-binding CAS.
    store.delete_objects(&dead)?;
    let rnk = keys.ref_name_key();
    let ref_h = ref_hash(&rnk, ref_name);
    let ahh = secsec_proto::prune::all_heads_hash(&[(ref_h, *blake3::hash(&head_blob).as_bytes())]);
    for batch in dead.chunks(MAX_HAS_IDS) {
        if !remote.prune(batch, &ahh, roster_seq).await? {
            // CAS conflict: the server's head/roster moved since we read it. Stop; a later prune
            // re-reads and retries. The local delete self-heals — content a moved head now references
            // is re-fetched on demand.
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secsec_kdf::MasterKey;
    use secsec_sig::DeviceKey;
    use secsec_snapshot::{seal_signed_commit, snapshot_tree, Commit};

    #[test]
    fn local_sweep_keeps_reachable_and_drops_orphans() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let m = MasterKey::new(1, [0x55; 32]);
        let dev = DeviceKey::generate().unwrap();

        // Commit a folder → the store holds exactly the head's reachable closure.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"data").unwrap();
        let (rt, rs) = snapshot_tree(src.path(), &m, &store, None).unwrap();
        let commit = Commit {
            root_tree: rt,
            root_salt: rs,
            parents: vec![],
            device_id: dev.device_id().unwrap(),
            version: 1,
            roster_seq: 0,
            last_seen_head: [0u8; 32],
            ts: 0,
        };
        let head = seal_signed_commit(&m, &store, &dev, &commit).unwrap();
        let reachable = store.object_count().unwrap();

        // Inject an unreachable orphan, then sweep: only the orphan is dropped; the closure survives.
        store.put(&[0xee; 32], b"orphan").unwrap();
        assert_eq!(store.object_count().unwrap(), reachable + 1);
        assert_eq!(local_sweep(&m, &store, &head).unwrap(), 1);
        assert_eq!(store.get(&[0xee; 32]).unwrap(), None);
        assert_eq!(store.object_count().unwrap(), reachable);
        assert!(secsec_snapshot::open_signed_commit(&head, &m, &store).is_ok());
    }

    #[tokio::test]
    async fn prune_history_keeps_last_n_versions_per_file() {
        use crate::testmem::MemRemote;
        use crate::{fetch_closure, fetch_head, push_head, push_objects};
        use secsec_sync::Head;

        let dir = tempfile::tempdir().unwrap();
        let m = MasterKey::new(1, [0x55; 32]);
        let dev = DeviceKey::generate().unwrap();
        let remote = MemRemote::new(Store::open(dir.path().join("r.redb")).unwrap());
        let store = Store::open(dir.path().join("c.redb")).unwrap();

        // Three fully-distinct multi-chunk versions of one file (each version's chunks are unique).
        let work = tempfile::tempdir().unwrap();
        let mut prev_tree: Option<(Id, [u8; 16])> = None;
        let mut prev_head: Option<(Head, Vec<u8>)> = None;
        let mut commits: Vec<Id> = Vec::new();
        for v in 1..=3u8 {
            let mut data = vec![0u8; 200 * 1024];
            getrandom::fill(&mut data).unwrap();
            std::fs::write(work.path().join("f.bin"), &data).unwrap();
            let (rt, rs) =
                snapshot_tree(work.path(), &m, &store, prev_tree.as_ref().map(|(t, s)| (t, s)))
                    .unwrap();
            let parents = commits.last().copied().map(|c| vec![c]).unwrap_or_default();
            let last_seen = prev_head
                .as_ref()
                .map(|(h, _)| secsec_sync::head_id(h))
                .unwrap_or([0u8; 32]);
            let commit = Commit {
                root_tree: rt,
                root_salt: rs,
                parents,
                device_id: dev.device_id().unwrap(),
                version: u64::from(v),
                roster_seq: 0,
                last_seen_head: last_seen,
                ts: u64::from(v),
            };
            let cid = seal_signed_commit(&m, &store, &dev, &commit).unwrap();
            let push = [v; 16];
            push_objects(&remote, &store, &m, &cid, &push).await.unwrap();
            let (h, b) = push_head(
                &remote,
                &m,
                &dev,
                "main",
                cid,
                0,
                prev_head.as_ref().map(|(h, b)| (h, b.as_slice())),
                &push,
            )
            .await
            .unwrap();
            prev_tree = Some((rt, rs));
            prev_head = Some((h, b));
            commits.push(cid);
        }
        let before = remote.store.object_count().unwrap();

        // Keep the last 2 versions per file: v1's unique content is pruned, v2/v3 + the head survive.
        prune_history(&remote, &store, &m, "main", 2, 0)
            .await
            .unwrap();
        let after = remote.store.object_count().unwrap();
        assert!(
            after < before,
            "v1's superseded content must be pruned ({before} -> {after})"
        );

        // The head (v3) is still fully fetchable + restorable into a fresh clone after the prune.
        let (h3, _, _) = fetch_head(&remote, &m, "main").await.unwrap().unwrap();
        assert_eq!(h3.commit_id, *commits.last().unwrap());
        let clone = Store::open(dir.path().join("clone.redb")).unwrap();
        fetch_closure(&remote, &clone, &m, &h3.commit_id)
            .await
            .unwrap();
    }
}
