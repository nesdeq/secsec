//! Client cache hygiene (`secsec-Design.md` §5). [`local_sweep`] drops objects in the client's own
//! object cache that are no longer reachable from the synced head — orphans left by cas-conflict
//! retries or aborted pushes. (Bounded server-side history retention — `prune_history` — is added
//! here in the retention layer.)

use crate::ClientError;
use secsec_kdf::MasterKeys;
use secsec_object::Id;
use secsec_snapshot::reachable_objects;
use secsec_store::Store;

/// Keep-only-reachable sweep of the client's **own** object cache: delete every object unreachable
/// from `head`. The cache serves only this device, so there is no grace window. **Fail-safe** — an
/// unbuildable closure errors and deletes nothing. Returns the number of objects dropped.
pub fn local_sweep<K: MasterKeys>(keys: &K, store: &Store, head: &Id) -> Result<u64, ClientError> {
    let keep = reachable_objects(keys, store, &[*head])?;
    Ok(store.retain(&keep)?)
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
}
