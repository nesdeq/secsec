//! `secsec-store` — the server's content-addressed blob store (`finaldesign.md` §13).
//!
//! Objects are opaque, content-addressed ciphertext blobs keyed by their 32-byte id. They are
//! stored in a single embedded `redb` database (its B-tree *is* the packing — the server is never
//! flooded with tiny files). The store holds opaque blobs (`{id, blob, arrival put_epoch}`) and the
//! per-device **keyslots** (§13 `/keyslots/<device_id>/<g>`); it never sees plaintext or
//! plaintext-derived metadata (device_ids and keyslot blobs are all opaque).
//!
//! Operations are the read/write primitives behind the §11/§12 server API: [`Store::put`]
//! (idempotent by id), [`Store::get`], [`Store::has`], and the keyslot store
//! ([`Store::put_keyslot`] / [`Store::get_keyslot`] / [`Store::keyslot_exists`] /
//! [`Store::delete_keyslot`] — the latter drives the §12 keyslot-existence auth check and §8.4
//! revocation). The monotonic `put_epoch` counter underpins the GC serialization of §15.

#![forbid(unsafe_code)]

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::Path;

/// id (32 bytes) → object blob.
const OBJECTS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("objects");
/// id (32 bytes) → the `put_epoch` at which it arrived (§15 GC).
const ARRIVAL: TableDefinition<'static, &[u8], u64> = TableDefinition::new("arrival");
/// named counters; currently just `"put_epoch"`.
const COUNTERS: TableDefinition<'static, &str, u64> = TableDefinition::new("counters");
/// `device_id(32) ‖ le32(gen)` → keyslot blob (§13 `/keyslots/<device_id>/<g>`).
const KEYSLOTS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("keyslots");

const PUT_EPOCH: &str = "put_epoch";

/// The fixed length of a keyslot key: `device_id(32) ‖ le32(gen)`.
const KEYSLOT_KEY_LEN: usize = 36;

fn keyslot_key(device_id: &[u8; 32], gen: u32) -> [u8; KEYSLOT_KEY_LEN] {
    let mut k = [0u8; KEYSLOT_KEY_LEN];
    k[..32].copy_from_slice(device_id);
    k[32..].copy_from_slice(&gen.to_le_bytes());
    k
}

/// An error from the store (wraps the underlying `redb` error).
#[derive(Debug)]
pub struct StoreError(Box<redb::Error>);

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "store: {}", self.0)
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

macro_rules! from_redb {
    ($($t:ty),* $(,)?) => {$(
        impl From<$t> for StoreError {
            fn from(e: $t) -> Self { StoreError(Box::new(e.into())) }
        }
    )*};
}
from_redb!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
);

/// A content-addressed object store backed by a single `redb` database file.
pub struct Store {
    db: Database,
}

impl Store {
    /// Open (creating if absent) a store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        // Materialize the tables so reads on a fresh database don't fail.
        let wtx = db.begin_write()?;
        {
            wtx.open_table(OBJECTS)?;
            wtx.open_table(ARRIVAL)?;
            wtx.open_table(COUNTERS)?;
            wtx.open_table(KEYSLOTS)?;
        }
        wtx.commit()?;
        Ok(Self { db })
    }

    /// Store (or overwrite) the keyslot blob for `device_id` at generation `gen`
    /// (§13 `/keyslots/<device_id>/<g>`).
    pub fn put_keyslot(
        &self,
        device_id: &[u8; 32],
        gen: u32,
        blob: &[u8],
    ) -> Result<(), StoreError> {
        let wtx = self.db.begin_write()?;
        {
            let mut ks = wtx.open_table(KEYSLOTS)?;
            ks.insert(&keyslot_key(device_id, gen)[..], blob)?;
        }
        wtx.commit()?;
        Ok(())
    }

    /// Fetch the keyslot blob for `device_id` at generation `gen`, or `None`.
    pub fn get_keyslot(
        &self,
        device_id: &[u8; 32],
        gen: u32,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let ks = rtx.open_table(KEYSLOTS)?;
        Ok(ks
            .get(&keyslot_key(device_id, gen)[..])?
            .map(|g| g.value().to_vec()))
    }

    /// Delete the keyslot for `device_id` at `gen` (revocation, §8.4). Returns `Ok(true)` if one was
    /// present.
    pub fn delete_keyslot(&self, device_id: &[u8; 32], gen: u32) -> Result<bool, StoreError> {
        let wtx = self.db.begin_write()?;
        let existed;
        {
            let mut ks = wtx.open_table(KEYSLOTS)?;
            existed = ks.remove(&keyslot_key(device_id, gen)[..])?.is_some();
        }
        wtx.commit()?;
        Ok(existed)
    }

    /// Whether **any** keyslot exists for `device_id` (the §12 keyslot-existence check). Scans the
    /// `device_id` prefix across generations — filesystem presence only, no decryption.
    pub fn keyslot_exists(&self, device_id: &[u8; 32]) -> Result<bool, StoreError> {
        let lo = keyslot_key(device_id, 0);
        let hi = keyslot_key(device_id, u32::MAX);
        let rtx = self.db.begin_read()?;
        let ks = rtx.open_table(KEYSLOTS)?;
        Ok(ks.range(&lo[..]..=&hi[..])?.next().is_some())
    }

    /// Store an object idempotently by `id`. Returns `Ok(true)` if newly stored, `Ok(false)` if an
    /// object with this id already existed (content addressing makes the stored bytes identical, so
    /// a duplicate `put` is a no-op).
    pub fn put(&self, id: &[u8; 32], blob: &[u8]) -> Result<bool, StoreError> {
        let wtx = self.db.begin_write()?;
        let newly;
        {
            let mut objs = wtx.open_table(OBJECTS)?;
            if objs.get(&id[..])?.is_some() {
                newly = false;
            } else {
                objs.insert(&id[..], blob)?;
                let mut counters = wtx.open_table(COUNTERS)?;
                let epoch = counters.get(PUT_EPOCH)?.map_or(0, |v| v.value()) + 1;
                counters.insert(PUT_EPOCH, epoch)?;
                let mut arrival = wtx.open_table(ARRIVAL)?;
                arrival.insert(&id[..], epoch)?;
                newly = true;
            }
        }
        wtx.commit()?;
        Ok(newly)
    }

    /// Fetch an object blob by id, or `None` if absent.
    pub fn get(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        Ok(objs.get(&id[..])?.map(|g| g.value().to_vec()))
    }

    /// Existence check for a batch of ids (drives dedup, §11 `has`).
    pub fn has(&self, ids: &[[u8; 32]]) -> Result<Vec<bool>, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(objs.get(&id[..])?.is_some());
        }
        Ok(out)
    }

    /// The current global `put_epoch` (0 if nothing stored yet).
    pub fn put_epoch(&self) -> Result<u64, StoreError> {
        let rtx = self.db.begin_read()?;
        let counters = rtx.open_table(COUNTERS)?;
        Ok(counters.get(PUT_EPOCH)?.map_or(0, |v| v.value()))
    }

    /// The `put_epoch` at which `id` arrived, or `None` if absent (§15 GC).
    pub fn arrival_epoch(&self, id: &[u8; 32]) -> Result<Option<u64>, StoreError> {
        let rtx = self.db.begin_read()?;
        let arrival = rtx.open_table(ARRIVAL)?;
        Ok(arrival.get(&id[..])?.map(|v| v.value()))
    }

    /// Number of distinct objects stored.
    pub fn object_count(&self) -> Result<u64, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        Ok(objs.len()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("objects.redb")).unwrap();
        (dir, store)
    }

    fn id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn put_get_round_trip_and_missing() {
        let (_d, s) = temp_store();
        assert!(s.put(&id(1), b"hello").unwrap());
        assert_eq!(s.get(&id(1)).unwrap().as_deref(), Some(&b"hello"[..]));
        assert_eq!(s.get(&id(2)).unwrap(), None);
    }

    #[test]
    fn put_is_idempotent_and_epoch_only_advances_on_new() {
        let (_d, s) = temp_store();
        assert_eq!(s.put_epoch().unwrap(), 0);
        assert!(s.put(&id(1), b"a").unwrap()); // new
        assert!(s.put(&id(2), b"b").unwrap()); // new
        assert_eq!(s.put_epoch().unwrap(), 2);
        assert!(!s.put(&id(1), b"a").unwrap()); // duplicate -> no-op
        assert_eq!(
            s.put_epoch().unwrap(),
            2,
            "duplicate put must not advance the epoch"
        );
        assert_eq!(s.arrival_epoch(&id(1)).unwrap(), Some(1));
        assert_eq!(s.arrival_epoch(&id(2)).unwrap(), Some(2));
        assert_eq!(s.object_count().unwrap(), 2);
    }

    #[test]
    fn has_batch() {
        let (_d, s) = temp_store();
        s.put(&id(1), b"x").unwrap();
        s.put(&id(3), b"z").unwrap();
        assert_eq!(
            s.has(&[id(1), id(2), id(3)]).unwrap(),
            vec![true, false, true]
        );
        assert_eq!(s.has(&[]).unwrap(), Vec::<bool>::new());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("objects.redb");
        {
            let s = Store::open(&path).unwrap();
            s.put(&id(7), b"durable").unwrap();
        } // drop closes the db
        let s2 = Store::open(&path).unwrap();
        assert_eq!(s2.get(&id(7)).unwrap().as_deref(), Some(&b"durable"[..]));
        assert_eq!(s2.put_epoch().unwrap(), 1);
    }

    #[test]
    fn large_blob() {
        let (_d, s) = temp_store();
        let blob = vec![0xABu8; 4 * 1024 * 1024];
        s.put(&id(9), &blob).unwrap();
        assert_eq!(s.get(&id(9)).unwrap().unwrap(), blob);
    }

    #[test]
    fn keyslot_put_get_exists_delete() {
        let (_d, s) = temp_store();
        let dev_a = id(0xA0);
        let dev_b = id(0xB0);

        // no keyslots initially.
        assert!(!s.keyslot_exists(&dev_a).unwrap());
        assert_eq!(s.get_keyslot(&dev_a, 1).unwrap(), None);

        // store a keyslot for dev_a at gen 1 and gen 2.
        s.put_keyslot(&dev_a, 1, b"slot-a1").unwrap();
        s.put_keyslot(&dev_a, 2, b"slot-a2").unwrap();
        assert_eq!(
            s.get_keyslot(&dev_a, 1).unwrap().as_deref(),
            Some(&b"slot-a1"[..])
        );
        assert_eq!(
            s.get_keyslot(&dev_a, 2).unwrap().as_deref(),
            Some(&b"slot-a2"[..])
        );

        // existence is per device, across generations; dev_b still has none.
        assert!(s.keyslot_exists(&dev_a).unwrap());
        assert!(!s.keyslot_exists(&dev_b).unwrap());

        // delete gen 1 — dev_a still enrolled via gen 2.
        assert!(s.delete_keyslot(&dev_a, 1).unwrap());
        assert_eq!(s.get_keyslot(&dev_a, 1).unwrap(), None);
        assert!(s.keyslot_exists(&dev_a).unwrap());
        // delete the last one — now no keyslot for dev_a.
        assert!(s.delete_keyslot(&dev_a, 2).unwrap());
        assert!(!s.keyslot_exists(&dev_a).unwrap());
        assert!(!s.delete_keyslot(&dev_a, 2).unwrap()); // already gone
    }
}
