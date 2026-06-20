//! `secsec-store` — the content-addressed blob store (`secsec-Design.md` §13): one embedded `redb`
//! database holding only opaque ciphertext (durable objects, in-flight push staging, keyslots, refs,
//! sigchain, key-history wraps). These are the read/write primitives behind the §11/§12 server API. A
//! push stages its objects and the winning `cas-head` atomically promotes them while swapping the ref,
//! so a durable head never references a non-durable object.

#![forbid(unsafe_code)]

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::Path;

/// id (32 bytes) → durable object blob.
const OBJECTS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("objects");
/// `push_id(16) ‖ id(32)` → a blob staged by an in-flight push. Staged objects are promoted into
/// `OBJECTS` when that push's `cas-head` wins, and dropped if the push is abandoned. Never durably
/// visible: a staged object does not exist until promotion.
const STAGING: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("staging");
/// `push_id(16)` → the push's last-activity time (unix seconds). One sliding-TTL clock per push,
/// refreshed on every `stage`, that the idle reclaimer ages out.
const STAGING_META: TableDefinition<'static, &[u8], u64> = TableDefinition::new("staging_meta");
/// `device_id(32) ‖ le32(gen)` → keyslot blob (§13 `/keyslots/<device_id>/<g>`).
const KEYSLOTS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("keyslots");
/// `ref_H(32)` → current head blob (§13 `/refs/<H>`); CAS-guarded by `BLAKE3(blob)`.
const REFS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("refs");
/// `be64(seq)` → encrypted roster sigchain entry blob (§13 `/roster/<seq>`); the tip is CAS-guarded.
const ROSTER: TableDefinition<'static, u64, &[u8]> = TableDefinition::new("roster");
/// `gen(u32)` → roster-key-history wrap (§8.2 `/roster-keyhist/<g>`; never trimmed).
const ROSTER_KEYHIST: TableDefinition<'static, u32, &[u8]> = TableDefinition::new("roster_keyhist");
/// `gen(u32)` → DATA key-history wrap (§8.2 `/keyhist/<g>`).
const KEYHIST: TableDefinition<'static, u32, &[u8]> = TableDefinition::new("keyhist");

/// `old_head_id` sentinel meaning "expect the ref to be absent" — a first `cas-head` (§12).
pub const ABSENT_HEAD: [u8; 32] = [0u8; 32];

/// A ref hash paired with the `BLAKE3` of its stored head blob — the per-ref token a `cas-head`
/// compares on, and the input the retention `Prune` head-binding check recomputes.
pub type RefBlobHash = ([u8; 32], [u8; 32]);

/// The result of [`Store::cas_ref`]: whether the swap happened and, if so, how many bytes of staged
/// content became durable (the new bytes charged against the per-key cap, §15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CasOutcome {
    /// Whether the compare-and-swap succeeded (the ref token matched).
    pub swapped: bool,
    /// Bytes of staged objects promoted to durable storage by this swap (0 on conflict).
    pub promoted_bytes: u64,
}

/// `push_id` length, in bytes — the per-attempt staging-key prefix.
const PUSH_ID_LEN: usize = 16;
/// The fixed length of a staging key: `push_id(16) ‖ id(32)`.
const STAGING_KEY_LEN: usize = PUSH_ID_LEN + 32;

fn staging_key(push_id: &[u8; PUSH_ID_LEN], id: &[u8; 32]) -> [u8; STAGING_KEY_LEN] {
    let mut k = [0u8; STAGING_KEY_LEN];
    k[..PUSH_ID_LEN].copy_from_slice(push_id);
    k[PUSH_ID_LEN..].copy_from_slice(id);
    k
}

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
    redb::CompactionError,
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
            wtx.open_table(STAGING)?;
            wtx.open_table(STAGING_META)?;
            wtx.open_table(KEYSLOTS)?;
            wtx.open_table(REFS)?;
            wtx.open_table(ROSTER)?;
            wtx.open_table(ROSTER_KEYHIST)?;
            wtx.open_table(KEYHIST)?;
        }
        wtx.commit()?;
        Ok(Self { db })
    }

    /// The number of sigchain entries stored (the next append's `seq`).
    pub fn roster_len(&self) -> Result<u64, StoreError> {
        let rtx = self.db.begin_read()?;
        let roster = rtx.open_table(ROSTER)?;
        Ok(roster.len()?)
    }

    /// The stored roster entry blob at `seq`, or `None`.
    pub fn get_roster_entry(&self, seq: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let roster = rtx.open_table(ROSTER)?;
        Ok(roster.get(seq)?.map(|g| g.value().to_vec()))
    }

    /// Store the roster-key-history wrap for generation `g` (§8.2 `/roster-keyhist/<g>`; never trimmed).
    pub fn put_roster_keyhist(&self, g: u32, wrap: &[u8]) -> Result<(), StoreError> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(ROSTER_KEYHIST)?;
            t.insert(g, wrap)?;
        }
        wtx.commit()?;
        Ok(())
    }

    /// The roster-key-history wrap for generation `g`, or `None` (§8.2).
    pub fn get_roster_keyhist(&self, g: u32) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let t = rtx.open_table(ROSTER_KEYHIST)?;
        Ok(t.get(g)?.map(|v| v.value().to_vec()))
    }

    /// Store the DATA key-history wrap for generation `g` (§8.2 `/keyhist/<g>`).
    pub fn put_keyhist(&self, g: u32, wrap: &[u8]) -> Result<(), StoreError> {
        let wtx = self.db.begin_write()?;
        {
            let mut t = wtx.open_table(KEYHIST)?;
            t.insert(g, wrap)?;
        }
        wtx.commit()?;
        Ok(())
    }

    /// The DATA key-history wrap for generation `g`, or `None` (§8.2 `/keyhist/<g>`).
    pub fn get_keyhist(&self, g: u32) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let t = rtx.open_table(KEYHIST)?;
        Ok(t.get(g)?.map(|v| v.value().to_vec()))
    }

    /// Append a sigchain entry CAS-guarded by the `/roster-head` tip (§8.1), in one write
    /// transaction. `Ok(Some(seq))` on success; `Ok(None)` on a tip mismatch (concurrent append —
    /// the client re-folds and retries).
    pub fn append_roster(
        &self,
        expected_old_tip: &[u8; 32],
        entry: &[u8],
    ) -> Result<Option<u64>, StoreError> {
        let wtx = self.db.begin_write()?;
        let result;
        {
            let mut roster = wtx.open_table(ROSTER)?;
            let count = roster.len()?;
            let current_tip = if count == 0 {
                ABSENT_HEAD
            } else {
                match roster.get(count - 1)? {
                    Some(g) => *blake3::hash(g.value()).as_bytes(),
                    None => ABSENT_HEAD, // non-contiguous (impossible for append-only): treat as empty
                }
            };
            if current_tip == *expected_old_tip {
                roster.insert(count, entry)?;
                result = Some(count);
            } else {
                result = None;
            }
        }
        wtx.commit()?;
        Ok(result)
    }

    /// The current head blob stored at `/refs/<ref_h>`, or `None`.
    pub fn get_ref(&self, ref_h: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let refs = rtx.open_table(REFS)?;
        Ok(refs.get(&ref_h[..])?.map(|g| g.value().to_vec()))
    }

    /// Every active ref as `(ref_h, BLAKE3(stored head blob))` — the §15 `all_heads_hash` input
    /// (the server-visible per-ref token `cas-head` also compares on).
    pub fn ref_blob_hashes(&self) -> Result<Vec<RefBlobHash>, StoreError> {
        let rtx = self.db.begin_read()?;
        let refs = rtx.open_table(REFS)?;
        let mut out = Vec::new();
        for item in refs.iter()? {
            let (k, v) = item?;
            if let Ok(ref_h) = <[u8; 32]>::try_from(k.value()) {
                out.push((ref_h, *blake3::hash(v.value()).as_bytes()));
            }
        }
        Ok(out)
    }

    /// Atomic `cas-head` with staged-object promotion (§12), one write transaction: if `BLAKE3(current
    /// blob)` (or [`ABSENT_HEAD`]) equals `expected_old`, promote every object staged under `promote`
    /// into `OBJECTS` and swap the ref to `new_blob`; otherwise nothing changes (a CAS conflict). The
    /// promote and swap commit together, so a durable head never references a non-durable object.
    /// Authenticity is the head's signature (§9.8); the store guards concurrency only.
    pub fn cas_ref(
        &self,
        ref_h: &[u8; 32],
        expected_old: &[u8; 32],
        new_blob: &[u8],
        promote: &[u8; PUSH_ID_LEN],
    ) -> Result<CasOutcome, StoreError> {
        let wtx = self.db.begin_write()?;
        let outcome;
        {
            let mut refs = wtx.open_table(REFS)?;
            let current = match refs.get(&ref_h[..])? {
                Some(g) => *blake3::hash(g.value()).as_bytes(),
                None => ABSENT_HEAD,
            };
            if current != *expected_old {
                outcome = CasOutcome::default();
            } else {
                // Promote this push's staged objects, then swap the ref — one commit. An object that
                // is already durable (a concurrent push promoted it) is neither re-stored nor charged.
                let mut objs = wtx.open_table(OBJECTS)?;
                let mut staging = wtx.open_table(STAGING)?;
                let mut meta = wtx.open_table(STAGING_META)?;
                let lo = staging_key(promote, &[0u8; 32]);
                let hi = staging_key(promote, &[0xffu8; 32]);
                let mut promoted_bytes = 0u64;
                let mut staged_keys: Vec<Vec<u8>> = Vec::new();
                for item in staging.range(&lo[..]..=&hi[..])? {
                    let (k, v) = item?;
                    let id = &k.value()[PUSH_ID_LEN..];
                    if objs.get(id)?.is_none() {
                        objs.insert(id, v.value())?;
                        promoted_bytes += v.value().len() as u64;
                    }
                    staged_keys.push(k.value().to_vec());
                }
                for k in &staged_keys {
                    staging.remove(k.as_slice())?;
                }
                meta.remove(&promote[..])?;
                refs.insert(&ref_h[..], new_blob)?;
                outcome = CasOutcome {
                    swapped: true,
                    promoted_bytes,
                };
            }
        }
        wtx.commit()?;
        Ok(outcome)
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

    /// Store an object durably and idempotently by `id`: `Ok(true)` if newly stored, `Ok(false)` if
    /// already present. The client's local cache and a server-side promotion both land objects here; a
    /// push to the blind server stages instead (see [`Self::stage`]).
    pub fn put(&self, id: &[u8; 32], blob: &[u8]) -> Result<bool, StoreError> {
        let wtx = self.db.begin_write()?;
        let newly;
        {
            let mut objs = wtx.open_table(OBJECTS)?;
            if objs.get(&id[..])?.is_some() {
                newly = false;
            } else {
                objs.insert(&id[..], blob)?;
                newly = true;
            }
        }
        wtx.commit()?;
        Ok(newly)
    }

    /// Stage `blob` under an in-flight `push_id` (§15): a no-op if `id` is already durable (dedup),
    /// otherwise recorded in `STAGING` with the push's `STAGING_META` activity clock refreshed to
    /// `now`. Staged objects stay invisible to [`Self::has`]/[`Self::get`] until a winning `cas-head`
    /// promotes them.
    pub fn stage(
        &self,
        push_id: &[u8; PUSH_ID_LEN],
        id: &[u8; 32],
        blob: &[u8],
        now: u64,
    ) -> Result<(), StoreError> {
        let wtx = self.db.begin_write()?;
        {
            let objs = wtx.open_table(OBJECTS)?;
            if objs.get(&id[..])?.is_none() {
                let mut staging = wtx.open_table(STAGING)?;
                staging.insert(&staging_key(push_id, id)[..], blob)?;
                let mut meta = wtx.open_table(STAGING_META)?;
                meta.insert(&push_id[..], now)?;
            }
        }
        wtx.commit()?;
        Ok(())
    }

    /// Fetch an object blob by id, or `None` if absent.
    pub fn get(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        Ok(objs.get(&id[..])?.map(|g| g.value().to_vec()))
    }

    /// Existence check for a batch of ids against **durable** storage only (drives dedup, §11 `has`).
    /// Staged-but-unpromoted objects do not count as present.
    pub fn has(&self, ids: &[[u8; 32]]) -> Result<Vec<bool>, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(objs.get(&id[..])?.is_some());
        }
        Ok(out)
    }

    /// Like [`Self::has`] but also counts an id as present if it is already staged under `push_id` — so
    /// a resumed push skips re-uploading what it staged before a crash. Durable objects always count.
    pub fn has_for_push(
        &self,
        push_id: &[u8; PUSH_ID_LEN],
        ids: &[[u8; 32]],
    ) -> Result<Vec<bool>, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        let staging = rtx.open_table(STAGING)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let present = objs.get(&id[..])?.is_some()
                || staging.get(&staging_key(push_id, id)[..])?.is_some();
            out.push(present);
        }
        Ok(out)
    }

    /// Total bytes of objects staged under `push_id` that are not yet durable — the upper bound on
    /// what a promote would add to durable storage, charged against the per-key cap before the swap.
    pub fn staged_bytes(&self, push_id: &[u8; PUSH_ID_LEN]) -> Result<u64, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        let staging = rtx.open_table(STAGING)?;
        let lo = staging_key(push_id, &[0u8; 32]);
        let hi = staging_key(push_id, &[0xffu8; 32]);
        let mut total = 0u64;
        for item in staging.range(&lo[..]..=&hi[..])? {
            let (k, v) = item?;
            let id = &k.value()[PUSH_ID_LEN..];
            if objs.get(id)?.is_none() {
                total += v.value().len() as u64;
            }
        }
        Ok(total)
    }

    /// Reclaim abandoned pushes (§15), one write transaction: for every push whose `STAGING_META`
    /// activity is idle past `ttl_secs`, drop all its staged objects and its activity row. Never
    /// touches `OBJECTS`. Returns the number of pushes reclaimed. The clock slides on every
    /// [`Self::stage`], so a live upload — however many objects it is mid-staging — is never reaped.
    pub fn reclaim_staging(&self, now: u64, ttl_secs: u64) -> Result<u64, StoreError> {
        let cutoff = now.saturating_sub(ttl_secs);
        let wtx = self.db.begin_write()?;
        let mut reclaimed = 0u64;
        {
            let mut staging = wtx.open_table(STAGING)?;
            let mut meta = wtx.open_table(STAGING_META)?;
            // Collect the idle push ids first (can't mutate a table mid-iteration).
            let mut idle: Vec<[u8; PUSH_ID_LEN]> = Vec::new();
            for item in meta.iter()? {
                let (k, v) = item?;
                if v.value() <= cutoff {
                    if let Ok(pid) = <[u8; PUSH_ID_LEN]>::try_from(k.value()) {
                        idle.push(pid);
                    }
                }
            }
            for pid in &idle {
                let lo = staging_key(pid, &[0u8; 32]);
                let hi = staging_key(pid, &[0xffu8; 32]);
                let mut keys: Vec<Vec<u8>> = Vec::new();
                for item in staging.range(&lo[..]..=&hi[..])? {
                    keys.push(item?.0.value().to_vec());
                }
                for k in &keys {
                    staging.remove(k.as_slice())?;
                }
                meta.remove(&pid[..])?;
                reclaimed += 1;
            }
        }
        wtx.commit()?;
        Ok(reclaimed)
    }

    /// Delete `ids` from durable storage — the retention `Prune` and the local orphan sweep. Returns
    /// the count removed; absent ids are skipped.
    pub fn delete_objects(&self, ids: &[[u8; 32]]) -> Result<u64, StoreError> {
        let wtx = self.db.begin_write()?;
        let mut removed = 0u64;
        {
            let mut objs = wtx.open_table(OBJECTS)?;
            for id in ids {
                if objs.remove(&id[..])?.is_some() {
                    removed += 1;
                }
            }
        }
        wtx.commit()?;
        Ok(removed)
    }

    /// Delete every durable object **not** in `keep` — the local cache's orphan sweep, dropping objects
    /// no longer reachable from the synced head. Returns the count removed. One write transaction.
    pub fn retain(&self, keep: &std::collections::BTreeSet<[u8; 32]>) -> Result<u64, StoreError> {
        let wtx = self.db.begin_write()?;
        let mut to_delete: Vec<[u8; 32]> = Vec::new();
        {
            let objs = wtx.open_table(OBJECTS)?;
            for item in objs.iter()? {
                let (k, _v) = item?;
                if let Ok(id) = <[u8; 32]>::try_from(k.value()) {
                    if !keep.contains(&id) {
                        to_delete.push(id);
                    }
                }
            }
        }
        {
            let mut objs = wtx.open_table(OBJECTS)?;
            for id in &to_delete {
                objs.remove(&id[..])?;
            }
        }
        wtx.commit()?;
        Ok(to_delete.len() as u64)
    }

    /// Number of distinct objects stored.
    pub fn object_count(&self) -> Result<u64, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        Ok(objs.len()?)
    }

    /// Compact the database file (reclaims freed pages after deletes); `true` if it shrank. Requires
    /// exclusive access, so the client calls it at startup before the sync loop opens transactions.
    /// Best-effort: failure leaves the store usable.
    pub fn compact(&mut self) -> Result<bool, StoreError> {
        Ok(self.db.compact()?)
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
    fn put_is_idempotent_durable() {
        let (_d, s) = temp_store();
        assert!(s.put(&id(1), b"a").unwrap()); // newly stored
        assert!(s.put(&id(2), b"b").unwrap());
        assert!(!s.put(&id(1), b"a").unwrap()); // duplicate -> no-op
        assert_eq!(s.object_count().unwrap(), 2);
    }

    #[test]
    fn stage_is_invisible_until_a_winning_cas_head_promotes_it() {
        let (_d, s) = temp_store();
        let push = [0x07u8; 16];
        let ref_h = id(0xCA);

        // Staged objects: durable `has`/`get` still report absent; `has_for_push` sees them.
        s.stage(&push, &id(1), b"alpha", 100).unwrap();
        s.stage(&push, &id(2), b"beta", 100).unwrap();
        assert_eq!(s.has(&[id(1), id(2)]).unwrap(), vec![false, false]);
        assert_eq!(s.get(&id(1)).unwrap(), None);
        assert_eq!(
            s.has_for_push(&push, &[id(1), id(2), id(3)]).unwrap(),
            vec![true, true, false]
        );
        assert_eq!(s.object_count().unwrap(), 0);

        // A winning cas-head (expect-absent ref) promotes the push's objects and swaps the ref.
        let out = s.cas_ref(&ref_h, &ABSENT_HEAD, b"head-v1", &push).unwrap();
        assert!(out.swapped);
        assert_eq!(out.promoted_bytes, (b"alpha".len() + b"beta".len()) as u64);
        assert_eq!(s.has(&[id(1), id(2)]).unwrap(), vec![true, true]);
        assert_eq!(s.get(&id(1)).unwrap().as_deref(), Some(&b"alpha"[..]));
        assert_eq!(s.get_ref(&ref_h).unwrap().as_deref(), Some(&b"head-v1"[..]));
        assert_eq!(s.object_count().unwrap(), 2);
    }

    #[test]
    fn lost_cas_head_promotes_nothing_and_leaves_staging_for_retry() {
        let (_d, s) = temp_store();
        let push = [0x09u8; 16];
        let ref_h = id(0xCB);
        s.stage(&push, &id(1), b"x", 0).unwrap();
        // Establish the ref at v1 via a separate (empty) push, so expect-absent now conflicts.
        assert!(
            s.cas_ref(&ref_h, &ABSENT_HEAD, b"v1", &[0u8; 16])
                .unwrap()
                .swapped
        );
        let out = s.cas_ref(&ref_h, &ABSENT_HEAD, b"v2", &push).unwrap();
        assert!(!out.swapped);
        assert_eq!(out.promoted_bytes, 0);
        assert_eq!(
            s.has(&[id(1)]).unwrap(),
            vec![false],
            "a lost cas-head must not promote"
        );
        assert_eq!(
            s.has_for_push(&push, &[id(1)]).unwrap(),
            vec![true],
            "staging survives for the retry"
        );
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

    #[test]
    fn cas_ref_first_write_then_swap_then_conflict() {
        let (_d, s) = temp_store();
        let r = id(0x11);
        let p = [0u8; 16]; // empty push: no staged objects to promote
        assert_eq!(s.get_ref(&r).unwrap(), None);

        // first write: expect-absent (ABSENT_HEAD) succeeds.
        assert!(s.cas_ref(&r, &ABSENT_HEAD, b"head-v1", &p).unwrap().swapped);
        assert_eq!(s.get_ref(&r).unwrap().as_deref(), Some(&b"head-v1"[..]));

        // a second first-write (still expecting absent) now conflicts.
        assert!(!s.cas_ref(&r, &ABSENT_HEAD, b"head-vX", &p).unwrap().swapped);
        assert_eq!(s.get_ref(&r).unwrap().as_deref(), Some(&b"head-v1"[..])); // unchanged

        // swap with the correct expected-old (= BLAKE3 of the current blob) succeeds.
        let cur_hash = *blake3::hash(b"head-v1").as_bytes();
        assert!(s.cas_ref(&r, &cur_hash, b"head-v2", &p).unwrap().swapped);
        assert_eq!(s.get_ref(&r).unwrap().as_deref(), Some(&b"head-v2"[..]));

        // a stale expected-old conflicts.
        assert!(!s.cas_ref(&r, &cur_hash, b"head-v3", &p).unwrap().swapped);
        assert_eq!(s.get_ref(&r).unwrap().as_deref(), Some(&b"head-v2"[..]));
    }

    #[test]
    fn append_roster_cas_chains_and_rejects_races() {
        let (_d, s) = temp_store();
        assert_eq!(s.roster_len().unwrap(), 0);

        // genesis: expect-absent.
        assert_eq!(s.append_roster(&ABSENT_HEAD, b"genesis").unwrap(), Some(0));
        assert_eq!(s.roster_len().unwrap(), 1);
        assert_eq!(
            s.get_roster_entry(0).unwrap().as_deref(),
            Some(&b"genesis"[..])
        );

        // a second genesis (still expect-absent) loses the CAS.
        assert_eq!(s.append_roster(&ABSENT_HEAD, b"genesis2").unwrap(), None);
        assert_eq!(s.roster_len().unwrap(), 1);

        // append seq 1 with the correct tip (= BLAKE3 of entry 0).
        let tip0 = *blake3::hash(b"genesis").as_bytes();
        assert_eq!(s.append_roster(&tip0, b"entry1").unwrap(), Some(1));
        assert_eq!(s.roster_len().unwrap(), 2);

        // a racing append still pointing at tip0 (stale) is rejected — no chain poisoning.
        assert_eq!(s.append_roster(&tip0, b"racer").unwrap(), None);
        assert_eq!(s.roster_len().unwrap(), 2);
    }

    #[test]
    fn reclaim_drops_idle_pushes_keeps_fresh_ones_and_never_touches_objects() {
        let (_d, s) = temp_store();
        s.put(&id(1), b"durable").unwrap(); // a durable object reclaim must never touch
        let idle = [0x01u8; 16];
        let live = [0x02u8; 16];
        s.stage(&idle, &id(2), b"old", 100).unwrap();
        s.stage(&live, &id(3), b"new", 1000).unwrap();

        // ttl 600 at now=1000: the idle push (last activity 100) is past its window; the live one isn't.
        assert_eq!(s.reclaim_staging(1000, 600).unwrap(), 1);
        assert_eq!(
            s.has_for_push(&idle, &[id(2)]).unwrap(),
            vec![false],
            "idle push reaped"
        );
        assert_eq!(
            s.has_for_push(&live, &[id(3)]).unwrap(),
            vec![true],
            "live push survives"
        );
        assert_eq!(
            s.get(&id(1)).unwrap().as_deref(),
            Some(&b"durable"[..]),
            "reclaim never touches OBJECTS"
        );
    }

    #[test]
    fn delete_objects_removes_durable_ids() {
        let (_d, s) = temp_store();
        s.put(&id(1), b"a").unwrap();
        s.put(&id(2), b"b").unwrap();
        s.put(&id(3), b"c").unwrap();
        assert_eq!(s.delete_objects(&[id(1), id(3), id(9)]).unwrap(), 2); // id(9) absent → skipped
        assert_eq!(s.get(&id(1)).unwrap(), None);
        assert_eq!(s.get(&id(2)).unwrap().as_deref(), Some(&b"b"[..]));
        assert_eq!(s.object_count().unwrap(), 1);
    }

    #[test]
    fn compact_reclaims_space_after_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("objects.redb");
        let mut s = Store::open(&path).unwrap();
        let mut ids = Vec::new();
        for i in 0..256u32 {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_le_bytes());
            s.put(&k, &vec![0xab; 4096]).unwrap();
            ids.push(k);
        }
        let grown = std::fs::metadata(&path).unwrap().len();
        assert_eq!(s.delete_objects(&ids).unwrap(), 256);
        assert_eq!(s.object_count().unwrap(), 0);
        // Deletes free pages but do not shrink the file; compaction returns them to the OS.
        s.compact().unwrap();
        let compacted = std::fs::metadata(&path).unwrap().len();
        assert!(
            compacted < grown,
            "compaction reclaims deleted space ({grown} → {compacted})"
        );
    }
}
