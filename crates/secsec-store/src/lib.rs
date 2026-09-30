//! The content-addressed blob store: one embedded `redb` database of opaque ciphertext (`secsec-Design.md` §13, §15).

#![forbid(unsafe_code)]

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::Path;

/// id (32 bytes) → durable object blob.
const OBJECTS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("objects");
/// `push_id(16) ‖ id(32)` → a blob staged by an in-flight push, invisible until promoted (§15).
const STAGING: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("staging");
/// `push_id(16)` → the push's last-activity unix seconds, the idle reclaimer's clock.
const STAGING_META: TableDefinition<'static, &[u8], u64> = TableDefinition::new("staging_meta");
/// `device_id(32) ‖ le32(gen)` → keyslot blob (§13 `/keyslots/<device_id>/<g>`).
const KEYSLOTS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("keyslots");
/// `ref_H(32)` → current head blob (§13 `/refs/<H>`), CAS-guarded by `BLAKE3(blob)`.
const REFS: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("refs");
/// `seq` → encrypted roster entry blob (§13 `/roster/<seq>`); the tip is CAS-guarded.
const ROSTER: TableDefinition<'static, u64, &[u8]> = TableDefinition::new("roster");
/// `gen` → roster-key-history wrap (§8.2 `/roster-keyhist/<g>`, never trimmed).
const ROSTER_KEYHIST: TableDefinition<'static, u32, &[u8]> = TableDefinition::new("roster_keyhist");
/// `gen` → data key-history wrap (§8.2 `/keyhist/<g>`).
const KEYHIST: TableDefinition<'static, u32, &[u8]> = TableDefinition::new("keyhist");

/// The "expect absent" CAS sentinel for a first `cas-head` or the genesis roster append (§12).
pub const ABSENT_HEAD: [u8; 32] = [0u8; 32];

/// A ref hash paired with `BLAKE3` of its stored head blob: the `cas-head` token and `all_heads_hash` input.
pub type RefBlobHash = ([u8; 32], [u8; 32]);

/// The result of [`Store::cas_ref`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CasOutcome {
    /// Whether the compare-and-swap succeeded.
    pub swapped: bool,
    /// Bytes of staged objects made durable by this swap (0 on conflict).
    pub promoted_bytes: u64,
}

/// One keyslot written by a [`RosterBatch`].
#[derive(Debug, Clone, Copy)]
pub struct KeyslotWrite<'a> {
    /// Owner device id.
    pub device_id: [u8; 32],
    /// Generation the keyslot wraps.
    pub gen: u32,
    /// Opaque `algo_id ‖ body` keyslot.
    pub blob: &'a [u8],
}

/// A head swap riding a [`RosterBatch`] (the revoke-time head re-sign, §8.4).
#[derive(Debug, Clone, Copy)]
pub struct HeadSwap<'a> {
    /// Keyed-hash ref name.
    pub ref_h: [u8; 32],
    /// Expected `BLAKE3` of the current head blob.
    pub expected_old: [u8; 32],
    /// The new head blob.
    pub new_blob: &'a [u8],
}

/// Every roster-side write of one sigchain operation, applied atomically under the tip CAS (§8.1, §8.4).
#[derive(Debug, Clone, Copy)]
pub struct RosterBatch<'a> {
    /// `BLAKE3` of the current tip entry blob, or [`ABSENT_HEAD`] for genesis.
    pub expected_tip: [u8; 32],
    /// Sealed entry blobs appended in order.
    pub entries: &'a [Vec<u8>],
    /// Keyslots written.
    pub keyslots: &'a [KeyslotWrite<'a>],
    /// Data key-history wrap `(g, wrap)`; one the chain has rotated past is never replaced.
    pub keyhist: Option<(u32, &'a [u8])>,
    /// Roster-key-history wrap `(g, wrap)`; one the chain has rotated past is never replaced.
    pub roster_keyhist: Option<(u32, &'a [u8])>,
    /// Devices whose keyslots at every generation are deleted.
    pub revoke: &'a [[u8; 32]],
    /// Optional head swap under its own CAS.
    pub head: Option<HeadSwap<'a>>,
}

/// `push_id` length, in bytes.
const PUSH_ID_LEN: usize = 16;
/// Staging key length `push_id(16) ‖ id(32)`.
const STAGING_KEY_LEN: usize = PUSH_ID_LEN + 32;

fn staging_key(push_id: &[u8; PUSH_ID_LEN], id: &[u8; 32]) -> [u8; STAGING_KEY_LEN] {
    let mut k = [0u8; STAGING_KEY_LEN];
    k[..PUSH_ID_LEN].copy_from_slice(push_id);
    k[PUSH_ID_LEN..].copy_from_slice(id);
    k
}

/// Inclusive bounds covering every STAGING key under `push_id`.
fn staging_range(push_id: &[u8; PUSH_ID_LEN]) -> ([u8; STAGING_KEY_LEN], [u8; STAGING_KEY_LEN]) {
    (
        staging_key(push_id, &[0u8; 32]),
        staging_key(push_id, &[0xffu8; 32]),
    )
}

/// Keyslot key length `device_id(32) ‖ le32(gen)`.
const KEYSLOT_KEY_LEN: usize = 36;

fn keyslot_key(device_id: &[u8; 32], gen: u32) -> [u8; KEYSLOT_KEY_LEN] {
    let mut k = [0u8; KEYSLOT_KEY_LEN];
    k[..32].copy_from_slice(device_id);
    k[32..].copy_from_slice(&gen.to_le_bytes());
    k
}

/// Inclusive bounds covering every keyslot of `device_id` across generations.
fn keyslot_range(device_id: &[u8; 32]) -> ([u8; KEYSLOT_KEY_LEN], [u8; KEYSLOT_KEY_LEN]) {
    let mut lo = [0u8; KEYSLOT_KEY_LEN];
    lo[..32].copy_from_slice(device_id);
    let mut hi = [0xffu8; KEYSLOT_KEY_LEN];
    hi[..32].copy_from_slice(device_id);
    (lo, hi)
}

/// The plaintext `FRAME.gen` of a stored roster entry, `None` if it has no valid FRAME.
fn frame_gen(blob: &[u8]) -> Option<u32> {
    let frame = blob.get(..secsec_frame::FRAME_LEN)?;
    secsec_frame::Frame::decode(frame).ok().map(|f| f.gen)
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

/// A content-addressed object store backed by a single `redb` file.
pub struct Store {
    db: Database,
}

impl Store {
    /// Open (creating if absent) a store at `path`; redb holds an exclusive lock on the file while open.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
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

    /// The roster-key-history wrap for generation `g`, or `None` (§8.2).
    pub fn get_roster_keyhist(&self, g: u32) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let t = rtx.open_table(ROSTER_KEYHIST)?;
        Ok(t.get(g)?.map(|v| v.value().to_vec()))
    }

    /// The data key-history wrap for generation `g`, or `None` (§8.2).
    pub fn get_keyhist(&self, g: u32) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let t = rtx.open_table(KEYHIST)?;
        Ok(t.get(g)?.map(|v| v.value().to_vec()))
    }

    /// Apply a [`RosterBatch`] in one write transaction; `Ok(Some(first_seq))`, or `Ok(None)` on any CAS miss.
    pub fn roster_batch(&self, batch: &RosterBatch<'_>) -> Result<Option<u64>, StoreError> {
        let wtx = self.db.begin_write()?;
        let applied = {
            let mut roster = wtx.open_table(ROSTER)?;
            let mut refs = wtx.open_table(REFS)?;
            let mut keyhist = wtx.open_table(KEYHIST)?;
            let mut rkh = wtx.open_table(ROSTER_KEYHIST)?;
            let mut ks = wtx.open_table(KEYSLOTS)?;

            let count = roster.len()?;
            let (current_tip, tip_gen) = match count.checked_sub(1) {
                None => (ABSENT_HEAD, None),
                Some(last) => match roster.get(last)? {
                    Some(g) => (*blake3::hash(g.value()).as_bytes(), frame_gen(g.value())),
                    None => (ABSENT_HEAD, None),
                },
            };
            // A wrap for g is live once the chain rotated past g; one left by an aborted rotation at g is replaceable.
            let wrap_free = |present: bool, g: u32| !present || tip_gen == Some(g);
            let head_ok = match &batch.head {
                None => true,
                Some(h) => {
                    let cur = match refs.get(&h.ref_h[..])? {
                        Some(g) => *blake3::hash(g.value()).as_bytes(),
                        None => ABSENT_HEAD,
                    };
                    cur == h.expected_old
                }
            };
            let keyhist_free = match batch.keyhist {
                Some((g, _)) => wrap_free(keyhist.get(g)?.is_some(), g),
                None => true,
            } && match batch.roster_keyhist {
                Some((g, _)) => wrap_free(rkh.get(g)?.is_some(), g),
                None => true,
            };

            if current_tip != batch.expected_tip || !head_ok || !keyhist_free {
                None
            } else {
                // Genesis: no keyslot may predate the first entry, so none squatted earlier survives (§7).
                if count == 0 {
                    let mut all: Vec<Vec<u8>> = Vec::new();
                    for item in ks.iter()? {
                        all.push(item?.0.value().to_vec());
                    }
                    for k in &all {
                        ks.remove(k.as_slice())?;
                    }
                }
                for (i, entry) in batch.entries.iter().enumerate() {
                    roster.insert(count + i as u64, entry.as_slice())?;
                }
                for dev in batch.revoke {
                    let (lo, hi) = keyslot_range(dev);
                    let mut gone: Vec<Vec<u8>> = Vec::new();
                    for item in ks.range(&lo[..]..=&hi[..])? {
                        gone.push(item?.0.value().to_vec());
                    }
                    for k in &gone {
                        ks.remove(k.as_slice())?;
                    }
                }
                for k in batch.keyslots {
                    ks.insert(&keyslot_key(&k.device_id, k.gen)[..], k.blob)?;
                }
                if let Some((g, wrap)) = batch.keyhist {
                    keyhist.insert(g, wrap)?;
                }
                if let Some((g, wrap)) = batch.roster_keyhist {
                    rkh.insert(g, wrap)?;
                }
                if let Some(h) = &batch.head {
                    refs.insert(&h.ref_h[..], h.new_blob)?;
                }
                Some(count)
            }
        };
        if applied.is_some() {
            wtx.commit()?;
        } else {
            wtx.abort()?;
        }
        Ok(applied)
    }

    /// The current head blob at `/refs/<ref_h>`, or `None`.
    pub fn get_ref(&self, ref_h: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let refs = rtx.open_table(REFS)?;
        Ok(refs.get(&ref_h[..])?.map(|g| g.value().to_vec()))
    }

    /// Every ref as `(ref_h, BLAKE3(stored head blob))`, the §15 `all_heads_hash` input.
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

    /// Atomic `cas-head` (§12, I1): on a token match, promote `promote`'s staging and swap the ref in one commit.
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
                // An object already durable (promoted by a concurrent push) is neither re-stored nor charged.
                let mut objs = wtx.open_table(OBJECTS)?;
                let mut staging = wtx.open_table(STAGING)?;
                let mut meta = wtx.open_table(STAGING_META)?;
                let (lo, hi) = staging_range(promote);
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
        if outcome.swapped {
            wtx.commit()?;
        } else {
            wtx.abort()?;
        }
        Ok(outcome)
    }

    /// Store (or overwrite) one keyslot directly; production writes go through [`Self::roster_batch`].
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

    /// The keyslot blob for `device_id` at `gen`, or `None`.
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

    /// Whether any generation's keyslot exists for `device_id` (§12); a storage error is an error, never `true`.
    pub fn keyslot_exists(&self, device_id: &[u8; 32]) -> Result<bool, StoreError> {
        let (lo, hi) = keyslot_range(device_id);
        let rtx = self.db.begin_read()?;
        let ks = rtx.open_table(KEYSLOTS)?;
        let mut range = ks.range(&lo[..]..=&hi[..])?;
        match range.next() {
            None => Ok(false),
            Some(item) => {
                item?;
                Ok(true)
            }
        }
    }

    /// Store an object durably, first write wins: `Ok(true)` if newly stored; a present id commits nothing.
    pub fn put(&self, id: &[u8; 32], blob: &[u8]) -> Result<bool, StoreError> {
        Ok(self.put_many(&[(*id, blob)])? == 1)
    }

    /// Store several objects in one transaction (first write wins per id); returns how many were new.
    pub fn put_many(&self, items: &[([u8; 32], &[u8])]) -> Result<u64, StoreError> {
        let wtx = self.db.begin_write()?;
        let mut newly = 0u64;
        {
            let mut objs = wtx.open_table(OBJECTS)?;
            for (id, blob) in items {
                if objs.get(&id[..])?.is_none() {
                    objs.insert(&id[..], *blob)?;
                    newly += 1;
                }
            }
        }
        if newly > 0 {
            wtx.commit()?;
        } else {
            wtx.abort()?;
        }
        Ok(newly)
    }

    /// Stage `blob` under `push_id` (§15), refreshing the push's activity clock; a durable id is staged too, so a prune racing the push cannot strand it.
    pub fn stage(
        &self,
        push_id: &[u8; PUSH_ID_LEN],
        id: &[u8; 32],
        blob: &[u8],
        now: u64,
    ) -> Result<(), StoreError> {
        let wtx = self.db.begin_write()?;
        {
            let mut staging = wtx.open_table(STAGING)?;
            staging.insert(&staging_key(push_id, id)[..], blob)?;
            let mut meta = wtx.open_table(STAGING_META)?;
            meta.insert(&push_id[..], now)?;
        }
        wtx.commit()?;
        Ok(())
    }

    /// Fetch an object blob by id, or `None`.
    pub fn get(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        Ok(objs.get(&id[..])?.map(|g| g.value().to_vec()))
    }

    /// Durable existence per id (§15); staged objects count as absent.
    pub fn has(&self, ids: &[[u8; 32]]) -> Result<Vec<bool>, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(objs.get(&id[..])?.is_some());
        }
        Ok(out)
    }

    /// Bytes staged under `push_id` not yet durable: the upper bound a promote would add.
    pub fn staged_bytes(&self, push_id: &[u8; PUSH_ID_LEN]) -> Result<u64, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        let staging = rtx.open_table(STAGING)?;
        let (lo, hi) = staging_range(push_id);
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

    /// Drop the staging of every push idle past `ttl_secs` (§15); never touches durable objects.
    pub fn reclaim_staging(&self, now: u64, ttl_secs: u64) -> Result<u64, StoreError> {
        let cutoff = now.saturating_sub(ttl_secs);
        let wtx = self.db.begin_write()?;
        let mut reclaimed = 0u64;
        {
            let mut staging = wtx.open_table(STAGING)?;
            let mut meta = wtx.open_table(STAGING_META)?;
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
                let (lo, hi) = staging_range(pid);
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
        if reclaimed > 0 {
            wtx.commit()?;
        } else {
            wtx.abort()?;
        }
        Ok(reclaimed)
    }

    /// Delete `ids` from durable storage (the local cache's retention drop); returns the count removed.
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
        if removed > 0 {
            wtx.commit()?;
        } else {
            wtx.abort()?;
        }
        Ok(removed)
    }

    /// §15 prune: recompute refs + roster length and delete `ids` only if `accept` approves, in one transaction.
    pub fn prune_if<F>(&self, ids: &[[u8; 32]], accept: F) -> Result<bool, StoreError>
    where
        F: FnOnce(&[RefBlobHash], u64) -> bool,
    {
        let wtx = self.db.begin_write()?;
        let matched = {
            let mut refs: Vec<RefBlobHash> = Vec::new();
            {
                let table = wtx.open_table(REFS)?;
                for item in table.iter()? {
                    let (k, v) = item?;
                    if let Ok(ref_h) = <[u8; 32]>::try_from(k.value()) {
                        refs.push((ref_h, *blake3::hash(v.value()).as_bytes()));
                    }
                }
            }
            let roster_len = wtx.open_table(ROSTER)?.len()?;
            if accept(&refs, roster_len) {
                let mut objs = wtx.open_table(OBJECTS)?;
                for id in ids {
                    objs.remove(&id[..])?;
                }
                true
            } else {
                false
            }
        };
        if matched {
            wtx.commit()?;
        } else {
            wtx.abort()?;
        }
        Ok(matched)
    }

    /// Delete every durable object not in `keep` (the local cache's orphan sweep); returns the count removed.
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
        if to_delete.is_empty() {
            wtx.abort()?;
            return Ok(0);
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

    /// Number of distinct durable objects.
    pub fn object_count(&self) -> Result<u64, StoreError> {
        let rtx = self.db.begin_read()?;
        let objs = rtx.open_table(OBJECTS)?;
        Ok(objs.len()?)
    }

    /// Compact the file (needs exclusive access); `true` if it shrank. Best-effort.
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

    fn entries(v: &[&[u8]]) -> Vec<Vec<u8>> {
        v.iter().map(|e| e.to_vec()).collect()
    }

    fn append(s: &Store, tip: [u8; 32], e: &[Vec<u8>]) -> Option<u64> {
        s.roster_batch(&RosterBatch {
            expected_tip: tip,
            entries: e,
            keyslots: &[],
            keyhist: None,
            roster_keyhist: None,
            revoke: &[],
            head: None,
        })
        .unwrap()
    }

    #[test]
    fn put_get_round_trip_and_missing() {
        let (_d, s) = temp_store();
        assert!(s.put(&id(1), b"hello").unwrap());
        assert_eq!(s.get(&id(1)).unwrap().as_deref(), Some(&b"hello"[..]));
        assert_eq!(s.get(&id(2)).unwrap(), None);
    }

    #[test]
    fn put_is_first_write_wins_and_put_many_counts_new() {
        let (_d, s) = temp_store();
        assert!(s.put(&id(1), b"a").unwrap());
        assert!(!s.put(&id(1), b"other").unwrap());
        assert_eq!(s.get(&id(1)).unwrap().as_deref(), Some(&b"a"[..]));
        assert_eq!(
            s.put_many(&[(id(1), b"a"), (id(2), b"b"), (id(3), b"c")])
                .unwrap(),
            2
        );
        assert_eq!(s.object_count().unwrap(), 3);
    }

    #[test]
    fn stage_is_invisible_until_a_winning_cas_head_promotes_it() {
        let (_d, s) = temp_store();
        let push = [0x07u8; 16];
        let ref_h = id(0xCA);

        s.stage(&push, &id(1), b"alpha", 100).unwrap();
        s.stage(&push, &id(2), b"beta", 100).unwrap();
        assert_eq!(s.has(&[id(1), id(2)]).unwrap(), vec![false, false]);
        assert_eq!(s.get(&id(1)).unwrap(), None);
        assert_eq!(s.staged_bytes(&push).unwrap(), 9);
        assert_eq!(s.object_count().unwrap(), 0);

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
        assert!(
            s.cas_ref(&ref_h, &ABSENT_HEAD, b"v1", &[0u8; 16])
                .unwrap()
                .swapped
        );
        let out = s.cas_ref(&ref_h, &ABSENT_HEAD, b"v2", &push).unwrap();
        assert!(!out.swapped);
        assert_eq!(out.promoted_bytes, 0);
        assert_eq!(s.has(&[id(1)]).unwrap(), vec![false]);
        assert_eq!(s.staged_bytes(&push).unwrap(), 1, "staging survives");
    }

    /// A blob staged while an identical one is durable outlives a prune of that one: the promote reinstates it (§15).
    #[test]
    fn a_staged_copy_of_a_durable_object_outlives_its_prune() {
        let (_d, s) = temp_store();
        s.put(&id(1), b"old chunk").unwrap();
        let push = [0x0a; 16];
        s.stage(&push, &id(1), b"old chunk", 0).unwrap();
        assert!(s.prune_if(&[id(1)], |_, _| true).unwrap());
        let out = s.cas_ref(&id(0xCC), &ABSENT_HEAD, b"head", &push).unwrap();
        assert!(out.swapped);
        assert_eq!(out.promoted_bytes, 9);
        assert_eq!(s.get(&id(1)).unwrap().as_deref(), Some(&b"old chunk"[..]));
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("objects.redb");
        {
            let s = Store::open(&path).unwrap();
            s.put(&id(7), b"durable").unwrap();
        }
        let s2 = Store::open(&path).unwrap();
        assert_eq!(s2.get(&id(7)).unwrap().as_deref(), Some(&b"durable"[..]));
    }

    #[test]
    fn keyslot_exists_spans_generations() {
        let (_d, s) = temp_store();
        let dev_a = id(0xA0);
        let dev_b = id(0xB0);
        assert!(!s.keyslot_exists(&dev_a).unwrap());
        s.put_keyslot(&dev_a, 1, b"slot-a1").unwrap();
        s.put_keyslot(&dev_a, u32::MAX, b"slot-amax").unwrap();
        assert!(s.keyslot_exists(&dev_a).unwrap());
        assert!(!s.keyslot_exists(&dev_b).unwrap());
        assert_eq!(
            s.get_keyslot(&dev_a, u32::MAX).unwrap().as_deref(),
            Some(&b"slot-amax"[..])
        );
    }

    #[test]
    fn cas_ref_first_write_then_swap_then_conflict() {
        let (_d, s) = temp_store();
        let r = id(0x11);
        let p = [0u8; 16];
        assert!(s.cas_ref(&r, &ABSENT_HEAD, b"head-v1", &p).unwrap().swapped);
        assert!(!s.cas_ref(&r, &ABSENT_HEAD, b"head-vX", &p).unwrap().swapped);
        let cur_hash = *blake3::hash(b"head-v1").as_bytes();
        assert!(s.cas_ref(&r, &cur_hash, b"head-v2", &p).unwrap().swapped);
        assert!(!s.cas_ref(&r, &cur_hash, b"head-v3", &p).unwrap().swapped);
        assert_eq!(s.get_ref(&r).unwrap().as_deref(), Some(&b"head-v2"[..]));
    }

    #[test]
    fn roster_batch_chains_and_rejects_races() {
        let (_d, s) = temp_store();
        assert_eq!(append(&s, ABSENT_HEAD, &entries(&[b"genesis"])), Some(0));
        assert_eq!(append(&s, ABSENT_HEAD, &entries(&[b"genesis2"])), None);
        let tip0 = *blake3::hash(b"genesis").as_bytes();
        assert_eq!(append(&s, tip0, &entries(&[b"e1", b"e2"])), Some(1));
        assert_eq!(s.roster_len().unwrap(), 3);
        assert_eq!(append(&s, tip0, &entries(&[b"racer"])), None);
        assert_eq!(s.get_roster_entry(2).unwrap().as_deref(), Some(&b"e2"[..]));
    }

    /// §7: the genesis batch purges keyslots squatted before the first entry; later batches never do.
    #[test]
    fn genesis_batch_purges_squatted_keyslots() {
        let (_d, s) = temp_store();
        s.put_keyslot(&id(0xEE), 1, b"squatter").unwrap();
        let me = id(0xA1);
        let e = entries(&[b"genesis"]);
        let ks = [KeyslotWrite {
            device_id: me,
            gen: 1,
            blob: b"mine",
        }];
        let first = s
            .roster_batch(&RosterBatch {
                expected_tip: ABSENT_HEAD,
                entries: &e,
                keyslots: &ks,
                keyhist: None,
                roster_keyhist: None,
                revoke: &[],
                head: None,
            })
            .unwrap();
        assert_eq!(first, Some(0));
        assert!(!s.keyslot_exists(&id(0xEE)).unwrap(), "squatter purged");
        assert!(s.keyslot_exists(&me).unwrap());
        s.put_keyslot(&id(0xEF), 1, b"later").unwrap();
        let tip = *blake3::hash(b"genesis").as_bytes();
        assert_eq!(append(&s, tip, &entries(&[b"e1"])), Some(1));
        assert!(s.keyslot_exists(&id(0xEF)).unwrap());
    }

    /// §8.4: one batch appends, writes keyslots + wraps, deletes every revoked generation, and swaps the head.
    #[test]
    fn rotation_batch_is_all_or_nothing() {
        let (_d, s) = temp_store();
        let (a, b) = (id(0xA1), id(0xB1));
        assert_eq!(append(&s, ABSENT_HEAD, &entries(&[b"g"])), Some(0));
        s.put_keyslot(&b, 1, b"b1").unwrap();
        s.put_keyslot(&b, 2, b"b2").unwrap();
        s.cas_ref(&id(0x33), &ABSENT_HEAD, b"head", &[0; 16])
            .unwrap();
        let tip = *blake3::hash(b"g").as_bytes();
        let e = entries(&[b"revoke-b", b"rotate"]);
        let ks = [KeyslotWrite {
            device_id: a,
            gen: 3,
            blob: b"a3",
        }];
        let head = HeadSwap {
            ref_h: id(0x33),
            expected_old: *blake3::hash(b"head").as_bytes(),
            new_blob: b"head-resigned",
        };
        let batch = RosterBatch {
            expected_tip: tip,
            entries: &e,
            keyslots: &ks,
            keyhist: Some((2, b"kh2")),
            roster_keyhist: Some((2, b"rkh2")),
            revoke: &[b],
            head: Some(head),
        };

        // A stale head token aborts everything.
        let stale = RosterBatch {
            head: Some(HeadSwap {
                expected_old: ABSENT_HEAD,
                ..head
            }),
            ..batch
        };
        assert_eq!(s.roster_batch(&stale).unwrap(), None);
        assert_eq!(s.roster_len().unwrap(), 1);
        assert!(s.keyslot_exists(&b).unwrap());
        assert_eq!(s.get_keyhist(2).unwrap(), None);

        assert_eq!(s.roster_batch(&batch).unwrap(), Some(1));
        assert_eq!(s.roster_len().unwrap(), 3);
        assert!(!s.keyslot_exists(&b).unwrap(), "every generation deleted");
        assert_eq!(s.get_keyslot(&a, 3).unwrap().as_deref(), Some(&b"a3"[..]));
        assert_eq!(s.get_keyhist(2).unwrap().as_deref(), Some(&b"kh2"[..]));
        assert_eq!(
            s.get_roster_keyhist(2).unwrap().as_deref(),
            Some(&b"rkh2"[..])
        );
        assert_eq!(
            s.get_ref(&id(0x33)).unwrap().as_deref(),
            Some(&b"head-resigned"[..])
        );

        // A wrap the chain has rotated past is never replaced: a batch that would overwrite one aborts.
        let tip2 = *blake3::hash(b"rotate").as_bytes();
        let e2 = entries(&[b"x"]);
        let clobber = RosterBatch {
            expected_tip: tip2,
            entries: &e2,
            keyslots: &[],
            keyhist: Some((2, b"evil")),
            roster_keyhist: None,
            revoke: &[],
            head: None,
        };
        assert_eq!(s.roster_batch(&clobber).unwrap(), None);
        assert_eq!(s.get_keyhist(2).unwrap().as_deref(), Some(&b"kh2"[..]));
    }

    /// A wrap left at the tip's own generation (an aborted rotation) is replaceable; one rotated past never is.
    #[test]
    fn dangling_key_history_is_replaceable_only_before_its_rotation() {
        let (_d, s) = temp_store();
        let entry = |gen: u32, body: &[u8]| {
            let mut b = secsec_frame::Frame::v2(gen, secsec_frame::ObjType::RosterEntry)
                .encode()
                .to_vec();
            b.extend_from_slice(body);
            b
        };
        let batch = |tip: [u8; 32], e: &[Vec<u8>], wrap: &'static [u8]| {
            s.roster_batch(&RosterBatch {
                expected_tip: tip,
                entries: e,
                keyslots: &[],
                keyhist: Some((1, wrap)),
                roster_keyhist: Some((1, wrap)),
                revoke: &[],
                head: None,
            })
            .unwrap()
        };
        let g = [entry(1, b"genesis")];
        assert_eq!(append(&s, ABSENT_HEAD, &g), Some(0));
        let e1 = [entry(1, b"no-rotate")];
        let tip = *blake3::hash(&g[0]).as_bytes();
        assert_eq!(batch(tip, &e1, b"dangling"), Some(1));

        let rot = [entry(2, b"rotate")];
        let tip = *blake3::hash(&e1[0]).as_bytes();
        assert_eq!(batch(tip, &rot, b"real"), Some(2));
        assert_eq!(s.get_keyhist(1).unwrap().as_deref(), Some(&b"real"[..]));

        let late = [entry(2, b"later")];
        let tip = *blake3::hash(&rot[0]).as_bytes();
        assert_eq!(batch(tip, &late, b"evil"), None);
        assert_eq!(s.get_keyhist(1).unwrap().as_deref(), Some(&b"real"[..]));
        assert_eq!(
            s.get_roster_keyhist(1).unwrap().as_deref(),
            Some(&b"real"[..])
        );
    }

    #[test]
    fn reclaim_drops_idle_pushes_keeps_fresh_ones_and_never_touches_objects() {
        let (_d, s) = temp_store();
        s.put(&id(1), b"durable").unwrap();
        let idle = [0x01u8; 16];
        let live = [0x02u8; 16];
        s.stage(&idle, &id(2), b"old", 100).unwrap();
        s.stage(&live, &id(3), b"new", 1000).unwrap();
        assert_eq!(s.reclaim_staging(1000, 600).unwrap(), 1);
        assert_eq!(s.staged_bytes(&idle).unwrap(), 0, "idle push reaped");
        assert_eq!(s.staged_bytes(&live).unwrap(), 3, "live push survives");
        assert_eq!(s.get(&id(1)).unwrap().as_deref(), Some(&b"durable"[..]));
        assert_eq!(s.reclaim_staging(1000, 600).unwrap(), 0);
    }

    #[test]
    fn delete_objects_removes_durable_ids() {
        let (_d, s) = temp_store();
        s.put(&id(1), b"a").unwrap();
        s.put(&id(2), b"b").unwrap();
        s.put(&id(3), b"c").unwrap();
        assert_eq!(s.delete_objects(&[id(1), id(3), id(9)]).unwrap(), 2);
        assert_eq!(s.get(&id(1)).unwrap(), None);
        assert_eq!(s.object_count().unwrap(), 1);
        assert_eq!(s.delete_objects(&[id(9)]).unwrap(), 0);
    }

    #[test]
    fn prune_if_deletes_only_when_the_predicate_accepts() {
        let (_d, s) = temp_store();
        s.put(&id(1), b"a").unwrap();
        s.put(&id(2), b"b").unwrap();
        assert!(!s.prune_if(&[id(1)], |_refs, _n| false).unwrap());
        assert_eq!(s.object_count().unwrap(), 2);
        assert!(s.prune_if(&[id(1)], |_refs, _n| true).unwrap());
        assert_eq!(s.get(&id(1)).unwrap(), None);

        s.cas_ref(&id(0xCA), &ABSENT_HEAD, b"head", &[0u8; 16])
            .unwrap();
        append(&s, ABSENT_HEAD, &entries(&[b"genesis"]));
        let mut seen = None;
        s.prune_if(&[id(2)], |refs, n| {
            seen = Some((refs.len(), n));
            false
        })
        .unwrap();
        assert_eq!(seen, Some((1usize, 1u64)));
        assert_eq!(s.get(&id(2)).unwrap().as_deref(), Some(&b"b"[..]));
    }

    #[test]
    fn retain_keeps_only_the_given_set() {
        let (_d, s) = temp_store();
        for b in 1..=3 {
            s.put(&id(b), b"x").unwrap();
        }
        let keep: std::collections::BTreeSet<[u8; 32]> = [id(2)].into_iter().collect();
        assert_eq!(s.retain(&keep).unwrap(), 2);
        assert_eq!(s.retain(&keep).unwrap(), 0);
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
        s.compact().unwrap();
        let compacted = std::fs::metadata(&path).unwrap().len();
        assert!(
            compacted < grown,
            "compaction reclaims deleted space ({grown} -> {compacted})"
        );
    }
}
