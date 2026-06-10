//! Shared test-only in-process [`Remote`] over a real [`Store`] — the single home for what were four
//! byte-identical per-module copies (`lib`/`sync`/`multiremote`/`gossip` tests). It exercises the exact
//! blind-CAS semantics the QUIC server uses (`cas_ref` = `BLAKE3`-of-blob compare), minus the network.
//!
//! `lie_on_get` makes `get_blob` serve garbage (an acks-put-but-returns-garbage remote, for the P15
//! quorum test). The module is `#[cfg(test)]` (gated by its declaration in `lib.rs`), so it only exists
//! in test builds, where every test module uses it.

use crate::{GcOutcome, Receipt, Remote, RemoteError};
use secsec_object::Id;
use secsec_store::Store;

/// An in-process [`Remote`] backed by a real [`Store`].
pub(crate) struct MemRemote {
    /// The backing object/ref/keyslot store.
    pub store: Store,
    /// When set, `get_blob` returns garbage instead of the stored blob (durability/quorum tests).
    pub lie_on_get: bool,
}

impl MemRemote {
    /// A truthful in-process remote over `store`.
    pub fn new(store: Store) -> Self {
        Self {
            store,
            lie_on_get: false,
        }
    }
}

impl Remote for MemRemote {
    async fn get_blob(&self, id: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        if self.lie_on_get {
            return Ok(Some(b"garbage".to_vec()));
        }
        self.store.get(id).map_err(|e| RemoteError(e.to_string()))
    }
    async fn put_blob(&self, id: &Id, blob: &[u8]) -> Result<Receipt, RemoteError> {
        self.store
            .put(id, blob)
            .map_err(|e| RemoteError(e.to_string()))?;
        let arrival_gen = self
            .store
            .arrival_epoch(id)
            .map_err(|e| RemoteError(e.to_string()))?
            .unwrap_or(0);
        let put_epoch = self
            .store
            .put_epoch()
            .map_err(|e| RemoteError(e.to_string()))?;
        Ok(Receipt::unsigned(arrival_gen, put_epoch))
    }
    async fn get_ref(&self, ref_h: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store
            .get_ref(ref_h)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn get_roster_entry(&self, seq: u64) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store
            .get_roster_entry(seq)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn get_keyslot(&self, device_id: &Id, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store
            .get_keyslot(device_id, gen)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn cas_head(
        &self,
        ref_h: &Id,
        expected_old: &Id,
        new_blob: &[u8],
    ) -> Result<bool, RemoteError> {
        self.store
            .cas_ref(ref_h, expected_old, new_blob)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn gc(
        &self,
        keep_set: Vec<Id>,
        gc_gen: u64,
        _all_heads_hash: &[u8; 32],
        _roster_seq: u64,
        _put_epoch: u64,
    ) -> Result<GcOutcome, RemoteError> {
        let keep: std::collections::BTreeSet<[u8; 32]> = keep_set.into_iter().collect();
        self.store
            .gc(&keep, gc_gen)
            .map(|_| GcOutcome::Swept)
            .map_err(|e| RemoteError(e.to_string()))
    }
}
