//! Shared test-only in-process [`Remote`] over a real [`Store`] — the single home for what were
//! byte-identical per-module copies (`lib`/`sync` tests). It exercises the exact blind-CAS semantics
//! the QUIC server uses (`cas_ref` = `BLAKE3`-of-blob compare), minus the network. The module is
//! `#[cfg(test)]` (gated by its declaration in `lib.rs`), so it only exists in test builds.

use crate::{Remote, RemoteError};
use secsec_object::Id;
use secsec_proto::PUSH_ID_LEN;
use secsec_store::Store;

/// An in-process [`Remote`] backed by a real [`Store`].
pub(crate) struct MemRemote {
    /// The backing object/ref/keyslot store.
    pub store: Store,
}

impl MemRemote {
    /// A truthful in-process remote over `store`.
    pub(crate) fn new(store: Store) -> Self {
        Self { store }
    }
}

impl Remote for MemRemote {
    async fn get_blob(&self, id: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store.get(id).map_err(|e| RemoteError(e.to_string()))
    }
    async fn put_blob(
        &self,
        id: &Id,
        blob: &[u8],
        push_id: &[u8; PUSH_ID_LEN],
    ) -> Result<(), RemoteError> {
        self.store
            .stage(push_id, id, blob, 0)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn has(&self, ids: &[Id]) -> Result<Vec<bool>, RemoteError> {
        self.store.has(ids).map_err(|e| RemoteError(e.to_string()))
    }
    async fn has_for_push(
        &self,
        push_id: &[u8; PUSH_ID_LEN],
        ids: &[Id],
    ) -> Result<Vec<bool>, RemoteError> {
        self.store
            .has_for_push(push_id, ids)
            .map_err(|e| RemoteError(e.to_string()))
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
    async fn get_keyhist(&self, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store
            .get_keyhist(gen)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn get_roster_keyhist(&self, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store
            .get_roster_keyhist(gen)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn cas_head(
        &self,
        ref_h: &Id,
        expected_old: &Id,
        new_blob: &[u8],
        promote: &[u8; PUSH_ID_LEN],
    ) -> Result<bool, RemoteError> {
        self.store
            .cas_ref(ref_h, expected_old, new_blob, promote)
            .map(|o| o.swapped)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn prune(
        &self,
        dead: &[Id],
        _all_heads_hash: &[u8; 32],
        _roster_seq: u64,
    ) -> Result<bool, RemoteError> {
        self.store
            .delete_objects(dead)
            .map(|_| true)
            .map_err(|e| RemoteError(e.to_string()))
    }
    // Enrollment ops (delegating to the store), so the in-process remote can drive the genesis /
    // grant / rotate flows (`init_repo_remote`, `grant_device_remote`, `rotate_repo_remote`) too.
    async fn put_keyslot(&self, device_id: &Id, gen: u32, blob: &[u8]) -> Result<(), RemoteError> {
        self.store
            .put_keyslot(device_id, gen, blob)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn roster_append(&self, old_tip: &Id, entry: &[u8]) -> Result<bool, RemoteError> {
        self.store
            .append_roster(old_tip, entry)
            .map(|seq| seq.is_some())
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn put_keyhist(&self, gen: u32, blob: &[u8]) -> Result<(), RemoteError> {
        self.store
            .put_keyhist(gen, blob)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn put_roster_keyhist(&self, gen: u32, blob: &[u8]) -> Result<(), RemoteError> {
        self.store
            .put_roster_keyhist(gen, blob)
            .map_err(|e| RemoteError(e.to_string()))
    }
    async fn delete_keyslot(&self, device_id: &Id, gen: u32) -> Result<(), RemoteError> {
        self.store
            .delete_keyslot(device_id, gen)
            .map(|_| ())
            .map_err(|e| RemoteError(e.to_string()))
    }
}
