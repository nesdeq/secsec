//! Test-only in-process [`Remote`] over a real [`Store`], with the server's CAS, batch, prune, and mailbox semantics minus auth.

use crate::{Remote, RemoteError, RosterWrite};
use secsec_object::Id;
use secsec_proto::PUSH_ID_LEN;
use secsec_roster::State;
use secsec_sig::{DeviceId, DeviceKey, DevicePublic};
use secsec_store::{HeadSwap, KeyslotWrite, RosterBatch, Store};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

/// An in-process [`Remote`] backed by a real [`Store`].
pub(crate) struct MemRemote {
    /// The backing store.
    pub store: Store,
    /// How many upcoming roster batches to refuse as CAS conflicts without applying them.
    pub refuse_batches: AtomicU32,
    pairing: Mutex<BTreeMap<Id, Vec<u8>>>,
}

impl MemRemote {
    pub(crate) fn new(store: Store) -> Self {
        Self {
            store,
            refuse_batches: AtomicU32::new(0),
            pairing: Mutex::new(BTreeMap::new()),
        }
    }
}

fn local(e: impl std::fmt::Display) -> RemoteError {
    RemoteError::Local(e.to_string())
}

/// A folded-roster stand-in whose current and historical members are `devices`.
pub(crate) fn roster_of(devices: &[&DeviceKey]) -> State {
    let members: BTreeMap<DeviceId, DevicePublic> = devices
        .iter()
        .map(|d| (d.device_id().unwrap(), d.public()))
        .collect();
    State {
        ever_members: members.clone(),
        members,
        generation: 1,
        min_algo: secsec_frame::MIN_ALGO_ID,
        mk_commits: BTreeMap::new(),
        added_by: BTreeMap::new(),
        added_at: BTreeMap::new(),
        enroll_pubs: BTreeMap::new(),
        tip_seq: 0,
    }
}

impl Remote for MemRemote {
    async fn get_blob(&self, id: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store.get(id).map_err(local)
    }
    async fn put_blob(
        &self,
        id: &Id,
        blob: &[u8],
        push_id: &[u8; PUSH_ID_LEN],
    ) -> Result<(), RemoteError> {
        self.store.stage(push_id, id, blob, 0).map_err(local)
    }
    async fn has(&self, ids: &[Id]) -> Result<Vec<bool>, RemoteError> {
        self.store.has(ids).map_err(local)
    }
    async fn get_ref(&self, ref_h: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store.get_ref(ref_h).map_err(local)
    }
    async fn get_roster_entry(&self, seq: u64) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store.get_roster_entry(seq).map_err(local)
    }
    async fn get_keyslot(&self, device_id: &Id, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store.get_keyslot(device_id, gen).map_err(local)
    }
    async fn get_roster_keyhist(&self, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store.get_roster_keyhist(gen).map_err(local)
    }
    async fn get_keyhist(&self, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        self.store.get_keyhist(gen).map_err(local)
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
            .map_err(local)
    }
    async fn roster_batch(&self, w: &RosterWrite) -> Result<bool, RemoteError> {
        let refuse = self
            .refuse_batches
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if refuse {
            return Ok(false);
        }
        let keyslots: Vec<KeyslotWrite<'_>> = w
            .keyslots
            .iter()
            .map(|k| KeyslotWrite {
                device_id: k.device_id,
                gen: k.gen,
                blob: &k.blob,
            })
            .collect();
        self.store
            .roster_batch(&RosterBatch {
                expected_tip: w.old_tip,
                entries: &w.entries,
                keyslots: &keyslots,
                keyhist: w.keyhist.as_ref().map(|(g, b)| (*g, b.as_slice())),
                roster_keyhist: w.roster_keyhist.as_ref().map(|(g, b)| (*g, b.as_slice())),
                revoke: &w.revoke,
                head: w.head.as_ref().map(|h| HeadSwap {
                    ref_h: h.ref_h,
                    expected_old: h.old_head,
                    new_blob: &h.new_blob,
                }),
            })
            .map(|seq| seq.is_some())
            .map_err(local)
    }
    async fn prune(
        &self,
        dead: &[Id],
        all_heads_hash: &[u8; 32],
        roster_len: u64,
    ) -> Result<bool, RemoteError> {
        self.store
            .prune_if(dead, |refs, len| {
                secsec_proto::prune::all_heads_hash(refs) == *all_heads_hash && len == roster_len
            })
            .map_err(local)
    }
    async fn pair_put(&self, slot: &Id, blob: &[u8]) -> Result<(), RemoteError> {
        self.pairing
            .lock()
            .expect("pairing mailbox")
            .insert(*slot, blob.to_vec());
        Ok(())
    }
    async fn pair_get(&self, slot: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        Ok(self.pairing.lock().expect("pairing mailbox").remove(slot))
    }
}
