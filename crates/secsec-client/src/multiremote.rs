//! Multi-remote durability & reconciliation (`secsec-Design.md` §14, security property P15).
//!
//! ┌──────────────────────────────────────────────────────────────────────────────────────────┐
//! │ **NOT WIRED.** No `secsec` CLI command calls anything in this module — `secsec sync` takes  │
//! │ a single `--server`. This is a complete, tested implementation with no caller.              │
//! │                                                                                             │
//! │ **Purpose (Design §14 / P15):** durability against a *malicious* server (the primary        │
//! │ adversary). A server can refuse or delete; the defence is replicating to ≥2 independent      │
//! │ servers and retaining local objects until a quorum has each passed put→get→verify, plus      │
//! │ cross-remote checks that expose a server hiding a revocation (shorter sigchain) or serving a  │
//! │ stale head. Until this is wired, durability is "your one server + your backups of it."       │
//! │                                                                                             │
//! │ **To wire it:** let the CLI take N servers (link + `--server` repeatable), connect to each,   │
//! │ and in the sync loop call [`reconcile_roster_tips`] / [`detect_head_rollback`] before         │
//! │ adopting state and [`quorum_put_objects`] on push. The primitives below are ready for that.   │
//! └──────────────────────────────────────────────────────────────────────────────────────────┘
//!
//! Remotes are pure content-addressed **replicas**; the client is the sole reconciler. This module
//! provides the three §14 primitives, built on the [`Remote`] abstraction:
//!
//! - [`quorum_put_objects`] — **P15 quorum**: push a commit's object closure to each remote, then
//!   **put→get→verify** (re-fetch and byte-check) on each; only a remote that returns exactly what was
//!   stored counts toward the quorum. A remote that acks `put` but serves garbage is not counted.
//! - [`reconcile_roster_tips`] — **sigchain cross-remote check**: fold each remote's chain against the
//!   RFP, adopt the **longest valid** chain (highest `roster_seq`), and flag any remote presenting a
//!   shorter valid chain (a possible hidden `RevokeDevice`) or an invalid one (forgery) as an alarm.
//! - [`detect_head_rollback`] — **per-ref head check**: flag any remote whose `head_version` is below
//!   both the max seen across remotes and the client's persisted high-water (a head rollback).

use crate::repo::{fetch_roster_entries, open_repo_remote, RepoError};
use crate::{ClientError, Remote};
use secsec_kdf::MasterKeys;
use secsec_object::Id;
use secsec_sig::DeviceKey;
use secsec_snapshot::reachable_objects;
use secsec_store::Store;

/// The result of a [`quorum_put_objects`] push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumResult {
    /// Number of remotes that passed put→get→verify for **every** object in the closure.
    pub confirmed: usize,
    /// Whether `confirmed ≥ quorum`. The client retains local objects until this is true (§14/P15).
    pub met: bool,
    /// Indices (into the `remotes` slice) of the remotes that fully confirmed.
    pub confirmed_remotes: Vec<usize>,
}

/// Push the reachable object closure of `commit_id` to each remote and **verify durability** (P15):
/// for every object, `put` then `get` and byte-check the returned blob against what was stored. A
/// remote that fails any object's verification does not count. Returns the [`QuorumResult`]; the
/// caller retains local objects until `met` (a configured `quorum`, ≥2, §14/§19).
pub async fn quorum_put_objects<R: Remote, K: MasterKeys>(
    remotes: &[&R],
    store: &Store,
    keys: &K,
    commit_id: &Id,
    quorum: usize,
) -> Result<QuorumResult, ClientError> {
    let ids = reachable_objects(keys, store, &[*commit_id])?;
    let mut confirmed_remotes = Vec::new();

    for (idx, remote) in remotes.iter().enumerate() {
        let mut ok = true;
        for id in &ids {
            let blob = store.get(id)?.ok_or(ClientError::MissingLocal(*id))?;
            remote.put_blob(id, &blob).await?;
            // put→get→verify (§14): a remote that acks put but returns garbage is not counted.
            match remote.get_blob(id).await? {
                Some(got) if got == blob => {}
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            confirmed_remotes.push(idx);
        }
    }

    let confirmed = confirmed_remotes.len();
    Ok(QuorumResult {
        confirmed,
        met: confirmed >= quorum,
        confirmed_remotes,
    })
}

/// The result of reconciling sigchain tips across remotes (§14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileResult {
    /// The index of the remote with the longest valid (RFP-anchored) chain — the one to adopt.
    pub best: Option<usize>,
    /// The highest valid `roster_seq` (chain length − 1) seen.
    pub best_roster_seq: u64,
    /// Remotes presenting a **valid but shorter** chain than `best` — a possible hidden revocation; a
    /// rollback **alarm** to surface to the user (§14).
    pub rollback_alarms: Vec<usize>,
    /// Remotes whose chain did **not** fold to the RFP (forged/corrupt) — a forgery alarm.
    pub invalid: Vec<usize>,
}

/// Fold each remote's sigchain against the pinned `rfp` and pick the **longest valid** chain to adopt
/// (§14). A remote whose chain is valid but shorter than the winner is a `rollback_alarm` (it may be
/// hiding a `RevokeDevice` — it presents a lower `roster_seq` than the honest remotes); a chain that
/// fails to fold to the RFP is `invalid` (forgery). `device` is needed to unwrap each remote's keyslot
/// during the fold (genesis generation; §8.1).
pub async fn reconcile_roster_tips<R: Remote>(
    remotes: &[&R],
    device: &DeviceKey,
    rfp: &[u8; 32],
) -> Result<ReconcileResult, ClientError> {
    let mut valid: Vec<(usize, u64)> = Vec::new(); // (remote idx, roster_seq)
    let mut invalid: Vec<usize> = Vec::new();

    for (idx, remote) in remotes.iter().enumerate() {
        let entries = fetch_roster_entries(*remote).await?;
        if entries.is_empty() {
            invalid.push(idx);
            continue;
        }
        // open_repo_remote folds the chain and verifies the RFP anchor + mk_commit; Ok ⇒ trustworthy.
        match open_repo_remote(*remote, device, rfp, None).await {
            Ok(_) => valid.push((idx, (entries.len() as u64) - 1)),
            // A chain that doesn't fold to the RFP (forged), or that this device can't open, is flagged.
            Err(RepoError::Roster(_)) => invalid.push(idx),
            Err(e) => return Err(ClientError::from(e)),
        }
    }

    let best_roster_seq = valid.iter().map(|(_, s)| *s).max().unwrap_or(0);
    let best = valid
        .iter()
        .filter(|(_, s)| *s == best_roster_seq)
        .map(|(i, _)| *i)
        .next();
    let rollback_alarms = valid
        .iter()
        .filter(|(_, s)| *s < best_roster_seq)
        .map(|(i, _)| *i)
        .collect();

    Ok(ReconcileResult {
        best,
        best_roster_seq,
        rollback_alarms,
        invalid,
    })
}

/// Detect a per-ref head rollback across remotes (§14). `observations` are `(remote_idx,
/// head_version)` for one ref; `hwm` is the client's persisted high-water for that ref's owning device
/// (§8.5). Returns the remotes presenting a `head_version` **strictly below both** the max seen across
/// remotes **and** `hwm` — a head-rollback **alarm** (a remote serving a stale head). A remote at or
/// above the max, or above the hwm, is not flagged.
#[must_use]
pub fn detect_head_rollback(observations: &[(usize, u64)], hwm: u64) -> Vec<usize> {
    let max_seen = observations.iter().map(|(_, v)| *v).max().unwrap_or(0);
    observations
        .iter()
        .filter(|(_, v)| *v < max_seen && *v < hwm)
        .map(|(i, _)| *i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{repo::init_repo, GcOutcome, Receipt, RemoteError};
    use secsec_kdf::MasterKey;

    /// In-process [`Remote`] over a real [`Store`]; `lie_on_get` makes it serve garbage on `get_blob`
    /// (an acks-put-but-returns-garbage remote, for the P15 quorum test).
    struct MemRemote {
        store: Store,
        lie_on_get: bool,
    }
    impl MemRemote {
        fn new(store: Store) -> Self {
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
            Ok(Receipt::unsigned(1, 1))
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
        async fn get_keyslot(&self, did: &Id, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
            self.store
                .get_keyslot(did, gen)
                .map_err(|e| RemoteError(e.to_string()))
        }
        async fn cas_head(
            &self,
            ref_h: &Id,
            old: &Id,
            new_blob: &[u8],
        ) -> Result<bool, RemoteError> {
            self.store
                .cas_ref(ref_h, old, new_blob)
                .map_err(|e| RemoteError(e.to_string()))
        }
        async fn gc(
            &self,
            keep: Vec<Id>,
            gc_gen: u64,
            _ahh: &[u8; 32],
            _rs: u64,
            _pe: u64,
        ) -> Result<GcOutcome, RemoteError> {
            let k: std::collections::BTreeSet<[u8; 32]> = keep.into_iter().collect();
            self.store
                .gc(&k, gc_gen)
                .map(|_| GcOutcome::Swept)
                .map_err(|e| RemoteError(e.to_string()))
        }
    }

    fn store(dir: &std::path::Path, n: &str) -> Store {
        Store::open(dir.join(n)).unwrap()
    }

    #[tokio::test]
    async fn quorum_counts_only_verifying_remotes() {
        let dir = tempfile::tempdir().unwrap();
        let m = MasterKey::new(1, [0x71; 32]);
        let device = DeviceKey::generate().unwrap();

        // local store with a snapshot commit.
        let local = store(dir.path(), "local.redb");
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f.txt"), b"durable").unwrap();
        let (rt, rs) = secsec_snapshot::snapshot_tree(src.path(), &m, &local, None).unwrap();
        let commit = secsec_snapshot::Commit {
            root_tree: rt,
            root_salt: rs,
            parents: vec![],
            device_id: device.device_id().unwrap(),
            version: 1,
            roster_seq: 0,
            last_seen_head: [0u8; 32],
            ts: 0,
        };
        let cid = secsec_snapshot::seal_signed_commit(&m, &local, &device, &commit).unwrap();

        let honest1 = MemRemote::new(store(dir.path(), "r1.redb"));
        let honest2 = MemRemote::new(store(dir.path(), "r2.redb"));
        let mut liar = MemRemote::new(store(dir.path(), "r3.redb"));
        liar.lie_on_get = true;

        let remotes: Vec<&MemRemote> = vec![&honest1, &honest2, &liar];
        let r = quorum_put_objects(&remotes, &local, &m, &cid, 2)
            .await
            .unwrap();
        // both honest remotes confirm; the liar (garbage on get) does not.
        assert_eq!(r.confirmed, 2);
        assert!(r.met);
        assert_eq!(r.confirmed_remotes, vec![0, 1]);

        // requiring a quorum of 3 is NOT met (the liar fails verification).
        let r3 = quorum_put_objects(&remotes, &local, &m, &cid, 3)
            .await
            .unwrap();
        assert_eq!(r3.confirmed, 2);
        assert!(!r3.met);
    }

    #[tokio::test]
    async fn reconcile_adopts_longest_chain_and_flags_laggard() {
        let dir = tempfile::tempdir().unwrap();
        let device = DeviceKey::generate().unwrap();

        // remote A: genesis repo (chain length 1, roster_seq 0).
        let a = MemRemote::new(store(dir.path(), "a.redb"));
        let rfp = init_repo(&a.store, &device, 0).unwrap();

        // remote B: a fresh empty store (no roster) — invalid / hiding everything.
        let b = MemRemote::new(store(dir.path(), "b.redb"));

        let remotes: Vec<&MemRemote> = vec![&a, &b];
        let r = reconcile_roster_tips(&remotes, &device, &rfp)
            .await
            .unwrap();
        assert_eq!(r.best, Some(0)); // adopt A
        assert_eq!(r.best_roster_seq, 0);
        assert_eq!(r.invalid, vec![1]); // B has no chain → flagged
    }

    #[test]
    fn head_rollback_flags_stale_remotes() {
        // remote 0 at v5, remote 1 at v5, remote 2 at v3 (stale); persisted hwm 4.
        let obs = [(0, 5u64), (1, 5), (2, 3)];
        // remote 2: v3 < max(5) AND v3 < hwm(4) → flagged.
        assert_eq!(detect_head_rollback(&obs, 4), vec![2]);
        // with a lower hwm (2), remote 2's v3 is >= hwm → not a frontier rollback, not flagged.
        assert!(detect_head_rollback(&obs, 2).is_empty());
        // all equal → nothing flagged.
        assert!(detect_head_rollback(&[(0, 5), (1, 5)], 5).is_empty());
    }
}
