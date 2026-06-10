//! Cross-remote fork detection (`finaldesign.md` §10 fork algorithm, §14 multi-remote cross-check).
//!
//! "Gossip" of head hashes shrinks the fork-detection window: when two devices write to different
//! remotes while partitioned, their per-ref heads become **DAG-incomparable** (neither an ancestor of
//! the other). [`cross_remote_fork_scan`] fetches each remote's head for a ref, brings its commit
//! closure local, and checks it against our head over the commit DAG ([`secsec_sync::dag`]); a
//! provable fork is recorded as a [`ForkEvent`] (the §10 step-3 audit record). The actual *resolution*
//! is the existing rollback-gated three-way merge ([`crate::sync_ref`]) — this is detection + logging.
//!
//! Device-to-device gossip (exchanging head ids over a direct channel) runs the **same** fork check on
//! the same inputs; it is a thin transport over this logic, not new crypto.

use crate::{fetch_closure, fetch_head, resolve_head_signer, ClientError, Remote};
use secsec_canon::{Reader, Writer};
use secsec_kdf::MasterKey;
use secsec_object::Id;
use secsec_sig::{DeviceId, DevicePublic};
use secsec_store::Store;
use secsec_sync::dag::incomparable;
use std::collections::BTreeMap;
use std::path::Path;

/// A provable fork, for the §10 audit log: our head, the divergent (DAG-incomparable) head, the device
/// that signed it, and the index of the remote that served it. `detected_at` is the client's wall-clock
/// (caller-supplied) — advisory, for user review only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkEvent {
    /// Our current head commit (`H_A`).
    pub our_head: Id,
    /// The divergent head commit (`H_B`), DAG-incomparable to ours.
    pub their_head: Id,
    /// The device that signed the divergent head (resolved from the roster), if a member; else `None`.
    pub their_device: Option<DeviceId>,
    /// The remote index (into the scanned slice) that served the divergent head.
    pub remote: usize,
    /// Client wall-clock at detection (advisory; §10 step 3).
    pub detected_at: u64,
}

/// Scan every remote's head for `ref_name` and report any that is **DAG-incomparable** to
/// `our_head_commit` — a provable fork (§10). For each remote: fetch its head, resolve+verify the
/// signer against `members`, bring its commit closure local (so the DAG is loadable), and compare over
/// the commit parent-DAG. A head equal to ours, or an ancestor/descendant of ours, is **not** a fork
/// (it is a fast-forward / already-held / behind). Returns one [`ForkEvent`] per forking remote.
///
/// This is detection only; the caller resolves a fork via [`crate::sync::sync_once`] /
/// [`crate::sync_ref`] (rollback-gated three-way merge) and SHOULD persist the events (§10 step 3).
pub async fn cross_remote_fork_scan<R: Remote>(
    remotes: &[&R],
    store: &Store,
    mk: &MasterKey,
    members: &BTreeMap<DeviceId, DevicePublic>,
    our_head_commit: &Id,
    ref_name: &str,
    now: u64,
) -> Result<Vec<ForkEvent>, ClientError> {
    let mut forks = Vec::new();

    for (idx, remote) in remotes.iter().enumerate() {
        let Some((head, sig, _blob)) = fetch_head(*remote, mk, ref_name).await? else {
            continue; // remote has no head for this ref
        };
        if head.commit_id == *our_head_commit {
            continue; // identical head — not a fork
        }
        let their_device = resolve_head_signer(members, &head, &sig);

        // Bring the remote head's closure local so both histories are in the DAG, then compare.
        fetch_closure(*remote, store, mk, &head.commit_id).await?;
        let (parents, _meta) =
            secsec_engine::load_commit_dag(&[*our_head_commit, head.commit_id], mk, store)?;

        if incomparable(&parents, our_head_commit, &head.commit_id) {
            forks.push(ForkEvent {
                our_head: *our_head_commit,
                their_head: head.commit_id,
                their_device,
                remote: idx,
                detected_at: now,
            });
        }
    }
    Ok(forks)
}

// ---- fork-event log (§10 step 3: persisted audit record) ----

impl ForkEvent {
    /// Canonical fixed-width encoding (§9.3): `our_head ‖ their_head ‖ has_device(u8) ‖ device(32) ‖
    /// remote(u64) ‖ detected_at(u64)`. The device field is present iff `has_device == 1`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&self.our_head).raw(&self.their_head);
        match self.their_device {
            Some(d) => {
                w.u8(1).raw(&d);
            }
            None => {
                w.u8(0).raw(&[0u8; 32]);
            }
        }
        w.u64(self.remote as u64).u64(self.detected_at);
        w.finish()
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, secsec_canon::CanonError> {
        let our_head = read32(r)?;
        let their_head = read32(r)?;
        let has_device = r.u8()?;
        let dev = read32(r)?;
        let remote = r.u64()? as usize;
        let detected_at = r.u64()?;
        Ok(ForkEvent {
            our_head,
            their_head,
            their_device: (has_device == 1).then_some(dev),
            remote,
            detected_at,
        })
    }
}

fn read32(r: &mut Reader<'_>) -> Result<Id, secsec_canon::CanonError> {
    let mut out = [0u8; 32];
    out.copy_from_slice(r.raw(32)?);
    Ok(out)
}

/// Append fork `events` to the §10-step-3 audit log at `path` (created if absent), each as a
/// length-prefixed canonical record. The log is **append-only** and unencrypted — fork ids are commit
/// content-addresses (not secret; the server already holds the objects), and the log's value is its
/// completeness for user review, so it is never rewritten.
pub fn append_fork_log(path: &Path, events: &[ForkEvent]) -> Result<(), ClientError> {
    use std::io::Write;
    if events.is_empty() {
        return Ok(());
    }
    let mut buf = Vec::new();
    for e in events {
        let rec = e.encode();
        buf.extend_from_slice(&(rec.len() as u32).to_le_bytes());
        buf.extend_from_slice(&rec);
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(&buf)?;
    Ok(())
}

/// Read the full fork-event log at `path` (empty if the file is absent). A truncated trailing record
/// (e.g. a crash mid-append) ends the read cleanly — earlier complete records are returned.
pub fn read_fork_log(path: &Path) -> Result<Vec<ForkEvent>, ClientError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(ClientError::Io(e)),
    };
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= bytes.len() {
        let len = u32::from_le_bytes(bytes[off..off + 4].try_into().expect("4 bytes")) as usize;
        off += 4;
        if off + len > bytes.len() {
            break; // truncated trailing record (crash mid-append) — stop cleanly.
        }
        let mut r = Reader::new(&bytes[off..off + len]);
        match ForkEvent::decode(&mut r) {
            Ok(e) if r.finish().is_ok() => out.push(e),
            _ => break, // malformed record — stop.
        }
        off += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{push_head, push_objects, GcOutcome, Receipt, RemoteError};
    use secsec_sig::DeviceKey;

    struct MemRemote {
        store: Store,
    }
    impl Remote for MemRemote {
        async fn get_blob(&self, id: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
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
        async fn get_keyslot(&self, d: &Id, g: u32) -> Result<Option<Vec<u8>>, RemoteError> {
            self.store
                .get_keyslot(d, g)
                .map_err(|e| RemoteError(e.to_string()))
        }
        async fn cas_head(&self, r: &Id, o: &Id, b: &[u8]) -> Result<bool, RemoteError> {
            self.store
                .cas_ref(r, o, b)
                .map_err(|e| RemoteError(e.to_string()))
        }
        async fn gc(
            &self,
            keep: Vec<Id>,
            g: u64,
            _a: &[u8; 32],
            _r: u64,
            _p: u64,
        ) -> Result<GcOutcome, RemoteError> {
            let k: std::collections::BTreeSet<[u8; 32]> = keep.into_iter().collect();
            self.store
                .gc(&k, g)
                .map(|_| GcOutcome::Swept)
                .map_err(|e| RemoteError(e.to_string()))
        }
    }

    fn commit(
        store: &Store,
        m: &MasterKey,
        dev: &DeviceKey,
        dir: &std::path::Path,
        parents: Vec<Id>,
    ) -> Id {
        let (rt, rs) = secsec_snapshot::snapshot_tree(dir, m, store, None).unwrap();
        let c = secsec_snapshot::Commit {
            root_tree: rt,
            root_salt: rs,
            parents,
            device_id: dev.device_id().unwrap(),
            version: 1,
            roster_seq: 0,
            last_seen_head: [0u8; 32],
            ts: 0,
        };
        secsec_snapshot::seal_signed_commit(m, store, dev, &c).unwrap()
    }

    #[tokio::test]
    async fn detects_divergent_head_as_fork() {
        let dir = tempfile::tempdir().unwrap();
        let m = MasterKey::new(1, [0x61; 32]);
        let dev = DeviceKey::generate().unwrap();
        let members: BTreeMap<DeviceId, DevicePublic> = [(dev.device_id().unwrap(), dev.public())]
            .into_iter()
            .collect();
        let local = Store::open(dir.path().join("local.redb")).unwrap();

        // base commit, then two DIVERGENT children A and B (both parented on base) — a fork.
        let bdir = tempfile::tempdir().unwrap();
        std::fs::write(bdir.path().join("f"), b"base").unwrap();
        let base = commit(&local, &m, &dev, bdir.path(), vec![]);

        let adir = tempfile::tempdir().unwrap();
        std::fs::write(adir.path().join("f"), b"branch-A").unwrap();
        let head_a = commit(&local, &m, &dev, adir.path(), vec![base]);

        let bbdir = tempfile::tempdir().unwrap();
        std::fs::write(bbdir.path().join("f"), b"branch-B").unwrap();
        let head_b = commit(&local, &m, &dev, bbdir.path(), vec![base]);

        // remote R1 publishes head B; our local head is A. They share `base` but are incomparable.
        let r1 = MemRemote {
            store: Store::open(dir.path().join("r1.redb")).unwrap(),
        };
        push_objects(&r1, &local, &m, &head_b).await.unwrap();
        push_head(&r1, &m, &dev, "main", head_b, 0, None)
            .await
            .unwrap();

        let remotes: Vec<&MemRemote> = vec![&r1];
        let forks = cross_remote_fork_scan(&remotes, &local, &m, &members, &head_a, "main", 42)
            .await
            .unwrap();
        assert_eq!(forks.len(), 1, "B is DAG-incomparable to A → fork");
        assert_eq!(forks[0].our_head, head_a);
        assert_eq!(forks[0].their_head, head_b);
        assert_eq!(forks[0].their_device, Some(dev.device_id().unwrap()));
        assert_eq!(forks[0].detected_at, 42);

        // a descendant head is NOT a fork: C parented on A (our head) → comparable.
        let cdir = tempfile::tempdir().unwrap();
        std::fs::write(cdir.path().join("f"), b"branch-A-next").unwrap();
        let head_c = commit(&local, &m, &dev, cdir.path(), vec![head_a]);
        let r2 = MemRemote {
            store: Store::open(dir.path().join("r2.redb")).unwrap(),
        };
        push_objects(&r2, &local, &m, &head_c).await.unwrap();
        push_head(&r2, &m, &dev, "main", head_c, 0, None)
            .await
            .unwrap();
        let remotes2: Vec<&MemRemote> = vec![&r2];
        let none = cross_remote_fork_scan(&remotes2, &local, &m, &members, &head_a, "main", 0)
            .await
            .unwrap();
        assert!(
            none.is_empty(),
            "a descendant head is a fast-forward, not a fork"
        );

        // persist the detected fork and read it back (§10 step 3).
        let log = dir.path().join("forks.log");
        append_fork_log(&log, &forks).unwrap();
        // a second append accumulates (append-only).
        let extra = ForkEvent {
            our_head: [9u8; 32],
            their_head: [8u8; 32],
            their_device: None,
            remote: 3,
            detected_at: 99,
        };
        append_fork_log(&log, std::slice::from_ref(&extra)).unwrap();

        let read = read_fork_log(&log).unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[0], forks[0]);
        assert_eq!(read[1], extra);
        assert_eq!(read[1].their_device, None); // None device round-trips
    }

    #[test]
    fn fork_log_round_trips_and_handles_absent_and_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("f.log");
        // absent file → empty.
        assert!(read_fork_log(&log).unwrap().is_empty());

        let e = ForkEvent {
            our_head: [1u8; 32],
            their_head: [2u8; 32],
            their_device: Some([3u8; 32]),
            remote: 0,
            detected_at: 7,
        };
        append_fork_log(&log, std::slice::from_ref(&e)).unwrap();
        assert_eq!(read_fork_log(&log).unwrap(), vec![e.clone()]);

        // a truncated trailing record (simulated crash mid-append) is dropped; prior records survive.
        let mut bytes = std::fs::read(&log).unwrap();
        bytes.extend_from_slice(&100u32.to_le_bytes()); // claims 100 more bytes, none follow
        bytes.push(0xAB);
        std::fs::write(&log, &bytes).unwrap();
        assert_eq!(read_fork_log(&log).unwrap(), vec![e]);
    }
}
