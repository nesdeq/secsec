//! One bidirectional sync of a working folder against a ref (`secsec-Design.md` §8.5, §10).

use crate::{
    fetch_closure, fetch_tree, fetch_verified_head, push_head, push_objects, ClientError, Remote,
    RemoteHead, Walk,
};
use secsec_engine::{
    accept_sibling, load_commit_dag, merge_accepted, merge_base, CommitAuthor, SyncAction,
};
use secsec_kdf::MasterKeys;
use secsec_object::{Id, PathSalt};
use secsec_proto::PUSH_ID_LEN;
use secsec_roster::State;
use secsec_sig::{DeviceId, DeviceKey};
use secsec_snapshot::{
    open_signed_commit, restore_commit_tree, seal_signed_commit, snapshot_tree, Commit, Prior,
    RestoreReport, SnapshotMemo,
};
use secsec_store::Store;
use secsec_sync::rollback::{MergeDecision, SyncFrontier};
use secsec_sync::NO_PREV_HEAD;
use std::path::Path;

/// What [`sync_once`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncKind {
    /// Nothing to do.
    UpToDate,
    /// First writer: our folder became the ref's first head.
    Published,
    /// A fresh link to an existing repo, nothing tracked locally: the head was restored.
    Cloned,
    /// The remote moved ahead of us and was restored.
    Pulled,
    /// Our commit was published on top of the remote head.
    Pushed,
    /// A divergent remote head was three-way merged, published, and restored.
    Merged,
}

/// The result of [`sync_once`]; the caller persists `base`, then `frontier` (§8.5).
#[derive(Debug, Clone)]
pub struct SyncOutcome {
    /// What happened.
    pub kind: SyncKind,
    /// The new last-synced commit.
    pub base: Option<Id>,
    /// The advanced frontier.
    pub frontier: SyncFrontier,
    /// Paths kept both ways: merge conflicts, and local edits made while the sync ran.
    pub conflicts: Vec<String>,
    /// Paths this device could not sync (too large, unreadable, or not creatable here).
    pub skipped: Vec<String>,
    /// The merge ran against an empty base because the common ancestor's tree is gone.
    pub base_missing: bool,
}

/// Everything one sync reads besides the remote, the frontier, and the base.
pub struct SyncInput<'a, K: MasterKeys> {
    /// The local object cache.
    pub store: &'a Store,
    /// The working folder.
    pub dir: &'a Path,
    /// The peeled key ring.
    pub keys: &'a K,
    /// This device's key.
    pub device: &'a DeviceKey,
    /// The folded roster.
    pub roster: &'a State,
    /// The ref this folder syncs.
    pub ref_name: &'a str,
    /// Advisory timestamp for new commits.
    pub ts: u64,
    /// This attempt's push id (§15).
    pub push_id: &'a [u8; PUSH_ID_LEN],
    /// Persists the frontier; runs before any ref-advancing push, and a failure aborts it (§8.5).
    pub seal: &'a dyn Fn(&SyncFrontier) -> Result<(), ClientError>,
}

/// Whether `dir` holds anything a snapshot would track.
fn has_tracked_entries(dir: &Path) -> Result<bool, ClientError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(ClientError::Io(e)),
    };
    for ent in entries {
        let ent = ent?;
        let ft = ent.file_type()?;
        let tracked = ent
            .file_name()
            .to_str()
            .is_some_and(secsec_snapshot::is_materializable);
        if tracked && (ft.is_file() || ft.is_dir()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// This device's highest commit version: the frontier's, else the highest in the known history (a fresh or lost frontier).
fn own_high<K: MasterKeys>(
    s: &SyncInput<'_, K>,
    frontier: &SyncFrontier,
    device_id: &DeviceId,
    heads: &[Id],
) -> Result<u64, ClientError> {
    if let Some(v) = frontier.commit_version_hwm.get(device_id) {
        return Ok(*v);
    }
    let (_, meta) = load_commit_dag(heads, s.keys, s.store)?;
    Ok(meta
        .values()
        .filter(|m| m.device_id == *device_id)
        .map(|m| m.version)
        .max()
        .unwrap_or(0))
}

fn next_version(v: u64) -> Result<u64, ClientError> {
    v.checked_add(1).ok_or(ClientError::VersionExhausted)
}

fn raise(frontier: &mut SyncFrontier, device_id: DeviceId, version: u64) {
    let e = frontier.commit_version_hwm.entry(device_id).or_insert(0);
    *e = (*e).max(version);
}

/// Restore `commit_id` into the folder against `ours`, this device's snapshot of it.
fn restore<K: MasterKeys>(
    s: &SyncInput<'_, K>,
    commit_id: &Id,
    ours: Option<&(Id, PathSalt)>,
) -> Result<RestoreReport, ClientError> {
    let (commit, _) = open_signed_commit(commit_id, s.keys, s.store)?;
    Ok(restore_commit_tree(
        &commit,
        commit_id,
        ours.map(|(t, salt)| (t, salt)),
        s.keys,
        s.store,
        s.dir,
    )?)
}

/// Reconcile the folder with the ref once; the caller persists the returned base, then the frontier.
pub async fn sync_once<R: Remote, K: MasterKeys>(
    remote: &R,
    s: &SyncInput<'_, K>,
    frontier: &SyncFrontier,
    base: Option<Id>,
    memo: &mut SnapshotMemo,
) -> Result<SyncOutcome, ClientError> {
    let device_id = s.device.device_id()?;
    let head = fetch_verified_head(remote, s.keys, &s.roster.members, s.ref_name).await?;
    if let Some(rh) = &head {
        if Some(rh.head.commit_id) != base {
            fetch_closure(remote, s.store, s.keys, &rh.head.commit_id).await?;
        }
    }

    // A fresh link to an existing repo with nothing tracked here clones; a non-empty folder merges instead.
    if let (None, Some(rh)) = (base, &head) {
        if !has_tracked_entries(s.dir)? {
            let accepted = accept_sibling(
                frontier,
                None,
                &rh.sibling,
                &device_id,
                &s.roster.ever_members,
                s.keys,
                s.store,
            )?;
            let report = restore(s, &rh.head.commit_id, None)?;
            return Ok(SyncOutcome {
                kind: SyncKind::Cloned,
                base: Some(rh.head.commit_id),
                frontier: accepted.frontier,
                conflicts: report.conflicts,
                skipped: report.skipped,
                base_missing: false,
            });
        }
    }

    let base_commit = match base {
        Some(b) => Some(open_signed_commit(&b, s.keys, s.store)?.0),
        None => None,
    };
    // With no base the server's head seeds per-path salts, so identical files get identical ids; its mtimes are not ours.
    let seed = match (&base_commit, &head) {
        (None, Some(rh)) => Some(open_signed_commit(&rh.head.commit_id, s.keys, s.store)?.0),
        _ => None,
    };
    let prior = match (&base_commit, &seed) {
        (Some(c), _) => Some(Prior {
            root: &c.root_tree,
            salt: &c.root_salt,
            fast_path: true,
        }),
        (None, Some(c)) => Some(Prior {
            root: &c.root_tree,
            salt: &c.root_salt,
            fast_path: false,
        }),
        (None, None) => None,
    };
    let snap = snapshot_tree(s.dir, s.keys, s.store, prior, memo)?;
    let ours = (snap.root, snap.salt);

    if let (Some(base_id), Some(bc)) = (base, &base_commit) {
        if bc.root_tree == snap.root {
            let Some(rh) = head else {
                return Ok(SyncOutcome {
                    kind: SyncKind::UpToDate,
                    base,
                    frontier: frontier.clone(),
                    conflicts: Vec::new(),
                    skipped: snap.skipped,
                    base_missing: false,
                });
            };
            if rh.head.commit_id == base_id {
                let mut f = frontier.clone();
                f.observe_head(&rh.sibling);
                return Ok(SyncOutcome {
                    kind: SyncKind::UpToDate,
                    base,
                    frontier: f,
                    conflicts: Vec::new(),
                    skipped: snap.skipped,
                    base_missing: false,
                });
            }
            // The remote moved, or was replayed: converge through the same accept, merge, and push path.
            let own = own_high(s, frontier, &device_id, &[base_id, rh.head.commit_id])?;
            let (action, f) = reconcile(
                remote,
                s,
                frontier,
                &base_id,
                &rh,
                &device_id,
                next_version(own)?,
            )
            .await?;
            return finish(s, action, f, base_id, &ours, snap.skipped);
        }
    }

    // A local change (or a first snapshot): a commit on the base, versioned after all of this device's history.
    let heads: Vec<Id> = base
        .into_iter()
        .chain(head.as_ref().map(|rh| rh.head.commit_id))
        .collect();
    let version = next_version(own_high(s, frontier, &device_id, &heads)?)?;
    let commit = Commit {
        root_tree: snap.root,
        root_salt: snap.salt,
        parents: base.into_iter().collect(),
        device_id,
        version,
        roster_seq: s.roster.tip_seq,
        last_seen_head: head.as_ref().map_or(NO_PREV_HEAD, |rh| rh.head.commit_id),
        ts: s.ts,
    };
    let our_commit = seal_signed_commit(s.keys.current(), s.store, s.device, &commit)?;
    let mut f = frontier.clone();
    raise(&mut f, device_id, version);

    let Some(rh) = head else {
        (s.seal)(&f)?;
        push_objects(remote, s.store, s.keys, &our_commit, None, s.push_id).await?;
        push_head(
            remote,
            s.keys,
            s.device,
            s.ref_name,
            our_commit,
            s.roster.tip_seq,
            None,
            s.push_id,
        )
        .await?;
        return Ok(SyncOutcome {
            kind: SyncKind::Published,
            base: Some(our_commit),
            frontier: f,
            conflicts: Vec::new(),
            skipped: snap.skipped,
            base_missing: false,
        });
    };
    let (action, f) = reconcile(
        remote,
        s,
        &f,
        &our_commit,
        &rh,
        &device_id,
        next_version(version)?,
    )
    .await?;
    finish(s, action, f, our_commit, &ours, snap.skipped)
}

/// Accept `rh` against `our_commit`, merge when incomparable, and publish whatever we are ahead with (§8.5 seal first).
async fn reconcile<R: Remote, K: MasterKeys>(
    remote: &R,
    s: &SyncInput<'_, K>,
    frontier: &SyncFrontier,
    our_commit: &Id,
    rh: &RemoteHead,
    device_id: &DeviceId,
    merge_version: u64,
) -> Result<(SyncAction, SyncFrontier), ClientError> {
    let accepted = accept_sibling(
        frontier,
        Some(our_commit),
        &rh.sibling,
        device_id,
        &s.roster.ever_members,
        s.keys,
        s.store,
    )?;
    if accepted.decision == MergeDecision::Merge {
        // The merge base's trees come on demand; one the server no longer holds merges as a missing base.
        if let Some(b) = merge_base(&accepted.parents, our_commit, &rh.head.commit_id) {
            let (bc, _) = open_signed_commit(&b, s.keys, s.store)?;
            match fetch_tree(
                remote,
                s.store,
                s.keys,
                &bc.root_tree,
                &bc.root_salt,
                Walk::Trees,
            )
            .await
            {
                Ok(_) | Err(ClientError::MissingRemote(_)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    let author = CommitAuthor {
        device: s.device,
        version: merge_version,
        roster_seq: s.roster.tip_seq,
        ts: s.ts,
    };
    let action = merge_accepted(&accepted, our_commit, &rh.sibling, author, s.keys, s.store)?;
    let mut fin = accepted.frontier.clone();
    let publish = match &action {
        SyncAction::Merged { commit_id, .. } => {
            raise(&mut fin, *device_id, merge_version);
            Some(*commit_id)
        }
        SyncAction::AlreadyHave => Some(*our_commit),
        SyncAction::FastForward { .. } => None,
    };
    if let Some(commit_id) = publish {
        // The pre-push seal carries the observed heads and our versions, not the merged-in commits' until the base moves.
        let own = fin.commit_version_hwm.get(device_id).copied().unwrap_or(0);
        (s.seal)(&frontier.with_heads_of(&accepted.frontier, (*device_id, own)))?;
        push_objects(
            remote,
            s.store,
            s.keys,
            &commit_id,
            Some(&rh.head.commit_id),
            s.push_id,
        )
        .await?;
        push_head(
            remote,
            s.keys,
            s.device,
            s.ref_name,
            commit_id,
            s.roster.tip_seq,
            Some((&rh.head, &rh.blob)),
            s.push_id,
        )
        .await?;
    }
    Ok((action, fin))
}

/// Bring the folder to the reconciled commit, restoring against our snapshot so later local edits are kept.
fn finish<K: MasterKeys>(
    s: &SyncInput<'_, K>,
    action: SyncAction,
    frontier: SyncFrontier,
    our_commit: Id,
    ours: &(Id, PathSalt),
    mut skipped: Vec<String>,
) -> Result<SyncOutcome, ClientError> {
    let (kind, base, mut conflicts, report, base_missing) = match action {
        SyncAction::AlreadyHave => (
            SyncKind::Pushed,
            our_commit,
            Vec::new(),
            RestoreReport::default(),
            false,
        ),
        SyncAction::FastForward { commit_id } => (
            SyncKind::Pulled,
            commit_id,
            Vec::new(),
            restore(s, &commit_id, Some(ours))?,
            false,
        ),
        SyncAction::Merged {
            commit_id,
            conflicts,
            base_missing,
        } => (
            SyncKind::Merged,
            commit_id,
            conflicts.into_iter().map(|c| c.path).collect(),
            restore(s, &commit_id, Some(ours))?,
            base_missing,
        ),
    };
    conflicts.extend(report.conflicts);
    skipped.extend(report.skipped);
    Ok(SyncOutcome {
        kind,
        base: Some(base),
        frontier,
        conflicts,
        skipped,
        base_missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch_head;
    use crate::testmem::{roster_of, MemRemote};
    use secsec_engine::MergeError;
    use secsec_kdf::MasterKey;
    use secsec_sync::rollback::MergeReject;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    fn mk() -> MasterKey {
        MasterKey::new(1, [0x55; 32])
    }

    /// One device's view: its cache, folder, base, and frontier.
    struct Side {
        store: Store,
        dir: tempfile::TempDir,
        base: Option<Id>,
        frontier: SyncFrontier,
        memo: SnapshotMemo,
    }

    impl Side {
        fn new(root: &Path, name: &str) -> Self {
            Self {
                store: Store::open(root.join(name)).unwrap(),
                dir: tempfile::tempdir().unwrap(),
                base: None,
                frontier: SyncFrontier::default(),
                memo: SnapshotMemo::default(),
            }
        }

        fn write(&self, name: &str, data: &[u8]) {
            std::fs::write(self.dir.path().join(name), data).unwrap();
        }

        fn read(&self, name: &str) -> Option<Vec<u8>> {
            std::fs::read(self.dir.path().join(name)).ok()
        }

        fn names(&self) -> Vec<String> {
            let mut v: Vec<String> = std::fs::read_dir(self.dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }

        /// Sync once, keeping base and frontier on success.
        async fn sync(
            &mut self,
            r: &MemRemote,
            dev: &DeviceKey,
            roster: &State,
            seal: &dyn Fn(&SyncFrontier) -> Result<(), ClientError>,
        ) -> Result<SyncOutcome, ClientError> {
            let m = mk();
            let input = SyncInput {
                store: &self.store,
                dir: self.dir.path(),
                keys: &m,
                device: dev,
                roster,
                ref_name: "main",
                ts: 0,
                push_id: &[0x44; 16],
                seal,
            };
            let out = sync_once(r, &input, &self.frontier, self.base, &mut self.memo).await?;
            self.base = out.base;
            self.frontier = out.frontier.clone();
            Ok(out)
        }
    }

    fn no_seal(_: &SyncFrontier) -> Result<(), ClientError> {
        Ok(())
    }

    #[tokio::test]
    async fn publish_clone_edit_pull_and_idle() {
        let root = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(root.path().join("r.redb")).unwrap());
        let dev = DeviceKey::generate().unwrap();
        let roster = roster_of(&[&dev]);
        let mut a = Side::new(root.path(), "a.redb");
        let mut b = Side::new(root.path(), "b.redb");

        a.write("hello.txt", b"v1");
        assert_eq!(
            a.sync(&r, &dev, &roster, &no_seal).await.unwrap().kind,
            SyncKind::Published
        );
        assert_eq!(
            b.sync(&r, &dev, &roster, &no_seal).await.unwrap().kind,
            SyncKind::Cloned
        );
        assert_eq!(b.read("hello.txt").unwrap(), b"v1");

        a.write("hello.txt", b"v2-edited");
        assert_eq!(
            a.sync(&r, &dev, &roster, &no_seal).await.unwrap().kind,
            SyncKind::Pushed
        );
        assert_eq!(
            b.sync(&r, &dev, &roster, &no_seal).await.unwrap().kind,
            SyncKind::Pulled
        );
        assert_eq!(b.read("hello.txt").unwrap(), b"v2-edited");
        assert_eq!(
            b.sync(&r, &dev, &roster, &no_seal).await.unwrap().kind,
            SyncKind::UpToDate
        );
    }

    /// A non-empty first link merges keep-both, identical files seed identical ids, and the version continues.
    #[tokio::test]
    async fn joining_a_nonempty_folder_merges_and_loses_nothing() {
        let root = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(root.path().join("r.redb")).unwrap());
        let dev = DeviceKey::generate().unwrap();
        let roster = roster_of(&[&dev]);
        let mut a = Side::new(root.path(), "a.redb");
        let mut b = Side::new(root.path(), "b.redb");

        a.write("shared.txt", b"from-A");
        a.write("same.txt", b"identical");
        a.write("a-only.txt", b"a");
        a.sync(&r, &dev, &roster, &no_seal).await.unwrap();

        b.write("shared.txt", b"from-B");
        b.write("same.txt", b"identical");
        b.write("b-only.txt", b"b");
        let out = b.sync(&r, &dev, &roster, &no_seal).await.unwrap();
        assert_eq!(out.kind, SyncKind::Merged);
        assert_eq!(out.conflicts, vec!["shared.txt".to_string()]);
        assert!(!out.base_missing);
        assert_eq!(b.read("b-only.txt").unwrap(), b"b");
        assert_eq!(b.read("a-only.txt").unwrap(), b"a");
        assert_eq!(b.read("shared.txt").unwrap(), b"from-B");
        let names = b.names();
        assert!(names.iter().any(|n| n.starts_with("shared.conflict-")));
        assert!(!names.iter().any(|n| n.starts_with("same.conflict-")));
        // The re-linked device continued after its own history: version 2 commit, version 3 merge.
        assert_eq!(
            out.frontier
                .commit_version_hwm
                .get(&dev.device_id().unwrap()),
            Some(&3)
        );

        assert_eq!(
            a.sync(&r, &dev, &roster, &no_seal).await.unwrap().kind,
            SyncKind::Pulled
        );
        assert_eq!(a.read("b-only.txt").unwrap(), b"b");

        let mut c = Side::new(root.path(), "c.redb");
        assert_eq!(
            c.sync(&r, &dev, &roster, &no_seal).await.unwrap().kind,
            SyncKind::Cloned
        );
    }

    #[tokio::test]
    async fn deletion_propagates_and_does_not_resurrect() {
        let root = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(root.path().join("r.redb")).unwrap());
        let dev = DeviceKey::generate().unwrap();
        let roster = roster_of(&[&dev]);
        let mut a = Side::new(root.path(), "a.redb");
        let mut b = Side::new(root.path(), "b.redb");
        a.write("keep.txt", b"k");
        a.write("gone.txt", b"g");
        a.sync(&r, &dev, &roster, &no_seal).await.unwrap();
        b.sync(&r, &dev, &roster, &no_seal).await.unwrap();
        assert!(b.read("gone.txt").is_some());

        std::fs::remove_file(a.dir.path().join("gone.txt")).unwrap();
        assert_eq!(
            a.sync(&r, &dev, &roster, &no_seal).await.unwrap().kind,
            SyncKind::Pushed
        );
        assert_eq!(
            b.sync(&r, &dev, &roster, &no_seal).await.unwrap().kind,
            SyncKind::Pulled
        );
        assert!(b.read("gone.txt").is_none());
        assert!(b.read("keep.txt").is_some());
        assert_eq!(
            b.sync(&r, &dev, &roster, &no_seal).await.unwrap().kind,
            SyncKind::UpToDate
        );
    }

    /// macOS's `Icon\r` never syncs, and a peer that never has it removes it only by deleting its folder.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_macos_folder_icon_lives_exactly_as_long_as_its_folder() {
        fn icons_intact(mac: &Side) {
            assert_eq!(mac.read("Icon\r").unwrap(), b"root icon");
            assert_eq!(mac.read("Photos/Icon\r").unwrap(), b"folder icon");
        }
        let root = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(root.path().join("r.redb")).unwrap());
        let dev_mac = DeviceKey::generate().unwrap();
        let dev_linux = DeviceKey::generate().unwrap();
        let roster = roster_of(&[&dev_mac, &dev_linux]);
        let mut mac = Side::new(root.path(), "mac.redb");
        let mut linux = Side::new(root.path(), "linux.redb");
        std::fs::create_dir(mac.dir.path().join("Photos")).unwrap();
        mac.write("Photos/a.jpg", b"a");
        mac.write("Photos/b.jpg", b"b");
        mac.write("Icon\r", b"root icon");
        mac.write("Photos/Icon\r", b"folder icon");
        mac.sync(&r, &dev_mac, &roster, &no_seal).await.unwrap();
        assert_eq!(
            linux
                .sync(&r, &dev_linux, &roster, &no_seal)
                .await
                .unwrap()
                .kind,
            SyncKind::Cloned
        );
        assert!(linux.read("Icon\r").is_none());
        assert!(linux.read("Photos/Icon\r").is_none());
        assert_eq!(linux.read("Photos/a.jpg").unwrap(), b"a");

        linux.write("Photos/a.jpg", b"edited on linux");
        std::fs::remove_file(linux.dir.path().join("Photos/b.jpg")).unwrap();
        linux.write("Photos/c.jpg", b"c");
        linux.sync(&r, &dev_linux, &roster, &no_seal).await.unwrap();
        assert_eq!(
            mac.sync(&r, &dev_mac, &roster, &no_seal)
                .await
                .unwrap()
                .kind,
            SyncKind::Pulled
        );
        assert_eq!(mac.read("Photos/a.jpg").unwrap(), b"edited on linux");
        assert!(mac.read("Photos/b.jpg").is_none());
        assert_eq!(mac.read("Photos/c.jpg").unwrap(), b"c");
        icons_intact(&mac);

        mac.write("from-mac.txt", b"m");
        linux.write("from-linux.txt", b"l");
        linux.sync(&r, &dev_linux, &roster, &no_seal).await.unwrap();
        assert_eq!(
            mac.sync(&r, &dev_mac, &roster, &no_seal)
                .await
                .unwrap()
                .kind,
            SyncKind::Merged
        );
        assert_eq!(mac.read("from-linux.txt").unwrap(), b"l");
        icons_intact(&mac);
        linux.sync(&r, &dev_linux, &roster, &no_seal).await.unwrap();
        assert_eq!(linux.read("from-mac.txt").unwrap(), b"m");
        assert!(linux.read("Icon\r").is_none());
        assert!(linux.read("Photos/Icon\r").is_none());

        std::fs::remove_dir_all(linux.dir.path().join("Photos")).unwrap();
        linux.sync(&r, &dev_linux, &roster, &no_seal).await.unwrap();
        assert_eq!(
            mac.sync(&r, &dev_mac, &roster, &no_seal)
                .await
                .unwrap()
                .kind,
            SyncKind::Pulled
        );
        assert!(!mac.dir.path().join("Photos").exists());
        assert_eq!(mac.read("Icon\r").unwrap(), b"root icon");
        assert_eq!(
            mac.sync(&r, &dev_mac, &roster, &no_seal)
                .await
                .unwrap()
                .kind,
            SyncKind::UpToDate
        );
        assert_eq!(
            linux
                .sync(&r, &dev_linux, &roster, &no_seal)
                .await
                .unwrap()
                .kind,
            SyncKind::UpToDate
        );
        assert!(!linux.dir.path().join("Photos").exists());
    }

    /// A merge's pre-push seal carries the observed head but not the merged-in commits' versions.
    #[tokio::test]
    async fn divergent_devices_merge_and_seal_only_what_the_base_vouches_for() {
        let root = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(root.path().join("r.redb")).unwrap());
        let dev_a = DeviceKey::generate().unwrap();
        let dev_b = DeviceKey::generate().unwrap();
        let (ida, idb) = (dev_a.device_id().unwrap(), dev_b.device_id().unwrap());
        let roster = roster_of(&[&dev_a, &dev_b]);
        let mut a = Side::new(root.path(), "a.redb");
        let mut b = Side::new(root.path(), "b.redb");
        a.write("keep", b"k0");
        a.write("shared", b"s0");
        a.sync(&r, &dev_a, &roster, &no_seal).await.unwrap();
        b.sync(&r, &dev_b, &roster, &no_seal).await.unwrap();

        a.write("shared", b"from A");
        a.sync(&r, &dev_a, &roster, &no_seal).await.unwrap();
        b.write("shared", b"from B, longer");
        let sealed = RefCell::new(Vec::new());
        let capture = |f: &SyncFrontier| {
            sealed.borrow_mut().push(f.clone());
            Ok(())
        };
        let out = b.sync(&r, &dev_b, &roster, &capture).await.unwrap();
        assert_eq!(out.kind, SyncKind::Merged);
        assert_eq!(out.conflicts, vec!["shared".to_string()]);
        assert_eq!(b.read("shared").unwrap(), b"from B, longer");
        let pre = sealed.borrow().last().cloned().unwrap();
        assert_eq!(pre.head_version_hwm.get(&ida), Some(&2));
        assert_eq!(
            pre.commit_version_hwm.get(&ida),
            Some(&1),
            "A's v2 waits for the base"
        );
        assert_eq!(out.frontier.commit_version_hwm.get(&ida), Some(&2));
        assert_eq!(pre.commit_version_hwm.get(&idb), Some(&2));

        let rh = fetch_head(&r, &mk(), "main").await.unwrap().unwrap();
        assert_eq!(Some(rh.0.commit_id), b.base);
        assert_eq!(
            a.sync(&r, &dev_a, &roster, &no_seal).await.unwrap().kind,
            SyncKind::Pulled
        );
        assert_eq!(a.read("shared").unwrap(), b"from B, longer");
        assert!(a.names().iter().any(|n| n.starts_with("shared.conflict-")));
    }

    /// §8.5: the seal runs before the ref-advancing push, so its failure publishes nothing.
    #[tokio::test]
    async fn seal_failure_aborts_before_publishing() {
        let root = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(root.path().join("r.redb")).unwrap());
        let dev = DeviceKey::generate().unwrap();
        let roster = roster_of(&[&dev]);
        let mut a = Side::new(root.path(), "a.redb");
        a.write("f.txt", b"v1");
        let failing = |_: &SyncFrontier| Err(ClientError::Io(std::io::Error::other("seal failed")));
        assert!(matches!(
            a.sync(&r, &dev, &roster, &failing).await,
            Err(ClientError::Io(_))
        ));
        assert!(fetch_head(&r, &mk(), "main").await.unwrap().is_none());
    }

    /// A clone of a head below the persisted head high-water is a rollback alarm, not a restore.
    #[tokio::test]
    async fn clone_rejects_a_head_below_the_frontier() {
        let root = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(root.path().join("r.redb")).unwrap());
        let dev = DeviceKey::generate().unwrap();
        let roster = roster_of(&[&dev]);
        let mut a = Side::new(root.path(), "a.redb");
        a.write("f", b"x");
        a.sync(&r, &dev, &roster, &no_seal).await.unwrap();
        let mut b = Side::new(root.path(), "b.redb");
        b.frontier.head_version_hwm = BTreeMap::from([(dev.device_id().unwrap(), 5)]);
        assert!(matches!(
            b.sync(&r, &dev, &roster, &no_seal).await,
            Err(ClientError::Merge(MergeError::Rollback(
                MergeReject::HeadRollback {
                    head_version: 1,
                    hwm: 5,
                    ..
                }
            )))
        ));
        assert!(b.names().is_empty());
    }

    /// §10/P8: a replayed ancestor head never rolls the folder back; the device converges by republishing its base.
    #[tokio::test]
    async fn an_ancestor_head_replay_is_repaired_not_restored() {
        let root = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(root.path().join("r.redb")).unwrap());
        let dev_a = DeviceKey::generate().unwrap();
        let dev_b = DeviceKey::generate().unwrap();
        let roster = roster_of(&[&dev_a, &dev_b]);
        let m = mk();
        let mut b = Side::new(root.path(), "b.redb");
        b.write("f", b"vB");
        b.sync(&r, &dev_b, &roster, &no_seal).await.unwrap();
        let (_, _, blob_b) = fetch_head(&r, &m, "main").await.unwrap().unwrap();

        let mut a = Side::new(root.path(), "a.redb");
        a.sync(&r, &dev_a, &roster, &no_seal).await.unwrap();
        a.write("f", b"vA");
        assert_eq!(
            a.sync(&r, &dev_a, &roster, &no_seal).await.unwrap().kind,
            SyncKind::Pushed
        );
        let c_a = a.base.unwrap();
        let (_, _, blob_a) = fetch_head(&r, &m, "main").await.unwrap().unwrap();

        // The server rolls /refs/main back to B's older head.
        let ref_h = secsec_sync::ref_hash(&secsec_kdf::MasterKeys::ref_name_key(&m), "main");
        r.store
            .cas_ref(&ref_h, blake3::hash(&blob_a).as_bytes(), &blob_b, &[0; 16])
            .unwrap();
        let out = a.sync(&r, &dev_a, &roster, &no_seal).await.unwrap();
        assert_eq!(out.kind, SyncKind::Pushed);
        assert_eq!(out.base, Some(c_a));
        assert_eq!(a.read("f").unwrap(), b"vA");
        assert_eq!(
            fetch_head(&r, &m, "main")
                .await
                .unwrap()
                .unwrap()
                .0
                .commit_id,
            c_a
        );
    }
}
