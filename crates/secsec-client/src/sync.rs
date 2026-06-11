//! One-shot bidirectional sync of a working directory against a remote ref (`secsec-Design.md` §10).
//!
//! [`sync_once`] reconciles a local working directory with `/refs/<ref>` on a [`Remote`], using a
//! **base** (the last-synced commit) to avoid the classic data-loss trap: a fresh client with an empty
//! directory must *clone* (pull + restore) to establish a base before it ever commits — otherwise its
//! "empty" snapshot would publish a deletion of everyone else's files. With the base tracked:
//!
//! - **no base, remote head exists** → clone (fetch + verify + restore), adopt the head as base.
//! - **no base, no remote head** → first publish (we are the first writer).
//! - **base, no local change** → fast-forward to a newer remote head (pull) or no-op.
//! - **base, local change** → author a commit on the base and [`crate::sync_ref`] it (push or
//!   rollback-gated three-way merge), restoring the reconciled result.
//!
//! The base is returned for the caller to persist (sealed under the device key, §8.5); on the next
//! sync it is fed back in. Versions come from the frontier's per-device high-water (replay-safe, §8.5).

use crate::{
    fetch_closure, fetch_head, push_head, push_objects, resolve_head_signer, sync_ref, ClientError,
    CommitAuthor, Remote, SyncAction,
};
use secsec_engine::MergeError;
use secsec_kdf::MasterKeys;
use secsec_object::Id;
use secsec_sig::{DeviceId, DeviceKey, DevicePublic};
use secsec_snapshot::{
    open_signed_commit, restore_commit_tree, seal_signed_commit, snapshot_tree, verify_commit,
    Commit,
};
use secsec_store::Store;
use secsec_sync::rollback::{MergeReject, SiblingHead, SyncFrontier};
use secsec_sync::{Head, NO_PREV_HEAD};
use std::collections::BTreeMap;
use std::path::Path;

/// What [`sync_once`] did this run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncKind {
    /// Already in sync; nothing transferred.
    UpToDate,
    /// First writer: published our directory as the initial commit.
    Published,
    /// Fresh client: cloned the existing repo and restored it to the working dir.
    Cloned,
    /// No local changes; fast-forwarded to a newer remote head and restored it.
    Pulled,
    /// Local changes published on top of the base (the remote had nothing newer).
    Pushed,
    /// Local changes reconciled with a divergent remote head via three-way merge.
    Merged,
}

/// The result of [`sync_once`].
#[derive(Debug, Clone)]
pub struct SyncOutcome {
    /// What happened.
    pub kind: SyncKind,
    /// The new last-synced commit (the **base** to persist and feed back next sync). `None` only when
    /// the repo has no head at all and we did not publish (cannot happen — first publish sets it).
    pub base: Option<Id>,
    /// The frontier advanced by this sync (§8.5: persist before the next sync).
    pub frontier: SyncFrontier,
    /// The §15 arrival receipts for objects pushed this sync (empty on a pure pull/clone/no-op). The
    /// caller merges these into its persisted receipt log to drive a later [`crate::gc::gc_collect`].
    pub receipts: Vec<(Id, crate::Receipt)>,
    /// Keep-both conflict paths produced by a three-way merge this sync (§10), so the caller can
    /// surface them to the user. Empty unless `kind == Merged` with genuine conflicts; the conflicting
    /// content is preserved on disk as `name.conflict-<device>-<id>.ext` (no data is lost).
    pub conflicts: Vec<String>,
}

/// Resolve a commit's author key from the folded roster (a commit by a non-member is rejected).
fn author_key<'a>(
    members: &'a BTreeMap<DeviceId, DevicePublic>,
    commit: &Commit,
) -> Result<&'a DevicePublic, ClientError> {
    members
        .get(&commit.device_id)
        .ok_or(ClientError::HeadNotMember)
}

/// Pull a verified head into the working dir: resolve+verify the head signer, fetch its closure,
/// verify the commit against its author, restore, and observe the head into the frontier.
#[allow(clippy::too_many_arguments)]
async fn pull_to<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    frontier: &SyncFrontier,
    members: &BTreeMap<DeviceId, DevicePublic>,
    head: &Head,
    head_sig: &[u8],
    dir: &Path,
) -> Result<SyncFrontier, ClientError> {
    let signer = resolve_head_signer(members, head, head_sig).ok_or(ClientError::HeadNotMember)?;

    // §8.5/§10 anti-rollback on the **pull** path (clone / no-local-change fast-forward). The merge
    // path runs these gates inside `merge_heads`; a head adopted-and-restored here must clear them too,
    // or a malicious server could replay an older member-signed head and silently roll this device's
    // working dir back to it (and the §10 `observe` below would then be operating on rolled-back
    // state). On a fresh clone the frontier is empty, so both gates pass; a genuinely newer head also
    // passes. Only a head whose counters regress below the persisted frontier is rejected (alarm).
    if head.roster_seq < frontier.roster_seq {
        return Err(ClientError::Merge(MergeError::Rollback(
            MergeReject::RosterRollback {
                sibling: head.roster_seq,
                frontier: frontier.roster_seq,
            },
        )));
    }
    let head_hwm = frontier.head_version_hwm.get(&signer).copied().unwrap_or(0);
    if head.head_version < head_hwm {
        return Err(ClientError::Merge(MergeError::Rollback(
            MergeReject::HeadRollback {
                device: signer,
                head_version: head.head_version,
                hwm: head_hwm,
            },
        )));
    }

    fetch_closure(remote, store, keys, &head.commit_id).await?;
    let (commit, csig) = open_signed_commit(&head.commit_id, keys, store)?;
    verify_commit(author_key(members, &commit)?, &commit, &csig)?;
    restore_commit_tree(&commit, keys, store, dir)?;

    // Observe the head into the frontier so later syncs gate against it (§8.5/§10).
    let (parents, meta) = secsec_engine::load_commit_dag(&[head.commit_id], keys, store)?;
    let sibling = SiblingHead {
        device_id: signer,
        head_version: head.head_version,
        roster_seq: head.roster_seq,
        commit_id: head.commit_id,
    };
    let mut f = frontier.clone();
    f.observe(&sibling, &parents, &meta);
    Ok(f)
}

/// Reconcile `dir` with `/refs/<ref_name>` once (§10). See the module docs for the four cases. `base`
/// is the last-synced commit (`None` on a fresh client / new repo); `roster_seq` is the current
/// sigchain sequence the commit is written under. `seal` persists the advanced frontier and is invoked
/// **before** any head push that advances the ref (§8.5 seal-before-write); a `seal` failure aborts
/// before publishing. Returns the action, the new base to persist, and the advanced frontier (which
/// the caller should also persist after the call, to capture our own commit's high-water).
#[allow(clippy::too_many_arguments)]
pub async fn sync_once<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    dir: &Path,
    keys: &K,
    device: &DeviceKey,
    members: &BTreeMap<DeviceId, DevicePublic>,
    frontier: &SyncFrontier,
    ref_name: &str,
    roster_seq: u64,
    base: Option<Id>,
    ts: u64,
    seal: &dyn Fn(&SyncFrontier) -> Result<(), ClientError>,
) -> Result<SyncOutcome, ClientError> {
    // Writes (snapshot, commit, head) use the current generation; reads (closures, old commits) route
    // through `keys`, which resolves any past generation after a rotation (§8.2).
    let device_id = device.device_id()?;
    let head = fetch_head(remote, keys.current(), ref_name).await?;

    // Fresh client with an existing repo → clone (never commit our unsynced dir).
    if base.is_none() {
        if let Some((h, sig, _)) = &head {
            let frontier = pull_to(remote, store, keys, frontier, members, h, sig, dir).await?;
            return Ok(SyncOutcome {
                kind: SyncKind::Cloned,
                base: Some(h.commit_id),
                frontier,
                receipts: Vec::new(),
                conflicts: Vec::new(),
            });
        }
    }

    // Snapshot the working dir incrementally on the base's tree (so salts/ids are stable, §9.7).
    let prev = match base {
        Some(b) => {
            let (c, _) = open_signed_commit(&b, keys, store)?;
            Some((c.root_tree, c.root_salt))
        }
        None => None,
    };
    let (our_tree, our_salt) = snapshot_tree(
        dir,
        keys.current(),
        store,
        prev.as_ref().map(|(t, s)| (t, s)),
    )?;
    let unchanged = prev.as_ref().is_some_and(|(t, _)| *t == our_tree);

    // No local changes: pull a newer head, or we are already up to date.
    if unchanged {
        return match &head {
            Some((h, sig, _)) if Some(h.commit_id) != base => {
                let frontier = pull_to(remote, store, keys, frontier, members, h, sig, dir).await?;
                Ok(SyncOutcome {
                    kind: SyncKind::Pulled,
                    base: Some(h.commit_id),
                    frontier,
                    receipts: Vec::new(),
                    conflicts: Vec::new(),
                })
            }
            _ => Ok(SyncOutcome {
                kind: SyncKind::UpToDate,
                base,
                frontier: frontier.clone(),
                receipts: Vec::new(),
                conflicts: Vec::new(),
            }),
        };
    }

    // Local changes: author a commit on the base.
    let version = frontier
        .commit_version_hwm
        .get(&device_id)
        .copied()
        .unwrap_or(0)
        + 1;
    let parents = base.map(|b| vec![b]).unwrap_or_default();
    let last_seen = head.as_ref().map_or(NO_PREV_HEAD, |(h, _, _)| h.commit_id);
    let commit = Commit {
        root_tree: our_tree,
        root_salt: our_salt,
        parents,
        device_id,
        version,
        roster_seq,
        last_seen_head: last_seen,
        ts,
    };
    let our_commit = seal_signed_commit(keys.current(), store, device, &commit)?;
    let mut f = frontier.clone();
    f.commit_version_hwm.insert(device_id, version);

    match head {
        // First publish: no remote head yet.
        None => {
            // §8.5: seal the frontier (carrying our commit's version) before the ref-advancing push.
            seal(&f)?;
            let receipts = push_objects(remote, store, keys, &our_commit).await?;
            push_head(
                remote,
                keys.current(),
                device,
                ref_name,
                our_commit,
                roster_seq,
                None,
            )
            .await?;
            Ok(SyncOutcome {
                kind: SyncKind::Published,
                base: Some(our_commit),
                frontier: f,
                receipts,
                conflicts: Vec::new(),
            })
        }
        // Reconcile our commit against the remote head (push if we're ahead, else merge).
        Some(_) => {
            // The merge commit, if any, is the next version after ours.
            let author = CommitAuthor {
                device,
                version: version + 1,
                roster_seq,
                ts,
            };
            let report = sync_ref(
                remote,
                store,
                keys,
                members,
                &f,
                ref_name,
                &our_commit,
                author,
                seal,
            )
            .await?;
            let receipts = report.receipts;
            let mut frontier = report.frontier;
            let (kind, base, conflicts) = match report.action {
                SyncAction::AlreadyHave => {
                    frontier.commit_version_hwm.insert(device_id, version);
                    (SyncKind::Pushed, our_commit, Vec::new())
                }
                SyncAction::Merged {
                    commit_id,
                    conflicts,
                } => {
                    frontier.commit_version_hwm.insert(device_id, version + 1);
                    let (mc, _) = open_signed_commit(&commit_id, keys, store)?;
                    restore_commit_tree(&mc, keys, store, dir)?;
                    let paths = conflicts.into_iter().map(|c| c.path).collect();
                    (SyncKind::Merged, commit_id, paths)
                }
                SyncAction::FastForward { commit_id } => {
                    let (c, _) = open_signed_commit(&commit_id, keys, store)?;
                    restore_commit_tree(&c, keys, store, dir)?;
                    (SyncKind::Pulled, commit_id, Vec::new())
                }
            };
            Ok(SyncOutcome {
                kind,
                base: Some(base),
                frontier,
                receipts,
                conflicts,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testmem::MemRemote;
    use secsec_kdf::MasterKey;
    use secsec_store::Store;

    fn read_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(root).unwrap() {
            let e = e.unwrap();
            out.push((
                e.file_name().to_str().unwrap().to_owned(),
                std::fs::read(e.path()).unwrap(),
            ));
        }
        out.sort();
        out
    }

    #[tokio::test]
    async fn two_clients_publish_clone_edit_pull() {
        let dir = tempfile::tempdir().unwrap();
        let m = MasterKey::new(1, [0x55; 32]);
        let dev_a = DeviceKey::generate().unwrap();
        let members: BTreeMap<DeviceId, DevicePublic> =
            [(dev_a.device_id().unwrap(), dev_a.public())]
                .into_iter()
                .collect();
        let remote = MemRemote::new(Store::open(dir.path().join("remote.redb")).unwrap());
        let a_store = Store::open(dir.path().join("a.redb")).unwrap();
        let b_store = Store::open(dir.path().join("b.redb")).unwrap();
        let fr = SyncFrontier::default();
        let seal = |_: &SyncFrontier| Ok::<(), ClientError>(());

        // A publishes a folder.
        let a_dir = tempfile::tempdir().unwrap();
        std::fs::write(a_dir.path().join("hello.txt"), b"v1").unwrap();
        let r1 = sync_once(
            &remote,
            &a_store,
            a_dir.path(),
            &m,
            &dev_a,
            &members,
            &fr,
            "main",
            0,
            None,
            0,
            &seal,
        )
        .await
        .unwrap();
        assert_eq!(r1.kind, SyncKind::Published);
        // §15: a publish surfaces arrival receipts (commit + tree + chunk) for the receipt log.
        assert!(!r1.receipts.is_empty(), "publish surfaces arrival receipts");
        let a_base = r1.base;

        // B clones into an empty dir → gets A's file (B does NOT publish its empty dir).
        let b_dir = tempfile::tempdir().unwrap();
        let r2 = sync_once(
            &remote,
            &b_store,
            b_dir.path(),
            &m,
            &dev_a,
            &members,
            &fr,
            "main",
            0,
            None,
            0,
            &seal,
        )
        .await
        .unwrap();
        assert_eq!(r2.kind, SyncKind::Cloned);
        assert!(r2.receipts.is_empty(), "a clone pushes nothing");
        assert_eq!(read_tree(b_dir.path()), read_tree(a_dir.path()));
        let b_base = r2.base;

        // A edits and syncs → pushes on top of its base (linear, no merge).
        std::fs::write(a_dir.path().join("hello.txt"), b"v2-edited").unwrap();
        let r3 = sync_once(
            &remote,
            &a_store,
            a_dir.path(),
            &m,
            &dev_a,
            &members,
            &r1.frontier,
            "main",
            0,
            a_base,
            0,
            &seal,
        )
        .await
        .unwrap();
        assert_eq!(r3.kind, SyncKind::Pushed);
        assert!(!r3.receipts.is_empty(), "a push surfaces arrival receipts");

        // B syncs (no local change) → fast-forwards, restoring A's edit.
        let r4 = sync_once(
            &remote,
            &b_store,
            b_dir.path(),
            &m,
            &dev_a,
            &members,
            &r2.frontier,
            "main",
            0,
            b_base,
            0,
            &seal,
        )
        .await
        .unwrap();
        assert_eq!(r4.kind, SyncKind::Pulled);
        assert!(r4.receipts.is_empty(), "a fast-forward pull pushes nothing");
        assert_eq!(
            std::fs::read(b_dir.path().join("hello.txt")).unwrap(),
            b"v2-edited"
        );

        // B re-syncs with nothing new → up to date.
        let r5 = sync_once(
            &remote,
            &b_store,
            b_dir.path(),
            &m,
            &dev_a,
            &members,
            &r4.frontier,
            "main",
            0,
            r4.base,
            0,
            &seal,
        )
        .await
        .unwrap();
        assert_eq!(r5.kind, SyncKind::UpToDate);
    }

    /// §8.5: the frontier seal runs **before** the ref-advancing push, so a seal failure aborts the
    /// publish — no head is written to the remote. (A crash post-push could otherwise leave a published
    /// head uncovered by the persisted anti-rollback frontier.)
    #[tokio::test]
    async fn seal_failure_aborts_before_publishing() {
        use secsec_sync::ref_hash;
        let dir = tempfile::tempdir().unwrap();
        let m = MasterKey::new(1, [0x55; 32]);
        let dev = DeviceKey::generate().unwrap();
        let members: BTreeMap<DeviceId, DevicePublic> = [(dev.device_id().unwrap(), dev.public())]
            .into_iter()
            .collect();
        let remote = MemRemote::new(Store::open(dir.path().join("r.redb")).unwrap());
        let store = Store::open(dir.path().join("c.redb")).unwrap();
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("f.txt"), b"v1").unwrap();

        // A seal that always fails: the first publish must abort before advancing the ref.
        let seal = |_: &SyncFrontier| {
            Err(ClientError::Io(std::io::Error::other(
                "seal failed on purpose",
            )))
        };
        let res = sync_once(
            &remote,
            &store,
            work.path(),
            &m,
            &dev,
            &members,
            &SyncFrontier::default(),
            "main",
            0,
            None,
            0,
            &seal,
        )
        .await;
        assert!(
            matches!(res, Err(ClientError::Io(_))),
            "a seal failure must abort the publish"
        );
        // The ref was NOT advanced — the remote head is still absent.
        let ref_h = ref_hash(&m.ref_name_key(), "main");
        assert!(
            remote.get_ref(&ref_h).await.unwrap().is_none(),
            "no head must be published when the pre-push seal fails"
        );
    }

    /// §8.5/§10: the pull path must reject a replayed head whose `head_version` is below the persisted
    /// per-device high-water — otherwise a malicious server could silently roll a no-local-change
    /// client's working dir back to an older (still member-signed) head. The gate runs before any
    /// closure fetch, so an empty remote is enough to exercise it.
    #[tokio::test]
    async fn pull_to_rejects_head_below_frontier_high_water() {
        use secsec_engine::MergeError;
        use secsec_sync::rollback::MergeReject;
        use secsec_sync::{build_head, sign_head};

        let dir = tempfile::tempdir().unwrap();
        let m = MasterKey::new(1, [0x55; 32]);
        let dev = DeviceKey::generate().unwrap();
        let signer = dev.device_id().unwrap();
        let members: BTreeMap<DeviceId, DevicePublic> =
            [(signer, dev.public())].into_iter().collect();
        let remote = MemRemote::new(Store::open(dir.path().join("r.redb")).unwrap());
        let store = Store::open(dir.path().join("c.redb")).unwrap();

        // A validly-signed but OLD head (head_version 1).
        let head = build_head("main", [0xC0; 32], 0, None);
        let sig = sign_head(&dev, &head).unwrap();

        // The client has already observed head_version 5 from this device.
        let frontier = SyncFrontier {
            head_version_hwm: BTreeMap::from([(signer, 5)]),
            ..Default::default()
        };
        let work = tempfile::tempdir().unwrap();
        let res = pull_to(
            &remote,
            &store,
            &m,
            &frontier,
            &members,
            &head,
            &sig,
            work.path(),
        )
        .await;
        assert!(
            matches!(
                res,
                Err(ClientError::Merge(MergeError::Rollback(
                    MergeReject::HeadRollback {
                        head_version: 1,
                        hwm: 5,
                        ..
                    }
                )))
            ),
            "a pulled head below the persisted head_version high-water must be a rollback alarm"
        );
    }

    #[tokio::test]
    async fn local_sweep_keeps_reachable_and_drops_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let m = MasterKey::new(1, [0x55; 32]);
        let dev_a = DeviceKey::generate().unwrap();
        let members: BTreeMap<DeviceId, DevicePublic> =
            [(dev_a.device_id().unwrap(), dev_a.public())]
                .into_iter()
                .collect();
        let remote = MemRemote::new(Store::open(dir.path().join("remote.redb")).unwrap());
        let a_store = Store::open(dir.path().join("a.redb")).unwrap();
        let seal = |_: &SyncFrontier| Ok::<(), ClientError>(());

        // A publishes a folder → a_store holds exactly the head's reachable closure.
        let a_dir = tempfile::tempdir().unwrap();
        std::fs::write(a_dir.path().join("hello.txt"), b"v1").unwrap();
        let r = sync_once(
            &remote,
            &a_store,
            a_dir.path(),
            &m,
            &dev_a,
            &members,
            &SyncFrontier::default(),
            "main",
            0,
            None,
            0,
            &seal,
        )
        .await
        .unwrap();
        let head = r.base.unwrap();
        let reachable = a_store.object_count().unwrap();

        // Inject an object unreachable from the head (an orphan, as a cas-conflict retry would leave).
        a_store.put(&[0xee; 32], b"orphan").unwrap();
        assert_eq!(a_store.object_count().unwrap(), reachable + 1);

        // The sweep drops exactly the orphan; the head's full closure survives and still opens.
        let dropped = crate::gc::local_sweep(&m, &a_store, &head).unwrap();
        assert_eq!(dropped, 1, "only the unreachable orphan is dropped");
        assert_eq!(a_store.get(&[0xee; 32]).unwrap(), None);
        assert_eq!(a_store.object_count().unwrap(), reachable);
        assert!(open_signed_commit(&head, &m, &a_store).is_ok());
    }
}
