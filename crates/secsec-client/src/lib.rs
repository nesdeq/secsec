//! `secsec-client` — client orchestration over a [`Remote`] (`finaldesign.md` §10, §12, §14).
//!
//! This crate plumbs the proven cores to a remote store: it pushes the reachable **object closure**
//! of a commit, advances the per-ref **head** via the blind-server compare-and-swap (§12), and on the
//! read side fetches a head, fetches a commit's closure **verifying every object on arrival** (§9.2),
//! and restores it. The remote is abstracted as the [`Remote`] trait so the orchestration is exercised
//! against the real blind-CAS storage semantics in-process; the QUIC adapter (over `secsec-transport`)
//! and the cross-device merge loop are layered on top.
//!
//! **This slice is the linear single-author path** — push, then pull-and-restore by a holder of the
//! same master key. Resolving *which* roster member signed a fetched head (needed before a
//! cross-device three-way merge) is the next slice; here the caller supplies the expected signer key.

#![forbid(unsafe_code)]

use secsec_frame::ObjType;
use secsec_kdf::MasterKey;
use secsec_object::{open_object, Id, ObjError, PathSalt};
use secsec_sig::DevicePublic;
use secsec_snapshot::{Entry, SnapError};
use secsec_store::{Store, StoreError, ABSENT_HEAD};
use secsec_sync::{
    build_head, open_head, random_nonce, ref_hash, seal_head, sign_head, verify_head, Head,
    HeadError,
};
use std::collections::BTreeSet;
use std::path::Path;

/// An opaque error from a [`Remote`] implementation (network, storage, protocol). Carried as a string
/// so the trait stays object-friendly across the in-process and QUIC backends.
#[derive(Debug)]
pub struct RemoteError(pub String);
impl core::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "remote: {}", self.0)
    }
}
impl std::error::Error for RemoteError {}

/// A content-addressed object + mutable-ref store on the far side of a connection (§12, §13). The
/// blind server exposes exactly this surface; an in-process backing store implements it identically.
#[allow(async_fn_in_trait)]
pub trait Remote {
    /// Fetch a blob by id (`None` if absent).
    async fn get_blob(&self, id: &Id) -> Result<Option<Vec<u8>>, RemoteError>;
    /// Store a blob (idempotent by id).
    async fn put_blob(&self, id: &Id, blob: &[u8]) -> Result<(), RemoteError>;
    /// Fetch the stored head blob for `/refs/<ref_h>` (`None` if absent).
    async fn get_ref(&self, ref_h: &Id) -> Result<Option<Vec<u8>>, RemoteError>;
    /// Blind compare-and-swap (§12): replace `/refs/<ref_h>` with `new_blob` iff `BLAKE3(current
    /// stored blob)` (or [`ABSENT_HEAD`]) equals `expected_old`. Returns `true` on swap, `false` on
    /// conflict.
    async fn cas_head(
        &self,
        ref_h: &Id,
        expected_old: &Id,
        new_blob: &[u8],
    ) -> Result<bool, RemoteError>;
}

/// Errors from client orchestration.
#[derive(Debug)]
pub enum ClientError {
    /// The far side errored.
    Remote(RemoteError),
    /// Local store error.
    Store(StoreError),
    /// Snapshot/restore error.
    Snap(SnapError),
    /// Object open/verify error (a fetched object failed §9.2 content-address verification).
    Object(ObjError),
    /// Head seal/open/verify error.
    Head(HeadError),
    /// An object expected in the local store was absent (push side).
    MissingLocal(Id),
    /// An object required to complete a fetch closure was absent on the remote.
    MissingRemote(Id),
    /// The `cas-head` lost the race (a concurrent writer advanced the ref).
    CasConflict,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::Remote(e) => write!(f, "{e}"),
            ClientError::Store(e) => write!(f, "store: {e}"),
            ClientError::Snap(e) => write!(f, "snapshot: {e}"),
            ClientError::Object(e) => write!(f, "object: {e}"),
            ClientError::Head(e) => write!(f, "head: {e}"),
            ClientError::MissingLocal(_) => f.write_str("object missing from local store"),
            ClientError::MissingRemote(_) => f.write_str("required object absent on remote"),
            ClientError::CasConflict => {
                f.write_str("cas-head conflict (ref advanced concurrently)")
            }
        }
    }
}
impl std::error::Error for ClientError {}
impl From<RemoteError> for ClientError {
    fn from(e: RemoteError) -> Self {
        ClientError::Remote(e)
    }
}
impl From<StoreError> for ClientError {
    fn from(e: StoreError) -> Self {
        ClientError::Store(e)
    }
}
impl From<SnapError> for ClientError {
    fn from(e: SnapError) -> Self {
        ClientError::Snap(e)
    }
}
impl From<ObjError> for ClientError {
    fn from(e: ObjError) -> Self {
        ClientError::Object(e)
    }
}
impl From<HeadError> for ClientError {
    fn from(e: HeadError) -> Self {
        ClientError::Head(e)
    }
}

// ---- push ----

/// Push the full reachable object closure of `commit_id` from `store` to `remote` (idempotent puts).
/// The id set is the §15 keep-set closure (commit + ancestors + trees + chunks); each blob is read
/// from the local store and `put`. Returns the number of objects pushed.
pub async fn push_objects<R: Remote>(
    remote: &R,
    store: &Store,
    mk: &MasterKey,
    commit_id: &Id,
) -> Result<usize, ClientError> {
    let ids = secsec_snapshot::reachable_objects(mk, store, &[*commit_id])?;
    let mut n = 0;
    for id in &ids {
        let blob = store.get(id)?.ok_or(ClientError::MissingLocal(*id))?;
        remote.put_blob(id, &blob).await?;
        n += 1;
    }
    Ok(n)
}

/// Advance `/refs/<ref_name>` to `commit_id`: seal a signed head (chained on `prev`), then blind-CAS
/// it onto the remote. `prev` is the `(head, stored_blob)` the client last observed for this ref
/// (`None` for the first head); the old CAS token is `BLAKE3(prev_blob)` (or [`ABSENT_HEAD`]). Returns
/// the new `(head, stored_blob)` to carry as `prev` next time. The caller pushes objects first.
pub async fn push_head<R: Remote>(
    remote: &R,
    mk: &MasterKey,
    device: &secsec_sig::DeviceKey,
    ref_name: &str,
    commit_id: Id,
    roster_seq: u64,
    prev: Option<(&Head, &[u8])>,
) -> Result<(Head, Vec<u8>), ClientError> {
    let head = build_head(ref_name, commit_id, roster_seq, prev.map(|(h, _)| h));
    let sig = sign_head(device, &head)?;
    let nonce = random_nonce()?;
    let rnk = mk.ref_name_key();
    let blob = seal_head(mk, &rnk, &head, &sig, &nonce);

    let ref_h = ref_hash(&rnk, ref_name);
    let old = prev.map_or(ABSENT_HEAD, |(_, b)| *blake3::hash(b).as_bytes());
    if remote.cas_head(&ref_h, &old, &blob).await? {
        Ok((head, blob))
    } else {
        Err(ClientError::CasConflict)
    }
}

// ---- fetch ----

/// Fetch the stored head blob for `ref_name`, open it (§9.8: FRAME check, AEAD open, ref-slot binding,
/// strict decode), and return `(head, sig, stored_blob)`. The caller MUST then [`verify_head`] against
/// the signer's roster key and check the frontier (§8.5). `None` if the ref is absent.
pub async fn fetch_head<R: Remote>(
    remote: &R,
    mk: &MasterKey,
    ref_name: &str,
) -> Result<Option<(Head, Vec<u8>, Vec<u8>)>, ClientError> {
    let rnk = mk.ref_name_key();
    let ref_h = ref_hash(&rnk, ref_name);
    let Some(blob) = remote.get_ref(&ref_h).await? else {
        return Ok(None);
    };
    let (head, sig) = open_head(mk, &rnk, ref_name, &blob)?;
    Ok(Some((head, sig, blob)))
}

/// One item of the typed fetch traversal (we know each id's role from its parent, so we can open and
/// verify it correctly without trusting a server-supplied type).
enum Work {
    Commit(Id),
    Tree(Id, PathSalt),
    Chunk(Id, PathSalt),
}

/// Fetch the full reachable object closure of `commit_id` from `remote` into `store`, **verifying
/// every object on arrival** (§9.2): each commit/tree is opened (re-deriving and checking its id) to
/// discover its children, and each chunk is opened under its file's `path_salt`. A missing object is
/// [`ClientError::MissingRemote`]. Idempotent: already-present objects are skipped. Returns the count
/// fetched this call.
pub async fn fetch_closure<R: Remote>(
    remote: &R,
    store: &Store,
    mk: &MasterKey,
    commit_id: &Id,
) -> Result<usize, ClientError> {
    let mut seen: BTreeSet<Id> = BTreeSet::new();
    let mut work = vec![Work::Commit(*commit_id)];
    let mut fetched = 0;

    while let Some(item) = work.pop() {
        let id = match &item {
            Work::Commit(id) | Work::Tree(id, _) | Work::Chunk(id, _) => *id,
        };
        if !seen.insert(id) {
            continue;
        }
        // Fetch + store (skip the network if we already hold it locally).
        if store.get(&id)?.is_none() {
            let blob = remote
                .get_blob(&id)
                .await?
                .ok_or(ClientError::MissingRemote(id))?;
            store.put(&id, &blob)?;
            fetched += 1;
        }
        match item {
            Work::Commit(_) => {
                // open_signed_commit re-verifies the content address and decodes (§9.2).
                let (commit, _sig) = secsec_snapshot::open_signed_commit(&id, mk, store)?;
                for p in &commit.parents {
                    work.push(Work::Commit(*p));
                }
                work.push(Work::Tree(commit.root_tree, commit.root_salt));
            }
            Work::Tree(_, salt) => {
                let tree = secsec_snapshot::load_tree(&id, &salt, mk, store)?;
                for e in tree.entries {
                    match e {
                        Entry::File {
                            path_salt, chunks, ..
                        } => {
                            for c in chunks {
                                work.push(Work::Chunk(c, path_salt));
                            }
                        }
                        Entry::Dir {
                            subtree,
                            subtree_salt,
                            ..
                        } => work.push(Work::Tree(subtree, subtree_salt)),
                    }
                }
            }
            Work::Chunk(_, salt) => {
                // Verify the chunk's content address (§9.2); leaf, no children.
                let blob = store.get(&id)?.ok_or(ClientError::MissingLocal(id))?;
                open_object(mk, ObjType::Chunk, &salt, &id, &blob)?;
            }
        }
    }
    Ok(fetched)
}

/// Pull a ref end-to-end: fetch+verify the head against `signer` (the linear single-author case — the
/// caller resolves the signer key), fetch the commit's object closure (verifying each object), verify
/// the commit signature against `signer`, and restore the working tree to `dest`. Returns the head, or
/// `None` if the ref is absent. (Cross-device merge of a divergent head is the next slice.)
pub async fn pull_restore<R: Remote>(
    remote: &R,
    store: &Store,
    mk: &MasterKey,
    signer: &DevicePublic,
    ref_name: &str,
    dest: &Path,
) -> Result<Option<Head>, ClientError> {
    let Some((head, sig, _blob)) = fetch_head(remote, mk, ref_name).await? else {
        return Ok(None);
    };
    verify_head(signer, &head, &sig)?;
    fetch_closure(remote, store, mk, &head.commit_id).await?;
    let (commit, csig) = secsec_snapshot::open_signed_commit(&head.commit_id, mk, store)?;
    secsec_snapshot::verify_commit(signer, &commit, &csig)?;
    secsec_snapshot::restore_commit_tree(&commit, mk, store, dest)?;
    Ok(Some(head))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secsec_sig::DeviceKey;

    /// An in-process [`Remote`] backed by a real [`Store`] — exercises the exact blind-CAS semantics
    /// the QUIC server uses (`cas_ref` = `BLAKE3`-of-blob compare), minus the network.
    struct MemRemote {
        store: Store,
    }
    impl Remote for MemRemote {
        async fn get_blob(&self, id: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
            self.store.get(id).map_err(|e| RemoteError(e.to_string()))
        }
        async fn put_blob(&self, id: &Id, blob: &[u8]) -> Result<(), RemoteError> {
            self.store
                .put(id, blob)
                .map(|_| ())
                .map_err(|e| RemoteError(e.to_string()))
        }
        async fn get_ref(&self, ref_h: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
            self.store
                .get_ref(ref_h)
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
    }

    fn mk() -> MasterKey {
        MasterKey::new(1, [0x33; 32])
    }

    fn open_store(dir: &Path, name: &str) -> Store {
        Store::open(dir.join(name)).unwrap()
    }

    fn read_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, Vec<u8>)>) {
            let mut es: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap())
                .collect();
            es.sort_by_key(std::fs::DirEntry::file_name);
            for e in es {
                let name = e.file_name().to_str().unwrap().to_owned();
                let rel = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                let p = e.path();
                if p.is_dir() {
                    walk(&p, &rel, out);
                } else {
                    out.push((rel, std::fs::read(&p).unwrap()));
                }
            }
        }
        walk(root, "", &mut out);
        out
    }

    #[tokio::test]
    async fn linear_push_then_pull_restore_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let m = mk();
        let device = DeviceKey::generate().unwrap();

        // Author A: local store + a working tree.
        let a_store = open_store(dir.path(), "a.redb");
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b.bin"), [7u8; 9000]).unwrap();

        // Snapshot → signed commit in A's store.
        let (rt, rs) = secsec_snapshot::snapshot_tree(src.path(), &m, &a_store, None).unwrap();
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
        let commit_id =
            secsec_snapshot::seal_signed_commit(&m, &a_store, &device, &commit).unwrap();

        // The remote (blind server).
        let remote = MemRemote {
            store: open_store(dir.path(), "remote.redb"),
        };

        // Push objects + advance the head.
        let pushed = push_objects(&remote, &a_store, &m, &commit_id)
            .await
            .unwrap();
        assert!(pushed >= 4); // commit + root tree + subtree + ≥1 chunk
        let (head, _blob) = push_head(&remote, &m, &device, "main", commit_id, 0, None)
            .await
            .unwrap();
        assert_eq!(head.head_version, 1);

        // Author B: a FRESH empty store, same master key, knows A's signer key.
        let b_store = open_store(dir.path(), "b.redb");
        let dst = tempfile::tempdir().unwrap();
        let got = pull_restore(&remote, &b_store, &m, &device.public(), "main", dst.path())
            .await
            .unwrap()
            .expect("ref present");
        assert_eq!(got, head);
        assert_eq!(read_tree(src.path()), read_tree(dst.path()));
    }

    #[tokio::test]
    async fn second_push_chains_head_and_first_cas_token_guards() {
        let dir = tempfile::tempdir().unwrap();
        let m = mk();
        let device = DeviceKey::generate().unwrap();
        let a_store = open_store(dir.path(), "a.redb");
        let remote = MemRemote {
            store: open_store(dir.path(), "remote.redb"),
        };

        // v1
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"one").unwrap();
        let (rt1, rs1) = secsec_snapshot::snapshot_tree(src.path(), &m, &a_store, None).unwrap();
        let c1 = secsec_snapshot::Commit {
            root_tree: rt1,
            root_salt: rs1,
            parents: vec![],
            device_id: device.device_id().unwrap(),
            version: 1,
            roster_seq: 0,
            last_seen_head: [0u8; 32],
            ts: 0,
        };
        let id1 = secsec_snapshot::seal_signed_commit(&m, &a_store, &device, &c1).unwrap();
        push_objects(&remote, &a_store, &m, &id1).await.unwrap();
        let (h1, b1) = push_head(&remote, &m, &device, "main", id1, 0, None)
            .await
            .unwrap();

        // v2 chained on v1.
        std::fs::write(src.path().join("f"), b"two").unwrap();
        let (rt2, rs2) =
            secsec_snapshot::snapshot_tree(src.path(), &m, &a_store, Some((&rt1, &rs1))).unwrap();
        let c2 = secsec_snapshot::Commit {
            root_tree: rt2,
            root_salt: rs2,
            parents: vec![id1],
            device_id: device.device_id().unwrap(),
            version: 2,
            roster_seq: 0,
            last_seen_head: id1,
            ts: 0,
        };
        let id2 = secsec_snapshot::seal_signed_commit(&m, &a_store, &device, &c2).unwrap();
        push_objects(&remote, &a_store, &m, &id2).await.unwrap();
        let (h2, _b2) = push_head(&remote, &m, &device, "main", id2, 0, Some((&h1, &b1)))
            .await
            .unwrap();
        assert_eq!(h2.head_version, 2);
        assert_eq!(h2.prev_head, secsec_sync::head_id(&h1));

        // A stale CAS token (re-using v1's blob as `prev`) must now lose the race.
        std::fs::write(src.path().join("f"), b"three").unwrap();
        let (rt3, rs3) =
            secsec_snapshot::snapshot_tree(src.path(), &m, &a_store, Some((&rt2, &rs2))).unwrap();
        let c3 = secsec_snapshot::Commit {
            root_tree: rt3,
            root_salt: rs3,
            parents: vec![id2],
            device_id: device.device_id().unwrap(),
            version: 3,
            roster_seq: 0,
            last_seen_head: id2,
            ts: 0,
        };
        let id3 = secsec_snapshot::seal_signed_commit(&m, &a_store, &device, &c3).unwrap();
        push_objects(&remote, &a_store, &m, &id3).await.unwrap();
        let stale = push_head(&remote, &m, &device, "main", id3, 0, Some((&h1, &b1))).await;
        assert!(matches!(stale, Err(ClientError::CasConflict)));
    }
}
