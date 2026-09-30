//! Client orchestration over a [`Remote`] (`secsec-Design.md` §10, §12, §15): verified fetch, minimal push, head CAS, sealed frontier.

#![forbid(unsafe_code)]

pub mod history;
pub mod pair;
pub mod prune;
pub mod quic;
pub mod repo;
pub mod sync;
pub mod watcher;

#[cfg(test)]
mod testmem;

use secsec_engine::{EngineError, MergeError};
use secsec_frame::MAX_TREE_DEPTH;
use secsec_kdf::MasterKeys;
use secsec_object::{Id, PathSalt};
use secsec_proto::wire::{ErrorCode, HeadPut, KeyslotPut};
use secsec_proto::PUSH_ID_LEN;
use secsec_sig::{DeviceId, DeviceKey, DevicePublic};
use secsec_snapshot::{open_signed_commit, Entry, SnapError};
use secsec_store::{Store, StoreError, ABSENT_HEAD};
use secsec_sync::rollback::{
    open_frontier, seal_frontier, FrontierError, SiblingHead, SyncFrontier,
};
use secsec_sync::{
    build_head, open_head, random_nonce, ref_hash, seal_head, sign_head, Head, HeadError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

/// A failure on the far side of a [`Remote`].
#[derive(Debug)]
pub enum RemoteError {
    /// The server refused `op` with a §12 error code.
    Refused(&'static str, ErrorCode),
    /// The reply to `op` did not fit the request (wrong kind or length).
    Protocol(&'static str),
    /// The connection or RPC failed.
    Transport(String),
    /// An in-process backend failed.
    Local(String),
}

impl RemoteError {
    /// Whether the server refused because this device owns no keyslot.
    #[must_use]
    pub fn is_not_enrolled(&self) -> bool {
        matches!(self, RemoteError::Refused(_, ErrorCode::NotEnrolled))
    }
}

impl core::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RemoteError::Refused(op, code) => write!(f, "server refused {op}: {code}"),
            RemoteError::Protocol(op) => write!(f, "unexpected server reply to {op}"),
            RemoteError::Transport(e) => write!(f, "connection: {e}"),
            RemoteError::Local(e) => write!(f, "remote store: {e}"),
        }
    }
}
impl std::error::Error for RemoteError {}

/// Every roster-side write of one sigchain operation, applied atomically by the server (§8.1, §8.4, §12).
#[derive(Debug, Clone, Default)]
pub struct RosterWrite {
    /// `BLAKE3` of the current tip entry blob, or [`ABSENT_HEAD`] for genesis.
    pub old_tip: Id,
    /// Sealed entries appended in order.
    pub entries: Vec<Vec<u8>>,
    /// Keyslots written.
    pub keyslots: Vec<KeyslotPut>,
    /// Data key-history wrap `(g, wrap)`.
    pub keyhist: Option<(u32, Vec<u8>)>,
    /// Roster-key-history wrap `(g, wrap)`.
    pub roster_keyhist: Option<(u32, Vec<u8>)>,
    /// Devices whose keyslots at every generation are deleted.
    pub revoke: Vec<Id>,
    /// A head re-sign under its own CAS.
    pub head: Option<HeadPut>,
}

/// The §12 server surface; the QUIC adapter and the in-process test backend implement it identically.
#[allow(async_fn_in_trait)]
pub trait Remote {
    /// Fetch a durable blob by id.
    async fn get_blob(&self, id: &Id) -> Result<Option<Vec<u8>>, RemoteError>;
    /// Stage a blob under `push_id`; it becomes durable when that push's [`Self::cas_head`] promotes it (§15).
    async fn put_blob(
        &self,
        id: &Id,
        blob: &[u8],
        push_id: &[u8; PUSH_ID_LEN],
    ) -> Result<(), RemoteError>;
    /// Durable existence per id, one answer per id in order; staged objects count as absent.
    async fn has(&self, ids: &[Id]) -> Result<Vec<bool>, RemoteError>;
    /// The head blob at `/refs/<ref_h>`.
    async fn get_ref(&self, ref_h: &Id) -> Result<Option<Vec<u8>>, RemoteError>;
    /// The sigchain entry at `seq`, `None` past the tip.
    async fn get_roster_entry(&self, seq: u64) -> Result<Option<Vec<u8>>, RemoteError>;
    /// A device's keyslot at generation `gen`.
    async fn get_keyslot(&self, device_id: &Id, gen: u32) -> Result<Option<Vec<u8>>, RemoteError>;
    /// The roster-key-history wrap for `gen` (§8.2).
    async fn get_roster_keyhist(&self, gen: u32) -> Result<Option<Vec<u8>>, RemoteError>;
    /// The data key-history wrap for `gen` (§8.2).
    async fn get_keyhist(&self, gen: u32) -> Result<Option<Vec<u8>>, RemoteError>;
    /// Swap `/refs/<ref_h>` to `new_blob` iff its blob hash is `expected_old`, promoting `promote`'s staging; `false` on conflict.
    async fn cas_head(
        &self,
        ref_h: &Id,
        expected_old: &Id,
        new_blob: &[u8],
        promote: &[u8; PUSH_ID_LEN],
    ) -> Result<bool, RemoteError>;
    /// Apply one sigchain operation atomically; `false` when the tip, the head, or a key-history slot moved.
    async fn roster_batch(&self, write: &RosterWrite) -> Result<bool, RemoteError>;
    /// Delete `dead` iff the server's heads and roster length still equal the claimed ones (§15); `false` when they moved.
    async fn prune(
        &self,
        dead: &[Id],
        all_heads_hash: &[u8; 32],
        roster_len: u64,
    ) -> Result<bool, RemoteError>;
    /// Post to a §7 pairing slot.
    async fn pair_put(&self, slot: &Id, blob: &[u8]) -> Result<(), RemoteError>;
    /// Take a §7 pairing slot's message, `None` if it is empty.
    async fn pair_get(&self, slot: &Id) -> Result<Option<Vec<u8>>, RemoteError>;
}

/// Errors from client orchestration.
#[derive(Debug)]
pub enum ClientError {
    /// The far side errored.
    Remote(RemoteError),
    /// Local store error.
    Store(StoreError),
    /// Snapshot, restore, or object verification error.
    Snap(SnapError),
    /// Head seal/open/verify error.
    Head(HeadError),
    /// An object the push needs is absent from the local store.
    MissingLocal(Id),
    /// An object the fetch needs is absent on the server.
    MissingRemote(Id),
    /// The `cas-head` lost to a concurrent writer.
    CasConflict,
    /// The fetched head is signed by no current member (a stale roster, or a forgery).
    HeadNotMember,
    /// Sibling acceptance or merge failed; [`MergeError::Rollback`] is a §10 alarm.
    Merge(MergeError),
    /// Filesystem I/O error.
    Io(std::io::Error),
    /// The sealed frontier exists but does not open: a §8.5 lost-frontier event.
    FrontierLost(FrontierError),
    /// Key/signing error.
    Sig(secsec_sig::SigError),
    /// Commit-DAG load error.
    Engine(EngineError),
    /// This device's commit version cannot advance past `u64::MAX`.
    VersionExhausted,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::Remote(e) => write!(f, "{e}"),
            ClientError::Store(e) => write!(f, "{e}"),
            ClientError::Snap(e) => write!(f, "{e}"),
            ClientError::Head(e) => write!(f, "head: {e}"),
            ClientError::MissingLocal(id) => write!(
                f,
                "object {} is missing from the local cache",
                secsec_snapshot::hex12(id)
            ),
            ClientError::MissingRemote(id) => write!(
                f,
                "object {} is absent on the server",
                secsec_snapshot::hex12(id)
            ),
            ClientError::CasConflict => f.write_str("the ref advanced concurrently"),
            ClientError::HeadNotMember => {
                f.write_str("the server's head is signed by a device that is not a member")
            }
            ClientError::Merge(e) => write!(f, "{e}"),
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::FrontierLost(e) => write!(f, "lost local frontier: {e}"),
            ClientError::Sig(e) => write!(f, "sig: {e}"),
            ClientError::Engine(e) => write!(f, "{e}"),
            ClientError::VersionExhausted => f.write_str("commit version exhausted"),
        }
    }
}
impl std::error::Error for ClientError {}
impl From<EngineError> for ClientError {
    fn from(e: EngineError) -> Self {
        ClientError::Engine(e)
    }
}
impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}
impl From<secsec_sig::SigError> for ClientError {
    fn from(e: secsec_sig::SigError) -> Self {
        ClientError::Sig(e)
    }
}
impl From<MergeError> for ClientError {
    fn from(e: MergeError) -> Self {
        ClientError::Merge(e)
    }
}
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
impl From<HeadError> for ClientError {
    fn from(e: HeadError) -> Self {
        ClientError::Head(e)
    }
}

/// Whether `id` is stored locally.
fn stored(store: &Store, id: &Id) -> Result<bool, StoreError> {
    Ok(store.has(std::slice::from_ref(id))?.contains(&true))
}

// ---- push ----

/// Stage what `commit_id` adds over `remote_head`: the head's closure strictly, older new commits' objects when held (§15).
pub(crate) async fn push_objects<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    commit_id: &Id,
    remote_head: Option<&Id>,
    push_id: &[u8; PUSH_ID_LEN],
) -> Result<(), ClientError> {
    let heads: Vec<Id> = std::iter::once(*commit_id)
        .chain(remote_head.copied())
        .collect();
    let (parents, _) = secsec_engine::load_commit_dag(&heads, keys, store)?;
    let new = secsec_sync::dag::new_commits(&parents, remote_head, commit_id);

    // The remote head's tree is durable there: its subtrees are never walked, its ids never sent.
    let mut known = BTreeSet::new();
    if let Some(h) = remote_head {
        let (hc, _) = open_signed_commit(h, keys, store)?;
        secsec_snapshot::tree_closure(
            keys,
            store,
            &hc.root_tree,
            &hc.root_salt,
            &BTreeSet::new(),
            &mut known,
        )?;
    }
    let mut strict: BTreeSet<Id> = new.clone();
    let (head, _) = open_signed_commit(commit_id, keys, store)?;
    secsec_snapshot::tree_closure(
        keys,
        store,
        &head.root_tree,
        &head.root_salt,
        &known,
        &mut strict,
    )?;
    // Older new commits keep their trees; their chunks may be pruned locally, which only thins their history.
    let mut lenient: BTreeSet<Id> = BTreeSet::new();
    for c in new.iter().filter(|c| *c != commit_id) {
        let (commit, _) = open_signed_commit(c, keys, store)?;
        secsec_snapshot::tree_closure(
            keys,
            store,
            &commit.root_tree,
            &commit.root_salt,
            &known,
            &mut lenient,
        )?;
    }
    let want: Vec<(Id, bool)> = strict
        .difference(&known)
        .map(|id| (*id, true))
        .chain(
            lenient
                .iter()
                .filter(|id| !known.contains(*id) && !strict.contains(*id))
                .map(|id| (*id, false)),
        )
        .collect();
    // Staged even when the server holds it: a copy skipped on `has` could be pruned before our cas-head promotes.
    for (id, required) in &want {
        match store.get(id)? {
            Some(blob) => remote.put_blob(id, &blob, push_id).await?,
            None if *required => return Err(ClientError::MissingLocal(*id)),
            None => {}
        }
    }
    Ok(())
}

/// Seal a signed head for `commit_id` chained on `prev` under the current generation and CAS it onto the remote (§12).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn push_head<R: Remote, K: MasterKeys>(
    remote: &R,
    keys: &K,
    device: &DeviceKey,
    ref_name: &str,
    commit_id: Id,
    roster_seq: u64,
    prev: Option<(&Head, &[u8])>,
    push_id: &[u8; PUSH_ID_LEN],
) -> Result<(Head, Vec<u8>), ClientError> {
    let head = build_head(ref_name, commit_id, roster_seq, prev.map(|(h, _)| h))?;
    let sig = sign_head(device, &head)?;
    let nonce = random_nonce()?;
    // The ref path is generation-stable (§13); the seal uses the current generation's head key.
    let rnk = keys.ref_name_key();
    let blob = seal_head(keys.current(), &rnk, &head, &sig, &nonce);
    let ref_h = ref_hash(&rnk, ref_name);
    let old = prev.map_or(ABSENT_HEAD, |(_, b)| *blake3::hash(b).as_bytes());
    if remote.cas_head(&ref_h, &old, &blob, push_id).await? {
        Ok((head, blob))
    } else {
        Err(ClientError::CasConflict)
    }
}

// ---- fetch ----

/// Fetch and open `ref_name`'s head as `(head, sig, stored_blob)` (§9.8); the signature is not yet checked.
pub async fn fetch_head<R: Remote, K: MasterKeys>(
    remote: &R,
    keys: &K,
    ref_name: &str,
) -> Result<Option<(Head, Vec<u8>, Vec<u8>)>, ClientError> {
    let rnk = keys.ref_name_key();
    let ref_h = ref_hash(&rnk, ref_name);
    let Some(blob) = remote.get_ref(&ref_h).await? else {
        return Ok(None);
    };
    let (head, sig) = open_head(keys, &rnk, ref_name, &blob)?;
    Ok(Some((head, sig, blob)))
}

/// A fetched head whose signature a current member made.
#[derive(Debug, Clone)]
pub struct RemoteHead {
    /// The opened head.
    pub head: Head,
    /// Its stored blob, the next `cas-head` token.
    pub blob: Vec<u8>,
    /// The verified signer view the gates read.
    pub sibling: SiblingHead,
}

/// [`fetch_head`] plus the member-signature check; a head no current member signed is [`ClientError::HeadNotMember`].
pub async fn fetch_verified_head<R: Remote, K: MasterKeys>(
    remote: &R,
    keys: &K,
    members: &BTreeMap<DeviceId, DevicePublic>,
    ref_name: &str,
) -> Result<Option<RemoteHead>, ClientError> {
    let Some((head, sig, blob)) = fetch_head(remote, keys, ref_name).await? else {
        return Ok(None);
    };
    let sibling = SiblingHead::verified(members, &head, &sig).ok_or(ClientError::HeadNotMember)?;
    Ok(Some(RemoteHead {
        head,
        blob,
        sibling,
    }))
}

/// Fetch every commit of `commit_id`'s history not stored locally, verifying each before it is stored (§9.2).
pub(crate) async fn fetch_commits<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    commit_id: &Id,
) -> Result<usize, ClientError> {
    let mut fetched: Vec<(Id, Vec<u8>)> = Vec::new();
    let mut seen: BTreeSet<Id> = BTreeSet::new();
    let mut work = vec![*commit_id];
    while let Some(id) = work.pop() {
        // A stored commit's history is already stored: commits land in one transaction per fetch.
        if !seen.insert(id) || stored(store, &id)? {
            continue;
        }
        let blob = remote
            .get_blob(&id)
            .await?
            .ok_or(ClientError::MissingRemote(id))?;
        let (commit, _) = secsec_snapshot::verified_commit(keys, &id, &blob)?;
        work.extend(commit.parents);
        fetched.push((id, blob));
    }
    let items: Vec<(Id, &[u8])> = fetched.iter().map(|(id, b)| (*id, b.as_slice())).collect();
    store.put_many(&items)?;
    Ok(fetched.len())
}

/// What a tree walk brings local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Walk {
    /// Trees only; a stored tree's subtrees are already stored.
    Trees,
    /// Trees and chunks; stored trees are still walked, since retention may have dropped their chunks.
    WithChunks,
}

/// Bring a tree local, verifying every object before it is stored; each tree is stored after its children.
pub(crate) async fn fetch_tree<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    root: &Id,
    salt: &PathSalt,
    walk: Walk,
) -> Result<usize, ClientError> {
    enum Step {
        Enter(Id, PathSalt, usize),
        Store(Id, Vec<u8>),
    }
    let mut fetched = 0usize;
    let mut seen: BTreeSet<Id> = BTreeSet::new();
    let mut stack = vec![Step::Enter(*root, *salt, 0)];
    while let Some(step) = stack.pop() {
        let (id, salt, depth) = match step {
            Step::Store(id, blob) => {
                store.put(&id, &blob)?;
                fetched += 1;
                continue;
            }
            Step::Enter(id, salt, depth) => (id, salt, depth),
        };
        if depth >= MAX_TREE_DEPTH {
            return Err(SnapError::DepthExceeded.into());
        }
        if !seen.insert(id) || (walk == Walk::Trees && stored(store, &id)?) {
            continue;
        }
        let tree = match store.get(&id)? {
            Some(blob) => secsec_snapshot::verified_tree(keys, &id, &salt, &blob)?,
            None => {
                let blob = remote
                    .get_blob(&id)
                    .await?
                    .ok_or(ClientError::MissingRemote(id))?;
                let tree = secsec_snapshot::verified_tree(keys, &id, &salt, &blob)?;
                stack.push(Step::Store(id, blob));
                tree
            }
        };
        let mut chunks: Vec<(Id, PathSalt)> = Vec::new();
        for e in tree.entries {
            match e {
                Entry::File {
                    path_salt,
                    chunks: cs,
                    ..
                } if walk == Walk::WithChunks => {
                    chunks.extend(cs.into_iter().map(|c| (c, path_salt)));
                }
                Entry::File { .. } => {}
                Entry::Dir {
                    subtree,
                    subtree_salt,
                    ..
                } => stack.push(Step::Enter(subtree, subtree_salt, depth + 1)),
            }
        }
        chunks.retain(|(c, _)| seen.insert(*c));
        let ids: Vec<Id> = chunks.iter().map(|(c, _)| *c).collect();
        for ((cid, csalt), have) in chunks.iter().zip(store.has(&ids)?) {
            if have {
                continue;
            }
            let blob = remote
                .get_blob(cid)
                .await?
                .ok_or(ClientError::MissingRemote(*cid))?;
            secsec_snapshot::verify_chunk(keys, cid, csalt, &blob)?;
            store.put(cid, &blob)?;
            fetched += 1;
        }
    }
    Ok(fetched)
}

/// Bring `commit_id`'s history and its full tree local, every object verified before it is stored (§9.2).
pub(crate) async fn fetch_closure<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    commit_id: &Id,
) -> Result<usize, ClientError> {
    let commits = fetch_commits(remote, store, keys, commit_id).await?;
    let (head, _) = open_signed_commit(commit_id, keys, store)?;
    let content = fetch_tree(
        remote,
        store,
        keys,
        &head.root_tree,
        &head.root_salt,
        Walk::WithChunks,
    )
    .await?;
    Ok(commits + content)
}

// ---- local state files ----

/// Replace `path` atomically with owner-only contents: same-directory temp file, fsync, rename, directory fsync.
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("state path has no file name"))?;
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| std::io::Error::other("OS CSPRNG failure"))?;
    let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = dir.join(format!(".{}.{hex}.tmp", name.to_string_lossy()));
    let result = (|| {
        let mut f = create_private(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        sync_dir(dir)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Create a new file readable and writable by its owner only (0600 on unix).
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Make a rename in `dir` durable (unix; other platforms have no directory handle to sync).
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// The result of [`load_frontier`].
#[derive(Debug)]
pub enum FrontierLoad {
    /// No state file: a first run, or for a linked folder a §8.5 lost-frontier event (the caller's policy).
    Absent,
    /// Loaded and authenticated against the device.
    Loaded(SyncFrontier),
}

/// Load the sealed frontier (§8.5); one sealed under the legacy v1 key is resealed under v2 on the way.
pub fn load_frontier(path: &Path, device: &DeviceKey) -> Result<FrontierLoad, ClientError> {
    let blob = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FrontierLoad::Absent),
        Err(e) => return Err(ClientError::Io(e)),
    };
    let device_id = device.device_id()?;
    let current = device.local_seal_key()?;
    let err = match open_frontier(&current, &device_id, &blob) {
        Ok(f) => return Ok(FrontierLoad::Loaded(f)),
        Err(e) => e,
    };
    let legacy = device.local_seal_key_v1()?;
    match open_frontier(&legacy, &device_id, &blob) {
        Ok(f) => {
            save_frontier(path, &f, device)?;
            Ok(FrontierLoad::Loaded(f))
        }
        Err(_) => Err(ClientError::FrontierLost(err)),
    }
}

/// Seal `frontier` under the device's local-seal key (§8.5) and replace `path` atomically.
pub fn save_frontier(
    path: &Path,
    frontier: &SyncFrontier,
    device: &DeviceKey,
) -> Result<(), ClientError> {
    let key = device.local_seal_key()?;
    let device_id = device.device_id()?;
    let blob = seal_frontier(frontier, &key, &device_id).ok_or_else(|| {
        ClientError::Io(std::io::Error::other("OS CSPRNG failure sealing frontier"))
    })?;
    write_private_atomic(path, &blob)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testmem::MemRemote;
    use secsec_kdf::MasterKey;
    use secsec_snapshot::{seal_signed_commit, snapshot_tree, Commit, Prior, SnapshotMemo};

    fn mk() -> MasterKey {
        MasterKey::new(1, [0x33; 32])
    }

    fn open_store(dir: &Path, name: &str) -> Store {
        Store::open(dir.join(name)).unwrap()
    }

    /// Snapshot `dir` and seal a signed commit on `parents`.
    fn commit_dir(
        dir: &Path,
        store: &Store,
        dev: &DeviceKey,
        prior: Option<&Commit>,
        parents: Vec<Id>,
        version: u64,
    ) -> (Id, Commit) {
        let snap = snapshot_tree(
            dir,
            &mk(),
            store,
            prior.map(|c| Prior {
                root: &c.root_tree,
                salt: &c.root_salt,
                fast_path: true,
            }),
            &mut SnapshotMemo::default(),
        )
        .unwrap();
        let commit = Commit {
            root_tree: snap.root,
            root_salt: snap.salt,
            parents,
            device_id: dev.device_id().unwrap(),
            version,
            roster_seq: 0,
            last_seen_head: [0; 32],
            ts: 0,
        };
        (
            seal_signed_commit(&mk(), store, dev, &commit).unwrap(),
            commit,
        )
    }

    #[tokio::test]
    async fn second_push_chains_head_and_a_stale_token_loses() {
        let dir = tempfile::tempdir().unwrap();
        let m = mk();
        let dev = DeviceKey::generate().unwrap();
        let a = open_store(dir.path(), "a.redb");
        let remote = MemRemote::new(open_store(dir.path(), "r.redb"));
        let src = tempfile::tempdir().unwrap();

        std::fs::write(src.path().join("f"), b"one").unwrap();
        let (id1, c1) = commit_dir(src.path(), &a, &dev, None, vec![], 1);
        push_objects(&remote, &a, &m, &id1, None, &[1; 16])
            .await
            .unwrap();
        let (h1, b1) = push_head(&remote, &m, &dev, "main", id1, 0, None, &[1; 16])
            .await
            .unwrap();

        std::fs::write(src.path().join("f"), b"two").unwrap();
        let (id2, _) = commit_dir(src.path(), &a, &dev, Some(&c1), vec![id1], 2);
        push_objects(&remote, &a, &m, &id2, Some(&id1), &[2; 16])
            .await
            .unwrap();
        let (h2, _) = push_head(
            &remote,
            &m,
            &dev,
            "main",
            id2,
            0,
            Some((&h1, &b1)),
            &[2; 16],
        )
        .await
        .unwrap();
        assert_eq!(h2.head_version, 2);
        assert_eq!(h2.prev_head, secsec_sync::head_id(&h1));

        let stale = push_head(
            &remote,
            &m,
            &dev,
            "main",
            id2,
            0,
            Some((&h1, &b1)),
            &[3; 16],
        )
        .await;
        assert!(matches!(stale, Err(ClientError::CasConflict)));
    }

    /// A tampered object is rejected before it is stored, and the fetch stores nothing of it.
    #[tokio::test]
    async fn fetch_verifies_every_object_before_storing_it() {
        let dir = tempfile::tempdir().unwrap();
        let m = mk();
        let dev = DeviceKey::generate().unwrap();
        let a = open_store(dir.path(), "a.redb");
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), vec![7u8; 20_000]).unwrap();
        let (id, commit) = commit_dir(src.path(), &a, &dev, None, vec![], 1);

        // A server holding every object, one chunk flipped.
        let tree =
            secsec_snapshot::load_tree(&commit.root_tree, &commit.root_salt, &m, &a).unwrap();
        let Entry::File { chunks, .. } = &tree.entries[0] else {
            panic!("f is a file")
        };
        let bad = chunks[0];
        let remote = MemRemote::new(open_store(dir.path(), "r.redb"));
        for obj in secsec_snapshot::reachable_objects(&m, &a, &id).unwrap() {
            let mut blob = a.get(&obj).unwrap().unwrap();
            if obj == bad {
                *blob.last_mut().unwrap() ^= 1;
            }
            remote.store.put(&obj, &blob).unwrap();
        }
        let b = open_store(dir.path(), "b.redb");
        assert!(matches!(
            fetch_closure(&remote, &b, &m, &id).await,
            Err(ClientError::Snap(SnapError::Object(_)))
        ));
        assert!(b.get(&bad).unwrap().is_none(), "the bad chunk never lands");
        assert!(b.get(&commit.root_tree).unwrap().is_none(), "nor its tree");
    }

    /// A second push sends only what the remote head lacks: nothing under an unchanged file.
    #[tokio::test]
    async fn push_sends_only_the_delta() {
        let dir = tempfile::tempdir().unwrap();
        let m = mk();
        let dev = DeviceKey::generate().unwrap();
        let a = open_store(dir.path(), "a.redb");
        let remote = MemRemote::new(open_store(dir.path(), "r.redb"));
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("keep"), vec![1u8; 30_000]).unwrap();
        std::fs::write(src.path().join("edit"), b"v1").unwrap();
        let (id1, c1) = commit_dir(src.path(), &a, &dev, None, vec![], 1);
        push_objects(&remote, &a, &m, &id1, None, &[1; 16])
            .await
            .unwrap();
        push_head(&remote, &m, &dev, "main", id1, 0, None, &[1; 16])
            .await
            .unwrap();
        let after_first = remote.store.object_count().unwrap();

        std::fs::write(src.path().join("edit"), b"v2").unwrap();
        let (id2, _) = commit_dir(src.path(), &a, &dev, Some(&c1), vec![id1], 2);
        push_objects(&remote, &a, &m, &id2, Some(&id1), &[2; 16])
            .await
            .unwrap();
        // Commit, root tree, and the edited file's chunk: nothing under the unchanged file is re-sent.
        let fresh = remote
            .store
            .cas_ref(&[9; 32], &ABSENT_HEAD, b"h", &[2; 16])
            .unwrap();
        assert!(fresh.swapped);
        assert_eq!(remote.store.object_count().unwrap(), after_first + 3);
    }

    /// §15: a prune racing a push never dangles the new head, even for an object the server already held.
    #[tokio::test]
    async fn a_prune_racing_a_push_cannot_dangle_the_new_head() {
        let dir = tempfile::tempdir().unwrap();
        let m = mk();
        let dev = DeviceKey::generate().unwrap();
        let a = open_store(dir.path(), "a.redb");
        let remote = MemRemote::new(open_store(dir.path(), "r.redb"));
        let src = tempfile::tempdir().unwrap();

        std::fs::write(src.path().join("f"), b"old v1").unwrap();
        let (id1, c1) = commit_dir(src.path(), &a, &dev, None, vec![], 1);
        push_objects(&remote, &a, &m, &id1, None, &[1; 16])
            .await
            .unwrap();
        let (h1, b1) = push_head(&remote, &m, &dev, "main", id1, 0, None, &[1; 16])
            .await
            .unwrap();
        let tree1 = secsec_snapshot::load_tree(&c1.root_tree, &c1.root_salt, &m, &a).unwrap();
        let Entry::File { chunks, .. } = &tree1.entries[0] else {
            panic!("f is a file")
        };
        let old_chunk = chunks[0];

        std::fs::write(src.path().join("f"), b"new version two").unwrap();
        let (id2, c2) = commit_dir(src.path(), &a, &dev, Some(&c1), vec![id1], 2);
        push_objects(&remote, &a, &m, &id2, Some(&id1), &[2; 16])
            .await
            .unwrap();
        let (h2, b2) = push_head(
            &remote,
            &m,
            &dev,
            "main",
            id2,
            0,
            Some((&h1, &b1)),
            &[2; 16],
        )
        .await
        .unwrap();

        // A revert re-derives the old chunk: durable on the server, outside the head's tree.
        std::fs::write(src.path().join("f"), b"old v1").unwrap();
        let (id3, _) = commit_dir(src.path(), &a, &dev, Some(&c2), vec![id2], 3);
        push_objects(&remote, &a, &m, &id3, Some(&id2), &[3; 16])
            .await
            .unwrap();
        // A prune signed against the unmoved head drops it before our cas-head lands.
        assert!(remote.store.prune_if(&[old_chunk], |_, _| true).unwrap());
        push_head(
            &remote,
            &m,
            &dev,
            "main",
            id3,
            0,
            Some((&h2, &b2)),
            &[3; 16],
        )
        .await
        .unwrap();
        assert!(remote.store.get(&old_chunk).unwrap().is_some());
    }

    #[test]
    fn frontier_persists_detects_loss_and_migrates_v1() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frontier");
        let device = DeviceKey::generate().unwrap();
        let id = device.device_id().unwrap();
        assert!(matches!(
            load_frontier(&path, &device).unwrap(),
            FrontierLoad::Absent
        ));

        let f = SyncFrontier {
            roster_seq: 12,
            head_version_hwm: BTreeMap::from([(id, 5)]),
            commit_version_hwm: BTreeMap::from([(id, 9)]),
        };
        save_frontier(&path, &f, &device).unwrap();
        let FrontierLoad::Loaded(got) = load_frontier(&path, &device).unwrap() else {
            panic!("expected a loaded frontier")
        };
        assert_eq!(got, f);
        assert!(matches!(
            load_frontier(&path, &DeviceKey::generate().unwrap()),
            Err(ClientError::FrontierLost(_))
        ));

        // A legacy v1 seal opens once and is rewritten under v2.
        let v1 = seal_frontier(&f, &device.local_seal_key_v1().unwrap(), &id).unwrap();
        std::fs::write(&path, &v1).unwrap();
        let FrontierLoad::Loaded(got) = load_frontier(&path, &device).unwrap() else {
            panic!("v1 frontier must migrate")
        };
        assert_eq!(got, f);
        let resealed = std::fs::read(&path).unwrap();
        assert!(open_frontier(&device.local_seal_key().unwrap(), &id, &resealed).is_ok());

        let mut blob = resealed;
        *blob.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &blob).unwrap();
        assert!(matches!(
            load_frontier(&path, &device),
            Err(ClientError::FrontierLost(_))
        ));
        // No temp file survives the atomic writes.
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["frontier".to_string()]);
    }
}
