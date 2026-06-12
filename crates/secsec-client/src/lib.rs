//! `secsec-client` — client orchestration over a [`Remote`] (`secsec-Design.md` §10, §12): push the
//! reachable object closure of a commit, advance the per-ref head via the blind-server CAS, and on
//! the read side fetch a head + closure **verifying every object on arrival** (§9.2). Cross-device
//! sync ([`sync_ref`]): fetch the remote head, [`resolve_head_signer`] against the folded roster,
//! bring the closure local, run the rollback-gated merge ([`secsec_engine::merge_heads`]), push.
//! The [`Remote`] trait abstracts the server; the QUIC adapter is a thin layer on top.

#![forbid(unsafe_code)]

pub mod gc;
pub mod history;
pub mod pair;
pub mod quic;
pub mod repo;
pub mod sync;
pub mod watcher;

/// Shared in-process [`Remote`] used by the test modules (consolidates four identical copies).
#[cfg(test)]
mod testmem;

use secsec_engine::{merge_heads, CommitAuthor, MergeError, SyncAction};
use secsec_frame::ObjType;
use secsec_kdf::MasterKeys;
use secsec_object::{open_object, Id, ObjError, PathSalt};
use secsec_sig::{DeviceId, DeviceKey, DevicePublic};
use secsec_snapshot::{Entry, SnapError};
use secsec_store::{Store, StoreError, ABSENT_HEAD};
use secsec_sync::rollback::{
    open_frontier, seal_frontier, FrontierError, SiblingHead, SyncFrontier,
};
use secsec_sync::{
    build_head, open_head, random_nonce, ref_hash, seal_head, sign_head, verify_head, Head,
    HeadError,
};
use std::collections::{BTreeMap, BTreeSet};
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

/// A §15 arrival receipt returned on a successful `put`. The client records it to choose a safe
/// `gc_gen` and to bind the `gc` CAS to `put_epoch`. Signed by the host receipt key (§15
/// defence-in-depth); all-zero pubkey/signature when unsigned (e.g. the in-process backend).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    /// The object's arrival generation (the `put_epoch` it first landed at).
    pub arrival_gen: u64,
    /// The server's current global `put_epoch` after this put.
    pub put_epoch: u64,
    /// The server's asserted timestamp (advisory; never used for GC eligibility, §15/§21).
    pub ts: u64,
    /// The host's Ed25519 receipt public key (all-zero if unsigned).
    pub receipt_pubkey: [u8; 32],
    /// The receipt signature over the §15 message (all-zero if unsigned).
    pub signature: [u8; 64],
}

impl Receipt {
    /// An unsigned receipt (all-zero pubkey/signature) — for an in-process backend with no host key.
    #[must_use]
    pub fn unsigned(arrival_gen: u64, put_epoch: u64) -> Self {
        Self {
            arrival_gen,
            put_epoch,
            ts: 0,
            receipt_pubkey: [0u8; 32],
            signature: [0u8; 64],
        }
    }

    /// Verify this receipt's signature against `host_id` (§15). Returns `false` for an unsigned
    /// receipt (all-zero pubkey). The caller TOFU-binds `receipt_pubkey` to the pinned `host_id` over
    /// the host-authenticated connection.
    #[must_use]
    pub fn verify(&self, id: &Id, host_id: &[u8; 32]) -> bool {
        secsec_proto::receipt::verify_receipt(
            &self.receipt_pubkey,
            &self.signature,
            id,
            host_id,
            self.arrival_gen,
            self.put_epoch,
            self.ts,
        )
    }
}

/// A content-addressed object + mutable-ref store on the far side of a connection (§12, §13). The
/// blind server exposes exactly this surface; an in-process backing store implements it identically.
#[allow(async_fn_in_trait)]
pub trait Remote {
    /// Fetch a blob by id (`None` if absent).
    async fn get_blob(&self, id: &Id) -> Result<Option<Vec<u8>>, RemoteError>;
    /// Store a blob (idempotent by id); returns the §15 arrival [`Receipt`].
    async fn put_blob(&self, id: &Id, blob: &[u8]) -> Result<Receipt, RemoteError>;
    /// Fetch the stored head blob for `/refs/<ref_h>` (`None` if absent).
    async fn get_ref(&self, ref_h: &Id) -> Result<Option<Vec<u8>>, RemoteError>;
    /// Fetch the sigchain entry blob at `seq` (`None` past the tip) — cold-start fold (§8.1).
    async fn get_roster_entry(&self, seq: u64) -> Result<Option<Vec<u8>>, RemoteError>;
    /// Fetch a device's keyslot blob for generation `gen` (`None` if absent) — cold-start unwrap.
    async fn get_keyslot(&self, device_id: &Id, gen: u32) -> Result<Option<Vec<u8>>, RemoteError>;
    /// Fetch the roster-key-history wrap for generation `gen` (`None` if absent) — rotation-era
    /// cold-start (§8.2). Default returns `None` so in-process backends without keyhist still compile.
    async fn get_roster_keyhist(&self, _gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        Ok(None)
    }
    /// Fetch the DATA key-history wrap for generation `gen` (`None` if absent) — peeling
    /// `master_key_g` to read pre-rotation object content (§8.2 `/keyhist/<g>`). Default returns
    /// `None` so in-process backends without keyhist still compile.
    async fn get_keyhist(&self, _gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        Ok(None)
    }
    /// Blind compare-and-swap (§12): replace `/refs/<ref_h>` with `new_blob` iff `BLAKE3(current
    /// stored blob)` (or [`ABSENT_HEAD`]) equals `expected_old`. Returns `true` on swap, `false` on
    /// conflict.
    async fn cas_head(
        &self,
        ref_h: &Id,
        expected_old: &Id,
        new_blob: &[u8],
    ) -> Result<bool, RemoteError>;
    /// Request a §15 GC sweep: delete objects with arrival `put_epoch ≤ gc_gen` not in `keep_set`. The
    /// `all_heads_hash`/`roster_seq`/`put_epoch` are the client's view; the server recomputes them and
    /// the sweep is a compare-and-swap (a concurrent mutation aborts it). Returns the outcome.
    async fn gc(
        &self,
        keep_set: Vec<Id>,
        gc_gen: u64,
        all_heads_hash: &[u8; 32],
        roster_seq: u64,
        put_epoch: u64,
    ) -> Result<GcOutcome, RemoteError>;
    /// Store a device's keyslot blob (§13) — the network half of enrollment (§7/§8.4). Defaults to an
    /// error so read-only / in-process backends need not implement it.
    async fn put_keyslot(
        &self,
        _device_id: &Id,
        _gen: u32,
        _blob: &[u8],
    ) -> Result<(), RemoteError> {
        Err(RemoteError(
            "put_keyslot unsupported by this remote".to_string(),
        ))
    }
    /// Append a sigchain entry CAS-guarded by `old_tip` (§8.1): `Ok(true)` = appended, `Ok(false)` =
    /// CAS conflict (re-fold + retry). Defaults to an error for read-only backends.
    async fn roster_append(&self, _old_tip: &Id, _entry: &[u8]) -> Result<bool, RemoteError> {
        Err(RemoteError(
            "roster_append unsupported by this remote".to_string(),
        ))
    }
    /// Post an opaque blob to the §7 invite-onboarding pairing mailbox slot. Allowed pre-enrollment.
    async fn pair_put(&self, _slot: &Id, _blob: &[u8]) -> Result<(), RemoteError> {
        Err(RemoteError(
            "pair_put unsupported by this remote".to_string(),
        ))
    }
    /// Read a §7 pairing mailbox slot (`None` if empty/expired). Allowed pre-enrollment.
    async fn pair_get(&self, _slot: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        Err(RemoteError(
            "pair_get unsupported by this remote".to_string(),
        ))
    }
    /// Store a DATA key-history wrap for generation `gen` (§8.2) — the network half of rotation.
    async fn put_keyhist(&self, _gen: u32, _blob: &[u8]) -> Result<(), RemoteError> {
        Err(RemoteError(
            "put_keyhist unsupported by this remote".to_string(),
        ))
    }
    /// Store a roster-key-history wrap for generation `gen` (§8.2) — the network half of rotation.
    async fn put_roster_keyhist(&self, _gen: u32, _blob: &[u8]) -> Result<(), RemoteError> {
        Err(RemoteError(
            "put_roster_keyhist unsupported by this remote".to_string(),
        ))
    }
    /// Delete a device's keyslot at generation `gen` (§8.4 revocation, over the wire).
    async fn delete_keyslot(&self, _device_id: &Id, _gen: u32) -> Result<(), RemoteError> {
        Err(RemoteError(
            "delete_keyslot unsupported by this remote".to_string(),
        ))
    }
}

/// The result of a [`Remote::gc`] request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcOutcome {
    /// The sweep ran (objects below `gc_gen` and outside the keep-set were deleted).
    Swept,
    /// The §15 compare-and-swap failed — the server's mutable state moved since the client computed
    /// `all_heads_hash`/`roster_seq`/`put_epoch` (a concurrent `cas-head`/`roster-append`/`put`). The
    /// client should re-read state and retry.
    CasConflict,
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
    /// A fetched head's signature matched no current roster member (forged or stale-roster head).
    HeadNotMember,
    /// The rollback-aware merge errored — notably [`MergeError::Rollback`], a §10 security alarm.
    Merge(MergeError),
    /// Filesystem I/O error (state-file read/write).
    Io(std::io::Error),
    /// The persisted local frontier exists but failed to open (corrupt / MAC-fail / wrong device) — a
    /// §8.5 **lost-frontier event**: the caller MUST alarm and treat the session as a reinstall.
    FrontierLost(FrontierError),
    /// Key/signing error (e.g. deriving the local-seal key).
    Sig(secsec_sig::SigError),
    /// Engine error loading the commit DAG.
    Engine(secsec_engine::EngineError),
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
            ClientError::HeadNotMember => f.write_str("fetched head signed by a non-member"),
            ClientError::Merge(e) => write!(f, "merge: {e}"),
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::FrontierLost(e) => write!(f, "lost local frontier: {e}"),
            ClientError::Sig(e) => write!(f, "sig: {e}"),
            ClientError::Engine(e) => write!(f, "engine: {e}"),
        }
    }
}
impl std::error::Error for ClientError {}
impl From<secsec_engine::EngineError> for ClientError {
    fn from(e: secsec_engine::EngineError) -> Self {
        ClientError::Engine(e)
    }
}
impl From<repo::RepoError> for ClientError {
    fn from(e: repo::RepoError) -> Self {
        // From the orchestration's view a cold-start/rotate RepoError is a remote-state failure.
        ClientError::Remote(RemoteError(e.to_string()))
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
/// from the local store and `put`. Returns the per-object arrival [`Receipt`]s (for the caller to
/// record toward `gc_gen`).
pub async fn push_objects<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    commit_id: &Id,
) -> Result<Vec<(Id, Receipt)>, ClientError> {
    let ids = secsec_snapshot::reachable_objects(keys, store, &[*commit_id])?;
    let mut receipts = Vec::with_capacity(ids.len());
    for id in &ids {
        let blob = store.get(id)?.ok_or(ClientError::MissingLocal(*id))?;
        let receipt = remote.put_blob(id, &blob).await?;
        receipts.push((*id, receipt));
    }
    Ok(receipts)
}

/// Advance `/refs/<ref_name>` to `commit_id`: seal a signed head (chained on `prev`), then blind-CAS
/// it onto the remote. `prev` is the `(head, stored_blob)` the client last observed for this ref
/// (`None` for the first head); the old CAS token is `BLAKE3(prev_blob)` (or [`ABSENT_HEAD`]). Returns
/// the new `(head, stored_blob)` to carry as `prev` next time. The caller pushes objects first.
pub async fn push_head<R: Remote, K: MasterKeys>(
    remote: &R,
    keys: &K,
    device: &secsec_sig::DeviceKey,
    ref_name: &str,
    commit_id: Id,
    roster_seq: u64,
    prev: Option<(&Head, &[u8])>,
) -> Result<(Head, Vec<u8>), ClientError> {
    let head = build_head(ref_name, commit_id, roster_seq, prev.map(|(h, _)| h));
    let sig = sign_head(device, &head)?;
    let nonce = random_nonce()?;
    // Sealed under the current generation's `head_key_g`, but addressed at the generation-stable
    // ref path (§13), so the ref does not move on rotation.
    let rnk = keys.ref_name_key();
    let blob = seal_head(keys.current(), &rnk, &head, &sig, &nonce);

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
    // `open_head` resolves the head's own generation against `keys` (§8.2 peel), so a head written
    // before a rotation is still readable by a current member.
    let (head, sig) = open_head(keys, &rnk, ref_name, &blob)?;
    Ok(Some((head, sig, blob)))
}

/// One item of the typed fetch traversal (we know each id's role from its parent, so we can open and
/// verify it correctly without trusting a server-supplied type).
enum Work {
    Commit(Id),
    Tree(Id, PathSalt),
    Chunk(Id, PathSalt),
}

/// Fetch the full reachable closure of `commit_id` from `remote` into `store`, **verifying every
/// object on arrival** (§9.2): commits/trees are opened to discover their children, chunks under
/// their file's `path_salt`. Idempotent (present objects skipped); returns the count fetched.
pub async fn fetch_closure<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
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
                let (commit, _sig) = secsec_snapshot::open_signed_commit(&id, keys, store)?;
                for p in &commit.parents {
                    work.push(Work::Commit(*p));
                }
                work.push(Work::Tree(commit.root_tree, commit.root_salt));
            }
            Work::Tree(_, salt) => {
                let tree = secsec_snapshot::load_tree(&id, &salt, keys, store)?;
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
                // Leaf: verify the chunk's content address (§9.2); `open_object` resolves its
                // generation from `keys` (§8.2).
                let blob = store.get(&id)?.ok_or(ClientError::MissingLocal(id))?;
                open_object(keys, ObjType::Chunk, &salt, &id, &blob)?;
            }
        }
    }
    Ok(fetched)
}

// ---- cross-device sync (fetch → resolve signer → rollback-gated merge → push) ----

/// Resolve which roster member signed `head` by trying each member's key — the head carries no
/// `device_id` (§9.6), so the signer is the one member key that verifies. `None` if no current
/// member signed it (forged / stale-roster head).
#[must_use]
pub fn resolve_head_signer(
    members: &BTreeMap<DeviceId, DevicePublic>,
    head: &Head,
    sig: &[u8],
) -> Option<DeviceId> {
    members
        .iter()
        .find_map(|(id, pk)| verify_head(pk, head, sig).is_ok().then_some(*id))
}

/// The outcome of [`sync_ref`].
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// What was done with the ref (reuses the engine's classification).
    pub action: SyncAction,
    /// The frontier advanced by observing the remote head (§8.5: seal before the next write).
    pub frontier: SyncFrontier,
    /// The head we wrote, if we advanced the ref (merge or fast-forward-the-remote-to-us).
    pub wrote: Option<(Head, Vec<u8>)>,
    /// The §15 arrival receipts for any objects we pushed this call (empty if we only adopted a
    /// remote head). The caller records these toward a future `gc_gen` (§15).
    pub receipts: Vec<(Id, Receipt)>,
}

/// Reconcile our local `our_commit` for `ref_name` against the remote (§10): fetch the remote head
/// (absent → push ours and create it), resolve its signer, bring the closure local, run the
/// rollback-gated [`merge_heads`], then push whatever we authored and advance the ref (or adopt a
/// remote fast-forward). A gate rejection surfaces as [`ClientError::Merge`] — a §10 alarm.
///
/// `seal` persists the advanced frontier and is invoked **before** any ref-advancing push (§8.5);
/// a `seal` failure aborts before publishing. Restoring the working tree is the caller's step.
// All distinct caller-supplied inputs with no cohesive subgroup; a parameter object would only
// exist to satisfy the lint.
#[allow(clippy::too_many_arguments)]
pub async fn sync_ref<R: Remote, K: MasterKeys>(
    remote: &R,
    store: &Store,
    keys: &K,
    members: &BTreeMap<DeviceId, DevicePublic>,
    frontier: &SyncFrontier,
    ref_name: &str,
    our_commit: &Id,
    author: CommitAuthor<'_>,
    seal: &dyn Fn(&SyncFrontier) -> Result<(), ClientError>,
) -> Result<SyncReport, ClientError> {
    let device: &DeviceKey = author.device;
    let roster_seq = author.roster_seq;

    // 1. Fetch the remote head (current generation). Absent → we are the first writer for this ref.
    let Some((remote_head, remote_sig, remote_blob)) = fetch_head(remote, keys, ref_name).await?
    else {
        // §8.5: seal the frontier (carrying our commit's version, set by the caller) before the
        // ref-advancing push.
        seal(frontier)?;
        let receipts = push_objects(remote, store, keys, our_commit).await?;
        let (head, blob) = push_head(
            remote,
            keys,
            device,
            ref_name,
            *our_commit,
            roster_seq,
            None,
        )
        .await?;
        return Ok(SyncReport {
            action: SyncAction::FastForward {
                commit_id: *our_commit,
            },
            frontier: frontier.clone(),
            wrote: Some((head, blob)),
            receipts,
        });
    };

    // 2. Resolve the signer (and thereby verify the head against a member key) and bring its closure
    //    local so the DAG/merge can read both histories (across generations via `keys`, §8.2).
    let signer = resolve_head_signer(members, &remote_head, &remote_sig)
        .ok_or(ClientError::HeadNotMember)?;
    fetch_closure(remote, store, keys, &remote_head.commit_id).await?;

    let sibling = SiblingHead {
        device_id: signer,
        head_version: remote_head.head_version,
        roster_seq: remote_head.roster_seq,
        commit_id: remote_head.commit_id,
    };

    // 3. Rollback-gated merge decision (reads cross-generation, seals the merge under current gen).
    let plan = merge_heads(frontier, our_commit, &sibling, author, keys, store)?;

    // 4. Apply: push whatever we authored and advance the ref (or fast-forward to the remote).
    let new_commit = match &plan.action {
        SyncAction::Merged { commit_id, .. } => Some(*commit_id),
        SyncAction::AlreadyHave => Some(*our_commit), // we are ahead → publish our commit
        SyncAction::FastForward { .. } => None,       // remote is ahead → adopt, nothing to push
    };

    let (wrote, receipts) = if let Some(commit_id) = new_commit {
        // §8.5: seal the observed frontier BEFORE publishing a head that descends from those
        // observations — a crash post-push must not leave the head uncovered by the frontier.
        seal(&plan.frontier)?;
        let receipts = push_objects(remote, store, keys, &commit_id).await?;
        let (head, blob) = push_head(
            remote,
            keys,
            device,
            ref_name,
            commit_id,
            roster_seq,
            Some((&remote_head, &remote_blob)),
        )
        .await?;
        (Some((head, blob)), receipts)
    } else {
        (None, Vec::new())
    };

    Ok(SyncReport {
        action: plan.action,
        frontier: plan.frontier,
        wrote,
        receipts,
    })
}

// ---- local frontier persistence (§8.5 / §9.8) ----

/// The result of [`load_frontier`].
#[derive(Debug)]
pub enum FrontierLoad {
    /// No state file. A genuine first run starts from a default frontier; for a repo known to be
    /// initialized, a missing file is itself a §8.5 lost-frontier event — the caller's policy.
    Absent,
    /// Loaded and authenticated against `device`.
    Loaded(SyncFrontier),
}

/// Load `device`'s sealed frontier from `path` (§8.5/§9.8). Missing file → [`FrontierLoad::Absent`];
/// present-but-unopenable → [`ClientError::FrontierLost`], the §8.5 lost-frontier event: the caller
/// MUST alarm and treat the session as a reinstall.
pub fn load_frontier(path: &Path, device: &DeviceKey) -> Result<FrontierLoad, ClientError> {
    let blob = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FrontierLoad::Absent),
        Err(e) => return Err(ClientError::Io(e)),
    };
    let key = device.local_seal_key()?;
    let device_id = device.device_id()?;
    match open_frontier(&key, &device_id, &blob) {
        Ok(f) => Ok(FrontierLoad::Loaded(f)),
        Err(e) => Err(ClientError::FrontierLost(e)),
    }
}

/// Seal `frontier` under `device`'s local-seal key (§8.5) and write it to `path` **atomically**
/// (temp file + rename, so a crash can't tear it). Per §8.5 the caller persists the advanced
/// frontier *before* publishing the head it authorized.
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
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &blob)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testmem::MemRemote;
    use secsec_kdf::MasterKey;
    use secsec_sig::DeviceKey;

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
    async fn second_push_chains_head_and_first_cas_token_guards() {
        let dir = tempfile::tempdir().unwrap();
        let m = mk();
        let device = DeviceKey::generate().unwrap();
        let a_store = open_store(dir.path(), "a.redb");
        let remote = MemRemote::new(open_store(dir.path(), "remote.redb"));

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

    fn write_dir(dir: &Path, files: &[(&str, &[u8])]) {
        for (name, content) in files {
            std::fs::write(dir.join(name), content).unwrap();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_commit(
        store: &Store,
        m: &MasterKey,
        dev: &DeviceKey,
        root_tree: Id,
        root_salt: PathSalt,
        parents: Vec<Id>,
        version: u64,
        last_seen: Id,
    ) -> Id {
        let commit = secsec_snapshot::Commit {
            root_tree,
            root_salt,
            parents,
            device_id: dev.device_id().unwrap(),
            version,
            roster_seq: 0,
            last_seen_head: last_seen,
            ts: 0,
        };
        secsec_snapshot::seal_signed_commit(m, store, dev, &commit).unwrap()
    }

    #[tokio::test]
    async fn two_devices_reconcile_through_blind_remote() {
        let dir = tempfile::tempdir().unwrap();
        let m = mk();
        let dev_a = DeviceKey::generate().unwrap();
        let dev_b = DeviceKey::generate().unwrap();
        let members: BTreeMap<DeviceId, DevicePublic> = [
            (dev_a.device_id().unwrap(), dev_a.public()),
            (dev_b.device_id().unwrap(), dev_b.public()),
        ]
        .into_iter()
        .collect();

        let remote = MemRemote::new(open_store(dir.path(), "remote.redb"));
        let a_store = open_store(dir.path(), "a.redb");
        let b_store = open_store(dir.path(), "b.redb");

        // base (A, v1): {keep:k0, shared:s0} → push + create head v1.
        let base = tempfile::tempdir().unwrap();
        write_dir(base.path(), &[("keep", b"k0"), ("shared", b"s0")]);
        let (bt, bs) = secsec_snapshot::snapshot_tree(base.path(), &m, &a_store, None).unwrap();
        let c_base = seal_commit(&a_store, &m, &dev_a, bt, bs, vec![], 1, [0u8; 32]);
        push_objects(&remote, &a_store, &m, &c_base).await.unwrap();
        let (h_base, b_base) = push_head(&remote, &m, &dev_a, "main", c_base, 0, None)
            .await
            .unwrap();

        // B clones the base so it can build on it.
        fetch_closure(&remote, &b_store, &m, &c_base).await.unwrap();

        // A edits "shared" → c_A (a, v2), advances the ref to head v2.
        let a_wt = tempfile::tempdir().unwrap();
        write_dir(a_wt.path(), &[("keep", b"k0"), ("shared", b"sA")]);
        let (at, asalt) =
            secsec_snapshot::snapshot_tree(a_wt.path(), &m, &a_store, Some((&bt, &bs))).unwrap();
        let c_a = seal_commit(&a_store, &m, &dev_a, at, asalt, vec![c_base], 2, c_base);
        push_objects(&remote, &a_store, &m, &c_a).await.unwrap();
        push_head(
            &remote,
            &m,
            &dev_a,
            "main",
            c_a,
            0,
            Some((&h_base, &b_base)),
        )
        .await
        .unwrap();

        // B edits "shared" DIFFERENTLY → c_B (b, v1), divergent, NOT pushed.
        let b_wt = tempfile::tempdir().unwrap();
        write_dir(b_wt.path(), &[("keep", b"k0"), ("shared", b"sB")]);
        let (bt2, bs2) =
            secsec_snapshot::snapshot_tree(b_wt.path(), &m, &b_store, Some((&bt, &bs))).unwrap();
        let c_b = seal_commit(&b_store, &m, &dev_b, bt2, bs2, vec![c_base], 1, c_base);

        // B syncs: fetch A's head, rollback-gated merge with c_B, push the merge + advance the ref.
        let seal = |_: &SyncFrontier| Ok::<(), ClientError>(());
        let rep_b = sync_ref(
            &remote,
            &b_store,
            &m,
            &members,
            &SyncFrontier::default(),
            "main",
            &c_b,
            CommitAuthor {
                device: &dev_b,
                version: 2,
                roster_seq: 0,
                ts: 0,
            },
            &seal,
        )
        .await
        .unwrap();
        let SyncAction::Merged {
            commit_id: merge_id,
            conflicts,
        } = rep_b.action
        else {
            panic!("B must perform a real merge")
        };
        assert_eq!(conflicts.len(), 1, "shared was edited on both sides");
        assert_eq!(conflicts[0].path, "shared");
        // the frontier observed A's head_version (A advanced the ref to v2 before B synced).
        assert_eq!(
            rep_b
                .frontier
                .head_version_hwm
                .get(&dev_a.device_id().unwrap()),
            Some(&2)
        );

        // The remote head now points at B's merge and is signed by B.
        let (rh, rsig, _) = fetch_head(&remote, &m, "main").await.unwrap().unwrap();
        assert_eq!(rh.commit_id, merge_id);
        assert_eq!(
            resolve_head_signer(&members, &rh, &rsig),
            Some(dev_b.device_id().unwrap())
        );

        // B's restored tree: shared kept-both, keep unchanged.
        let (mc, _) = secsec_snapshot::open_signed_commit(&merge_id, &m, &b_store).unwrap();
        let b_out = tempfile::tempdir().unwrap();
        secsec_snapshot::restore_commit_tree(&mc, &m, &b_store, b_out.path()).unwrap();
        let bf: BTreeMap<String, Vec<u8>> = read_tree(b_out.path()).into_iter().collect();
        assert_eq!(bf.get("keep").unwrap(), b"k0");
        assert_eq!(bf.get("shared").unwrap(), b"sB"); // ours (B) keeps the name
        assert!(
            bf.keys().any(|k| k.starts_with("shared.conflict-")),
            "A's divergent shared kept-both"
        );

        // A re-syncs: the remote merge descends from c_A → fast-forward, no new commit.
        let rep_a = sync_ref(
            &remote,
            &a_store,
            &m,
            &members,
            &SyncFrontier::default(),
            "main",
            &c_a,
            CommitAuthor {
                device: &dev_a,
                version: 3,
                roster_seq: 0,
                ts: 0,
            },
            &seal,
        )
        .await
        .unwrap();
        assert!(
            matches!(rep_a.action, SyncAction::FastForward { commit_id } if commit_id == merge_id)
        );
        assert!(rep_a.wrote.is_none());

        // A restores the same merged tree B produced.
        let (mca, _) = secsec_snapshot::open_signed_commit(&merge_id, &m, &a_store).unwrap();
        let a_out = tempfile::tempdir().unwrap();
        secsec_snapshot::restore_commit_tree(&mca, &m, &a_store, a_out.path()).unwrap();
        assert_eq!(read_tree(a_out.path()), read_tree(b_out.path()));
    }

    #[test]
    fn frontier_persists_across_restart_and_detects_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frontier.state");
        let device = DeviceKey::generate().unwrap();

        // missing file on a fresh repo → Absent (not yet a loss).
        assert!(matches!(
            load_frontier(&path, &device).unwrap(),
            FrontierLoad::Absent
        ));

        let f = SyncFrontier {
            roster_seq: 12,
            head_version_hwm: BTreeMap::from([(device.device_id().unwrap(), 5)]),
            commit_version_hwm: BTreeMap::from([(device.device_id().unwrap(), 9)]),
        };
        save_frontier(&path, &f, &device).unwrap();

        // "restart": re-load → identical frontier (rollback gates survive a process restart).
        let FrontierLoad::Loaded(got) = load_frontier(&path, &device).unwrap() else {
            panic!("expected a loaded frontier")
        };
        assert_eq!(got, f);

        // a different device cannot open it → lost-frontier event (the device_id AD binds it).
        let other = DeviceKey::generate().unwrap();
        assert!(matches!(
            load_frontier(&path, &other),
            Err(ClientError::FrontierLost(_))
        ));

        // a corrupted file is a lost-frontier event, not a silent reset.
        let mut blob = std::fs::read(&path).unwrap();
        *blob.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &blob).unwrap();
        assert!(matches!(
            load_frontier(&path, &device),
            Err(ClientError::FrontierLost(_))
        ));
    }
}
