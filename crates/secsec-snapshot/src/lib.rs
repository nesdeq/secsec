//! `secsec-snapshot` — the object graph and directory snapshot/restore (`finaldesign.md` §6, §9.2).
//!
//! A snapshot is a `Commit` pointing at a root `Tree`; trees list files (chunk-id lists) and
//! subtrees, content-addressed via [`secsec_object`]. [`snapshot`] walks a directory, chunks files
//! with keyed FastCDC, seals every chunk/tree/commit and `put`s it to a [`Store`]; [`restore`]
//! walks the commit back, `get`s each object, opens it with full verification (§9.2 three-way
//! check), un-pads, and rebuilds the directory byte-for-byte.
//!
//! **Per-path salts (§9.2/§9.7).** Each file's chunks and each subtree are addressed with a 16-byte
//! `path_salt`; a tree stores the salt of each child, and the commit stores the root tree's salt.
//! On restore the salts come from the parent object, so the id re-verification in
//! [`secsec_object::open_object`] is meaningful.
//!
//! **Incremental snapshots.** A path's salt is generated once (first sync) and is **constant across
//! all versions** (§9.7): [`snapshot_tree`] takes the previous root `(id, salt)` and reuses each
//! path's salt from the prior tree, so an unchanged file re-chunks to the identical ids. That
//! stability is what makes incremental upload/dedup and the three-way merge's content equality work
//! — it is not an optimization but a correctness requirement of the sync model.

#![forbid(unsafe_code)]

use secsec_canon::{CanonError, Reader, Writer};
use secsec_frame::{ObjType, MAX_LIST_ELEMENTS, MAX_TREE_DEPTH, MAX_TREE_FANOUT};
use secsec_kdf::MasterKey;
use secsec_object::{
    open_object, seal_object, unpad_chunk, Id, ObjError, Padding, PathSalt, ZERO_SALT,
};
use secsec_store::{Store, StoreError};
use std::path::Path;

/// Maximum length of a single path-component name (bytes).
pub const MAX_NAME: usize = 4096;

/// A directory listing (§6). Entries are kept sorted by name for a canonical encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// The directory's entries.
    pub entries: Vec<Entry>,
}

/// One tree entry: a file or a subdirectory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A regular file: its content is the concatenation of `chunks` (each padded then sealed),
    /// addressed with `path_salt`.
    File {
        /// File name (UTF-8 path component).
        name: String,
        /// Unix mode bits (0 on platforms without them).
        mode: u32,
        /// Modification time, seconds since the Unix epoch (advisory).
        mtime: u64,
        /// Plaintext size in bytes.
        size: u64,
        /// Per-file path salt used for this file's chunk ids.
        path_salt: PathSalt,
        /// Ordered chunk ids.
        chunks: Vec<Id>,
    },
    /// A subdirectory pointing at another `Tree` object.
    Dir {
        /// Directory name (UTF-8 path component).
        name: String,
        /// Unix mode bits (0 on platforms without them).
        mode: u32,
        /// Modification time, seconds since the Unix epoch (advisory).
        mtime: u64,
        /// Content address of the subtree object.
        subtree: Id,
        /// Path salt of the subtree object.
        subtree_salt: PathSalt,
    },
}

/// A snapshot commit (§6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// Root tree content address.
    pub root_tree: Id,
    /// Root tree path salt (stored here because the root has no parent tree).
    pub root_salt: PathSalt,
    /// Parent commit ids (empty for the first commit).
    pub parents: Vec<Id>,
    /// Authoring device id (`BLAKE3(pubkey)`; zero until identity exists).
    pub device_id: [u8; 32],
    /// Strictly increasing per-device version.
    pub version: u64,
    /// Roster sequence assumed by this commit.
    pub roster_seq: u64,
    /// Head the author last saw (zero if none).
    pub last_seen_head: [u8; 32],
    /// Author-asserted timestamp (advisory; never trusted for security).
    pub ts: u64,
}

/// Errors from snapshot / restore.
#[derive(Debug)]
pub enum SnapError {
    /// Filesystem I/O error.
    Io(std::io::Error),
    /// Object store error.
    Store(StoreError),
    /// Object open/verify error.
    Object(ObjError),
    /// Canonical decode error.
    Canon(CanonError),
    /// A required object was not present in the store.
    Missing(Id),
    /// A decoded structure was malformed.
    Malformed(&'static str),
    /// Tree nesting exceeded `MAX_TREE_DEPTH`.
    DepthExceeded,
    /// A directory entry was neither a regular file nor a directory.
    UnsupportedFileType,
    /// A file name was not valid UTF-8.
    NonUtf8Name,
    /// OS RNG failure.
    Rng,
    /// Commit signature invalid, or the signer is not the commit's author (§9.6).
    BadSignature,
    /// Signing/key error.
    Sig(secsec_sig::SigError),
}

impl core::fmt::Display for SnapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SnapError::Io(e) => write!(f, "io: {e}"),
            SnapError::Store(e) => write!(f, "store: {e}"),
            SnapError::Object(e) => write!(f, "object: {e}"),
            SnapError::Canon(e) => write!(f, "decode: {e}"),
            SnapError::Missing(_) => f.write_str("required object missing from store"),
            SnapError::Malformed(s) => write!(f, "malformed: {s}"),
            SnapError::DepthExceeded => f.write_str("tree nesting too deep"),
            SnapError::UnsupportedFileType => f.write_str("unsupported file type"),
            SnapError::NonUtf8Name => f.write_str("non-UTF-8 file name"),
            SnapError::Rng => f.write_str("OS RNG failure"),
            SnapError::BadSignature => f.write_str("commit signature invalid or wrong author"),
            SnapError::Sig(e) => write!(f, "sig: {e}"),
        }
    }
}

impl std::error::Error for SnapError {}
impl From<std::io::Error> for SnapError {
    fn from(e: std::io::Error) -> Self {
        SnapError::Io(e)
    }
}
impl From<StoreError> for SnapError {
    fn from(e: StoreError) -> Self {
        SnapError::Store(e)
    }
}
impl From<ObjError> for SnapError {
    fn from(e: ObjError) -> Self {
        SnapError::Object(e)
    }
}
impl From<CanonError> for SnapError {
    fn from(e: CanonError) -> Self {
        SnapError::Canon(e)
    }
}
impl From<secsec_sig::SigError> for SnapError {
    fn from(e: secsec_sig::SigError) -> Self {
        SnapError::Sig(e)
    }
}

fn random_salt() -> Result<PathSalt, SnapError> {
    let mut s = [0u8; 16];
    getrandom::fill(&mut s).map_err(|_| SnapError::Rng)?;
    Ok(s)
}

fn arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a
}
fn arr16(b: &[u8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(b);
    a
}

// ---- canonical encoding (§9.3) ----

const ENTRY_FILE: u8 = 0;
const ENTRY_DIR: u8 = 1;

fn encode_tree(tree: &Tree) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(tree.entries.len() as u32);
    for e in &tree.entries {
        match e {
            Entry::File {
                name,
                mode,
                mtime,
                size,
                path_salt,
                chunks,
            } => {
                w.u8(ENTRY_FILE)
                    .bytes(name.as_bytes())
                    .u32(*mode)
                    .u64(*mtime)
                    .u64(*size)
                    .raw(path_salt)
                    .u32(chunks.len() as u32);
                for c in chunks {
                    w.raw(c);
                }
            }
            Entry::Dir {
                name,
                mode,
                mtime,
                subtree,
                subtree_salt,
            } => {
                w.u8(ENTRY_DIR)
                    .bytes(name.as_bytes())
                    .u32(*mode)
                    .u64(*mtime)
                    .raw(subtree)
                    .raw(subtree_salt);
            }
        }
    }
    w.finish()
}

fn decode_tree(bytes: &[u8]) -> Result<Tree, SnapError> {
    let mut r = Reader::new(bytes);
    let count = r.u32()? as usize;
    if count > MAX_TREE_FANOUT {
        return Err(SnapError::Malformed("tree fan-out exceeds maximum"));
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = r.u8()?;
        let name =
            String::from_utf8(r.bytes(MAX_NAME)?.to_vec()).map_err(|_| SnapError::NonUtf8Name)?;
        let mode = r.u32()?;
        let mtime = r.u64()?;
        match kind {
            ENTRY_FILE => {
                let size = r.u64()?;
                let path_salt = arr16(r.raw(16)?);
                let chunk_count = r.u32()? as usize;
                if chunk_count > MAX_LIST_ELEMENTS {
                    return Err(SnapError::Malformed("chunk list exceeds maximum"));
                }
                let mut chunks = Vec::with_capacity(chunk_count);
                for _ in 0..chunk_count {
                    chunks.push(arr32(r.raw(32)?));
                }
                entries.push(Entry::File {
                    name,
                    mode,
                    mtime,
                    size,
                    path_salt,
                    chunks,
                });
            }
            ENTRY_DIR => {
                let subtree = arr32(r.raw(32)?);
                let subtree_salt = arr16(r.raw(16)?);
                entries.push(Entry::Dir {
                    name,
                    mode,
                    mtime,
                    subtree,
                    subtree_salt,
                });
            }
            _ => return Err(SnapError::Malformed("unknown tree entry kind")),
        }
    }
    r.finish()?;
    Ok(Tree { entries })
}

/// Maximum stored commit-signature length (an SSHSIG PEM is well under this).
const MAX_COMMIT_SIG: usize = 4096;

fn write_commit_fields(w: &mut Writer, c: &Commit) {
    w.raw(&c.root_tree)
        .raw(&c.root_salt)
        .u32(c.parents.len() as u32);
    for p in &c.parents {
        w.raw(p);
    }
    w.raw(&c.device_id)
        .u64(c.version)
        .u64(c.roster_seq)
        .raw(&c.last_seen_head)
        .u64(c.ts);
}

fn read_commit_fields(r: &mut Reader<'_>) -> Result<Commit, SnapError> {
    let root_tree = arr32(r.raw(32)?);
    let root_salt = arr16(r.raw(16)?);
    let parent_count = r.u32()? as usize;
    if parent_count > MAX_LIST_ELEMENTS {
        return Err(SnapError::Malformed("parent list exceeds maximum"));
    }
    let mut parents = Vec::with_capacity(parent_count);
    for _ in 0..parent_count {
        parents.push(arr32(r.raw(32)?));
    }
    let device_id = arr32(r.raw(32)?);
    let version = r.u64()?;
    let roster_seq = r.u64()?;
    let last_seen_head = arr32(r.raw(32)?);
    let ts = r.u64()?;
    Ok(Commit {
        root_tree,
        root_salt,
        parents,
        device_id,
        version,
        roster_seq,
        last_seen_head,
        ts,
    })
}

fn encode_commit(c: &Commit) -> Vec<u8> {
    let mut w = Writer::new();
    write_commit_fields(&mut w, c);
    w.finish()
}

fn decode_commit(bytes: &[u8]) -> Result<Commit, SnapError> {
    let mut r = Reader::new(bytes);
    let c = read_commit_fields(&mut r)?;
    r.finish()?;
    Ok(c)
}

/// The stored signed-commit object: the canonical commit fields followed by the SSHSIG (§9.6).
fn encode_signed_commit(c: &Commit, sig: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    write_commit_fields(&mut w, c);
    w.bytes(sig);
    w.finish()
}

fn decode_signed_commit(bytes: &[u8]) -> Result<(Commit, Vec<u8>), SnapError> {
    let mut r = Reader::new(bytes);
    let c = read_commit_fields(&mut r)?;
    let sig = r.bytes(MAX_COMMIT_SIG)?.to_vec();
    r.finish()?;
    Ok((c, sig))
}

// ---- commit signing (§9.6 secsec-commit-v1) ----

impl Commit {
    /// The canonical signed message — the commit's encoded fields (§9.3/§9.6). The `device_id`,
    /// `version`, `roster_seq`, and `last_seen_head` are all covered, binding the commit to its
    /// author, its replay counter, the roster state it assumed, and the head it last saw.
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        encode_commit(self)
    }
}

/// Sign a commit under [`secsec_sig::NS_COMMIT`] (§9.6). The signer should be the device named by
/// `commit.device_id`; [`verify_commit`] enforces that.
pub fn sign_commit(device: &secsec_sig::DeviceKey, commit: &Commit) -> Result<Vec<u8>, SnapError> {
    Ok(device.sign(secsec_sig::NS_COMMIT, &commit.signed_message())?)
}

/// Verify a commit signature: the SSHSIG must be valid under `NS_COMMIT` **and** `pubkey` must be the
/// commit's author (`pubkey.device_id() == commit.device_id`). The caller resolves `pubkey` from the
/// RFP-anchored roster (§8) for `commit.device_id`, so a non-member cannot forge a commit (§9.6 P3).
pub fn verify_commit(
    pubkey: &secsec_sig::DevicePublic,
    commit: &Commit,
    sig: &[u8],
) -> Result<(), SnapError> {
    if pubkey.device_id()? != commit.device_id {
        return Err(SnapError::BadSignature);
    }
    pubkey
        .verify(secsec_sig::NS_COMMIT, &commit.signed_message(), sig)
        .map_err(|_| SnapError::BadSignature)
}

// ---- snapshot ----

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}
#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    0
}

fn mtime_of(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// Snapshot the directory `root` into `store` under `mk` and return its root **tree** id and salt
/// (no commit). This is the content half of a sync push; the orchestration wraps it in a signed
/// commit (see [`seal_signed_commit`]) carrying the version/roster_seq/parent metadata (§10).
///
/// `prev` is the previous snapshot's root `(tree_id, salt)`, or `None` for the very first sync. When
/// given, every path's salt is **reused** from the prior tree (§9.2/§9.7: a path's `path_salt` is
/// generated once at first sync and is constant across all versions). This is what makes an
/// unchanged file re-chunk to the **same** ids — the basis for incremental upload/dedup and for the
/// three-way merge's content equality. Only genuinely new paths get a fresh random salt.
pub fn snapshot_tree(
    root: &Path,
    mk: &MasterKey,
    store: &Store,
    prev: Option<(&Id, &PathSalt)>,
) -> Result<(Id, PathSalt), SnapError> {
    let chunker = secsec_chunk::Chunker::with_defaults(&mk.cdc_seed());
    let prev_tree = match prev {
        Some((id, salt)) => Some(load_tree(id, salt, mk, store)?),
        None => None,
    };
    // The root tree's own salt persists too (reused if the repo has synced before).
    let root_salt = match prev {
        Some((_, salt)) => *salt,
        None => random_salt()?,
    };
    snapshot_dir(root, mk, store, &chunker, 0, prev_tree.as_ref(), root_salt)
}

/// The name field of a tree entry (file or dir).
fn entry_name(e: &Entry) -> &str {
    match e {
        Entry::File { name, .. } | Entry::Dir { name, .. } => name,
    }
}

/// Snapshot `root` into `store` under `mk`; returns the commit id. `ts` is the author-asserted
/// timestamp to record (advisory). The commit is **unsigned** with placeholder metadata — for the
/// object-graph round trip and tests. Sync uses [`snapshot_tree`] + [`seal_signed_commit`].
pub fn snapshot(root: &Path, mk: &MasterKey, store: &Store, ts: u64) -> Result<Id, SnapError> {
    let (root_tree, root_salt) = snapshot_tree(root, mk, store, None)?;
    let commit = Commit {
        root_tree,
        root_salt,
        parents: Vec::new(),
        device_id: [0u8; 32],
        version: 1,
        roster_seq: 0,
        last_seen_head: [0u8; 32],
        ts,
    };
    let (id, blob) = seal_object(mk, ObjType::Commit, &ZERO_SALT, &encode_commit(&commit));
    store.put(&id, &blob)?;
    Ok(id)
}

/// Sign `commit` (under `NS_COMMIT`, §9.6), seal the signed-commit object (fields ‖ sig) under `mk`,
/// store it, and return its content id. The signer must be `commit.device_id` (a member key); the
/// content id is the commit id a Head points at. See [`open_signed_commit`] for the read side.
pub fn seal_signed_commit(
    mk: &MasterKey,
    store: &Store,
    device: &secsec_sig::DeviceKey,
    commit: &Commit,
) -> Result<Id, SnapError> {
    let sig = sign_commit(device, commit)?;
    let bytes = encode_signed_commit(commit, &sig);
    let (id, blob) = seal_object(mk, ObjType::Commit, &ZERO_SALT, &bytes);
    store.put(&id, &blob)?;
    Ok(id)
}

/// Fetch and open the signed-commit object `commit_id` from `store`, returning the decoded commit and
/// its signature. The content id is re-verified by [`open_object`]; the caller still must
/// [`verify_commit`] the signature against the author's roster key before trusting the commit (§9.6).
pub fn open_signed_commit(
    commit_id: &Id,
    mk: &MasterKey,
    store: &Store,
) -> Result<(Commit, Vec<u8>), SnapError> {
    let bytes = fetch_open(mk, ObjType::Commit, &ZERO_SALT, commit_id, store)?;
    decode_signed_commit(&bytes)
}

/// Restore the tree named by `commit` (its `root_tree`/`root_salt`) into `dest` (created if absent).
/// The caller is expected to have already [`verify_commit`]-ed the commit (§9.6).
pub fn restore_commit_tree(
    commit: &Commit,
    mk: &MasterKey,
    store: &Store,
    dest: &Path,
) -> Result<(), SnapError> {
    std::fs::create_dir_all(dest)?;
    restore_tree(&commit.root_tree, &commit.root_salt, mk, store, dest, 0)
}

fn snapshot_dir(
    dir: &Path,
    mk: &MasterKey,
    store: &Store,
    chunker: &secsec_chunk::Chunker,
    depth: usize,
    prev: Option<&Tree>,
    this_salt: PathSalt,
) -> Result<(Id, PathSalt), SnapError> {
    if depth > MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    // Read and sort entries by name for a deterministic, canonical tree.
    let mut names: Vec<std::ffi::OsString> = Vec::new();
    for ent in std::fs::read_dir(dir)? {
        names.push(ent?.file_name());
    }
    names.sort();

    let mut entries = Vec::with_capacity(names.len());
    for name_os in names {
        let name = name_os.to_str().ok_or(SnapError::NonUtf8Name)?.to_owned();
        let path = dir.join(&name_os);
        let meta = std::fs::symlink_metadata(&path)?;
        let ft = meta.file_type();
        // The same-named entry in the prior tree (if any), used to reuse this path's salt.
        let prev_entry = prev.and_then(|t| t.entries.iter().find(|e| entry_name(e) == name));
        if ft.is_file() {
            let data = std::fs::read(&path)?;
            // Reuse the path's salt across versions (§9.7); a path first seen now gets a fresh one.
            let path_salt = match prev_entry {
                Some(Entry::File { path_salt, .. }) => *path_salt,
                _ => random_salt()?,
            };
            let mut chunks = Vec::new();
            for chunk in chunker.chunks(&data) {
                let padded = secsec_object::pad_chunk(chunk, Padding::PowerOfTwo);
                let (id, blob) = seal_object(mk, ObjType::Chunk, &path_salt, &padded);
                store.put(&id, &blob)?;
                chunks.push(id);
            }
            entries.push(Entry::File {
                name,
                mode: mode_of(&meta),
                mtime: mtime_of(&meta),
                size: data.len() as u64,
                path_salt,
                chunks,
            });
        } else if ft.is_dir() {
            // Reuse the subdir's salt and feed its prior tree down so its descendants reuse salts too.
            let (prev_sub, sub_salt) = match prev_entry {
                Some(Entry::Dir {
                    subtree,
                    subtree_salt,
                    ..
                }) => (
                    Some(load_tree(subtree, subtree_salt, mk, store)?),
                    *subtree_salt,
                ),
                _ => (None, random_salt()?),
            };
            let (subtree, subtree_salt) = snapshot_dir(
                &path,
                mk,
                store,
                chunker,
                depth + 1,
                prev_sub.as_ref(),
                sub_salt,
            )?;
            entries.push(Entry::Dir {
                name,
                mode: mode_of(&meta),
                mtime: mtime_of(&meta),
                subtree,
                subtree_salt,
            });
        } else {
            return Err(SnapError::UnsupportedFileType);
        }
    }

    let tree = Tree { entries };
    let (id, blob) = seal_object(mk, ObjType::Tree, &this_salt, &encode_tree(&tree));
    store.put(&id, &blob)?;
    Ok((id, this_salt))
}

// ---- restore ----

fn fetch_open(
    mk: &MasterKey,
    obj_type: ObjType,
    salt: &PathSalt,
    id: &Id,
    store: &Store,
) -> Result<Vec<u8>, SnapError> {
    let blob = store.get(id)?.ok_or(SnapError::Missing(*id))?;
    Ok(open_object(mk, obj_type, salt, id, &blob)?)
}

/// Restore the snapshot `commit_id` from `store` into `dest` (created if absent).
pub fn restore(
    commit_id: &Id,
    mk: &MasterKey,
    store: &Store,
    dest: &Path,
) -> Result<(), SnapError> {
    let commit = decode_commit(&fetch_open(
        mk,
        ObjType::Commit,
        &ZERO_SALT,
        commit_id,
        store,
    )?)?;
    std::fs::create_dir_all(dest)?;
    restore_tree(&commit.root_tree, &commit.root_salt, mk, store, dest, 0)
}

fn restore_tree(
    tree_id: &Id,
    tree_salt: &PathSalt,
    mk: &MasterKey,
    store: &Store,
    dir: &Path,
    depth: usize,
) -> Result<(), SnapError> {
    if depth > MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    let tree = decode_tree(&fetch_open(mk, ObjType::Tree, tree_salt, tree_id, store)?)?;
    std::fs::create_dir_all(dir)?;
    for entry in &tree.entries {
        match entry {
            Entry::File {
                name,
                size,
                path_salt,
                chunks,
                ..
            } => {
                let mut data = Vec::new();
                for cid in chunks {
                    let padded = fetch_open(mk, ObjType::Chunk, path_salt, cid, store)?;
                    data.extend_from_slice(unpad_chunk(&padded, Padding::PowerOfTwo)?);
                }
                if data.len() as u64 != *size {
                    return Err(SnapError::Malformed("restored file size mismatch"));
                }
                std::fs::write(dir.join(name), &data)?;
            }
            Entry::Dir {
                name,
                subtree,
                subtree_salt,
                ..
            } => {
                restore_tree(subtree, subtree_salt, mk, store, &dir.join(name), depth + 1)?;
            }
        }
    }
    Ok(())
}

// ---- tree bridge primitives (§10 merge orchestration) ----
//
// Single-level tree I/O exposed for the sync engine, which converts a `Tree` to/from its in-memory
// merge model and drives the recursion itself (it does not pull `secsec-sync` in here).

/// Fetch, open (re-verifying the content address, §9.2), and decode a single `Tree` object. Used by
/// the merge engine to materialize one directory level; it recurses on `Entry::Dir` children itself.
pub fn load_tree(
    tree_id: &Id,
    tree_salt: &PathSalt,
    mk: &MasterKey,
    store: &Store,
) -> Result<Tree, SnapError> {
    decode_tree(&fetch_open(mk, ObjType::Tree, tree_salt, tree_id, store)?)
}

/// Seal a single `Tree` object under a fresh random salt, store it, and return its `(id, salt)`. The
/// caller seals child subtrees first and records each child's returned salt in its `Entry::Dir`.
pub fn seal_tree(tree: &Tree, mk: &MasterKey, store: &Store) -> Result<(Id, PathSalt), SnapError> {
    let salt = random_salt()?;
    let (id, blob) = seal_object(mk, ObjType::Tree, &salt, &encode_tree(tree));
    store.put(&id, &blob)?;
    Ok((id, salt))
}

/// Restore the tree named by `(tree_id, tree_salt)` into `dest` (created if absent). Like [`restore`]
/// but starting from a bare tree id rather than a commit — used to materialize a merged tree.
pub fn restore_tree_into(
    tree_id: &Id,
    tree_salt: &PathSalt,
    mk: &MasterKey,
    store: &Store,
    dest: &Path,
) -> Result<(), SnapError> {
    std::fs::create_dir_all(dest)?;
    restore_tree(tree_id, tree_salt, mk, store, dest, 0)
}

// ---- reachable closure (GC keep-set, §15) ----

/// The full set of object ids reachable from `heads` (commit ids): each head, its transitive commit
/// parents, every tree/subtree, and every chunk (§15 keep-set). Each commit/tree is fetched, opened
/// (so §9.2 content-addressing is re-verified), and decoded; a **missing** object anywhere in the
/// closure returns [`SnapError::Missing`] so GC **fails safe** (never deletes when the keep-set is
/// incomplete, §15). The caller hashes the result with `secsec_proto::gc::keep_set_hash`.
pub fn reachable_objects(
    mk: &MasterKey,
    store: &Store,
    heads: &[Id],
) -> Result<std::collections::BTreeSet<Id>, SnapError> {
    use std::collections::BTreeSet;
    let mut reachable: BTreeSet<Id> = BTreeSet::new();
    let mut commits_done: BTreeSet<Id> = BTreeSet::new();
    let mut work: Vec<Id> = heads.to_vec();

    while let Some(cid) = work.pop() {
        if !commits_done.insert(cid) {
            continue;
        }
        reachable.insert(cid);
        let commit = decode_commit(&fetch_open(mk, ObjType::Commit, &ZERO_SALT, &cid, store)?)?;
        collect_tree(
            mk,
            store,
            &commit.root_tree,
            &commit.root_salt,
            0,
            &mut reachable,
        )?;
        for parent in commit.parents {
            work.push(parent);
        }
    }
    Ok(reachable)
}

fn collect_tree(
    mk: &MasterKey,
    store: &Store,
    tree_id: &Id,
    tree_salt: &PathSalt,
    depth: usize,
    reachable: &mut std::collections::BTreeSet<Id>,
) -> Result<(), SnapError> {
    if depth > MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    if !reachable.insert(*tree_id) {
        return Ok(()); // shared subtree already walked
    }
    let tree = decode_tree(&fetch_open(mk, ObjType::Tree, tree_salt, tree_id, store)?)?;
    for entry in &tree.entries {
        match entry {
            Entry::File { chunks, .. } => {
                for cid in chunks {
                    reachable.insert(*cid);
                }
            }
            Entry::Dir {
                subtree,
                subtree_salt,
                ..
            } => collect_tree(mk, store, subtree, subtree_salt, depth + 1, reachable)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn mk() -> MasterKey {
        MasterKey::new(1, [0x66; 32])
    }

    #[test]
    fn tree_commit_encode_round_trip() {
        let tree = Tree {
            entries: vec![
                Entry::File {
                    name: "a.txt".into(),
                    mode: 0o644,
                    mtime: 111,
                    size: 5,
                    path_salt: [1u8; 16],
                    chunks: vec![[2u8; 32], [3u8; 32]],
                },
                Entry::Dir {
                    name: "sub".into(),
                    mode: 0o755,
                    mtime: 222,
                    subtree: [4u8; 32],
                    subtree_salt: [5u8; 16],
                },
            ],
        };
        assert_eq!(decode_tree(&encode_tree(&tree)).unwrap(), tree);

        let commit = Commit {
            root_tree: [9u8; 32],
            root_salt: [8u8; 16],
            parents: vec![[7u8; 32]],
            device_id: [6u8; 32],
            version: 3,
            roster_seq: 2,
            last_seen_head: [5u8; 32],
            ts: 1234,
        };
        assert_eq!(decode_commit(&encode_commit(&commit)).unwrap(), commit);
    }

    #[test]
    fn commit_sign_verify_and_author_binding() {
        use secsec_sig::DeviceKey;
        let dev = DeviceKey::generate().unwrap();
        let commit = Commit {
            root_tree: [9u8; 32],
            root_salt: [8u8; 16],
            parents: vec![[7u8; 32]],
            device_id: dev.device_id().unwrap(), // author = dev
            version: 3,
            roster_seq: 2,
            last_seen_head: [5u8; 32],
            ts: 1234,
        };
        let sig = sign_commit(&dev, &commit).unwrap();
        assert!(verify_commit(&dev.public(), &commit, &sig).is_ok());

        // a key that isn't the named author is rejected (device_id binding, §9.6).
        let other = DeviceKey::generate().unwrap();
        assert!(matches!(
            verify_commit(&other.public(), &commit, &sig),
            Err(SnapError::BadSignature)
        ));

        // tampering any signed field invalidates the signature.
        let mut tampered = commit.clone();
        tampered.version = 4;
        assert!(matches!(
            verify_commit(&dev.public(), &tampered, &sig),
            Err(SnapError::BadSignature)
        ));
    }

    /// Read a directory tree into a sorted map of relative-path -> contents for comparison.
    fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            let mut ents: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            ents.sort();
            for p in ents {
                let rel = p
                    .strip_prefix(base)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/");
                if p.is_dir() {
                    out.insert(format!("{rel}/"), Vec::new());
                    walk(base, &p, out);
                } else {
                    out.insert(rel, std::fs::read(&p).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(root, root, &mut out);
        out
    }

    #[test]
    fn snapshot_then_restore_is_byte_identical() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let m = mk();

        // Build a directory tree: empty file, small file, a >256 KiB file (multi-chunk),
        // and nested subdirs.
        std::fs::write(src.path().join("empty"), b"").unwrap();
        std::fs::write(src.path().join("small.txt"), b"hello world").unwrap();
        let mut big = vec![0u8; 700 * 1024];
        // random content so the file actually splits into several chunks
        getrandom::fill(&mut big).unwrap();
        std::fs::write(src.path().join("big.bin"), &big).unwrap();
        std::fs::create_dir_all(src.path().join("sub/deeper")).unwrap();
        std::fs::write(src.path().join("sub/note.md"), b"# note\n").unwrap();
        std::fs::write(src.path().join("sub/deeper/leaf"), [7u8; 40 * 1024]).unwrap();

        let commit_id = snapshot(src.path(), &m, &store, 0).unwrap();
        restore(&commit_id, &m, &store, dst.path()).unwrap();

        assert_eq!(
            read_tree(src.path()),
            read_tree(dst.path()),
            "restored tree differs from source"
        );
    }

    #[test]
    fn signed_commit_lifecycle_round_trips() {
        use secsec_sig::DeviceKey;
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let m = mk();
        let device = DeviceKey::generate().unwrap();

        std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b.bin"), [3u8; 8 * 1024]).unwrap();

        // produce side: snapshot the tree, wrap it in a signed commit, seal+store it.
        let (root_tree, root_salt) = snapshot_tree(src.path(), &m, &store, None).unwrap();
        let commit = Commit {
            root_tree,
            root_salt,
            parents: vec![[0x44u8; 32]],
            device_id: device.device_id().unwrap(),
            version: 7,
            roster_seq: 2,
            last_seen_head: [0x55u8; 32],
            ts: 99,
        };
        let commit_id = seal_signed_commit(&m, &store, &device, &commit).unwrap();

        // consume side: fetch, verify against the author key, restore the tree.
        let (got, sig) = open_signed_commit(&commit_id, &m, &store).unwrap();
        assert_eq!(got, commit);
        verify_commit(&device.public(), &got, &sig).unwrap();
        restore_commit_tree(&got, &m, &store, dst.path()).unwrap();

        assert_eq!(read_tree(src.path()), read_tree(dst.path()));

        // a forged commit by a non-author is rejected on the consume side.
        let attacker = DeviceKey::generate().unwrap();
        assert!(matches!(
            verify_commit(&attacker.public(), &got, &sig),
            Err(SnapError::BadSignature)
        ));
    }

    #[test]
    fn incremental_snapshot_reuses_salts_and_is_idempotent() {
        let src = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let m = mk();

        std::fs::write(src.path().join("a.txt"), b"AAAA").unwrap();
        std::fs::write(src.path().join("b.txt"), b"BBBB").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/c"), b"CCCC").unwrap();

        let (id1, salt1) = snapshot_tree(src.path(), &m, &store, None).unwrap();
        let tree1 = load_tree(&id1, &salt1, &m, &store).unwrap();

        // Re-snapshot with NO change, feeding the prior tree: full idempotence — identical root id
        // and salt (§9.2/§9.7: salts are constant across versions). Without salt reuse this would
        // mint all-new ids.
        let (id2, salt2) = snapshot_tree(src.path(), &m, &store, Some((&id1, &salt1))).unwrap();
        assert_eq!(
            id1, id2,
            "unchanged repo must produce the identical root tree id"
        );
        assert_eq!(salt1, salt2);

        // Change exactly one file; unchanged paths keep their entries verbatim (same salt → same
        // chunk ids → idempotent put), only a.txt's chunks change, and the root salt persists.
        std::fs::write(src.path().join("a.txt"), b"A-modified").unwrap();
        let (id3, salt3) = snapshot_tree(src.path(), &m, &store, Some((&id2, &salt2))).unwrap();
        assert_ne!(id1, id3, "a real change must change the root tree");
        assert_eq!(salt3, salt1, "root salt persists across versions");
        let tree3 = load_tree(&id3, &salt3, &m, &store).unwrap();

        let find = |t: &Tree, n: &str| {
            t.entries
                .iter()
                .find(|e| entry_name(e) == n)
                .unwrap()
                .clone()
        };
        // b.txt and the sub/ subtree are byte-for-byte the same entries as before.
        assert_eq!(find(&tree1, "b.txt"), find(&tree3, "b.txt"));
        assert_eq!(find(&tree1, "sub"), find(&tree3, "sub"));
        // a.txt: salt reused (constant per path), chunk ids differ (content changed).
        let (
            Entry::File {
                path_salt: ps1,
                chunks: ch1,
                ..
            },
            Entry::File {
                path_salt: ps3,
                chunks: ch3,
                ..
            },
        ) = (find(&tree1, "a.txt"), find(&tree3, "a.txt"))
        else {
            panic!("a.txt must be a file")
        };
        assert_eq!(ps1, ps3, "path_salt is constant across versions");
        assert_ne!(ch1, ch3, "changed content yields new chunk ids");
    }

    #[test]
    fn reachable_objects_covers_graph_and_fails_safe() {
        let src = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let m = mk();

        std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b.bin"), [3u8; 8 * 1024]).unwrap();

        let commit_id = snapshot(src.path(), &m, &store, 0).unwrap();
        let reachable = reachable_objects(&m, &store, &[commit_id]).unwrap();

        // every stored object is reachable from the single commit (no garbage; keep-everything).
        assert_eq!(reachable.len() as u64, store.object_count().unwrap());
        assert!(reachable.contains(&commit_id));

        // fail-safe (§15): an empty store can't resolve the commit → Missing, so GC must not proceed.
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = Store::open(empty_dir.path().join("e.redb")).unwrap();
        assert!(matches!(
            reachable_objects(&m, &empty, &[commit_id]),
            Err(SnapError::Missing(_))
        ));
    }

    #[test]
    fn restore_detects_missing_object() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let m = mk();
        std::fs::write(src.path().join("f"), b"data").unwrap();
        let commit_id = snapshot(src.path(), &m, &store, 0).unwrap();

        // Restoring against a *fresh empty* store must fail (commit object missing), not panic.
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = Store::open(empty_dir.path().join("e.redb")).unwrap();
        assert!(matches!(
            restore(&commit_id, &m, &empty, dst.path()),
            Err(SnapError::Missing(_))
        ));
    }
}
