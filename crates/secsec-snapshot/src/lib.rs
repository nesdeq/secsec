//! The Tree/Commit object graph and directory snapshot/restore (`secsec-Design.md` §6, §9.2, §10).

#![forbid(unsafe_code)]

use secsec_canon::{CanonError, Reader, Writer};
use secsec_frame::{
    ObjType, MAX_BLOB_SIZE, MAX_CHUNKS_PER_FILE, MAX_LIST_ELEMENTS, MAX_NAME_LEN, MAX_TREE_DEPTH,
    MAX_TREE_FANOUT,
};
use secsec_kdf::{MasterKey, MasterKeys};
use secsec_object::{
    open_object, seal_object, unpad_chunk, Id, ObjError, Padding, PathSalt, ZERO_SALT,
};
use secsec_sig::MAX_SIG_LEN;
use secsec_store::{Store, StoreError};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Name prefix of restore's temporary files; the scanner and reconcile never treat such names as user files.
pub const TMP_PREFIX: &str = ".secsec-tmp-";

/// A directory listing (§6), entries sorted by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// The directory's entries.
    pub entries: Vec<Entry>,
}

/// One tree entry: a file or a subdirectory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A regular file: the concatenation of `chunks`, addressed with `path_salt`.
    File {
        /// File name (one UTF-8 path component).
        name: String,
        /// Unix permission bits (0 when the author had none).
        mode: u32,
        /// Modification time, nanoseconds since the epoch (advisory).
        mtime: u64,
        /// Plaintext size in bytes.
        size: u64,
        /// Per-file path salt for the chunk ids.
        path_salt: PathSalt,
        /// Ordered chunk ids.
        chunks: Vec<Id>,
    },
    /// A subdirectory pointing at another `Tree` object.
    Dir {
        /// Directory name (one UTF-8 path component).
        name: String,
        /// Unix permission bits (0 when the author had none).
        mode: u32,
        /// Modification time, nanoseconds since the epoch (advisory).
        mtime: u64,
        /// Content address of the subtree.
        subtree: Id,
        /// Path salt of the subtree.
        subtree_salt: PathSalt,
    },
}

/// A snapshot commit (§6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// Root tree content address.
    pub root_tree: Id,
    /// Root tree path salt (the root has no parent tree).
    pub root_salt: PathSalt,
    /// Parent commit ids (empty for a first commit).
    pub parents: Vec<Id>,
    /// Authoring device id.
    pub device_id: [u8; 32],
    /// Strictly increasing per-device version.
    pub version: u64,
    /// Roster sequence the commit was written under.
    pub roster_seq: u64,
    /// Head the author last saw (zero if none).
    pub last_seen_head: [u8; 32],
    /// Author-asserted timestamp (advisory).
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
    /// A file name was not valid UTF-8.
    NonUtf8Name,
    /// OS RNG failure.
    Rng,
    /// Commit signature invalid, or the signer is not the commit's author (§9.6).
    BadSignature,
    /// A requested path did not exist in the resolved tree.
    PathNotFound(String),
    /// The requested version's content is pruned beyond retention (§15).
    PrunedBeyondRetention(String),
    /// A directory cannot be encoded into a decodable tree (§19 fan-out or object cap).
    TreeTooLarge(String),
    /// A restore target was not a clean path inside the destination root.
    UnsafePath(String),
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
            SnapError::NonUtf8Name => f.write_str("non-UTF-8 file name"),
            SnapError::Rng => f.write_str("OS RNG failure"),
            SnapError::BadSignature => f.write_str("commit signature invalid or wrong author"),
            SnapError::PathNotFound(p) => write!(f, "path not found in that version: {p}"),
            SnapError::PrunedBeyondRetention(p) => {
                write!(
                    f,
                    "the requested version of {p} has been pruned beyond retention"
                )
            }
            SnapError::TreeTooLarge(d) => {
                write!(
                    f,
                    "the directory {d} cannot be encoded into a decodable tree (§19 limits: at most \
                     {MAX_TREE_FANOUT} entries and {MAX_BLOB_SIZE} encoded bytes, 32 of them per \
                     chunk id); split it across subdirectories"
                )
            }
            SnapError::UnsafePath(p) => write!(f, "unsafe restore path: {p}"),
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

fn random_bytes<const N: usize>() -> Result<[u8; N], SnapError> {
    let mut s = [0u8; N];
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

/// §18 name guard, enforced both ways: one non-empty component, no `.`/`..`, separator, or control character.
fn is_safe_entry_name(name: &str) -> bool {
    !(name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(|c| c.is_control()))
}

/// The per-component name length limit of this platform's filesystems (NAME_MAX: 255 bytes, 255 UTF-16 units on Windows).
const OS_NAME_MAX: usize = 255;

/// Whether a Windows filesystem refuses `name` (reserved device names, reserved characters, trailing dot/space).
fn windows_rejects(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_uppercase();
    let device = matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ((upper.starts_with("COM") || upper.starts_with("LPT"))
        && upper.chars().count() == 4
        && upper
            .chars()
            .nth(3)
            .is_some_and(|c| c.is_ascii_digit() || matches!(c, '¹' | '²' | '³')));
    device
        || name.ends_with('.')
        || name.ends_with(' ')
        || name
            .chars()
            .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        || name.encode_utf16().count() > OS_NAME_MAX
}

/// Whether this device can create a tree entry named `name`: one normal path component the OS accepts, not a restore temp.
#[must_use]
pub fn is_materializable(name: &str) -> bool {
    use std::path::Component;
    let mut comps = Path::new(name).components();
    let single = matches!(
        (comps.next(), comps.next()),
        (Some(Component::Normal(c)), None) if c == std::ffi::OsStr::new(name)
    );
    single
        && is_safe_entry_name(name)
        && !name.starts_with(TMP_PREFIX)
        && if cfg!(windows) {
            !windows_rejects(name)
        } else {
            name.len() <= OS_NAME_MAX
        }
}

fn decode_tree(bytes: &[u8]) -> Result<Tree, SnapError> {
    let mut r = Reader::new(bytes);
    let count = r.u32()? as usize;
    if count > MAX_TREE_FANOUT {
        return Err(SnapError::Malformed("tree fan-out exceeds maximum"));
    }
    let mut entries = Vec::with_capacity(count.min(r.remaining()));
    for _ in 0..count {
        let kind = r.u8()?;
        let name = String::from_utf8(r.bytes(MAX_NAME_LEN)?.to_vec())
            .map_err(|_| SnapError::NonUtf8Name)?;
        if !is_safe_entry_name(&name) {
            return Err(SnapError::Malformed("unsafe tree entry name"));
        }
        // §9.3: names strictly ascending, which also bans duplicates.
        if let Some(last) = entries.last() {
            if name.as_str() <= entry_name(last) {
                return Err(SnapError::Malformed(
                    "tree entries must be strictly ascending and unique by name",
                ));
            }
        }
        let mode = r.u32()?;
        let mtime = r.u64()?;
        match kind {
            ENTRY_FILE => {
                let size = r.u64()?;
                let path_salt = arr16(r.raw(16)?);
                let chunk_count = r.u32()? as usize;
                if chunk_count > MAX_CHUNKS_PER_FILE {
                    return Err(SnapError::Malformed("chunk list exceeds maximum"));
                }
                // A lying count cannot pre-allocate past what the remaining input holds.
                let mut chunks = Vec::with_capacity(chunk_count.min(r.remaining() / 32));
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
    let mut parents = Vec::with_capacity(parent_count.min(r.remaining() / 32));
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

/// The stored signed-commit object: commit fields ‖ SSHSIG (§9.6).
fn encode_signed_commit(c: &Commit, sig: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    write_commit_fields(&mut w, c);
    w.bytes(sig);
    w.finish()
}

fn decode_signed_commit(bytes: &[u8]) -> Result<(Commit, Vec<u8>), SnapError> {
    let mut r = Reader::new(bytes);
    let c = read_commit_fields(&mut r)?;
    let sig = r.bytes(MAX_SIG_LEN)?.to_vec();
    r.finish()?;
    Ok((c, sig))
}

/// Fuzz hook: drive the tree decoder on arbitrary bytes.
#[doc(hidden)]
pub fn __fuzz_decode_tree(bytes: &[u8]) {
    let _ = decode_tree(bytes);
}

/// Fuzz hook: drive the signed-commit decoder on arbitrary bytes.
#[doc(hidden)]
pub fn __fuzz_decode_signed_commit(bytes: &[u8]) {
    let _ = decode_signed_commit(bytes);
}

/// Test hook: seal a commit carrying an arbitrary `sig` (forged-history tests); production seals via [`seal_signed_commit`].
#[doc(hidden)]
pub fn __seal_commit_with_sig(
    mk: &MasterKey,
    store: &Store,
    commit: &Commit,
    sig: &[u8],
) -> Result<Id, SnapError> {
    let (id, blob) = seal_object(
        mk,
        ObjType::Commit,
        &ZERO_SALT,
        &encode_signed_commit(commit, sig),
    );
    store.put(&id, &blob)?;
    Ok(id)
}

// ---- commit signing (§9.6 secsec-commit-v1) ----

impl Commit {
    /// The canonical signed message: every commit field (§9.3/§9.6).
    #[must_use]
    pub(crate) fn signed_message(&self) -> Vec<u8> {
        encode_commit(self)
    }
}

/// Sign a commit under `NS_COMMIT`; [`verify_commit`] requires the signer to be `commit.device_id`.
pub(crate) fn sign_commit(
    device: &secsec_sig::DeviceKey,
    commit: &Commit,
) -> Result<Vec<u8>, SnapError> {
    Ok(device.sign(secsec_sig::NS_COMMIT, &commit.signed_message())?)
}

/// Verify a commit's SSHSIG under `NS_COMMIT` and that `pubkey` is its named author (P3).
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

/// The 9 standard permission bits only; setuid/setgid/sticky are dropped both ways (§18).
#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o0777
}
#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    0
}

/// Modification time in nanoseconds since the epoch: with size, the unchanged-file signal.
fn mtime_of(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// The §19 bounds a snapshot or merge must never author past; tests shrink them.
#[derive(Clone, Copy)]
struct Limits {
    max_chunks_per_file: usize,
    max_fanout: usize,
    max_blob: usize,
}

impl Limits {
    const SPEC: Self = Self {
        max_chunks_per_file: MAX_CHUNKS_PER_FILE,
        max_fanout: MAX_TREE_FANOUT,
        max_blob: MAX_BLOB_SIZE,
    };
}

/// A tree a snapshot builds on: salts are reused per path; `fast_path` trusts matching size+mtime as unchanged.
#[derive(Clone, Copy)]
pub struct Prior<'a> {
    /// Root tree id.
    pub root: &'a Id,
    /// Root tree salt.
    pub salt: &'a PathSalt,
    /// True only for this device's own last snapshot; false when seeding salts from another device's tree.
    pub fast_path: bool,
}

/// State kept across snapshots: files already found past the chunk bound, by path at `(size, mtime)`.
#[derive(Debug, Default)]
pub struct SnapshotMemo {
    oversize: BTreeMap<PathBuf, (u64, u64)>,
}

/// A snapshot's root and the paths it could not sync this pass.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Root tree id.
    pub root: Id,
    /// Root tree salt.
    pub salt: PathSalt,
    /// Unsyncable paths (too many chunks, unreadable); an already-synced one keeps its previous entry.
    pub skipped: Vec<String>,
}

/// Snapshot `root` into `store` (§6): per-path salts reused from `prior`, unsyncable paths frozen and reported.
pub fn snapshot_tree<K: MasterKeys>(
    root: &Path,
    keys: &K,
    store: &Store,
    prior: Option<Prior<'_>>,
    memo: &mut SnapshotMemo,
) -> Result<Snapshot, SnapError> {
    snapshot_tree_with(root, keys, store, prior, memo, Limits::SPEC)
}

fn snapshot_tree_with<K: MasterKeys>(
    root: &Path,
    keys: &K,
    store: &Store,
    prior: Option<Prior<'_>>,
    memo: &mut SnapshotMemo,
    limits: Limits,
) -> Result<Snapshot, SnapError> {
    // New objects seal under the current generation; the prior tree reads through the whole ring (§8.2).
    let chunker = secsec_chunk::Chunker::with_defaults(&keys.current().cdc_seed());
    let prev_tree = match prior {
        Some(p) => Some(load_tree(p.root, p.salt, keys, store)?),
        None => None,
    };
    let root_salt = match prior {
        Some(p) => *p.salt,
        None => random_bytes()?,
    };
    // Racy-clean guard: the fast path trusts a file only if its mtime predates this snapshot.
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    let mut ctx = SnapCtx {
        keys,
        store,
        chunker: &chunker,
        now_nanos,
        fast_path: prior.is_some_and(|p| p.fast_path),
        limits,
        skipped: Vec::new(),
        memo,
    };
    let (id, salt) = snapshot_dir(&mut ctx, root, 0, prev_tree.as_ref(), root_salt)?;
    Ok(Snapshot {
        root: id,
        salt,
        skipped: ctx.skipped,
    })
}

/// Walk-constant snapshot context.
struct SnapCtx<'a, K: MasterKeys> {
    keys: &'a K,
    store: &'a Store,
    chunker: &'a secsec_chunk::Chunker,
    now_nanos: u64,
    fast_path: bool,
    limits: Limits,
    skipped: Vec<String>,
    memo: &'a mut SnapshotMemo,
}

/// The name field of a tree entry.
fn entry_name(e: &Entry) -> &str {
    match e {
        Entry::File { name, .. } | Entry::Dir { name, .. } => name,
    }
}

/// The entry named `name` in a (strictly name-sorted) tree.
fn find_entry<'a>(tree: Option<&'a Tree>, name: &str) -> Option<&'a Entry> {
    let t = tree?;
    t.entries
        .binary_search_by(|e| entry_name(e).cmp(name))
        .ok()
        .map(|i| &t.entries[i])
}

/// Sign `commit`, seal and store the signed object, and return its id; the signer must be `commit.device_id`.
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

/// Fetch, open (id re-verified), and decode a signed commit; callers still [`verify_commit`].
pub fn open_signed_commit<K: MasterKeys>(
    commit_id: &Id,
    keys: &K,
    store: &Store,
) -> Result<(Commit, Vec<u8>), SnapError> {
    decode_signed_commit(&fetch_open(
        keys,
        ObjType::Commit,
        &ZERO_SALT,
        commit_id,
        store,
    )?)
}

/// Verify an in-memory commit blob against `commit_id` and decode it (fetch path: verify before storing).
pub fn verified_commit<K: MasterKeys>(
    keys: &K,
    commit_id: &Id,
    blob: &[u8],
) -> Result<(Commit, Vec<u8>), SnapError> {
    decode_signed_commit(&open_object(
        keys,
        ObjType::Commit,
        &ZERO_SALT,
        commit_id,
        blob,
    )?)
}

/// Verify an in-memory tree blob against `(tree_id, salt)` and decode it (fetch path: verify before storing).
pub fn verified_tree<K: MasterKeys>(
    keys: &K,
    tree_id: &Id,
    salt: &PathSalt,
    blob: &[u8],
) -> Result<Tree, SnapError> {
    decode_tree(&open_object(keys, ObjType::Tree, salt, tree_id, blob)?)
}

/// Verify an in-memory chunk blob against `(chunk_id, salt)` (fetch path: verify before storing).
pub fn verify_chunk<K: MasterKeys>(
    keys: &K,
    chunk_id: &Id,
    salt: &PathSalt,
    blob: &[u8],
) -> Result<(), SnapError> {
    open_object(keys, ObjType::Chunk, salt, chunk_id, blob)?;
    Ok(())
}

/// How one file entry resolved during a snapshot walk.
enum FileScan {
    Entry(Entry),
    Skip(String),
    Gone,
}

fn snapshot_file<K: MasterKeys>(
    ctx: &mut SnapCtx<'_, K>,
    path: &Path,
    name: String,
    meta: &std::fs::Metadata,
    prev_entry: Option<&Entry>,
) -> Result<FileScan, SnapError> {
    let this_mtime = mtime_of(meta);
    if let Some(Entry::File {
        mtime: prev_mtime,
        size: prev_size,
        path_salt,
        chunks,
        ..
    }) = prev_entry
    {
        // Fast path: same size and nanosecond mtime as our last snapshot, and older than this pass.
        if ctx.fast_path
            && *prev_size == meta.len()
            && *prev_mtime == this_mtime
            && this_mtime < ctx.now_nanos
        {
            return Ok(FileScan::Entry(Entry::File {
                name,
                mode: mode_of(meta),
                mtime: this_mtime,
                size: *prev_size,
                path_salt: *path_salt,
                chunks: chunks.clone(),
            }));
        }
    }
    let too_many = format!(
        "{} (needs more than {} chunks)",
        path.display(),
        ctx.limits.max_chunks_per_file
    );
    if ctx.memo.oversize.get(path) == Some(&(meta.len(), this_mtime)) {
        return Ok(FileScan::Skip(too_many));
    }
    let path_salt = match prev_entry {
        Some(Entry::File { path_salt, .. }) => *path_salt,
        _ => random_bytes()?,
    };
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        // Deleted between the listing and the open: a plain deletion, not an unreadable file.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FileScan::Gone),
        Err(e) => {
            return Ok(FileScan::Skip(format!(
                "{} (unreadable: {e})",
                path.display()
            )))
        }
    };
    let mut chunks = Vec::new();
    let mut over_chunk_limit = false;
    let (keys, store, chunker, limit) = (
        ctx.keys,
        ctx.store,
        ctx.chunker,
        ctx.limits.max_chunks_per_file,
    );
    let streamed = chunker.chunk_stream(file, |chunk| -> Result<(), SnapError> {
        if chunks.len() >= limit {
            over_chunk_limit = true;
            return Err(SnapError::Malformed("chunk list exceeds maximum"));
        }
        let padded = secsec_object::pad_chunk(chunk, Padding::PowerOfTwo);
        let (id, blob) = seal_object(keys.current(), ObjType::Chunk, &path_salt, &padded);
        store.put(&id, &blob)?;
        chunks.push(id);
        Ok(())
    });
    match streamed {
        Ok(size) => Ok(FileScan::Entry(Entry::File {
            name,
            mode: mode_of(meta),
            mtime: this_mtime,
            size,
            path_salt,
            chunks,
        })),
        Err(_) if over_chunk_limit => {
            ctx.memo
                .oversize
                .insert(path.to_path_buf(), (meta.len(), this_mtime));
            Ok(FileScan::Skip(too_many))
        }
        Err(secsec_chunk::StreamError::Read(io)) => Ok(FileScan::Skip(format!(
            "{} (unreadable: {io})",
            path.display()
        ))),
        Err(secsec_chunk::StreamError::Emit(se)) => Err(se),
    }
}

fn snapshot_dir<K: MasterKeys>(
    ctx: &mut SnapCtx<'_, K>,
    dir: &Path,
    depth: usize,
    prev: Option<&Tree>,
    this_salt: PathSalt,
) -> Result<(Id, PathSalt), SnapError> {
    if depth >= MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    let mut names: Vec<std::ffi::OsString> = Vec::new();
    for ent in std::fs::read_dir(dir)? {
        names.push(ent?.file_name());
    }
    names.sort();

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut entries: Vec<Entry> = Vec::with_capacity(names.len());
    for name_os in names {
        // A name no tree may carry (non-UTF-8, unsafe, or a restore temp) is skipped like a symlink (§6).
        let Some(name) = name_os
            .to_str()
            .filter(|n| is_safe_entry_name(n) && !n.starts_with(TMP_PREFIX))
            .map(str::to_owned)
        else {
            continue;
        };
        let path = dir.join(&name_os);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let ft = meta.file_type();
        let prev_entry = find_entry(prev, &name);
        let scanned = if ft.is_file() {
            seen.insert(name.clone());
            snapshot_file(ctx, &path, name, &meta, prev_entry)?
        } else if ft.is_dir() {
            seen.insert(name.clone());
            let (prev_sub, sub_salt) = match prev_entry {
                Some(Entry::Dir {
                    subtree,
                    subtree_salt,
                    ..
                }) => (
                    Some(load_tree(subtree, subtree_salt, ctx.keys, ctx.store)?),
                    *subtree_salt,
                ),
                _ => (None, random_bytes()?),
            };
            match snapshot_dir(ctx, &path, depth + 1, prev_sub.as_ref(), sub_salt) {
                Ok((subtree, subtree_salt)) => FileScan::Entry(Entry::Dir {
                    name,
                    mode: mode_of(&meta),
                    mtime: mtime_of(&meta),
                    subtree,
                    subtree_salt,
                }),
                // A directory whose own listing fails (read_dir, an entry, or an entry's metadata) is frozen, not failed.
                Err(SnapError::Io(e)) => {
                    FileScan::Skip(format!("{} (unreadable: {e})", path.display()))
                }
                Err(e) => return Err(e),
            }
        } else {
            // Symlinks, FIFOs, sockets, devices: never synced, never an error (§6).
            continue;
        };
        match scanned {
            FileScan::Entry(e) => entries.push(e),
            FileScan::Gone => {}
            FileScan::Skip(msg) => {
                ctx.skipped.push(msg);
                // An omitted name is a deletion everywhere else, so an already-synced path freezes instead.
                if let Some(kept) = prev_entry {
                    entries.push(kept.clone());
                }
            }
        }
    }
    // Entries this device cannot create on disk ride forward unchanged instead of reading as deletions.
    if let Some(p) = prev {
        for e in &p.entries {
            let n = entry_name(e);
            if !seen.contains(n) && !is_materializable(n) {
                entries.push(e.clone());
            }
        }
    }
    entries.sort_by(|a, b| entry_name(a).cmp(entry_name(b)));
    if entries.len() > ctx.limits.max_fanout {
        return Err(SnapError::TreeTooLarge(dir.display().to_string()));
    }
    let tree = Tree { entries };
    let (id, blob) = seal_object(
        ctx.keys.current(),
        ObjType::Tree,
        &this_salt,
        &encode_tree(&tree),
    );
    if blob.len() > ctx.limits.max_blob {
        return Err(SnapError::TreeTooLarge(dir.display().to_string()));
    }
    ctx.store.put(&id, &blob)?;
    Ok((id, this_salt))
}

// ---- restore ----

fn fetch_open<K: MasterKeys>(
    keys: &K,
    obj_type: ObjType,
    salt: &PathSalt,
    id: &Id,
    store: &Store,
) -> Result<Vec<u8>, SnapError> {
    let blob = store.get(id)?.ok_or(SnapError::Missing(*id))?;
    Ok(open_object(keys, obj_type, salt, id, &blob)?)
}

/// What a restore did beyond the plain reconcile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Incoming versions written beside a local edit made after the snapshot (keep-both).
    pub conflicts: Vec<String>,
    /// Entries this device cannot create (OS name rules); they ride forward in the next snapshot.
    pub skipped: Vec<String>,
}

/// What restore reconciles the disk against.
#[derive(Clone, Copy)]
enum Against<'a> {
    /// This device's snapshot of the folder (`None` = nothing tracked here): only unchanged tracked entries are replaced or deleted.
    Snapshot(Option<&'a Tree>),
    /// Explicit `secsec restore`: the target overwrites whatever is there.
    Overwrite,
}

/// Restore `target` into `dest` against `ours` (this device's snapshot of `dest`); `label` names keep-both copies.
pub fn restore_tree_into<K: MasterKeys>(
    target: (&Id, &PathSalt),
    ours: Option<(&Id, &PathSalt)>,
    keys: &K,
    store: &Store,
    dest: &Path,
    label: &str,
) -> Result<RestoreReport, SnapError> {
    std::fs::create_dir_all(dest)?;
    let ours_tree = match ours {
        Some((id, salt)) => Some(load_tree(id, salt, keys, store)?),
        None => None,
    };
    let mut rctx = RestoreCtx {
        keys,
        store,
        label,
        report: RestoreReport::default(),
    };
    restore_dir(
        &mut rctx,
        target.0,
        target.1,
        Against::Snapshot(ours_tree.as_ref()),
        dest,
        "",
        0,
    )?;
    Ok(rctx.report)
}

/// Restore `commit`'s tree into `dest` against `ours`, labelling keep-both copies by the commit's author and id.
pub fn restore_commit_tree<K: MasterKeys>(
    commit: &Commit,
    commit_id: &Id,
    ours: Option<(&Id, &PathSalt)>,
    keys: &K,
    store: &Store,
    dest: &Path,
) -> Result<RestoreReport, SnapError> {
    let label = format!("{}-{}", hex12(&commit.device_id), hex12(commit_id));
    restore_tree_into(
        (&commit.root_tree, &commit.root_salt),
        ours,
        keys,
        store,
        dest,
        &label,
    )
}

/// First 6 bytes as 12 lowercase hex characters (the §10 keep-both label component).
#[must_use]
pub fn hex12(b: &[u8; 32]) -> String {
    b[..6].iter().map(|x| format!("{x:02x}")).collect()
}

struct RestoreCtx<'a, K: MasterKeys> {
    keys: &'a K,
    store: &'a Store,
    label: &'a str,
    report: RestoreReport,
}

fn join_rel(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

/// Whether the on-disk file still matches our snapshot entry (same size and nanosecond mtime).
fn unchanged_since(meta: &std::fs::Metadata, snap: Option<&Entry>) -> bool {
    matches!(snap, Some(Entry::File { size, mtime, .. })
        if meta.is_file() && meta.len() == *size && mtime_of(meta) == *mtime)
}

/// Grant the owner write on `dir` for the duration of a restore; returns the permissions to put back.
#[cfg(unix)]
fn ensure_writable(dir: &Path) -> Result<Option<std::fs::Permissions>, SnapError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::symlink_metadata(dir)?.permissions();
    if perms.mode() & 0o200 != 0 {
        return Ok(None);
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(perms.mode() | 0o700))?;
    Ok(Some(perms))
}
#[cfg(not(unix))]
fn ensure_writable(_dir: &Path) -> Result<Option<std::fs::Permissions>, SnapError> {
    Ok(None)
}

/// Remove leftover restore temps (a crash mid-write); they are ours by name.
fn remove_stale_temps(dir: &Path) -> Result<(), SnapError> {
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        if ent
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(TMP_PREFIX))
            && ent.file_type()?.is_file()
        {
            std::fs::remove_file(ent.path())?;
        }
    }
    Ok(())
}

/// macOS's custom-folder-icon file: never synced, and never deleted while its folder lives.
const MACOS_FOLDER_ICON: &str = "Icon\r";

/// Remove `dir`'s macOS folder icon when it is the only entry left, so a folder deleted upstream can go.
fn remove_lone_folder_icon(dir: &Path) -> Result<(), SnapError> {
    let mut entries = std::fs::read_dir(dir)?;
    let (Some(only), None) = (entries.next().transpose()?, entries.next()) else {
        return Ok(());
    };
    if only.file_name().as_os_str() == MACOS_FOLDER_ICON && only.file_type()?.is_file() {
        std::fs::remove_file(only.path())?;
    }
    Ok(())
}

/// A name for the incoming version beside a local edit, colliding with nothing on disk or in `taken`.
fn local_conflict_name(dir: &Path, name: &str, label: &str, taken: &BTreeSet<&str>) -> String {
    let base = |l: &str| match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}.conflict-{l}.{ext}"),
        _ => format!("{name}.conflict-{l}"),
    };
    let mut candidate = base(label);
    let mut n = 2u32;
    while taken.contains(candidate.as_str())
        || std::fs::symlink_metadata(dir.join(&candidate)).is_ok()
        || !is_materializable(&candidate)
    {
        candidate = base(&format!("{label}-{n}"));
        n += 1;
    }
    candidate
}

/// Delete what our snapshot tracked under `dir` and is still unchanged, then a lone macOS folder icon; keep everything else. Returns whether `dir` is now gone.
fn remove_tracked<K: MasterKeys>(
    rctx: &RestoreCtx<'_, K>,
    dir: &Path,
    snap: &Tree,
    depth: usize,
) -> Result<bool, SnapError> {
    if depth >= MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    let restore_perms = ensure_writable(dir)?;
    for e in &snap.entries {
        let path = dir.join(entry_name(e));
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        match e {
            Entry::File { .. } if unchanged_since(&meta, Some(e)) => std::fs::remove_file(&path)?,
            Entry::Dir {
                subtree,
                subtree_salt,
                ..
            } if meta.is_dir() => {
                let sub = load_tree(subtree, subtree_salt, rctx.keys, rctx.store)?;
                remove_tracked(rctx, &path, &sub, depth + 1)?;
            }
            _ => {}
        }
    }
    remove_stale_temps(dir)?;
    remove_lone_folder_icon(dir)?;
    match std::fs::remove_dir(dir) {
        Ok(()) => Ok(true),
        Err(_) => {
            if let Some(p) = restore_perms {
                std::fs::set_permissions(dir, p)?;
            }
            Ok(false)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn restore_dir<K: MasterKeys>(
    rctx: &mut RestoreCtx<'_, K>,
    tree_id: &Id,
    tree_salt: &PathSalt,
    against: Against<'_>,
    dir: &Path,
    rel: &str,
    depth: usize,
) -> Result<(), SnapError> {
    if depth >= MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    let tree = load_tree(tree_id, tree_salt, rctx.keys, rctx.store)?;
    std::fs::create_dir_all(dir)?;
    let restore_perms = ensure_writable(dir)?;
    remove_stale_temps(dir)?;
    let ours = match against {
        Against::Snapshot(t) => t,
        Against::Overwrite => None,
    };

    // Deletions: what our snapshot tracked and is unchanged since; Overwrite deletes every file and directory the tree lacks.
    let keep: BTreeSet<&str> = tree.entries.iter().map(entry_name).collect();
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let Some(name) = ent.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if keep.contains(name.as_str())
            || !is_safe_entry_name(&name)
            || name.starts_with(TMP_PREFIX)
        {
            continue;
        }
        let path = ent.path();
        let meta = std::fs::symlink_metadata(&path)?;
        match (against, find_entry(ours, &name)) {
            (Against::Overwrite, _) if meta.is_file() => std::fs::remove_file(&path)?,
            (Against::Overwrite, _) if meta.is_dir() => std::fs::remove_dir_all(&path)?,
            (Against::Snapshot(_), snap @ Some(Entry::File { .. })) => {
                if unchanged_since(&meta, snap) {
                    std::fs::remove_file(&path)?;
                }
            }
            (
                Against::Snapshot(_),
                Some(Entry::Dir {
                    subtree,
                    subtree_salt,
                    ..
                }),
            ) if meta.is_dir() => {
                let sub = load_tree(subtree, subtree_salt, rctx.keys, rctx.store)?;
                remove_tracked(rctx, &path, &sub, depth + 1)?;
            }
            _ => {}
        }
    }

    for entry in &tree.entries {
        let name = entry_name(entry);
        let rel_path = join_rel(rel, name);
        if !is_materializable(name) {
            rctx.report.skipped.push(rel_path);
            continue;
        }
        let path = dir.join(name);
        let disk = std::fs::symlink_metadata(&path).ok();
        let snap = find_entry(ours, name);
        let overwrite = matches!(against, Against::Overwrite);
        match entry {
            Entry::File {
                mode,
                mtime,
                size,
                path_salt,
                chunks,
                ..
            } => {
                let file = FileTarget {
                    mode: *mode,
                    mtime: *mtime,
                    size: *size,
                    path_salt,
                    chunks,
                };
                let dest = match &disk {
                    None => match snap {
                        // Deleted locally after the snapshot and unchanged upstream: the deletion propagates.
                        Some(Entry::File { chunks: c, .. }) if !overwrite && c == chunks => None,
                        _ => Some(path.clone()),
                    },
                    Some(m) if m.is_file() => match snap {
                        // Content unchanged upstream: the disk copy stays, and only an unedited one takes the incoming metadata.
                        Some(Entry::File { chunks: c, .. }) if !overwrite && c == chunks => {
                            if unchanged_since(m, snap) {
                                apply_metadata(&path, *mode, *mtime)?;
                            }
                            None
                        }
                        _ if overwrite || unchanged_since(m, snap) => Some(path.clone()),
                        _ => Some(conflict_dest(rctx, dir, name, &rel_path, &keep)),
                    },
                    Some(m) if m.is_dir() => {
                        let cleared = match (overwrite, snap) {
                            (true, _) => {
                                std::fs::remove_dir_all(&path)?;
                                true
                            }
                            (
                                false,
                                Some(Entry::Dir {
                                    subtree,
                                    subtree_salt,
                                    ..
                                }),
                            ) => {
                                let sub = load_tree(subtree, subtree_salt, rctx.keys, rctx.store)?;
                                remove_tracked(rctx, &path, &sub, depth + 1)?
                            }
                            _ => false,
                        };
                        if cleared {
                            Some(path.clone())
                        } else {
                            Some(conflict_dest(rctx, dir, name, &rel_path, &keep))
                        }
                    }
                    // An untracked symlink/special file is unlinked, never followed (§10).
                    Some(_) => {
                        std::fs::remove_file(&path)?;
                        Some(path.clone())
                    }
                };
                if let Some(dest) = dest {
                    write_file_atomic(rctx, dir, &dest, &file)?;
                }
            }
            Entry::Dir {
                mode,
                mtime,
                subtree,
                subtree_salt,
                ..
            } => {
                let snap_sub = match snap {
                    Some(Entry::Dir {
                        subtree: s,
                        subtree_salt: ss,
                        ..
                    }) => Some((s, ss)),
                    _ => None,
                };
                let target_dir = match &disk {
                    None => match snap_sub {
                        Some((s, _)) if !overwrite && s == subtree => None,
                        _ => Some(path.clone()),
                    },
                    Some(m) if m.is_dir() => Some(path.clone()),
                    Some(m) if m.is_file() => {
                        if overwrite || unchanged_since(m, snap) {
                            std::fs::remove_file(&path)?;
                            Some(path.clone())
                        } else {
                            Some(conflict_dest(rctx, dir, name, &rel_path, &keep))
                        }
                    }
                    Some(_) => {
                        std::fs::remove_file(&path)?;
                        Some(path.clone())
                    }
                };
                let Some(target_dir) = target_dir else {
                    continue;
                };
                // Recurse against our snapshot of this same path only when writing to it.
                let sub_snap = match (snap_sub, target_dir == path) {
                    (Some((s, ss)), true) => Some(load_tree(s, ss, rctx.keys, rctx.store)?),
                    _ => None,
                };
                let sub_against = match against {
                    Against::Overwrite => Against::Overwrite,
                    Against::Snapshot(_) => Against::Snapshot(sub_snap.as_ref()),
                };
                restore_dir(
                    rctx,
                    subtree,
                    subtree_salt,
                    sub_against,
                    &target_dir,
                    &rel_path,
                    depth + 1,
                )?;
                // Metadata after populating (writing children bumps the dir mtime).
                apply_metadata(&target_dir, *mode, *mtime)?;
            }
        }
    }
    if let Some(p) = restore_perms {
        std::fs::set_permissions(dir, p)?;
    }
    Ok(())
}

/// Record a keep-both copy and return its path.
fn conflict_dest<K: MasterKeys>(
    rctx: &mut RestoreCtx<'_, K>,
    dir: &Path,
    name: &str,
    rel_path: &str,
    keep: &BTreeSet<&str>,
) -> PathBuf {
    let cname = local_conflict_name(dir, name, rctx.label, keep);
    rctx.report.conflicts.push(rel_path.to_string());
    dir.join(cname)
}

/// A file's content and metadata to materialize.
struct FileTarget<'a> {
    mode: u32,
    mtime: u64,
    size: u64,
    path_salt: &'a PathSalt,
    chunks: &'a [Id],
}

/// Write `file` to `dest` atomically: stream into a same-directory temp, fsync, set metadata, rename over.
fn write_file_atomic<K: MasterKeys>(
    rctx: &RestoreCtx<'_, K>,
    dir: &Path,
    dest: &Path,
    file: &FileTarget<'_>,
) -> Result<(), SnapError> {
    let tmp = dir.join(format!("{TMP_PREFIX}{}", hex_of(&random_bytes::<8>()?)));
    let result = (|| -> Result<(), SnapError> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        let mut written: u64 = 0;
        for cid in file.chunks {
            let padded = fetch_open(rctx.keys, ObjType::Chunk, file.path_salt, cid, rctx.store)?;
            let plain = unpad_chunk(&padded, Padding::PowerOfTwo)?;
            // A member-authored entry never makes restore write past its declared size or a chunk past the chunker max.
            if plain.len() > secsec_chunk::MAX_CHUNK_LEN
                || written.saturating_add(plain.len() as u64) > file.size
            {
                return Err(SnapError::Malformed(
                    "restored file exceeds its declared size",
                ));
            }
            f.write_all(plain)?;
            written += plain.len() as u64;
        }
        if written != file.size {
            return Err(SnapError::Malformed("restored file size mismatch"));
        }
        f.sync_all()?;
        drop(f);
        apply_metadata(&tmp, file.mode, file.mtime)?;
        replace_file(&tmp, dest)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Rename `tmp` over `dest`; Windows refuses to replace a read-only file, so that attribute is cleared first.
fn replace_file(tmp: &Path, dest: &Path) -> Result<(), SnapError> {
    #[cfg(windows)]
    if let Ok(meta) = std::fs::symlink_metadata(dest) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            std::fs::set_permissions(dest, perms)?;
        }
    }
    std::fs::rename(tmp, dest)?;
    Ok(())
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Apply the recorded mode (9 bits, §18; 0 means the author had none) and mtime.
fn apply_metadata(path: &Path, mode: u32, mtime: u64) -> Result<(), SnapError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if mode != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o0777))?;
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    // Member-authored nanoseconds: split and saturate so a hostile value cannot wrap.
    let secs = i64::try_from(mtime / 1_000_000_000).unwrap_or(i64::MAX);
    let subsec_nanos = (mtime % 1_000_000_000) as u32;
    filetime::set_file_mtime(path, filetime::FileTime::from_unix_time(secs, subsec_nanos))?;
    Ok(())
}

// ---- tree primitives for the merge engine (§10) ----

/// Fetch, verify (§9.2), and decode one `Tree`.
pub fn load_tree<K: MasterKeys>(
    tree_id: &Id,
    tree_salt: &PathSalt,
    keys: &K,
    store: &Store,
) -> Result<Tree, SnapError> {
    decode_tree(&fetch_open(keys, ObjType::Tree, tree_salt, tree_id, store)?)
}

/// Seal one `Tree` under `salt` within the §19 fan-out and object bounds; `dir` names it in the error.
pub fn seal_tree(
    tree: &Tree,
    salt: &PathSalt,
    mk: &MasterKey,
    store: &Store,
    dir: &str,
) -> Result<Id, SnapError> {
    seal_tree_with(tree, salt, mk, store, dir, Limits::SPEC)
}

fn seal_tree_with(
    tree: &Tree,
    salt: &PathSalt,
    mk: &MasterKey,
    store: &Store,
    dir: &str,
    limits: Limits,
) -> Result<Id, SnapError> {
    if tree.entries.len() > limits.max_fanout {
        return Err(SnapError::TreeTooLarge(dir.to_string()));
    }
    let (id, blob) = seal_object(mk, ObjType::Tree, salt, &encode_tree(tree));
    if blob.len() > limits.max_blob {
        return Err(SnapError::TreeTooLarge(dir.to_string()));
    }
    store.put(&id, &blob)?;
    Ok(id)
}

// ---- closures (push set / retention / cache sweep, §15) ----

/// Every object reachable from `head`: commits and their present content; the head's own tree is strict.
pub fn reachable_objects<K: MasterKeys>(
    keys: &K,
    store: &Store,
    head: &Id,
) -> Result<BTreeSet<Id>, SnapError> {
    let mut reachable: BTreeSet<Id> = BTreeSet::new();
    let mut commits_done: BTreeSet<Id> = BTreeSet::new();
    let mut work: Vec<Id> = vec![*head];
    while let Some(cid) = work.pop() {
        if !commits_done.insert(cid) {
            continue;
        }
        let is_head = cid == *head;
        let blob = match store.get(&cid)? {
            Some(b) => b,
            None if is_head => return Err(SnapError::Missing(cid)),
            None => continue,
        };
        reachable.insert(cid);
        let (commit, _sig) = verified_commit(keys, &cid, &blob)?;
        collect_tree(
            keys,
            store,
            &commit.root_tree,
            &commit.root_salt,
            0,
            &mut reachable,
            is_head,
        )?;
        work.extend(commit.parents);
    }
    Ok(reachable)
}

/// Every tree and chunk id under `(root, salt)`, strict, not descending into subtrees already in `known`.
pub fn tree_closure<K: MasterKeys>(
    keys: &K,
    store: &Store,
    root: &Id,
    salt: &PathSalt,
    known: &BTreeSet<Id>,
    out: &mut BTreeSet<Id>,
) -> Result<(), SnapError> {
    let mut work: Vec<(Id, PathSalt, usize)> = vec![(*root, *salt, 0)];
    while let Some((id, s, depth)) = work.pop() {
        if depth >= MAX_TREE_DEPTH {
            return Err(SnapError::DepthExceeded);
        }
        if known.contains(&id) || !out.insert(id) {
            continue;
        }
        for e in load_tree(&id, &s, keys, store)?.entries {
            match e {
                Entry::File { chunks, .. } => out.extend(chunks),
                Entry::Dir {
                    subtree,
                    subtree_salt,
                    ..
                } => work.push((subtree, subtree_salt, depth + 1)),
            }
        }
    }
    Ok(())
}

/// Walk one tree into `reachable`; chunk ids come from the verified tree. Missing is an error only when `strict`.
fn collect_tree<K: MasterKeys>(
    keys: &K,
    store: &Store,
    tree_id: &Id,
    tree_salt: &PathSalt,
    depth: usize,
    reachable: &mut BTreeSet<Id>,
    strict: bool,
) -> Result<(), SnapError> {
    if depth >= MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    if reachable.contains(tree_id) {
        return Ok(());
    }
    let blob = match store.get(tree_id)? {
        Some(b) => b,
        None if strict => return Err(SnapError::Missing(*tree_id)),
        None => return Ok(()),
    };
    reachable.insert(*tree_id);
    let tree = verified_tree(keys, tree_id, tree_salt, &blob)?;
    for entry in &tree.entries {
        match entry {
            Entry::File { chunks, .. } => reachable.extend(chunks.iter().copied()),
            Entry::Dir {
                subtree,
                subtree_salt,
                ..
            } => collect_tree(
                keys,
                store,
                subtree,
                subtree_salt,
                depth + 1,
                reachable,
                strict,
            )?,
        }
    }
    Ok(())
}

// ---- path resolution, single-path restore, and tree diff (`secsec log` / `restore`) ----

/// A file or directory resolved at a path within a commit's tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathNode {
    /// A regular file.
    File {
        /// Unix mode bits.
        mode: u32,
        /// Modification time (advisory).
        mtime: u64,
        /// Plaintext size.
        size: u64,
        /// The file's path salt.
        path_salt: PathSalt,
        /// Ordered chunk ids.
        chunks: Vec<Id>,
    },
    /// A directory.
    Dir {
        /// Subtree content id.
        subtree: Id,
        /// Subtree path salt.
        subtree_salt: PathSalt,
    },
}

/// Split a slash path into components, dropping empty and `.` segments.
fn path_components(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect()
}

/// Resolve `path` under `(root_tree, root_salt)`; `None` if missing or a non-final component is a file.
pub fn resolve_path<K: MasterKeys>(
    keys: &K,
    store: &Store,
    root_tree: &Id,
    root_salt: &PathSalt,
    path: &str,
) -> Result<Option<PathNode>, SnapError> {
    let comps = path_components(path);
    if comps.is_empty() {
        return Ok(Some(PathNode::Dir {
            subtree: *root_tree,
            subtree_salt: *root_salt,
        }));
    }
    let (mut cur_tree, mut cur_salt) = (*root_tree, *root_salt);
    for (i, comp) in comps.iter().enumerate() {
        let tree = load_tree(&cur_tree, &cur_salt, keys, store)?;
        let Some(entry) = find_entry(Some(&tree), comp) else {
            return Ok(None);
        };
        let last = i + 1 == comps.len();
        match entry {
            Entry::File {
                mode,
                mtime,
                size,
                path_salt,
                chunks,
                ..
            } => {
                return Ok(last.then(|| PathNode::File {
                    mode: *mode,
                    mtime: *mtime,
                    size: *size,
                    path_salt: *path_salt,
                    chunks: chunks.clone(),
                }));
            }
            Entry::Dir {
                subtree,
                subtree_salt,
                ..
            } => {
                if last {
                    return Ok(Some(PathNode::Dir {
                        subtree: *subtree,
                        subtree_salt: *subtree_salt,
                    }));
                }
                cur_tree = *subtree;
                cur_salt = *subtree_salt;
            }
        }
    }
    Ok(None)
}

/// Chunk ids needed to materialize `path` (a file's chunks, or all under a directory); skip-missing, `None` if unresolvable.
pub fn path_chunks<K: MasterKeys>(
    keys: &K,
    store: &Store,
    root_tree: &Id,
    root_salt: &PathSalt,
    path: &str,
) -> Result<Option<BTreeSet<Id>>, SnapError> {
    let node = match resolve_path(keys, store, root_tree, root_salt, path) {
        Ok(Some(n)) => n,
        Ok(None) | Err(SnapError::Missing(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut out = BTreeSet::new();
    match node {
        PathNode::File { chunks, .. } => out.extend(chunks),
        PathNode::Dir {
            subtree,
            subtree_salt,
        } => {
            let mut all = BTreeSet::new();
            collect_tree(keys, store, &subtree, &subtree_salt, 0, &mut all, false)?;
            let mut trees = BTreeSet::new();
            let mut work = vec![(subtree, subtree_salt)];
            while let Some((t, s)) = work.pop() {
                if !trees.insert(t) {
                    continue;
                }
                if let Some(blob) = store.get(&t)? {
                    for e in verified_tree(keys, &t, &s, &blob)?.entries {
                        if let Entry::Dir {
                            subtree,
                            subtree_salt,
                            ..
                        } = e
                        {
                            work.push((subtree, subtree_salt));
                        }
                    }
                }
            }
            out.extend(all.difference(&trees).copied());
        }
    }
    Ok(Some(out))
}

/// Resolve `comps` under `root` one by one, creating directories but refusing any symlink or non-directory on the way.
fn safe_join(root: &Path, comps: &[&str]) -> Result<PathBuf, SnapError> {
    let mut cur = root.to_path_buf();
    let Some((last, parents)) = comps.split_last() else {
        return Ok(cur);
    };
    for c in parents {
        cur.push(c);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(SnapError::UnsafePath(cur.display().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(&cur)?,
            Err(e) => return Err(e.into()),
        }
    }
    cur.push(last);
    Ok(cur)
}

/// `secsec restore`: write `path` from `commit` into `dest_root` at the same relative path, overwriting (§10 history).
pub fn restore_path<K: MasterKeys>(
    keys: &K,
    store: &Store,
    commit: &Commit,
    path: &str,
    dest_root: &Path,
) -> Result<(), SnapError> {
    // Confine the write to `dest_root` by construction: validated components only, never `..`, never a symlink.
    let comps = path_components(path);
    if comps.iter().any(|c| *c == ".." || !is_materializable(c)) {
        return Err(SnapError::UnsafePath(path.to_string()));
    }
    let node = match resolve_path(keys, store, &commit.root_tree, &commit.root_salt, path) {
        Ok(Some(n)) => n,
        Ok(None) => return Err(SnapError::PathNotFound(path.to_string())),
        Err(SnapError::Missing(_)) => {
            return Err(SnapError::PrunedBeyondRetention(path.to_string()))
        }
        Err(e) => return Err(e),
    };
    let target = safe_join(dest_root, &comps)?;
    let parent = target.parent().unwrap_or(dest_root).to_path_buf();
    let rctx = RestoreCtx {
        keys,
        store,
        label: "",
        report: RestoreReport::default(),
    };
    let pruned = |e: SnapError| match e {
        SnapError::Missing(_) => SnapError::PrunedBeyondRetention(path.to_string()),
        e => e,
    };
    match node {
        PathNode::File {
            mode,
            mtime,
            size,
            path_salt,
            chunks,
        } => {
            // A symlink or directory in the way is replaced, never followed.
            if let Ok(m) = std::fs::symlink_metadata(&target) {
                if m.is_dir() {
                    std::fs::remove_dir_all(&target)?;
                }
            }
            write_file_atomic(
                &rctx,
                &parent,
                &target,
                &FileTarget {
                    mode,
                    mtime,
                    size,
                    path_salt: &path_salt,
                    chunks: &chunks,
                },
            )
            .map_err(pruned)?;
        }
        PathNode::Dir {
            subtree,
            subtree_salt,
        } => {
            if let Ok(m) = std::fs::symlink_metadata(&target) {
                if !m.is_dir() {
                    std::fs::remove_file(&target)?;
                }
            }
            let mut rctx = rctx;
            restore_dir(
                &mut rctx,
                &subtree,
                &subtree_salt,
                Against::Overwrite,
                &target,
                path,
                0,
            )
            .map_err(pruned)?;
        }
    }
    Ok(())
}

/// File paths whose content differs between two trees (`None` = empty side), sorted; identical subtrees are skipped.
pub fn changed_paths<K: MasterKeys>(
    keys: &K,
    store: &Store,
    old: Option<(&Id, &PathSalt)>,
    new: Option<(&Id, &PathSalt)>,
) -> Result<Vec<String>, SnapError> {
    let mut out = Vec::new();
    diff_trees(keys, store, old, new, "", 0, &mut out)?;
    out.sort();
    Ok(out)
}

fn diff_trees<K: MasterKeys>(
    keys: &K,
    store: &Store,
    old: Option<(&Id, &PathSalt)>,
    new: Option<(&Id, &PathSalt)>,
    prefix: &str,
    depth: usize,
    out: &mut Vec<String>,
) -> Result<(), SnapError> {
    if depth >= MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    // A tree absent from the store is an empty side, so `log` lists the commit without a diff.
    let load = |t: Option<(&Id, &PathSalt)>| -> Result<Vec<Entry>, SnapError> {
        match t {
            Some((id, salt)) => match load_tree(id, salt, keys, store) {
                Ok(tree) => Ok(tree.entries),
                Err(SnapError::Missing(_)) => Ok(Vec::new()),
                Err(e) => Err(e),
            },
            None => Ok(Vec::new()),
        }
    };
    let old_entries = load(old)?;
    let new_entries = load(new)?;
    let by_name = |es: &[Entry]| -> BTreeMap<String, Entry> {
        es.iter()
            .map(|e| (entry_name(e).to_string(), e.clone()))
            .collect()
    };
    let om = by_name(&old_entries);
    let nm = by_name(&new_entries);
    let names: BTreeSet<&String> = om.keys().chain(nm.keys()).collect();
    for name in names {
        let path = join_rel(prefix, name);
        let dir_side = |e: Option<&Entry>| match e {
            Some(Entry::Dir {
                subtree,
                subtree_salt,
                ..
            }) => Some((*subtree, *subtree_salt)),
            _ => None,
        };
        match (om.get(name), nm.get(name)) {
            (Some(Entry::File { chunks: oc, .. }), Some(Entry::File { chunks: nc, .. })) => {
                if oc != nc {
                    out.push(path);
                }
            }
            (o, n) => {
                // A file on either side is itself a change (added, removed, or replaced by a directory).
                if matches!(o, Some(Entry::File { .. })) || matches!(n, Some(Entry::File { .. })) {
                    out.push(path.clone());
                }
                let (od, nd) = (dir_side(o), dir_side(n));
                if (od.is_some() || nd.is_some()) && od.map(|d| d.0) != nd.map(|d| d.0) {
                    diff_trees(
                        keys,
                        store,
                        od.as_ref().map(|(i, s)| (i, s)),
                        nd.as_ref().map(|(i, s)| (i, s)),
                        &path,
                        depth + 1,
                        out,
                    )?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> MasterKey {
        MasterKey::new(1, [0x66; 32])
    }

    fn store_in(dir: &tempfile::TempDir) -> Store {
        Store::open(dir.path().join("s.redb")).unwrap()
    }

    fn snap(
        src: &Path,
        m: &impl MasterKeys,
        store: &Store,
        prior: Option<(&Id, &PathSalt)>,
    ) -> Snapshot {
        snapshot_tree(
            src,
            m,
            store,
            prior.map(|(root, salt)| Prior {
                root,
                salt,
                fast_path: true,
            }),
            &mut SnapshotMemo::default(),
        )
        .unwrap()
    }

    fn restore_into(t: &Snapshot, m: &MasterKey, store: &Store, dst: &Path) -> RestoreReport {
        restore_tree_into((&t.root, &t.salt), None, m, store, dst, "L").unwrap()
    }

    /// Read a directory into `relative-path → contents` (dirs as `path/`).
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
    fn oversized_file_is_reported_frozen_and_memoized() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let tight = Limits {
            max_chunks_per_file: 1,
            ..Limits::SPEC
        };
        let mut memo = SnapshotMemo::default();

        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("small"), b"still small").unwrap();
        std::fs::write(src.path().join("big"), vec![7u8; 8]).unwrap();
        let s1 = snapshot_tree_with(src.path(), &m, &store, None, &mut memo, tight).unwrap();
        assert!(s1.skipped.is_empty());
        let v1 = load_tree(&s1.root, &s1.salt, &m, &store).unwrap();

        std::fs::write(src.path().join("big"), vec![7u8; 600 * 1024]).unwrap();
        let prior = Prior {
            root: &s1.root,
            salt: &s1.salt,
            fast_path: true,
        };
        let s2 = snapshot_tree_with(src.path(), &m, &store, Some(prior), &mut memo, tight).unwrap();
        assert_eq!(s2.skipped.len(), 1);
        assert!(s2.skipped[0].contains("big"));
        let v2 = load_tree(&s2.root, &s2.salt, &m, &store).unwrap();
        assert_eq!(find_entry(Some(&v1), "big"), find_entry(Some(&v2), "big"));

        // The memo spares the next pass a re-chunk: no new chunk objects appear.
        let before = store.object_count().unwrap();
        let s3 = snapshot_tree_with(src.path(), &m, &store, Some(prior), &mut memo, tight).unwrap();
        assert_eq!(s3.skipped.len(), 1);
        assert_eq!(s3.root, s2.root);
        assert_eq!(store.object_count().unwrap(), before);
    }

    #[test]
    fn oversized_file_never_seen_before_is_just_reported() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("keep"), b"ok").unwrap();
        std::fs::write(src.path().join("huge"), vec![3u8; 600 * 1024]).unwrap();
        let s = snapshot_tree_with(
            src.path(),
            &m,
            &store,
            None,
            &mut SnapshotMemo::default(),
            Limits {
                max_chunks_per_file: 1,
                ..Limits::SPEC
            },
        )
        .unwrap();
        assert_eq!(s.skipped.len(), 1);
        let tree = load_tree(&s.root, &s.salt, &m, &store).unwrap();
        let names: Vec<&str> = tree.entries.iter().map(entry_name).collect();
        assert_eq!(names, vec!["keep"]);
    }

    /// Fan-out and object-size overflow fail loudly; a skipped name does not count toward fan-out.
    #[test]
    fn undecodable_directory_fails_loudly_rather_than_being_authored() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let src = tempfile::tempdir().unwrap();
        for i in 0..4 {
            std::fs::write(src.path().join(format!("f{i}")), b"x").unwrap();
        }
        let run = |limits: Limits| {
            snapshot_tree_with(
                src.path(),
                &m,
                &store,
                None,
                &mut SnapshotMemo::default(),
                limits,
            )
        };
        assert!(matches!(
            run(Limits {
                max_fanout: 3,
                ..Limits::SPEC
            }),
            Err(SnapError::TreeTooLarge(_))
        ));
        assert!(matches!(
            run(Limits {
                max_blob: 32,
                ..Limits::SPEC
            }),
            Err(SnapError::TreeTooLarge(_))
        ));
        std::fs::write(src.path().join(format!("{TMP_PREFIX}x")), b"temp").unwrap();
        assert!(run(Limits {
            max_fanout: 4,
            ..Limits::SPEC
        })
        .is_ok());
    }

    /// `seal_tree` applies the same §19 bounds as a snapshot (merges never author undecodable trees).
    #[test]
    fn seal_tree_enforces_bounds() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let file = |n: &str| Entry::File {
            name: n.into(),
            mode: 0o644,
            mtime: 0,
            size: 0,
            path_salt: [0; 16],
            chunks: vec![],
        };
        let tree = Tree {
            entries: vec![file("a"), file("b")],
        };
        let tight = Limits {
            max_fanout: 1,
            ..Limits::SPEC
        };
        assert!(matches!(
            seal_tree_with(&tree, &[1; 16], &m, &store, "d", tight),
            Err(SnapError::TreeTooLarge(_))
        ));
        let a = seal_tree(&tree, &[1; 16], &m, &store, "d").unwrap();
        assert_eq!(a, seal_tree(&tree, &[1; 16], &m, &store, "d").unwrap());
    }

    /// `restore_path` confines writes to `dest_root`: no `..`, no leading `/` escape, no symlink traversal.
    #[test]
    fn restore_path_stays_inside_the_destination_root() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("d")).unwrap();
        std::fs::write(src.path().join("d/f"), b"content").unwrap();
        let s = snap(src.path(), &m, &store, None);
        let commit = Commit {
            root_tree: s.root,
            root_salt: s.salt,
            parents: vec![],
            device_id: [0; 32],
            version: 1,
            roster_seq: 0,
            last_seen_head: [0u8; 32],
            ts: 0,
        };

        let dest = tempfile::tempdir().unwrap();
        assert!(matches!(
            restore_path(&m, &store, &commit, "../escape", dest.path()),
            Err(SnapError::UnsafePath(_))
        ));
        restore_path(&m, &store, &commit, "/d/f", dest.path()).unwrap();
        assert_eq!(std::fs::read(dest.path().join("d/f")).unwrap(), b"content");

        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            let dest2 = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(outside.path(), dest2.path().join("d")).unwrap();
            assert!(matches!(
                restore_path(&m, &store, &commit, "d/f", dest2.path()),
                Err(SnapError::UnsafePath(_))
            ));
            assert!(
                !outside.path().join("f").exists(),
                "no write through a symlink"
            );
        }
    }

    #[test]
    fn path_resolve_diff_and_restore() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();

        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("a")).unwrap();
        std::fs::write(src.path().join("a/x"), b"one").unwrap();
        std::fs::write(src.path().join("a/y"), b"two").unwrap();
        std::fs::write(src.path().join("b"), b"three").unwrap();
        let s1 = snap(src.path(), &m, &store, None);

        let Some(PathNode::File { size, .. }) =
            resolve_path(&m, &store, &s1.root, &s1.salt, "a/x").unwrap()
        else {
            panic!("a/x is a file")
        };
        assert_eq!(size, 3);
        assert!(matches!(
            resolve_path(&m, &store, &s1.root, &s1.salt, "a").unwrap(),
            Some(PathNode::Dir { .. })
        ));
        assert!(resolve_path(&m, &store, &s1.root, &s1.salt, "nope")
            .unwrap()
            .is_none());

        std::fs::write(src.path().join("a/x"), b"ONE-modified").unwrap();
        let s2 = snap(src.path(), &m, &store, Some((&s1.root, &s1.salt)));
        assert_eq!(
            changed_paths(
                &m,
                &store,
                Some((&s1.root, &s1.salt)),
                Some((&s2.root, &s2.salt))
            )
            .unwrap(),
            vec!["a/x".to_string()]
        );

        let c1 = Commit {
            root_tree: s1.root,
            root_salt: s1.salt,
            parents: vec![],
            device_id: [0; 32],
            version: 1,
            roster_seq: 0,
            last_seen_head: [0; 32],
            ts: 0,
        };
        let work = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(work.path().join("a")).unwrap();
        std::fs::write(work.path().join("a/x"), b"ONE-modified").unwrap();
        std::fs::write(work.path().join("a/new"), b"later").unwrap();
        restore_path(&m, &store, &c1, "a/x", work.path()).unwrap();
        assert_eq!(std::fs::read(work.path().join("a/x")).unwrap(), b"one");

        // A folder restore makes the folder exactly the old version.
        restore_path(&m, &store, &c1, "a", work.path()).unwrap();
        assert_eq!(std::fs::read(work.path().join("a/y")).unwrap(), b"two");
        assert!(!work.path().join("a/new").exists());
        assert!(matches!(
            restore_path(&m, &store, &c1, "nope", work.path()),
            Err(SnapError::PathNotFound(_))
        ));
    }

    /// A file↔directory swap reports the file path and the directory's files.
    #[test]
    fn changed_paths_reports_type_changes() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("x"), b"file").unwrap();
        let s1 = snap(src.path(), &m, &store, None);
        std::fs::remove_file(src.path().join("x")).unwrap();
        std::fs::create_dir(src.path().join("x")).unwrap();
        std::fs::write(src.path().join("x/inner"), b"i").unwrap();
        let s2 = snap(src.path(), &m, &store, Some((&s1.root, &s1.salt)));
        let fwd = changed_paths(
            &m,
            &store,
            Some((&s1.root, &s1.salt)),
            Some((&s2.root, &s2.salt)),
        )
        .unwrap();
        assert_eq!(fwd, vec!["x".to_string(), "x/inner".to_string()]);
        let back = changed_paths(
            &m,
            &store,
            Some((&s2.root, &s2.salt)),
            Some((&s1.root, &s1.salt)),
        )
        .unwrap();
        assert_eq!(back, vec!["x".to_string(), "x/inner".to_string()]);
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
        let (got, sig) =
            decode_signed_commit(&encode_signed_commit(&commit, b"sig-bytes")).unwrap();
        assert_eq!(got, commit);
        assert_eq!(sig, b"sig-bytes");
    }

    /// §18: the decoder rejects names that could escape the folder or inject control bytes.
    #[test]
    fn decode_tree_rejects_path_traversal_names() {
        let one = |name: &str| Tree {
            entries: vec![Entry::File {
                name: name.into(),
                mode: 0o644,
                mtime: 0,
                size: 0,
                path_salt: [0u8; 16],
                chunks: vec![],
            }],
        };
        for bad in [
            "..",
            ".",
            "",
            "../etc/passwd",
            "a/b",
            "/abs",
            "back\\slash",
            "nul\0byte",
            "tab\there",
            "bell\x07",
            "esc\x1b[2J",
            "del\x7f",
        ] {
            assert!(
                matches!(
                    decode_tree(&encode_tree(&one(bad))),
                    Err(SnapError::Malformed(_))
                ),
                "name {bad:?} must be rejected"
            );
        }
        assert!(decode_tree(&encode_tree(&one("ok.txt"))).is_ok());
    }

    /// Materializability: one normal component the OS accepts; Windows device names and prefixes never pass there.
    #[test]
    fn materializable_names() {
        assert!(is_materializable("ok.txt"));
        assert!(!is_materializable(&format!("{TMP_PREFIX}abc")));
        assert!(!is_materializable(".."));
        assert!(!is_materializable(&"x".repeat(OS_NAME_MAX + 1)));
        for bad in [
            "CON", "con.txt", "Com1", "LPT9.log", "NUL ", "a:b", "C:x", "q?", "trail.", "star*",
        ] {
            assert!(windows_rejects(bad), "{bad} is not a Windows name");
        }
        for ok in ["CONSOLE", "com10", "report.txt", "résumé"] {
            assert!(!windows_rejects(ok), "{ok} is a Windows name");
        }
        if cfg!(windows) {
            assert!(!is_materializable("C:x"));
        } else {
            assert!(is_materializable("C:x"));
        }
    }

    /// Scan/decode symmetry (§6): unsafe names are skipped like symlinks. Unix-only fixtures.
    #[cfg(unix)]
    #[test]
    fn snapshot_skips_unsafe_names() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("keep.txt"), b"good").unwrap();
        std::fs::write(work.path().join("Icon\r"), b"resource fork").unwrap();
        std::fs::write(work.path().join("tab\there"), b"weird").unwrap();
        let s = snap(work.path(), &m, &store, None);
        let tree = load_tree(&s.root, &s.salt, &m, &store).unwrap();
        let names: Vec<&str> = tree.entries.iter().map(entry_name).collect();
        assert_eq!(names, vec!["keep.txt"]);
    }

    /// Restore never deletes what the snapshot skipped (unsafe names, never-synced oversize, unreadable).
    #[cfg(unix)]
    #[test]
    fn restore_keeps_everything_the_snapshot_never_tracked() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("keep.txt"), b"good").unwrap();
        std::fs::write(work.path().join("Icon\r"), b"resource fork").unwrap();
        let ours = snap(work.path(), &m, &store, None);
        std::fs::write(work.path().join("born-after-snapshot"), b"new").unwrap();

        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join("upstream.txt"), b"u").unwrap();
        let target = snap(other.path(), &m, &store, None);
        let rep = restore_tree_into(
            (&target.root, &target.salt),
            Some((&ours.root, &ours.salt)),
            &m,
            &store,
            work.path(),
            "L",
        )
        .unwrap();
        assert!(rep.conflicts.is_empty());
        assert!(work.path().join("Icon\r").exists(), "unsafe name untouched");
        assert!(work.path().join("born-after-snapshot").exists());
        assert!(
            !work.path().join("keep.txt").exists(),
            "tracked + unchanged is deleted"
        );
        assert_eq!(
            std::fs::read(work.path().join("upstream.txt")).unwrap(),
            b"u"
        );
    }

    /// A folder deleted or replaced upstream takes a lone macOS icon with it; anything else untracked keeps both.
    #[cfg(unix)]
    #[test]
    fn a_folder_gone_upstream_takes_only_a_lone_macos_icon_with_it() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let work = tempfile::tempdir().unwrap();
        for d in ["deleted", "replaced", "busy"] {
            std::fs::create_dir(work.path().join(d)).unwrap();
            std::fs::write(work.path().join(d).join("f"), b"tracked").unwrap();
            std::fs::write(work.path().join(d).join("Icon\r"), b"icon").unwrap();
        }
        let ours = snap(work.path(), &m, &store, None);
        std::fs::write(work.path().join("busy/born-after-snapshot"), b"new").unwrap();

        let up = tempfile::tempdir().unwrap();
        std::fs::write(up.path().join("replaced"), b"now a file").unwrap();
        let target = snap(up.path(), &m, &store, None);
        let rep = restore_tree_into(
            (&target.root, &target.salt),
            Some((&ours.root, &ours.salt)),
            &m,
            &store,
            work.path(),
            "L",
        )
        .unwrap();
        assert!(rep.conflicts.is_empty());
        assert!(!work.path().join("deleted").exists());
        assert_eq!(
            std::fs::read(work.path().join("replaced")).unwrap(),
            b"now a file"
        );
        assert!(!work.path().join("busy/f").exists());
        assert_eq!(
            std::fs::read(work.path().join("busy/Icon\r")).unwrap(),
            b"icon"
        );
        assert!(work.path().join("busy/born-after-snapshot").exists());
    }

    /// A local edit made after the snapshot is kept; the incoming version lands beside it.
    #[test]
    fn restore_never_clobbers_an_edit_made_after_the_snapshot() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("f.txt"), b"base").unwrap();
        std::fs::write(work.path().join("g.txt"), b"base").unwrap();
        let ours = snap(work.path(), &m, &store, None);

        let up = tempfile::tempdir().unwrap();
        std::fs::write(up.path().join("f.txt"), b"upstream").unwrap();
        std::fs::write(up.path().join("g.txt"), b"upstream-g").unwrap();
        let target = snap(up.path(), &m, &store, None);

        // Edit f.txt after the snapshot (a different size guarantees a changed signal).
        std::fs::write(work.path().join("f.txt"), b"local edit!").unwrap();
        let rep = restore_tree_into(
            (&target.root, &target.salt),
            Some((&ours.root, &ours.salt)),
            &m,
            &store,
            work.path(),
            "dev-abc",
        )
        .unwrap();
        assert_eq!(rep.conflicts, vec!["f.txt".to_string()]);
        assert_eq!(
            std::fs::read(work.path().join("f.txt")).unwrap(),
            b"local edit!"
        );
        assert_eq!(
            std::fs::read(work.path().join("f.conflict-dev-abc.txt")).unwrap(),
            b"upstream"
        );
        assert_eq!(
            std::fs::read(work.path().join("g.txt")).unwrap(),
            b"upstream-g"
        );
        // No temp file survives.
        assert!(std::fs::read_dir(work.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_str()
            .unwrap()
            .starts_with(TMP_PREFIX)));
    }

    /// A local edit to a file upstream left alone stays as it is, with no conflict copy.
    #[test]
    fn an_edit_to_a_file_upstream_left_alone_is_not_a_conflict() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("mine.txt"), b"base").unwrap();
        std::fs::write(work.path().join("theirs.txt"), b"base").unwrap();
        let ours = snap(work.path(), &m, &store, None);

        let up = tempfile::tempdir().unwrap();
        std::fs::write(up.path().join("mine.txt"), b"base").unwrap();
        std::fs::write(up.path().join("theirs.txt"), b"upstream").unwrap();
        let target = snapshot_tree(
            up.path(),
            &m,
            &store,
            Some(Prior {
                root: &ours.root,
                salt: &ours.salt,
                fast_path: false,
            }),
            &mut SnapshotMemo::default(),
        )
        .unwrap();

        std::fs::write(work.path().join("mine.txt"), b"local edit!").unwrap();
        let rep = restore_tree_into(
            (&target.root, &target.salt),
            Some((&ours.root, &ours.salt)),
            &m,
            &store,
            work.path(),
            "L",
        )
        .unwrap();
        assert!(rep.conflicts.is_empty());
        assert_eq!(
            std::fs::read(work.path().join("mine.txt")).unwrap(),
            b"local edit!"
        );
        assert_eq!(
            std::fs::read(work.path().join("theirs.txt")).unwrap(),
            b"upstream"
        );
        assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 2);
    }

    /// A read-only file and a read-only directory are replaced without an EACCES wedge.
    #[cfg(unix)]
    #[test]
    fn restore_replaces_read_only_files_and_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let work = tempfile::tempdir().unwrap();
        std::fs::create_dir(work.path().join("ro")).unwrap();
        std::fs::write(work.path().join("ro/f"), b"v1").unwrap();
        std::fs::set_permissions(
            work.path().join("ro/f"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        std::fs::set_permissions(
            work.path().join("ro"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        let ours = snap(work.path(), &m, &store, None);

        let up = tempfile::tempdir().unwrap();
        std::fs::create_dir(up.path().join("ro")).unwrap();
        std::fs::write(up.path().join("ro/f"), b"version two").unwrap();
        std::fs::set_permissions(
            up.path().join("ro/f"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        std::fs::set_permissions(up.path().join("ro"), std::fs::Permissions::from_mode(0o555))
            .unwrap();
        let target = snap(up.path(), &m, &store, None);

        restore_tree_into(
            (&target.root, &target.salt),
            Some((&ours.root, &ours.salt)),
            &m,
            &store,
            work.path(),
            "L",
        )
        .unwrap();
        assert_eq!(
            std::fs::read(work.path().join("ro/f")).unwrap(),
            b"version two"
        );
        let dir_mode = std::fs::metadata(work.path().join("ro"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            dir_mode & 0o777,
            0o555,
            "the recorded dir mode is reapplied"
        );
        for p in [up.path().join("ro"), work.path().join("ro")] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// Entries this OS cannot create ride forward instead of reading as deletions.
    #[test]
    fn unmaterializable_entries_are_carried_forward() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("real"), b"r").unwrap();
        let s = snap(src.path(), &m, &store, None);
        let mut tree = load_tree(&s.root, &s.salt, &m, &store).unwrap();
        tree.entries.push(Entry::File {
            name: "x".repeat(OS_NAME_MAX + 1),
            mode: 0o644,
            mtime: 0,
            size: 0,
            path_salt: [0; 16],
            chunks: vec![],
        });
        tree.entries
            .sort_by(|a, b| entry_name(a).cmp(entry_name(b)));
        let root = seal_tree(&tree, &s.salt, &m, &store, "").unwrap();

        let dst = tempfile::tempdir().unwrap();
        let rep = restore_tree_into((&root, &s.salt), None, &m, &store, dst.path(), "L").unwrap();
        assert_eq!(rep.skipped.len(), 1);
        let again = snap(dst.path(), &m, &store, Some((&root, &s.salt)));
        let t2 = load_tree(&again.root, &again.salt, &m, &store).unwrap();
        assert_eq!(t2.entries.len(), 2, "the long name is carried forward");
    }

    /// §18: setuid/setgid/sticky in a member-authored tree are stripped on restore.
    #[cfg(unix)]
    #[test]
    fn restore_strips_setuid_setgid_sticky() {
        use std::os::unix::fs::PermissionsExt;
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let tree = Tree {
            entries: vec![Entry::File {
                name: "x".into(),
                mode: 0o7755,
                mtime: 0,
                size: 0,
                path_salt: [0u8; 16],
                chunks: vec![],
            }],
        };
        let id = seal_tree(&tree, &[3; 16], &m, &store, "").unwrap();
        let dst = tempfile::tempdir().unwrap();
        restore_tree_into((&id, &[3; 16]), None, &m, &store, dst.path(), "L").unwrap();
        let mode = std::fs::metadata(dst.path().join("x"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7000, 0);
        assert_eq!(mode & 0o0777, 0o0755);
    }

    /// A member-authored entry declaring a smaller size than its chunks never writes past it.
    #[test]
    fn restore_refuses_content_past_the_declared_size() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), vec![5u8; 10_000]).unwrap();
        let s = snap(src.path(), &m, &store, None);
        let mut tree = load_tree(&s.root, &s.salt, &m, &store).unwrap();
        if let Entry::File { size, .. } = &mut tree.entries[0] {
            *size = 10;
        }
        let root = seal_tree(&tree, &s.salt, &m, &store, "").unwrap();
        let dst = tempfile::tempdir().unwrap();
        assert!(matches!(
            restore_tree_into((&root, &s.salt), None, &m, &store, dst.path(), "L"),
            Err(SnapError::Malformed(_))
        ));
        assert!(!dst.path().join("f").exists());
    }

    #[test]
    fn decode_tree_rejects_unsorted_and_duplicate_names() {
        let file = |name: &str| Entry::File {
            name: name.into(),
            mode: 0o644,
            mtime: 0,
            size: 0,
            path_salt: [0u8; 16],
            chunks: vec![],
        };
        for bad in [vec![file("b"), file("a")], vec![file("a"), file("a")]] {
            assert!(matches!(
                decode_tree(&encode_tree(&Tree { entries: bad })),
                Err(SnapError::Malformed(_))
            ));
        }
        let ok = Tree {
            entries: vec![file("a"), file("b"), file("c")],
        };
        assert_eq!(decode_tree(&encode_tree(&ok)).unwrap(), ok);
    }

    #[test]
    fn commit_sign_verify_and_author_binding() {
        use secsec_sig::DeviceKey;
        let dev = DeviceKey::generate().unwrap();
        let commit = Commit {
            root_tree: [9u8; 32],
            root_salt: [8u8; 16],
            parents: vec![[7u8; 32]],
            device_id: dev.device_id().unwrap(),
            version: 3,
            roster_seq: 2,
            last_seen_head: [5u8; 32],
            ts: 1234,
        };
        let sig = sign_commit(&dev, &commit).unwrap();
        assert!(verify_commit(&dev.public(), &commit, &sig).is_ok());
        let other = DeviceKey::generate().unwrap();
        assert!(matches!(
            verify_commit(&other.public(), &commit, &sig),
            Err(SnapError::BadSignature)
        ));
        let mut tampered = commit.clone();
        tampered.version = 4;
        assert!(matches!(
            verify_commit(&dev.public(), &tampered, &sig),
            Err(SnapError::BadSignature)
        ));
    }

    #[test]
    fn snapshot_then_restore_is_byte_identical_and_idempotent() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();

        std::fs::write(src.path().join("empty"), b"").unwrap();
        std::fs::write(src.path().join("small.txt"), b"hello world").unwrap();
        let mut big = vec![0u8; 700 * 1024];
        getrandom::fill(&mut big).unwrap();
        std::fs::write(src.path().join("big.bin"), &big).unwrap();
        std::fs::create_dir_all(src.path().join("sub/deeper")).unwrap();
        std::fs::write(src.path().join("sub/note.md"), b"# note\n").unwrap();
        std::fs::write(src.path().join("sub/deeper/leaf"), [7u8; 40 * 1024]).unwrap();

        let s = snap(src.path(), &m, &store, None);
        restore_into(&s, &m, &store, dst.path());
        let again = snap(dst.path(), &m, &store, Some((&s.root, &s.salt)));
        assert_eq!(again.root, s.root, "restore→snapshot must be idempotent");
        assert_eq!(read_tree(src.path()), read_tree(dst.path()));
    }

    #[test]
    fn signed_commit_lifecycle_round_trips() {
        use secsec_sig::DeviceKey;
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let device = DeviceKey::generate().unwrap();

        std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b.bin"), [3u8; 8 * 1024]).unwrap();

        let s = snap(src.path(), &m, &store, None);
        let commit = Commit {
            root_tree: s.root,
            root_salt: s.salt,
            parents: vec![[0x44u8; 32]],
            device_id: device.device_id().unwrap(),
            version: 7,
            roster_seq: 2,
            last_seen_head: [0x55u8; 32],
            ts: 99,
        };
        let commit_id = seal_signed_commit(&m, &store, &device, &commit).unwrap();
        let (got, sig) = open_signed_commit(&commit_id, &m, &store).unwrap();
        assert_eq!(got, commit);
        verify_commit(&device.public(), &got, &sig).unwrap();
        restore_commit_tree(&got, &commit_id, None, &m, &store, dst.path()).unwrap();
        assert_eq!(read_tree(src.path()), read_tree(dst.path()));
    }

    #[test]
    fn incremental_snapshot_reuses_salts_and_is_idempotent() {
        let src = tempfile::tempdir().unwrap();
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();

        std::fs::write(src.path().join("a.txt"), b"AAAA").unwrap();
        std::fs::write(src.path().join("b.txt"), b"BBBB").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/c"), b"CCCC").unwrap();

        let s1 = snap(src.path(), &m, &store, None);
        let tree1 = load_tree(&s1.root, &s1.salt, &m, &store).unwrap();
        let s2 = snap(src.path(), &m, &store, Some((&s1.root, &s1.salt)));
        assert_eq!(s1.root, s2.root);
        assert_eq!(s1.salt, s2.salt);

        std::fs::write(src.path().join("a.txt"), b"A-modified").unwrap();
        let s3 = snap(src.path(), &m, &store, Some((&s2.root, &s2.salt)));
        assert_ne!(s1.root, s3.root);
        assert_eq!(s3.salt, s1.salt);
        let tree3 = load_tree(&s3.root, &s3.salt, &m, &store).unwrap();
        assert_eq!(
            find_entry(Some(&tree1), "b.txt"),
            find_entry(Some(&tree3), "b.txt")
        );
        assert_eq!(
            find_entry(Some(&tree1), "sub"),
            find_entry(Some(&tree3), "sub")
        );
        let (
            Some(Entry::File {
                path_salt: ps1,
                chunks: ch1,
                ..
            }),
            Some(Entry::File {
                path_salt: ps3,
                chunks: ch3,
                ..
            }),
        ) = (
            find_entry(Some(&tree1), "a.txt"),
            find_entry(Some(&tree3), "a.txt"),
        )
        else {
            panic!("a.txt must be a file")
        };
        assert_eq!(ps1, ps3);
        assert_ne!(ch1, ch3);
    }

    /// Seeding salts from another device's tree makes identical content identical ids, with no fast path.
    #[test]
    fn seeded_salts_give_identical_ids_for_identical_content() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let a = tempfile::tempdir().unwrap();
        std::fs::write(a.path().join("same.txt"), b"identical").unwrap();
        std::fs::write(a.path().join("diff.txt"), b"from a").unwrap();
        let sa = snap(a.path(), &m, &store, None);

        let b = tempfile::tempdir().unwrap();
        std::fs::write(b.path().join("same.txt"), b"identical").unwrap();
        std::fs::write(b.path().join("diff.txt"), b"from b").unwrap();
        let sb = snapshot_tree(
            b.path(),
            &m,
            &store,
            Some(Prior {
                root: &sa.root,
                salt: &sa.salt,
                fast_path: false,
            }),
            &mut SnapshotMemo::default(),
        )
        .unwrap();
        let ta = load_tree(&sa.root, &sa.salt, &m, &store).unwrap();
        let tb = load_tree(&sb.root, &sb.salt, &m, &store).unwrap();
        assert_eq!(
            find_entry(Some(&ta), "same.txt"),
            {
                let mut e = find_entry(Some(&tb), "same.txt").cloned().unwrap();
                if let (
                    Entry::File { mtime, mode, .. },
                    Some(Entry::File {
                        mtime: ma,
                        mode: mo,
                        ..
                    }),
                ) = (&mut e, find_entry(Some(&ta), "same.txt"))
                {
                    *mtime = *ma;
                    *mode = *mo;
                }
                Some(e)
            }
            .as_ref()
        );
        assert_ne!(
            find_entry(Some(&ta), "diff.txt").map(|e| match e {
                Entry::File { chunks, .. } => chunks.clone(),
                Entry::Dir { .. } => vec![],
            }),
            find_entry(Some(&tb), "diff.txt").map(|e| match e {
                Entry::File { chunks, .. } => chunks.clone(),
                Entry::Dir { .. } => vec![],
            })
        );
    }

    #[test]
    fn reachable_objects_covers_graph_and_fails_safe() {
        let src = tempfile::tempdir().unwrap();
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b.bin"), [3u8; 8 * 1024]).unwrap();
        let commit_id = test_signed_commit(src.path(), &m, &store);
        let reachable = reachable_objects(&m, &store, &commit_id).unwrap();
        assert_eq!(reachable.len() as u64, store.object_count().unwrap());
        let ed = tempfile::tempdir().unwrap();
        let empty = store_in(&ed);
        assert!(matches!(
            reachable_objects(&m, &empty, &commit_id),
            Err(SnapError::Missing(_))
        ));
    }

    /// `tree_closure` never descends into a known subtree and matches the full walk otherwise.
    #[test]
    fn tree_closure_skips_known_subtrees() {
        let src = tempfile::tempdir().unwrap();
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b"), b"b").unwrap();
        std::fs::write(src.path().join("a"), b"a").unwrap();
        let s = snap(src.path(), &m, &store, None);
        let mut all = BTreeSet::new();
        tree_closure(&m, &store, &s.root, &s.salt, &BTreeSet::new(), &mut all).unwrap();
        assert_eq!(all.len() as u64, store.object_count().unwrap());
        let t = load_tree(&s.root, &s.salt, &m, &store).unwrap();
        let Some(Entry::Dir { subtree, .. }) = find_entry(Some(&t), "sub") else {
            panic!("sub is a dir")
        };
        let mut partial = BTreeSet::new();
        tree_closure(
            &m,
            &store,
            &s.root,
            &s.salt,
            &BTreeSet::from([*subtree]),
            &mut partial,
        )
        .unwrap();
        assert_eq!(partial.len(), 2, "root tree + a's chunk only");
    }

    #[test]
    fn reads_across_a_generation_boundary_with_a_key_ring() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let dev = secsec_sig::DeviceKey::generate().unwrap();
        let mk1 = MasterKey::new(1, [0x11; 32]);
        let mk2 = MasterKey::new(2, [0x22; 32]);

        let src1 = tempfile::tempdir().unwrap();
        std::fs::write(src1.path().join("old.txt"), b"gen1 file").unwrap();
        let s1 = snap(src1.path(), &mk1, &store, None);
        let c1 = Commit {
            root_tree: s1.root,
            root_salt: s1.salt,
            parents: vec![],
            device_id: dev.device_id().unwrap(),
            version: 1,
            roster_seq: 0,
            last_seen_head: [0u8; 32],
            ts: 0,
        };
        let c1_id = seal_signed_commit(&mk1, &store, &dev, &c1).unwrap();

        let src2 = tempfile::tempdir().unwrap();
        std::fs::write(src2.path().join("new.txt"), b"gen2 file").unwrap();
        let s2 = snap(src2.path(), &mk2, &store, None);
        let c2 = Commit {
            root_tree: s2.root,
            root_salt: s2.salt,
            parents: vec![c1_id],
            device_id: dev.device_id().unwrap(),
            version: 2,
            roster_seq: 0,
            last_seen_head: c1_id,
            ts: 0,
        };
        let c2_id = seal_signed_commit(&mk2, &store, &dev, &c2).unwrap();

        assert!(matches!(
            reachable_objects(&mk2, &store, &c2_id),
            Err(SnapError::Object(ObjError::UnknownGeneration(1)))
        ));
        let keyring: BTreeMap<u32, MasterKey> = [(1u32, mk1), (2u32, mk2)].into_iter().collect();
        let reachable = reachable_objects(&keyring, &store, &c2_id).unwrap();
        assert!(reachable.contains(&c1_id) && reachable.contains(&c2_id));
        let (got_c1, _) = open_signed_commit(&c1_id, &keyring, &store).unwrap();
        let dst = tempfile::tempdir().unwrap();
        restore_commit_tree(&got_c1, &c1_id, None, &keyring, &store, dst.path()).unwrap();
        assert_eq!(
            std::fs::read(dst.path().join("old.txt")).unwrap(),
            b"gen1 file"
        );
    }

    fn test_signed_commit(src: &Path, m: &MasterKey, store: &Store) -> Id {
        let dev = secsec_sig::DeviceKey::generate().unwrap();
        let s = snap(src, m, store, None);
        let commit = Commit {
            root_tree: s.root,
            root_salt: s.salt,
            parents: Vec::new(),
            device_id: dev.device_id().unwrap(),
            version: 1,
            roster_seq: 0,
            last_seen_head: [0u8; 32],
            ts: 0,
        };
        seal_signed_commit(m, store, &dev, &commit).unwrap()
    }

    /// Symlinks are skipped; an untracked one in the destination survives restore.
    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_and_untracked_ones_survive_restore() {
        use std::os::unix::fs::symlink;
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let m = mk();
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("real.txt"), b"data").unwrap();
        symlink("real.txt", src.path().join("link")).unwrap();
        let s = snap(src.path(), &m, &store, None);
        let tree = load_tree(&s.root, &s.salt, &m, &store).unwrap();
        let names: Vec<&str> = tree.entries.iter().map(entry_name).collect();
        assert_eq!(names, vec!["real.txt"]);

        let dst = tempfile::tempdir().unwrap();
        symlink("/nonexistent-target", dst.path().join("mylink")).unwrap();
        restore_into(&s, &m, &store, dst.path());
        assert_eq!(std::fs::read(dst.path().join("real.txt")).unwrap(), b"data");
        assert!(std::fs::symlink_metadata(dst.path().join("mylink")).is_ok());
    }

    /// An unchanged file keeps its chunk ids across a rotation (the fast path reads through the ring).
    #[test]
    fn unchanged_file_reuses_chunk_ids_across_a_rotation() {
        let sd = tempfile::tempdir().unwrap();
        let store = store_in(&sd);
        let mk1 = MasterKey::new(1, [0x11; 32]);
        let src = tempfile::tempdir().unwrap();
        let mut big = vec![0u8; 400 * 1024];
        getrandom::fill(&mut big).unwrap();
        std::fs::write(src.path().join("f.bin"), &big).unwrap();
        let chunks_of =
            |root: &Id, salt: &PathSalt, keys: &dyn Fn(&Id, &PathSalt) -> Tree| match find_entry(
                Some(&keys(root, salt)),
                "f.bin",
            ) {
                Some(Entry::File { chunks, .. }) => chunks.clone(),
                _ => panic!("f.bin must be a file"),
            };
        let s1 = snap(src.path(), &mk1, &store, None);
        let ring: BTreeMap<u32, MasterKey> = [
            (1u32, MasterKey::new(1, [0x11; 32])),
            (2u32, MasterKey::new(2, [0x22; 32])),
        ]
        .into_iter()
        .collect();
        let s2 = snap(src.path(), &ring, &store, Some((&s1.root, &s1.salt)));
        let load1 = |r: &Id, s: &PathSalt| load_tree(r, s, &mk1, &store).unwrap();
        let load2 = |r: &Id, s: &PathSalt| load_tree(r, s, &ring, &store).unwrap();
        assert_eq!(
            chunks_of(&s1.root, &s1.salt, &load1),
            chunks_of(&s2.root, &s2.salt, &load2)
        );
    }
}
