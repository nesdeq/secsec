//! `secsec-snapshot` — the object graph and directory snapshot/restore (`secsec-Design.md` §6, §9.2).
//!
//! A snapshot is an SSHSIG-signed `Commit` pointing at a root `Tree`; trees list files (chunk-id
//! lists) and subtrees, sealed via [`secsec_object`]. Restore walks the tree back, verifying every
//! object (§9.2), and rebuilds the directory byte-for-byte. Per-path salts ride in the parent
//! object (root salt in the commit), and a path's salt is **constant across versions** (§9.7) —
//! [`snapshot_tree`] reuses salts from the previous tree, which is what makes incremental
//! upload/dedup and merge content-equality work (a correctness requirement, not an optimization).

#![forbid(unsafe_code)]

use secsec_canon::{CanonError, Reader, Writer};
use secsec_frame::{ObjType, MAX_LIST_ELEMENTS, MAX_TREE_DEPTH, MAX_TREE_FANOUT};
use secsec_kdf::{MasterKey, MasterKeys};
use secsec_object::{
    open_object, seal_object, unpad_chunk, Id, ObjError, Padding, PathSalt, ZERO_SALT,
};
use secsec_store::{Store, StoreError};
use std::io::Write;
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
        /// Modification time, nanoseconds since the Unix epoch (advisory).
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
        /// Modification time, nanoseconds since the Unix epoch (advisory).
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
    /// A file name was not valid UTF-8.
    NonUtf8Name,
    /// OS RNG failure.
    Rng,
    /// Commit signature invalid, or the signer is not the commit's author (§9.6).
    BadSignature,
    /// A requested path did not exist in the tree being resolved (`secsec log`/`restore`).
    PathNotFound(String),
    /// The requested version's content has been pruned beyond retention (§15) — it cannot be restored.
    PrunedBeyondRetention(String),
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
                write!(f, "the requested version of {p} has been pruned beyond retention")
            }
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

/// Path-traversal guard, enforced at decode (§18): a name MUST be a single non-empty path
/// component — never `.`/`..`, a separator, or a control character (terminal-escape injection). A
/// compromised member (§3) can author a tree, so restore must never join an unchecked name.
fn validate_entry_name(name: &str) -> Result<(), SnapError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(|c| c.is_control())
    {
        return Err(SnapError::Malformed("unsafe tree entry name"));
    }
    Ok(())
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
        // Name guard + §9.3 canonical ordering: strictly ascending names (also bans duplicates).
        validate_entry_name(&name)?;
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

/// Fuzz-only hook: drive [`decode_tree`] on arbitrary bytes (must never panic / OOM, §18). Not part
/// of the public API.
#[doc(hidden)]
pub fn __fuzz_decode_tree(bytes: &[u8]) {
    let _ = decode_tree(bytes);
}

/// Fuzz-only hook: drive [`decode_signed_commit`] on arbitrary bytes (must never panic / OOM, §18).
#[doc(hidden)]
pub fn __fuzz_decode_signed_commit(bytes: &[u8]) {
    let _ = decode_signed_commit(bytes);
}

// ---- commit signing (§9.6 secsec-commit-v1) ----

impl Commit {
    /// The canonical signed message — all commit fields, binding author, replay counter, roster
    /// state, and last-seen head (§9.3/§9.6).
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

/// Verify a commit: valid SSHSIG under `NS_COMMIT` **and** `pubkey` is the named author. The caller
/// resolves `pubkey` from the RFP-anchored roster (§8), so a non-member cannot forge a commit (P3).
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

/// The recorded permission bits: the 9 standard bits only — setuid/setgid/sticky are dropped (§18;
/// a member-authored tree must not plant them). Masked symmetrically with [`apply_metadata`] so
/// snapshot→restore→snapshot stays idempotent.
#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o0777
}
#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    0
}

/// File modification time as nanoseconds since the Unix epoch — the fast-path's change signal (with
/// size). Nanosecond resolution stops two distinct same-size writes from colliding on one value.
fn mtime_of(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Snapshot the directory `root` into `store`, returning its root tree `(id, salt)` — the content
/// half of a sync push ([`seal_signed_commit`] wraps it). `prev` is the previous snapshot's root
/// (`None` on first sync); each path's salt is reused from it (§9.7 — salts are constant across
/// versions, the basis for dedup and merge content-equality), fresh salts only for new paths.
pub fn snapshot_tree<K: MasterKeys>(
    root: &Path,
    keys: &K,
    store: &Store,
    prev: Option<(&Id, &PathSalt)>,
) -> Result<(Id, PathSalt), SnapError> {
    // New objects are chunked and sealed under the current generation; the previous tree may have been
    // sealed under an older one, so it is read through the whole key ring (§8.2).
    let chunker = secsec_chunk::Chunker::with_defaults(&keys.current().cdc_seed());
    let prev_tree = match prev {
        Some((id, salt)) => Some(load_tree(id, salt, keys, store)?),
        None => None,
    };
    // The root tree's own salt persists too (reused if the repo has synced before).
    let root_salt = match prev {
        Some((_, salt)) => *salt,
        None => random_salt()?,
    };
    // Wall-clock at snapshot start: the fast-path reuses a file only when its mtime is strictly before
    // this, so a file touched during the snapshot is never trusted as unchanged (racy-clean guard).
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    let ctx = SnapCtx {
        keys,
        store,
        chunker: &chunker,
        now_nanos,
    };
    snapshot_dir(&ctx, root, 0, prev_tree.as_ref(), root_salt)
}

/// Walk-constant context for a snapshot: the key ring, object store, chunker, and the snapshot-start
/// time (nanoseconds) used by the unchanged-file fast path's racy-clean guard. Threaded through the
/// recursion so per-directory calls stay short.
struct SnapCtx<'a, K: MasterKeys> {
    keys: &'a K,
    store: &'a Store,
    chunker: &'a secsec_chunk::Chunker,
    now_nanos: u64,
}

/// The name field of a tree entry (file or dir).
fn entry_name(e: &Entry) -> &str {
    match e {
        Entry::File { name, .. } | Entry::Dir { name, .. } => name,
    }
}

/// Sign `commit` (§9.6), seal the signed-commit object (fields ‖ sig), store it, and return its
/// content id — the commit id a Head points at. The signer must be `commit.device_id`.
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

/// Fetch and open the signed-commit object `commit_id`, returning `(commit, sig)`. The content id
/// is re-verified by [`open_object`]; the caller must still [`verify_commit`] against the author's
/// roster key (§9.6).
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

/// Restore the tree named by `commit` (its `root_tree`/`root_salt`) into `dest` (created if absent).
/// The caller is expected to have already [`verify_commit`]-ed the commit (§9.6).
pub fn restore_commit_tree<K: MasterKeys>(
    commit: &Commit,
    keys: &K,
    store: &Store,
    dest: &Path,
) -> Result<(), SnapError> {
    std::fs::create_dir_all(dest)?;
    restore_tree(&commit.root_tree, &commit.root_salt, keys, store, dest, 0)
}

fn snapshot_dir<K: MasterKeys>(
    ctx: &SnapCtx<'_, K>,
    dir: &Path,
    depth: usize,
    prev: Option<&Tree>,
    this_salt: PathSalt,
) -> Result<(Id, PathSalt), SnapError> {
    if depth >= MAX_TREE_DEPTH {
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
            let this_mtime = mtime_of(&meta);
            // Fast path: a file with the same size and the same nanosecond mtime as the previous
            // snapshot — and whose mtime is strictly before this snapshot started, so it cannot still
            // be changing within the current clock tick — is taken as unchanged and reuses its prior
            // chunk ids verbatim, with no read, re-chunk, or re-seal. Those ids stay valid across a key
            // rotation (they address the old generation; cross-generation reads are legal, §8.2), so a
            // revoke does not re-store the whole working set.
            if let Some(Entry::File {
                mtime: prev_mtime,
                size: prev_size,
                path_salt,
                chunks,
                ..
            }) = prev_entry
            {
                if *prev_size == meta.len()
                    && *prev_mtime == this_mtime
                    && this_mtime < ctx.now_nanos
                {
                    entries.push(Entry::File {
                        name,
                        mode: mode_of(&meta),
                        mtime: this_mtime,
                        size: *prev_size,
                        path_salt: *path_salt,
                        chunks: chunks.clone(),
                    });
                    continue;
                }
            }
            // Reuse the path's salt across versions (§9.7); a path first seen now gets a fresh one.
            let path_salt = match prev_entry {
                Some(Entry::File { path_salt, .. }) => *path_salt,
                _ => random_salt()?,
            };
            // Stream the file through the chunker so a file larger than RAM is never read whole.
            let file = std::fs::File::open(&path)?;
            let mut chunks = Vec::new();
            let size = ctx
                .chunker
                .chunk_stream(file, |chunk| -> Result<(), SnapError> {
                    let padded = secsec_object::pad_chunk(chunk, Padding::PowerOfTwo);
                    let (id, blob) =
                        seal_object(ctx.keys.current(), ObjType::Chunk, &path_salt, &padded);
                    ctx.store.put(&id, &blob)?;
                    chunks.push(id);
                    Ok(())
                })
                .map_err(|e| match e {
                    secsec_chunk::StreamError::Read(io) => SnapError::Io(io),
                    secsec_chunk::StreamError::Emit(se) => se,
                })?;
            entries.push(Entry::File {
                name,
                mode: mode_of(&meta),
                mtime: this_mtime,
                size,
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
                    Some(load_tree(subtree, subtree_salt, ctx.keys, ctx.store)?),
                    *subtree_salt,
                ),
                _ => (None, random_salt()?),
            };
            let (subtree, subtree_salt) =
                snapshot_dir(ctx, &path, depth + 1, prev_sub.as_ref(), sub_salt)?;
            entries.push(Entry::Dir {
                name,
                mode: mode_of(&meta),
                mtime: mtime_of(&meta),
                subtree,
                subtree_salt,
            });
        }
        // Symlinks/FIFOs/sockets/devices are skipped, never an error (§6: files + dirs only).
    }

    let tree = Tree { entries };
    let (id, blob) = seal_object(ctx.keys.current(), ObjType::Tree, &this_salt, &encode_tree(&tree));
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

fn restore_tree<K: MasterKeys>(
    tree_id: &Id,
    tree_salt: &PathSalt,
    keys: &K,
    store: &Store,
    dir: &Path,
    depth: usize,
) -> Result<(), SnapError> {
    if depth >= MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    let tree = decode_tree(&fetch_open(keys, ObjType::Tree, tree_salt, tree_id, store)?)?;
    std::fs::create_dir_all(dir)?;

    // Reconcile the directory TO the tree (§10 Materialize): tracked-kind on-disk entries absent
    // from the tree are removed, so upstream deletions apply instead of resurrecting. Untracked
    // kinds (symlinks/special files) are left alone.
    let keep: std::collections::BTreeSet<&str> = tree.entries.iter().map(entry_name).collect();
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let on_disk = ent.file_name();
        // A non-UTF-8 name can never be a (UTF-8) tree entry → extra.
        let is_kept = on_disk.to_str().is_some_and(|n| keep.contains(n));
        if !is_kept {
            remove_extra(&ent.path())?;
        }
    }

    for entry in &tree.entries {
        match entry {
            Entry::File {
                name,
                mode,
                mtime,
                size,
                path_salt,
                chunks,
            } => {
                let path = dir.join(name);
                // Clear a non-file at this path first; a symlink is unlinked, never followed (the
                // write must not dereference it onto a target outside the folder).
                clear_for_regular_file(&path)?;
                // Stream chunk-by-chunk to disk so a file larger than RAM is never held whole.
                let mut file = std::fs::File::create(&path)?;
                let mut written: u64 = 0;
                for cid in chunks {
                    let padded = fetch_open(keys, ObjType::Chunk, path_salt, cid, store)?;
                    let plain = unpad_chunk(&padded, Padding::PowerOfTwo)?;
                    file.write_all(plain)?;
                    written += plain.len() as u64;
                }
                if written != *size {
                    return Err(SnapError::Malformed("restored file size mismatch"));
                }
                apply_metadata(&path, *mode, *mtime)?;
            }
            Entry::Dir {
                name,
                mode,
                mtime,
                subtree,
                subtree_salt,
            } => {
                let path = dir.join(name);
                // file/symlink → dir type change: remove the old entry (a symlink as a link).
                if let Ok(meta) = std::fs::symlink_metadata(&path) {
                    if !meta.file_type().is_dir() {
                        std::fs::remove_file(&path)?;
                    }
                }
                restore_tree(subtree, subtree_salt, keys, store, &path, depth + 1)?;
                // Set the dir's metadata AFTER populating it (writing children bumps its mtime).
                apply_metadata(&path, *mode, *mtime)?;
            }
        }
    }
    Ok(())
}

/// Apply a deletion: remove a regular file or real directory not in the restored tree. Symlinks and
/// special files are untouched (never synced, so never secsec's to delete; never traversed).
fn remove_extra(path: &Path) -> Result<(), SnapError> {
    let ft = std::fs::symlink_metadata(path)?.file_type();
    if ft.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else if ft.is_file() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Free `path` for a regular-file write: remove a directory recursively, unlink a symlink/special
/// file (never followed); an existing regular file or absent path is left for `write`.
fn clear_for_regular_file(path: &Path) -> Result<(), SnapError> {
    if let Ok(ft) = std::fs::symlink_metadata(path).map(|m| m.file_type()) {
        if ft.is_dir() {
            std::fs::remove_dir_all(path)?;
        } else if !ft.is_file() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

/// Reproduce the recorded `mode`/`mtime` on the restored path — required for snapshot→restore→
/// snapshot idempotence (the tree id covers them, §6; dropping them would spuriously re-commit).
fn apply_metadata(path: &Path, mode: u32, mtime: u64) -> Result<(), SnapError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 9 standard permission bits only — never restore setuid/setgid/sticky (§18, matches mode_of).
        if mode != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o0777))?;
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    // mtime is nanoseconds since the epoch, member-authored: split into whole seconds + sub-second
    // nanos, saturating so a hostile value can't wrap and break restore→snapshot idempotence.
    let secs = i64::try_from(mtime / 1_000_000_000).unwrap_or(i64::MAX);
    let subsec_nanos = (mtime % 1_000_000_000) as u32;
    filetime::set_file_mtime(path, filetime::FileTime::from_unix_time(secs, subsec_nanos))?;
    Ok(())
}

// ---- tree bridge primitives (§10 merge orchestration) ----
//
// Single-level tree I/O exposed for the sync engine, which converts a `Tree` to/from its in-memory
// merge model and drives the recursion itself (it does not pull `secsec-sync` in here).

/// Fetch, open (re-verifying the content address, §9.2), and decode a single `Tree` object. Used by
/// the merge engine to materialize one directory level; it recurses on `Entry::Dir` children itself.
pub fn load_tree<K: MasterKeys>(
    tree_id: &Id,
    tree_salt: &PathSalt,
    keys: &K,
    store: &Store,
) -> Result<Tree, SnapError> {
    decode_tree(&fetch_open(keys, ObjType::Tree, tree_salt, tree_id, store)?)
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
pub fn restore_tree_into<K: MasterKeys>(
    tree_id: &Id,
    tree_salt: &PathSalt,
    keys: &K,
    store: &Store,
    dest: &Path,
) -> Result<(), SnapError> {
    std::fs::create_dir_all(dest)?;
    restore_tree(tree_id, tree_salt, keys, store, dest, 0)
}

// ---- reachable closure (push set / retention, §15) ----

/// All object ids reachable from `heads` (commits + parents + trees + chunks). Each commit in `heads`
/// and its own tree are **strict** — a missing object errors, because current content must be complete
/// — while an ancestor commit's content is **skip-missing**: history pruned beyond retention is simply
/// absent (§15/I5). Every present object is opened (§9.2-verified).
pub fn reachable_objects<K: MasterKeys>(
    keys: &K,
    store: &Store,
    heads: &[Id],
) -> Result<std::collections::BTreeSet<Id>, SnapError> {
    use std::collections::BTreeSet;
    let head_set: BTreeSet<Id> = heads.iter().copied().collect();
    let mut reachable: BTreeSet<Id> = BTreeSet::new();
    let mut commits_done: BTreeSet<Id> = BTreeSet::new();
    let mut work: Vec<Id> = heads.to_vec();

    while let Some(cid) = work.pop() {
        if !commits_done.insert(cid) {
            continue;
        }
        let is_head = head_set.contains(&cid);
        // A head commit must be present; a pruned ancestor commit is skipped (commits are kept, I4,
        // so this only fires on a genuinely truncated history).
        let blob = match store.get(&cid)? {
            Some(b) => b,
            None if is_head => return Err(SnapError::Missing(cid)),
            None => continue,
        };
        reachable.insert(cid);
        let (commit, _sig) =
            decode_signed_commit(&open_object(keys, ObjType::Commit, &ZERO_SALT, &cid, &blob)?)?;
        collect_tree(
            keys,
            store,
            &commit.root_tree,
            &commit.root_salt,
            0,
            &mut reachable,
            is_head,
        )?;
        for parent in commit.parents {
            work.push(parent);
        }
    }
    Ok(reachable)
}

fn collect_tree<K: MasterKeys>(
    keys: &K,
    store: &Store,
    tree_id: &Id,
    tree_salt: &PathSalt,
    depth: usize,
    reachable: &mut std::collections::BTreeSet<Id>,
    strict: bool,
) -> Result<(), SnapError> {
    if depth >= MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    if reachable.contains(tree_id) {
        return Ok(()); // shared subtree already walked
    }
    // A pruned tree is absent: under the head's own tree that is an error (current content must be
    // complete); under an ancestor it is skipped — its old content fell out of retention (§15/I5).
    let blob = match store.get(tree_id)? {
        Some(b) => b,
        None if strict => return Err(SnapError::Missing(*tree_id)),
        None => return Ok(()),
    };
    reachable.insert(*tree_id);
    let tree = decode_tree(&open_object(keys, ObjType::Tree, tree_salt, tree_id, &blob)?)?;
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
            } => collect_tree(keys, store, subtree, subtree_salt, depth + 1, reachable, strict)?,
        }
    }
    Ok(())
}

// ---- path resolution, single-path restore, and tree diff (§10 history: `secsec log` / `restore`) ----

/// A file or directory resolved at a path within a commit's tree (for `secsec log`/`restore`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathNode {
    /// A regular file: its content is the ordered `chunks` sealed under `path_salt` (§9.2).
    File {
        /// Unix mode bits.
        mode: u32,
        /// Modification time (advisory).
        mtime: u64,
        /// Plaintext size.
        size: u64,
        /// The file's path salt.
        path_salt: PathSalt,
        /// Ordered chunk ids — the file's content identity.
        chunks: Vec<Id>,
    },
    /// A directory: the subtree object id + its salt.
    Dir {
        /// Subtree content id.
        subtree: Id,
        /// Subtree path salt.
        subtree_salt: PathSalt,
    },
}

/// Split a slash-separated repo-relative path into clean components (dropping empty/`.` segments).
fn path_components(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect()
}

/// Resolve the slash-separated `path` (relative to `(root_tree, root_salt)`) to the file or directory
/// there, or `None` if any component is missing (or a non-final component is a file). An empty path
/// resolves to the root directory. Walks one tree level per component (re-verifying §9.2 on each).
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
        let Some(entry) = tree.entries.iter().find(|e| entry_name(e) == *comp) else {
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

/// The object ids needed to materialize `path` from `(root_tree, root_salt)`: the tree ids on the
/// spine from the root to `path`, plus — for a file — its chunk ids, or — for a directory — the full
/// closure under it. `None` if `path` does not resolve (or its spine has already been pruned). Used by
/// retention to keep one specific version's content (§15); skip-missing, so an already-pruned part is
/// simply not added.
pub fn path_content<K: MasterKeys>(
    keys: &K,
    store: &Store,
    root_tree: &Id,
    root_salt: &PathSalt,
    path: &str,
) -> Result<Option<std::collections::BTreeSet<Id>>, SnapError> {
    let mut content: std::collections::BTreeSet<Id> = std::collections::BTreeSet::new();
    content.insert(*root_tree);
    let comps = path_components(path);
    if comps.is_empty() {
        collect_tree(keys, store, root_tree, root_salt, 0, &mut content, false)?;
        return Ok(Some(content));
    }
    let (mut cur_tree, mut cur_salt) = (*root_tree, *root_salt);
    for (i, comp) in comps.iter().enumerate() {
        let tree = match load_tree(&cur_tree, &cur_salt, keys, store) {
            Ok(t) => t,
            Err(SnapError::Missing(_)) => return Ok(None), // this version's spine is already pruned
            Err(e) => return Err(e),
        };
        let Some(entry) = tree.entries.iter().find(|e| entry_name(e) == *comp) else {
            return Ok(None);
        };
        let last = i + 1 == comps.len();
        match entry {
            Entry::File { chunks, .. } => {
                if last {
                    content.extend(chunks.iter().copied());
                    return Ok(Some(content));
                }
                return Ok(None); // a non-final component is a file
            }
            Entry::Dir {
                subtree,
                subtree_salt,
                ..
            } => {
                content.insert(*subtree);
                if last {
                    collect_tree(keys, store, subtree, subtree_salt, 0, &mut content, false)?;
                    return Ok(Some(content));
                }
                cur_tree = *subtree;
                cur_salt = *subtree_salt;
            }
        }
    }
    Ok(None)
}

/// Restore the file or directory at `path` from `commit` into `dest_root` at the same relative
/// `path` — the read side of `secsec restore`. A file is materialized (parent dirs created, §9.2
/// verified, padding stripped); a directory is restored recursively. `PathNotFound` if the path did
/// not exist in that commit's tree. The caller then lets the normal sync commit + propagate it.
pub fn restore_path<K: MasterKeys>(
    keys: &K,
    store: &Store,
    commit: &Commit,
    path: &str,
    dest_root: &Path,
) -> Result<(), SnapError> {
    let node = match resolve_path(keys, store, &commit.root_tree, &commit.root_salt, path) {
        Ok(Some(n)) => n,
        Ok(None) => return Err(SnapError::PathNotFound(path.to_string())),
        Err(SnapError::Missing(_)) => {
            return Err(SnapError::PrunedBeyondRetention(path.to_string()))
        }
        Err(e) => return Err(e),
    };
    let target = dest_root.join(path);
    match node {
        PathNode::File {
            mode,
            mtime,
            size,
            path_salt,
            chunks,
        } => {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = std::fs::File::create(&target)?;
            let mut written: u64 = 0;
            for cid in &chunks {
                let padded = match fetch_open(keys, ObjType::Chunk, &path_salt, cid, store) {
                    Ok(b) => b,
                    Err(SnapError::Missing(_)) => {
                        return Err(SnapError::PrunedBeyondRetention(path.to_string()))
                    }
                    Err(e) => return Err(e),
                };
                let plain = unpad_chunk(&padded, Padding::PowerOfTwo)?;
                file.write_all(plain)?;
                written += plain.len() as u64;
            }
            if written != size {
                return Err(SnapError::Malformed("restored file size mismatch"));
            }
            apply_metadata(&target, mode, mtime)?;
        }
        PathNode::Dir {
            subtree,
            subtree_salt,
        } => {
            restore_tree_into(&subtree, &subtree_salt, keys, store, &target)?;
        }
    }
    Ok(())
}

/// The set of **file** paths whose content differs between `old` and `new` trees (each `(id, salt)`,
/// or `None` for an empty side — e.g. a commit with no parent). Slash-separated, sorted. Unchanged
/// subtrees are pruned by id equality, so this is cheap (it never descends into identical subtrees).
/// Used to summarize what a commit changed vs its parent (`secsec log`).
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

#[allow(clippy::too_many_arguments)]
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
    let load = |t: Option<(&Id, &PathSalt)>| -> Result<Vec<Entry>, SnapError> {
        match t {
            Some((id, salt)) => match load_tree(id, salt, keys, store) {
                Ok(tree) => Ok(tree.entries),
                // A tree pruned beyond retention is treated as an empty side, so `log` lists the commit
                // without a diff rather than erroring (§15).
                Err(SnapError::Missing(_)) => Ok(Vec::new()),
                Err(e) => Err(e),
            },
            None => Ok(Vec::new()),
        }
    };
    let old_entries = load(old)?;
    let new_entries = load(new)?;
    let by_name = |es: &[Entry]| -> std::collections::BTreeMap<String, Entry> {
        es.iter()
            .map(|e| (entry_name(e).to_string(), e.clone()))
            .collect()
    };
    let om = by_name(&old_entries);
    let nm = by_name(&new_entries);
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for k in om.keys().chain(nm.keys()) {
        names.insert(k.clone());
    }
    for name in &names {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        match (om.get(name), nm.get(name)) {
            (Some(Entry::File { chunks: oc, .. }), Some(Entry::File { chunks: nc, .. })) => {
                if oc != nc {
                    out.push(path);
                }
            }
            (
                Some(Entry::Dir {
                    subtree: os,
                    subtree_salt: oss,
                    ..
                }),
                Some(Entry::Dir {
                    subtree: ns,
                    subtree_salt: nss,
                    ..
                }),
            ) => {
                if os != ns {
                    diff_trees(
                        keys,
                        store,
                        Some((os, oss)),
                        Some((ns, nss)),
                        &path,
                        depth + 1,
                        out,
                    )?;
                }
            }
            // added / removed / type-changed: recurse into a present dir to list its files, else report.
            (o, n) => {
                let side = |e: Option<&Entry>| match e {
                    Some(Entry::Dir {
                        subtree,
                        subtree_salt,
                        ..
                    }) => Some((*subtree, *subtree_salt)),
                    _ => None,
                };
                match (side(o), side(n)) {
                    (od, nd) if od.is_some() || nd.is_some() => {
                        let oref = od.as_ref().map(|(i, s)| (i, s));
                        let nref = nd.as_ref().map(|(i, s)| (i, s));
                        diff_trees(keys, store, oref, nref, &path, depth + 1, out)?;
                    }
                    _ => out.push(path), // file added/removed, or file<->dir type change
                }
            }
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

    /// `secsec log`/`restore` cores: resolve a path, diff two snapshots for the changed file, and
    /// restore an old version of a file/folder over the current working copy.
    #[test]
    fn path_resolve_diff_and_restore() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let m = mk();

        // v1: a/x="one", a/y="two", b="three".
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("a")).unwrap();
        std::fs::write(src.path().join("a/x"), b"one").unwrap();
        std::fs::write(src.path().join("a/y"), b"two").unwrap();
        std::fs::write(src.path().join("b"), b"three").unwrap();
        let (rt1, rs1) = snapshot_tree(src.path(), &m, &store, None).unwrap();

        // resolve a file, a dir, and missing paths.
        let Some(PathNode::File { size, .. }) =
            resolve_path(&m, &store, &rt1, &rs1, "a/x").unwrap()
        else {
            panic!("a/x is a file")
        };
        assert_eq!(size, 3);
        assert!(matches!(
            resolve_path(&m, &store, &rt1, &rs1, "a").unwrap(),
            Some(PathNode::Dir { .. })
        ));
        assert!(resolve_path(&m, &store, &rt1, &rs1, "nope")
            .unwrap()
            .is_none());
        assert!(resolve_path(&m, &store, &rt1, &rs1, "a/nope")
            .unwrap()
            .is_none());

        // v2: change only a/x.
        std::fs::write(src.path().join("a/x"), b"ONE-modified").unwrap();
        let (rt2, rs2) = snapshot_tree(src.path(), &m, &store, Some((&rt1, &rs1))).unwrap();
        assert_eq!(
            changed_paths(&m, &store, Some((&rt1, &rs1)), Some((&rt2, &rs2))).unwrap(),
            vec!["a/x".to_string()],
            "only a/x changed between the two snapshots"
        );

        // restore the OLD a/x (v1) over the current (v2) working copy.
        let c1 = Commit {
            root_tree: rt1,
            root_salt: rs1,
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
        restore_path(&m, &store, &c1, "a/x", work.path()).unwrap();
        assert_eq!(std::fs::read(work.path().join("a/x")).unwrap(), b"one");

        // restore a whole folder (a/) from v1 — both files come back.
        std::fs::remove_dir_all(work.path().join("a")).unwrap();
        restore_path(&m, &store, &c1, "a", work.path()).unwrap();
        assert_eq!(std::fs::read(work.path().join("a/x")).unwrap(), b"one");
        assert_eq!(std::fs::read(work.path().join("a/y")).unwrap(), b"two");

        // a path that never existed errors clearly.
        assert!(matches!(
            restore_path(&m, &store, &c1, "nope", work.path()),
            Err(SnapError::PathNotFound(_))
        ));
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
        // the stored commit object is the signed form (fields ‖ sig); round-trips through the codec.
        let (got, sig) =
            decode_signed_commit(&encode_signed_commit(&commit, b"sig-bytes")).unwrap();
        assert_eq!(got, commit);
        assert_eq!(sig, b"sig-bytes");
    }

    /// Path-traversal guard (§9.2/§18): `decode_tree` MUST reject a tree entry whose name could escape
    /// the synced folder on restore. `encode_tree` happily serializes any name (a malicious member
    /// authors the bytes), so the decode-side check is the security boundary.
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
            "tab\there", // control characters are rejected (terminal-escape / cross-platform safety)
            "bell\x07",
            "esc\x1b[2J",
            "del\x7f",
        ] {
            assert!(
                matches!(
                    decode_tree(&encode_tree(&one(bad))),
                    Err(SnapError::Malformed(_))
                ),
                "name {bad:?} must be rejected as an unsafe tree entry name"
            );
        }
        // a benign single-component name still decodes.
        assert!(decode_tree(&encode_tree(&one("ok.txt"))).is_ok());
    }

    /// Restore hardening (§18): setuid / setgid / sticky bits in a member-authored tree are stripped —
    /// only the 9 standard permission bits are applied, so a compromised member cannot plant a
    /// setgid/setuid file on every device.
    #[cfg(unix)]
    #[test]
    fn restore_strips_setuid_setgid_sticky() {
        use std::os::unix::fs::PermissionsExt;
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let m = mk();
        // A hand-built tree entry carrying setuid+setgid+sticky (0o7000) plus rwxr-xr-x.
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
        let (id, salt) = seal_tree(&tree, &m, &store).unwrap();
        let dst = tempfile::tempdir().unwrap();
        restore_tree_into(&id, &salt, &m, &store, dst.path()).unwrap();
        let mode = std::fs::metadata(dst.path().join("x"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7000, 0, "setuid/setgid/sticky must be stripped");
        assert_eq!(mode & 0o0777, 0o0755, "standard permission bits preserved");
    }

    /// Canonical ordering (§9.3 "no duplicate keys", deterministic order): `decode_tree` MUST reject
    /// entries that are not strictly ascending by name (out-of-order or duplicate). `snapshot_dir`
    /// only ever emits sorted, unique names, so anything else is a malformed/forged tree.
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
        // out of order ("b" before "a").
        let unsorted = Tree {
            entries: vec![file("b"), file("a")],
        };
        assert!(matches!(
            decode_tree(&encode_tree(&unsorted)),
            Err(SnapError::Malformed(_))
        ));
        // duplicate name.
        let dup = Tree {
            entries: vec![file("a"), file("a")],
        };
        assert!(matches!(
            decode_tree(&encode_tree(&dup)),
            Err(SnapError::Malformed(_))
        ));
        // strictly ascending is accepted.
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

        let (root_tree, root_salt) = snapshot_tree(src.path(), &m, &store, None).unwrap();
        restore_tree_into(&root_tree, &root_salt, &m, &store, dst.path()).unwrap();

        // restore→snapshot idempotence: identical root id (mtimes/modes preserved), else every
        // post-clone sync would author a spurious commit.
        let (resnap, _) =
            snapshot_tree(dst.path(), &m, &store, Some((&root_tree, &root_salt))).unwrap();
        assert_eq!(resnap, root_tree, "restore→snapshot must be idempotent");

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

        let commit_id = test_signed_commit(src.path(), &m, &store);
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
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let m = mk();
        std::fs::write(src.path().join("f"), b"data").unwrap();
        let commit_id = test_signed_commit(src.path(), &m, &store);

        // Reading the commit against a *fresh empty* store must fail (object missing), not panic.
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = Store::open(empty_dir.path().join("e.redb")).unwrap();
        assert!(matches!(
            open_signed_commit(&commit_id, &m, &empty),
            Err(SnapError::Missing(_))
        ));
    }

    /// §8.2 cross-rotation reads: a history whose parent commit predates a rotation is reachable and
    /// restorable with the peeled key ring, but NOT with a single generation's key.
    #[test]
    fn reads_across_a_generation_boundary_with_a_key_ring() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let dev = secsec_sig::DeviceKey::generate().unwrap();
        let mk1 = MasterKey::new(1, [0x11; 32]);
        let mk2 = MasterKey::new(2, [0x22; 32]);

        // gen-1 commit C1 over a dir; gen-2 commit C2 (parent C1) over another, sealed under mk2.
        let src1 = tempfile::tempdir().unwrap();
        std::fs::write(src1.path().join("old.txt"), b"gen1 file").unwrap();
        let (rt1, rs1) = snapshot_tree(src1.path(), &mk1, &store, None).unwrap();
        let c1 = Commit {
            root_tree: rt1,
            root_salt: rs1,
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
        let (rt2, rs2) = snapshot_tree(src2.path(), &mk2, &store, None).unwrap();
        let c2 = Commit {
            root_tree: rt2,
            root_salt: rs2,
            parents: vec![c1_id],
            device_id: dev.device_id().unwrap(),
            version: 2,
            roster_seq: 0,
            last_seen_head: c1_id,
            ts: 0,
        };
        let c2_id = seal_signed_commit(&mk2, &store, &dev, &c2).unwrap();

        // A single-generation key cannot walk across the rotation boundary: traversing from C2 hits
        // C1 (gen 1) and fails to resolve its key.
        assert!(matches!(
            reachable_objects(&mk2, &store, &[c2_id]),
            Err(SnapError::Object(ObjError::UnknownGeneration(1)))
        ));

        // The peeled key ring {1: mk1, 2: mk2} reads the whole history and restores either commit.
        let keyring: std::collections::BTreeMap<u32, MasterKey> =
            [(1u32, mk1), (2u32, mk2)].into_iter().collect();
        let reachable = reachable_objects(&keyring, &store, &[c2_id]).unwrap();
        assert!(reachable.contains(&c1_id) && reachable.contains(&c2_id));

        let (got_c1, _) = open_signed_commit(&c1_id, &keyring, &store).unwrap();
        let dst = tempfile::tempdir().unwrap();
        restore_commit_tree(&got_c1, &keyring, &store, dst.path()).unwrap();
        assert_eq!(
            std::fs::read(dst.path().join("old.txt")).unwrap(),
            b"gen1 file"
        );
    }

    /// Snapshot `src` and seal a signed commit (a throwaway device) — the production commit form.
    fn test_signed_commit(src: &Path, m: &MasterKey, store: &Store) -> Id {
        let dev = secsec_sig::DeviceKey::generate().unwrap();
        let (root_tree, root_salt) = snapshot_tree(src, m, store, None).unwrap();
        let commit = Commit {
            root_tree,
            root_salt,
            parents: Vec::new(),
            device_id: dev.device_id().unwrap(),
            version: 1,
            roster_seq: 0,
            last_seen_head: [0u8; 32],
            ts: 0,
        };
        seal_signed_commit(m, store, &dev, &commit).unwrap()
    }

    /// A symlink (or special file) must not fail the whole snapshot — it is skipped, not synced. And on
    /// restore, an untracked symlink in the destination is left alone (snapshots never tracked it), while
    /// a tracked file that disappeared upstream is removed.
    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_and_untracked_ones_survive_restore() {
        use std::os::unix::fs::symlink;
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let m = mk();

        // Source: a real file plus a symlink — the snapshot must succeed and track only the file.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("real.txt"), b"data").unwrap();
        symlink("real.txt", src.path().join("link")).unwrap();
        let (rt, rs) = snapshot_tree(src.path(), &m, &store, None).unwrap();
        let tree = load_tree(&rt, &rs, &m, &store).unwrap();
        let names: Vec<&str> = tree.entries.iter().map(entry_name).collect();
        assert_eq!(
            names,
            vec!["real.txt"],
            "the symlink is skipped, the file is tracked"
        );

        // Destination already holds its own untracked symlink and a now-deleted-upstream file.
        let dst = tempfile::tempdir().unwrap();
        std::fs::write(dst.path().join("stale.txt"), b"old").unwrap();
        symlink("/nonexistent-target", dst.path().join("mylink")).unwrap();
        restore_tree_into(&rt, &rs, &m, &store, dst.path()).unwrap();

        assert_eq!(std::fs::read(dst.path().join("real.txt")).unwrap(), b"data");
        assert!(
            !dst.path().join("stale.txt").exists(),
            "a tracked file gone upstream is removed on restore"
        );
        assert!(
            std::fs::symlink_metadata(dst.path().join("mylink")).is_ok(),
            "an untracked symlink in the destination is preserved (never secsec's to delete)"
        );
    }

    /// The mtime/size fast-path: re-snapshotting an unchanged file under a NEW generation reuses its
    /// prior chunk ids verbatim (they address the old generation; cross-generation reads are legal,
    /// §8.2), so a key rotation does not re-store the working set's chunks.
    #[test]
    fn unchanged_file_reuses_chunk_ids_across_a_rotation() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().join("s.redb")).unwrap();
        let mk1 = MasterKey::new(1, [0x11; 32]);
        let mk2 = MasterKey::new(2, [0x22; 32]);

        let src = tempfile::tempdir().unwrap();
        let mut big = vec![0u8; 400 * 1024]; // multi-chunk so there are real ids to compare
        getrandom::fill(&mut big).unwrap();
        std::fs::write(src.path().join("f.bin"), &big).unwrap();

        let file_chunks = |id: &Id, salt: &PathSalt, mk: &MasterKey| -> Vec<Id> {
            let Entry::File { chunks, .. } = load_tree(id, salt, mk, &store)
                .unwrap()
                .entries
                .into_iter()
                .find(|e| entry_name(e) == "f.bin")
                .unwrap()
            else {
                panic!("f.bin must be a file")
            };
            chunks
        };

        let (rt1, rs1) = snapshot_tree(src.path(), &mk1, &store, None).unwrap();
        let ch1 = file_chunks(&rt1, &rs1, &mk1);

        // Re-snapshot the UNCHANGED dir under generation 2, reading the prior tree through the key ring
        // {1, 2}; the mtime/size fast-path reuses the gen-1 chunk ids (the new tree object is re-sealed
        // under gen 2, but the bulk chunk content is not).
        let ring: BTreeMap<u32, MasterKey> = [
            (1u32, MasterKey::new(1, [0x11; 32])),
            (2u32, MasterKey::new(2, [0x22; 32])),
        ]
        .into_iter()
        .collect();
        let (rt2, rs2) = snapshot_tree(src.path(), &ring, &store, Some((&rt1, &rs1))).unwrap();
        let ch2 = file_chunks(&rt2, &rs2, &mk2);
        assert_eq!(
            ch1, ch2,
            "an unchanged file keeps its chunk ids across a rotation"
        );
    }
}
