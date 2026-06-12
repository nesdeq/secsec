//! `secsec-snapshot` — the object graph and directory snapshot/restore (`secsec-Design.md` §6, §9.2).
//!
//! A snapshot is a `Commit` pointing at a root `Tree`; trees list files (chunk-id lists) and
//! subtrees, content-addressed via [`secsec_object`]. [`snapshot_tree`] walks a directory, chunks
//! files with keyed FastCDC, and seals every chunk/tree, `put`ting them to a [`Store`];
//! [`seal_signed_commit`] wraps the root tree in an SSHSIG-signed `Commit` (§6, §9.6 — commits are
//! **always** signed). On the read side [`open_signed_commit`] fetches+verifies a commit and
//! [`restore_commit_tree`] / [`restore_tree_into`] walk the tree back, `get`ting each object, opening
//! it with full verification (§9.2 three-way check), un-padding, and rebuilding the directory
//! byte-for-byte.
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
use secsec_kdf::{MasterKey, MasterKeys};
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
    /// A file name was not valid UTF-8.
    NonUtf8Name,
    /// OS RNG failure.
    Rng,
    /// Commit signature invalid, or the signer is not the commit's author (§9.6).
    BadSignature,
    /// A requested path did not exist in the tree being resolved (`secsec log`/`restore`).
    PathNotFound(String),
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

/// Reject a tree entry name that could escape the synced folder on restore (§9.2/§18). A name MUST be
/// a single, non-empty path component: never empty, `.`/`..`, or containing a path separator (`/`,
/// `\`) or a NUL byte. `restore_tree`/`restore_path` join these names onto a destination directory, so
/// an unchecked `..` or `/etc/...` (which `Path::join` resolves as an escape/absolute replacement)
/// would let a malicious member's tree write arbitrary files outside the synced folder. Trees are
/// keyed-hash content-addressed (a blind server cannot forge one), but a compromised/stolen member
/// (§3) can author such a tree, so the guard is enforced here at decode for every restore path.
fn validate_entry_name(name: &str) -> Result<(), SnapError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
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
        // Path-traversal guard (above) + canonical ordering (§9.3): entries MUST be strictly
        // ascending by name, which also forbids duplicate names ("no duplicate keys"). `snapshot_dir`
        // emits sorted, unique names, so an out-of-order or duplicate entry is a malformed/forged tree.
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
pub fn open_signed_commit<K: MasterKeys>(
    commit_id: &Id,
    keys: &K,
    store: &Store,
) -> Result<(Commit, Vec<u8>), SnapError> {
    // `fetch_open` resolves the commit's own generation (§8.2): a single `&MasterKey` resolves only
    // its generation (no-rotation case); a peeled key ring resolves any past generation.
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

fn snapshot_dir(
    dir: &Path,
    mk: &MasterKey,
    store: &Store,
    chunker: &secsec_chunk::Chunker,
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
        }
        // Anything else — a symlink, FIFO, socket, or device node — is **skipped**, not synced (the
        // object model is regular files + directories only, §6). A single unsupported entry must not
        // fail the whole snapshot; restore leaves any such on-disk entry on peers untouched.
    }

    let tree = Tree { entries };
    let (id, blob) = seal_object(mk, ObjType::Tree, &this_salt, &encode_tree(&tree));
    store.put(&id, &blob)?;
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
    // `open_object` resolves this object's authenticated generation against `keys` (§8.2): a single
    // `&MasterKey` resolves only its own generation; a peeled key ring resolves any.
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

    // Reconcile the directory **to** the tree: remove any on-disk child whose name is not a tree
    // entry. Without this, restore is additive — a file deleted upstream is never removed, and the
    // next snapshot re-adds it (a deletion that silently resurrects). Symlinks and special files are
    // **not tracked** by snapshots (they are skipped), so they are left untouched here — only the
    // regular files and real directories secsec actually syncs are reconciled.
    let keep: std::collections::BTreeSet<&str> = tree.entries.iter().map(entry_name).collect();
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let on_disk = ent.file_name();
        // A non-UTF-8 on-disk name can never be a (UTF-8) tree entry, so it is an extra.
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
                let mut data = Vec::new();
                for cid in chunks {
                    let padded = fetch_open(keys, ObjType::Chunk, path_salt, cid, store)?;
                    data.extend_from_slice(unpad_chunk(&padded, Padding::PowerOfTwo)?);
                }
                if data.len() as u64 != *size {
                    return Err(SnapError::Malformed("restored file size mismatch"));
                }
                let path = dir.join(name);
                // Clear anything at this path that is not already a regular file: a directory (upstream
                // type-changed dir→file) is removed recursively, and a **symlink** is unlinked rather
                // than followed — otherwise `write` would dereference the link and clobber its target
                // outside the synced folder.
                clear_for_regular_file(&path)?;
                std::fs::write(&path, &data)?;
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
                // A name that was a file/symlink upstream but is now a directory: remove it (a symlink
                // as a link, never followed) so `create_dir_all` inside the recursion can take its place.
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

/// Remove an on-disk path that is not in the restored tree (a deletion to apply). Only the kinds
/// secsec tracks are removed: a regular **file** is unlinked and a real **directory** is removed
/// recursively. A **symlink** or special file (FIFO/socket/device) is left untouched — snapshots skip
/// those, so they were never synced and are not secsec's to delete (and a symlink is never traversed).
fn remove_extra(path: &Path) -> Result<(), SnapError> {
    let ft = std::fs::symlink_metadata(path)?.file_type();
    if ft.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else if ft.is_file() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Ensure `path` is free for writing a regular file: a real directory is removed recursively; a
/// symlink or special file is unlinked (never followed). A path that is already a regular file, or
/// absent, is left for `write` to overwrite/create.
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

/// Reproduce a tree entry's recorded `mode` (Unix perms) and `mtime` on the restored path, so that a
/// snapshot → restore → snapshot round trip is **idempotent** (the tree id is content-addressed and
/// includes mtime/mode, §6; if restore dropped them, every post-clone sync would see a phantom change
/// and author a spurious commit). `mtime` is whole seconds (matching the snapshot's precision).
fn apply_metadata(path: &Path, mode: u32, mtime: u64) -> Result<(), SnapError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if mode != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))?;
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    // `mtime` is attacker-influenced (decoded from a member-authored tree); saturate at i64::MAX so a
    // hostile value cannot wrap to a negative (pre-1970) time, which would break snapshot→restore
    // idempotence (re-snapshot reads back the OS-clamped value, not the stored one) and spuriously
    // re-commit. Snapshots only ever record real file mtimes, so this never affects honest data.
    let secs = i64::try_from(mtime).unwrap_or(i64::MAX);
    filetime::set_file_mtime(path, filetime::FileTime::from_unix_time(secs, 0))?;
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

// ---- reachable closure (GC keep-set, §15) ----

/// The full set of object ids reachable from `heads` (commit ids): each head, its transitive commit
/// parents, every tree/subtree, and every chunk (§15 keep-set). Each commit/tree is fetched, opened
/// (so §9.2 content-addressing is re-verified), and decoded; a **missing** object anywhere in the
/// closure returns [`SnapError::Missing`] so GC **fails safe** (never deletes when the keep-set is
/// incomplete, §15). The caller hashes the result with `secsec_proto::gc::keep_set_hash`.
pub fn reachable_objects<K: MasterKeys>(
    keys: &K,
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
        // A chain that spans a rotation has parents under older generations; `fetch_open`/`collect_tree`
        // resolve each object's generation against `keys` (§8.2). A single-generation member resolves
        // to its own key throughout.
        let (commit, _sig) =
            decode_signed_commit(&fetch_open(keys, ObjType::Commit, &ZERO_SALT, &cid, store)?)?;
        collect_tree(
            keys,
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

fn collect_tree<K: MasterKeys>(
    keys: &K,
    store: &Store,
    tree_id: &Id,
    tree_salt: &PathSalt,
    depth: usize,
    reachable: &mut std::collections::BTreeSet<Id>,
) -> Result<(), SnapError> {
    if depth >= MAX_TREE_DEPTH {
        return Err(SnapError::DepthExceeded);
    }
    if !reachable.insert(*tree_id) {
        return Ok(()); // shared subtree already walked
    }
    let tree = decode_tree(&fetch_open(keys, ObjType::Tree, tree_salt, tree_id, store)?)?;
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
            } => collect_tree(keys, store, subtree, subtree_salt, depth + 1, reachable)?,
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
    let node = resolve_path(keys, store, &commit.root_tree, &commit.root_salt, path)?
        .ok_or_else(|| SnapError::PathNotFound(path.to_string()))?;
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
            let mut data = Vec::new();
            for cid in &chunks {
                let padded = fetch_open(keys, ObjType::Chunk, &path_salt, cid, store)?;
                data.extend_from_slice(unpad_chunk(&padded, Padding::PowerOfTwo)?);
            }
            if data.len() as u64 != size {
                return Err(SnapError::Malformed("restored file size mismatch"));
            }
            std::fs::write(&target, &data)?;
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
            Some((id, salt)) => Ok(load_tree(id, salt, keys, store)?.entries),
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

        // restore→snapshot is idempotent: re-snapshotting the restored tree on top of the same base
        // yields the IDENTICAL root id (mtimes/modes preserved). Without it, a phantom mtime change
        // would make every post-clone sync author a spurious commit (the CommitReplay bug).
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
}
