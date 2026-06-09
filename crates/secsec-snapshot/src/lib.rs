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

fn encode_commit(c: &Commit) -> Vec<u8> {
    let mut w = Writer::new();
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
    w.finish()
}

fn decode_commit(bytes: &[u8]) -> Result<Commit, SnapError> {
    let mut r = Reader::new(bytes);
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
    r.finish()?;
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

/// Snapshot `root` into `store` under `mk`; returns the commit id. `ts` is the author-asserted
/// timestamp to record (advisory).
pub fn snapshot(root: &Path, mk: &MasterKey, store: &Store, ts: u64) -> Result<Id, SnapError> {
    let chunker = secsec_chunk::Chunker::with_defaults(&mk.cdc_seed());
    let (root_tree, root_salt) = snapshot_dir(root, mk, store, &chunker, 0)?;
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

fn snapshot_dir(
    dir: &Path,
    mk: &MasterKey,
    store: &Store,
    chunker: &secsec_chunk::Chunker,
    depth: usize,
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
        if ft.is_file() {
            let data = std::fs::read(&path)?;
            let path_salt = random_salt()?;
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
            let (subtree, subtree_salt) = snapshot_dir(&path, mk, store, chunker, depth + 1)?;
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
    let salt = random_salt()?;
    let (id, blob) = seal_object(mk, ObjType::Tree, &salt, &encode_tree(&tree));
    store.put(&id, &blob)?;
    Ok((id, salt))
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
