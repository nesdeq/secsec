//! Per-path three-way merge over in-memory [`Node`] trees (`secsec-Design.md` §10): content by chunk lists, modes merged three ways, divergence kept both.

use secsec_frame::MAX_NAME_LEN;
use std::collections::{BTreeMap, BTreeSet};

/// A 256-bit chunk content-address (§9.2).
pub type Id = [u8; 32];

/// A 16-byte per-path salt (§9.2/§9.7).
pub type PathSalt = [u8; 16];

/// An in-memory file-tree node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A regular file: content is the ordered `chunks`; mtime is advisory.
    File {
        /// Unix permission bits.
        mode: u32,
        /// Modification time (advisory).
        mtime: u64,
        /// Plaintext size.
        size: u64,
        /// The salt `chunks` were sealed under (§9.2); rides along, never compared.
        path_salt: PathSalt,
        /// Ordered chunk ids: the file's content identity.
        chunks: Vec<Id>,
    },
    /// A directory whose identity is its `children`.
    Dir {
        /// Unix permission bits.
        mode: u32,
        /// Modification time (advisory).
        mtime: u64,
        /// The salt this directory's tree is sealed under, reused so a merge re-seals deterministically.
        salt: PathSalt,
        /// Child name → child node.
        children: BTreeMap<String, Node>,
    },
}

impl Node {
    fn mode(&self) -> u32 {
        match self {
            Node::File { mode, .. } | Node::Dir { mode, .. } => *mode,
        }
    }

    fn with_mode(&self, mode: u32) -> Node {
        let mut n = self.clone();
        match &mut n {
            Node::File { mode: m, .. } | Node::Dir { mode: m, .. } => *m = mode,
        }
        n
    }
}

/// Why a path conflicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    /// Both sides modified the same file differently.
    ModifyModify,
    /// One side modified, the other deleted.
    ModifyDelete,
    /// Both sides added the same name with different content.
    AddAdd,
    /// A file on one side and a directory on the other.
    TypeChange,
}

/// A conflict at a slash-separated `path` from the merge root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// Slash-separated path from the merge root.
    pub path: String,
    /// What kind of divergence it was.
    pub kind: ConflictKind,
}

/// A merged directory with keep-both already applied, plus the conflicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merge {
    /// The merged directory.
    pub tree: BTreeMap<String, Node>,
    /// Conflicts, in path order.
    pub conflicts: Vec<Conflict>,
}

/// Content equality (§10): files by chunk list, directories by children, never by metadata.
fn same_content(a: &Node, b: &Node) -> bool {
    match (a, b) {
        (Node::File { chunks: x, .. }, Node::File { chunks: y, .. }) => x == y,
        (Node::Dir { children: x, .. }, Node::Dir { children: y, .. }) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| same_content(v, w)))
        }
        _ => false,
    }
}

fn same_opt(a: Option<&Node>, b: Option<&Node>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => same_content(x, y),
        _ => false,
    }
}

/// Three-way pick: a one-sided change wins, a two-sided divergence keeps ours.
fn pick3(base: Option<u32>, ours: u32, theirs: u32) -> u32 {
    if ours == theirs || base != Some(ours) {
        ours
    } else {
        theirs
    }
}

/// `name.conflict-<label>.ext` (or `name.conflict-<label>`), the stem truncated so the name fits [`MAX_NAME_LEN`].
fn conflict_name(name: &str, label: &str) -> String {
    let (stem, ext) = match name.rsplit_once('.') {
        // A leading dot (dotfile) is not an extension separator.
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (name, None),
    };
    let suffix = match ext {
        Some(ext) => format!(".conflict-{label}.{ext}"),
        None => format!(".conflict-{label}"),
    };
    if stem.len() + suffix.len() <= MAX_NAME_LEN {
        return format!("{stem}{suffix}");
    }
    let (base, suffix) = if suffix.len() < MAX_NAME_LEN {
        (stem, suffix)
    } else {
        (name, format!(".conflict-{label}"))
    };
    let mut cut = MAX_NAME_LEN.saturating_sub(suffix.len()).min(base.len());
    while !base.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{suffix}", &base[..cut])
}

/// A keep-both name colliding with nothing in play or already written; deterministic on every device.
fn free_conflict_name(
    name: &str,
    label: &str,
    names: &BTreeSet<&str>,
    out: &BTreeMap<String, Node>,
) -> String {
    let mut candidate = conflict_name(name, label);
    let mut n = 2u32;
    while names.contains(candidate.as_str()) || out.contains_key(&candidate) {
        candidate = conflict_name(name, &format!("{label}-{n}"));
        n += 1;
    }
    candidate
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

/// Three-way merge of two directories against `base`; `their_label` (`<device>-<commit_id_hex12>`) names keep-both copies.
#[must_use]
pub fn three_way_merge(
    base: &BTreeMap<String, Node>,
    ours: &BTreeMap<String, Node>,
    theirs: &BTreeMap<String, Node>,
    their_label: &str,
) -> Merge {
    let mut out = Merge {
        tree: BTreeMap::new(),
        conflicts: Vec::new(),
    };
    merge_dir("", base, ours, theirs, their_label, &mut out);
    out
}

fn merge_dir(
    prefix: &str,
    base: &BTreeMap<String, Node>,
    ours: &BTreeMap<String, Node>,
    theirs: &BTreeMap<String, Node>,
    their_label: &str,
    out: &mut Merge,
) {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for k in base.keys().chain(ours.keys()).chain(theirs.keys()) {
        names.insert(k.as_str());
    }

    for &name in &names {
        let path = join(prefix, name);
        let (b, o, t) = (base.get(name), ours.get(name), theirs.get(name));
        let base_mode = b.map(Node::mode);

        match (o, t) {
            // Two directories always merge recursively, so a change deep in either side survives.
            (
                Some(Node::Dir {
                    mode: omode,
                    mtime: omtime,
                    salt,
                    children: od,
                }),
                Some(Node::Dir {
                    mode: tmode,
                    children: td,
                    ..
                }),
            ) => {
                let bd = match b {
                    Some(Node::Dir { children, .. }) => children.clone(),
                    _ => BTreeMap::new(),
                };
                let mut sub = Merge {
                    tree: BTreeMap::new(),
                    conflicts: Vec::new(),
                };
                merge_dir(&path, &bd, od, td, their_label, &mut sub);
                out.tree.insert(
                    name.to_string(),
                    Node::Dir {
                        mode: pick3(base_mode, *omode, *tmode),
                        mtime: *omtime,
                        salt: *salt,
                        children: sub.tree,
                    },
                );
                out.conflicts.extend(sub.conflicts);
            }
            _ if same_opt(o, t) || same_opt(t, b) => {
                if let Some(node) = o {
                    let mode = t.map_or(node.mode(), |t| pick3(base_mode, node.mode(), t.mode()));
                    out.tree.insert(name.to_string(), node.with_mode(mode));
                }
            }
            _ if same_opt(o, b) => {
                if let Some(node) = t {
                    let mode = o.map_or(node.mode(), |o| pick3(base_mode, o.mode(), node.mode()));
                    out.tree.insert(name.to_string(), node.with_mode(mode));
                }
            }
            // Genuine divergence: keep both, ours under the name (no data loss).
            _ => {
                let kind = classify(b, o, t);
                if let Some(node) = o {
                    out.tree.insert(name.to_string(), node.clone());
                }
                if let Some(node) = t {
                    let cname = free_conflict_name(name, their_label, &names, &out.tree);
                    out.tree.insert(cname, node.clone());
                }
                out.conflicts.push(Conflict { path, kind });
            }
        }
    }
}

fn classify(b: Option<&Node>, o: Option<&Node>, t: Option<&Node>) -> ConflictKind {
    let is_file = |n: Option<&Node>| matches!(n, Some(Node::File { .. }));
    let is_dir = |n: Option<&Node>| matches!(n, Some(Node::Dir { .. }));
    match (o, t) {
        (None, _) | (_, None) => ConflictKind::ModifyDelete,
        _ if (is_file(o) && is_dir(t)) || (is_dir(o) && is_file(t)) => ConflictKind::TypeChange,
        _ if b.is_none() => ConflictKind::AddAdd,
        _ => ConflictKind::ModifyModify,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(byte: u8) -> Node {
        file_mode(byte, 0o644)
    }
    fn file_mode(byte: u8, mode: u32) -> Node {
        Node::File {
            mode,
            mtime: 0,
            size: 1,
            path_salt: [0u8; 16],
            chunks: vec![[byte; 32]],
        }
    }
    /// Same content as `file(byte)`, different mtime and salt: never a conflict.
    fn file_touched(byte: u8) -> Node {
        Node::File {
            mode: 0o644,
            mtime: 999,
            size: 1,
            path_salt: [0xAB; 16],
            chunks: vec![[byte; 32]],
        }
    }
    fn dir(entries: &[(&str, Node)]) -> Node {
        dir_mode(entries, 0o755)
    }
    fn dir_mode(entries: &[(&str, Node)], mode: u32) -> Node {
        Node::Dir {
            mode,
            mtime: 0,
            salt: [0x5A; 16],
            children: entries
                .iter()
                .map(|(n, v)| ((*n).to_string(), v.clone()))
                .collect(),
        }
    }
    fn map(entries: &[(&str, Node)]) -> BTreeMap<String, Node> {
        entries
            .iter()
            .map(|(n, v)| ((*n).to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn no_changes_is_identity() {
        let b = map(&[("a", file(1)), ("d", dir(&[("x", file(2))]))]);
        let m = three_way_merge(&b, &b, &b, "x");
        assert_eq!(m.tree, b);
        assert!(m.conflicts.is_empty());
    }

    #[test]
    fn one_sided_add_and_modify_taken() {
        let base = map(&[("keep", file(1))]);
        let ours = map(&[("keep", file(1)), ("new", file(2))]);
        let theirs = map(&[("keep", file(9))]);
        let m = three_way_merge(&base, &ours, &theirs, "x");
        assert_eq!(m.conflicts, vec![]);
        assert_eq!(m.tree, map(&[("keep", file(9)), ("new", file(2))]));
    }

    #[test]
    fn identical_change_both_sides_no_conflict() {
        let base = map(&[("a", file(1))]);
        let same = map(&[("a", file(2))]);
        let m = three_way_merge(&base, &same, &same, "x");
        assert!(m.conflicts.is_empty());
        assert_eq!(m.tree, same);
    }

    #[test]
    fn mtime_only_difference_is_not_a_conflict() {
        let base = map(&[("a", file(1))]);
        let ours = map(&[("a", file(5))]);
        let theirs = map(&[("a", file_touched(5))]);
        let m = three_way_merge(&base, &ours, &theirs, "x");
        assert!(m.conflicts.is_empty());
        assert_eq!(m.tree.get("a"), Some(&file(5)));
    }

    /// A one-sided chmod survives the merge, including one deep inside an otherwise unchanged directory.
    #[test]
    fn one_sided_mode_change_is_kept() {
        let base = map(&[("a", file(1)), ("d", dir(&[("x", file(2))]))]);
        let ours = map(&[("a", file(1)), ("d", dir(&[("x", file(2))]))]);
        let theirs = map(&[
            ("a", file_mode(1, 0o755)),
            ("d", dir_mode(&[("x", file_mode(2, 0o600))], 0o700)),
        ]);
        let m = three_way_merge(&base, &ours, &theirs, "x");
        assert!(m.conflicts.is_empty());
        assert_eq!(m.tree.get("a"), Some(&file_mode(1, 0o755)));
        assert_eq!(
            m.tree.get("d"),
            Some(&dir_mode(&[("x", file_mode(2, 0o600))], 0o700))
        );
        // Ours changed content while theirs changed only the mode: both apply.
        let ours2 = map(&[("a", file(7)), ("d", dir(&[("x", file(2))]))]);
        let m2 = three_way_merge(&base, &ours2, &theirs, "x");
        assert_eq!(m2.tree.get("a"), Some(&file_mode(7, 0o755)));
    }

    #[test]
    fn modify_modify_keeps_both() {
        let base = map(&[("a", file(1))]);
        let ours = map(&[("a", file(2))]);
        let theirs = map(&[("a", file(3))]);
        let m = three_way_merge(&base, &ours, &theirs, "devB-abc123");
        assert_eq!(
            m.conflicts,
            vec![Conflict {
                path: "a".into(),
                kind: ConflictKind::ModifyModify
            }]
        );
        assert_eq!(m.tree.get("a"), Some(&file(2)));
        assert_eq!(m.tree.get("a.conflict-devB-abc123"), Some(&file(3)));
    }

    #[test]
    fn modify_delete_keeps_modified_and_flags() {
        let base = map(&[("a", file(1))]);
        let ours = map(&[("a", file(2))]);
        let theirs = map(&[]);
        let m = three_way_merge(&base, &ours, &theirs, "x");
        assert_eq!(
            m.conflicts.first().unwrap().kind,
            ConflictKind::ModifyDelete
        );
        assert_eq!(m.tree.get("a"), Some(&file(2)));
    }

    #[test]
    fn deletion_against_a_real_base_applies() {
        let base = map(&[("a", file(1)), ("d", dir(&[("x", file(2))]))]);
        let ours = map(&[("a", file(1)), ("d", dir(&[("x", file(2))]))]);
        let theirs = map(&[("d", dir(&[]))]);
        let m = three_way_merge(&base, &ours, &theirs, "x");
        assert!(m.conflicts.is_empty());
        assert_eq!(m.tree, map(&[("d", dir(&[]))]));
    }

    #[test]
    fn add_add_divergent_is_conflict() {
        let base = map(&[]);
        let ours = map(&[("a", file(2))]);
        let theirs = map(&[("a", file(3))]);
        let m = three_way_merge(&base, &ours, &theirs, "L");
        assert_eq!(m.conflicts.first().unwrap().kind, ConflictKind::AddAdd);
        assert_eq!(m.tree.get("a"), Some(&file(2)));
        assert_eq!(m.tree.get("a.conflict-L"), Some(&file(3)));
    }

    #[test]
    fn type_change_is_conflict_keep_both() {
        let base = map(&[("a", file(1))]);
        let ours = map(&[("a", file(2))]);
        let theirs = map(&[("a", dir(&[("inner", file(7))]))]);
        let m = three_way_merge(&base, &ours, &theirs, "L");
        assert_eq!(m.conflicts.first().unwrap().kind, ConflictKind::TypeChange);
        assert_eq!(m.tree.get("a"), Some(&file(2)));
        assert!(matches!(m.tree.get("a.conflict-L"), Some(Node::Dir { .. })));
    }

    #[test]
    fn divergent_directories_merge_recursively() {
        let base = map(&[("d", dir(&[("x", file(1)), ("y", file(1))]))]);
        let ours = map(&[("d", dir(&[("x", file(2)), ("y", file(1))]))]);
        let theirs = map(&[("d", dir(&[("x", file(1)), ("y", file(3))]))]);
        let m = three_way_merge(&base, &ours, &theirs, "L");
        assert!(m.conflicts.is_empty());
        assert_eq!(
            m.tree.get("d"),
            Some(&dir(&[("x", file(2)), ("y", file(3))]))
        );
    }

    #[test]
    fn divergent_directories_surface_inner_conflict_with_full_path() {
        let base = map(&[("d", dir(&[("x", file(1)), ("y", file(1))]))]);
        let ours = map(&[("d", dir(&[("x", file(2)), ("y", file(1))]))]);
        let theirs = map(&[("d", dir(&[("x", file(8)), ("y", file(1))]))]);
        let m = three_way_merge(&base, &ours, &theirs, "L");
        assert_eq!(
            m.conflicts,
            vec![Conflict {
                path: "d/x".into(),
                kind: ConflictKind::ModifyModify
            }]
        );
        let Some(Node::Dir { children: d, .. }) = m.tree.get("d") else {
            panic!("d must be a dir")
        };
        assert_eq!(d.get("x"), Some(&file(2)));
        assert_eq!(d.get("x.conflict-L"), Some(&file(8)));
    }

    /// A merged directory keeps ours' salt, so two devices merging the same states seal the same tree.
    #[test]
    fn merged_directory_keeps_its_salt() {
        let base = map(&[("d", dir(&[("x", file(1))]))]);
        let ours = map(&[("d", dir(&[("x", file(2))]))]);
        let theirs = map(&[("d", dir(&[("x", file(1)), ("y", file(3))]))]);
        let m = three_way_merge(&base, &ours, &theirs, "L");
        let Some(Node::Dir { salt, .. }) = m.tree.get("d") else {
            panic!("d must be a dir")
        };
        assert_eq!(*salt, [0x5A; 16]);
    }

    /// A real entry named like the keep-both copy is never overwritten by it.
    #[test]
    fn conflict_copy_never_overwrites_a_real_entry_of_that_name() {
        let base = map(&[("a.txt", file(1))]);
        let ours = map(&[("a.txt", file(2)), ("a.conflict-L.txt", file(8))]);
        let theirs = map(&[("a.txt", file(3))]);
        let m = three_way_merge(&base, &ours, &theirs, "L");
        assert_eq!(m.tree.get("a.txt"), Some(&file(2)));
        assert_eq!(m.tree.get("a.conflict-L.txt"), Some(&file(8)));
        assert_eq!(m.tree.get("a.conflict-L-2.txt"), Some(&file(3)));
    }

    #[test]
    fn conflict_name_extension_handling() {
        assert_eq!(conflict_name("notes.md", "L"), "notes.conflict-L.md");
        assert_eq!(conflict_name("LICENSE", "L"), "LICENSE.conflict-L");
        assert_eq!(conflict_name(".bashrc", "L"), ".bashrc.conflict-L");
        assert_eq!(conflict_name("a.tar.gz", "L"), "a.tar.conflict-L.gz");
    }

    /// A keep-both name never exceeds the decoder's name bound, even for a maximal or multibyte name.
    #[test]
    fn conflict_name_fits_the_name_bound() {
        let long = format!("{}.txt", "é".repeat(MAX_NAME_LEN / 2));
        let c = conflict_name(&long, "abcdef-123456789012");
        assert!(c.len() <= MAX_NAME_LEN);
        assert!(c.ends_with(".conflict-abcdef-123456789012.txt"));
        let huge_ext = format!("a.{}", "x".repeat(MAX_NAME_LEN - 2));
        let c2 = conflict_name(&huge_ext, "L");
        assert!(c2.len() <= MAX_NAME_LEN);
        assert!(c2.ends_with(".conflict-L"));
    }
}
