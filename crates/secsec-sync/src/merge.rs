//! Per-path three-way merge (`secsec-Design.md` §10), storage-free over in-memory [`Node`] trees.
//! One-sided or identical change → take; genuine divergence → **keep-both conflict**
//! (`name.conflict-<label>.ext`); divergent directories merge recursively. Equality is by content
//! (chunk lists), never timestamps. The rollback gates live in [`crate::rollback`].

use std::collections::BTreeMap;

/// A 256-bit chunk content-address (§9.2).
pub type Id = [u8; 32];

/// A 16-byte per-path salt (§9.2/§9.7).
pub type PathSalt = [u8; 16];

/// An in-memory file-tree node. A directory maps child name → node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A regular file: its content is the ordered `chunks` (metadata is advisory, never trusted).
    File {
        /// Unix mode bits.
        mode: u32,
        /// Modification time (advisory; not used for merge equality).
        mtime: u64,
        /// Plaintext size.
        size: u64,
        /// The salt the `chunks` were sealed under (needed to re-verify on restore, §9.2); rides
        /// along, never part of merge equality.
        path_salt: PathSalt,
        /// Ordered chunk ids — the file's content identity.
        chunks: Vec<Id>,
    },
    /// A directory. `mode`/`mtime` are advisory (preserved through merge so re-sealing keeps subdir
    /// permissions; never compared for equality). Identity is the `children` map.
    Dir {
        /// Unix mode bits.
        mode: u32,
        /// Modification time (advisory; not used for merge equality).
        mtime: u64,
        /// Child name → child node.
        children: BTreeMap<String, Node>,
    },
}

/// Why a path conflicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    /// Both sides modified the same file differently.
    ModifyModify,
    /// One side modified, the other deleted.
    ModifyDelete,
    /// Both sides added the same name with different content (no base).
    AddAdd,
    /// The path is a file on one side and a directory on the other.
    TypeChange,
}

/// A reported conflict at `path` (slash-separated from the merge root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// Slash-separated path from the merge root.
    pub path: String,
    /// What kind of divergence it was.
    pub kind: ConflictKind,
}

/// The result of a three-way merge: the merged directory and any conflicts (keep-both already
/// applied to `tree`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merge {
    /// The merged directory (name → node).
    pub tree: BTreeMap<String, Node>,
    /// Conflicts encountered, in path order.
    pub conflicts: Vec<Conflict>,
}

/// Content equality (§10: timestamps are hints, never trusted). Files are equal iff their chunk
/// lists match; directories iff they have the same children, recursively equal by content.
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

/// Insert `.conflict-<label>` before the final extension: `notes.md` → `notes.conflict-<label>.md`;
/// `LICENSE` → `LICENSE.conflict-<label>` (§10 keep-both naming; the uniqueness-bearing label is the
/// caller's `<device>-<commit_id_hex12>`).
fn conflict_name(name: &str, label: &str) -> String {
    match name.rsplit_once('.') {
        // Don't treat a leading dot (dotfile, empty stem) as an extension separator.
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}.conflict-{label}.{ext}"),
        _ => format!("{name}.conflict-{label}"),
    }
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

/// Three-way merge of two directories against their common ancestor `base`. `their_label` is the
/// keep-both suffix for the incoming side (`<device>-<commit_id_hex12>`, §10). The merge root path is
/// empty; nested conflicts carry their full slash-path.
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
    // Union of names across all three sides, sorted (BTreeSet-style via BTreeMap keys).
    let mut names: BTreeMap<&String, ()> = BTreeMap::new();
    for k in base.keys().chain(ours.keys()).chain(theirs.keys()) {
        names.insert(k, ());
    }

    for name in names.keys().copied() {
        let path = join(prefix, name);
        let (b, o, t) = (base.get(name), ours.get(name), theirs.get(name));

        // Identical on both sides (incl. both absent), or one side unchanged: take, no conflict.
        if same_opt(o, t) || same_opt(t, b) {
            if let Some(node) = o {
                out.tree.insert(name.clone(), node.clone());
            }
            continue;
        }
        if same_opt(o, b) {
            if let Some(node) = t {
                out.tree.insert(name.clone(), node.clone());
            }
            continue;
        }

        // Genuine divergence.
        match (o, t) {
            // Two diverged directories merge recursively — never a conflict on the dir itself. The
            // merged dir keeps ours's advisory mode/mtime (deterministic; metadata, not content).
            (
                Some(Node::Dir {
                    mode: omode,
                    mtime: omtime,
                    children: od,
                }),
                Some(Node::Dir { children: td, .. }),
            ) => {
                let bd = match b {
                    Some(Node::Dir { children, .. }) => children.clone(),
                    _ => BTreeMap::new(), // base absent or a file: merge against empty
                };
                let mut sub = Merge {
                    tree: BTreeMap::new(),
                    conflicts: Vec::new(),
                };
                merge_dir(&path, &bd, od, td, their_label, &mut sub);
                out.tree.insert(
                    name.clone(),
                    Node::Dir {
                        mode: *omode,
                        mtime: *omtime,
                        children: sub.tree,
                    },
                );
                out.conflicts.extend(sub.conflicts);
            }
            // Everything else diverging is a keep-both conflict (no data loss).
            _ => {
                let kind = classify(b, o, t);
                if let Some(node) = o {
                    out.tree.insert(name.clone(), node.clone());
                }
                if let Some(node) = t {
                    out.tree
                        .insert(conflict_name(name, their_label), node.clone());
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
        Node::File {
            mode: 0o644,
            mtime: 0,
            size: 1,
            path_salt: [0u8; 16],
            chunks: vec![[byte; 32]],
        }
    }
    /// Same content as `file(byte)` but a different mtime AND path_salt — must NOT be a conflict
    /// (§10: equality is by chunk list alone; salt/mtime ride along but don't gate the merge).
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
        Node::Dir {
            mode: 0o755,
            mtime: 0,
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
        let b = map(&[("a", file(1))]);
        let m = three_way_merge(&b, &b, &b, "x");
        assert_eq!(m.tree, b);
        assert!(m.conflicts.is_empty());
    }

    #[test]
    fn one_sided_add_and_modify_taken() {
        let base = map(&[("keep", file(1))]);
        let ours = map(&[("keep", file(1)), ("new", file(2))]); // we added "new"
        let theirs = map(&[("keep", file(9))]); // they modified "keep"
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
        let theirs = map(&[("a", file_touched(5))]); // same chunks, different mtime
        let m = three_way_merge(&base, &ours, &theirs, "x");
        assert!(
            m.conflicts.is_empty(),
            "content-equal files must not conflict"
        );
        assert_eq!(m.tree.get("a"), Some(&file(5)));
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
        // ours keeps the name; theirs renamed; both retained (no data loss).
        assert_eq!(m.tree.get("a"), Some(&file(2)));
        assert_eq!(m.tree.get("a.conflict-devB-abc123"), Some(&file(3)));
    }

    #[test]
    fn modify_delete_keeps_modified_and_flags() {
        let base = map(&[("a", file(1))]);
        let ours = map(&[("a", file(2))]); // modified
        let theirs = map(&[]); // deleted
        let m = three_way_merge(&base, &ours, &theirs, "x");
        assert_eq!(
            m.conflicts.first().unwrap().kind,
            ConflictKind::ModifyDelete
        );
        assert_eq!(m.tree.get("a"), Some(&file(2))); // modification preserved
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
        let ours = map(&[("a", file(2))]); // still a file, modified
        let theirs = map(&[("a", dir(&[("inner", file(7))]))]); // became a dir
        let m = three_way_merge(&base, &ours, &theirs, "L");
        assert_eq!(m.conflicts.first().unwrap().kind, ConflictKind::TypeChange);
        assert_eq!(m.tree.get("a"), Some(&file(2)));
        assert!(matches!(m.tree.get("a.conflict-L"), Some(Node::Dir { .. })));
    }

    #[test]
    fn divergent_directories_merge_recursively() {
        // both sides changed *different* files inside dir "d" -> merge, no conflict.
        let base = dir_map_base();
        let ours = map(&[("d", dir(&[("x", file(2)), ("y", file(1))]))]); // changed x
        let theirs = map(&[("d", dir(&[("x", file(1)), ("y", file(3))]))]); // changed y
        let m = three_way_merge(&base, &ours, &theirs, "L");
        assert!(
            m.conflicts.is_empty(),
            "non-overlapping dir edits must merge"
        );
        assert_eq!(
            m.tree.get("d"),
            Some(&dir(&[("x", file(2)), ("y", file(3))]))
        );
    }

    #[test]
    fn divergent_directories_surface_inner_conflict_with_full_path() {
        let base = dir_map_base();
        let ours = map(&[("d", dir(&[("x", file(2)), ("y", file(1))]))]); // x -> 2
        let theirs = map(&[("d", dir(&[("x", file(8)), ("y", file(1))]))]); // x -> 8
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

    fn dir_map_base() -> BTreeMap<String, Node> {
        map(&[("d", dir(&[("x", file(1)), ("y", file(1))]))])
    }

    #[test]
    fn conflict_name_extension_handling() {
        assert_eq!(conflict_name("notes.md", "L"), "notes.conflict-L.md");
        assert_eq!(conflict_name("LICENSE", "L"), "LICENSE.conflict-L");
        assert_eq!(conflict_name(".bashrc", "L"), ".bashrc.conflict-L"); // dotfile, no stem
        assert_eq!(conflict_name("a.tar.gz", "L"), "a.tar.conflict-L.gz");
    }
}
