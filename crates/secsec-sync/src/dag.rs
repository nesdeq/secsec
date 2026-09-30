//! Commit-DAG ancestry for fork detection and merge bases (`secsec-Design.md` §10); traversals tolerate cycles.

use std::collections::{BTreeMap, BTreeSet};

/// A 256-bit commit content-address (§9.2).
pub type Id = [u8; 32];

/// The DAG as `commit id → parent ids`; a missing entry is a root.
pub type ParentMap = BTreeMap<Id, Vec<Id>>;

/// Every ancestor of the `starts`, including the starts themselves.
fn ancestors_of_all(parents: &ParentMap, starts: &[Id]) -> BTreeSet<Id> {
    let mut seen: BTreeSet<Id> = BTreeSet::new();
    let mut work: Vec<Id> = starts.to_vec();
    while let Some(c) = work.pop() {
        if !seen.insert(c) {
            continue;
        }
        if let Some(ps) = parents.get(&c) {
            work.extend(ps.iter().filter(|p| !seen.contains(*p)).copied());
        }
    }
    seen
}

/// Every ancestor of `start`, including `start`.
#[must_use]
pub(crate) fn ancestors(parents: &ParentMap, start: &Id) -> BTreeSet<Id> {
    ancestors_of_all(parents, &[*start])
}

/// Whether `ancestor` is an ancestor of, or equal to, `descendant`.
#[must_use]
pub fn is_ancestor(parents: &ParentMap, ancestor: &Id, descendant: &Id) -> bool {
    if ancestor == descendant {
        return true;
    }
    let mut seen: BTreeSet<Id> = BTreeSet::new();
    let mut work = vec![*descendant];
    while let Some(c) = work.pop() {
        if !seen.insert(c) {
            continue;
        }
        if let Some(ps) = parents.get(&c) {
            for p in ps {
                if p == ancestor {
                    return true;
                }
                if !seen.contains(p) {
                    work.push(*p);
                }
            }
        }
    }
    false
}

/// Whether `a` and `b` are DAG-incomparable (the §10 fork condition); equal commits are comparable.
#[cfg(test)]
#[must_use]
pub fn incomparable(parents: &ParentMap, a: &Id, b: &Id) -> bool {
    !is_ancestor(parents, a, b) && !is_ancestor(parents, b, a)
}

/// Commits reachable from `sibling` that are not in `ours`' history (all of them when `ours` is `None`).
#[must_use]
pub fn new_commits(parents: &ParentMap, ours: Option<&Id>, sibling: &Id) -> BTreeSet<Id> {
    let known = ours.map(|o| ancestors(parents, o)).unwrap_or_default();
    ancestors(parents, sibling)
        .into_iter()
        .filter(|c| !known.contains(c))
        .collect()
}

/// The lowest common ancestors of `a` and `b` (§10 merge base): common ancestors not below another, in O(V+E).
#[must_use]
pub fn lowest_common_ancestors(parents: &ParentMap, a: &Id, b: &Id) -> BTreeSet<Id> {
    let anc_a = ancestors(parents, a);
    let common: BTreeSet<Id> = ancestors(parents, b)
        .into_iter()
        .filter(|c| anc_a.contains(c))
        .collect();
    // The common set is ancestor-closed, so its proper ancestors are everything reachable from its parents.
    let parent_starts: Vec<Id> = common
        .iter()
        .filter_map(|c| parents.get(c))
        .flatten()
        .copied()
        .collect();
    let below = ancestors_of_all(parents, &parent_starts);
    common.into_iter().filter(|c| !below.contains(c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id {
        [n; 32]
    }

    /// Build a parent map from `(child, [parents])` pairs.
    fn dag(edges: &[(u8, &[u8])]) -> ParentMap {
        edges
            .iter()
            .map(|(c, ps)| (id(*c), ps.iter().map(|p| id(*p)).collect()))
            .collect()
    }

    #[test]
    fn linear_chain() {
        let g = dag(&[(2, &[1]), (3, &[2])]);
        assert!(is_ancestor(&g, &id(1), &id(3)));
        assert!(is_ancestor(&g, &id(2), &id(3)));
        assert!(is_ancestor(&g, &id(3), &id(3)));
        assert!(!is_ancestor(&g, &id(3), &id(1)));
        assert!(!incomparable(&g, &id(1), &id(3)));
        assert_eq!(
            lowest_common_ancestors(&g, &id(2), &id(3)),
            BTreeSet::from([id(2)])
        );
    }

    #[test]
    fn fork_is_incomparable_with_root_lca() {
        let g = dag(&[(2, &[1]), (3, &[1])]);
        assert!(incomparable(&g, &id(2), &id(3)));
        assert_eq!(
            lowest_common_ancestors(&g, &id(2), &id(3)),
            BTreeSet::from([id(1)])
        );
    }

    #[test]
    fn diamond_lca_is_fork_point() {
        let g = dag(&[(2, &[1]), (3, &[1]), (4, &[2, 3])]);
        assert!(is_ancestor(&g, &id(1), &id(4)));
        assert!(!incomparable(&g, &id(2), &id(4)));
        assert_eq!(
            lowest_common_ancestors(&g, &id(2), &id(3)),
            BTreeSet::from([id(1)])
        );
    }

    #[test]
    fn deeper_lca_not_the_root() {
        let g = dag(&[(2, &[1]), (3, &[2]), (4, &[2])]);
        assert!(incomparable(&g, &id(3), &id(4)));
        assert_eq!(
            lowest_common_ancestors(&g, &id(3), &id(4)),
            BTreeSet::from([id(2)])
        );
    }

    #[test]
    fn disjoint_histories_have_no_common_ancestor() {
        let g = dag(&[(2, &[1]), (4, &[3])]);
        assert!(incomparable(&g, &id(2), &id(4)));
        assert!(lowest_common_ancestors(&g, &id(2), &id(4)).is_empty());
    }

    #[test]
    fn criss_cross_yields_multiple_lcas() {
        let g = dag(&[(3, &[1, 2]), (4, &[1, 2])]);
        assert!(incomparable(&g, &id(3), &id(4)));
        assert_eq!(
            lowest_common_ancestors(&g, &id(3), &id(4)),
            BTreeSet::from([id(1), id(2)])
        );
    }

    #[test]
    fn new_commits_excludes_our_history() {
        let g = dag(&[(2, &[1]), (3, &[2]), (4, &[2])]);
        assert_eq!(
            new_commits(&g, Some(&id(3)), &id(4)),
            BTreeSet::from([id(4)])
        );
        assert_eq!(
            new_commits(&g, None, &id(4)),
            BTreeSet::from([id(1), id(2), id(4)])
        );
        assert!(new_commits(&g, Some(&id(3)), &id(2)).is_empty());
    }

    #[test]
    fn cyclic_input_terminates() {
        let g = dag(&[(1, &[2]), (2, &[1])]);
        let _ = is_ancestor(&g, &id(1), &id(2));
        let _ = ancestors(&g, &id(1));
        let _ = lowest_common_ancestors(&g, &id(1), &id(2));
    }
}
