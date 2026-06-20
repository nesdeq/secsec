//! Commit-DAG ancestry (`secsec-Design.md` §10): pure graph logic for fork detection
//! (DAG-incomparability) and the merge base (lowest common ancestors). The DAG comes in as
//! `commit id → parents`; traversals carry a visited set, so even a malformed cyclic map terminates.

use std::collections::{BTreeMap, BTreeSet};

/// A 256-bit commit content-address (§9.2).
pub type Id = [u8; 32];

/// The DAG as `commit id → its parent ids`. Missing entries are treated as roots (no parents).
pub type ParentMap = BTreeMap<Id, Vec<Id>>;

/// Every ancestor of `start`, **including `start` itself** (reflexive closure up the parent edges).
#[must_use]
pub(crate) fn ancestors(parents: &ParentMap, start: &Id) -> BTreeSet<Id> {
    let mut seen: BTreeSet<Id> = BTreeSet::new();
    let mut work = vec![*start];
    while let Some(c) = work.pop() {
        if !seen.insert(c) {
            continue;
        }
        if let Some(ps) = parents.get(&c) {
            for p in ps {
                if !seen.contains(p) {
                    work.push(*p);
                }
            }
        }
    }
    seen
}

/// Is `ancestor` an ancestor of — **or equal to** — `descendant`? Reflexive: every commit is its
/// own ancestor. Bounded walk up from `descendant`.
#[must_use]
pub(crate) fn is_ancestor(parents: &ParentMap, ancestor: &Id, descendant: &Id) -> bool {
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

/// Are `a` and `b` **DAG-incomparable** — neither an ancestor of the other (§10 fork condition)?
/// Equal commits are comparable (not a fork).
#[cfg(test)]
#[must_use]
pub fn incomparable(parents: &ParentMap, a: &Id, b: &Id) -> bool {
    !is_ancestor(parents, a, b) && !is_ancestor(parents, b, a)
}

/// All commits that are ancestors of **both** `a` and `b` (the candidate merge bases).
#[must_use]
pub(crate) fn common_ancestors(parents: &ParentMap, a: &Id, b: &Id) -> BTreeSet<Id> {
    let anc_a = ancestors(parents, a);
    let anc_b = ancestors(parents, b);
    anc_a.intersection(&anc_b).copied().collect()
}

/// The **lowest** common ancestors of `a` and `b` (§10 three-way-merge base): the common ancestors
/// that are not a proper ancestor of any *other* common ancestor. A clean fork/diamond yields a
/// single LCA; a criss-cross history can yield several (the caller decides — e.g. keep-both, §10).
#[must_use]
pub fn lowest_common_ancestors(parents: &ParentMap, a: &Id, b: &Id) -> BTreeSet<Id> {
    let common = common_ancestors(parents, a, b);
    common
        .iter()
        .copied()
        .filter(|c| {
            !common
                .iter()
                .any(|other| other != c && is_ancestor(parents, c, other))
        })
        .collect()
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
        // 1 <- 2 <- 3
        let g = dag(&[(2, &[1]), (3, &[2])]);
        assert!(is_ancestor(&g, &id(1), &id(3)));
        assert!(is_ancestor(&g, &id(2), &id(3)));
        assert!(is_ancestor(&g, &id(3), &id(3))); // reflexive
        assert!(!is_ancestor(&g, &id(3), &id(1)));
        assert!(!incomparable(&g, &id(1), &id(3)));
        assert_eq!(
            lowest_common_ancestors(&g, &id(2), &id(3)),
            BTreeSet::from([id(2)])
        );
    }

    #[test]
    fn fork_is_incomparable_with_root_lca() {
        // root 1; branches 2 and 3 both off 1.
        let g = dag(&[(2, &[1]), (3, &[1])]);
        assert!(incomparable(&g, &id(2), &id(3)));
        assert_eq!(
            common_ancestors(&g, &id(2), &id(3)),
            BTreeSet::from([id(1)])
        );
        assert_eq!(
            lowest_common_ancestors(&g, &id(2), &id(3)),
            BTreeSet::from([id(1)])
        );
    }

    #[test]
    fn diamond_lca_is_fork_point() {
        // 1 <- 2 ; 1 <- 3 ; {2,3} <- 4   (merge). LCA(2,3) = 1; 4 descends from both.
        let g = dag(&[(2, &[1]), (3, &[1]), (4, &[2, 3])]);
        assert!(is_ancestor(&g, &id(1), &id(4)));
        assert!(is_ancestor(&g, &id(2), &id(4)));
        assert!(is_ancestor(&g, &id(3), &id(4)));
        assert!(!incomparable(&g, &id(2), &id(4))); // 2 is an ancestor of the merge 4
        assert_eq!(
            lowest_common_ancestors(&g, &id(2), &id(3)),
            BTreeSet::from([id(1)])
        );
    }

    #[test]
    fn deeper_lca_not_the_root() {
        // 1 <- 2 <- 3 ; 2 <- 4 . LCA(3,4) = 2 (not the root 1).
        let g = dag(&[(2, &[1]), (3, &[2]), (4, &[2])]);
        assert!(incomparable(&g, &id(3), &id(4)));
        assert_eq!(
            common_ancestors(&g, &id(3), &id(4)),
            BTreeSet::from([id(1), id(2)])
        );
        assert_eq!(
            lowest_common_ancestors(&g, &id(3), &id(4)),
            BTreeSet::from([id(2)])
        );
    }

    #[test]
    fn disjoint_histories_have_no_common_ancestor() {
        // two independent roots/chains.
        let g = dag(&[(2, &[1]), (4, &[3])]);
        assert!(incomparable(&g, &id(2), &id(4)));
        assert!(common_ancestors(&g, &id(2), &id(4)).is_empty());
        assert!(lowest_common_ancestors(&g, &id(2), &id(4)).is_empty());
    }

    #[test]
    fn criss_cross_yields_multiple_lcas() {
        // 1,2 roots; 3 = merge(1,2); 4 = merge(1,2). LCAs(3,4) = {1,2} (both, neither below the other).
        let g = dag(&[(3, &[1, 2]), (4, &[1, 2])]);
        assert!(incomparable(&g, &id(3), &id(4)));
        assert_eq!(
            lowest_common_ancestors(&g, &id(3), &id(4)),
            BTreeSet::from([id(1), id(2)])
        );
    }

    #[test]
    fn cyclic_input_terminates() {
        // Malformed (content-addressing forbids this), but traversal must not loop: 1<->2.
        let g = dag(&[(1, &[2]), (2, &[1])]);
        // terminates and gives some answer; the point is it returns at all.
        let _ = is_ancestor(&g, &id(1), &id(2));
        let _ = ancestors(&g, &id(1));
    }
}
