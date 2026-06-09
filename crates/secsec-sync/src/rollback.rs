//! Rollback-aware merge gates and fork detection (`finaldesign.md` §10, §8.5; risk R4).
//!
//! Before a client merges a server-presented sibling head it must clear three gates (§10), checked
//! against its **persisted frontier** ([`SyncFrontier`], the §8.5 counters) so a malicious server
//! cannot replay an old branch into the merge:
//!
//! 1. the sibling's `roster_seq` ≥ the persisted `roster_seq` frontier;
//! 2. every **new** commit's per-device `version` exceeds that device's high-water mark, **and** the
//!    sibling device's `head_version` ≥ its persisted high-water;
//! 3. the sibling is genuinely DAG-incomparable (otherwise it is a fast-forward or already held).
//!
//! [`evaluate_merge`] returns the decision or the specific rollback rejection. After acceptance the
//! caller updates the frontier with [`SyncFrontier::observe`] (the §10 HWM update rule: bump the
//! direct sibling **and** every device in the sibling's transitively reachable commit chain) — and,
//! per §8.5, MUST seal the new frontier *before* writing the local merge commit.
//!
//! **`last_seen_head`** (embedded in commits, §10) is a **commit id**, so fork detection and the
//! ancestor relations are all over the commit parent-DAG ([`crate::dag`]). [`fork_check`] implements
//! the §10 fork algorithm: a known, DAG-incomparable `last_seen_head` is a provable fork → alarm.

use crate::dag::{self, Id, ParentMap};
use secsec_sig::DeviceId;
use std::collections::{BTreeMap, BTreeSet};

/// The sentinel `last_seen_head` meaning "none" (§6: zero if none).
pub const NO_HEAD: Id = [0u8; 32];

/// The persisted, monotonic client frontier (§8.5) the merge gates check against. Sealed locally
/// under the device key (§8.5/§9.8); this is just the in-memory state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncFrontier {
    /// Highest accepted sigchain `roster_seq` (gate 1).
    pub roster_seq: u64,
    /// Per-device highest commit `version` observed — the replay high-water (gate 2a, §8.5).
    pub commit_version_hwm: BTreeMap<DeviceId, u64>,
    /// Per-device highest `head_version` observed, incl. indirect (gate 2b, §8.5/§10).
    pub head_version_hwm: BTreeMap<DeviceId, u64>,
}

/// A fetched, signature-verified sibling head (the inputs the gates need from it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiblingHead {
    /// The device that authored (signed) this head.
    pub device_id: DeviceId,
    /// The head's per-ref version (§8.5).
    pub head_version: u64,
    /// The roster sequence the head was written under.
    pub roster_seq: u64,
    /// The commit this head points at.
    pub commit_id: Id,
}

/// Per-commit metadata the gates read (decoded from each [`secsec_snapshot::Commit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitMeta {
    /// The authoring device.
    pub device_id: DeviceId,
    /// The author's strictly-increasing per-device commit version.
    pub version: u64,
}

/// What to do with an accepted sibling (after the gates pass).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeDecision {
    /// The sibling is an ancestor of (or equal to) our head — nothing new; ignore.
    AlreadyHave,
    /// Our head is an ancestor of the sibling — advance to it, no merge needed.
    FastForward,
    /// DAG-incomparable and all gates pass — run a three-way merge ([`crate::merge`]).
    Merge,
}

/// A specific rollback rejection (§10). Each carries the observed vs expected values for the alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeReject {
    /// Gate 1: the sibling's `roster_seq` is below the persisted frontier.
    RosterRollback {
        /// The sibling's roster_seq.
        sibling: u64,
        /// The client's frontier.
        frontier: u64,
    },
    /// Gate 2a: a new commit's `version` did not exceed that device's high-water (replay).
    CommitReplay {
        /// The authoring device.
        device: DeviceId,
        /// The commit's version.
        version: u64,
        /// The persisted high-water.
        hwm: u64,
    },
    /// Gate 2b: the sibling device's `head_version` is below its persisted high-water.
    HeadRollback {
        /// The sibling's device.
        device: DeviceId,
        /// The sibling's head_version.
        head_version: u64,
        /// The persisted high-water.
        hwm: u64,
    },
}

/// The commits reachable from `sibling` that are **not** already in our history — the ones a merge or
/// fast-forward would newly accept.
fn new_commits(parents: &ParentMap, our_head: &Id, sibling: &Id) -> BTreeSet<Id> {
    let ours = dag::ancestors(parents, our_head);
    dag::ancestors(parents, sibling)
        .into_iter()
        .filter(|c| !ours.contains(c))
        .collect()
}

/// Run the §10 rollback gates against the persisted `frontier` and classify the sibling. `parents`
/// and `commit_meta` MUST cover both our and the sibling's reachable history. Returns the decision,
/// or the specific [`MergeReject`] to alarm on.
pub fn evaluate_merge(
    frontier: &SyncFrontier,
    our_head: &Id,
    sibling: &SiblingHead,
    parents: &ParentMap,
    commit_meta: &BTreeMap<Id, CommitMeta>,
) -> Result<MergeDecision, MergeReject> {
    // Gate 1: roster_seq frontier.
    if sibling.roster_seq < frontier.roster_seq {
        return Err(MergeReject::RosterRollback {
            sibling: sibling.roster_seq,
            frontier: frontier.roster_seq,
        });
    }

    // Nothing new to accept: the sibling is behind or equal.
    if dag::is_ancestor(parents, &sibling.commit_id, our_head) {
        return Ok(MergeDecision::AlreadyHave);
    }

    // Gate 2a: every newly-accepted commit's version must exceed that device's high-water.
    for c in new_commits(parents, our_head, &sibling.commit_id) {
        if let Some(meta) = commit_meta.get(&c) {
            let hwm = frontier
                .commit_version_hwm
                .get(&meta.device_id)
                .copied()
                .unwrap_or(0);
            if meta.version <= hwm {
                return Err(MergeReject::CommitReplay {
                    device: meta.device_id,
                    version: meta.version,
                    hwm,
                });
            }
        }
    }

    // Gate 2b: the sibling device's head_version must not be below its high-water (≥, §10).
    let head_hwm = frontier
        .head_version_hwm
        .get(&sibling.device_id)
        .copied()
        .unwrap_or(0);
    if sibling.head_version < head_hwm {
        return Err(MergeReject::HeadRollback {
            device: sibling.device_id,
            head_version: sibling.head_version,
            hwm: head_hwm,
        });
    }

    // Gate 3 / decision: fast-forward if our head is an ancestor of the sibling, else a real merge.
    if dag::is_ancestor(parents, our_head, &sibling.commit_id) {
        Ok(MergeDecision::FastForward)
    } else {
        Ok(MergeDecision::Merge)
    }
}

impl SyncFrontier {
    /// Apply the §10 HWM update rule after accepting `sibling`: raise `roster_seq`, the sibling
    /// device's `head_version` high-water, and the commit-`version` high-water of **every** device in
    /// the sibling's transitively reachable commit chain (indirect observations count). Per §8.5 the
    /// caller MUST seal the updated frontier before writing the local merge commit.
    pub fn observe(
        &mut self,
        sibling: &SiblingHead,
        parents: &ParentMap,
        commit_meta: &BTreeMap<Id, CommitMeta>,
    ) {
        self.roster_seq = self.roster_seq.max(sibling.roster_seq);
        let e = self.head_version_hwm.entry(sibling.device_id).or_insert(0);
        *e = (*e).max(sibling.head_version);
        for c in dag::ancestors(parents, &sibling.commit_id) {
            if let Some(meta) = commit_meta.get(&c) {
                let e = self.commit_version_hwm.entry(meta.device_id).or_insert(0);
                *e = (*e).max(meta.version);
            }
        }
    }
}

/// The result of the §10 fork check on an incoming commit's `last_seen_head`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkStatus {
    /// Comparable (ancestor either way) or no `last_seen_head` — no fork.
    Comparable,
    /// `last_seen_head` is known and DAG-incomparable to our head — a provable fork; alarm (§10).
    Forked,
    /// `last_seen_head` is unknown to the client — record it and fetch from all remotes (§10 step 2).
    Unknown,
}

/// §10 fork detection. Given our current head commit, the set of commit ids the client `known`s, the
/// parent-DAG, and an incoming commit's `last_seen_head` (a commit id, [`NO_HEAD`] if none), classify
/// it. A known, incomparable `last_seen_head` is a provable fork.
#[must_use]
pub fn fork_check(
    parents: &ParentMap,
    known: &BTreeSet<Id>,
    our_head: &Id,
    last_seen_head: &Id,
) -> ForkStatus {
    if *last_seen_head == NO_HEAD {
        return ForkStatus::Comparable;
    }
    if !known.contains(last_seen_head) {
        return ForkStatus::Unknown;
    }
    if dag::incomparable(parents, our_head, last_seen_head) {
        ForkStatus::Forked
    } else {
        ForkStatus::Comparable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id {
        [n; 32]
    }
    fn dev(n: u8) -> DeviceId {
        [0x80 | n; 32]
    }
    fn dag(edges: &[(u8, &[u8])]) -> ParentMap {
        edges
            .iter()
            .map(|(c, ps)| (id(*c), ps.iter().map(|p| id(*p)).collect()))
            .collect()
    }
    fn meta(entries: &[(u8, u8, u64)]) -> BTreeMap<Id, CommitMeta> {
        // (commit, device, version)
        entries
            .iter()
            .map(|(c, d, v)| {
                (
                    id(*c),
                    CommitMeta {
                        device_id: dev(*d),
                        version: *v,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn gate1_roster_rollback_rejected() {
        let f = SyncFrontier {
            roster_seq: 10,
            ..Default::default()
        };
        let sib = SiblingHead {
            device_id: dev(2),
            head_version: 1,
            roster_seq: 9, // below frontier
            commit_id: id(2),
        };
        assert_eq!(
            evaluate_merge(&f, &id(1), &sib, &dag(&[(2, &[])]), &meta(&[(2, 2, 1)])),
            Err(MergeReject::RosterRollback {
                sibling: 9,
                frontier: 10
            })
        );
    }

    #[test]
    fn already_have_when_sibling_is_ancestor() {
        // our head 3 descends from sibling 2.
        let g = dag(&[(2, &[1]), (3, &[2])]);
        let f = SyncFrontier::default();
        let sib = SiblingHead {
            device_id: dev(2),
            head_version: 1,
            roster_seq: 0,
            commit_id: id(2),
        };
        assert_eq!(
            evaluate_merge(
                &f,
                &id(3),
                &sib,
                &g,
                &meta(&[(1, 1, 1), (2, 2, 1), (3, 1, 2)])
            ),
            Ok(MergeDecision::AlreadyHave)
        );
    }

    #[test]
    fn fast_forward_when_our_head_is_ancestor() {
        // our head 1; sibling 2 descends from 1.
        let g = dag(&[(2, &[1])]);
        let f = SyncFrontier::default();
        let sib = SiblingHead {
            device_id: dev(2),
            head_version: 1,
            roster_seq: 0,
            commit_id: id(2),
        };
        assert_eq!(
            evaluate_merge(&f, &id(1), &sib, &g, &meta(&[(2, 2, 1)])),
            Ok(MergeDecision::FastForward)
        );
    }

    #[test]
    fn merge_when_incomparable_and_gates_pass() {
        // fork: 1 root; our head 2, sibling 3.
        let g = dag(&[(2, &[1]), (3, &[1])]);
        let f = SyncFrontier::default();
        let sib = SiblingHead {
            device_id: dev(2),
            head_version: 1,
            roster_seq: 0,
            commit_id: id(3),
        };
        assert_eq!(
            evaluate_merge(&f, &id(2), &sib, &g, &meta(&[(3, 2, 1)])),
            Ok(MergeDecision::Merge)
        );
    }

    #[test]
    fn gate2a_commit_replay_rejected() {
        // sibling 3 authored by device 2 at version 1, but we already saw version 5 from device 2.
        let g = dag(&[(2, &[1]), (3, &[1])]);
        let f = SyncFrontier {
            commit_version_hwm: BTreeMap::from([(dev(2), 5)]),
            ..Default::default()
        };
        let sib = SiblingHead {
            device_id: dev(2),
            head_version: 9,
            roster_seq: 0,
            commit_id: id(3),
        };
        assert_eq!(
            evaluate_merge(&f, &id(2), &sib, &g, &meta(&[(3, 2, 1)])),
            Err(MergeReject::CommitReplay {
                device: dev(2),
                version: 1,
                hwm: 5
            })
        );
    }

    #[test]
    fn gate2b_head_rollback_rejected() {
        let g = dag(&[(2, &[1]), (3, &[1])]);
        let f = SyncFrontier {
            head_version_hwm: BTreeMap::from([(dev(2), 7)]),
            ..Default::default()
        };
        let sib = SiblingHead {
            device_id: dev(2),
            head_version: 6, // below the high-water 7
            roster_seq: 0,
            commit_id: id(3),
        };
        assert_eq!(
            evaluate_merge(&f, &id(2), &sib, &g, &meta(&[(3, 2, 9)])),
            Err(MergeReject::HeadRollback {
                device: dev(2),
                head_version: 6,
                hwm: 7
            })
        );
    }

    #[test]
    fn observe_raises_all_high_waters() {
        // sibling 4 (dev2,v3) descends from 2 (dev2,v2) and 1 (dev1,v1).
        let g = dag(&[(2, &[1]), (4, &[2])]);
        let cm = meta(&[(1, 1, 1), (2, 2, 2), (4, 2, 3)]);
        let mut f = SyncFrontier {
            roster_seq: 1,
            ..Default::default()
        };
        let sib = SiblingHead {
            device_id: dev(2),
            head_version: 5,
            roster_seq: 4,
            commit_id: id(4),
        };
        f.observe(&sib, &g, &cm);
        assert_eq!(f.roster_seq, 4);
        assert_eq!(f.head_version_hwm.get(&dev(2)), Some(&5));
        // commit-version HWM updated for every device in the reachable chain.
        assert_eq!(f.commit_version_hwm.get(&dev(1)), Some(&1));
        assert_eq!(f.commit_version_hwm.get(&dev(2)), Some(&3));
        // idempotent / monotonic: re-observing a lower head_version doesn't lower it.
        let older = SiblingHead {
            head_version: 2,
            roster_seq: 0,
            ..sib
        };
        f.observe(&older, &g, &cm);
        assert_eq!(f.head_version_hwm.get(&dev(2)), Some(&5));
        assert_eq!(f.roster_seq, 4);
    }

    #[test]
    fn fork_check_classifies() {
        // 1 root; our head 2, other branch 3 -> incomparable. 4 descends from 2 (comparable).
        let g = dag(&[(2, &[1]), (3, &[1]), (4, &[2])]);
        let known = BTreeSet::from([id(1), id(2), id(3), id(4)]);
        assert_eq!(fork_check(&g, &known, &id(2), &id(3)), ForkStatus::Forked);
        assert_eq!(
            fork_check(&g, &known, &id(4), &id(2)),
            ForkStatus::Comparable
        );
        assert_eq!(
            fork_check(&g, &known, &id(2), &NO_HEAD),
            ForkStatus::Comparable
        );
        assert_eq!(fork_check(&g, &known, &id(2), &id(9)), ForkStatus::Unknown);
    }
}
