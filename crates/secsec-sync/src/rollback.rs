//! Rollback-aware merge gates + fork detection (`secsec-Design.md` §10, §8.5; risk R4):
//! [`evaluate_merge`] runs the three §10 gates against the persisted frontier so a malicious server
//! cannot replay an old branch into a merge; a DAG-incomparable sibling routes to the keep-both
//! merge. After acceptance the caller applies [`SyncFrontier::observe`] and MUST seal the frontier
//! before writing the merge commit (§8.5). The sealed local-state codec is also here.

use crate::dag::{self, Id, ParentMap};
use secsec_canon::{CanonError, Reader, Writer};
use secsec_frame::MAX_LIST_ELEMENTS;
use secsec_sig::DeviceId;
use std::collections::{BTreeMap, BTreeSet};

/// Local sealed-state nonce length (§9.8): 96-bit.
pub(crate) const FRONTIER_NONCE_LEN: usize = 12;
/// Poly1305 tag length in the sealed frontier blob (§9.8).
pub(crate) const FRONTIER_TAG_LEN: usize = 16;

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

/// Run the §10 gates against the persisted `frontier` and classify the sibling; `parents`/
/// `commit_meta` MUST cover both reachable histories. Commits authored by `local_device` are exempt
/// from gate 2a (§10: own history re-encountered after a re-link is not a replay; self-replay via a
/// stale head is gate 2b's job, and ancestor authorship is pinned by the verified head's
/// content-address chain). Returns the decision or the [`MergeReject`] to alarm on.
pub fn evaluate_merge(
    frontier: &SyncFrontier,
    our_head: &Id,
    sibling: &SiblingHead,
    local_device: &DeviceId,
    parents: &ParentMap,
    commit_meta: &BTreeMap<Id, CommitMeta>,
) -> Result<MergeDecision, MergeReject> {
    // Before the gates: a sibling already in our history is a no-op, never a rollback (a peer that
    // folds the roster late, stamping an older roster_seq on a held commit, must not alarm).
    if dag::is_ancestor(parents, &sibling.commit_id, our_head) {
        return Ok(MergeDecision::AlreadyHave);
    }

    // Gate 1: roster_seq frontier — reject sibling state authored under a roster older than ours.
    if sibling.roster_seq < frontier.roster_seq {
        return Err(MergeReject::RosterRollback {
            sibling: sibling.roster_seq,
            frontier: frontier.roster_seq,
        });
    }

    // Gate 2a: every newly-accepted commit's version must exceed its device's high-water; the local
    // device's own commits are exempt (fn docs).
    for c in new_commits(parents, our_head, &sibling.commit_id) {
        if let Some(meta) = commit_meta.get(&c) {
            if meta.device_id == *local_device {
                continue;
            }
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
    /// The §10 HWM update rule: raise `roster_seq`, the sibling's `head_version` high-water, and the
    /// commit-version high-water of every device in its reachable chain. The caller MUST seal the
    /// updated frontier before writing the merge commit (§8.5).
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

// ---- local sealed state (§8.5 / §9.8) ----

/// Errors sealing/opening the local frontier state.
#[derive(Debug)]
pub enum FrontierError {
    /// Blob too short for `nonce ‖ tag ‖ ct`.
    BadBlobSize,
    /// The §9.8 AEAD failed to open — wrong device key, wrong device_id AD, or a tampered/rolled-back
    /// blob from a different device. A **lost-frontier event** (§8.5): alarm and treat as a reinstall.
    Aead,
    /// The decrypted state was not canonical (truncation, over-long map, trailing bytes).
    Canon(CanonError),
}
impl core::fmt::Display for FrontierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrontierError::BadBlobSize => f.write_str("frontier blob size out of bounds"),
            FrontierError::Aead => f.write_str("frontier AEAD open failed (lost-frontier event)"),
            FrontierError::Canon(e) => write!(f, "canon: {e}"),
        }
    }
}
impl std::error::Error for FrontierError {}
impl From<CanonError> for FrontierError {
    fn from(e: CanonError) -> Self {
        FrontierError::Canon(e)
    }
}

fn encode_hwm(w: &mut Writer, map: &BTreeMap<DeviceId, u64>) {
    // BTreeMap iterates in ascending key order → canonical.
    w.u64(map.len() as u64);
    for (id, v) in map {
        w.raw(id).u64(*v);
    }
}

fn decode_hwm(r: &mut Reader<'_>) -> Result<BTreeMap<DeviceId, u64>, CanonError> {
    let n = r.u64()? as usize;
    if n > MAX_LIST_ELEMENTS {
        return Err(CanonError::LengthExceedsMax {
            len: n as u64,
            max: MAX_LIST_ELEMENTS,
        });
    }
    let mut map = BTreeMap::new();
    for _ in 0..n {
        let mut id = [0u8; 32];
        id.copy_from_slice(r.raw(32)?);
        map.insert(id, r.u64()?);
    }
    Ok(map)
}

impl SyncFrontier {
    /// Canonical plaintext encoding of the frontier (the inner of the §8.5 sealed blob).
    #[must_use]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(self.roster_seq);
        encode_hwm(&mut w, &self.commit_version_hwm);
        encode_hwm(&mut w, &self.head_version_hwm);
        w.finish()
    }

    /// Strictly decode a frontier plaintext (inverse of [`Self::encode`]).
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FrontierError> {
        let mut r = Reader::new(bytes);
        let roster_seq = r.u64()?;
        let commit_version_hwm = decode_hwm(&mut r)?;
        let head_version_hwm = decode_hwm(&mut r)?;
        r.finish()?;
        Ok(SyncFrontier {
            roster_seq,
            commit_version_hwm,
            head_version_hwm,
        })
    }
}

/// Seal the frontier as the §8.5 local-state blob `nonce(12) ‖ tag(16) ‖ ct` (§9.8 AEAD, fresh
/// OS-CSPRNG nonce per write, AD = `device_id`). `None` on RNG failure.
#[must_use]
pub fn seal_frontier(
    frontier: &SyncFrontier,
    local_seal_key: &[u8; 32],
    device_id: &DeviceId,
) -> Option<Vec<u8>> {
    let mut nonce = [0u8; FRONTIER_NONCE_LEN];
    getrandom::fill(&mut nonce).ok()?;
    let (tag, ct) = secsec_aead::seal_mut(local_seal_key, &nonce, device_id, &frontier.encode());
    let mut out = Vec::with_capacity(FRONTIER_NONCE_LEN + FRONTIER_TAG_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Open a sealed frontier blob. Any failure is a §8.5 **lost-frontier event**: the caller must
/// alarm and treat the session as a reinstall. The `device_id` AD binds the blob to this device.
pub fn open_frontier(
    local_seal_key: &[u8; 32],
    device_id: &DeviceId,
    blob: &[u8],
) -> Result<SyncFrontier, FrontierError> {
    if blob.len() < FRONTIER_NONCE_LEN + FRONTIER_TAG_LEN {
        return Err(FrontierError::BadBlobSize);
    }
    let nonce: [u8; FRONTIER_NONCE_LEN] = blob[..FRONTIER_NONCE_LEN]
        .try_into()
        .expect("slice is exactly FRONTIER_NONCE_LEN");
    let tag: [u8; FRONTIER_TAG_LEN] = blob
        [FRONTIER_NONCE_LEN..FRONTIER_NONCE_LEN + FRONTIER_TAG_LEN]
        .try_into()
        .expect("slice is exactly FRONTIER_TAG_LEN");
    let ct = &blob[FRONTIER_NONCE_LEN + FRONTIER_TAG_LEN..];
    let pt = secsec_aead::open_mut(local_seal_key, &nonce, device_id, &tag, ct)
        .map_err(|_| FrontierError::Aead)?;
    SyncFrontier::decode(&pt)
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
            evaluate_merge(
                &f,
                &id(1),
                &sib,
                &dev(9),
                &dag(&[(2, &[])]),
                &meta(&[(2, 2, 1)])
            ),
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
                &dev(9),
                &g,
                &meta(&[(1, 1, 1), (2, 2, 1), (3, 1, 2)])
            ),
            Ok(MergeDecision::AlreadyHave)
        );
    }

    /// A sibling we already contain must be `AlreadyHave` even when it carries an **older** `roster_seq`
    /// than our frontier (a peer that folded the roster later than we did). It must NOT trip gate 1's
    /// rollback alarm — adopting a commit already in our history changes nothing (regression for M3).
    #[test]
    fn already_held_ancestor_with_stale_roster_seq_is_not_a_rollback() {
        let g = dag(&[(2, &[1]), (3, &[2])]); // our head 3 descends from sibling 2
        let f = SyncFrontier {
            roster_seq: 7, // we have advanced past the sibling's roster_seq
            ..Default::default()
        };
        let sib = SiblingHead {
            device_id: dev(2),
            head_version: 1,
            roster_seq: 4, // below our frontier — would trip gate 1 if checked first
            commit_id: id(2),
        };
        assert_eq!(
            evaluate_merge(
                &f,
                &id(3),
                &sib,
                &dev(9),
                &g,
                &meta(&[(2, 2, 1), (3, 1, 2)])
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
            evaluate_merge(&f, &id(1), &sib, &dev(9), &g, &meta(&[(2, 2, 1)])),
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
            evaluate_merge(&f, &id(2), &sib, &dev(9), &g, &meta(&[(3, 2, 1)])),
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
            evaluate_merge(&f, &id(2), &sib, &dev(9), &g, &meta(&[(3, 2, 1)])),
            Err(MergeReject::CommitReplay {
                device: dev(2),
                version: 1,
                hwm: 5
            })
        );
    }

    /// Re-link / reinstall (fresh frontier, parentless local commit): the genuine head contains the
    /// local device's OWN earlier commits. Gate 2a must exempt them (history, not replays) — while a
    /// peer's stale commit in the same history is still rejected for any other local device.
    #[test]
    fn gate2a_exempts_local_devices_own_history() {
        // Disjoint roots: our fresh parentless commit 9 vs head 4, whose history holds our own old
        // commits 2 (v1) → 3 (v2) and peer dev(2)'s commit 4 (v1) on top.
        let g = dag(&[(3, &[2]), (4, &[3])]);
        let sib = SiblingHead {
            device_id: dev(2),
            head_version: 7,
            roster_seq: 0,
            commit_id: id(4),
        };
        // Our frontier already carries our NEW commit's version (3 = old max 2 + 1), exactly as
        // sync_once records it before merging.
        let f = SyncFrontier {
            commit_version_hwm: BTreeMap::from([(dev(1), 3)]),
            ..Default::default()
        };
        let cm = meta(&[(2, 1, 1), (3, 1, 2), (4, 2, 1)]);
        // As local device dev(1): its own old v1/v2 (≤ hwm 3) are exempt → the join merges.
        assert_eq!(
            evaluate_merge(&f, &id(9), &sib, &dev(1), &g, &cm),
            Ok(MergeDecision::Merge)
        );
        // For any OTHER local device there is no exemption: dev(1)'s v1 ≤ hwm 3 is a replay.
        assert_eq!(
            evaluate_merge(&f, &id(9), &sib, &dev(9), &g, &cm),
            Err(MergeReject::CommitReplay {
                device: dev(1),
                version: 1,
                hwm: 3
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
            evaluate_merge(&f, &id(2), &sib, &dev(9), &g, &meta(&[(3, 2, 9)])),
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

    fn sample_frontier() -> SyncFrontier {
        SyncFrontier {
            roster_seq: 7,
            commit_version_hwm: BTreeMap::from([(dev(1), 3), (dev(2), 9)]),
            head_version_hwm: BTreeMap::from([(dev(2), 4)]),
        }
    }

    #[test]
    fn frontier_encode_round_trips_and_rejects_trailing() {
        let f = sample_frontier();
        assert_eq!(SyncFrontier::decode(&f.encode()).unwrap(), f);
        // empty frontier too.
        let empty = SyncFrontier::default();
        assert_eq!(SyncFrontier::decode(&empty.encode()).unwrap(), empty);
        // trailing bytes are rejected (malleability guard).
        let mut bytes = f.encode();
        bytes.push(0);
        assert!(matches!(
            SyncFrontier::decode(&bytes),
            Err(FrontierError::Canon(CanonError::TrailingBytes { .. }))
        ));
    }

    #[test]
    fn frontier_seal_open_round_trip_and_fresh_nonce() {
        let key = [0x5a; 32];
        let device = dev(1);
        let f = sample_frontier();

        let b1 = seal_frontier(&f, &key, &device).unwrap();
        let b2 = seal_frontier(&f, &key, &device).unwrap();
        assert_ne!(
            b1, b2,
            "a fresh nonce must change the sealed blob each write (§9.8)"
        );
        assert_eq!(open_frontier(&key, &device, &b1).unwrap(), f);
        assert_eq!(open_frontier(&key, &device, &b2).unwrap(), f);
    }

    #[test]
    fn frontier_open_rejects_tamper_wrong_key_and_wrong_device() {
        let key = [0x5a; 32];
        let device = dev(1);
        let blob = seal_frontier(&sample_frontier(), &key, &device).unwrap();

        // tampered ciphertext.
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(matches!(
            open_frontier(&key, &device, &bad),
            Err(FrontierError::Aead)
        ));
        // a different device key cannot open it (lost-frontier on that device).
        assert!(matches!(
            open_frontier(&[0x5b; 32], &device, &blob),
            Err(FrontierError::Aead)
        ));
        // the device_id AD binds the blob to this device; another device's id won't open.
        assert!(matches!(
            open_frontier(&key, &dev(2), &blob),
            Err(FrontierError::Aead)
        ));
        // too-short blob.
        assert!(matches!(
            open_frontier(&key, &device, &blob[..10]),
            Err(FrontierError::BadBlobSize)
        ));
    }
}
