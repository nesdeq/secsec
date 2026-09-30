//! Rollback-aware merge gates, fork classification, and the sealed local frontier (`secsec-Design.md` §8.5, §10; R4).

use crate::dag::{self, Id, ParentMap};
use crate::{verify_head, Head};
use secsec_canon::{verify_reencode, CanonError, Reader, Writer};
use secsec_frame::MAX_LIST_ELEMENTS;
use secsec_sig::{DeviceId, DevicePublic};
use std::collections::{BTreeMap, BTreeSet};

/// Local sealed-state nonce length (§9.8).
pub(crate) const FRONTIER_NONCE_LEN: usize = 12;
/// Poly1305 tag length in the sealed frontier blob (§9.8).
pub(crate) const FRONTIER_TAG_LEN: usize = 16;

/// The persisted, monotonic client frontier the gates check against (§8.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncFrontier {
    /// Highest accepted sigchain `roster_seq` (gate 1).
    pub roster_seq: u64,
    /// Per-device highest commit `version` accepted into this device's history (gate 2a).
    pub commit_version_hwm: BTreeMap<DeviceId, u64>,
    /// Per-device highest `head_version` observed (gate 2b).
    pub head_version_hwm: BTreeMap<DeviceId, u64>,
}

/// A fetched head whose signature a current member made; [`SiblingHead::verified`] is the only constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SiblingHead {
    /// The device that signed this head.
    pub device_id: DeviceId,
    /// The head's per-ref version (§8.5).
    pub head_version: u64,
    /// The roster sequence the head was written under.
    pub roster_seq: u64,
    /// The commit this head points at.
    pub commit_id: Id,
}

impl SiblingHead {
    /// Verify `sig` over `head` against the current `members`; `None` if no member signed it.
    #[must_use]
    pub fn verified(
        members: &BTreeMap<DeviceId, DevicePublic>,
        head: &Head,
        sig: &[u8],
    ) -> Option<Self> {
        let device_id = members
            .iter()
            .find_map(|(id, pk)| verify_head(pk, head, sig).is_ok().then_some(*id))?;
        Some(Self {
            device_id,
            head_version: head.head_version,
            roster_seq: head.roster_seq,
            commit_id: head.commit_id,
        })
    }
}

/// Per-commit metadata the gates read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitMeta {
    /// The authoring device.
    pub device_id: DeviceId,
    /// The author's strictly-increasing per-device commit version.
    pub version: u64,
}

/// What to do with a sibling that passed the gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeDecision {
    /// The sibling is an ancestor of (or equal to) our head.
    AlreadyHave,
    /// Our head is an ancestor of the sibling: advance, no merge.
    FastForward,
    /// DAG-incomparable: three-way merge ([`crate::merge`]).
    Merge,
}

/// A specific rollback rejection (§10), carrying observed vs expected values for the alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeReject {
    /// Gate 1: the sibling's `roster_seq` is below the frontier.
    RosterRollback {
        /// The sibling's roster_seq.
        sibling: u64,
        /// The client's frontier.
        frontier: u64,
    },
    /// Gate 2a: a new commit's `version` did not exceed its device's high-water (replay).
    CommitReplay {
        /// The authoring device.
        device: DeviceId,
        /// The commit's version.
        version: u64,
        /// The persisted high-water.
        hwm: u64,
    },
    /// The caller's DAG lacks metadata for a commit the gates must examine; fails closed.
    IncompleteDag {
        /// The reachable commit that carried no metadata.
        commit: Id,
    },
    /// Gate 2b: the sibling device's `head_version` is below its high-water.
    HeadRollback {
        /// The sibling's device.
        device: DeviceId,
        /// The sibling's head_version.
        head_version: u64,
        /// The persisted high-water.
        hwm: u64,
    },
}

/// Run the §10 gates for `sibling` against `frontier`; commits by `local_device` are exempt from gate 2a.
pub fn evaluate_merge(
    frontier: &SyncFrontier,
    our_head: &Id,
    sibling: &SiblingHead,
    local_device: &DeviceId,
    parents: &ParentMap,
    commit_meta: &BTreeMap<Id, CommitMeta>,
) -> Result<MergeDecision, MergeReject> {
    // A sibling already in our history is a no-op, never a rollback (checked before the gates).
    if dag::is_ancestor(parents, &sibling.commit_id, our_head) {
        return Ok(MergeDecision::AlreadyHave);
    }
    check_gates(
        frontier,
        sibling,
        local_device,
        &dag::new_commits(parents, Some(our_head), &sibling.commit_id),
        commit_meta,
    )?;
    if dag::is_ancestor(parents, our_head, &sibling.commit_id) {
        Ok(MergeDecision::FastForward)
    } else {
        Ok(MergeDecision::Merge)
    }
}

/// Gates 1, 2a, 2b over the commits `new` to this device.
pub fn check_gates(
    frontier: &SyncFrontier,
    sibling: &SiblingHead,
    local_device: &DeviceId,
    new: &BTreeSet<Id>,
    commit_meta: &BTreeMap<Id, CommitMeta>,
) -> Result<(), MergeReject> {
    if sibling.roster_seq < frontier.roster_seq {
        return Err(MergeReject::RosterRollback {
            sibling: sibling.roster_seq,
            frontier: frontier.roster_seq,
        });
    }
    for c in new {
        let Some(meta) = commit_meta.get(c) else {
            return Err(MergeReject::IncompleteDag { commit: *c });
        };
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
    Ok(())
}

impl SyncFrontier {
    /// The §8.5 HWM rule: raise `roster_seq`, the sibling's head high-water, and every new commit's version high-water.
    pub fn observe(
        &mut self,
        sibling: &SiblingHead,
        new: &BTreeSet<Id>,
        commit_meta: &BTreeMap<Id, CommitMeta>,
    ) {
        self.observe_head(sibling);
        for c in new {
            if let Some(meta) = commit_meta.get(c) {
                let e = self.commit_version_hwm.entry(meta.device_id).or_insert(0);
                *e = (*e).max(meta.version);
            }
        }
    }

    /// Raise only `roster_seq` and the sibling device's head high-water.
    pub fn observe_head(&mut self, sibling: &SiblingHead) {
        self.roster_seq = self.roster_seq.max(sibling.roster_seq);
        let e = self.head_version_hwm.entry(sibling.device_id).or_insert(0);
        *e = (*e).max(sibling.head_version);
    }

    /// The pre-push seal (§8.5): `observed`'s roster/head high-waters, our commit high-waters, and `own` for us.
    #[must_use]
    pub fn with_heads_of(&self, observed: &SyncFrontier, own: (DeviceId, u64)) -> SyncFrontier {
        let mut out = self.clone();
        out.roster_seq = observed.roster_seq;
        out.head_version_hwm = observed.head_version_hwm.clone();
        let e = out.commit_version_hwm.entry(own.0).or_insert(0);
        *e = (*e).max(own.1);
        out
    }
}

// ---- local sealed state (§8.5 / §9.8) ----

/// Errors sealing/opening the local frontier state.
#[derive(Debug)]
pub enum FrontierError {
    /// Blob too short for `nonce ‖ tag ‖ ct`.
    BadBlobSize,
    /// The AEAD failed (wrong key or device, or a tampered blob): a §8.5 lost-frontier event.
    Aead,
    /// The decrypted state was not canonical.
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
    w.u64(map.len() as u64);
    for (id, v) in map {
        w.raw(id).u64(*v);
    }
}

fn decode_hwm(r: &mut Reader<'_>) -> Result<BTreeMap<DeviceId, u64>, CanonError> {
    let n = r.u64()?;
    if n > MAX_LIST_ELEMENTS as u64 {
        return Err(CanonError::LengthExceedsMax {
            len: n,
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
    /// Canonical plaintext encoding (the inner of the §8.5 sealed blob).
    #[must_use]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(self.roster_seq);
        encode_hwm(&mut w, &self.commit_version_hwm);
        encode_hwm(&mut w, &self.head_version_hwm);
        w.finish()
    }

    /// Strictly decode a frontier plaintext, with the §9.3 re-encode guard (ids ascending and unique).
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FrontierError> {
        let mut r = Reader::new(bytes);
        let roster_seq = r.u64()?;
        let commit_version_hwm = decode_hwm(&mut r)?;
        let head_version_hwm = decode_hwm(&mut r)?;
        r.finish()?;
        let frontier = SyncFrontier {
            roster_seq,
            commit_version_hwm,
            head_version_hwm,
        };
        verify_reencode(bytes, &frontier, SyncFrontier::encode)?;
        Ok(frontier)
    }
}

/// Seal the frontier as `nonce(12) ‖ tag(16) ‖ ct` (§9.8, fresh nonce, AD = `device_id`); `None` on RNG failure.
#[must_use]
pub fn seal_frontier(
    frontier: &SyncFrontier,
    local_seal_key: &[u8; 32],
    device_id: &DeviceId,
) -> Option<Vec<u8>> {
    let mut nonce = [0u8; FRONTIER_NONCE_LEN];
    getrandom::fill(&mut nonce).ok()?;
    let (tag, ct) = secsec_aead::seal_mut(
        local_seal_key,
        secsec_aead::FreshNonce::new(&nonce),
        device_id,
        &frontier.encode(),
    );
    let mut out = Vec::with_capacity(FRONTIER_NONCE_LEN + FRONTIER_TAG_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Open a sealed frontier; any failure is a §8.5 lost-frontier event.
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

/// Fuzz hook: the frontier plaintext decoder on arbitrary bytes.
#[doc(hidden)]
pub fn __fuzz_decode_frontier(bytes: &[u8]) {
    let _ = SyncFrontier::decode(bytes);
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
    fn sib(d: u8, head_version: u64, roster_seq: u64, c: u8) -> SiblingHead {
        SiblingHead {
            device_id: dev(d),
            head_version,
            roster_seq,
            commit_id: id(c),
        }
    }

    #[test]
    fn gate1_roster_rollback_rejected() {
        let f = SyncFrontier {
            roster_seq: 10,
            ..Default::default()
        };
        assert_eq!(
            evaluate_merge(
                &f,
                &id(1),
                &sib(2, 1, 9, 2),
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
    fn already_have_when_sibling_is_ancestor_even_with_stale_roster_seq() {
        let g = dag(&[(2, &[1]), (3, &[2])]);
        let f = SyncFrontier {
            roster_seq: 7,
            ..Default::default()
        };
        assert_eq!(
            evaluate_merge(
                &f,
                &id(3),
                &sib(2, 1, 4, 2),
                &dev(9),
                &g,
                &meta(&[(2, 2, 1), (3, 1, 2)])
            ),
            Ok(MergeDecision::AlreadyHave)
        );
    }

    #[test]
    fn fast_forward_and_merge_classification() {
        let g = dag(&[(2, &[1])]);
        assert_eq!(
            evaluate_merge(
                &SyncFrontier::default(),
                &id(1),
                &sib(2, 1, 0, 2),
                &dev(9),
                &g,
                &meta(&[(2, 2, 1)])
            ),
            Ok(MergeDecision::FastForward)
        );
        let g = dag(&[(2, &[1]), (3, &[1])]);
        assert_eq!(
            evaluate_merge(
                &SyncFrontier::default(),
                &id(2),
                &sib(2, 1, 0, 3),
                &dev(9),
                &g,
                &meta(&[(3, 2, 1)])
            ),
            Ok(MergeDecision::Merge)
        );
    }

    #[test]
    fn gate2a_commit_replay_rejected() {
        let g = dag(&[(2, &[1]), (3, &[1])]);
        let f = SyncFrontier {
            commit_version_hwm: BTreeMap::from([(dev(2), 5)]),
            ..Default::default()
        };
        assert_eq!(
            evaluate_merge(
                &f,
                &id(2),
                &sib(2, 9, 0, 3),
                &dev(9),
                &g,
                &meta(&[(3, 2, 1)])
            ),
            Err(MergeReject::CommitReplay {
                device: dev(2),
                version: 1,
                hwm: 5
            })
        );
    }

    /// Re-link: the local device's own earlier commits in the head are history, not replays.
    #[test]
    fn gate2a_exempts_local_devices_own_history() {
        let g = dag(&[(3, &[2]), (4, &[3])]);
        let f = SyncFrontier {
            commit_version_hwm: BTreeMap::from([(dev(1), 3)]),
            ..Default::default()
        };
        let cm = meta(&[(2, 1, 1), (3, 1, 2), (4, 2, 1)]);
        assert_eq!(
            evaluate_merge(&f, &id(9), &sib(2, 7, 0, 4), &dev(1), &g, &cm),
            Ok(MergeDecision::Merge)
        );
        assert_eq!(
            evaluate_merge(&f, &id(9), &sib(2, 7, 0, 4), &dev(9), &g, &cm),
            Err(MergeReject::CommitReplay {
                device: dev(1),
                version: 1,
                hwm: 3
            })
        );
    }

    #[test]
    fn incomplete_dag_is_rejected_rather_than_skipped() {
        let g = dag(&[(2, &[1]), (3, &[2])]);
        let f = SyncFrontier::default();
        assert_eq!(
            evaluate_merge(
                &f,
                &id(9),
                &sib(2, 1, 0, 3),
                &dev(9),
                &g,
                &meta(&[(3, 2, 2)])
            ),
            Err(MergeReject::IncompleteDag { commit: id(1) })
        );
        assert_eq!(
            evaluate_merge(
                &f,
                &id(9),
                &sib(2, 1, 0, 3),
                &dev(9),
                &g,
                &meta(&[(1, 1, 1), (2, 2, 1), (3, 2, 2)])
            ),
            Ok(MergeDecision::Merge)
        );
    }

    #[test]
    fn frontier_decode_rejects_non_canonical_hwm_order() {
        let mut w = Writer::new();
        w.u64(0);
        w.u64(2);
        w.raw(&dev(2)).u64(1);
        w.raw(&dev(1)).u64(1);
        w.u64(0);
        let bytes = w.finish();
        assert!(matches!(
            SyncFrontier::decode(&bytes),
            Err(FrontierError::Canon(CanonError::NonCanonical))
        ));
    }

    #[test]
    fn gate2b_head_rollback_rejected() {
        let g = dag(&[(2, &[1]), (3, &[1])]);
        let f = SyncFrontier {
            head_version_hwm: BTreeMap::from([(dev(2), 7)]),
            ..Default::default()
        };
        assert_eq!(
            evaluate_merge(
                &f,
                &id(2),
                &sib(2, 6, 0, 3),
                &dev(9),
                &g,
                &meta(&[(3, 2, 9)])
            ),
            Err(MergeReject::HeadRollback {
                device: dev(2),
                head_version: 6,
                hwm: 7
            })
        );
    }

    /// `observe` raises the roster and head high-waters and the new commits' version high-waters, never lowering any.
    #[test]
    fn observe_raises_new_high_waters_only() {
        let cm = meta(&[(1, 1, 1), (2, 2, 2), (4, 2, 3)]);
        let mut f = SyncFrontier {
            roster_seq: 1,
            ..Default::default()
        };
        let s = sib(2, 5, 4, 4);
        f.observe(&s, &BTreeSet::from([id(2), id(4)]), &cm);
        assert_eq!(f.roster_seq, 4);
        assert_eq!(f.head_version_hwm.get(&dev(2)), Some(&5));
        assert_eq!(f.commit_version_hwm.get(&dev(2)), Some(&3));
        assert_eq!(f.commit_version_hwm.get(&dev(1)), None);
        f.observe(&sib(2, 2, 0, 4), &BTreeSet::new(), &cm);
        assert_eq!(f.head_version_hwm.get(&dev(2)), Some(&5));
        assert_eq!(f.roster_seq, 4);
    }

    /// The pre-push seal carries the observed head/roster high-waters but no other device's commit high-water.
    #[test]
    fn with_heads_of_keeps_commit_hwms_behind_the_base() {
        let old = SyncFrontier {
            roster_seq: 1,
            commit_version_hwm: BTreeMap::from([(dev(2), 4)]),
            head_version_hwm: BTreeMap::new(),
        };
        let observed = SyncFrontier {
            roster_seq: 3,
            commit_version_hwm: BTreeMap::from([(dev(2), 9)]),
            head_version_hwm: BTreeMap::from([(dev(2), 7)]),
        };
        let pre = old.with_heads_of(&observed, (dev(1), 6));
        assert_eq!(pre.roster_seq, 3);
        assert_eq!(pre.head_version_hwm.get(&dev(2)), Some(&7));
        assert_eq!(pre.commit_version_hwm.get(&dev(2)), Some(&4));
        assert_eq!(pre.commit_version_hwm.get(&dev(1)), Some(&6));
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
        let empty = SyncFrontier::default();
        assert_eq!(SyncFrontier::decode(&empty.encode()).unwrap(), empty);
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
        assert_ne!(b1, b2, "a fresh nonce must change the sealed blob");
        assert_eq!(open_frontier(&key, &device, &b1).unwrap(), f);
        assert_eq!(open_frontier(&key, &device, &b2).unwrap(), f);
    }

    #[test]
    fn frontier_open_rejects_tamper_wrong_key_and_wrong_device() {
        let key = [0x5a; 32];
        let device = dev(1);
        let blob = seal_frontier(&sample_frontier(), &key, &device).unwrap();
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(matches!(
            open_frontier(&key, &device, &bad),
            Err(FrontierError::Aead)
        ));
        assert!(matches!(
            open_frontier(&[0x5b; 32], &device, &blob),
            Err(FrontierError::Aead)
        ));
        assert!(matches!(
            open_frontier(&key, &dev(2), &blob),
            Err(FrontierError::Aead)
        ));
        assert!(matches!(
            open_frontier(&key, &device, &blob[..10]),
            Err(FrontierError::BadBlobSize)
        ));
    }
}
