//! `secsec-roster` — the roster sigchain: entries, fold/succession, and the anti-rollback frontier
//! (`finaldesign.md` §8.1). This is the real ACL.
//!
//! An append-only, hash-chained, SSHSIG-signed log. Each entry is `{seq, prev, op, ts, signer}`
//! signed under [`secsec_sig::NS_ROSTER`]; `prev` is the BLAKE3 of the full previous entry, and the
//! genesis entry's hash is the repository's **RFP** (§5). [`fold`] replays the chain with
//! **succession**: entry `n` is valid only if its signer is a *current member* of the state folded
//! from entries `0..n-1` — so a non-member or revoked device cannot extend the chain. [`Frontier`]
//! + [`check_frontier`] implement the §8.1 anti-rollback (a chain shorter than, or inconsistent
//!   with, a persisted frontier is rejected).
//!
//! This slice handles the **plaintext** sigchain logic. Per-entry encryption under `roster_key_g`
//! (§9.5) and the key-history chains (§8.2) are a separate layer that wraps these bytes.

#![forbid(unsafe_code)]

use secsec_canon::Writer;
use secsec_sig::{DeviceId, DeviceKey, DevicePublic, NS_ROSTER};
use std::collections::BTreeMap;

/// A 256-bit master-key generation commitment (`mk_commit_g`, recorded for verification elsewhere).
pub type MkCommit = [u8; 32];

/// A sigchain operation (§8.1). `params` are inlined per variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// The trust root: device-1's canonical pubkey + generation-1 commitment. Self-signed at seq 0.
    Genesis {
        /// Canonical SSH encoding of device-1's public key.
        pubkey: Vec<u8>,
        /// `mk_commit_1`.
        mk_commit: MkCommit,
    },
    /// Add a device: its canonical pubkey + the current generation's commitment.
    AddDevice {
        /// Canonical SSH encoding of the new device's public key.
        pubkey: Vec<u8>,
        /// `mk_commit_g` at the time of the grant.
        mk_commit: MkCommit,
    },
    /// Remove a device by id.
    RevokeDevice {
        /// The device being removed.
        device: DeviceId,
    },
    /// Mint a new master-key generation; records the new generation's commitment.
    Rotate {
        /// `mk_commit_{g+1}`.
        mk_commit: MkCommit,
    },
    /// Raise the repo-wide minimum algorithm id (§16 downgrade floor).
    SetMinAlgo {
        /// The new floor.
        min_algo: u8,
    },
}

/// A signed sigchain entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Strictly increasing sequence number; genesis is 0.
    pub seq: u64,
    /// BLAKE3 of the full previous entry (`[0;32]` for genesis).
    pub prev: [u8; 32],
    /// The operation.
    pub op: Op,
    /// Author-asserted timestamp (advisory).
    pub ts: u64,
    /// The signing device's id.
    pub signer: DeviceId,
    /// SSHSIG (PEM bytes) over the signed portion, namespace `secsec-roster-v1`.
    pub sig: Vec<u8>,
}

/// Errors from building / folding the sigchain.
#[derive(Debug)]
pub enum RosterError {
    /// Empty chain.
    Empty,
    /// Genesis entry malformed (wrong seq/prev/op, or not self-signed by device-1).
    BadGenesis,
    /// Genesis hash did not equal the pinned RFP.
    RfpMismatch,
    /// A non-genesis entry had a `Genesis` op.
    DoubleGenesis,
    /// Sequence numbers are not 0,1,2,….
    BadSeq,
    /// An entry's `prev` did not equal the hash of its predecessor.
    ChainBreak,
    /// An entry was signed by a key that is not a current member (succession violation).
    NotMember,
    /// An entry's signature did not verify.
    BadSignature,
    /// A fetched chain was shorter than, or inconsistent with, the persisted frontier (rollback).
    Rollback,
    /// Signing/key error.
    Sig(secsec_sig::SigError),
}

impl core::fmt::Display for RosterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RosterError::Empty => f.write_str("empty sigchain"),
            RosterError::BadGenesis => f.write_str("malformed genesis entry"),
            RosterError::RfpMismatch => f.write_str("genesis does not match pinned RFP"),
            RosterError::DoubleGenesis => f.write_str("genesis op past seq 0"),
            RosterError::BadSeq => f.write_str("non-sequential sequence number"),
            RosterError::ChainBreak => f.write_str("prev hash does not chain"),
            RosterError::NotMember => f.write_str("entry signed by a non-member (succession)"),
            RosterError::BadSignature => f.write_str("entry signature invalid"),
            RosterError::Rollback => f.write_str("sigchain rolled back below frontier"),
            RosterError::Sig(e) => write!(f, "sig: {e}"),
        }
    }
}

impl std::error::Error for RosterError {}
impl From<secsec_sig::SigError> for RosterError {
    fn from(e: secsec_sig::SigError) -> Self {
        RosterError::Sig(e)
    }
}

fn encode_op(w: &mut Writer, op: &Op) {
    match op {
        Op::Genesis { pubkey, mk_commit } => {
            w.u8(0).bytes(pubkey).raw(mk_commit);
        }
        Op::AddDevice { pubkey, mk_commit } => {
            w.u8(1).bytes(pubkey).raw(mk_commit);
        }
        Op::RevokeDevice { device } => {
            w.u8(2).raw(device);
        }
        Op::Rotate { mk_commit } => {
            w.u8(3).raw(mk_commit);
        }
        Op::SetMinAlgo { min_algo } => {
            w.u8(4).u8(*min_algo);
        }
    }
}

/// The signed portion: `seq ‖ prev ‖ op ‖ ts ‖ signer` (§8.1).
fn signed_bytes(seq: u64, prev: &[u8; 32], op: &Op, ts: u64, signer: &DeviceId) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(seq).raw(prev);
    encode_op(&mut w, op);
    w.u64(ts).raw(signer);
    w.finish()
}

/// The full entry (signed portion + signature), as hashed for the chain.
fn full_bytes(e: &Entry) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(e.seq).raw(&e.prev);
    encode_op(&mut w, &e.op);
    w.u64(e.ts).raw(&e.signer).bytes(&e.sig);
    w.finish()
}

/// BLAKE3 of the full entry — the chain link `prev` and the genesis RFP.
#[must_use]
pub fn entry_hash(e: &Entry) -> [u8; 32] {
    *blake3::hash(&full_bytes(e)).as_bytes()
}

/// Create the genesis entry (seq 0, self-signed by device-1). Returns `(entry, rfp)`.
pub fn genesis(
    device: &DeviceKey,
    mk_commit: MkCommit,
    ts: u64,
) -> Result<(Entry, [u8; 32]), RosterError> {
    let signer = device.device_id()?;
    let pubkey = device.public().to_canonical()?;
    let op = Op::Genesis { pubkey, mk_commit };
    let sig = device.sign(NS_ROSTER, &signed_bytes(0, &[0u8; 32], &op, ts, &signer))?;
    let entry = Entry {
        seq: 0,
        prev: [0u8; 32],
        op,
        ts,
        signer,
        sig,
    };
    let rfp = entry_hash(&entry);
    Ok((entry, rfp))
}

/// Append a new entry after `prev_entry`, signed by `signer` (who must be a current member for the
/// resulting chain to fold). Computes `seq`/`prev` automatically.
pub fn append(
    prev_entry: &Entry,
    op: Op,
    signer: &DeviceKey,
    ts: u64,
) -> Result<Entry, RosterError> {
    let seq = prev_entry.seq + 1;
    let prev = entry_hash(prev_entry);
    let signer_id = signer.device_id()?;
    let sig = signer.sign(NS_ROSTER, &signed_bytes(seq, &prev, &op, ts, &signer_id))?;
    Ok(Entry {
        seq,
        prev,
        op,
        ts,
        signer: signer_id,
        sig,
    })
}

/// The folded roster state (§8.1).
pub struct State {
    /// Current member device ids → their public keys.
    pub members: BTreeMap<DeviceId, DevicePublic>,
    /// Current generation (`#Rotate + 1`).
    pub generation: u32,
    /// Minimum algorithm id (max over `SetMinAlgo`).
    pub min_algo: u8,
    /// Per-generation `mk_commit` recorded by genesis/rotate.
    pub mk_commits: BTreeMap<u32, MkCommit>,
}

fn verify_entry_sig(pubkey: &DevicePublic, e: &Entry) -> Result<(), RosterError> {
    pubkey
        .verify(
            NS_ROSTER,
            &signed_bytes(e.seq, &e.prev, &e.op, e.ts, &e.signer),
            &e.sig,
        )
        .map_err(|_| RosterError::BadSignature)
}

/// Fold and fully validate a sigchain against the pinned `rfp`. Enforces genesis = RFP,
/// sequential seqs, the `prev` hash chain, per-entry signatures, and **succession** (each signer
/// must be a current member of the prefix). Returns the resulting [`State`].
pub fn fold(entries: &[Entry], rfp: &[u8; 32]) -> Result<State, RosterError> {
    let g = entries.first().ok_or(RosterError::Empty)?;
    if g.seq != 0 || g.prev != [0u8; 32] {
        return Err(RosterError::BadGenesis);
    }
    if entry_hash(g) != *rfp {
        return Err(RosterError::RfpMismatch);
    }
    let (gpub, gmk) = match &g.op {
        Op::Genesis { pubkey, mk_commit } => (DevicePublic::from_canonical(pubkey)?, *mk_commit),
        _ => return Err(RosterError::BadGenesis),
    };
    // Genesis must be self-signed by device-1 (signer id == the embedded pubkey's id).
    if g.signer != gpub.device_id()? {
        return Err(RosterError::BadGenesis);
    }
    verify_entry_sig(&gpub, g)?;

    let mut st = State {
        members: BTreeMap::new(),
        generation: 1,
        min_algo: secsec_frame::MIN_ALGO_ID,
        mk_commits: BTreeMap::new(),
    };
    st.members.insert(g.signer, gpub);
    st.mk_commits.insert(1, gmk);

    for (i, e) in entries.iter().enumerate().skip(1) {
        if e.seq != i as u64 {
            return Err(RosterError::BadSeq);
        }
        if e.prev != entry_hash(&entries[i - 1]) {
            return Err(RosterError::ChainBreak);
        }
        // Succession: the signer must be a current member of the state so far.
        let signer_pub = st.members.get(&e.signer).ok_or(RosterError::NotMember)?;
        verify_entry_sig(signer_pub, e)?;

        match &e.op {
            Op::Genesis { .. } => return Err(RosterError::DoubleGenesis),
            Op::AddDevice {
                pubkey,
                mk_commit: _,
            } => {
                let p = DevicePublic::from_canonical(pubkey)?;
                st.members.insert(p.device_id()?, p);
            }
            Op::RevokeDevice { device } => {
                st.members.remove(device);
            }
            Op::Rotate { mk_commit } => {
                st.generation += 1;
                st.mk_commits.insert(st.generation, *mk_commit);
            }
            Op::SetMinAlgo { min_algo } => {
                if *min_algo > st.min_algo {
                    st.min_algo = *min_algo;
                }
            }
        }
    }
    Ok(st)
}

/// A persisted anti-rollback frontier (§8.1): the highest accepted seq and that entry's hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frontier {
    /// Highest accepted sequence number.
    pub max_seq: u64,
    /// Hash of the entry at `max_seq`.
    pub tip_hash: [u8; 32],
}

/// The frontier of a (validated) chain.
#[must_use]
pub fn frontier_of(entries: &[Entry]) -> Option<Frontier> {
    entries.last().map(|last| Frontier {
        max_seq: last.seq,
        tip_hash: entry_hash(last),
    })
}

/// Reject a fetched chain that rolls back below `frontier` (§8.1 anti-rollback): it must be at
/// least as long, and the entry at the frontier's `max_seq` must hash to the stored `tip_hash`
/// (the tip-hash consistency check — a chain re-forked from an earlier point is caught here).
pub fn check_frontier(entries: &[Entry], frontier: &Frontier) -> Result<(), RosterError> {
    let idx = frontier.max_seq as usize;
    if entries.len() <= idx {
        return Err(RosterError::Rollback);
    }
    if entry_hash(&entries[idx]) != frontier.tip_hash {
        return Err(RosterError::Rollback);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MK: MkCommit = [0xAA; 32];

    fn pubkey_of(d: &DeviceKey) -> Vec<u8> {
        d.public().to_canonical().unwrap()
    }

    /// device-1 genesis, then a list of appended ops, returns (entries, rfp).
    fn chain(d1: &DeviceKey, ops: Vec<(Op, &DeviceKey)>) -> (Vec<Entry>, [u8; 32]) {
        let (g, rfp) = genesis(d1, MK, 0).unwrap();
        let mut entries = vec![g];
        for (op, signer) in ops {
            let e = append(entries.last().unwrap(), op, signer, 0).unwrap();
            entries.push(e);
        }
        (entries, rfp)
    }

    #[test]
    fn fold_genesis_only() {
        let d1 = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(&d1, vec![]);
        let st = fold(&entries, &rfp).unwrap();
        assert_eq!(st.generation, 1);
        assert!(st.members.contains_key(&d1.device_id().unwrap()));
        assert_eq!(st.members.len(), 1);
        assert_eq!(st.mk_commits.get(&1), Some(&MK));
    }

    #[test]
    fn add_revoke_rotate_setminalgo() {
        let d1 = DeviceKey::generate().unwrap();
        let d2 = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(
            &d1,
            vec![
                (
                    Op::AddDevice {
                        pubkey: pubkey_of(&d2),
                        mk_commit: MK,
                    },
                    &d1,
                ),
                (
                    Op::Rotate {
                        mk_commit: [0xBB; 32],
                    },
                    &d1,
                ),
                (Op::SetMinAlgo { min_algo: 2 }, &d2), // d2 is now a member, may sign
                (
                    Op::RevokeDevice {
                        device: d2.device_id().unwrap(),
                    },
                    &d1,
                ),
            ],
        );
        let st = fold(&entries, &rfp).unwrap();
        assert_eq!(st.generation, 2);
        assert_eq!(st.min_algo, 2);
        assert!(st.members.contains_key(&d1.device_id().unwrap()));
        assert!(
            !st.members.contains_key(&d2.device_id().unwrap()),
            "d2 revoked"
        );
        assert_eq!(st.mk_commits.get(&2), Some(&[0xBB; 32]));
    }

    #[test]
    fn non_member_cannot_sign() {
        let d1 = DeviceKey::generate().unwrap();
        let d3 = DeviceKey::generate().unwrap(); // never added
        let (entries, rfp) = chain(&d1, vec![(Op::SetMinAlgo { min_algo: 2 }, &d3)]);
        assert!(matches!(fold(&entries, &rfp), Err(RosterError::NotMember)));
    }

    #[test]
    fn revoked_device_cannot_sign_afterwards() {
        let d1 = DeviceKey::generate().unwrap();
        let d2 = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(
            &d1,
            vec![
                (
                    Op::AddDevice {
                        pubkey: pubkey_of(&d2),
                        mk_commit: MK,
                    },
                    &d1,
                ),
                (
                    Op::RevokeDevice {
                        device: d2.device_id().unwrap(),
                    },
                    &d1,
                ),
                (Op::SetMinAlgo { min_algo: 2 }, &d2), // d2 revoked -> must fail succession
            ],
        );
        assert!(matches!(fold(&entries, &rfp), Err(RosterError::NotMember)));
    }

    #[test]
    fn rfp_mismatch_rejected() {
        let d1 = DeviceKey::generate().unwrap();
        let (entries, _rfp) = chain(&d1, vec![]);
        assert!(matches!(
            fold(&entries, &[0u8; 32]),
            Err(RosterError::RfpMismatch)
        ));
    }

    #[test]
    fn chain_break_rejected() {
        let d1 = DeviceKey::generate().unwrap();
        let d2 = DeviceKey::generate().unwrap();
        let (mut entries, rfp) = chain(
            &d1,
            vec![(
                Op::AddDevice {
                    pubkey: pubkey_of(&d2),
                    mk_commit: MK,
                },
                &d1,
            )],
        );
        entries[1].prev[0] ^= 0x01;
        assert!(matches!(fold(&entries, &rfp), Err(RosterError::ChainBreak)));
    }

    #[test]
    fn bad_signature_rejected() {
        let d1 = DeviceKey::generate().unwrap();
        let (mut entries, rfp) = chain(&d1, vec![(Op::SetMinAlgo { min_algo: 2 }, &d1)]);
        *entries[1].sig.last_mut().unwrap() ^= 0x01;
        // tampering the sig also breaks the chain hash of later entries, but here it's the tip;
        // the signature check must reject it.
        assert!(matches!(
            fold(&entries, &rfp),
            Err(RosterError::BadSignature)
        ));
    }

    #[test]
    fn frontier_blocks_rollback() {
        let d1 = DeviceKey::generate().unwrap();
        let d2 = DeviceKey::generate().unwrap();
        let (entries, _rfp) = chain(
            &d1,
            vec![
                (
                    Op::AddDevice {
                        pubkey: pubkey_of(&d2),
                        mk_commit: MK,
                    },
                    &d1,
                ),
                (
                    Op::RevokeDevice {
                        device: d2.device_id().unwrap(),
                    },
                    &d1,
                ),
            ],
        );
        let frontier = frontier_of(&entries).unwrap();
        assert_eq!(frontier.max_seq, 2);
        // Full chain satisfies the frontier.
        assert!(check_frontier(&entries, &frontier).is_ok());
        // A rolled-back (truncated) chain that drops the revoke is rejected.
        let truncated = &entries[..2];
        assert!(matches!(
            check_frontier(truncated, &frontier),
            Err(RosterError::Rollback)
        ));
    }
}
