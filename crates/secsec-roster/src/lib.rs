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

use secsec_canon::{verify_reencode, CanonError, Reader, Writer};
use secsec_frame::{
    assemble_blob, parse_blob, Frame, FrameError, ObjType, CTX_TAG_LEN, FRAME_LEN,
    MAX_ROSTER_ENTRY_SIZE,
};
use secsec_kdf::{roster_entry_key, roster_keyhist_key, SecretKey};
use secsec_sig::{DeviceId, DeviceKey, DevicePublic, NS_ROSTER};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

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
    /// An entry's encoded op carried an unknown tag.
    BadOp,
    /// Strict canonical decode failed (truncation, over-long field, trailing bytes, or
    /// non-canonical re-encode).
    Canon(CanonError),
    /// The stored entry's FRAME was malformed or did not match the expected `(gen, type)` (§18).
    Frame(FrameError),
    /// The per-entry AEAD failed to open (wrong key/generation, or tampered ciphertext/commitment).
    Aead,
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
            RosterError::BadOp => f.write_str("unknown roster op tag"),
            RosterError::Canon(e) => write!(f, "canon: {e}"),
            RosterError::Frame(e) => write!(f, "frame: {e}"),
            RosterError::Aead => f.write_str("roster entry AEAD open failed"),
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
impl From<CanonError> for RosterError {
    fn from(e: CanonError) -> Self {
        RosterError::Canon(e)
    }
}
impl From<FrameError> for RosterError {
    fn from(e: FrameError) -> Self {
        RosterError::Frame(e)
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

/// The canonical wire encoding of a full entry (signed portion + signature). This is the byte
/// string that is hashed for the chain (`prev`/RFP) and that the per-entry AEAD layer (§9.5)
/// encrypts. Field order: `seq ‖ prev ‖ op ‖ ts ‖ signer ‖ sig`.
#[must_use]
pub fn encode_entry(e: &Entry) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(e.seq).raw(&e.prev);
    encode_op(&mut w, &e.op);
    w.u64(e.ts).raw(&e.signer).bytes(&e.sig);
    w.finish()
}

fn decode_op(r: &mut Reader<'_>) -> Result<Op, RosterError> {
    let tag = r.u8()?;
    Ok(match tag {
        0 => {
            let pubkey = r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec();
            Op::Genesis {
                pubkey,
                mk_commit: read32(r)?,
            }
        }
        1 => {
            let pubkey = r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec();
            Op::AddDevice {
                pubkey,
                mk_commit: read32(r)?,
            }
        }
        2 => Op::RevokeDevice { device: read32(r)? },
        3 => Op::Rotate {
            mk_commit: read32(r)?,
        },
        4 => Op::SetMinAlgo { min_algo: r.u8()? },
        _ => return Err(RosterError::BadOp),
    })
}

fn read32(r: &mut Reader<'_>) -> Result<[u8; 32], RosterError> {
    let mut out = [0u8; 32];
    out.copy_from_slice(r.raw(32)?);
    Ok(out)
}

/// Strictly decode a full entry from its canonical wire bytes (inverse of [`encode_entry`]).
///
/// Rejects truncation, over-long length-prefixed fields (bounded by
/// [`secsec_frame::MAX_ROSTER_ENTRY_SIZE`]), trailing bytes, and — via the §9.3 re-encode guard —
/// any non-canonical encoding of an otherwise-valid entry. This is the malleability boundary: the
/// bytes a signature/hash is computed over are the unique canonical encoding of the parsed value.
pub fn decode_entry(bytes: &[u8]) -> Result<Entry, RosterError> {
    let mut r = Reader::new(bytes);
    let seq = r.u64()?;
    let prev = read32(&mut r)?;
    let op = decode_op(&mut r)?;
    let ts = r.u64()?;
    let signer = read32(&mut r)?;
    let sig = r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec();
    r.finish()?;
    let entry = Entry {
        seq,
        prev,
        op,
        ts,
        signer,
        sig,
    };
    verify_reencode(bytes, &entry, encode_entry)?;
    Ok(entry)
}

/// BLAKE3 of the full entry — the chain link `prev` and the genesis RFP.
#[must_use]
pub fn entry_hash(e: &Entry) -> [u8; 32] {
    *blake3::hash(&encode_entry(e)).as_bytes()
}

// ---------------------------------------------------------------------------
// Per-entry AEAD (§9.5 "Roster entry AEAD"): the entries are stored on the
// untrusted server encrypted under a per-sequence subkey of `roster_key_g`.
// ---------------------------------------------------------------------------

/// `AD_roster = FRAME_roster ‖ le64(seq)` (§9.5). The 11-byte FRAME binds `type=roster` and the
/// generation `g`; `seq` is appended because the FRAME does not carry it. This is the analogue of
/// the object AEAD's `FRAME ‖ id`.
fn ad_roster(frame: &Frame, seq: u64) -> [u8; FRAME_LEN + 8] {
    let mut ad = [0u8; FRAME_LEN + 8];
    ad[..FRAME_LEN].copy_from_slice(&frame.encode());
    ad[FRAME_LEN..].copy_from_slice(&seq.to_le_bytes());
    ad
}

/// Encrypt a canonical entry plaintext ([`encode_entry`] bytes) for storage under generation `gen`
/// at sequence `seq`, using `roster_key_g`. Returns the stored blob `FRAME ‖ ctx_tag ‖ ciphertext`
/// (§9.1/§9.5). The per-entry key `k_roster_entry[g][seq]` is unique per `(roster_key_g, seq)`, so
/// the fixed zero nonce is safe; the CTX construction gives CMT-4.
#[must_use]
pub fn seal_entry(roster_key_g: &[u8; 32], gen: u32, seq: u64, entry_plaintext: &[u8]) -> Vec<u8> {
    let k = roster_entry_key(roster_key_g, seq);
    let frame = Frame::v1(gen, ObjType::RosterEntry);
    let ad = ad_roster(&frame, seq);
    let (ctx_tag, ct) = secsec_aead::seal(&k, &ad, entry_plaintext);
    assemble_blob(&frame, &ctx_tag, &ct)
}

/// Decrypt a stored roster entry blob written under generation `gen` at sequence `seq`, using
/// `roster_key_g`. Validates the stored FRAME against the expected `(gen, type=roster)` (§18) before
/// any AEAD work, then opens with `AD_roster`. Returns the canonical entry plaintext on success.
///
/// The caller is responsible for deriving `roster_key_g` for the `gen` carried in the blob's
/// (plaintext, server-readable) FRAME — typically via the §8.2 key-history peel — and then for
/// [`decode_entry`]-ing and chain-verifying the returned bytes.
pub fn open_entry(
    roster_key_g: &[u8; 32],
    gen: u32,
    seq: u64,
    stored: &[u8],
) -> Result<Vec<u8>, RosterError> {
    let frame = Frame::v1(gen, ObjType::RosterEntry);
    let (ctx_tag, ct) = parse_blob(stored, &frame)?;
    let ad = ad_roster(&frame, seq);
    let k = roster_entry_key(roster_key_g, seq);
    secsec_aead::open(&k, &ad, ctx_tag, ct).map_err(|_| RosterError::Aead)
}

// ---------------------------------------------------------------------------
// Roster-key history (§8.2 "Roster-key history (never trimmed)"): a forward
// chain of wraps that lets a current member peel `roster_key_current → … →
// roster_key_1`, so the *whole* sigchain (every generation) can be decrypted
// and signature-verified at cold start. A revoked device, lacking the current
// roster key, cannot peel forward — roster forward secrecy (P11).
// ---------------------------------------------------------------------------

/// A 256-bit roster key, the plaintext wrapped by the roster-key history.
const ROSTER_KEY_LEN: usize = 32;
/// Stored size of one `roster_keyhist_g` wrap: `ctx_tag(32) ‖ ct(32)` (§8.2, "64 bytes total").
/// Unlike a normal blob there is **no** FRAME prefix — `g` is known from the storage path and the
/// `FRAME_rkh` AD is reconstructed by the reader.
pub const ROSTER_KEYHIST_LEN: usize = CTX_TAG_LEN + ROSTER_KEY_LEN;

/// Wrap `roster_key_g` so it can be recovered by a holder of `roster_key_{g+1}` (the next
/// generation). Keyed by `k_rkh_g = derive_key("secsec-roster-keyhist-v1", roster_key_{g+1} ‖
/// le32(g))`, AD = `FRAME_rkh(type=roster-keyhist, gen=g)`. Returns the bare
/// [`ROSTER_KEYHIST_LEN`]-byte `ctx_tag ‖ ct`.
#[must_use]
pub fn seal_roster_keyhist(
    roster_key_next: &[u8; 32],
    g: u32,
    roster_key_g: &[u8; 32],
) -> [u8; ROSTER_KEYHIST_LEN] {
    let k = roster_keyhist_key(roster_key_next, g);
    let ad = Frame::v1(g, ObjType::RosterKeyhist).encode();
    let (ctx_tag, ct) = secsec_aead::seal(&k, &ad, roster_key_g);
    let mut out = [0u8; ROSTER_KEYHIST_LEN];
    out[..CTX_TAG_LEN].copy_from_slice(&ctx_tag);
    out[CTX_TAG_LEN..].copy_from_slice(&ct);
    out
}

/// Recover `roster_key_g` from a `roster_keyhist_g` wrap using `roster_key_{g+1}`. Verifies the
/// CMT-4 commitment before releasing the key. Returns the zeroizing-wrapped recovered key.
pub fn open_roster_keyhist(
    roster_key_next: &[u8; 32],
    g: u32,
    stored: &[u8],
) -> Result<SecretKey, RosterError> {
    if stored.len() != ROSTER_KEYHIST_LEN {
        return Err(RosterError::Aead);
    }
    let ctx_tag: &[u8; CTX_TAG_LEN] = stored[..CTX_TAG_LEN]
        .try_into()
        .expect("slice is exactly CTX_TAG_LEN");
    let ct = &stored[CTX_TAG_LEN..];
    let ad = Frame::v1(g, ObjType::RosterKeyhist).encode();
    let k = roster_keyhist_key(roster_key_next, g);
    let mut pt = secsec_aead::open(&k, &ad, ctx_tag, ct).map_err(|_| RosterError::Aead)?;
    if pt.len() != ROSTER_KEY_LEN {
        pt.zeroize();
        return Err(RosterError::Aead);
    }
    let mut out = Zeroizing::new([0u8; ROSTER_KEY_LEN]);
    out.copy_from_slice(&pt);
    pt.zeroize();
    Ok(out)
}

/// Peel the entire roster-key history: starting from `roster_key_current` (generation
/// `current_gen`), recover `roster_key_g` for every `g` in `1..current_gen` using the wraps in
/// `history` (keyed by generation `g`, each [`ROSTER_KEYHIST_LEN`] bytes). Returns a map of
/// `g → roster_key_g` for all `1..=current_gen` (including `current_gen` itself).
///
/// `history` MUST contain a wrap for every `g` in `1..current_gen`; a missing or unopenable wrap
/// aborts the peel (a current member can always produce the never-trimmed chain). The peel proceeds
/// downward because decrypting `roster_keyhist_g` requires `roster_key_{g+1}`.
pub fn peel_roster_keys(
    roster_key_current: &[u8; 32],
    current_gen: u32,
    history: &BTreeMap<u32, Vec<u8>>,
) -> Result<BTreeMap<u32, SecretKey>, RosterError> {
    let mut keys: BTreeMap<u32, SecretKey> = BTreeMap::new();
    keys.insert(current_gen, Zeroizing::new(*roster_key_current));
    let mut g = current_gen;
    while g > 1 {
        let next = keys
            .get(&g)
            .expect("roster_key for current peel generation is present");
        let wrap = history.get(&(g - 1)).ok_or(RosterError::Aead)?;
        let prev = open_roster_keyhist(next, g - 1, wrap)?;
        keys.insert(g - 1, prev);
        g -= 1;
    }
    Ok(keys)
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

    #[test]
    fn codec_round_trips_every_op_and_preserves_hash() {
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
                    Op::Rotate {
                        mk_commit: [0xBB; 32],
                    },
                    &d1,
                ),
                (Op::SetMinAlgo { min_algo: 9 }, &d2),
                (
                    Op::RevokeDevice {
                        device: d2.device_id().unwrap(),
                    },
                    &d1,
                ),
            ],
        );
        // Genesis + all four other op variants survive a decode→encode round trip byte-for-byte,
        // and the chain hash is identical to the in-memory entry's hash.
        for e in &entries {
            let bytes = encode_entry(e);
            let decoded = decode_entry(&bytes).unwrap();
            assert_eq!(&decoded, e);
            assert_eq!(encode_entry(&decoded), bytes);
            assert_eq!(entry_hash(&decoded), entry_hash(e));
        }
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let d1 = DeviceKey::generate().unwrap();
        let (g, _rfp) = genesis(&d1, MK, 0).unwrap();
        let mut bytes = encode_entry(&g);
        bytes.push(0x00);
        assert!(matches!(
            decode_entry(&bytes),
            Err(RosterError::Canon(CanonError::TrailingBytes { .. }))
        ));
    }

    #[test]
    fn decode_rejects_truncation() {
        let d1 = DeviceKey::generate().unwrap();
        let (g, _rfp) = genesis(&d1, MK, 0).unwrap();
        let bytes = encode_entry(&g);
        assert!(matches!(
            decode_entry(&bytes[..bytes.len() - 1]),
            Err(RosterError::Canon(_))
        ));
    }

    #[test]
    fn decode_rejects_unknown_op_tag() {
        let d1 = DeviceKey::generate().unwrap();
        let (g, _rfp) = genesis(&d1, MK, 0).unwrap();
        let mut bytes = encode_entry(&g);
        // The op tag sits right after seq(8) + prev(32). Flip Genesis(0) to an unknown tag.
        bytes[40] = 0xFF;
        assert!(matches!(decode_entry(&bytes), Err(RosterError::BadOp)));
    }

    // ---- Per-entry AEAD (§9.5) ----

    use secsec_kdf::MasterKey;

    fn roster_key_for(gen: u32, key: [u8; 32]) -> secsec_kdf::SecretKey {
        MasterKey::new(gen, key).roster_key()
    }

    #[test]
    fn entry_aead_round_trip() {
        let d1 = DeviceKey::generate().unwrap();
        let (g, _rfp) = genesis(&d1, MK, 0).unwrap();
        let pt = encode_entry(&g);
        let rk = roster_key_for(1, [0x33; 32]);

        let blob = seal_entry(&rk, 1, 0, &pt);
        // The blob is FRAME(11) ‖ ctx_tag(32) ‖ ct and reveals nothing of the plaintext.
        assert_ne!(&blob[FRAME_LEN + 32..], &pt[..]);

        let got = open_entry(&rk, 1, 0, &blob).unwrap();
        assert_eq!(got, pt);
        // ...and the recovered bytes decode back to the original entry.
        assert_eq!(decode_entry(&got).unwrap(), g);
    }

    #[test]
    fn entry_aead_wrong_generation_is_frame_mismatch() {
        let d1 = DeviceKey::generate().unwrap();
        let (g, _rfp) = genesis(&d1, MK, 0).unwrap();
        let rk = roster_key_for(1, [0x33; 32]);
        let blob = seal_entry(&rk, 1, 0, &encode_entry(&g));
        // Opening as a different generation must fail at the FRAME check (§18) before any AEAD work.
        assert!(matches!(
            open_entry(&rk, 2, 0, &blob),
            Err(RosterError::Frame(FrameError::FrameMismatch))
        ));
    }

    #[test]
    fn entry_aead_wrong_seq_rejected() {
        let d1 = DeviceKey::generate().unwrap();
        let (g, _rfp) = genesis(&d1, MK, 0).unwrap();
        let rk = roster_key_for(1, [0x33; 32]);
        let blob = seal_entry(&rk, 1, 7, &encode_entry(&g));
        // Same gen, wrong seq: both the per-entry key and AD differ -> AEAD open fails.
        assert!(matches!(
            open_entry(&rk, 1, 8, &blob),
            Err(RosterError::Aead)
        ));
    }

    #[test]
    fn entry_aead_wrong_key_rejected() {
        let d1 = DeviceKey::generate().unwrap();
        let (g, _rfp) = genesis(&d1, MK, 0).unwrap();
        let rk = roster_key_for(1, [0x33; 32]);
        let other = roster_key_for(1, [0x44; 32]);
        let blob = seal_entry(&rk, 1, 0, &encode_entry(&g));
        assert!(matches!(
            open_entry(&other, 1, 0, &blob),
            Err(RosterError::Aead)
        ));
    }

    #[test]
    fn entry_aead_tamper_rejected() {
        let d1 = DeviceKey::generate().unwrap();
        let (g, _rfp) = genesis(&d1, MK, 0).unwrap();
        let rk = roster_key_for(1, [0x33; 32]);
        let mut blob = seal_entry(&rk, 1, 0, &encode_entry(&g));
        // Flip a ciphertext byte (past FRAME + ctx_tag) -> commitment mismatch.
        *blob.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            open_entry(&rk, 1, 0, &blob),
            Err(RosterError::Aead)
        ));
    }

    // ---- Roster-key history (§8.2) ----

    #[test]
    fn roster_keyhist_round_trip_is_64_bytes() {
        let rk1 = roster_key_for(1, [0x01; 32]);
        let rk2 = roster_key_for(2, [0x02; 32]);
        let wrap = seal_roster_keyhist(&rk2, 1, &rk1);
        assert_eq!(wrap.len(), ROSTER_KEYHIST_LEN);
        assert_eq!(ROSTER_KEYHIST_LEN, 64);
        let got = open_roster_keyhist(&rk2, 1, &wrap).unwrap();
        assert_eq!(&got[..], &rk1[..]);
    }

    #[test]
    fn roster_keyhist_wrong_next_key_rejected() {
        let rk1 = roster_key_for(1, [0x01; 32]);
        let rk2 = roster_key_for(2, [0x02; 32]);
        let wrong = roster_key_for(2, [0x99; 32]);
        let wrap = seal_roster_keyhist(&rk2, 1, &rk1);
        assert!(matches!(
            open_roster_keyhist(&wrong, 1, &wrap),
            Err(RosterError::Aead)
        ));
    }

    #[test]
    fn roster_keyhist_wrong_generation_rejected() {
        // The AD binds g; opening the g=1 wrap as g=2 must fail (FRAME_rkh mismatch in the AD).
        let rk1 = roster_key_for(1, [0x01; 32]);
        let rk2 = roster_key_for(2, [0x02; 32]);
        let wrap = seal_roster_keyhist(&rk2, 1, &rk1);
        assert!(matches!(
            open_roster_keyhist(&rk2, 2, &wrap),
            Err(RosterError::Aead)
        ));
    }

    #[test]
    fn roster_keyhist_tamper_and_bad_length_rejected() {
        let rk1 = roster_key_for(1, [0x01; 32]);
        let rk2 = roster_key_for(2, [0x02; 32]);
        let mut wrap = seal_roster_keyhist(&rk2, 1, &rk1);
        wrap[ROSTER_KEYHIST_LEN - 1] ^= 0x01;
        assert!(matches!(
            open_roster_keyhist(&rk2, 1, &wrap),
            Err(RosterError::Aead)
        ));
        assert!(matches!(
            open_roster_keyhist(&rk2, 1, &wrap[..ROSTER_KEYHIST_LEN - 1]),
            Err(RosterError::Aead)
        ));
    }

    #[test]
    fn peel_recovers_every_generation() {
        // Five generations with independent master keys; build the never-trimmed wrap chain.
        let n = 5u32;
        let rks: Vec<SecretKey> = (1..=n).map(|g| roster_key_for(g, [g as u8; 32])).collect();
        let mut history: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for g in 1..n {
            // wrap roster_key_g under roster_key_{g+1}
            let wrap = seal_roster_keyhist(&rks[g as usize], g, &rks[(g - 1) as usize]);
            history.insert(g, wrap.to_vec());
        }
        let peeled = peel_roster_keys(&rks[(n - 1) as usize], n, &history).unwrap();
        assert_eq!(peeled.len(), n as usize);
        for g in 1..=n {
            assert_eq!(&peeled[&g][..], &rks[(g - 1) as usize][..], "gen {g}");
        }
    }

    #[test]
    fn peel_aborts_on_missing_wrap() {
        let n = 3u32;
        let rks: Vec<SecretKey> = (1..=n).map(|g| roster_key_for(g, [g as u8; 32])).collect();
        let mut history: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        // Only provide the wrap for g=2, omit g=1.
        history.insert(2, seal_roster_keyhist(&rks[2], 2, &rks[1]).to_vec());
        assert!(matches!(
            peel_roster_keys(&rks[(n - 1) as usize], n, &history),
            Err(RosterError::Aead)
        ));
    }
}
