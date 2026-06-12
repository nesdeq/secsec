//! `secsec-roster` — the roster sigchain, the real ACL (`secsec-Design.md` §8).
//!
//! An append-only, hash-chained, SSHSIG-signed log; genesis hashes to the RFP (§5). [`fold`]
//! enforces **succession** (each entry's signer must be a current member of the prefix). Also here:
//! the per-entry AEAD (§9.5), the never-trimmed key histories and their peels (§8.2), the
//! cold-start bootstrap fold (§8.1), and the revoke⇒rotate op builder (§8.4). The anti-rollback
//! anchor is enforced by the client cold-start.

#![forbid(unsafe_code)]

use secsec_canon::{verify_reencode, CanonError, Reader, Writer};
use secsec_frame::{
    assemble_blob, parse_blob, Frame, FrameError, ObjType, CTX_TAG_LEN, FRAME_LEN,
    MAX_ROSTER_ENTRY_SIZE,
};
use secsec_kdf::{data_keyhist_key, roster_entry_key, roster_keyhist_key, MasterKey, SecretKey};
use secsec_sig::{DeviceId, DeviceKey, DevicePublic, NS_ROSTER};
use std::collections::{BTreeMap, BTreeSet};
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
        /// The device's **X-Wing public key** bytes (§8.3/§17), published so a granter can wrap the
        /// keyslot to it. Opaque here — the keyslot layer interprets it.
        enroll_pub: Vec<u8>,
    },
    /// Add a device: its canonical pubkey + the current generation's commitment.
    AddDevice {
        /// Canonical SSH encoding of the new device's public key.
        pubkey: Vec<u8>,
        /// `mk_commit_g` at the time of the grant.
        mk_commit: MkCommit,
        /// The new device's **X-Wing public key** bytes (§8.3/§17), as in [`Op::Genesis`].
        enroll_pub: Vec<u8>,
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
    /// Cold start: an entry's `FRAME.gen` had no peeled roster key (gen beyond `g_cur`, or a
    /// tip/`g_cur` mismatch) — a forged or inconsistent chain.
    BadGeneration,
    /// Cold start: the keyslot-recovered candidate key failed `mk_commit_{g_cur}` from the
    /// RFP-anchored chain (§7 step 3) — a forged keyslot / fake key.
    MkCommitMismatch,
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
            RosterError::BadGeneration => f.write_str("entry generation has no peeled roster key"),
            RosterError::MkCommitMismatch => {
                f.write_str("candidate key fails mk_commit from the RFP-anchored chain")
            }
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
        Op::Genesis {
            pubkey,
            mk_commit,
            enroll_pub,
        } => {
            w.u8(0).bytes(pubkey).raw(mk_commit).bytes(enroll_pub);
        }
        Op::AddDevice {
            pubkey,
            mk_commit,
            enroll_pub,
        } => {
            w.u8(1).bytes(pubkey).raw(mk_commit).bytes(enroll_pub);
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
            // Read in encode order: pubkey, mk_commit, enroll_pub.
            let pubkey = r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec();
            let mk_commit = read32(r)?;
            let enroll_pub = r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec();
            Op::Genesis {
                pubkey,
                mk_commit,
                enroll_pub,
            }
        }
        1 => {
            let pubkey = r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec();
            let mk_commit = read32(r)?;
            let enroll_pub = r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec();
            Op::AddDevice {
                pubkey,
                mk_commit,
                enroll_pub,
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

// ---- per-entry AEAD (§9.5 "Roster entry AEAD") ----

/// `AD_roster = FRAME_roster ‖ le64(seq)` (§9.5) — the FRAME binds type+gen, `seq` is appended.
fn ad_roster(frame: &Frame, seq: u64) -> [u8; FRAME_LEN + 8] {
    let mut ad = [0u8; FRAME_LEN + 8];
    ad[..FRAME_LEN].copy_from_slice(&frame.encode());
    ad[FRAME_LEN..].copy_from_slice(&seq.to_le_bytes());
    ad
}

/// Seal a canonical entry plaintext at `(gen, seq)` under `roster_key_g` → stored blob
/// `FRAME ‖ ctx_tag ‖ ct` (§9.5; the per-(key,seq) entry key makes the zero nonce safe).
#[must_use]
pub fn seal_entry(roster_key_g: &[u8; 32], gen: u32, seq: u64, entry_plaintext: &[u8]) -> Vec<u8> {
    let k = roster_entry_key(roster_key_g, seq);
    let frame = Frame::v1(gen, ObjType::RosterEntry);
    let ad = ad_roster(&frame, seq);
    let (ctx_tag, ct) = secsec_aead::seal(&k, &ad, entry_plaintext);
    assemble_blob(&frame, &ctx_tag, &ct)
}

/// Open a stored roster entry blob at `(gen, seq)`: expected-FRAME check (§18) then AEAD open.
/// The caller derives `roster_key_g` (peel, §8.2) and [`decode_entry`]s + chain-verifies the result.
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

// ---- roster-key history (§8.2; never trimmed — peels roster_key_current → roster_key_1) ----

/// A 256-bit roster key, the plaintext wrapped by the roster-key history.
const ROSTER_KEY_LEN: usize = 32;
/// Stored size of one `roster_keyhist_g` wrap: `ctx_tag(32) ‖ ct(32)` (§8.2). No FRAME prefix —
/// `g` comes from the storage path and the AD is reconstructed by the reader.
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

/// Peel the roster-key history downward from `roster_key_current`: returns `g → roster_key_g` for
/// all `1..=current_gen`. `history` MUST hold a wrap for every `g` in `1..current_gen`; a missing
/// or unopenable wrap aborts (a current member can always produce the never-trimmed chain).
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

// ---- DATA key-history (§8.2; peels master_key_current → master_key_1 for old-object reads) ----

/// Stored size of one DATA `keyhist_g` wrap: `ctx_tag(32) ‖ ct(32)` (§8.2). Same layout as the
/// roster-key history; no FRAME prefix (`g` comes from the storage path).
pub const DATA_KEYHIST_LEN: usize = CTX_TAG_LEN + 32;

/// Wrap `master_key_g` under `master_key_{g+1}` (§8.2): the CTX/CMT-4 seal with
/// AD = `FRAME(type=keyhist, gen=g)`; returns the bare `ctx_tag ‖ ct`.
#[must_use]
pub fn seal_data_keyhist(
    master_key_next: &[u8; 32],
    g: u32,
    master_key_g: &[u8; 32],
) -> [u8; DATA_KEYHIST_LEN] {
    let k = data_keyhist_key(master_key_next, g);
    let ad = Frame::v1(g, ObjType::Keyhist).encode();
    let (ctx_tag, ct) = secsec_aead::seal(&k, &ad, master_key_g);
    let mut out = [0u8; DATA_KEYHIST_LEN];
    out[..CTX_TAG_LEN].copy_from_slice(&ctx_tag);
    out[CTX_TAG_LEN..].copy_from_slice(&ct);
    out
}

/// Recover `master_key_g` from a DATA `keyhist_g` wrap using `master_key_{g+1}` (§8.2). Verifies the
/// CMT-4 commitment before releasing the key. Returns the generation-`g` [`MasterKey`].
pub fn open_data_keyhist(
    master_key_next: &[u8; 32],
    g: u32,
    stored: &[u8],
) -> Result<MasterKey, RosterError> {
    if stored.len() != DATA_KEYHIST_LEN {
        return Err(RosterError::Aead);
    }
    let ctx_tag: &[u8; CTX_TAG_LEN] = stored[..CTX_TAG_LEN]
        .try_into()
        .expect("slice is exactly CTX_TAG_LEN");
    let ct = &stored[CTX_TAG_LEN..];
    let ad = Frame::v1(g, ObjType::Keyhist).encode();
    let k = data_keyhist_key(master_key_next, g);
    let mut pt = secsec_aead::open(&k, &ad, ctx_tag, ct).map_err(|_| RosterError::Aead)?;
    if pt.len() != 32 {
        pt.zeroize();
        return Err(RosterError::Aead);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&pt);
    pt.zeroize();
    Ok(MasterKey::new(g, *key))
}

/// Peel the DATA key-history downward from `master_key_current`: returns `g → master_key_g` for
/// all `1..=current_gen`. A missing or unopenable wrap aborts.
pub fn peel_data_keys(
    master_key_current: &[u8; 32],
    current_gen: u32,
    history: &BTreeMap<u32, Vec<u8>>,
) -> Result<BTreeMap<u32, MasterKey>, RosterError> {
    let mut keys: BTreeMap<u32, MasterKey> = BTreeMap::new();
    keys.insert(
        current_gen,
        MasterKey::new(current_gen, *master_key_current),
    );
    let mut g = current_gen;
    while g > 1 {
        let next = Zeroizing::new(
            *keys
                .get(&g)
                .expect("master key for current peel generation is present")
                .expose_secret(),
        );
        let wrap = history.get(&(g - 1)).ok_or(RosterError::Aead)?;
        let prev = open_data_keyhist(&next, g - 1, wrap)?;
        keys.insert(g - 1, prev);
        g -= 1;
    }
    Ok(keys)
}

/// Create the genesis entry (seq 0, self-signed by device-1). Returns `(entry, rfp)`. `enroll_pub` is
/// device-1's X-Wing public key bytes (§8.3/§17).
pub fn genesis(
    device: &DeviceKey,
    enroll_pub: Vec<u8>,
    mk_commit: MkCommit,
    ts: u64,
) -> Result<(Entry, [u8; 32]), RosterError> {
    let signer = device.device_id()?;
    let pubkey = device.public().to_canonical()?;
    let op = Op::Genesis {
        pubkey,
        mk_commit,
        enroll_pub,
    };
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

/// Append a sequence of ops as a chain of signed entries after `prev_entry`, each linking to the
/// one before it (so the whole batch is a valid hash-chain extension). Used to emit the multi-op
/// `revoke⇒rotate` sequence from [`revoke_rotate_ops`] atomically in author order.
pub fn append_many(
    prev_entry: &Entry,
    ops: Vec<Op>,
    signer: &DeviceKey,
    ts: u64,
) -> Result<Vec<Entry>, RosterError> {
    let mut out: Vec<Entry> = Vec::with_capacity(ops.len());
    for op in ops {
        let prev = out.last().unwrap_or(prev_entry);
        out.push(append(prev, op, signer, ts)?);
    }
    Ok(out)
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
    /// For each current member added by an `AddDevice` (i.e. **not** genesis device-1), the device
    /// that authored that grant. Drives the revoke-before-add closure (§8.1). Cleared on revoke.
    pub added_by: BTreeMap<DeviceId, DeviceId>,
    /// For each member in [`added_by`], the `seq` of its (latest) `AddDevice` entry.
    pub added_at: BTreeMap<DeviceId, u64>,
    /// Per current member, the **X-Wing public key** bytes it published at enrollment (§8.3/§17), so
    /// a granter/rotation can wrap its keyslot to it. Cleared on revoke.
    pub enroll_pubs: BTreeMap<DeviceId, Vec<u8>>,
}

impl State {
    /// Whether `device` is a current member — the membership half of per-op auth (§9.6, §12).
    #[must_use]
    pub fn is_member(&self, device: &DeviceId) -> bool {
        self.members.contains_key(device)
    }
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
    let (gpub, gmk, g_enroll) = match &g.op {
        Op::Genesis {
            pubkey,
            mk_commit,
            enroll_pub,
        } => (
            DevicePublic::from_canonical(pubkey)?,
            *mk_commit,
            enroll_pub.clone(),
        ),
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
        added_by: BTreeMap::new(),
        added_at: BTreeMap::new(),
        enroll_pubs: BTreeMap::new(),
    };
    st.members.insert(g.signer, gpub);
    st.mk_commits.insert(1, gmk);
    if !g_enroll.is_empty() {
        st.enroll_pubs.insert(g.signer, g_enroll);
    }

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
                enroll_pub,
            } => {
                let p = DevicePublic::from_canonical(pubkey)?;
                let id = p.device_id()?;
                st.members.insert(id, p);
                // Record provenance for the revoke-before-add closure (§8.1). A re-add overwrites
                // the prior grant, so the latest adder/seq wins.
                st.added_by.insert(id, e.signer);
                st.added_at.insert(id, e.seq);
                if enroll_pub.is_empty() {
                    st.enroll_pubs.remove(&id);
                } else {
                    st.enroll_pubs.insert(id, enroll_pub.clone());
                }
            }
            Op::RevokeDevice { device } => {
                st.members.remove(device);
                st.added_by.remove(device);
                st.added_at.remove(device);
                st.enroll_pubs.remove(device);
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

/// The §8.1 cold-start fold for a device with no local state: peel the roster keys, decrypt +
/// strictly decode every stored entry by its authenticated `FRAME.gen`, [`fold`] (RFP + chain +
/// signatures + succession), then verify the keyslot-recovered candidate against `mk_commit_{g_cur}`
/// (§7 step 3 — the forged-keyslot / fake-universe defense). Returns the folded [`State`] and the
/// now-authenticated [`MasterKey`]. The caller unwraps the keyslot and reads `g_cur` from the tip's
/// `FRAME.gen` first.
pub fn cold_start_fold(
    candidate_master_key: &[u8; 32],
    g_cur: u32,
    rfp: &[u8; 32],
    roster_keyhist: &BTreeMap<u32, Vec<u8>>,
    stored_entries: &[Vec<u8>],
) -> Result<(State, MasterKey), RosterError> {
    let mk = MasterKey::new(g_cur, *candidate_master_key);

    // §8.1 step 1 invariant: the tip's plaintext FRAME.gen is the current generation.
    let tip = stored_entries.last().ok_or(RosterError::Empty)?;
    let tip_frame = tip
        .get(..FRAME_LEN)
        .ok_or(RosterError::Frame(FrameError::ShortBlob))?;
    if Frame::decode(tip_frame)?.gen != g_cur {
        return Err(RosterError::BadGeneration);
    }

    // (1) derive roster_key_{g_cur} and peel back to roster_key_1.
    let roster_key_cur = mk.roster_key();
    let roster_keys = peel_roster_keys(&roster_key_cur, g_cur, roster_keyhist)?;

    // (2) decrypt + decode every entry, selecting the key by each blob's authenticated FRAME.gen.
    let mut entries = Vec::with_capacity(stored_entries.len());
    for (seq, blob) in stored_entries.iter().enumerate() {
        let frame_bytes = blob
            .get(..FRAME_LEN)
            .ok_or(RosterError::Frame(FrameError::ShortBlob))?;
        let gen = Frame::decode(frame_bytes)?.gen;
        let rk = roster_keys.get(&gen).ok_or(RosterError::BadGeneration)?;
        let plaintext = open_entry(rk, gen, seq as u64, blob)?;
        entries.push(decode_entry(&plaintext)?);
    }

    // (3) fold: genesis = RFP, prev-chain, signatures, succession.
    let state = fold(&entries, rfp)?;

    // (4) authenticity (§7 step 3): the candidate must match mk_commit_{g_cur} from the chain.
    let expected = *state
        .mk_commits
        .get(&g_cur)
        .ok_or(RosterError::BadGeneration)?;
    if mk.mk_commit() != expected {
        return Err(RosterError::MkCommitMismatch);
    }
    Ok((state, mk))
}

/// One level of the revoke-before-add closure (§8.1, §8.4 step 1): current members `revoked`
/// granted at/after `after_seq` (the revoker's last-authored-or-witnessed seq). Sorted, so the
/// follow-on `RevokeDevice` entries are deterministic.
#[must_use]
pub fn devices_added_by(state: &State, revoked: &DeviceId, after_seq: u64) -> Vec<DeviceId> {
    state
        .added_by
        .iter()
        .filter(|(id, adder)| {
            *adder == revoked && state.added_at.get(*id).is_some_and(|s| *s >= after_seq)
        })
        .map(|(id, _)| *id)
        .collect()
}

/// The **transitive** revoke-before-add closure (§8.1, §8.4 step 1): every current member reachable
/// from `revoked` through the add-by graph whose own grant is at/after `after_seq` (one level misses
/// the nested sleeper, §8.1). The traversal walks the whole subtree — through pre-`after_seq`
/// children — but collects only at/after-`after_seq` grants; filtering the *traversal* instead
/// would let a pre-reference child shield its post-reference subtree. Excludes `revoked`; sorted.
#[must_use]
pub fn revoke_closure(state: &State, revoked: &DeviceId, after_seq: u64) -> Vec<DeviceId> {
    let mut result: BTreeSet<DeviceId> = BTreeSet::new();
    let mut seen: BTreeSet<DeviceId> = BTreeSet::new();
    let mut work = vec![*revoked];
    while let Some(cur) = work.pop() {
        // after_seq = 0 here: traverse everything, collect selectively below.
        for d in devices_added_by(state, &cur, 0) {
            if !seen.insert(d) {
                continue;
            }
            work.push(d);
            if state.added_at.get(&d).is_some_and(|s| *s >= after_seq) {
                result.insert(d);
            }
        }
    }
    result.into_iter().collect()
}

/// The ordered `revoke⇒rotate` op sequence (§8.4): `RevokeDevice(revoked)`, the transitive
/// [`revoke_closure`], then `Rotate(next_mk_commit)`. The caller signs these ([`append_many`]) and
/// performs the keyslot re-wrap/deletion (§8.4 steps 2–4).
#[must_use]
pub fn revoke_rotate_ops(
    state: &State,
    revoked: &DeviceId,
    after_seq: u64,
    next_mk_commit: MkCommit,
) -> Vec<Op> {
    let mut ops = Vec::new();
    ops.push(Op::RevokeDevice { device: *revoked });
    for d in revoke_closure(state, revoked, after_seq) {
        ops.push(Op::RevokeDevice { device: d });
    }
    ops.push(Op::Rotate {
        mk_commit: next_mk_commit,
    });
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    const MK: MkCommit = [0xAA; 32];

    fn pubkey_of(d: &DeviceKey) -> Vec<u8> {
        d.public().to_canonical().unwrap()
    }

    /// An `AddDevice` op granting `d` at the generation-`MK` commitment.
    fn add(d: &DeviceKey) -> Op {
        Op::AddDevice {
            pubkey: pubkey_of(d),
            mk_commit: MK,
            enroll_pub: vec![],
        }
    }

    /// device-1 genesis, then a list of appended ops, returns (entries, rfp).
    fn chain(d1: &DeviceKey, ops: Vec<(Op, &DeviceKey)>) -> (Vec<Entry>, [u8; 32]) {
        let (g, rfp) = genesis(d1, vec![], MK, 0).unwrap();
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
                        enroll_pub: vec![],
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
    fn state_tracks_provenance_and_membership() {
        let d1 = DeviceKey::generate().unwrap();
        let d2 = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(
            &d1,
            vec![(
                Op::AddDevice {
                    pubkey: pubkey_of(&d2),
                    mk_commit: MK,
                    enroll_pub: vec![],
                },
                &d1,
            )],
        );
        let st = fold(&entries, &rfp).unwrap();
        let (id1, id2) = (d1.device_id().unwrap(), d2.device_id().unwrap());
        // is_member predicate
        assert!(st.is_member(&id1));
        assert!(st.is_member(&id2));
        assert!(!st.is_member(&DeviceKey::generate().unwrap().device_id().unwrap()));
        // genesis device-1 has no adder; d2 was added by d1 at seq 1
        assert!(!st.added_by.contains_key(&id1));
        assert_eq!(st.added_by.get(&id2), Some(&id1));
        assert_eq!(st.added_at.get(&id2), Some(&1));
    }

    /// §8.1/§8.4 revoke-before-add closure: revoking B must also catch devices B granted at/after
    /// the revoking device's reference seq, but not earlier grants or grants by other devices.
    #[test]
    fn revoke_before_add_closure() {
        let d1 = DeviceKey::generate().unwrap(); // founder / revoker
        let b = DeviceKey::generate().unwrap(); // to-be-revoked
        let early = DeviceKey::generate().unwrap(); // B-added, before the reference point
        let c = DeviceKey::generate().unwrap(); // B-added, after the reference point
        let dd = DeviceKey::generate().unwrap(); // B-added, after the reference point
        let other = DeviceKey::generate().unwrap(); // added by d1, must not be swept

        let (entries, rfp) = chain(
            &d1,
            vec![
                (add(&b), &d1),     // seq 1: d1 adds B
                (add(&early), &b),  // seq 2: B adds `early`
                (add(&other), &d1), // seq 3: d1 adds `other`
                (add(&c), &b),      // seq 4: B adds C
                (add(&dd), &b),     // seq 5: B adds D
            ],
        );
        let st = fold(&entries, &rfp).unwrap();
        let b_id = b.device_id().unwrap();

        // Reference seq = 3 (d1's last-authored entry before deciding to revoke B): only C(4) and
        // D(5) are at/after it; `early`(2) is excluded.
        let mut swept = devices_added_by(&st, &b_id, 3);
        swept.sort();
        let mut want = vec![c.device_id().unwrap(), dd.device_id().unwrap()];
        want.sort();
        assert_eq!(swept, want);

        // `other` was added by d1, never swept regardless of seq.
        assert!(!devices_added_by(&st, &b_id, 0).contains(&other.device_id().unwrap()));
        // With reference seq 0, the whole of B's still-present grants are caught (incl. `early`).
        assert_eq!(devices_added_by(&st, &b_id, 0).len(), 3);
        // A device that is no longer a member is not reported: revoke `early`, re-fold.
        let revoke_early = append(
            entries.last().unwrap(),
            Op::RevokeDevice {
                device: early.device_id().unwrap(),
            },
            &d1,
            0,
        )
        .unwrap();
        let mut entries2 = entries.clone();
        entries2.push(revoke_early);
        let st2 = fold(&entries2, &rfp).unwrap();
        assert_eq!(devices_added_by(&st2, &b_id, 0).len(), 2); // early gone, C+D remain
    }

    /// The transitive closure catches the two-hop sleeper that one level misses: B adds C, C adds E.
    #[test]
    fn revoke_closure_is_transitive() {
        let d1 = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let c = DeviceKey::generate().unwrap();
        let e = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(
            &d1,
            vec![
                (add(&b), &d1), // seq 1: d1 adds B
                (add(&c), &b),  // seq 2: B adds C
                (add(&e), &c),  // seq 3: C adds E (the nested sleeper)
            ],
        );
        let st = fold(&entries, &rfp).unwrap();
        let b_id = b.device_id().unwrap();

        // one level sees only C ...
        assert_eq!(
            devices_added_by(&st, &b_id, 0),
            vec![c.device_id().unwrap()]
        );
        // ... the transitive closure sweeps C and E both.
        let mut closure = revoke_closure(&st, &b_id, 0);
        closure.sort();
        let mut want = vec![c.device_id().unwrap(), e.device_id().unwrap()];
        want.sort();
        assert_eq!(closure, want);
    }

    /// `after_seq > 0`: a pre-reference child is retained (its grant was witnessed under prior trust),
    /// but the traversal still reaches and sweeps its **post-reference** descendant — the nested-sleeper
    /// guard must not be blocked by an out-of-scope intermediate.
    #[test]
    fn revoke_closure_reaches_post_reference_descendant_of_pre_reference_child() {
        let d1 = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let c = DeviceKey::generate().unwrap();
        let e = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(
            &d1,
            vec![
                (add(&b), &d1), // seq 1
                (add(&c), &b),  // seq 2: B adds C  (pre-reference grant)
                (add(&e), &c),  // seq 3: C adds E  (post-reference grant)
            ],
        );
        let st = fold(&entries, &rfp).unwrap();
        let b_id = b.device_id().unwrap();

        // Reference point seq = 3: C's grant (seq 2) is out of scope; E's grant (seq 3) is in scope.
        // C is retained; E — the sleeper C added after the reference — is swept.
        let closure = revoke_closure(&st, &b_id, 3);
        assert_eq!(closure, vec![e.device_id().unwrap()]);
        assert!(!closure.contains(&c.device_id().unwrap()));
    }

    /// End-to-end: building revoke⇒rotate ops, appending them, and re-folding leaves none of the
    /// suspect subtree as a member and bumps the generation.
    #[test]
    fn revoke_rotate_ops_evicts_whole_subtree() {
        let d1 = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let c = DeviceKey::generate().unwrap();
        let e = DeviceKey::generate().unwrap();
        let (mut entries, rfp) = chain(&d1, vec![(add(&b), &d1), (add(&c), &b), (add(&e), &c)]);
        let st = fold(&entries, &rfp).unwrap();
        let b_id = b.device_id().unwrap();

        // d1 builds and appends RevokeDevice(B), RevokeDevice(closure...), Rotate.
        let ops = revoke_rotate_ops(&st, &b_id, 0, [0xCC; 32]);
        // last op is the Rotate; the rest are revokes (B + its subtree = B, C, E -> 3 revokes).
        assert!(matches!(ops.last(), Some(Op::Rotate { .. })));
        assert_eq!(ops.len(), 1 /*B*/ + 2 /*C,E*/ + 1 /*Rotate*/);

        let new_entries = append_many(entries.last().unwrap(), ops, &d1, 0).unwrap();
        entries.extend(new_entries);

        let st2 = fold(&entries, &rfp).unwrap();
        assert!(st2.is_member(&d1.device_id().unwrap()), "founder remains");
        for dead in [&b, &c, &e] {
            assert!(
                !st2.is_member(&dead.device_id().unwrap()),
                "whole compromised subtree evicted"
            );
        }
        assert_eq!(st2.generation, 2);
        assert_eq!(st2.mk_commits.get(&2), Some(&[0xCC; 32]));
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
                        enroll_pub: vec![],
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
                    enroll_pub: vec![],
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
                        enroll_pub: vec![],
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
        let (g, _rfp) = genesis(&d1, vec![], MK, 0).unwrap();
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
        let (g, _rfp) = genesis(&d1, vec![], MK, 0).unwrap();
        let bytes = encode_entry(&g);
        assert!(matches!(
            decode_entry(&bytes[..bytes.len() - 1]),
            Err(RosterError::Canon(_))
        ));
    }

    #[test]
    fn decode_rejects_unknown_op_tag() {
        let d1 = DeviceKey::generate().unwrap();
        let (g, _rfp) = genesis(&d1, vec![], MK, 0).unwrap();
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
        let (g, _rfp) = genesis(&d1, vec![], MK, 0).unwrap();
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
        let (g, _rfp) = genesis(&d1, vec![], MK, 0).unwrap();
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
        let (g, _rfp) = genesis(&d1, vec![], MK, 0).unwrap();
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
        let (g, _rfp) = genesis(&d1, vec![], MK, 0).unwrap();
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
        let (g, _rfp) = genesis(&d1, vec![], MK, 0).unwrap();
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

    // ---- DATA key-history (§8.2: read pre-rotation object content) ----

    #[test]
    fn data_keyhist_peels_every_master_key() {
        // Five generations with independent master keys; build the never-trimmed DATA wrap chain.
        let mks: [[u8; 32]; 5] = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
        let mut history: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for g in 1u32..5 {
            // wrap master_key_g under master_key_{g+1}.
            let wrap = seal_data_keyhist(&mks[g as usize], g, &mks[(g - 1) as usize]);
            assert_eq!(wrap.len(), DATA_KEYHIST_LEN);
            history.insert(g, wrap.to_vec());
        }
        let peeled = peel_data_keys(&mks[4], 5, &history).unwrap();
        assert_eq!(peeled.len(), 5);
        for g in 1u32..=5 {
            // each recovered MasterKey is the genuine generation-g key (same derived subkeys).
            let want = MasterKey::new(g, mks[(g - 1) as usize]);
            assert_eq!(peeled[&g].generation(), g);
            assert_eq!(
                &peeled[&g].roster_key()[..],
                &want.roster_key()[..],
                "recovered master_key_{g} must match"
            );
            assert_eq!(peeled[&g].mk_commit(), want.mk_commit());
        }
        // wrong next-gen key → AEAD failure (CMT-4, not a silent wrong key).
        assert!(matches!(
            open_data_keyhist(&[0x99; 32], 1, &history[&1]),
            Err(RosterError::Aead)
        ));
        // a missing wrap aborts the peel (a current member can always produce the full chain).
        let mut partial = history.clone();
        partial.remove(&1);
        assert!(matches!(
            peel_data_keys(&mks[4], 5, &partial),
            Err(RosterError::Aead)
        ));
    }

    /// Frozen wire KATs for the deterministic AEAD layers, mirrored in
    /// `vectors/secsec-kat-v1.txt`. Input `roster_key` is `roster_key[g=1]` for
    /// `master_key=[0x11;32]` (the kdf vector), so the chain of vectors is self-consistent.
    #[test]
    fn wire_kat() {
        let rk = roster_key_for(1, [0x11; 32]); // == roster_key[g=1] in the [kdf] vector

        // Roster entry AEAD (§9.5): FRAME(11) ‖ ctx_tag(32) ‖ ct, gen=1, seq=1.
        let blob = seal_entry(&rk, 1, 1, b"roster-entry-kat");
        assert_eq!(
            hx(&blob),
            "7373656301010100000004c69b06e76f52eb0570b7bac2eff9552c545c1906dddfc31b06a39faf2e36d4a764087224e2cb1ce70dbe9a15092153aa"
        );
        assert_eq!(open_entry(&rk, 1, 1, &blob).unwrap(), b"roster-entry-kat");

        // Roster-key history (§8.2): bare ctx_tag(32) ‖ ct(32), g=1, wrapping 0x00..0x1f.
        let kg: [u8; 32] = core::array::from_fn(|i| i as u8);
        let wrap = seal_roster_keyhist(&rk, 1, &kg);
        assert_eq!(
            hx(&wrap),
            "92397f6784bd2df46eb8a3fb1984fa98970abc9d6ecc80656a8d674b55221483d7626d73f776a99579f59ba22ce7b32d3929091d7b720d4d465e0b3f775f4a68"
        );
        assert_eq!(&open_roster_keyhist(&rk, 1, &wrap).unwrap()[..], &kg[..]);
    }

    // ---- Cold-start fold (§8.1 bootstrap; R5 capstone) ----

    #[test]
    fn cold_start_fold_bootstraps_multigen_chain() {
        const MK1: [u8; 32] = [0x51; 32];
        const MK2: [u8; 32] = [0x52; 32];
        let mkc1 = MasterKey::new(1, MK1).mk_commit();
        let mkc2 = MasterKey::new(2, MK2).mk_commit();
        let rk1: [u8; 32] = *MasterKey::new(1, MK1).roster_key();
        let rk2: [u8; 32] = *MasterKey::new(2, MK2).roster_key();

        let d1 = DeviceKey::generate().unwrap();
        let d2 = DeviceKey::generate().unwrap();

        // Plaintext chain: genesis(g1), AddDevice(g1), Rotate→g2, SetMinAlgo(g2, signed by d2).
        let (g, rfp) = genesis(&d1, vec![], mkc1, 0).unwrap();
        let e1 = append(
            &g,
            Op::AddDevice {
                pubkey: pubkey_of(&d2),
                mk_commit: mkc1,
                enroll_pub: vec![],
            },
            &d1,
            0,
        )
        .unwrap();
        let e2 = append(&e1, Op::Rotate { mk_commit: mkc2 }, &d1, 0).unwrap();
        let e3 = append(&e2, Op::SetMinAlgo { min_algo: 2 }, &d2, 0).unwrap();

        // Seal each entry under its generation: genesis+AddDevice = g1; Rotate and after = g2 (§9.5).
        let stored = vec![
            seal_entry(&rk1, 1, 0, &encode_entry(&g)),
            seal_entry(&rk1, 1, 1, &encode_entry(&e1)),
            seal_entry(&rk2, 2, 2, &encode_entry(&e2)),
            seal_entry(&rk2, 2, 3, &encode_entry(&e3)),
        ];
        // Never-trimmed roster-key history: roster_key_1 wrapped under roster_key_2.
        let mut hist = BTreeMap::new();
        hist.insert(1u32, seal_roster_keyhist(&rk2, 1, &rk1).to_vec());

        // Bootstrap from the gen-2 master key, as a fresh device would after keyslot unwrap.
        let (state, mk) = cold_start_fold(&MK2, 2, &rfp, &hist, &stored).unwrap();
        assert_eq!(state.generation, 2);
        assert_eq!(state.min_algo, 2);
        assert!(state.is_member(&d1.device_id().unwrap()));
        assert!(state.is_member(&d2.device_id().unwrap()));
        assert_eq!(mk.generation(), 2);
        // the recovered key is the genuine gen-2 key (derives the same roster key)
        assert_eq!(&mk.roster_key()[..], &rk2[..]);
    }

    #[test]
    fn cold_start_rejects_forged_and_inconsistent_inputs() {
        const MK1: [u8; 32] = [0x61; 32];
        let mkc1 = MasterKey::new(1, MK1).mk_commit();
        let rk1: [u8; 32] = *MasterKey::new(1, MK1).roster_key();
        let empty: BTreeMap<u32, Vec<u8>> = BTreeMap::new();

        let d1 = DeviceKey::generate().unwrap();
        let d2 = DeviceKey::generate().unwrap();
        let (g, rfp) = genesis(&d1, vec![], mkc1, 0).unwrap();
        let e1 = append(
            &g,
            Op::AddDevice {
                pubkey: pubkey_of(&d2),
                mk_commit: mkc1,
                enroll_pub: vec![],
            },
            &d1,
            0,
        )
        .unwrap();
        let stored = vec![
            seal_entry(&rk1, 1, 0, &encode_entry(&g)),
            seal_entry(&rk1, 1, 1, &encode_entry(&e1)),
        ];

        // happy path (gen-1-only chain)
        assert!(cold_start_fold(&MK1, 1, &rfp, &empty, &stored).is_ok());

        // forged keyslot serving a different key: its roster_key can't decrypt the real chain.
        assert!(matches!(
            cold_start_fold(&[0x99; 32], 1, &rfp, &empty, &stored),
            Err(RosterError::Aead)
        ));

        // wrong pinned RFP -> fold rejects.
        assert!(matches!(
            cold_start_fold(&MK1, 1, &[0u8; 32], &empty, &stored),
            Err(RosterError::RfpMismatch)
        ));

        // g_cur that disagrees with the tip's FRAME.gen.
        assert!(matches!(
            cold_start_fold(&MK1, 2, &rfp, &empty, &stored),
            Err(RosterError::BadGeneration)
        ));

        // fake key: chain records a mk_commit for a DIFFERENT key than the one that sealed it. The
        // candidate decrypts (its roster_key matches) and folds, but fails the §7-step-3 mk_commit
        // check — the forged-keyslot / fake-universe defense.
        let wrong_commit = MasterKey::new(1, [0xEE; 32]).mk_commit();
        let (gf, rfpf) = genesis(&d1, vec![], wrong_commit, 0).unwrap();
        let stored_f = vec![seal_entry(&rk1, 1, 0, &encode_entry(&gf))];
        assert!(matches!(
            cold_start_fold(&MK1, 1, &rfpf, &empty, &stored_f),
            Err(RosterError::MkCommitMismatch)
        ));
    }

    // ---- Model-based differential test (R5): fold vs an independent reference state machine ----

    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Act {
        Add(usize),
        Revoke(usize),
        Rotate,
        SetMinAlgo(u8),
    }

    fn act_strategy() -> impl Strategy<Value = (usize, Act)> {
        let kind = prop_oneof![
            (0usize..6).prop_map(Act::Add),
            (0usize..6).prop_map(Act::Revoke),
            Just(Act::Rotate),
            (0u8..6).prop_map(Act::SetMinAlgo),
        ];
        (0usize..6, kind)
    }

    /// Deterministically pick a current member (always non-empty: device 0 is never revoked).
    fn pick_member(members: &BTreeSet<usize>, hint: usize) -> usize {
        let v: Vec<usize> = members.iter().copied().collect();
        v[hint % v.len()]
    }

    fn commit_for(gen: u32) -> MkCommit {
        MasterKey::new(gen, [gen as u8; 32]).mk_commit()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Build a random *valid* sigchain (signers are always current members, by construction) and
        /// assert `fold` reproduces an independently-computed reference state — membership set,
        /// generation, and min_algo. This is the R5 fold-vs-model differential check.
        #[test]
        fn fold_matches_reference_model(actions in proptest::collection::vec(act_strategy(), 0..40)) {
            let devices: Vec<DeviceKey> = (0..6).map(|_| DeviceKey::generate().unwrap()).collect();
            let ids: Vec<DeviceId> = devices.iter().map(|d| d.device_id().unwrap()).collect();

            // Genesis by device 0 (the never-revoked founder, so a signer always exists).
            let (g, rfp) = genesis(&devices[0], vec![], commit_for(1), 0).unwrap();
            let mut entries = vec![g];

            // Reference model.
            let mut members: BTreeSet<usize> = BTreeSet::from([0]);
            let mut generation: u32 = 1;
            let mut min_algo: u8 = secsec_frame::MIN_ALGO_ID;

            for (signer_hint, kind) in actions {
                let signer = pick_member(&members, signer_hint);
                let prev = entries.last().unwrap();
                match kind {
                    Act::Add(target) if target != 0 && !members.contains(&target) => {
                        let op = Op::AddDevice {
                            pubkey: pubkey_of(&devices[target]),
                            mk_commit: commit_for(generation),
                            enroll_pub: vec![],
                        };
                        entries.push(append(prev, op, &devices[signer], 0).unwrap());
                        members.insert(target);
                    }
                    Act::Revoke(target) if target != 0 && members.contains(&target) => {
                        let op = Op::RevokeDevice { device: ids[target] };
                        entries.push(append(prev, op, &devices[signer], 0).unwrap());
                        members.remove(&target);
                    }
                    Act::Rotate => {
                        generation += 1;
                        let op = Op::Rotate { mk_commit: commit_for(generation) };
                        entries.push(append(prev, op, &devices[signer], 0).unwrap());
                    }
                    Act::SetMinAlgo(v) => {
                        let op = Op::SetMinAlgo { min_algo: v };
                        entries.push(append(prev, op, &devices[signer], 0).unwrap());
                        min_algo = min_algo.max(v);
                    }
                    // Add of an existing/founder device, or revoke of a non-member: skip (no-op).
                    _ => {}
                }
            }

            let st = fold(&entries, &rfp).unwrap();
            prop_assert_eq!(st.generation, generation);
            prop_assert_eq!(st.min_algo, min_algo);
            let got: BTreeSet<DeviceId> = st.members.keys().copied().collect();
            let want: BTreeSet<DeviceId> = members.iter().map(|i| ids[*i]).collect();
            prop_assert_eq!(got, want);
        }
    }

    fn hx(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }
}
