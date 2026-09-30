//! The roster sigchain: fold/succession, per-entry AEAD, key-history peels, cold start, and revoke⇒rotate ops (`secsec-Design.md` §8).

#![forbid(unsafe_code)]

use secsec_canon::{verify_reencode, CanonError, Reader, Writer};
use secsec_frame::{
    parse_blob, parse_frame_prefix, Frame, FrameError, ObjType, CTX_TAG_LEN, FRAME_LEN,
    MAX_ROSTER_ENTRY_SIZE,
};
use secsec_kdf::{
    data_keyhist_key, roster_entry_key, roster_entry_key_v2, roster_keyhist_key, MasterKey,
    SecretKey, ROSTER_ENTRY_SALT_LEN,
};
use secsec_sig::{DeviceId, DeviceKey, DevicePublic, NS_ROSTER};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// A 256-bit master-key generation commitment `mk_commit_g`.
pub type MkCommit = [u8; 32];

/// A sigchain operation (§8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// The trust root, self-signed at seq 0.
    Genesis {
        /// Canonical SSH encoding of device-1's public key.
        pubkey: Vec<u8>,
        /// `mk_commit_1`.
        mk_commit: MkCommit,
        /// Device-1's X-Wing public key (§8.3/§17).
        enroll_pub: Vec<u8>,
    },
    /// Add a device at the current generation.
    AddDevice {
        /// Canonical SSH encoding of the new device's public key.
        pubkey: Vec<u8>,
        /// `mk_commit_g` of the current generation; fold rejects any other value.
        mk_commit: MkCommit,
        /// The new device's X-Wing public key (§8.3/§17).
        enroll_pub: Vec<u8>,
    },
    /// Remove a device by id.
    RevokeDevice {
        /// The device being removed.
        device: DeviceId,
    },
    /// Mint generation `g+1`.
    Rotate {
        /// `mk_commit_{g+1}`.
        mk_commit: MkCommit,
    },
    /// Raise the repo-wide keyslot algorithm floor (§16).
    SetMinAlgo {
        /// The new floor.
        min_algo: u8,
    },
}

/// A signed sigchain entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Sequence number; genesis is 0.
    pub seq: u64,
    /// BLAKE3 of the full previous entry (`[0;32]` for genesis).
    pub prev: [u8; 32],
    /// The operation.
    pub op: Op,
    /// Author-asserted timestamp (advisory).
    pub ts: u64,
    /// The signing device's id.
    pub signer: DeviceId,
    /// SSHSIG PEM over the signed portion (`secsec-roster-v1`).
    pub sig: Vec<u8>,
}

/// Errors from building / folding the sigchain.
#[derive(Debug)]
pub enum RosterError {
    /// Empty chain.
    Empty,
    /// Genesis malformed or not self-signed by device-1.
    BadGenesis,
    /// Genesis hash did not equal the pinned RFP.
    RfpMismatch,
    /// A non-genesis entry had a `Genesis` op.
    DoubleGenesis,
    /// Sequence numbers are not 0,1,2,… (or would overflow).
    BadSeq,
    /// An entry's `prev` did not equal the hash of its predecessor.
    ChainBreak,
    /// An entry was signed by a non-member (succession violation).
    NotMember,
    /// An entry's signature did not verify.
    BadSignature,
    /// Unknown op tag.
    BadOp,
    /// An `AddDevice` recorded an `mk_commit` other than the current generation's.
    BadCommit,
    /// A device would revoke itself, which would leave its own later entries unsigned by a member.
    SelfRevoke,
    /// Strict canonical decode failed.
    Canon(CanonError),
    /// FRAME malformed or not the expected `(version, gen, type)` (§18).
    Frame(FrameError),
    /// The per-entry AEAD failed to open.
    Aead,
    /// An entry's generation has no peeled roster key (forged or inconsistent chain).
    BadGeneration,
    /// The candidate master key failed `mk_commit_{g_cur}` (§7 step 3: forged keyslot / fake key).
    MkCommitMismatch,
    /// OS RNG failure.
    Rng,
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
            RosterError::BadOp => f.write_str("unknown roster op tag"),
            RosterError::BadCommit => {
                f.write_str("AddDevice mk_commit differs from the current generation's")
            }
            RosterError::SelfRevoke => f.write_str("a device cannot revoke itself"),
            RosterError::Canon(e) => write!(f, "canon: {e}"),
            RosterError::Frame(e) => write!(f, "frame: {e}"),
            RosterError::Aead => f.write_str("roster entry AEAD open failed"),
            RosterError::BadGeneration => f.write_str("entry generation has no peeled roster key"),
            RosterError::MkCommitMismatch => {
                f.write_str("candidate key fails mk_commit from the RFP-anchored chain")
            }
            RosterError::Rng => f.write_str("OS RNG failure"),
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

/// The signed portion `seq ‖ prev ‖ op ‖ ts ‖ signer` (§8.1).
fn signed_bytes(seq: u64, prev: &[u8; 32], op: &Op, ts: u64, signer: &DeviceId) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(seq).raw(prev);
    encode_op(&mut w, op);
    w.u64(ts).raw(signer);
    w.finish()
}

/// The canonical entry `seq ‖ prev ‖ op ‖ ts ‖ signer ‖ sig`: hashed for `prev`/RFP and sealed by the AEAD.
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

/// Strictly decode a canonical entry: bounded fields, no trailing bytes, §9.3 re-encode guard.
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

/// BLAKE3 of the full entry: the chain link `prev` and the genesis RFP.
#[must_use]
pub(crate) fn entry_hash(e: &Entry) -> [u8; 32] {
    *blake3::hash(&encode_entry(e)).as_bytes()
}

// ---- per-entry AEAD (§9.5) ----

/// v1 AD `FRAME ‖ le64(seq)`.
fn ad_roster_v1(frame: &Frame, seq: u64) -> [u8; FRAME_LEN + 8] {
    let mut ad = [0u8; FRAME_LEN + 8];
    ad[..FRAME_LEN].copy_from_slice(&frame.encode());
    ad[FRAME_LEN..].copy_from_slice(&seq.to_le_bytes());
    ad
}

/// v2 AD `FRAME ‖ le64(seq) ‖ salt`.
fn ad_roster_v2(
    frame: &Frame,
    seq: u64,
    salt: &[u8; ROSTER_ENTRY_SALT_LEN],
) -> [u8; FRAME_LEN + 8 + ROSTER_ENTRY_SALT_LEN] {
    let mut ad = [0u8; FRAME_LEN + 8 + ROSTER_ENTRY_SALT_LEN];
    ad[..FRAME_LEN + 8].copy_from_slice(&ad_roster_v1(frame, seq));
    ad[FRAME_LEN + 8..].copy_from_slice(salt);
    ad
}

/// Seal a canonical entry at `(gen, seq)` as v2 `FRAME ‖ salt ‖ ctx_tag ‖ ct` under a fresh random salt (§9.5).
pub fn seal_entry(
    roster_key_g: &[u8; 32],
    gen: u32,
    seq: u64,
    entry_plaintext: &[u8],
) -> Result<Vec<u8>, RosterError> {
    let mut salt = [0u8; ROSTER_ENTRY_SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| RosterError::Rng)?;
    Ok(seal_entry_with_salt(
        roster_key_g,
        gen,
        seq,
        &salt,
        entry_plaintext,
    ))
}

/// [`seal_entry`] with a caller-supplied salt, which MUST be fresh random per seal; fixed salts are for KATs only.
#[must_use]
pub fn seal_entry_with_salt(
    roster_key_g: &[u8; 32],
    gen: u32,
    seq: u64,
    salt: &[u8; ROSTER_ENTRY_SALT_LEN],
    entry_plaintext: &[u8],
) -> Vec<u8> {
    let k = roster_entry_key_v2(roster_key_g, seq, salt);
    let frame = Frame::v2(gen, ObjType::RosterEntry);
    let ad = ad_roster_v2(&frame, seq, salt);
    let (ctx_tag, ct) = secsec_aead::seal(secsec_aead::UniqueKey::new(&k), &ad, entry_plaintext);
    let mut out = Vec::with_capacity(FRAME_LEN + ROSTER_ENTRY_SALT_LEN + CTX_TAG_LEN + ct.len());
    out.extend_from_slice(&frame.encode());
    out.extend_from_slice(salt);
    out.extend_from_slice(&ctx_tag);
    out.extend_from_slice(&ct);
    out
}

/// Seal a legacy v1 entry (zero nonce, per-(key, seq) key); kept only so tests and KATs exercise the v1 reader.
#[cfg(any(test, feature = "legacy-v1"))]
#[must_use]
pub fn seal_entry_v1(
    roster_key_g: &[u8; 32],
    gen: u32,
    seq: u64,
    entry_plaintext: &[u8],
) -> Vec<u8> {
    let k = roster_entry_key(roster_key_g, seq);
    let frame = Frame::v1(gen, ObjType::RosterEntry);
    let ad = ad_roster_v1(&frame, seq);
    let (ctx_tag, ct) = secsec_aead::seal(secsec_aead::UniqueKey::new(&k), &ad, entry_plaintext);
    secsec_frame::assemble_blob(&frame, &ctx_tag, &ct)
}

/// Open a stored entry at `(gen, seq)`, v2 or legacy v1 by its FRAME version (§18 check, then AEAD).
pub fn open_entry(
    roster_key_g: &[u8; 32],
    gen: u32,
    seq: u64,
    stored: &[u8],
) -> Result<Vec<u8>, RosterError> {
    let frame_bytes = stored
        .get(..FRAME_LEN)
        .ok_or(RosterError::Frame(FrameError::ShortBlob))?;
    if Frame::decode(frame_bytes)?.is_v2() {
        let frame = Frame::v2(gen, ObjType::RosterEntry);
        let rest = parse_frame_prefix(stored, &frame)?;
        if rest.len() < ROSTER_ENTRY_SALT_LEN + CTX_TAG_LEN {
            return Err(RosterError::Frame(FrameError::ShortBlob));
        }
        let (salt, rest) = rest.split_at(ROSTER_ENTRY_SALT_LEN);
        let (tag, ct) = rest.split_at(CTX_TAG_LEN);
        let salt: &[u8; ROSTER_ENTRY_SALT_LEN] = salt.try_into().expect("salt length");
        let ctx_tag: &[u8; CTX_TAG_LEN] = tag.try_into().expect("tag length");
        let k = roster_entry_key_v2(roster_key_g, seq, salt);
        let ad = ad_roster_v2(&frame, seq, salt);
        secsec_aead::open(&k, &ad, ctx_tag, ct).map_err(|_| RosterError::Aead)
    } else {
        let frame = Frame::v1(gen, ObjType::RosterEntry);
        let (ctx_tag, ct) = parse_blob(stored, &frame)?;
        let ad = ad_roster_v1(&frame, seq);
        let k = roster_entry_key(roster_key_g, seq);
        secsec_aead::open(&k, &ad, ctx_tag, ct).map_err(|_| RosterError::Aead)
    }
}

// ---- roster-key history (§8.2; never trimmed) ----

/// A roster key's length.
const ROSTER_KEY_LEN: usize = 32;
/// Stored size of one roster-key-history wrap `ctx_tag(32) ‖ ct(32)`; `g` comes from the storage path.
pub const ROSTER_KEYHIST_LEN: usize = CTX_TAG_LEN + ROSTER_KEY_LEN;

/// Wrap `roster_key_g` under `k_rkh_g` (from `roster_key_{g+1}`), AD `FRAME(roster-keyhist, g)` (§8.2).
#[must_use]
pub fn seal_roster_keyhist(
    roster_key_next: &[u8; 32],
    g: u32,
    roster_key_g: &[u8; 32],
) -> [u8; ROSTER_KEYHIST_LEN] {
    let k = roster_keyhist_key(roster_key_next, g);
    let ad = Frame::v1(g, ObjType::RosterKeyhist).encode();
    let (ctx_tag, ct) = secsec_aead::seal(secsec_aead::UniqueKey::new(&k), &ad, roster_key_g);
    let mut out = [0u8; ROSTER_KEYHIST_LEN];
    out[..CTX_TAG_LEN].copy_from_slice(&ctx_tag);
    out[CTX_TAG_LEN..].copy_from_slice(&ct);
    out
}

/// Recover `roster_key_g` from its wrap with `roster_key_{g+1}`, CMT-4 checked first.
pub(crate) fn open_roster_keyhist(
    roster_key_next: &[u8; 32],
    g: u32,
    stored: &[u8],
) -> Result<SecretKey, RosterError> {
    open_key_wrap(
        &roster_keyhist_key(roster_key_next, g),
        Frame::v1(g, ObjType::RosterKeyhist),
        stored,
    )
}

/// Open a 64-byte `ctx_tag ‖ ct` key wrap under `k` with AD `frame`, returning the zeroizing key.
fn open_key_wrap(k: &[u8; 32], frame: Frame, stored: &[u8]) -> Result<SecretKey, RosterError> {
    if stored.len() != CTX_TAG_LEN + ROSTER_KEY_LEN {
        return Err(RosterError::Aead);
    }
    let ctx_tag: &[u8; CTX_TAG_LEN] = stored[..CTX_TAG_LEN]
        .try_into()
        .expect("slice is exactly CTX_TAG_LEN");
    let ct = &stored[CTX_TAG_LEN..];
    let pt = Zeroizing::new(
        secsec_aead::open(k, &frame.encode(), ctx_tag, ct).map_err(|_| RosterError::Aead)?,
    );
    let mut out = Zeroizing::new([0u8; ROSTER_KEY_LEN]);
    out.copy_from_slice(&pt);
    Ok(out)
}

/// Peel `roster_key_current` down to `roster_key_1`; every wrap in `1..current_gen` must be present and open.
pub(crate) fn peel_roster_keys(
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

// ---- data key-history (§8.2) ----

/// Stored size of one data key-history wrap `ctx_tag(32) ‖ ct(32)`.
pub const DATA_KEYHIST_LEN: usize = CTX_TAG_LEN + 32;

/// Wrap `master_key_g` under `k_keyhist_g` (from `master_key_{g+1}`), AD `FRAME(keyhist, g)` (§8.2).
#[must_use]
pub fn seal_data_keyhist(
    master_key_next: &[u8; 32],
    g: u32,
    master_key_g: &[u8; 32],
) -> [u8; DATA_KEYHIST_LEN] {
    let k = data_keyhist_key(master_key_next, g);
    let ad = Frame::v1(g, ObjType::Keyhist).encode();
    let (ctx_tag, ct) = secsec_aead::seal(secsec_aead::UniqueKey::new(&k), &ad, master_key_g);
    let mut out = [0u8; DATA_KEYHIST_LEN];
    out[..CTX_TAG_LEN].copy_from_slice(&ctx_tag);
    out[CTX_TAG_LEN..].copy_from_slice(&ct);
    out
}

/// Recover `master_key_g` from its wrap with `master_key_{g+1}`, CMT-4 checked first.
pub(crate) fn open_data_keyhist(
    master_key_next: &[u8; 32],
    g: u32,
    stored: &[u8],
) -> Result<MasterKey, RosterError> {
    let key = open_key_wrap(
        &data_keyhist_key(master_key_next, g),
        Frame::v1(g, ObjType::Keyhist),
        stored,
    )?;
    Ok(MasterKey::new(g, *key))
}

/// Peel `master_key_current` down to `master_key_1`, each generation checked against `mk_commits` (§8.2).
pub fn peel_data_keys(
    master_key_current: &[u8; 32],
    current_gen: u32,
    history: &BTreeMap<u32, Vec<u8>>,
    mk_commits: &BTreeMap<u32, MkCommit>,
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
    for (g, mk) in &keys {
        if mk_commits.get(g) != Some(&mk.mk_commit()) {
            return Err(RosterError::MkCommitMismatch);
        }
    }
    Ok(keys)
}

/// Create the self-signed genesis entry (seq 0); returns `(entry, rfp)`.
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

/// Append one entry after `prev_entry`, signed by `signer` (a current member for the chain to fold).
pub fn append(
    prev_entry: &Entry,
    op: Op,
    signer: &DeviceKey,
    ts: u64,
) -> Result<Entry, RosterError> {
    let seq = prev_entry.seq.checked_add(1).ok_or(RosterError::BadSeq)?;
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

/// Append `ops` as a chained run of signed entries after `prev_entry`.
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
    /// Current members → public keys.
    pub members: BTreeMap<DeviceId, DevicePublic>,
    /// Every device ever admitted (genesis or `AddDevice`), including revoked ones: verifies historical commits.
    pub ever_members: BTreeMap<DeviceId, DevicePublic>,
    /// Current generation (`#Rotate + 1`).
    pub generation: u32,
    /// Keyslot algorithm floor (max over `SetMinAlgo`).
    pub min_algo: u8,
    /// Per-generation `mk_commit` from genesis/rotate.
    pub mk_commits: BTreeMap<u32, MkCommit>,
    /// For each current non-genesis member, the device that granted it (the §8.1 closure input).
    pub added_by: BTreeMap<DeviceId, DeviceId>,
    /// For each member in `added_by`, the seq of its latest `AddDevice`.
    pub added_at: BTreeMap<DeviceId, u64>,
    /// Per current member, its published X-Wing public key (§8.3/§17).
    pub enroll_pubs: BTreeMap<DeviceId, Vec<u8>>,
    /// The tip seq this state was folded to.
    pub tip_seq: u64,
}

impl State {
    /// Whether `device` is a current member.
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

/// Fold and validate a sigchain against `rfp`: genesis = RFP, seq order, `prev` chain, signatures, succession.
pub(crate) fn fold(entries: &[Entry], rfp: &[u8; 32]) -> Result<State, RosterError> {
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
    if g.signer != gpub.device_id()? {
        return Err(RosterError::BadGenesis);
    }
    verify_entry_sig(&gpub, g)?;

    let mut st = State {
        members: BTreeMap::new(),
        ever_members: BTreeMap::new(),
        generation: 1,
        min_algo: secsec_frame::MIN_ALGO_ID,
        mk_commits: BTreeMap::new(),
        added_by: BTreeMap::new(),
        added_at: BTreeMap::new(),
        enroll_pubs: BTreeMap::new(),
        tip_seq: 0,
    };
    st.members.insert(g.signer, gpub.clone());
    st.ever_members.insert(g.signer, gpub);
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
        let signer_pub = st.members.get(&e.signer).ok_or(RosterError::NotMember)?;
        verify_entry_sig(signer_pub, e)?;

        match &e.op {
            Op::Genesis { .. } => return Err(RosterError::DoubleGenesis),
            Op::AddDevice {
                pubkey,
                mk_commit,
                enroll_pub,
            } => {
                if st.mk_commits.get(&st.generation) != Some(mk_commit) {
                    return Err(RosterError::BadCommit);
                }
                let p = DevicePublic::from_canonical(pubkey)?;
                let id = p.device_id()?;
                st.members.insert(id, p.clone());
                st.ever_members.insert(id, p);
                // A re-add overwrites the prior grant: the latest adder/seq wins.
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
                st.generation = st.generation.checked_add(1).ok_or(RosterError::BadSeq)?;
                st.mk_commits.insert(st.generation, *mk_commit);
            }
            Op::SetMinAlgo { min_algo } => {
                st.min_algo = st.min_algo.max(*min_algo);
            }
        }
        st.tip_seq = e.seq;
    }
    Ok(st)
}

/// §8.1 cold start: peel roster keys, open each entry by its FRAME.gen, fold, then check the candidate key's `mk_commit`.
pub fn cold_start_fold(
    candidate_master_key: &[u8; 32],
    g_cur: u32,
    rfp: &[u8; 32],
    roster_keyhist: &BTreeMap<u32, Vec<u8>>,
    stored_entries: &[Vec<u8>],
) -> Result<(State, MasterKey), RosterError> {
    let mk = MasterKey::new(g_cur, *candidate_master_key);

    let tip = stored_entries.last().ok_or(RosterError::Empty)?;
    if frame_gen(tip)? != g_cur {
        return Err(RosterError::BadGeneration);
    }

    let roster_keys = peel_roster_keys(&mk.roster_key(), g_cur, roster_keyhist)?;

    let mut entries = Vec::with_capacity(stored_entries.len());
    for (seq, blob) in stored_entries.iter().enumerate() {
        let gen = frame_gen(blob)?;
        let rk = roster_keys.get(&gen).ok_or(RosterError::BadGeneration)?;
        let plaintext = open_entry(rk, gen, seq as u64, blob)?;
        entries.push(decode_entry(&plaintext)?);
    }

    let state = fold(&entries, rfp)?;

    let expected = *state
        .mk_commits
        .get(&g_cur)
        .ok_or(RosterError::BadGeneration)?;
    if mk.mk_commit() != expected {
        return Err(RosterError::MkCommitMismatch);
    }
    Ok((state, mk))
}

/// The authenticated-by-AD `FRAME.gen` of a stored entry blob.
pub fn frame_gen(blob: &[u8]) -> Result<u32, RosterError> {
    let frame_bytes = blob
        .get(..FRAME_LEN)
        .ok_or(RosterError::Frame(FrameError::ShortBlob))?;
    Ok(Frame::decode(frame_bytes)?.gen)
}

/// One closure level: current members `revoked` granted at seq ≥ `after_seq`, sorted.
#[must_use]
pub(crate) fn devices_added_by(state: &State, revoked: &DeviceId, after_seq: u64) -> Vec<DeviceId> {
    state
        .added_by
        .iter()
        .filter(|(id, adder)| {
            *adder == revoked && state.added_at.get(*id).is_some_and(|s| *s >= after_seq)
        })
        .map(|(id, _)| *id)
        .collect()
}

/// The transitive revoke-before-add closure of `revoked` (§8.1): every descendant granted at seq ≥ `after_seq`, walking through earlier children, never `revoker`.
#[must_use]
pub fn revoke_closure(
    state: &State,
    revoked: &DeviceId,
    after_seq: u64,
    revoker: &DeviceId,
) -> Vec<DeviceId> {
    let mut result: BTreeSet<DeviceId> = BTreeSet::new();
    let mut seen: BTreeSet<DeviceId> = [*revoked, *revoker].into_iter().collect();
    let mut work = vec![*revoked];
    while let Some(cur) = work.pop() {
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

/// The ordered revoke⇒rotate ops (§8.4): `RevokeDevice(revoked)`, the closure, then `Rotate(next_mk_commit)`.
pub fn revoke_rotate_ops(
    state: &State,
    revoked: &DeviceId,
    after_seq: u64,
    revoker: &DeviceId,
    next_mk_commit: MkCommit,
) -> Result<Vec<Op>, RosterError> {
    if revoked == revoker {
        return Err(RosterError::SelfRevoke);
    }
    let mut ops = vec![Op::RevokeDevice { device: *revoked }];
    for d in revoke_closure(state, revoked, after_seq, revoker) {
        ops.push(Op::RevokeDevice { device: d });
    }
    ops.push(Op::Rotate {
        mk_commit: next_mk_commit,
    });
    Ok(ops)
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

    /// device-1 genesis then `ops`; returns (entries, rfp).
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
        assert_eq!(st.tip_seq, 0);
    }

    #[test]
    fn add_revoke_rotate_setminalgo() {
        let d1 = DeviceKey::generate().unwrap();
        let d2 = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(
            &d1,
            vec![
                (add(&d2), &d1),
                (
                    Op::Rotate {
                        mk_commit: [0xBB; 32],
                    },
                    &d1,
                ),
                (Op::SetMinAlgo { min_algo: 2 }, &d2),
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
        assert!(
            st.ever_members.contains_key(&d2.device_id().unwrap()),
            "a revoked device stays in ever_members to verify its historical commits"
        );
        assert_eq!(st.mk_commits.get(&2), Some(&[0xBB; 32]));
        assert_eq!(st.tip_seq, 4);
    }

    /// An `AddDevice` must record the current generation's commitment (§7 step 3 relies on it).
    #[test]
    fn add_device_with_a_stale_commit_is_rejected() {
        let d1 = DeviceKey::generate().unwrap();
        let d2 = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(
            &d1,
            vec![
                (
                    Op::Rotate {
                        mk_commit: [0xBB; 32],
                    },
                    &d1,
                ),
                (add(&d2), &d1),
            ],
        );
        assert!(matches!(fold(&entries, &rfp), Err(RosterError::BadCommit)));
    }

    #[test]
    fn state_tracks_provenance_and_membership() {
        let d1 = DeviceKey::generate().unwrap();
        let d2 = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(&d1, vec![(add(&d2), &d1)]);
        let st = fold(&entries, &rfp).unwrap();
        let (id1, id2) = (d1.device_id().unwrap(), d2.device_id().unwrap());
        assert!(st.is_member(&id1));
        assert!(st.is_member(&id2));
        assert!(!st.is_member(&DeviceKey::generate().unwrap().device_id().unwrap()));
        assert!(!st.added_by.contains_key(&id1));
        assert_eq!(st.added_by.get(&id2), Some(&id1));
        assert_eq!(st.added_at.get(&id2), Some(&1));
    }

    /// One closure level catches grants at/after the reference seq, never earlier ones or other adders'.
    #[test]
    fn revoke_before_add_closure() {
        let d1 = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let early = DeviceKey::generate().unwrap();
        let c = DeviceKey::generate().unwrap();
        let dd = DeviceKey::generate().unwrap();
        let other = DeviceKey::generate().unwrap();

        let (entries, rfp) = chain(
            &d1,
            vec![
                (add(&b), &d1),     // seq 1
                (add(&early), &b),  // seq 2
                (add(&other), &d1), // seq 3
                (add(&c), &b),      // seq 4
                (add(&dd), &b),     // seq 5
            ],
        );
        let st = fold(&entries, &rfp).unwrap();
        let b_id = b.device_id().unwrap();

        let mut swept = devices_added_by(&st, &b_id, 3);
        swept.sort();
        let mut want = vec![c.device_id().unwrap(), dd.device_id().unwrap()];
        want.sort();
        assert_eq!(swept, want);
        assert!(!devices_added_by(&st, &b_id, 0).contains(&other.device_id().unwrap()));
        assert_eq!(devices_added_by(&st, &b_id, 0).len(), 3);
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
        assert_eq!(devices_added_by(&st2, &b_id, 0).len(), 2);
    }

    /// The transitive closure catches the two-hop sleeper: B adds C, C adds E.
    #[test]
    fn revoke_closure_is_transitive() {
        let d1 = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let c = DeviceKey::generate().unwrap();
        let e = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(&d1, vec![(add(&b), &d1), (add(&c), &b), (add(&e), &c)]);
        let st = fold(&entries, &rfp).unwrap();
        let b_id = b.device_id().unwrap();
        assert_eq!(
            devices_added_by(&st, &b_id, 0),
            vec![c.device_id().unwrap()]
        );
        let mut closure = revoke_closure(&st, &b_id, 0, &d1.device_id().unwrap());
        closure.sort();
        let mut want = vec![c.device_id().unwrap(), e.device_id().unwrap()];
        want.sort();
        assert_eq!(closure, want);
    }

    /// A pre-reference child is retained but the walk still sweeps its post-reference descendant.
    #[test]
    fn revoke_closure_reaches_post_reference_descendant_of_pre_reference_child() {
        let d1 = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let c = DeviceKey::generate().unwrap();
        let e = DeviceKey::generate().unwrap();
        let (entries, rfp) = chain(&d1, vec![(add(&b), &d1), (add(&c), &b), (add(&e), &c)]);
        let st = fold(&entries, &rfp).unwrap();
        let closure = revoke_closure(&st, &b.device_id().unwrap(), 3, &d1.device_id().unwrap());
        assert_eq!(closure, vec![e.device_id().unwrap()]);
        assert!(!closure.contains(&c.device_id().unwrap()));
    }

    /// A revoker re-added by the target is never swept, a re-add cycle lists the target once, and the ops still fold.
    #[test]
    fn revoke_closure_never_includes_the_revoker_or_the_target() {
        let r = DeviceKey::generate().unwrap(); // founder, the revoker
        let b = DeviceKey::generate().unwrap(); // target
        let c = DeviceKey::generate().unwrap(); // granted by r after r's re-add
        let e = DeviceKey::generate().unwrap(); // sleeper granted by b
        let (r_id, b_id) = (r.device_id().unwrap(), b.device_id().unwrap());
        let (mut entries, rfp) = chain(
            &r,
            vec![
                (add(&b), &r), // seq 1: r adds b
                (add(&r), &b), // seq 2: b re-adds r (a re-invite), so added_by[r] = b
                (add(&b), &r), // seq 3: r re-adds b, a cycle b→r→b
                (add(&c), &r), // seq 4
                (add(&e), &b), // seq 5
            ],
        );
        let st = fold(&entries, &rfp).unwrap();
        let closure = revoke_closure(&st, &b_id, 0, &r_id);
        assert_eq!(closure, vec![e.device_id().unwrap()]);

        let ops = revoke_rotate_ops(&st, &b_id, 0, &r_id, [0xCC; 32]).unwrap();
        let new = append_many(entries.last().unwrap(), ops, &r, 0).unwrap();
        entries.extend(new);
        let st2 = fold(&entries, &rfp).unwrap();
        assert!(st2.is_member(&r_id), "the revoker stays a member");
        assert!(st2.is_member(&c.device_id().unwrap()));
        assert!(!st2.is_member(&b_id));
        assert!(!st2.is_member(&e.device_id().unwrap()));
        assert!(matches!(
            revoke_rotate_ops(&st, &r_id, 0, &r_id, [0; 32]),
            Err(RosterError::SelfRevoke)
        ));
    }

    /// Appending revoke⇒rotate ops and refolding evicts the whole subtree and bumps the generation.
    #[test]
    fn revoke_rotate_ops_evicts_whole_subtree() {
        let d1 = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let c = DeviceKey::generate().unwrap();
        let e = DeviceKey::generate().unwrap();
        let (mut entries, rfp) = chain(&d1, vec![(add(&b), &d1), (add(&c), &b), (add(&e), &c)]);
        let st = fold(&entries, &rfp).unwrap();
        let b_id = b.device_id().unwrap();

        let ops = revoke_rotate_ops(&st, &b_id, 0, &d1.device_id().unwrap(), [0xCC; 32]).unwrap();
        assert!(matches!(ops.last(), Some(Op::Rotate { .. })));
        assert_eq!(ops.len(), 4);

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
        let d3 = DeviceKey::generate().unwrap();
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
                (add(&d2), &d1),
                (
                    Op::RevokeDevice {
                        device: d2.device_id().unwrap(),
                    },
                    &d1,
                ),
                (Op::SetMinAlgo { min_algo: 2 }, &d2),
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
        let (mut entries, rfp) = chain(&d1, vec![(add(&d2), &d1)]);
        entries[1].prev[0] ^= 0x01;
        assert!(matches!(fold(&entries, &rfp), Err(RosterError::ChainBreak)));
    }

    #[test]
    fn bad_signature_rejected() {
        let d1 = DeviceKey::generate().unwrap();
        let (mut entries, rfp) = chain(&d1, vec![(Op::SetMinAlgo { min_algo: 2 }, &d1)]);
        *entries[1].sig.last_mut().unwrap() ^= 0x01;
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
                (add(&d2), &d1),
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
        bytes[40] = 0xFF; // the op tag follows seq(8) + prev(32)
        assert!(matches!(decode_entry(&bytes), Err(RosterError::BadOp)));
    }

    // ---- Per-entry AEAD (§9.5) ----

    fn roster_key_for(gen: u32, key: [u8; 32]) -> SecretKey {
        MasterKey::new(gen, key).roster_key()
    }

    #[test]
    fn entry_aead_round_trip_v2_and_legacy_v1() {
        let d1 = DeviceKey::generate().unwrap();
        let (g, _rfp) = genesis(&d1, vec![], MK, 0).unwrap();
        let pt = encode_entry(&g);
        let rk = roster_key_for(1, [0x33; 32]);

        let blob = seal_entry(&rk, 1, 0, &pt).unwrap();
        assert_eq!(blob[4], 2, "new entries are format v2");
        assert_eq!(open_entry(&rk, 1, 0, &blob).unwrap(), pt);
        assert_eq!(
            decode_entry(&open_entry(&rk, 1, 0, &blob).unwrap()).unwrap(),
            g
        );

        let v1 = seal_entry_v1(&rk, 1, 0, &pt);
        assert_eq!(open_entry(&rk, 1, 0, &v1).unwrap(), pt);
    }

    /// Two entries sealed at the same `(key, seq)` (a CAS race) never share a keystream.
    #[test]
    fn raced_entries_at_one_seq_use_distinct_keys() {
        let rk = roster_key_for(1, [0x33; 32]);
        let a = seal_entry(&rk, 1, 5, &[0u8; 64]).unwrap();
        let b = seal_entry(&rk, 1, 5, &[0u8; 64]).unwrap();
        let body = FRAME_LEN + ROSTER_ENTRY_SALT_LEN + CTX_TAG_LEN;
        assert_ne!(&a[FRAME_LEN..FRAME_LEN + 32], &b[FRAME_LEN..FRAME_LEN + 32]);
        assert_ne!(
            &a[body..],
            &b[body..],
            "equal plaintexts must not encrypt to equal ciphertexts"
        );
    }

    #[test]
    fn entry_aead_wrong_generation_is_frame_mismatch() {
        let rk = roster_key_for(1, [0x33; 32]);
        let blob = seal_entry(&rk, 1, 0, b"entry").unwrap();
        assert!(matches!(
            open_entry(&rk, 2, 0, &blob),
            Err(RosterError::Frame(FrameError::FrameMismatch))
        ));
    }

    #[test]
    fn entry_aead_wrong_seq_key_or_tamper_rejected() {
        let rk = roster_key_for(1, [0x33; 32]);
        let other = roster_key_for(1, [0x44; 32]);
        let blob = seal_entry(&rk, 1, 7, b"entry").unwrap();
        assert!(matches!(
            open_entry(&rk, 1, 8, &blob),
            Err(RosterError::Aead)
        ));
        assert!(matches!(
            open_entry(&other, 1, 7, &blob),
            Err(RosterError::Aead)
        ));
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            open_entry(&rk, 1, 7, &bad),
            Err(RosterError::Aead)
        ));
        let mut salt_flip = blob.clone();
        salt_flip[FRAME_LEN] ^= 0x01;
        assert!(matches!(
            open_entry(&rk, 1, 7, &salt_flip),
            Err(RosterError::Aead)
        ));
        assert!(open_entry(&rk, 1, 7, &blob[..FRAME_LEN + 10]).is_err());
    }

    // ---- key histories (§8.2) ----

    #[test]
    fn roster_keyhist_round_trip_and_rejections() {
        let rk1 = roster_key_for(1, [0x01; 32]);
        let rk2 = roster_key_for(2, [0x02; 32]);
        let wrap = seal_roster_keyhist(&rk2, 1, &rk1);
        assert_eq!(wrap.len(), 64);
        assert_eq!(&open_roster_keyhist(&rk2, 1, &wrap).unwrap()[..], &rk1[..]);
        let wrong = roster_key_for(2, [0x99; 32]);
        assert!(matches!(
            open_roster_keyhist(&wrong, 1, &wrap),
            Err(RosterError::Aead)
        ));
        assert!(matches!(
            open_roster_keyhist(&rk2, 2, &wrap),
            Err(RosterError::Aead)
        ));
        let mut bad = wrap;
        bad[ROSTER_KEYHIST_LEN - 1] ^= 0x01;
        assert!(matches!(
            open_roster_keyhist(&rk2, 1, &bad),
            Err(RosterError::Aead)
        ));
        assert!(matches!(
            open_roster_keyhist(&rk2, 1, &wrap[..ROSTER_KEYHIST_LEN - 1]),
            Err(RosterError::Aead)
        ));
    }

    #[test]
    fn peel_recovers_every_generation_and_aborts_on_a_missing_wrap() {
        let n = 5u32;
        let rks: Vec<SecretKey> = (1..=n).map(|g| roster_key_for(g, [g as u8; 32])).collect();
        let mut history: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for g in 1..n {
            let wrap = seal_roster_keyhist(&rks[g as usize], g, &rks[(g - 1) as usize]);
            history.insert(g, wrap.to_vec());
        }
        let peeled = peel_roster_keys(&rks[(n - 1) as usize], n, &history).unwrap();
        assert_eq!(peeled.len(), n as usize);
        for g in 1..=n {
            assert_eq!(&peeled[&g][..], &rks[(g - 1) as usize][..], "gen {g}");
        }
        history.remove(&1);
        assert!(matches!(
            peel_roster_keys(&rks[(n - 1) as usize], n, &history),
            Err(RosterError::Aead)
        ));
    }

    #[test]
    fn data_keyhist_peels_every_master_key_checked_against_mk_commits() {
        let mks: [[u8; 32]; 5] = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
        let commits: BTreeMap<u32, MkCommit> = (1u32..=5)
            .map(|g| (g, MasterKey::new(g, mks[(g - 1) as usize]).mk_commit()))
            .collect();
        let mut history: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for g in 1u32..5 {
            let wrap = seal_data_keyhist(&mks[g as usize], g, &mks[(g - 1) as usize]);
            history.insert(g, wrap.to_vec());
        }
        let peeled = peel_data_keys(&mks[4], 5, &history, &commits).unwrap();
        assert_eq!(peeled.len(), 5);
        for g in 1u32..=5 {
            assert_eq!(peeled[&g].mk_commit(), commits[&g]);
        }
        // A wrap re-sealed around a foreign key opens, but fails the chain's commitment.
        let mut forged = history.clone();
        forged.insert(1, seal_data_keyhist(&mks[1], 1, &[0x66; 32]).to_vec());
        assert!(matches!(
            peel_data_keys(&mks[4], 5, &forged, &commits),
            Err(RosterError::MkCommitMismatch)
        ));
        let mut partial = history.clone();
        partial.remove(&1);
        assert!(matches!(
            peel_data_keys(&mks[4], 5, &partial, &commits),
            Err(RosterError::Aead)
        ));
    }

    /// Frozen wire KATs mirrored in `vectors/secsec-kat-v1.txt`, with `roster_key[g=1]` of `master_key=[0x11;32]`.
    #[test]
    fn wire_kat() {
        let rk = roster_key_for(1, [0x11; 32]);

        // A legacy v1 entry opens.
        let v1 = seal_entry_v1(&rk, 1, 1, b"roster-entry-kat");
        assert_eq!(
            hx(&v1),
            "7373656301010100000004c69b06e76f52eb0570b7bac2eff9552c545c1906dddfc31b06a39faf2e36d4a764087224e2cb1ce70dbe9a15092153aa"
        );
        assert_eq!(open_entry(&rk, 1, 1, &v1).unwrap(), b"roster-entry-kat");

        // v2 entry with salt 0x5a*32.
        let v2 = seal_entry_with_salt(&rk, 1, 1, &[0x5a; 32], b"roster-entry-kat");
        assert_eq!(
            hx(&v2),
            "73736563020101000000045a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a64ad3cec963e4616bf6167e47c529acf1118b20272d7df6f3616cd76cf3ead82768088696a16be8cf17e6f3575496075"
        );
        assert_eq!(open_entry(&rk, 1, 1, &v2).unwrap(), b"roster-entry-kat");

        let kg: [u8; 32] = core::array::from_fn(|i| i as u8);
        let wrap = seal_roster_keyhist(&rk, 1, &kg);
        assert_eq!(
            hx(&wrap),
            "92397f6784bd2df46eb8a3fb1984fa98970abc9d6ecc80656a8d674b55221483d7626d73f776a99579f59ba22ce7b32d3929091d7b720d4d465e0b3f775f4a68"
        );
        assert_eq!(&open_roster_keyhist(&rk, 1, &wrap).unwrap()[..], &kg[..]);
    }

    // ---- Cold-start fold (§8.1) ----

    #[test]
    fn cold_start_fold_bootstraps_multigen_chain_with_mixed_entry_versions() {
        const MK1: [u8; 32] = [0x51; 32];
        const MK2: [u8; 32] = [0x52; 32];
        let mkc1 = MasterKey::new(1, MK1).mk_commit();
        let mkc2 = MasterKey::new(2, MK2).mk_commit();
        let rk1: [u8; 32] = *MasterKey::new(1, MK1).roster_key();
        let rk2: [u8; 32] = *MasterKey::new(2, MK2).roster_key();

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
        let e2 = append(&e1, Op::Rotate { mk_commit: mkc2 }, &d1, 0).unwrap();
        let e3 = append(&e2, Op::SetMinAlgo { min_algo: 2 }, &d2, 0).unwrap();

        // A chain of legacy v1 entries followed by v2 ones.
        let stored = vec![
            seal_entry_v1(&rk1, 1, 0, &encode_entry(&g)),
            seal_entry_v1(&rk1, 1, 1, &encode_entry(&e1)),
            seal_entry(&rk2, 2, 2, &encode_entry(&e2)).unwrap(),
            seal_entry(&rk2, 2, 3, &encode_entry(&e3)).unwrap(),
        ];
        let mut hist = BTreeMap::new();
        hist.insert(1u32, seal_roster_keyhist(&rk2, 1, &rk1).to_vec());

        let (state, mk) = cold_start_fold(&MK2, 2, &rfp, &hist, &stored).unwrap();
        assert_eq!(state.generation, 2);
        assert_eq!(state.min_algo, 2);
        assert!(state.is_member(&d1.device_id().unwrap()));
        assert!(state.is_member(&d2.device_id().unwrap()));
        assert_eq!(mk.generation(), 2);
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
            seal_entry(&rk1, 1, 0, &encode_entry(&g)).unwrap(),
            seal_entry(&rk1, 1, 1, &encode_entry(&e1)).unwrap(),
        ];

        assert!(cold_start_fold(&MK1, 1, &rfp, &empty, &stored).is_ok());
        assert!(matches!(
            cold_start_fold(&[0x99; 32], 1, &rfp, &empty, &stored),
            Err(RosterError::Aead)
        ));
        assert!(matches!(
            cold_start_fold(&MK1, 1, &[0u8; 32], &empty, &stored),
            Err(RosterError::RfpMismatch)
        ));
        assert!(matches!(
            cold_start_fold(&MK1, 2, &rfp, &empty, &stored),
            Err(RosterError::BadGeneration)
        ));
        // A chain whose genesis records another key's commitment fails the §7 step-3 check.
        let wrong_commit = MasterKey::new(1, [0xEE; 32]).mk_commit();
        let (gf, rfpf) = genesis(&d1, vec![], wrong_commit, 0).unwrap();
        let stored_f = vec![seal_entry(&rk1, 1, 0, &encode_entry(&gf)).unwrap()];
        assert!(matches!(
            cold_start_fold(&MK1, 1, &rfpf, &empty, &stored_f),
            Err(RosterError::MkCommitMismatch)
        ));
    }

    // ---- Model-based differential test (R5) ----

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

    /// Deterministically pick a current member (device 0 is never revoked).
    fn pick_member(members: &BTreeSet<usize>, hint: usize) -> usize {
        let v: Vec<usize> = members.iter().copied().collect();
        v[hint % v.len()]
    }

    fn commit_for(gen: u32) -> MkCommit {
        MasterKey::new(gen, [gen as u8; 32]).mk_commit()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// `fold` reproduces an independent reference model's membership, generation, and min_algo.
        #[test]
        fn fold_matches_reference_model(actions in proptest::collection::vec(act_strategy(), 0..40)) {
            let devices: Vec<DeviceKey> = (0..6).map(|_| DeviceKey::generate().unwrap()).collect();
            let ids: Vec<DeviceId> = devices.iter().map(|d| d.device_id().unwrap()).collect();

            let (g, rfp) = genesis(&devices[0], vec![], commit_for(1), 0).unwrap();
            let mut entries = vec![g];

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
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
