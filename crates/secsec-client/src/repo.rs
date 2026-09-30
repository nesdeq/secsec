//! Repository genesis, cold-start open, enrollment, and rotation over a [`Remote`] (`secsec-Design.md` §7, §8.1 to §8.4, §16).

use crate::{Remote, RemoteError, RosterWrite};
use secsec_kdf::{MasterKey, MasterKeys};
use secsec_pq::{XWingPublic, XWingSecret};
use secsec_proto::server::limits::MAX_TOTAL_SIGCHAIN;
use secsec_proto::wire::{HeadPut, KeyslotPut};
use secsec_roster::{
    append, append_many, cold_start_fold, decode_entry, encode_entry, frame_gen, genesis,
    open_entry, peel_data_keys, revoke_rotate_ops, seal_data_keyhist, seal_entry,
    seal_roster_keyhist, Entry, Op, RosterError, State,
};
use secsec_sig::{DeviceId, DeviceKey, DevicePublic};
use secsec_store::ABSENT_HEAD;
use secsec_sync::rollback::SiblingHead;
use secsec_sync::{build_head, open_head, random_nonce, ref_hash, seal_head, sign_head, HeadError};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// The X-Wing keyslot algorithm id (§8.3), and the highest one this build speaks.
pub(crate) const ALGO_XWING: u8 = 1;

/// A device's X-Wing keypair from its SSH private seed (§8.3), consistency-checked on every derivation.
fn xwing_keypair(device: &DeviceKey) -> Result<(XWingSecret, XWingPublic), RepoError> {
    XWingSecret::from_seed(*device.xwing_seed()?).map_err(|_| RepoError::Pq)
}

/// A device's published X-Wing public key, recorded in the roster at enrollment (§8.3).
pub(crate) fn device_xwing_pub(device: &DeviceKey) -> Result<Vec<u8>, RepoError> {
    Ok(xwing_keypair(device)?.1.to_bytes())
}

/// Wrap `master_key` to a validated X-Wing public key as `algo_id ‖ body` (§8.3).
fn wrap_keyslot(
    master_key: &[u8; 32],
    gen: u32,
    device_id: &DeviceId,
    xwing_pub: &[u8],
) -> Result<Vec<u8>, RepoError> {
    let pk = XWingPublic::from_bytes(xwing_pub).map_err(|_| RepoError::Pq)?;
    let body = secsec_pq::wrap_pq(master_key, gen, device_id, &pk).map_err(|_| RepoError::Pq)?;
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(ALGO_XWING);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Unwrap a keyslot to the candidate master key; its authenticity is the fold's `mk_commit` check (§8.1).
fn unwrap_keyslot_raw(
    keyslot: &[u8],
    gen: u32,
    device_id: &DeviceId,
    device: &DeviceKey,
) -> Result<Zeroizing<[u8; 32]>, RepoError> {
    let (&algo, body) = keyslot.split_first().ok_or(RepoError::BadKeyslot)?;
    match algo {
        ALGO_XWING => {}
        a if a > ALGO_XWING => return Err(RepoError::UpgradeRequired { floor: a }),
        a => return Err(RepoError::UnsupportedAlgo(a)),
    }
    let (sk, _) = xwing_keypair(device)?;
    secsec_pq::unwrap_pq_raw(body, gen, device_id, &sk).map_err(|_| RepoError::Pq)
}

/// Errors from repository genesis, open, enrollment, and rotation.
#[derive(Debug)]
pub enum RepoError {
    /// Roster fold or cold-start error (RFP or `mk_commit` mismatch included).
    Roster(RosterError),
    /// Signing/key error.
    Sig(secsec_sig::SigError),
    /// Head open/seal error during a revoke's head re-sign.
    Head(HeadError),
    /// OS RNG failure.
    Rng,
    /// The server holds no roster.
    NotInitialized,
    /// Genesis found an existing repository this device is not enrolled in.
    AlreadyInitialized,
    /// Genesis found an existing repository this device is already enrolled in.
    AlreadyEnrolled,
    /// This device owns no keyslot at the current generation.
    NoKeyslot,
    /// The roster-key-history wrap for generation `g` (§8.2) is absent.
    MissingRosterKeyhist(u32),
    /// The data key-history wrap for generation `g` (§8.2) is absent.
    MissingDataKeyhist(u32),
    /// The server returned a sigchain past the §19 total cap.
    ChainTooLong,
    /// The roster batch kept conflicting against a state that did not move.
    RosterCasConflict,
    /// A keyslot carried an algorithm id below any this build accepts.
    UnsupportedAlgo(u8),
    /// A keyslot was empty.
    BadKeyslot,
    /// The sigchain does not extend the persisted anchor (§8.1, P7): a server rollback.
    Rollback,
    /// An X-Wing operation failed (malformed or invalid public key, or ciphertext).
    Pq,
    /// The repository requires a keyslot algorithm newer than this build (§16).
    UpgradeRequired {
        /// The required floor.
        floor: u8,
    },
    /// The named device is not a current member.
    NotMember(DeviceId),
    /// The master-key generation cannot advance past `u32::MAX`.
    GenerationExhausted,
    /// The far side errored.
    Remote(RemoteError),
}

impl core::fmt::Display for RepoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RepoError::Roster(e) => write!(f, "roster: {e}"),
            RepoError::Sig(e) => write!(f, "sig: {e}"),
            RepoError::Head(e) => write!(f, "head: {e}"),
            RepoError::Rng => f.write_str("OS RNG failure"),
            RepoError::NotInitialized => f.write_str("the server holds no repository"),
            RepoError::AlreadyInitialized => {
                f.write_str("a repository already exists on this server")
            }
            RepoError::AlreadyEnrolled => {
                f.write_str("this device is already enrolled in the repository on this server")
            }
            RepoError::NoKeyslot => {
                f.write_str("this device holds no keyslot at the current generation")
            }
            RepoError::MissingRosterKeyhist(g) => {
                write!(f, "roster-key history for generation {g} is missing (§8.2)")
            }
            RepoError::MissingDataKeyhist(g) => {
                write!(f, "data key history for generation {g} is missing (§8.2)")
            }
            RepoError::ChainTooLong => {
                f.write_str("the server returned a sigchain past the §19 cap")
            }
            RepoError::RosterCasConflict => {
                f.write_str("the roster update kept conflicting; try again")
            }
            RepoError::UnsupportedAlgo(a) => write!(f, "unsupported keyslot algorithm {a}"),
            RepoError::BadKeyslot => f.write_str("empty keyslot"),
            RepoError::Rollback => f.write_str(
                "the server's sigchain does not extend the one this folder already verified (§8.1)",
            ),
            RepoError::Pq => f.write_str("X-Wing keyslot operation failed"),
            RepoError::UpgradeRequired { floor } => write!(
                f,
                "this repository requires keyslot algorithm {floor}; this build supports up to \
                 {ALGO_XWING}: upgrade secsec"
            ),
            RepoError::NotMember(d) => write!(
                f,
                "device {} is not a current member",
                secsec_snapshot::hex12(d)
            ),
            RepoError::GenerationExhausted => f.write_str("master-key generation exhausted"),
            RepoError::Remote(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for RepoError {}
impl From<RemoteError> for RepoError {
    fn from(e: RemoteError) -> Self {
        RepoError::Remote(e)
    }
}
impl From<RosterError> for RepoError {
    fn from(e: RosterError) -> Self {
        RepoError::Roster(e)
    }
}
impl From<secsec_sig::SigError> for RepoError {
    fn from(e: secsec_sig::SigError) -> Self {
        RepoError::Sig(e)
    }
}
impl From<HeadError> for RepoError {
    fn from(e: HeadError) -> Self {
        RepoError::Head(e)
    }
}

/// The persisted anti-rollback anchor (§8.1, P7): the highest accepted seq and `BLAKE3` of its stored blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RosterAnchor {
    /// Highest accepted sequence number.
    pub max_seq: u64,
    /// `BLAKE3` of the stored (sealed) entry blob at `max_seq`, also the tip CAS token.
    pub tip_hash: [u8; 32],
}

/// A cold-started view of the repository.
struct Fold {
    mk: MasterKey,
    state: State,
    anchor: RosterAnchor,
    entries: Vec<Vec<u8>>,
}

/// §7 `init` over a [`Remote`]: one atomic genesis batch (entry and own keyslot); returns the RFP to record.
pub async fn init_repo_remote<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    ts: u64,
) -> Result<[u8; 32], RepoError> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut_slice()).map_err(|_| RepoError::Rng)?;
    let mk = MasterKey::new(1, *key);
    let xwing_pub = device_xwing_pub(device)?;
    let (entry, rfp) = genesis(device, xwing_pub.clone(), mk.mk_commit(), ts)?;
    let device_id = device.device_id()?;
    let write = RosterWrite {
        old_tip: ABSENT_HEAD,
        entries: vec![seal_entry(&mk.roster_key(), 1, 0, &encode_entry(&entry))?],
        keyslots: vec![KeyslotPut {
            device_id,
            gen: 1,
            blob: wrap_keyslot(&key, 1, &device_id, &xwing_pub)?,
        }],
        ..RosterWrite::default()
    };
    match remote.roster_batch(&write).await {
        Ok(true) => Ok(rfp),
        Ok(false) => existing_repo(remote).await,
        Err(e) if e.is_not_enrolled() => existing_repo(remote).await,
        Err(e) => Err(e.into()),
    }
}

/// Classify a refused genesis: reads succeed only for an enrolled device.
async fn existing_repo<R: Remote>(remote: &R) -> Result<[u8; 32], RepoError> {
    match remote.get_roster_entry(0).await {
        Ok(_) => Err(RepoError::AlreadyEnrolled),
        Err(e) if e.is_not_enrolled() => Err(RepoError::AlreadyInitialized),
        Err(e) => Err(e.into()),
    }
}

/// Fetch the whole sigchain, refusing one past the §19 total cap.
async fn fetch_roster_entries<R: Remote>(remote: &R) -> Result<Vec<Vec<u8>>, RepoError> {
    let mut entries = Vec::new();
    for seq in 0..=MAX_TOTAL_SIGCHAIN {
        match remote.get_roster_entry(seq).await? {
            Some(_) if seq == MAX_TOTAL_SIGCHAIN => return Err(RepoError::ChainTooLong),
            Some(blob) => entries.push(blob),
            None => break,
        }
    }
    Ok(entries)
}

/// §16: a floor above this build's algorithm stops the client instead of misreading the repo.
fn enforce_min_algo(state: &State) -> Result<(), RepoError> {
    if state.min_algo > ALGO_XWING {
        return Err(RepoError::UpgradeRequired {
            floor: state.min_algo,
        });
    }
    Ok(())
}

/// §8.1 cold start: fetch the chain, check it extends `prev`, unwrap our keyslot, peel, fold, verify RFP and `mk_commit`.
async fn fold<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    rfp: &[u8; 32],
    prev: Option<RosterAnchor>,
) -> Result<Fold, RepoError> {
    let entries = fetch_roster_entries(remote).await?;
    let tip = entries.last().ok_or(RepoError::NotInitialized)?;
    if let Some(p) = prev {
        let at = usize::try_from(p.max_seq).ok().and_then(|i| entries.get(i));
        if at.map(|b| *blake3::hash(b).as_bytes()) != Some(p.tip_hash) {
            return Err(RepoError::Rollback);
        }
    }
    let anchor = RosterAnchor {
        max_seq: (entries.len() - 1) as u64,
        tip_hash: *blake3::hash(tip).as_bytes(),
    };
    let g_cur = frame_gen(tip)?;
    let device_id = device.device_id()?;
    let keyslot = remote
        .get_keyslot(&device_id, g_cur)
        .await?
        .ok_or(RepoError::NoKeyslot)?;
    let candidate = unwrap_keyslot_raw(&keyslot, g_cur, &device_id, device)?;
    let mut keyhist: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for g in 1..g_cur {
        let wrap = remote
            .get_roster_keyhist(g)
            .await?
            .ok_or(RepoError::MissingRosterKeyhist(g))?;
        keyhist.insert(g, wrap);
    }
    let (state, mk) = cold_start_fold(&candidate, g_cur, rfp, &keyhist, &entries)?;
    enforce_min_algo(&state)?;
    Ok(Fold {
        mk,
        state,
        anchor,
        entries,
    })
}

/// The decrypted tip entry of a fold (at the current generation, which the fold checked).
fn tip_entry(fold: &Fold) -> Result<Entry, RepoError> {
    let tip = fold.entries.last().ok_or(RepoError::NotInitialized)?;
    let pt = open_entry(
        &fold.mk.roster_key(),
        fold.mk.generation(),
        fold.anchor.max_seq,
        tip,
    )?;
    Ok(decode_entry(&pt)?)
}

/// §8.1 cold start over a [`Remote`]; `prev` is the persisted anchor, which the chain must extend.
pub async fn open_repo_remote<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    rfp: &[u8; 32],
    prev: Option<RosterAnchor>,
) -> Result<(MasterKey, State, RosterAnchor), RepoError> {
    let f = fold(remote, device, rfp, prev).await?;
    Ok((f.mk, f.state, f.anchor))
}

/// Whether the sigchain grew past `anchor` (the cheap per-tick probe before a refold).
pub async fn roster_grew<R: Remote>(remote: &R, anchor: &RosterAnchor) -> Result<bool, RepoError> {
    let next = anchor.max_seq.saturating_add(1);
    Ok(remote.get_roster_entry(next).await?.is_some())
}

/// The §8.2 data key ring: `master_key_g` for every generation, each checked against the chain's `mk_commit`.
pub async fn data_keyring_remote<R: Remote>(
    remote: &R,
    mk: &MasterKey,
    state: &State,
) -> Result<BTreeMap<u32, MasterKey>, RepoError> {
    let g_cur = mk.generation();
    let mut hist: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for g in 1..g_cur {
        let wrap = remote
            .get_keyhist(g)
            .await?
            .ok_or(RepoError::MissingDataKeyhist(g))?;
        hist.insert(g, wrap);
    }
    Ok(peel_data_keys(
        mk.expose_secret(),
        g_cur,
        &hist,
        &state.mk_commits,
    )?)
}

/// §7 grant: one batch appending `AddDevice` and the joiner's keyslot, refolding and retrying while the tip moves.
pub(crate) async fn grant_device_remote<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    rfp: &[u8; 32],
    prev: Option<RosterAnchor>,
    d_pubkey: &DevicePublic,
    d_xwing_pub: &[u8],
    ts: u64,
) -> Result<RosterAnchor, RepoError> {
    XWingPublic::from_bytes(d_xwing_pub).map_err(|_| RepoError::Pq)?;
    let d_id = d_pubkey.device_id()?;
    let d_canonical = d_pubkey.to_canonical()?;
    let mut prev = prev;
    let mut last: Option<[u8; 32]> = None;
    loop {
        let fold = fold(remote, device, rfp, prev).await?;
        prev = Some(fold.anchor);
        let g = fold.mk.generation();
        let op = Op::AddDevice {
            pubkey: d_canonical.clone(),
            mk_commit: fold.mk.mk_commit(),
            enroll_pub: d_xwing_pub.to_vec(),
        };
        let entry = append(&tip_entry(&fold)?, op, device, ts)?;
        let blob = seal_entry(&fold.mk.roster_key(), g, entry.seq, &encode_entry(&entry))?;
        let tip_hash = *blake3::hash(&blob).as_bytes();
        let write = RosterWrite {
            old_tip: fold.anchor.tip_hash,
            entries: vec![blob],
            keyslots: vec![KeyslotPut {
                device_id: d_id,
                gen: g,
                blob: wrap_keyslot(fold.mk.expose_secret(), g, &d_id, d_xwing_pub)?,
            }],
            ..RosterWrite::default()
        };
        if remote.roster_batch(&write).await? {
            return Ok(RosterAnchor {
                max_seq: entry.seq,
                tip_hash,
            });
        }
        // Retry only while the tip moves; a conflict against an unchanged tip will not resolve.
        if last == Some(fold.anchor.tip_hash) {
            return Err(RepoError::RosterCasConflict);
        }
        last = Some(fold.anchor.tip_hash);
    }
}

/// A revocation: the target and the first sigchain seq whose grants its closure sweeps (§8.1).
#[derive(Debug, Clone, Copy)]
pub struct Revoke {
    /// The device to revoke.
    pub device: DeviceId,
    /// Grants at or after this seq, down the target's add-by tree, are revoked with it.
    pub after_seq: u64,
}

/// What a rotation did.
pub struct Rotation {
    /// The new generation's master key.
    pub mk: MasterKey,
    /// The roster folded after the rotation.
    pub state: State,
    /// The new anchor to persist.
    pub anchor: RosterAnchor,
    /// Every device revoked, the target first.
    pub revoked: Vec<DeviceId>,
}

/// The revoke preview: the target and every device its closure would revoke, against `state`.
#[must_use]
pub fn revoke_preview(state: &State, revoke: &Revoke, revoker: &DeviceId) -> Vec<DeviceId> {
    std::iter::once(revoke.device)
        .chain(secsec_roster::revoke_closure(
            state,
            &revoke.device,
            revoke.after_seq,
            revoker,
        ))
        .collect()
}

/// §8.4 rotation as one atomic batch: entries, re-wrapped keyslots, both key histories, revocations, and the head re-sign.
pub async fn rotate_repo_remote<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    rfp: &[u8; 32],
    prev: Option<RosterAnchor>,
    revoke: Option<Revoke>,
    ref_name: &str,
    ts: u64,
) -> Result<Rotation, RepoError> {
    let me = device.device_id()?;
    let mut prev = prev;
    let mut last: Option<([u8; 32], Option<[u8; 32]>)> = None;
    loop {
        let fold = fold(remote, device, rfp, prev).await?;
        prev = Some(fold.anchor);
        let g = fold.mk.generation();
        let g1 = g.checked_add(1).ok_or(RepoError::GenerationExhausted)?;
        let mut newkey = Zeroizing::new([0u8; 32]);
        getrandom::fill(newkey.as_mut_slice()).map_err(|_| RepoError::Rng)?;
        let new_mk = MasterKey::new(g1, *newkey);
        let (rk_g, rk_g1) = (fold.mk.roster_key(), new_mk.roster_key());

        let ops = match revoke {
            Some(r) if !fold.state.is_member(&r.device) => {
                return Err(RepoError::NotMember(r.device))
            }
            Some(r) => {
                revoke_rotate_ops(&fold.state, &r.device, r.after_seq, &me, new_mk.mk_commit())?
            }
            None => vec![Op::Rotate {
                mk_commit: new_mk.mk_commit(),
            }],
        };
        let revoked: Vec<DeviceId> = ops
            .iter()
            .filter_map(|op| match op {
                Op::RevokeDevice { device } => Some(*device),
                _ => None,
            })
            .collect();
        let new_entries = append_many(&tip_entry(&fold)?, ops, device, ts)?;
        // Entries before the Rotate stay under generation g; the Rotate and anything after it seal under g+1 (§9.5).
        let mut sealed = Vec::with_capacity(new_entries.len());
        let mut gen = g;
        for e in &new_entries {
            if matches!(e.op, Op::Rotate { .. }) {
                gen = g1;
            }
            let rk = if gen == g1 { &rk_g1 } else { &rk_g };
            sealed.push(seal_entry(rk, gen, e.seq, &encode_entry(e))?);
        }
        let gone: BTreeSet<DeviceId> = revoked.iter().copied().collect();
        let mut keyslots = Vec::new();
        for id in fold.state.members.keys().filter(|id| !gone.contains(*id)) {
            let pubkey = fold.state.enroll_pubs.get(id).ok_or(RepoError::Pq)?;
            keyslots.push(KeyslotPut {
                device_id: *id,
                gen: g1,
                blob: wrap_keyslot(&newkey, g1, id, pubkey)?,
            });
        }
        let tip_seq = new_entries.last().map_or(fold.anchor.max_seq, |e| e.seq);
        let head = resign_head(remote, &fold, &new_mk, device, ref_name, &gone, tip_seq).await?;
        let seen = (fold.anchor.tip_hash, head.as_ref().map(|h| h.old_head));
        let write = RosterWrite {
            old_tip: fold.anchor.tip_hash,
            entries: sealed,
            keyslots,
            keyhist: Some((
                g,
                seal_data_keyhist(&newkey, g, fold.mk.expose_secret()).to_vec(),
            )),
            roster_keyhist: Some((g, seal_roster_keyhist(&rk_g1, g, &rk_g).to_vec())),
            revoke: revoked.clone(),
            head,
        };
        if remote.roster_batch(&write).await? {
            let after = self::fold(remote, device, rfp, Some(fold.anchor)).await?;
            return Ok(Rotation {
                mk: after.mk,
                state: after.state,
                anchor: after.anchor,
                revoked,
            });
        }
        // Retry only while the tip or the head moves; a conflict against an unchanged state will not resolve.
        if last == Some(seen) {
            return Err(RepoError::RosterCasConflict);
        }
        last = Some(seen);
    }
}

/// When the current head's signer is being revoked: the same commit re-signed by us, sealed at the new generation (§8.4).
async fn resign_head<R: Remote>(
    remote: &R,
    fold: &Fold,
    new_mk: &MasterKey,
    device: &DeviceKey,
    ref_name: &str,
    gone: &BTreeSet<DeviceId>,
    roster_seq: u64,
) -> Result<Option<HeadPut>, RepoError> {
    if gone.is_empty() {
        return Ok(None);
    }
    let keyring = data_keyring_remote(remote, &fold.mk, &fold.state).await?;
    let rnk = MasterKeys::ref_name_key(&keyring);
    let ref_h = ref_hash(&rnk, ref_name);
    let Some(blob) = remote.get_ref(&ref_h).await? else {
        return Ok(None);
    };
    let (head, sig) = open_head(&keyring, &rnk, ref_name, &blob)?;
    match SiblingHead::verified(&fold.state.members, &head, &sig) {
        Some(s) if gone.contains(&s.device_id) => {}
        _ => return Ok(None),
    }
    let next = build_head(ref_name, head.commit_id, roster_seq, Some(&head))?;
    let sig = sign_head(device, &next)?;
    let new_blob = seal_head(new_mk, &rnk, &next, &sig, &random_nonce()?);
    Ok(Some(HeadPut {
        ref_h,
        old_head: *blake3::hash(&blob).as_bytes(),
        new_blob,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testmem::MemRemote;
    use crate::{fetch_head, fetch_verified_head, push_head, push_objects};
    use secsec_store::Store;
    use std::sync::atomic::Ordering;

    fn remote(dir: &tempfile::TempDir) -> MemRemote {
        MemRemote::new(Store::open(dir.path().join("r.redb")).unwrap())
    }

    /// Publish a one-file commit by `dev` as the head of `main`.
    async fn publish(r: &MemRemote, dev: &DeviceKey, keys: &BTreeMap<u32, MasterKey>) -> [u8; 32] {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f.txt"), b"v1").unwrap();
        let snap = secsec_snapshot::snapshot_tree(
            src.path(),
            keys,
            &r.store,
            None,
            &mut secsec_snapshot::SnapshotMemo::default(),
        )
        .unwrap();
        let commit = secsec_snapshot::Commit {
            root_tree: snap.root,
            root_salt: snap.salt,
            parents: vec![],
            device_id: dev.device_id().unwrap(),
            version: 1,
            roster_seq: 0,
            last_seen_head: [0; 32],
            ts: 0,
        };
        let id =
            secsec_snapshot::seal_signed_commit(keys.current(), &r.store, dev, &commit).unwrap();
        push_objects(r, &r.store, keys, &id, None, &[0x60; 16])
            .await
            .unwrap();
        push_head(r, keys, dev, "main", id, 0, None, &[0x60; 16])
            .await
            .unwrap();
        id
    }

    async fn keyring(r: &MemRemote, dev: &DeviceKey, rfp: &[u8; 32]) -> BTreeMap<u32, MasterKey> {
        let (mk, st, _) = open_repo_remote(r, dev, rfp, None).await.unwrap();
        data_keyring_remote(r, &mk, &st).await.unwrap()
    }

    /// Genesis is atomic and refused on an existing repo without touching the enrolled device's keyslot.
    #[tokio::test]
    async fn init_open_and_refused_reinit() {
        let dir = tempfile::tempdir().unwrap();
        let r = remote(&dir);
        let device = DeviceKey::generate().unwrap();
        let rfp = init_repo_remote(&r, &device, 0).await.unwrap();
        let (mk1, st, anchor) = open_repo_remote(&r, &device, &rfp, None).await.unwrap();
        assert_eq!(mk1.generation(), 1);
        assert!(st.is_member(&device.device_id().unwrap()));
        assert_eq!(anchor.max_seq, 0);
        assert!(matches!(
            init_repo_remote(&r, &device, 0).await,
            Err(RepoError::AlreadyEnrolled)
        ));
        let (mk2, _, _) = open_repo_remote(&r, &device, &rfp, Some(anchor))
            .await
            .unwrap();
        assert_eq!(mk2.mk_commit(), mk1.mk_commit());
        assert!(open_repo_remote(&r, &device, &[0xAB; 32], None)
            .await
            .is_err());
        assert!(matches!(
            open_repo_remote(&r, &DeviceKey::generate().unwrap(), &rfp, None).await,
            Err(RepoError::NoKeyslot)
        ));
        let beyond = RosterAnchor {
            max_seq: 5,
            tip_hash: anchor.tip_hash,
        };
        assert!(matches!(
            open_repo_remote(&r, &device, &rfp, Some(beyond)).await,
            Err(RepoError::Rollback)
        ));
    }

    #[tokio::test]
    async fn rotation_cold_starts_and_keeps_old_objects_readable() {
        use secsec_frame::ObjType;
        use secsec_object::{open_object, seal_object};
        let dir = tempfile::tempdir().unwrap();
        let r = remote(&dir);
        let device = DeviceKey::generate().unwrap();
        let rfp = init_repo_remote(&r, &device, 0).await.unwrap();
        let (mk1, st1, a1) = open_repo_remote(&r, &device, &rfp, None).await.unwrap();
        assert_eq!(data_keyring_remote(&r, &mk1, &st1).await.unwrap().len(), 1);
        let salt = [7u8; 16];
        let (id1, blob1) = seal_object(&mk1, ObjType::Chunk, &salt, b"gen-1 content");

        let rot = rotate_repo_remote(&r, &device, &rfp, Some(a1), None, "main", 0)
            .await
            .unwrap();
        assert_eq!(rot.mk.generation(), 2);
        assert!(rot.revoked.is_empty());
        let rot3 = rotate_repo_remote(&r, &device, &rfp, Some(rot.anchor), None, "main", 0)
            .await
            .unwrap();
        assert_eq!(rot3.mk.generation(), 3);

        let (mk, st, _) = open_repo_remote(&r, &device, &rfp, None).await.unwrap();
        assert_eq!(mk.generation(), 3);
        assert!(st.mk_commits.contains_key(&1) && st.mk_commits.contains_key(&3));
        let ring = data_keyring_remote(&r, &mk, &st).await.unwrap();
        assert_eq!(ring.len(), 3);
        assert_eq!(
            open_object(&ring, ObjType::Chunk, &salt, &id1, &blob1).unwrap(),
            b"gen-1 content"
        );
    }

    /// §16: an unknown keyslot algorithm above this build asks for an upgrade; below it is unsupported.
    #[tokio::test]
    async fn keyslot_algorithm_floor() {
        let dir = tempfile::tempdir().unwrap();
        let r = remote(&dir);
        let device = DeviceKey::generate().unwrap();
        let did = device.device_id().unwrap();
        let rfp = init_repo_remote(&r, &device, 0).await.unwrap();
        let keyslot = r.store.get_keyslot(&did, 1).unwrap().unwrap();
        assert_eq!(keyslot[0], ALGO_XWING);
        let mut newer = keyslot.clone();
        newer[0] = ALGO_XWING + 1;
        r.store.put_keyslot(&did, 1, &newer).unwrap();
        assert!(matches!(
            open_repo_remote(&r, &device, &rfp, None).await,
            Err(RepoError::UpgradeRequired { floor }) if floor == ALGO_XWING + 1
        ));
        let mut older = keyslot;
        older[0] = 0;
        r.store.put_keyslot(&did, 1, &older).unwrap();
        assert!(matches!(
            open_repo_remote(&r, &device, &rfp, None).await,
            Err(RepoError::UnsupportedAlgo(0))
        ));
    }

    /// Revoke is one batch that deletes every generation of the target's keyslots and re-signs its head.
    #[tokio::test]
    async fn revoke_is_atomic_deletes_all_generations_and_resigns_the_head() {
        let dir = tempfile::tempdir().unwrap();
        let r = remote(&dir);
        let e = DeviceKey::generate().unwrap();
        let d = DeviceKey::generate().unwrap();
        let did = d.device_id().unwrap();
        let rfp = init_repo_remote(&r, &e, 0).await.unwrap();
        grant_device_remote(
            &r,
            &e,
            &rfp,
            None,
            &d.public(),
            &device_xwing_pub(&d).unwrap(),
            0,
        )
        .await
        .unwrap();
        // A plain rotation gives D a gen-2 keyslot; D then publishes the head.
        rotate_repo_remote(&r, &e, &rfp, None, None, "main", 0)
            .await
            .unwrap();
        assert!(r.store.get_keyslot(&did, 1).unwrap().is_some());
        assert!(r.store.get_keyslot(&did, 2).unwrap().is_some());
        let ring_d = keyring(&r, &d, &rfp).await;
        let commit = publish(&r, &d, &ring_d).await;

        // One refused batch is retried after a refold.
        r.refuse_batches.store(1, Ordering::SeqCst);
        let rot = rotate_repo_remote(
            &r,
            &e,
            &rfp,
            None,
            Some(Revoke {
                device: did,
                after_seq: 0,
            }),
            "main",
            0,
        )
        .await
        .unwrap();
        assert_eq!(rot.revoked, vec![did]);
        assert_eq!(rot.mk.generation(), 3);
        assert!(!rot.state.is_member(&did));
        assert!(rot.state.ever_members.contains_key(&did));
        for g in 1..=3 {
            assert!(r.store.get_keyslot(&did, g).unwrap().is_none(), "gen {g}");
        }
        let ring = data_keyring_remote(&r, &rot.mk, &rot.state).await.unwrap();
        let rh = fetch_verified_head(&r, &ring, &rot.state.members, "main")
            .await
            .unwrap()
            .expect("head survives the revoke");
        assert_eq!(rh.head.commit_id, commit);
        assert_eq!(rh.sibling.device_id, e.device_id().unwrap());
        assert!(matches!(
            open_repo_remote(&r, &d, &rfp, None).await,
            Err(RepoError::NoKeyslot)
        ));
        // A persistently refused batch terminates instead of spinning.
        r.refuse_batches.store(u32::MAX, Ordering::SeqCst);
        assert!(matches!(
            rotate_repo_remote(&r, &e, &rfp, None, None, "main", 0).await,
            Err(RepoError::RosterCasConflict)
        ));
    }

    /// The closure sweeps grants made at or after `after_seq` down the target's tree, never the revoker.
    #[tokio::test]
    async fn revoke_closure_honours_the_revokers_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let r = remote(&dir);
        let e = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let c = DeviceKey::generate().unwrap();
        let rfp = init_repo_remote(&r, &e, 0).await.unwrap();
        let seen_by_e = grant_device_remote(
            &r,
            &e,
            &rfp,
            None,
            &b.public(),
            &device_xwing_pub(&b).unwrap(),
            0,
        )
        .await
        .unwrap();
        grant_device_remote(
            &r,
            &b,
            &rfp,
            None,
            &c.public(),
            &device_xwing_pub(&c).unwrap(),
            0,
        )
        .await
        .unwrap();
        let (_, st, _) = open_repo_remote(&r, &e, &rfp, None).await.unwrap();
        let bid = b.device_id().unwrap();
        let cid = c.device_id().unwrap();
        let me = e.device_id().unwrap();
        let later = Revoke {
            device: bid,
            after_seq: seen_by_e.max_seq + 1,
        };
        assert_eq!(revoke_preview(&st, &later, &me), vec![bid, cid]);
        let earlier = Revoke {
            device: bid,
            after_seq: seen_by_e.max_seq + 2,
        };
        assert_eq!(revoke_preview(&st, &earlier, &me), vec![bid]);
        let rot = rotate_repo_remote(&r, &e, &rfp, None, Some(later), "main", 0)
            .await
            .unwrap();
        assert_eq!(rot.revoked, vec![bid, cid]);
        assert!(!rot.state.is_member(&cid));
        assert!(matches!(
            rotate_repo_remote(
                &r,
                &e,
                &rfp,
                None,
                Some(Revoke {
                    device: me,
                    after_seq: 0
                }),
                "main",
                0
            )
            .await,
            Err(RepoError::Roster(RosterError::SelfRevoke))
        ));
    }

    /// Grant validates the joiner's X-Wing key before writing anything.
    #[tokio::test]
    async fn grant_rejects_an_invalid_xwing_key() {
        let dir = tempfile::tempdir().unwrap();
        let r = remote(&dir);
        let e = DeviceKey::generate().unwrap();
        let d = DeviceKey::generate().unwrap();
        let rfp = init_repo_remote(&r, &e, 0).await.unwrap();
        let mut bad = device_xwing_pub(&d).unwrap();
        bad[..384].fill(0xFF);
        assert!(matches!(
            grant_device_remote(&r, &e, &rfp, None, &d.public(), &bad, 0).await,
            Err(RepoError::Pq)
        ));
        assert_eq!(r.store.roster_len().unwrap(), 1);
    }

    /// A head published before a rotation stays at the same path and opens with the peeled ring.
    #[tokio::test]
    async fn head_survives_a_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let r = remote(&dir);
        let device = DeviceKey::generate().unwrap();
        let rfp = init_repo_remote(&r, &device, 0).await.unwrap();
        let ring1 = keyring(&r, &device, &rfp).await;
        let commit = publish(&r, &device, &ring1).await;
        rotate_repo_remote(&r, &device, &rfp, None, None, "main", 0)
            .await
            .unwrap();
        let ring2 = keyring(&r, &device, &rfp).await;
        assert_eq!(ring2.len(), 2);
        let (head, _, _) = fetch_head(&r, &ring2, "main").await.unwrap().unwrap();
        assert_eq!(head.commit_id, commit);
    }
}
