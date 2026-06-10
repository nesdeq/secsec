//! Repository genesis and cold-start open (`finaldesign.md` §7 `init`, §8.1 cold-start fold).
//!
//! [`init_repo`] creates a fresh repo for device 1: generate `master_key_1`, write the self-signed
//! **genesis** sigchain entry (the RFP anchor, §5/§7) and device-1's **keyslot** wrapping the master
//! key, both into a [`Store`]. The master key is dropped after wrapping — the keyslot is its durable
//! form. [`open_repo`] reverses it (§8.1): unwrap the keyslot to a candidate, peel roster keys,
//! decrypt + fold the chain, and verify both the RFP anchor and the candidate against `mk_commit`.
//!
//! [`rotate_repo`] mints a new generation (§8.4): it extends the never-trimmed roster-key history
//! (§8.2), appends the `Rotate` entry (with the transitive revoke closure when revoking), and re-wraps
//! every remaining member's keyslot. [`open_repo`]/[`open_repo_remote`] handle **any** generation —
//! peeling the roster-key history back to genesis to fold the whole chain. (The *data* key-history that
//! lets members read pre-rotation **object** content — §8.2 `/keyhist` — is a separate, not-yet-wired
//! concern; rotation here covers membership + key generations, i.e. forward secrecy P6/P11.)

use crate::{Remote, RemoteError};
use secsec_frame::{Frame, FRAME_LEN};
use secsec_kdf::MasterKey;
use secsec_proto::server::limits::MAX_TOTAL_SIGCHAIN;
use secsec_roster::{
    append_many, cold_start_fold, decode_entry, encode_entry, genesis, open_entry, revoke_closure,
    revoke_rotate_ops, seal_entry, seal_roster_keyhist, Op, RosterError, State,
};
use secsec_sig::{DeviceId, DeviceKey};
use secsec_store::{Store, StoreError, ABSENT_HEAD};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Errors from repository genesis / open.
#[derive(Debug)]
pub enum RepoError {
    /// Store error.
    Store(StoreError),
    /// Roster fold / cold-start error (incl. RFP mismatch, `mk_commit` mismatch).
    Roster(RosterError),
    /// Keyslot wrap/unwrap error.
    Keyslot(secsec_keyslot::KeyslotError),
    /// Signing/key error.
    Sig(secsec_sig::SigError),
    /// OS RNG failure generating the master key.
    Rng,
    /// The store has no roster (not initialized).
    NotInitialized,
    /// `init` was run on a store that already has a roster tip.
    AlreadyInitialized,
    /// A roster entry expected in `0..roster_len` was missing.
    MissingEntry(u64),
    /// This device owns no keyslot at the current generation (not enrolled here).
    NoKeyslot,
    /// The genesis entry blob was too short to read its FRAME.
    BadFrame,
    /// The repo has rotated past genesis but the remote did not provide the §8.2 roster-key-history
    /// needed to peel — rotation-era cold-start over that remote is unavailable.
    RotationUnsupported(u32),
    /// The roster-key-history wrap for generation `g` (§8.2) was absent — the chain can't be peeled.
    MissingRosterKeyhist(u32),
    /// A concurrent sigchain append moved the tip during a rotate; the caller should re-fold + retry.
    RosterCasConflict,
    /// The far side errored, or returned a roster longer than the §19 cap (a misbehaving server).
    Remote(RemoteError),
}

impl core::fmt::Display for RepoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RepoError::Store(e) => write!(f, "store: {e}"),
            RepoError::Roster(e) => write!(f, "roster: {e}"),
            RepoError::Keyslot(e) => write!(f, "keyslot: {e}"),
            RepoError::Sig(e) => write!(f, "sig: {e}"),
            RepoError::Rng => f.write_str("OS RNG failure"),
            RepoError::NotInitialized => f.write_str("store has no roster (run init)"),
            RepoError::AlreadyInitialized => f.write_str("store already initialized"),
            RepoError::MissingEntry(s) => write!(f, "roster entry {s} missing"),
            RepoError::NoKeyslot => {
                f.write_str("no keyslot for this device at the current generation")
            }
            RepoError::BadFrame => f.write_str("genesis entry blob too short for FRAME"),
            RepoError::RotationUnsupported(g) => {
                write!(
                    f,
                    "repo at generation {g}; remote lacks the roster-key history to peel"
                )
            }
            RepoError::MissingRosterKeyhist(g) => {
                write!(
                    f,
                    "roster-key-history wrap for generation {g} missing (§8.2)"
                )
            }
            RepoError::RosterCasConflict => f.write_str("roster CAS conflict during rotate; retry"),
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
impl From<StoreError> for RepoError {
    fn from(e: StoreError) -> Self {
        RepoError::Store(e)
    }
}
impl From<RosterError> for RepoError {
    fn from(e: RosterError) -> Self {
        RepoError::Roster(e)
    }
}
impl From<secsec_keyslot::KeyslotError> for RepoError {
    fn from(e: secsec_keyslot::KeyslotError) -> Self {
        RepoError::Keyslot(e)
    }
}
impl From<secsec_sig::SigError> for RepoError {
    fn from(e: secsec_sig::SigError) -> Self {
        RepoError::Sig(e)
    }
}

/// §7 `init` (device 1): generate `master_key_1`, write the self-signed genesis sigchain entry (sealed
/// under `roster_key_1`) and device-1's keyslot wrapping the master key, into `store`. Returns the
/// **RFP** — the out-of-band anchor the user records (§5/§7). The master key never leaves this
/// function; it is recovered later by [`open_repo`] unwrapping the keyslot.
pub fn init_repo(store: &Store, device: &DeviceKey, ts: u64) -> Result<[u8; 32], RepoError> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut_slice()).map_err(|_| RepoError::Rng)?;
    let mk = MasterKey::new(1, *key);

    // Genesis entry + RFP, sealed under roster_key_1 and appended as seq 0 (old_tip = absent).
    let (entry, rfp) = genesis(device, mk.mk_commit(), ts)?;
    let roster_key = mk.roster_key();
    let blob = seal_entry(&roster_key, 1, 0, &encode_entry(&entry));
    if store.append_roster(&ABSENT_HEAD, &blob)?.is_none() {
        // The store already had a roster tip — not a fresh repo.
        return Err(RepoError::AlreadyInitialized);
    }

    // Device-1 keyslot wrapping master_key_1 to its own X25519 key.
    let device_id = device.device_id()?;
    let keyslot = secsec_keyslot::wrap(&key, 1, &device_id, &device.x25519_public()?)?;
    store.put_keyslot(&device_id, 1, &keyslot)?;
    Ok(rfp)
}

fn frame_gen(blob: &[u8]) -> Result<u32, RepoError> {
    let frame_bytes = blob.get(..FRAME_LEN).ok_or(RepoError::BadFrame)?;
    Frame::decode(frame_bytes)
        .map(|f| f.gen)
        .map_err(|_| RepoError::BadFrame)
}

/// §8.1 cold-start open: recover the live `MasterKey` and folded roster [`State`] for `device` from
/// `store`, verifying the pinned `rfp` anchor. Reads the genesis..tip roster entries and this device's
/// keyslot, HPKE-unwraps the candidate, then `cold_start_fold` peels keys, decrypts + folds the chain,
/// and verifies the RFP and `mk_commit` (§7 step 3). Genesis generation only (see module note).
pub fn open_repo(
    store: &Store,
    device: &DeviceKey,
    rfp: &[u8; 32],
) -> Result<(MasterKey, State), RepoError> {
    let n = store.roster_len()?;
    if n == 0 {
        return Err(RepoError::NotInitialized);
    }
    let mut entries = Vec::with_capacity(n as usize);
    for seq in 0..n {
        entries.push(
            store
                .get_roster_entry(seq)?
                .ok_or(RepoError::MissingEntry(seq))?,
        );
    }

    // g_cur from the tip's authenticated plaintext FRAME.gen (§8.1 step 1).
    let g_cur = frame_gen(entries.last().expect("n > 0"))?;

    let device_id = device.device_id()?;
    let keyslot = store
        .get_keyslot(&device_id, g_cur)?
        .ok_or(RepoError::NoKeyslot)?;
    let secret = device.x25519_secret()?;
    let candidate = secsec_keyslot::unwrap_raw(&keyslot, g_cur, &device_id, &secret)?;

    // Roster-key history (§8.2): the wrap for every generation 1..g_cur, so the fold can peel
    // roster_key_g back to genesis. Empty at g_cur=1.
    let mut keyhist: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for g in 1..g_cur {
        let wrap = store
            .get_roster_keyhist(g)?
            .ok_or(RepoError::MissingRosterKeyhist(g))?;
        keyhist.insert(g, wrap);
    }
    let (state, mk) = cold_start_fold(&candidate, g_cur, rfp, &keyhist, &entries)?;
    Ok((mk, state))
}

/// §8.4 rotation: mint `master_key_{g+1}`, extend the never-trimmed roster-key history (§8.2), append
/// the `Rotate` entry (plus the transitive revoke closure when `revoke` is set), and re-wrap every
/// remaining member's keyslot to the new generation. Returns the new live `(MasterKey, State)`.
///
/// `device` (a current member) signs the appended entries. `mk`/`state` are the current generation's;
/// `rfp` is the pinned anchor. When `revoke` is `Some(b)`, `b` and its transitive add-by closure
/// (§8.1, conservative: all grants) are revoked before the rotate and their keyslots deleted — the
/// `revoke ⇒ rotate` forward-secrecy flow (P6/P11). **Note:** this rotates membership + keys; the
/// *data* key-history that lets members read pre-rotation **object** content (§8.2 `/keyhist`) is a
/// separate concern not written here.
pub fn rotate_repo(
    store: &Store,
    device: &DeviceKey,
    mk: &MasterKey,
    state: &State,
    rfp: &[u8; 32],
    revoke: Option<DeviceId>,
    ts: u64,
) -> Result<(MasterKey, State), RepoError> {
    let g = mk.generation();
    let g1 = g + 1;

    // Mint master_key_{g+1} (RAM, zeroized).
    let mut newkey = Zeroizing::new([0u8; 32]);
    getrandom::fill(newkey.as_mut_slice()).map_err(|_| RepoError::Rng)?;
    let new_mk = MasterKey::new(g1, *newkey);
    let rk_g = mk.roster_key();
    let rk_g1 = new_mk.roster_key();

    // §8.2 roster-key history: wrap roster_key_g under roster_key_{g+1} so future cold-start can peel.
    let wrap = seal_roster_keyhist(&rk_g1, g, &rk_g);
    store.put_roster_keyhist(g, &wrap)?;

    // Fetch + decrypt the current tip entry to chain the new ops onto it.
    let n = store.roster_len()?;
    let tip_seq = n.checked_sub(1).ok_or(RepoError::NotInitialized)?;
    let tip_blob = store
        .get_roster_entry(tip_seq)?
        .ok_or(RepoError::MissingEntry(tip_seq))?;
    let tip_pt = open_entry(&rk_g, g, tip_seq, &tip_blob)?;
    let tip_entry = decode_entry(&tip_pt)?;

    // Build the op sequence: [Revoke(b), Revoke(closure)…,] Rotate(mk_commit_{g+1}).
    let ops = match revoke {
        Some(b) => revoke_rotate_ops(state, &b, 0, new_mk.mk_commit()),
        None => vec![Op::Rotate {
            mk_commit: new_mk.mk_commit(),
        }],
    };
    let entries = append_many(&tip_entry, ops, device, ts)?;

    // Seal + CAS-append each entry. Per §9.5: entries BEFORE the Rotate stay under gen g; the Rotate
    // and everything after are under g+1 (it embeds mk_commit_{g+1}).
    let mut cur_gen = g;
    let mut prev_tip = *blake3::hash(&tip_blob).as_bytes();
    for e in &entries {
        if matches!(e.op, Op::Rotate { .. }) {
            cur_gen = g1;
        }
        let rk = if cur_gen == g1 { &rk_g1 } else { &rk_g };
        let blob = seal_entry(rk, cur_gen, e.seq, &encode_entry(e));
        if store.append_roster(&prev_tip, &blob)?.is_none() {
            // A concurrent append moved the tip — the caller re-folds and retries (§8.1).
            return Err(RepoError::RosterCasConflict);
        }
        prev_tip = *blake3::hash(&blob).as_bytes();
    }

    // Re-wrap keyslots to g+1 for remaining members; delete the revoked devices' keyslots.
    let revoked: std::collections::BTreeSet<DeviceId> = match revoke {
        Some(b) => {
            let mut s: std::collections::BTreeSet<DeviceId> =
                revoke_closure(state, &b, 0).into_iter().collect();
            s.insert(b);
            s
        }
        None => std::collections::BTreeSet::new(),
    };
    for (id, pubkey) in &state.members {
        if revoked.contains(id) {
            store.delete_keyslot(id, g)?;
            continue;
        }
        let x = pubkey.x25519_public()?;
        let ks = secsec_keyslot::wrap(&newkey, g1, id, &x)?;
        store.put_keyslot(id, g1, &ks)?;
    }

    // Re-open to fold the now-extended chain into the new live state.
    open_repo(store, device, rfp)
}

/// Fetch a remote's full sigchain (`get-roster` `seq = 0, 1, …` until absent), bounded by the §19
/// total-sigchain cap so a misbehaving server cannot stream entries forever. Entries are the stored
/// (encrypted) blobs; the caller folds/verifies them against the RFP (§8.1).
pub async fn fetch_roster_entries<R: Remote>(remote: &R) -> Result<Vec<Vec<u8>>, RepoError> {
    let mut entries: Vec<Vec<u8>> = Vec::new();
    let mut seq = 0u64;
    while seq < MAX_TOTAL_SIGCHAIN {
        match remote.get_roster_entry(seq).await? {
            Some(blob) => entries.push(blob),
            None => break,
        }
        seq += 1;
    }
    Ok(entries)
}

/// §8.1 cold-start open against a **remote** (the network counterpart of [`open_repo`]). Fetches the
/// sigchain entries (`seq = 0, 1, … `until absent, bounded by the §19 cap), this device's keyslot, and
/// the §8.2 roster-key history over the [`Remote`], then runs the same `cold_start_fold` (peel,
/// decrypt, fold, verify RFP + `mk_commit`). Recovers the **identity** (master key + roster); objects
/// are fetched separately by the sync loop.
pub async fn open_repo_remote<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    rfp: &[u8; 32],
) -> Result<(MasterKey, State), RepoError> {
    let entries = fetch_roster_entries(remote).await?;
    if entries.is_empty() {
        return Err(RepoError::NotInitialized);
    }
    let g_cur = frame_gen(entries.last().expect("non-empty"))?;

    let device_id = device.device_id()?;
    let keyslot = remote
        .get_keyslot(&device_id, g_cur)
        .await?
        .ok_or(RepoError::NoKeyslot)?;
    let secret = device.x25519_secret()?;
    let candidate = secsec_keyslot::unwrap_raw(&keyslot, g_cur, &device_id, &secret)?;

    // Roster-key history (§8.2): fetch the wrap for every generation 1..g_cur over the wire so the
    // fold can peel back to genesis. A remote lacking a needed wrap can't support the cold-start.
    let mut keyhist: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for g in 1..g_cur {
        let wrap = remote
            .get_roster_keyhist(g)
            .await?
            .ok_or(RepoError::RotationUnsupported(g_cur))?;
        keyhist.insert(g, wrap);
    }
    let (state, mk) = cold_start_fold(&candidate, g_cur, rfp, &keyhist, &entries)?;
    Ok((mk, state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_then_open_recovers_master_key_and_membership() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let device = DeviceKey::generate().unwrap();

        let rfp = init_repo(&store, &device, 0).unwrap();

        // a second init on the same store is rejected (already has a roster tip).
        assert!(init_repo(&store, &device, 0).is_err());

        // cold-start open recovers a usable master key + the folded roster with device 1 a member.
        let (mk, state) = open_repo(&store, &device, &rfp).unwrap();
        assert_eq!(mk.generation(), 1);
        assert!(state.is_member(&device.device_id().unwrap()));
        assert_eq!(state.members.len(), 1);

        // a wrong RFP is rejected (the genesis anchor must match).
        assert!(open_repo(&store, &device, &[0xAB; 32]).is_err());

        // another device (no keyslot here) cannot open the repo.
        let other = DeviceKey::generate().unwrap();
        assert!(matches!(
            open_repo(&store, &other, &rfp),
            Err(RepoError::NoKeyslot)
        ));
    }

    #[test]
    fn rotate_then_cold_start_recovers_new_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let device = DeviceKey::generate().unwrap();
        let rfp = init_repo(&store, &device, 0).unwrap();

        let (mk1, st1) = open_repo(&store, &device, &rfp).unwrap();
        assert_eq!(mk1.generation(), 1);

        // rotate (no revoke): mint generation 2.
        let (mk2, st2) = rotate_repo(&store, &device, &mk1, &st1, &rfp, None, 0).unwrap();
        assert_eq!(mk2.generation(), 2);
        assert!(st2.is_member(&device.device_id().unwrap()));

        // a FRESH cold-start (no in-memory state) must recover generation 2 — peeling the roster-key
        // history back to genesis to fold the whole chain, anchored to the same RFP.
        let (mk_cs, st_cs) = open_repo(&store, &device, &rfp).unwrap();
        assert_eq!(
            mk_cs.generation(),
            2,
            "cold-start recovers the rotated generation"
        );
        assert!(st_cs.is_member(&device.device_id().unwrap()));
        assert_eq!(st_cs.members.len(), 1);
        // mk_commit for both generations is anchored in the folded chain.
        assert!(st_cs.mk_commits.contains_key(&1));
        assert!(st_cs.mk_commits.contains_key(&2));

        // rotate again → generation 3 cold-starts too (multi-hop peel).
        let (mk3, st3) = rotate_repo(&store, &device, &mk2, &st2, &rfp, None, 0).unwrap();
        assert_eq!(mk3.generation(), 3);
        let (mk_cs3, _) = open_repo(&store, &device, &rfp).unwrap();
        assert_eq!(mk_cs3.generation(), 3);
        let _ = st3;

        // a wrong RFP still fails the fold after rotation.
        assert!(open_repo(&store, &device, &[0xAB; 32]).is_err());
    }
}
