//! Repository genesis and cold-start open (`finaldesign.md` §7 `init`, §8.1 cold-start fold).
//!
//! [`init_repo`] creates a fresh repo for device 1: generate `master_key_1`, write the self-signed
//! **genesis** sigchain entry (the RFP anchor, §5/§7) and device-1's **keyslot** wrapping the master
//! key, both into a [`Store`]. The master key is dropped after wrapping — the keyslot is its durable
//! form. [`open_repo`] reverses it (§8.1): unwrap the keyslot to a candidate, peel roster keys,
//! decrypt + fold the chain, and verify both the RFP anchor and the candidate against `mk_commit`.
//!
//! This slice covers the **genesis generation** (g = 1) — all `init` produces. Rotation-era
//! cold-start (peeling roster-key history across generations) needs the §8.2 key-history storage and
//! the rotate flow, which are later milestones; [`open_repo`] errors clearly if the tip is past g = 1.

use secsec_frame::{Frame, FRAME_LEN};
use secsec_kdf::MasterKey;
use secsec_roster::{cold_start_fold, encode_entry, genesis, seal_entry, RosterError, State};
use secsec_sig::DeviceKey;
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
    /// The repo has rotated past genesis; rotation-era cold-start is not yet wired (needs §8.2
    /// roster-key-history storage).
    RotationUnsupported(u32),
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
                    "repo at generation {g}; rotation-era cold-start not yet wired"
                )
            }
        }
    }
}
impl std::error::Error for RepoError {}
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
    if g_cur != 1 {
        return Err(RepoError::RotationUnsupported(g_cur));
    }

    let device_id = device.device_id()?;
    let keyslot = store
        .get_keyslot(&device_id, g_cur)?
        .ok_or(RepoError::NoKeyslot)?;
    let secret = device.x25519_secret()?;
    let candidate = secsec_keyslot::unwrap_raw(&keyslot, g_cur, &device_id, &secret)?;

    // No roster-key history at genesis (no rotation yet).
    let keyhist: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
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
}
