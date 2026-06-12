//! Repository genesis and cold-start open (`secsec-Design.md` §7 `init`, §8.1 cold-start fold).
//!
//! [`init_repo`] creates a fresh repo for device 1: generate `master_key_1`, write the self-signed
//! **genesis** sigchain entry (the RFP anchor, §5/§7) and device-1's **keyslot** wrapping the master
//! key, both into a [`Store`]. The master key is dropped after wrapping — the keyslot is its durable
//! form. [`open_repo`] reverses it (§8.1): unwrap the keyslot to a candidate, peel roster keys,
//! decrypt + fold the chain, and verify both the RFP anchor and the candidate against `mk_commit`.
//!
//! [`rotate_repo`] mints a new generation (§8.4): it extends **both** §8.2 key-histories (roster-key
//! for sigchain folding, data-key for old-object readability via [`data_keyring`]), appends the
//! `Rotate` entry (with the transitive revoke closure when revoking), and re-wraps every remaining
//! member's keyslot at the repo's `min_algo` (§16). [`open_repo`]/[`open_repo_remote`] handle **any**
//! generation — peeling the roster-key history back to genesis to fold the whole chain.
//!
//! Keyslots are **algo-tagged** (`algo_id(1B) ‖ body`, §9.1): X-Wing (`algo_id = 1`, §8.3/§17) is the
//! keyslot KEM — post-quantum, so the one harvestable asymmetric exposure is PQ-safe. A device's
//! X-Wing keypair is derived from its SSH private **seed** ([`secsec_sig::DeviceKey::xwing_seed`] —
//! the seed, not the clamped scalar, so it is quantum-hard to recover from the public Ed25519 key)
//! and its X-Wing public is published in the roster (`Genesis`/`AddDevice`), so a granter/rotation
//! can wrap to it. The cold-start unwrap checks the `algo_id` and enforces the §16 `min_algo` floor
//! after folding.

use crate::{Remote, RemoteError};
use secsec_frame::{Frame, FRAME_LEN};
use secsec_kdf::MasterKey;
use secsec_pq::{XWingPublic, XWingSecret};
use secsec_proto::server::limits::MAX_TOTAL_SIGCHAIN;
use secsec_roster::{
    append, append_many, cold_start_fold, decode_entry, encode_entry, genesis, open_entry,
    peel_data_keys, revoke_closure, revoke_rotate_ops, seal_data_keyhist, seal_entry,
    seal_roster_keyhist, Op, RosterError, State,
};
use secsec_sig::{DeviceId, DeviceKey, DevicePublic};
use secsec_store::{Store, StoreError, ABSENT_HEAD};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Keyslot KEM algorithm id (`secsec-Design.md` §9.1 / §8.3): a stored keyslot is `algo_id(1B) ‖ body`.
/// X-Wing (§17) is the keyslot KEM — post-quantum, so the one harvestable asymmetric exposure is
/// PQ-safe. The 1-byte tag plus the §16 `min_algo` floor give the protocol crypto agility; a keyslot
/// whose `algo_id` is below the chain's `min_algo` is rejected at cold-start.
pub const ALGO_XWING: u8 = 1;

/// A device's X-Wing keypair, derived from its SSH private **seed** (§8.3): no extra stored PQ key
/// material — "the SSH key is the only credential" (§1). Derived from the seed, not the scalar, so a
/// quantum adversary cannot reconstruct it from the public Ed25519 key (see `DeviceKey::xwing_seed`).
fn xwing_keypair(device: &DeviceKey) -> Result<(XWingSecret, XWingPublic), RepoError> {
    let sk = XWingSecret::from_seed(*device.xwing_seed()?);
    let pk = sk.public();
    Ok((sk, pk))
}

/// A device's published **X-Wing public key** bytes (§8.3/§17) — recorded in the roster
/// (`Genesis`/`AddDevice`) so a granter or rotation can wrap `master_key_g` to it. Public so the CLI
/// (`enroll-pubkey`) can print it for the granter during enrollment (§7).
pub fn device_xwing_pub(device: &DeviceKey) -> Result<Vec<u8>, RepoError> {
    Ok(xwing_keypair(device)?.1.to_bytes())
}

/// Wrap `master_key` to a device's X-Wing public key, prefixing the `algo_id` (§9.1/§16).
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

/// The `algo_id` of a stored keyslot (its first byte).
fn keyslot_algo(keyslot: &[u8]) -> Result<u8, RepoError> {
    keyslot.first().copied().ok_or(RepoError::BadKeyslot)
}

/// Unwrap a stored keyslot to the **raw** master-key bytes for cold-start (§8.1): an `algo_id` other
/// than X-Wing is rejected. The §16 `min_algo` floor is re-checked by the caller after folding (the
/// floor lives inside the chain this unwrap bootstraps); see [`open_repo`].
fn unwrap_keyslot_raw(
    keyslot: &[u8],
    gen: u32,
    device_id: &DeviceId,
    device: &DeviceKey,
) -> Result<Zeroizing<[u8; 32]>, RepoError> {
    let (&algo, body) = keyslot.split_first().ok_or(RepoError::BadKeyslot)?;
    if algo != ALGO_XWING {
        return Err(RepoError::UnsupportedAlgo(algo));
    }
    let (sk, _) = xwing_keypair(device)?;
    secsec_pq::unwrap_pq_raw(body, gen, device_id, &sk).map_err(|_| RepoError::Pq)
}

/// Errors from repository genesis / open.
#[derive(Debug)]
pub enum RepoError {
    /// Store error.
    Store(StoreError),
    /// Roster fold / cold-start error (incl. RFP mismatch, `mk_commit` mismatch).
    Roster(RosterError),
    /// Signing/key error.
    Sig(secsec_sig::SigError),
    /// OS RNG failure generating the master key.
    Rng,
    /// The store has no roster (not initialized).
    NotInitialized,
    /// `init` was run on a store that already has a roster tip.
    AlreadyInitialized,
    /// `init_repo_remote` was called by a device that already owns a keyslot (it is already enrolled).
    /// Running genesis again would overwrite — and on losing the genesis race, delete — that live
    /// keyslot, locking the device out of its own repo; the create flow refuses instead (§7).
    AlreadyEnrolled,
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
    /// The DATA key-history wrap for generation `g` (§8.2 `/keyhist`) was absent — pre-rotation object
    /// content under that generation can't be read.
    MissingDataKeyhist(u32),
    /// A concurrent sigchain append moved the tip during a rotate; the caller should re-fold + retry.
    RosterCasConflict,
    /// A stored keyslot carried an `algo_id` this build does not support (§16).
    UnsupportedAlgo(u8),
    /// A stored keyslot blob was empty / missing its `algo_id` prefix.
    BadKeyslot,
    /// The fetched sigchain is shorter than — or re-forked below — the persisted anti-rollback anchor
    /// (§8.1, P7): the server tried to roll the roster back, e.g. to drop a revocation. Refuse.
    Rollback,
    /// An X-Wing keyslot operation failed (malformed public/ciphertext or AEAD).
    Pq,
    /// §16 downgrade floor: a fetched keyslot's `algo_id` was below the chain's `min_algo`.
    AlgoTooWeak {
        /// The keyslot's `algo_id`.
        got: u8,
        /// The folded chain's `min_algo` floor.
        floor: u8,
    },
    /// The far side errored, or returned a roster longer than the §19 cap (a misbehaving server).
    Remote(RemoteError),
}

impl core::fmt::Display for RepoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RepoError::Store(e) => write!(f, "store: {e}"),
            RepoError::Roster(e) => write!(f, "roster: {e}"),
            RepoError::Sig(e) => write!(f, "sig: {e}"),
            RepoError::Rng => f.write_str("OS RNG failure"),
            RepoError::NotInitialized => f.write_str("store has no roster (run init)"),
            RepoError::AlreadyInitialized => f.write_str("store already initialized"),
            RepoError::AlreadyEnrolled => {
                f.write_str("this device is already enrolled; refusing to re-create the repo")
            }
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
            RepoError::MissingDataKeyhist(g) => {
                write!(f, "DATA key-history wrap for generation {g} missing (§8.2)")
            }
            RepoError::RosterCasConflict => f.write_str("roster CAS conflict during rotate; retry"),
            RepoError::UnsupportedAlgo(a) => write!(f, "unsupported keyslot algo_id {a}"),
            RepoError::BadKeyslot => f.write_str("malformed keyslot (missing algo_id prefix)"),
            RepoError::Rollback => f.write_str(
                "the server served a rolled-back sigchain (below the persisted anchor, §8.1)",
            ),
            RepoError::Pq => f.write_str("X-Wing keyslot operation failed"),
            RepoError::AlgoTooWeak { got, floor } => {
                write!(
                    f,
                    "keyslot algo_id {got} below min_algo floor {floor} (§16)"
                )
            }
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

    // Genesis publishes device-1's X-Wing public key (§8.3/§17); the keyslot wraps master_key_1 to it.
    // Post-quantum is mandatory — every keyslot is X-Wing from genesis on.
    let xwing_pub = device_xwing_pub(device)?;
    let (entry, rfp) = genesis(device, xwing_pub.clone(), mk.mk_commit(), ts)?;
    let roster_key = mk.roster_key();
    let blob = seal_entry(&roster_key, 1, 0, &encode_entry(&entry));
    if store.append_roster(&ABSENT_HEAD, &blob)?.is_none() {
        // The store already had a roster tip — not a fresh repo.
        return Err(RepoError::AlreadyInitialized);
    }

    let device_id = device.device_id()?;
    let keyslot = wrap_keyslot(&key, 1, &device_id, &xwing_pub)?;
    store.put_keyslot(&device_id, 1, &keyslot)?;
    Ok(rfp)
}

/// §7 `init` over a [`Remote`] — the network counterpart of [`init_repo`]. The first device to reach an
/// empty repo creates it **over the wire**: it mints `master_key_1` (RAM-only, never sent), pushes the
/// self-signed genesis entry via `roster-append` and its own keyslot via `put-keyslot`, and returns the
/// **RFP**. The master key never touches the server — only the genesis blob + the opaque keyslot do.
/// Returns [`RepoError::AlreadyInitialized`] if another device won the genesis `roster-append` race.
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
    let roster_key = mk.roster_key();
    let blob = seal_entry(&roster_key, 1, 0, &encode_entry(&entry));

    // Refuse to run genesis if this device is already enrolled (it already owns a gen-1 keyslot).
    // The keyslot path is /keyslots/<device_id>/1, so the put_keyslot below would OVERWRITE the live
    // keyslot, and the lost-genesis-race cleanup would then DELETE it — self-lockout. This bites when
    // an enrolled device runs `sync` on a new, unlinked folder with no --invite (it falls into the
    // create path). Only `Ok(Some(_))` — we can actually read our own keyslot — means enrolled: a
    // genuinely fresh device's keyslot read is gated by the server (NotEnrolled ⇒ Err), which we treat
    // as not-enrolled, the legitimate genesis path. Catching the enrolled case leaves the live keyslot
    // untouched and makes the cleanup delete below safe (now only reached for a keyslot we just wrote).
    let device_id = device.device_id()?;
    if matches!(remote.get_keyslot(&device_id, 1).await, Ok(Some(_))) {
        return Err(RepoError::AlreadyEnrolled);
    }

    // Write the creator's own keyslot FIRST (allowed pre-enrollment only while the roster is empty —
    // the server's genesis-bootstrap exception), so that by the time the genesis entry is appended the
    // creator is already enrolled.
    let keyslot = wrap_keyslot(&key, 1, &device_id, &xwing_pub)?;
    remote.put_keyslot(&device_id, 1, &keyslot).await?;

    // Genesis CAS: `old_tip` is the all-zero sentinel ("expect empty"); a `false` return means another
    // device already created the repo.
    if !remote.roster_append(&ABSENT_HEAD, &blob).await? {
        // We lost the genesis race. The keyslot we just wrote (under the empty-roster bootstrap
        // exception) is now an orphan — it wraps *our* master_key_1, which has nothing to do with the
        // winner's genesis, so it fails the winner's `mk_commit` at cold-start. Delete it (best-effort)
        // so it neither accumulates on retry nor lingers as a gate-passing keyslot for a non-member.
        let _ = remote.delete_keyslot(&device_id, 1).await;
        return Err(RepoError::AlreadyInitialized);
    }
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
/// keyslot, X-Wing-unwraps the candidate, then `cold_start_fold` peels keys, decrypts + folds the
/// chain, and verifies the RFP and `mk_commit` (§7 step 3). Genesis generation only (see module note).
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
    // Unwrap the X-Wing keyslot (§8.3/§17) to the candidate master key.
    let candidate = unwrap_keyslot_raw(&keyslot, g_cur, &device_id, device)?;

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
    enforce_min_algo(&keyslot, &state)?;
    Ok((mk, state))
}

/// §16 downgrade floor: a fetched keyslot's `algo_id` MUST be ≥ the folded chain's `min_algo`. Checked
/// **after** the fold (the floor lives in the chain the keyslot bootstraps), so a server cannot replay
/// an older/weaker keyslot after a `SetMinAlgo` bump.
fn enforce_min_algo(keyslot: &[u8], state: &State) -> Result<(), RepoError> {
    let got = keyslot_algo(keyslot)?;
    // PQ is mandatory: the floor is at least X-Wing, raised further by any `SetMinAlgo` in the chain.
    let floor = state.min_algo.max(ALGO_XWING);
    if got < floor {
        return Err(RepoError::AlgoTooWeak { got, floor });
    }
    Ok(())
}

/// Build the §8.2 DATA key-history keyring from the **local** store: peel `master_key_g` for every
/// generation `1..=mk.generation()`, so the caller can open objects sealed under any past generation
/// (pre-rotation content readability). Returns `g → master_key_g`. A missing `/keyhist/<g>` wrap is
/// [`RepoError::MissingDataKeyhist`]. At generation 1 the map is just `{1: mk}` (no history to peel).
pub fn data_keyring(store: &Store, mk: &MasterKey) -> Result<BTreeMap<u32, MasterKey>, RepoError> {
    let g_cur = mk.generation();
    let mut hist: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for g in 1..g_cur {
        let wrap = store
            .get_keyhist(g)?
            .ok_or(RepoError::MissingDataKeyhist(g))?;
        hist.insert(g, wrap);
    }
    Ok(peel_data_keys(mk.expose_secret(), g_cur, &hist)?)
}

/// The network counterpart of [`data_keyring`]: peel the §8.2 DATA key-history over a [`Remote`]
/// (`get-keyhist` for `g = 1..g_cur`), so a cold-started device can read pre-rotation object content.
pub async fn data_keyring_remote<R: Remote>(
    remote: &R,
    mk: &MasterKey,
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
    Ok(peel_data_keys(mk.expose_secret(), g_cur, &hist)?)
}

/// §8.4 rotation: mint `master_key_{g+1}`, extend the never-trimmed roster-key history (§8.2), append
/// the `Rotate` entry (plus the transitive revoke closure when `revoke` is set), and re-wrap every
/// remaining member's keyslot to the new generation. Returns the new live `(MasterKey, State)`.
///
/// `device` (a current member) signs the appended entries. `mk`/`state` are the current generation's;
/// `rfp` is the pinned anchor. When `revoke` is `Some(b)`, `b` and its transitive add-by closure
/// (§8.1, conservative: all grants) are revoked before the rotate and their keyslots deleted — the
/// `revoke ⇒ rotate` forward-secrecy flow (P6/P11). It writes **both** §8.2 key-histories: the
/// roster-key history (sigchain folding) **and** the DATA key-history (`/keyhist/<g>`, wrapping
/// `master_key_g` under `master_key_{g+1}`) so a current member can later [`data_keyring`]-peel old
/// master keys and read pre-rotation **object** content.
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

    // §8.2 DATA key-history: wrap master_key_g under master_key_{g+1} so a current member can peel it
    // back and read pre-rotation OBJECT content. (The roster-key history above is for sigchain
    // folding; this one is for old-data readability — both never-trimmed.)
    let data_wrap = seal_data_keyhist(&newkey, g, mk.expose_secret());
    store.put_keyhist(g, &data_wrap)?;

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
    // Re-wrap every remaining member's keyslot to the new generation under X-Wing (§8.3/§17, PQ
    // mandatory), using the member's published X-Wing public (§8.2); delete revoked devices' keyslots.
    for id in state.members.keys() {
        if revoked.contains(id) {
            store.delete_keyslot(id, g)?;
            continue;
        }
        let xwing_pub = state.enroll_pubs.get(id).ok_or(RepoError::Pq)?;
        let ks = wrap_keyslot(&newkey, g1, id, xwing_pub)?;
        store.put_keyslot(id, g1, &ks)?;
    }

    // Re-open to fold the now-extended chain into the new live state.
    open_repo(store, device, rfp)
}

/// §8.4 rotation over a [`Remote`] — the network counterpart of [`rotate_repo`], used by `revoke`.
/// Mints `master_key_{g+1}`, pushes both §8.2 key-history wraps, appends the `Rotate` (+ revoke
/// closure) entries, re-wraps every remaining member's keyslot, and deletes the revoked devices'
/// keyslots — all over the wire — then cold-starts the new generation. `revoke = Some(b)` removes `b`
/// and its transitive add-by closure (forward secrecy, P6/P11).
pub async fn rotate_repo_remote<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    mk: &MasterKey,
    state: &State,
    rfp: &[u8; 32],
    revoke: Option<DeviceId>,
    ts: u64,
) -> Result<(MasterKey, State), RepoError> {
    let g = mk.generation();
    let g1 = g + 1;

    let mut newkey = Zeroizing::new([0u8; 32]);
    getrandom::fill(newkey.as_mut_slice()).map_err(|_| RepoError::Rng)?;
    let new_mk = MasterKey::new(g1, *newkey);
    let rk_g = mk.roster_key();
    let rk_g1 = new_mk.roster_key();

    // §8.2 key-histories (roster-key for folding, DATA for old-object readability).
    remote
        .put_roster_keyhist(g, &seal_roster_keyhist(&rk_g1, g, &rk_g))
        .await?;
    remote
        .put_keyhist(g, &seal_data_keyhist(&newkey, g, mk.expose_secret()))
        .await?;

    // Chain the new ops onto the current tip.
    let entries = fetch_roster_entries(remote).await?;
    let tip_seq = u64::try_from(
        entries
            .len()
            .checked_sub(1)
            .ok_or(RepoError::NotInitialized)?,
    )
    .map_err(|_| RepoError::NotInitialized)?;
    let tip_blob = entries.last().ok_or(RepoError::NotInitialized)?.clone();
    let tip_entry = decode_entry(&open_entry(&rk_g, g, tip_seq, &tip_blob)?)?;

    let ops = match revoke {
        Some(b) => revoke_rotate_ops(state, &b, 0, new_mk.mk_commit()),
        None => vec![Op::Rotate {
            mk_commit: new_mk.mk_commit(),
        }],
    };
    let new_entries = append_many(&tip_entry, ops, device, ts)?;

    // Seal + CAS-append each entry; entries up to the Rotate stay under gen g, the rest under g+1.
    let mut cur_gen = g;
    let mut prev_tip = *blake3::hash(&tip_blob).as_bytes();
    for e in &new_entries {
        if matches!(e.op, Op::Rotate { .. }) {
            cur_gen = g1;
        }
        let rk = if cur_gen == g1 { &rk_g1 } else { &rk_g };
        let blob = seal_entry(rk, cur_gen, e.seq, &encode_entry(e));
        if !remote.roster_append(&prev_tip, &blob).await? {
            return Err(RepoError::RosterCasConflict);
        }
        prev_tip = *blake3::hash(&blob).as_bytes();
    }

    // Re-wrap remaining members' keyslots to g+1; delete the revoked devices' keyslots.
    let revoked: std::collections::BTreeSet<DeviceId> = match revoke {
        Some(b) => {
            let mut s: std::collections::BTreeSet<DeviceId> =
                revoke_closure(state, &b, 0).into_iter().collect();
            s.insert(b);
            s
        }
        None => std::collections::BTreeSet::new(),
    };
    for id in state.members.keys() {
        if revoked.contains(id) {
            remote.delete_keyslot(id, g).await?;
            continue;
        }
        let xwing_pub = state.enroll_pubs.get(id).ok_or(RepoError::Pq)?;
        let ks = wrap_keyslot(&newkey, g1, id, xwing_pub)?;
        remote.put_keyslot(id, g1, &ks).await?;
    }

    // Re-fold to return the fresh (mk, state) at the new generation. No anchor is checked here (this
    // device just authored the extension — the caller persists the advanced anchor on its next open).
    open_repo_remote(remote, device, rfp, None)
        .await
        .map(|(mk, st, _)| (mk, st))
}

/// §7 `grant` over a [`Remote`] — the network half of enrollment, run by a current member while
/// completing an invite pairing ([`crate::pair`]). Fetches the sigchain tip, appends an `AddDevice`
/// entry (publishing D's X-Wing public), and wraps `master_key_g` to D's keyslot, all over the wire
/// (`roster-append` + `put-keyslot`). D's keys are authenticated by the invite-code MAC (§7). On a
/// CAS race the caller re-folds and retries.
pub async fn grant_device_remote<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    mk: &MasterKey,
    d_pubkey: &DevicePublic,
    d_xwing_pub: &[u8],
    ts: u64,
) -> Result<(), RepoError> {
    if d_xwing_pub.is_empty() {
        return Err(RepoError::Pq);
    }
    let g = mk.generation();
    let mk_commit = mk.mk_commit();
    let rk = mk.roster_key();

    // Fetch + decrypt the current tip to chain the AddDevice entry onto it.
    let entries = fetch_roster_entries(remote).await?;
    let tip_seq = u64::try_from(
        entries
            .len()
            .checked_sub(1)
            .ok_or(RepoError::NotInitialized)?,
    )
    .map_err(|_| RepoError::NotInitialized)?;
    let tip_blob = entries.last().ok_or(RepoError::NotInitialized)?;
    let tip_entry = decode_entry(&open_entry(&rk, g, tip_seq, tip_blob)?)?;

    let d_canonical = d_pubkey.to_canonical()?;
    let op = Op::AddDevice {
        pubkey: d_canonical,
        mk_commit,
        enroll_pub: d_xwing_pub.to_vec(),
    };
    let entry = append(&tip_entry, op, device, ts)?;
    let roster_seq = entry.seq;
    let blob = seal_entry(&rk, g, roster_seq, &encode_entry(&entry));
    let old_tip = *blake3::hash(tip_blob).as_bytes();
    if !remote.roster_append(&old_tip, &blob).await? {
        return Err(RepoError::RosterCasConflict);
    }

    let d_id = d_pubkey.device_id()?;
    let keyslot = wrap_keyslot(mk.expose_secret(), g, &d_id, d_xwing_pub)?;
    remote.put_keyslot(&d_id, g, &keyslot).await?;
    Ok(())
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

/// A persisted **anti-rollback anchor** for a folder's sigchain (§8.1, P7): the highest roster `seq`
/// this device has accepted and the BLAKE3 of the *stored* (sealed) entry blob at that seq. The sealed
/// blob is deterministic (nonce=0 under a key-committing AEAD with a derived key), so its hash is a
/// stable per-seq token re-derivable **without** decrypting. Every cold-start MUST extend this anchor;
/// a shorter or re-forked chain is a server rollback (e.g. dropping a `RevokeDevice`+`Rotate`) and is
/// refused. Persisted per folder; the returned anchor is saved after each successful open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RosterAnchor {
    /// Highest accepted sequence number (`= entries.len() - 1`).
    pub max_seq: u64,
    /// BLAKE3 of the stored (sealed) entry blob at `max_seq`.
    pub tip_hash: [u8; 32],
}

/// §8.1 cold-start open against a **remote** (the network counterpart of [`open_repo`]). Fetches the
/// sigchain entries (`seq = 0, 1, … `until absent, bounded by the §19 cap), this device's keyslot, and
/// the §8.2 roster-key history over the [`Remote`], then runs the same `cold_start_fold` (peel,
/// decrypt, fold, verify RFP + `mk_commit`). `prev` is the persisted [`RosterAnchor`] (`None` on a
/// fresh link); the fetched chain is rejected with [`RepoError::Rollback`] if it does not extend it
/// (P7 anti-rollback). Recovers the **identity** (master key + roster) and the new anchor to persist;
/// objects are fetched separately by the sync loop.
pub async fn open_repo_remote<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    rfp: &[u8; 32],
    prev: Option<RosterAnchor>,
) -> Result<(MasterKey, State, RosterAnchor), RepoError> {
    let entries = fetch_roster_entries(remote).await?;
    if entries.is_empty() {
        return Err(RepoError::NotInitialized);
    }
    // §8.1 anti-rollback (P7): the fetched chain MUST extend the persisted anchor — at least as long,
    // and the stored blob at the anchor's seq must still hash to the recorded tip (the tip-hash
    // consistency check catches a chain re-forked from an earlier point). This refuses a server that
    // truncates or re-forks the sigchain to undo a revocation. No decryption needed for the check.
    if let Some(p) = prev {
        let idx = p.max_seq as usize;
        if entries.len() <= idx || *blake3::hash(&entries[idx]).as_bytes() != p.tip_hash {
            return Err(RepoError::Rollback);
        }
    }
    let anchor = RosterAnchor {
        max_seq: (entries.len() - 1) as u64,
        tip_hash: *blake3::hash(entries.last().expect("non-empty")).as_bytes(),
    };
    let g_cur = frame_gen(entries.last().expect("non-empty"))?;

    let device_id = device.device_id()?;
    let keyslot = remote
        .get_keyslot(&device_id, g_cur)
        .await?
        .ok_or(RepoError::NoKeyslot)?;
    // Unwrap the X-Wing keyslot (§8.3/§17) to the candidate master key.
    let candidate = unwrap_keyslot_raw(&keyslot, g_cur, &device_id, device)?;

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
    enforce_min_algo(&keyslot, &state)?;
    Ok((mk, state, anchor))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A device that already owns a keyslot must not be able to destroy it by re-running genesis. An
    /// enrolled device that re-enters `init_repo_remote` (e.g. `sync` on a new, unlinked folder with no
    /// `--invite`, which falls into the create path) MUST be refused with `AlreadyEnrolled` and keep
    /// its live keyslot — otherwise the genesis `put-keyslot` would overwrite it and the lost-race
    /// cleanup would delete it, locking the device out of its own repo.
    #[tokio::test]
    async fn init_remote_refuses_an_enrolled_device_and_keeps_its_keyslot() {
        use crate::testmem::MemRemote;
        let dir = tempfile::tempdir().unwrap();
        let remote = MemRemote::new(Store::open(dir.path().join("r.redb")).unwrap());
        let device = DeviceKey::generate().unwrap();

        // Create the repo over the wire, then confirm the device opens it (keyslot present, unwraps).
        let rfp = init_repo_remote(&remote, &device, 0).await.unwrap();
        let (mk1, _st, _anchor) = open_repo_remote(&remote, &device, &rfp, None)
            .await
            .unwrap();

        // Re-running genesis (the new-unlinked-folder, no-invite case) is refused, touching nothing.
        assert!(matches!(
            init_repo_remote(&remote, &device, 0).await,
            Err(RepoError::AlreadyEnrolled)
        ));

        // The live keyslot survived: the device still cold-starts to the SAME master key + membership.
        let (mk2, st, _) = open_repo_remote(&remote, &device, &rfp, None)
            .await
            .unwrap();
        assert_eq!(
            mk2.mk_commit(),
            mk1.mk_commit(),
            "keyslot must be intact (same master key) after a refused re-init"
        );
        assert!(st.is_member(&device.device_id().unwrap()));
    }

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

    #[test]
    fn rotation_writes_data_keyhist_and_old_objects_stay_readable() {
        use secsec_frame::ObjType;
        use secsec_object::{open_object, seal_object};

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let device = DeviceKey::generate().unwrap();
        let rfp = init_repo(&store, &device, 0).unwrap();

        // gen 1: open + seal an object under master_key_1.
        let (mk1, st1) = open_repo(&store, &device, &rfp).unwrap();
        assert_eq!(mk1.generation(), 1);
        let salt = [0x07u8; 16];
        let (id1, blob1) = seal_object(&mk1, ObjType::Chunk, &salt, b"gen-1 content");
        store.put(&id1, &blob1).unwrap();

        // a genesis-only repo's data keyring is just {1: mk} (nothing to peel).
        let kr1 = data_keyring(&store, &mk1).unwrap();
        assert_eq!(kr1.len(), 1);
        assert!(kr1.contains_key(&1));

        // rotate → gen 2; this writes the §8.2 DATA key-history wrap for gen 1.
        let (mk2, _st2) = rotate_repo(&store, &device, &mk1, &st1, &rfp, None, 0).unwrap();
        assert_eq!(mk2.generation(), 2);
        let (id2, blob2) = seal_object(&mk2, ObjType::Chunk, &salt, b"gen-2 content");
        store.put(&id2, &blob2).unwrap();

        // FRESH cold-start (no in-memory key): recover the gen-2 master key, then peel the data keyring.
        let (mk_cs, _st_cs) = open_repo(&store, &device, &rfp).unwrap();
        assert_eq!(mk_cs.generation(), 2);
        let kr = data_keyring(&store, &mk_cs).unwrap();
        assert_eq!(kr.len(), 2, "peeled master_key_1 and master_key_2");

        // The cold-started device reads BOTH generations by selecting the right-gen key — the whole
        // point of §8.2: a routine rotate does not make pre-rotation object content unreadable.
        assert_eq!(
            open_object(&kr[&1], ObjType::Chunk, &salt, &id1, &blob1).unwrap(),
            b"gen-1 content"
        );
        assert_eq!(
            open_object(&kr[&2], ObjType::Chunk, &salt, &id2, &blob2).unwrap(),
            b"gen-2 content"
        );
        // Using the wrong generation's key fails (FRAME gen mismatch) — no silent cross-gen read.
        assert!(open_object(&kr[&2], ObjType::Chunk, &salt, &id1, &blob1).is_err());
    }

    #[test]
    fn keyslot_is_xwing_and_unknown_algo_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let device = DeviceKey::generate().unwrap();
        let rfp = init_repo(&store, &device, 0).unwrap();
        let did = device.device_id().unwrap();

        // `init` writes an X-Wing keyslot, and cold-start unwraps it (the X-Wing secret derived from
        // the device's SSH seed, §8.3/§17).
        let keyslot = store.get_keyslot(&did, 1).unwrap().unwrap();
        assert_eq!(keyslot_algo(&keyslot).unwrap(), ALGO_XWING);
        let (mk_cs, _st) = open_repo(&store, &device, &rfp).unwrap();
        assert_eq!(mk_cs.generation(), 1);

        // A keyslot tagged with any algo_id other than X-Wing is rejected (no negotiation/downgrade).
        let mut bad = keyslot.clone();
        bad[0] = ALGO_XWING + 1;
        store.put_keyslot(&did, 1, &bad).unwrap();
        assert!(matches!(
            open_repo(&store, &device, &rfp),
            Err(RepoError::UnsupportedAlgo(a)) if a == ALGO_XWING + 1
        ));
    }

    /// The wired enrollment + revocation path over a [`Remote`]: E creates the repo, grants D (the
    /// invite-pairing grant, minus the mailbox MAC), then revoke⇒rotates D away — D leaves the roster,
    /// its keyslot is deleted, and a new generation is minted (§8.4).
    #[tokio::test]
    async fn grant_then_revoke_rotate_over_remote() {
        use crate::testmem::MemRemote;
        let dir = tempfile::tempdir().unwrap();
        let remote = MemRemote::new(Store::open(dir.path().join("r.redb")).unwrap());
        let e = DeviceKey::generate().unwrap(); // founder (device 1)
        let d = DeviceKey::generate().unwrap(); // device to enroll then revoke

        let rfp = init_repo_remote(&remote, &e, 0).await.unwrap();
        let (mk, _st, _a) = open_repo_remote(&remote, &e, &rfp, None).await.unwrap();

        // E grants D.
        let d_xwing = device_xwing_pub(&d).unwrap();
        grant_device_remote(&remote, &e, &mk, &d.public(), &d_xwing, 0)
            .await
            .unwrap();

        // D is now a member and owns a gen-1 keyslot.
        let did = d.device_id().unwrap();
        let (mk_d, st_d, _a) = open_repo_remote(&remote, &d, &rfp, None).await.unwrap();
        assert_eq!(mk_d.generation(), 1);
        assert!(st_d.is_member(&did));
        assert!(st_d.is_member(&e.device_id().unwrap()));
        assert!(remote.store.get_keyslot(&did, 1).unwrap().is_some());

        // E revoke⇒rotates D.
        rotate_repo_remote(&remote, &e, &mk, &st_d, &rfp, Some(did), 0)
            .await
            .unwrap();

        // E cold-starts onto the new generation; D is gone and its old keyslot was deleted.
        let (mk2, st2, _a) = open_repo_remote(&remote, &e, &rfp, None).await.unwrap();
        assert_eq!(mk2.generation(), 2);
        assert!(
            !st2.is_member(&did),
            "revoked device removed from the roster"
        );
        assert!(st2.is_member(&e.device_id().unwrap()));
        assert!(
            remote.store.get_keyslot(&did, 1).unwrap().is_none(),
            "revoked device's keyslot was deleted"
        );
    }

    /// C2 regression: a head published before a rotation must remain findable and readable afterward.
    /// The ref path is generation-stable (§13), so it doesn't move when the master key rotates, and
    /// `fetch_head` peels the key ring to open the head sealed under the prior generation (§8.2/§9.8).
    /// Before the fix, a current-generation client looked at a moved (empty) ref path and would treat
    /// the repo as headless — a fresh clone would then publish its empty directory as the head.
    #[tokio::test]
    async fn head_survives_a_rotation() {
        use crate::testmem::MemRemote;
        use crate::{fetch_head, push_head, push_objects};
        let dir = tempfile::tempdir().unwrap();
        let remote = MemRemote::new(Store::open(dir.path().join("r.redb")).unwrap());
        let device = DeviceKey::generate().unwrap();

        let rfp = init_repo(&remote.store, &device, 0).unwrap();
        let (mk1, st1) = open_repo(&remote.store, &device, &rfp).unwrap();

        // Publish a head at generation 1.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f.txt"), b"v1").unwrap();
        let (rt, rs) =
            secsec_snapshot::snapshot_tree(src.path(), &mk1, &remote.store, None).unwrap();
        let commit = secsec_snapshot::Commit {
            root_tree: rt,
            root_salt: rs,
            parents: vec![],
            device_id: device.device_id().unwrap(),
            version: 1,
            roster_seq: 0,
            last_seen_head: [0u8; 32],
            ts: 0,
        };
        let commit_id =
            secsec_snapshot::seal_signed_commit(&mk1, &remote.store, &device, &commit).unwrap();
        push_objects(&remote, &remote.store, &mk1, &commit_id)
            .await
            .unwrap();
        push_head(&remote, &mk1, &device, "main", commit_id, 0, None)
            .await
            .unwrap();

        // Rotate to generation 2 and build the peeled key ring a cold-started member would hold.
        let (mk2, _st2) = rotate_repo(&remote.store, &device, &mk1, &st1, &rfp, None, 0).unwrap();
        assert_eq!(mk2.generation(), 2);
        let keyring = data_keyring(&remote.store, &mk2).unwrap();

        // The head is still at the same path and opens under the peeled gen-1 key.
        let found = fetch_head(&remote, &keyring, "main").await.unwrap();
        let (head, _sig, _blob) = found.expect("head must survive a rotation");
        assert_eq!(head.commit_id, commit_id);
    }
}
