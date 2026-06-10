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
//! Keyslots are **algo-tagged** (`algo_id(1B) ‖ body`, §9.1): classical HPKE(X25519) or hybrid-PQ
//! X-Wing (§17). A device's X-Wing keypair is derived from its SSH private scalar
//! ([`secsec_sig::DeviceKey::xwing_seed`]) and its X-Wing public is published in the roster
//! (`Genesis`/`AddDevice`), so a granter/rotation can wrap to it once `min_algo` reaches X-Wing. The
//! cold-start unwrap dispatches by `algo_id` and enforces the §16 `min_algo` floor after folding.

use crate::{Remote, RemoteError};
use secsec_canon::{Reader, Writer};
use secsec_frame::{Frame, FRAME_LEN, MAX_ROSTER_ENTRY_SIZE};
use secsec_kdf::MasterKey;
use secsec_pq::{XWingPublic, XWingSecret};
use secsec_proto::server::limits::MAX_TOTAL_SIGCHAIN;
use secsec_recovery::{recover_raw_with_code, recovery_key_from_code, seal_recovery, SALT_LEN};
use secsec_roster::{
    append, append_many, cold_start_fold, decode_entry, encode_entry, genesis, open_entry,
    peel_data_keys, revoke_closure, revoke_rotate_ops, seal_data_keyhist, seal_entry,
    seal_roster_keyhist, sign_grant, Op, RosterError, State, ENROLLMENT_NONCE_LEN,
};
use secsec_sig::{DeviceId, DeviceKey, DevicePublic};
use secsec_store::{Store, StoreError, ABSENT_HEAD};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Keyslot algorithm id (`secsec-Design.md` §9.1 / §8.3): a stored keyslot is `algo_id(1B) ‖ body`.
/// **Post-quantum is mandatory** — X-Wing (§17) is the *only* keyslot algorithm; the classical
/// X25519/HPKE wrap was removed. The 1-byte tag and the §16 `min_algo` floor remain for forward
/// agility (a future PQ KEM bumps the floor via `SetMinAlgo`); any keyslot below X-Wing is rejected.
pub const ALGO_XWING: u8 = 2;

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

/// Unwrap a stored keyslot to the **raw** master-key bytes for cold-start (§8.1). X-Wing only — any
/// other `algo_id` is rejected (PQ is mandatory). The §16 `min_algo` floor is re-checked by the caller
/// after folding (the floor lives inside the chain this unwrap bootstraps); see [`open_repo`].
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
    /// An X-Wing keyslot operation failed (malformed public/ciphertext or AEAD).
    Pq,
    /// §16 downgrade floor: a fetched keyslot's `algo_id` was below the chain's `min_algo`.
    AlgoTooWeak {
        /// The keyslot's `algo_id`.
        got: u8,
        /// The folded chain's `min_algo` floor.
        floor: u8,
    },
    /// Sealing / opening the §8.6 recovery keyslot failed (bad code/passphrase, malformed blob).
    Recovery(secsec_recovery::RecoveryError),
    /// `recover` was asked to run but no §8.6 recovery keyslot was ever created for this repo.
    NoRecovery,
    /// The stored §8.6 recovery record was malformed (truncated / non-canonical framing).
    BadRecovery,
    /// The recovery keyslot was created at generation `record` but the repo is now at `cur`: it was
    /// superseded by a rotation and only recovers the generation it was pinned to. Re-create recovery.
    RecoveryStale {
        /// The generation the recovery keyslot was sealed at.
        record: u32,
        /// The repo's current tip generation.
        cur: u32,
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
            RepoError::Pq => f.write_str("X-Wing keyslot operation failed"),
            RepoError::AlgoTooWeak { got, floor } => {
                write!(
                    f,
                    "keyslot algo_id {got} below min_algo floor {floor} (§16)"
                )
            }
            RepoError::Recovery(e) => write!(f, "recovery: {e}"),
            RepoError::NoRecovery => f.write_str("no recovery keyslot for this repo (§8.6)"),
            RepoError::BadRecovery => f.write_str("malformed recovery record (§8.6)"),
            RepoError::RecoveryStale { record, cur } => write!(
                f,
                "recovery keyslot is at generation {record} but the repo is at {cur}; \
                 it was superseded by a rotation — re-create recovery (§8.6)"
            ),
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
impl From<secsec_recovery::RecoveryError> for RepoError {
    fn from(e: secsec_recovery::RecoveryError) -> Self {
        RepoError::Recovery(e)
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
    // Genesis CAS: `old_tip` is the all-zero sentinel ("expect empty"); a `false` return means another
    // device already created the repo.
    if !remote.roster_append(&ABSENT_HEAD, &blob).await? {
        return Err(RepoError::AlreadyInitialized);
    }

    let device_id = device.device_id()?;
    let keyslot = wrap_keyslot(&key, 1, &device_id, &xwing_pub)?;
    remote.put_keyslot(&device_id, 1, &keyslot).await?;
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
    // Dispatch the unwrap by the keyslot's algo_id (classical / X-Wing, §8.3/§17).
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

/// Encode the §8.6 `/recovery` record: `le32(gen) ‖ bytes(device_pubkey) ‖ raw(blob)`. The pinned
/// generation + device pubkey let the recoverer recompute the §9.4 AD; `blob` is the keyslot itself.
fn encode_recovery_record(gen: u32, device_pubkey: &[u8], blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(gen).bytes(device_pubkey).raw(blob);
    w.finish()
}

/// Decode an [`encode_recovery_record`] blob into `(gen, device_pubkey, recovery_blob)`.
fn decode_recovery_record(record: &[u8]) -> Result<(u32, Vec<u8>, Vec<u8>), RepoError> {
    let mut r = Reader::new(record);
    let gen = r.u32().map_err(|_| RepoError::BadRecovery)?;
    let pubkey = r
        .bytes(MAX_ROSTER_ENTRY_SIZE)
        .map_err(|_| RepoError::BadRecovery)?
        .to_vec();
    let rest = r.remaining();
    let blob = r.raw(rest).map_err(|_| RepoError::BadRecovery)?.to_vec();
    r.finish().map_err(|_| RepoError::BadRecovery)?;
    Ok((gen, pubkey, blob))
}

/// §8.6 `recovery-init`: create the repo's optional recovery keyslot for `device`, sealing the live
/// `mk` under a freshly generated 256-bit **recovery code** (returned — show it to the user once; it
/// is never stored). Writes the `/recovery` record `le32(gen) ‖ bytes(device_pubkey) ‖ blob` so the
/// recoverer can recompute the §9.4 AD. The recovered candidate is anchored to `mk_commit` at recover
/// time (§7 step 3), so this is a user-held break-glass key, **not** a server-exploitable backdoor.
///
/// The keyslot is pinned to the current generation; a later [`rotate_repo`] supersedes it (the new
/// master key is not wrapped under the code), so re-run this after a rotation (see [`recover_master`]).
/// Re-running overwrites any existing recovery keyslot with a fresh code + salt (§19).
pub fn create_recovery(
    store: &Store,
    device: &DeviceKey,
    mk: &MasterKey,
) -> Result<Zeroizing<[u8; 32]>, RepoError> {
    let mut code = Zeroizing::new([0u8; 32]);
    getrandom::fill(code.as_mut_slice()).map_err(|_| RepoError::Rng)?;
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| RepoError::Rng)?;
    let rkey = recovery_key_from_code(&salt, &code);

    let device_pubkey = device.public().to_canonical()?;
    let gen = mk.generation();
    let blob = seal_recovery(mk.expose_secret(), gen, &device_pubkey, &rkey, &salt);

    store.put_recovery(&encode_recovery_record(gen, &device_pubkey, &blob))?;
    Ok(code)
}

/// §8.6 `recover`: reconstruct the live `(MasterKey, State)` from the recovery `code` alone — the
/// break-glass path when every enrolled device is lost. Reads the `/recovery` record, recovers the
/// raw master-key candidate (no commit check here), then folds the RFP-anchored chain, which verifies
/// the candidate against `mk_commit_g` (§7 step 3) — so a wrong code or a server-forged record is
/// rejected by the fold, not silently accepted.
///
/// Only the generation the keyslot was pinned to is recoverable: if the repo rotated after
/// `recovery-init`, this returns [`RepoError::RecoveryStale`] (the post-rotation master key is not
/// wrapped under the code). Recovers **read** access (master key + roster, and thence the §8.2 data
/// keyring); re-enrolling a fresh device afterward is a normal [`grant_device`] from this identity.
pub fn recover_master(
    store: &Store,
    code: &[u8; 32],
    rfp: &[u8; 32],
) -> Result<(MasterKey, State), RepoError> {
    let record = store.get_recovery()?.ok_or(RepoError::NoRecovery)?;
    let (rec_gen, device_pubkey, blob) = decode_recovery_record(&record)?;

    // Read the whole sigchain; the tip's gen must equal the keyslot's gen (else the keyslot is stale).
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
    let g_cur = frame_gen(entries.last().expect("n > 0"))?;
    if rec_gen != g_cur {
        return Err(RepoError::RecoveryStale {
            record: rec_gen,
            cur: g_cur,
        });
    }

    // Recover the raw candidate from the code (no commit check — the fold verifies mk_commit below).
    let candidate = recover_raw_with_code(&blob, code, &device_pubkey, g_cur)?;

    // Roster-key history (§8.2): peel roster_key_g back to genesis, then fold + verify RFP + mk_commit.
    // No `enforce_min_algo` here: recovery bypasses the device keyslot entirely, so the §16
    // keyslot-downgrade floor does not apply.
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

/// §7 `grant` (record-writing half): enroll device `d_pubkey` into the repo. The granter `device` (a
/// current member holding `mk`) appends an `AddDevice` entry (publishing `d_xwing_pub`), wraps
/// `master_key_g` to D's **X-Wing** keyslot (PQ is mandatory, §8.3/§17), and signs the
/// `secsec-grant-v1` attestation over `enrollment_nonce`. Returns the attestation for E to send to D
/// over the out-of-band grant channel (§7 step 5).
///
/// The **interactive** half — the SAS commitment-before-reveal ceremony, the human fingerprint check,
/// and the per-`D_pubkey` rate limit (§7) — is the channel orchestration **above** this; the caller
/// MUST complete it (confirming `d_pubkey` and `d_xwing_pub` out-of-band via the SAS) before invoking.
/// `d_xwing_pub` is D's X-Wing public key bytes (D derives it from its SSH key — see
/// `secsec_sig::DeviceKey::xwing_seed` — and sends it over the grant channel). On D's side,
/// [`open_repo`]/[`open_repo_remote`] verify the RFP + `mk_commit`, and the caller verifies this
/// attestation with `secsec_roster::verify_grant`.
pub fn grant_device(
    store: &Store,
    device: &DeviceKey,
    mk: &MasterKey,
    d_pubkey: &DevicePublic,
    d_xwing_pub: &[u8],
    enrollment_nonce: &[u8; ENROLLMENT_NONCE_LEN],
    ts: u64,
) -> Result<Vec<u8>, RepoError> {
    // PQ is mandatory: the new device MUST publish an X-Wing public key to be wrapped to.
    if d_xwing_pub.is_empty() {
        return Err(RepoError::Pq);
    }
    let g = mk.generation();
    let mk_commit = mk.mk_commit();
    let rk = mk.roster_key();

    // Fetch + decrypt the current tip to chain the AddDevice entry.
    let n = store.roster_len()?;
    let tip_seq = n.checked_sub(1).ok_or(RepoError::NotInitialized)?;
    let tip_blob = store
        .get_roster_entry(tip_seq)?
        .ok_or(RepoError::MissingEntry(tip_seq))?;
    let tip_entry = decode_entry(&open_entry(&rk, g, tip_seq, &tip_blob)?)?;

    let d_canonical = d_pubkey.to_canonical()?;
    let op = Op::AddDevice {
        pubkey: d_canonical.clone(),
        mk_commit,
        enroll_pub: d_xwing_pub.to_vec(),
    };
    let entry = append(&tip_entry, op, device, ts)?;
    let roster_seq = entry.seq;
    let blob = seal_entry(&rk, g, roster_seq, &encode_entry(&entry));
    let old_tip = *blake3::hash(&tip_blob).as_bytes();
    if store.append_roster(&old_tip, &blob)?.is_none() {
        return Err(RepoError::RosterCasConflict);
    }

    // Wrap master_key_g to D's X-Wing keyslot (§8.3/§17).
    let d_id = d_pubkey.device_id()?;
    let keyslot = wrap_keyslot(mk.expose_secret(), g, &d_id, d_xwing_pub)?;
    store.put_keyslot(&d_id, g, &keyslot)?;

    // Sign the grant attestation over the directly-delivered enrollment_nonce (§9.6).
    Ok(sign_grant(
        device,
        &d_canonical,
        &mk_commit,
        roster_seq,
        enrollment_nonce,
    )?)
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
    // Dispatch the unwrap by the keyslot's algo_id (classical / X-Wing, §8.3/§17).
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
    fn keyslot_is_xwing_and_non_pq_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let device = DeviceKey::generate().unwrap();
        let rfp = init_repo(&store, &device, 0).unwrap();
        let did = device.device_id().unwrap();

        // PQ is mandatory: `init` writes an X-Wing keyslot, and cold-start unwraps it via the X-Wing
        // path (the X-Wing secret derived from the device's SSH seed, §8.3/§17).
        let keyslot = store.get_keyslot(&did, 1).unwrap().unwrap();
        assert_eq!(keyslot_algo(&keyslot).unwrap(), ALGO_XWING);
        let (mk_cs, _st) = open_repo(&store, &device, &rfp).unwrap();
        assert_eq!(mk_cs.generation(), 1);

        // A keyslot tagged with any non-X-Wing algo_id (e.g. a downgraded "classical" 1) is rejected —
        // no pre-quantum keyslot is ever accepted.
        let mut downgraded = keyslot.clone();
        downgraded[0] = 1;
        store.put_keyslot(&did, 1, &downgraded).unwrap();
        assert!(matches!(
            open_repo(&store, &device, &rfp),
            Err(RepoError::UnsupportedAlgo(1))
        ));
    }

    #[test]
    fn recovery_round_trips_and_rejects_wrong_code_and_stale_gen() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let device = DeviceKey::generate().unwrap();
        let rfp = init_repo(&store, &device, 0).unwrap();
        let (mk, _st) = open_repo(&store, &device, &rfp).unwrap();

        // recovery-init: seal master_key_1 under a fresh 256-bit code.
        let code = create_recovery(&store, &device, &mk).unwrap();

        // recover from the code alone reconstructs the same live identity (gen + membership), and
        // its master key opens the SAME data keyring as the original device's.
        let (mk_r, st_r) = recover_master(&store, &code, &rfp).unwrap();
        assert_eq!(mk_r.generation(), 1);
        assert!(st_r.is_member(&device.device_id().unwrap()));
        assert_eq!(mk_r.mk_commit(), mk.mk_commit());

        // a wrong code fails the CTX AEAD (CMT-4) — not a silent wrong key.
        assert!(matches!(
            recover_master(&store, &[0u8; 32], &rfp),
            Err(RepoError::Recovery(_))
        ));
        // a wrong RFP fails the fold's anchor check.
        assert!(recover_master(&store, &code, &[0xAB; 32]).is_err());

        // after a rotation the keyslot is stale (pinned to gen 1; the repo is at gen 2).
        let (mk2, st2) = open_repo(&store, &device, &rfp).unwrap();
        let _ = rotate_repo(&store, &device, &mk2, &st2, &rfp, None, 0).unwrap();
        assert!(matches!(
            recover_master(&store, &code, &rfp),
            Err(RepoError::RecoveryStale { record: 1, cur: 2 })
        ));

        // re-running recovery-init at the new generation restores recoverability.
        let (mk_g2, _) = open_repo(&store, &device, &rfp).unwrap();
        let code2 = create_recovery(&store, &device, &mk_g2).unwrap();
        let (mk_r2, _) = recover_master(&store, &code2, &rfp).unwrap();
        assert_eq!(mk_r2.generation(), 2);
        assert_eq!(mk_r2.mk_commit(), mk_g2.mk_commit());
    }

    #[test]
    fn recover_without_keyslot_is_no_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let device = DeviceKey::generate().unwrap();
        let rfp = init_repo(&store, &device, 0).unwrap();
        // no recovery-init was run.
        assert!(matches!(
            recover_master(&store, &[0u8; 32], &rfp),
            Err(RepoError::NoRecovery)
        ));
    }

    #[test]
    fn grant_enrolls_a_second_device_end_to_end() {
        use secsec_roster::{sas_value, verify_grant};
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        let e = DeviceKey::generate().unwrap(); // granter (device 1)
        let d = DeviceKey::generate().unwrap(); // new device
        let rfp = init_repo(&store, &e, 0).unwrap();
        let (mk, _st) = open_repo(&store, &e, &rfp).unwrap();

        // --- the SAS ceremony (cores; the channel/human steps are the caller's) ---
        let d_canonical = d.public().to_canonical().unwrap();
        let grant_nonce = [0x42u8; secsec_roster::GRANT_NONCE_LEN];
        // both sides compute the SAS over RFP ‖ D_pubkey ‖ grant_nonce; the human confirms they match.
        let sas_e = sas_value(&rfp, &d_canonical, &grant_nonce);
        let sas_d = sas_value(&rfp, &d_canonical, &grant_nonce);
        assert_eq!(sas_e, sas_d, "SAS must agree out-of-band");

        // --- E writes the grant records + attestation ---
        let enrollment_nonce = [0x99u8; ENROLLMENT_NONCE_LEN];
        // D derives its X-Wing public from its SSH key and sends it over the grant channel; E wraps
        // D's (mandatory) X-Wing keyslot to it.
        let d_xwing = device_xwing_pub(&d).unwrap();
        let attestation =
            grant_device(&store, &e, &mk, &d.public(), &d_xwing, &enrollment_nonce, 0).unwrap();

        // --- D's first sync: cold-start recovers the master key + sees itself a member ---
        let (mk_d, st_d) = open_repo(&store, &d, &rfp).unwrap();
        assert_eq!(mk_d.generation(), 1);
        assert!(st_d.is_member(&d.device_id().unwrap()));
        assert!(st_d.is_member(&e.device_id().unwrap()));
        assert_eq!(st_d.members.len(), 2);

        // D verifies the grant attestation covers exactly the enrollment_nonce it received from E (§7
        // step 4), signed by a current member (E).
        let roster_seq = store.roster_len().unwrap() - 1; // the AddDevice entry's seq
        assert!(verify_grant(
            &e.public(),
            &d_canonical,
            &mk.mk_commit(),
            roster_seq,
            &enrollment_nonce,
            &attestation,
        )
        .is_ok());
        // a wrong enrollment_nonce (a replayed/stale attestation) is rejected.
        assert!(verify_grant(
            &e.public(),
            &d_canonical,
            &mk.mk_commit(),
            roster_seq,
            &[0u8; ENROLLMENT_NONCE_LEN],
            &attestation,
        )
        .is_err());

        // after the grant, E can rotate-revoke D (revoke ⇒ rotate), removing it from membership.
        let (_mk2, st2) = rotate_repo(
            &store,
            &e,
            &mk,
            &st_d,
            &rfp,
            Some(d.device_id().unwrap()),
            0,
        )
        .unwrap();
        assert!(
            !st2.is_member(&d.device_id().unwrap()),
            "revoked device removed"
        );
        assert!(st2.is_member(&e.device_id().unwrap()));
    }
}
