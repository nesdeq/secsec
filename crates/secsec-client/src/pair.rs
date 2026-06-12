//! §7 invite-onboarding pairing: a joiner carries one short, single-use **invite code** from an
//! enrolled device — the shared secret authenticating a key exchange **through** the blind server,
//! which never learns the code and so cannot MITM, swap keys, or feed a fake repo. All blobs are
//! code-MAC'd and relayed via the transient pairing mailbox (slot ids = `derive_key(label, code)`):
//! joiner D posts `{D_pubkey, D_xwing_pub}` to slot `d`; host E verifies the MAC, grants
//! ([`crate::repo::grant_device_remote`]), and posts `{RFP, host_id}` to slot `e`; D verifies, then
//! cold-starts and checks its new keyslot against `mk_commit` (§7).

use crate::repo::{device_xwing_pub, grant_device_remote};
use crate::{Remote, RemoteError};
use secsec_canon::{CanonError, Reader, Writer};
use secsec_frame::MAX_ROSTER_ENTRY_SIZE;
use secsec_kdf::MasterKey;
use secsec_sig::{DeviceId, DeviceKey, DevicePublic};
use std::time::Duration;

/// Invite-code length in bytes (96-bit; single-use + the §7 rate-limit make this ample against a
/// server's online guessing — the only attack, since the code never leaves the two devices).
const CODE_LEN: usize = 12;
/// Poll cadence for the pairing mailbox.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

const SLOT_D: &str = "secsec-pair-slot-d-v1";
const SLOT_E: &str = "secsec-pair-slot-e-v1";
const MAC_CTX: &str = "secsec-pair-mac-v1";

/// Errors from the pairing flow.
#[derive(Debug)]
pub enum PairError {
    /// A pairing message failed its code-MAC — wrong code, or a server/relay tampering attempt.
    BadMac,
    /// The pairing did not complete before the deadline.
    Timeout,
    /// A pairing message was malformed.
    Decode(CanonError),
    /// The invite code string did not parse to [`CODE_LEN`] bytes.
    BadCode,
    /// A device-key error.
    Sig(secsec_sig::SigError),
    /// A remote/transport error.
    Remote(RemoteError),
    /// The host pin the inviting device vouched for does not match the server the joiner connected to
    /// — a possible MITM. Abort.
    HostMismatch,
    /// The networked grant / cold-start failed.
    Enroll(String),
    /// OS RNG failure.
    Rng,
}

impl core::fmt::Display for PairError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PairError::BadMac => {
                f.write_str("pairing message failed its code authentication (wrong invite code?)")
            }
            PairError::Timeout => {
                f.write_str("pairing timed out (the other device never completed it)")
            }
            PairError::Decode(e) => write!(f, "malformed pairing message: {e}"),
            PairError::BadCode => f.write_str("invalid invite code"),
            PairError::Sig(e) => write!(f, "sig: {e}"),
            PairError::Remote(e) => write!(f, "{e}"),
            PairError::HostMismatch => {
                f.write_str("server host pin mismatch during pairing (possible MITM); aborted")
            }
            PairError::Enroll(e) => write!(f, "enrollment during pairing failed: {e}"),
            PairError::Rng => f.write_str("OS RNG failure"),
        }
    }
}
impl std::error::Error for PairError {}
impl From<CanonError> for PairError {
    fn from(e: CanonError) -> Self {
        PairError::Decode(e)
    }
}
impl From<secsec_sig::SigError> for PairError {
    fn from(e: secsec_sig::SigError) -> Self {
        PairError::Sig(e)
    }
}
impl From<RemoteError> for PairError {
    fn from(e: RemoteError) -> Self {
        PairError::Remote(e)
    }
}

/// A fresh single-use invite: the raw code bytes and a human-typeable display string (lowercase hex
/// grouped in fours, e.g. `1a2b-3c4d-…`).
pub fn new_invite() -> Result<([u8; CODE_LEN], String), PairError> {
    let mut code = [0u8; CODE_LEN];
    getrandom::fill(&mut code).map_err(|_| PairError::Rng)?;
    Ok((code, encode_code(&code)))
}

/// Display the code as dash-grouped lowercase hex.
#[must_use]
pub fn encode_code(code: &[u8; CODE_LEN]) -> String {
    let hex: String = code.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("hex is ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse a typed invite code (ignoring case, dashes, and whitespace) back to its bytes.
pub fn decode_code(s: &str) -> Result<[u8; CODE_LEN], PairError> {
    let hex: String = s
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .flat_map(|c| c.to_lowercase())
        .collect();
    if hex.len() != CODE_LEN * 2 {
        return Err(PairError::BadCode);
    }
    let mut code = [0u8; CODE_LEN];
    for (i, byte) in code.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| PairError::BadCode)?;
    }
    Ok(code)
}

fn slot(label: &str, code: &[u8; CODE_LEN]) -> [u8; 32] {
    blake3::derive_key(label, code)
}

fn mac(code: &[u8; CODE_LEN], label: u8, parts: &[&[u8]]) -> [u8; 32] {
    let key = blake3::derive_key(MAC_CTX, code);
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(&[label]);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Poll a mailbox slot until present or the deadline passes.
async fn poll_slot<R: Remote>(
    remote: &R,
    slot: &[u8; 32],
    rounds: u32,
) -> Result<Vec<u8>, PairError> {
    for _ in 0..rounds {
        if let Some(blob) = remote.pair_get(slot).await? {
            return Ok(blob);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Err(PairError::Timeout)
}

// ---- joiner (new device) side ----

/// Joiner D: submit `{D_pubkey, D_xwing_pub}` (code-MAC'd) to slot `d`, then poll slot `e` for the
/// host's response and verify its MAC. Returns the genuine `(rfp, host_id)` — the caller MUST confirm
/// `host_id` equals the pin of the server it actually connected to before trusting the repo. `rounds`
/// bounds the wait (× [`POLL_INTERVAL`]).
pub async fn join<R: Remote>(
    remote: &R,
    code: &[u8; CODE_LEN],
    d_pubkey: &DevicePublic,
    d_xwing_pub: &[u8],
    rounds: u32,
) -> Result<([u8; 32], [u8; 32]), PairError> {
    let d_canonical = d_pubkey.to_canonical()?;
    let tag = mac(code, b'd', &[&d_canonical, d_xwing_pub]);
    let mut w = Writer::new();
    w.bytes(&d_canonical).bytes(d_xwing_pub).raw(&tag);
    remote.pair_put(&slot(SLOT_D, code), &w.finish()).await?;

    let blob = poll_slot(remote, &slot(SLOT_E, code), rounds).await?;
    let mut r = Reader::new(&blob);
    let rfp: [u8; 32] = r.raw(32)?.try_into().expect("32");
    let host_id: [u8; 32] = r.raw(32)?.try_into().expect("32");
    let got: [u8; 32] = r.raw(32)?.try_into().expect("32");
    r.finish()?;
    if !ct_eq(&got, &mac(code, b'e', &[&rfp, &host_id])) {
        return Err(PairError::BadMac);
    }
    Ok((rfp, host_id))
}

// ---- host (inviting member) side ----

/// Host E: wait for the joiner's submission on slot `d` and verify its code-MAC. Returns the joiner's
/// `(DevicePublic, xwing_pub)` for the caller to [`grant_device_remote`](crate::repo::grant_device_remote);
/// the caller then calls [`respond`] to hand the joiner the RFP + host pin.
pub async fn await_join<R: Remote>(
    remote: &R,
    code: &[u8; CODE_LEN],
    rounds: u32,
) -> Result<(DevicePublic, Vec<u8>), PairError> {
    let blob = poll_slot(remote, &slot(SLOT_D, code), rounds).await?;
    let mut r = Reader::new(&blob);
    let d_canonical = r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec();
    let d_xwing = r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec();
    let got: [u8; 32] = r.raw(32)?.try_into().expect("32");
    r.finish()?;
    if !ct_eq(&got, &mac(code, b'd', &[&d_canonical, &d_xwing])) {
        return Err(PairError::BadMac);
    }
    let d_pubkey = DevicePublic::from_canonical(&d_canonical)?;
    Ok((d_pubkey, d_xwing))
}

/// Host E: post the code-MAC'd `{rfp, host_id}` response to slot `e` so the joiner learns the genuine
/// repo anchor + server pin. Call this **after** granting the joiner a keyslot.
pub async fn respond<R: Remote>(
    remote: &R,
    code: &[u8; CODE_LEN],
    rfp: &[u8; 32],
    host_id: &[u8; 32],
) -> Result<(), PairError> {
    let tag = mac(code, b'e', &[rfp, host_id]);
    let mut w = Writer::new();
    w.raw(rfp).raw(host_id).raw(&tag);
    remote.pair_put(&slot(SLOT_E, code), &w.finish()).await?;
    Ok(())
}

// ---- full orchestration (used by the `secsec invite` / `secsec sync --invite` CLI) ----

/// Full host-side flow (`secsec invite`): wait for the joiner, enroll it over the wire
/// ([`grant_device_remote`]), then hand it the genuine RFP + the server pin it should trust. `mk`/`rfp`
/// are the host's already-open repo; `host_id` is the pin the host connected under. Returns the
/// enrolled device id.
#[allow(clippy::too_many_arguments)]
pub async fn run_host<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    mk: &MasterKey,
    rfp: &[u8; 32],
    host_id: &[u8; 32],
    code: &[u8; CODE_LEN],
    rounds: u32,
    ts: u64,
) -> Result<DeviceId, PairError> {
    let (d_pubkey, d_xwing) = await_join(remote, code, rounds).await?;
    grant_device_remote(remote, device, mk, &d_pubkey, &d_xwing, ts)
        .await
        .map_err(|e| PairError::Enroll(e.to_string()))?;
    respond(remote, code, rfp, host_id).await?;
    Ok(d_pubkey.device_id()?)
}

/// Full joiner-side flow (`secsec sync --invite`): pair through the server, **confirm the host pin
/// matches the server actually connected to** (`connected_host_id`, captured via TOFU), and return the
/// genuine RFP. The caller then cold-starts ([`open_repo_remote`](crate::repo::open_repo_remote)) — the
/// keyslot the host just wrote is verified against `mk_commit` there.
pub async fn run_join<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    code: &[u8; CODE_LEN],
    connected_host_id: &[u8; 32],
    rounds: u32,
) -> Result<[u8; 32], PairError> {
    let d_xwing = device_xwing_pub(device).map_err(|e| PairError::Enroll(e.to_string()))?;
    let (rfp, host_id) = join(remote, code, &device.public(), &d_xwing, rounds).await?;
    if !ct_eq(&host_id, connected_host_id) {
        return Err(PairError::HostMismatch);
    }
    Ok(rfp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_round_trips_and_tolerates_formatting() {
        let (code, disp) = new_invite().unwrap();
        assert_eq!(decode_code(&disp).unwrap(), code);
        // dashes/case/spaces are ignored.
        assert_eq!(decode_code(&disp.to_uppercase()).unwrap(), code);
        assert_eq!(decode_code(&disp.replace('-', " ")).unwrap(), code);
        assert!(decode_code("too-short").is_err());
    }

    #[test]
    fn mac_binds_label_and_content() {
        let code = [0x11u8; CODE_LEN];
        let a = mac(&code, b'd', &[b"x", b"y"]);
        assert_eq!(a, mac(&code, b'd', &[b"x", b"y"]));
        assert_ne!(a, mac(&code, b'e', &[b"x", b"y"])); // label
        assert_ne!(a, mac(&code, b'd', &[b"x", b"z"])); // content
        assert_ne!(a, mac(&[0x22; CODE_LEN], b'd', &[b"x", b"y"])); // code
    }
}
