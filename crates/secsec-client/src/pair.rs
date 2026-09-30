//! §7 invite pairing through the blind server's mailbox: a short single-use code authenticates both directions of the exchange.

use crate::repo::{device_xwing_pub, grant_device_remote, RosterAnchor};
use crate::{Remote, RemoteError};
use secsec_canon::{CanonError, Reader, Writer};
use secsec_frame::MAX_ROSTER_ENTRY_SIZE;
use secsec_sig::{DeviceId, DeviceKey, DevicePublic};
use std::time::Duration;

/// Invite-code length in bytes: 96 bits against a server's online guessing, the only attack (§7).
const CODE_LEN: usize = 12;
/// Poll cadence for the pairing mailbox.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

const SLOT_D: &str = "secsec-pair-slot-d-v1";
const SLOT_E: &str = "secsec-pair-slot-e-v1";
const MAC_CTX: &str = "secsec-pair-mac-v2";

/// Errors from the pairing flow.
#[derive(Debug)]
pub enum PairError {
    /// A pairing message failed its code MAC: a wrong code, or tampering.
    BadMac,
    /// The other device did not complete the pairing in time.
    Timeout,
    /// A pairing message was malformed.
    Decode(CanonError),
    /// The invite code did not parse.
    BadCode,
    /// A device-key error.
    Sig(secsec_sig::SigError),
    /// A remote/transport error.
    Remote(RemoteError),
    /// The server pin the inviting device vouched for differs from the one connected to: a possible MITM.
    HostMismatch,
    /// The grant or cold start failed.
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

/// A fresh single-use invite: the code bytes and its dash-grouped hex display form.
pub fn new_invite() -> Result<([u8; CODE_LEN], String), PairError> {
    let mut code = [0u8; CODE_LEN];
    getrandom::fill(&mut code).map_err(|_| PairError::Rng)?;
    Ok((code, encode_code(&code)))
}

/// Display the code as dash-grouped lowercase hex.
#[must_use]
pub(crate) fn encode_code(code: &[u8; CODE_LEN]) -> String {
    let hex: String = code.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("hex is ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse a typed invite code, ignoring case, dashes, and whitespace.
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

/// The code MAC over `label ‖ (le64(len) ‖ part)…`, so part boundaries cannot shift.
fn mac(code: &[u8; CODE_LEN], label: u8, parts: &[&[u8]]) -> [u8; 32] {
    let key = blake3::derive_key(MAC_CTX, code);
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(&[label]);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// KAT hook: the two slot ids and the two MACs for `code`, as `[slot_d, slot_e, mac('d', d_parts), mac('e', e_parts)]`.
#[doc(hidden)]
#[must_use]
pub fn __kat(code: &[u8; CODE_LEN], d_parts: &[&[u8]], e_parts: &[&[u8]]) -> [[u8; 32]; 4] {
    [
        slot(SLOT_D, code),
        slot(SLOT_E, code),
        mac(code, b'd', d_parts),
        mac(code, b'e', e_parts),
    ]
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

fn read32(r: &mut Reader<'_>) -> Result<[u8; 32], PairError> {
    let mut out = [0u8; 32];
    out.copy_from_slice(r.raw(32)?);
    Ok(out)
}

/// Poll a mailbox slot until its message arrives or `rounds` polls pass.
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

/// Joiner: post `{pubkey, xwing_pub}` to slot `d`, then take and verify the host's `{rfp, host_id}` from slot `e`.
pub(crate) async fn join<R: Remote>(
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
    let resp = parse_response(&blob)?;
    if !ct_eq(&resp.mac, &mac(code, b'e', &[&resp.rfp, &resp.host_id])) {
        return Err(PairError::BadMac);
    }
    Ok((resp.rfp, resp.host_id))
}

/// The host's response: the RFP, the server pin it vouches for, and the code MAC.
struct Response {
    rfp: [u8; 32],
    host_id: [u8; 32],
    mac: [u8; 32],
}

/// The joiner's submission: its canonical public key, its X-Wing public key, and the code MAC.
struct Submission {
    pubkey: Vec<u8>,
    xwing_pub: Vec<u8>,
    mac: [u8; 32],
}

/// Parse `rfp ‖ host_id ‖ mac`.
fn parse_response(blob: &[u8]) -> Result<Response, PairError> {
    let mut r = Reader::new(blob);
    let resp = Response {
        rfp: read32(&mut r)?,
        host_id: read32(&mut r)?,
        mac: read32(&mut r)?,
    };
    r.finish()?;
    Ok(resp)
}

/// Parse `bytes(pubkey) ‖ bytes(xwing_pub) ‖ mac`.
fn parse_join(blob: &[u8]) -> Result<Submission, PairError> {
    let mut r = Reader::new(blob);
    let sub = Submission {
        pubkey: r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec(),
        xwing_pub: r.bytes(MAX_ROSTER_ENTRY_SIZE)?.to_vec(),
        mac: read32(&mut r)?,
    };
    r.finish()?;
    Ok(sub)
}

/// Fuzz hook: both pairing-message parsers on arbitrary bytes.
#[doc(hidden)]
pub fn __fuzz_parse(blob: &[u8]) {
    let _ = parse_response(blob);
    let _ = parse_join(blob);
}

/// Host: take and verify the joiner's submission from slot `d`.
pub(crate) async fn await_join<R: Remote>(
    remote: &R,
    code: &[u8; CODE_LEN],
    rounds: u32,
) -> Result<(DevicePublic, Vec<u8>), PairError> {
    let blob = poll_slot(remote, &slot(SLOT_D, code), rounds).await?;
    let sub = parse_join(&blob)?;
    if !ct_eq(&sub.mac, &mac(code, b'd', &[&sub.pubkey, &sub.xwing_pub])) {
        return Err(PairError::BadMac);
    }
    Ok((DevicePublic::from_canonical(&sub.pubkey)?, sub.xwing_pub))
}

/// Host: post the code-MAC'd `{rfp, host_id}` to slot `e`, after the grant.
pub(crate) async fn respond<R: Remote>(
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

/// The inviting side (`secsec invite`): await the joiner, grant it, hand it the RFP and pin; returns its id and our new anchor.
#[allow(clippy::too_many_arguments)]
pub async fn run_host<R: Remote>(
    remote: &R,
    device: &DeviceKey,
    rfp: &[u8; 32],
    anchor: Option<RosterAnchor>,
    host_id: &[u8; 32],
    code: &[u8; CODE_LEN],
    rounds: u32,
    ts: u64,
) -> Result<(DeviceId, RosterAnchor), PairError> {
    let (d_pubkey, d_xwing) = await_join(remote, code, rounds).await?;
    let anchor = grant_device_remote(remote, device, rfp, anchor, &d_pubkey, &d_xwing, ts)
        .await
        .map_err(|e| PairError::Enroll(e.to_string()))?;
    respond(remote, code, rfp, host_id).await?;
    Ok((d_pubkey.device_id()?, anchor))
}

/// The joining side (`secsec sync --invite`): pair, confirm the vouched pin is the connected server's, return the RFP.
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
    use crate::repo::{init_repo_remote, open_repo_remote};
    use crate::testmem::MemRemote;
    use secsec_store::Store;

    #[test]
    fn code_round_trips_and_tolerates_formatting() {
        let (code, disp) = new_invite().unwrap();
        assert_eq!(decode_code(&disp).unwrap(), code);
        assert_eq!(decode_code(&disp.to_uppercase()).unwrap(), code);
        assert_eq!(decode_code(&disp.replace('-', " ")).unwrap(), code);
        assert!(decode_code("too-short").is_err());
    }

    /// The MAC binds label, code, content, and the boundary between parts.
    #[test]
    fn mac_binds_label_content_and_part_boundaries() {
        let code = [0x11u8; CODE_LEN];
        let a = mac(&code, b'd', &[b"x", b"y"]);
        assert_eq!(a, mac(&code, b'd', &[b"x", b"y"]));
        assert_ne!(a, mac(&code, b'e', &[b"x", b"y"]));
        assert_ne!(a, mac(&code, b'd', &[b"x", b"z"]));
        assert_ne!(a, mac(&[0x22; CODE_LEN], b'd', &[b"x", b"y"]));
        assert_ne!(
            a,
            mac(&code, b'd', &[b"xy", b""]),
            "a shifted boundary is a different message"
        );
    }

    /// Frozen pairing KAT, mirrored in `vectors/secsec-kat-v1.txt [pair]`: code `0x0c×12`.
    #[test]
    fn pairing_kat() {
        let hx = |b: &[u8; 32]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        let code = [0x0c; CODE_LEN];
        assert_eq!(
            hx(&slot(SLOT_D, &code)),
            "6422d073de3303a8087cbfefdf9065aa8460bc38405e89ec6c8b8b0267f3addc"
        );
        assert_eq!(
            hx(&slot(SLOT_E, &code)),
            "8d0f01e9f48a455625a0d192bfbcb54c97001c56ec8d71d60de5715554c54f47"
        );
        assert_eq!(
            hx(&mac(&code, b'd', &[b"d-pubkey", b"d-xwing"])),
            "b5363f3d7513006a59dab46549afac1bec86d3cf55d487647df69cc912953bc6"
        );
        assert_eq!(
            hx(&mac(&code, b'e', &[&[0x11; 32], &[0x22; 32]])),
            "3d0d17fd65bd2112ada81dc4c82115a29c85ac7d6df056322f328172f8381a6e"
        );
    }

    /// End to end over the in-process mailbox: the joiner is enrolled, learns the RFP, and each message is taken once.
    #[tokio::test]
    async fn pairing_enrolls_the_joiner() {
        let dir = tempfile::tempdir().unwrap();
        let r = MemRemote::new(Store::open(dir.path().join("r.redb")).unwrap());
        let host = DeviceKey::generate().unwrap();
        let joiner = DeviceKey::generate().unwrap();
        let rfp = init_repo_remote(&r, &host, 0).await.unwrap();
        let (code, _) = new_invite().unwrap();
        let pin = [0x42; 32];
        let (hosted, joined) = tokio::join!(
            run_host(&r, &host, &rfp, None, &pin, &code, 20, 0),
            run_join(&r, &joiner, &code, &pin, 20),
        );
        let (id, anchor) = hosted.unwrap();
        assert_eq!(id, joiner.device_id().unwrap());
        assert_eq!(anchor.max_seq, 1);
        assert_eq!(joined.unwrap(), rfp);
        let (_, st, _) = open_repo_remote(&r, &joiner, &rfp, None).await.unwrap();
        assert!(st.is_member(&id));
        assert!(r.pair_get(&slot(SLOT_E, &code)).await.unwrap().is_none());
        // A joiner connected to another server refuses the vouched pin.
        let (code2, _) = new_invite().unwrap();
        let other = DeviceKey::generate().unwrap();
        let (_, joined) = tokio::join!(
            run_host(&r, &host, &rfp, Some(anchor), &pin, &code2, 20, 0),
            run_join(&r, &other, &code2, &[0x43; 32], 20),
        );
        assert!(matches!(joined, Err(PairError::HostMismatch)));
    }
}
