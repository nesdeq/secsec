//! Client-side per-op RPC over a handshaken QUIC connection (`secsec-Design.md` §12). Each request is
//! one bidirectional stream: the server sends a fresh per-op `server_nonce`, the client signs the
//! `secsec-write-v1` / `secsec-read-v1` authorization over the recomputed `args_hash` + the session
//! transcript (+ the nonce, for writes), sends the [`AuthedRequest`], and reads the [`Response`].

use crate::auth::NONCE_LEN;
use crate::frame::{read_frame, write_frame, FrameError, MAX_FRAME_LEN};
use quinn::Connection;
use secsec_proto::wire::{AuthedRequest, Request, Response, WireError};
use secsec_proto::{op_and_args, ReadAuth, WriteAuth};
use secsec_sig::{DeviceKey, SigError};

/// Errors from a client RPC.
#[derive(Debug)]
pub enum RpcError {
    /// Stream framing/I/O error.
    Frame(FrameError),
    /// A response failed to decode.
    Wire(WireError),
    /// The server's per-op nonce frame was malformed.
    BadNonce,
    /// Signing failed.
    Sig(SigError),
    /// Opening the request stream failed.
    Stream(String),
}

impl core::fmt::Display for RpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RpcError::Frame(e) => write!(f, "frame: {e}"),
            RpcError::Wire(e) => write!(f, "wire: {e}"),
            RpcError::BadNonce => f.write_str("malformed per-op nonce"),
            RpcError::Sig(e) => write!(f, "sig: {e}"),
            RpcError::Stream(e) => write!(f, "stream: {e}"),
        }
    }
}
impl std::error::Error for RpcError {}
impl From<FrameError> for RpcError {
    fn from(e: FrameError) -> Self {
        RpcError::Frame(e)
    }
}
impl From<WireError> for RpcError {
    fn from(e: WireError) -> Self {
        RpcError::Wire(e)
    }
}
impl From<SigError> for RpcError {
    fn from(e: SigError) -> Self {
        RpcError::Sig(e)
    }
}

/// Issue one authorized request on a fresh stream and return the server's response. `transcript` is
/// the per-connection session transcript from the handshake; `device` signs the per-op authorization.
pub async fn request(
    conn: &Connection,
    transcript: [u8; 32],
    device: &DeviceKey,
    request: Request,
) -> Result<Response, RpcError> {
    // `op_sig` is built from the recomputed `args_hash` (so the client can't lie about what it
    // signed). prune has a state-bound args_hash and uses `request_prune` instead.
    send_authed(conn, &request, |nonce| {
        let (op_label, args_hash, is_write) = op_and_args(&request);
        if is_write {
            WriteAuth {
                op: op_label,
                args_hash,
                session_transcript: transcript,
                server_nonce: nonce,
            }
            .sign(device)
            .map_err(map_proto_sig)
        } else {
            ReadAuth {
                op: op_label,
                args_hash,
                session_transcript: transcript,
            }
            .sign(device)
            .map_err(map_proto_sig)
        }
    })
    .await
}

/// Issue a §5 retention `prune` request: its `args_hash` binds the client's view of the server's
/// mutable head/roster state (`all_heads_hash`/`roster_seq` — the §5 head-binding CAS), so it signs
/// the full `args_prune` rather than the generic `op_and_args` binding.
pub async fn request_prune(
    conn: &Connection,
    transcript: [u8; 32],
    device: &DeviceKey,
    dead: Vec<[u8; 32]>,
    all_heads_hash: &[u8; 32],
    roster_seq: u64,
) -> Result<Response, RpcError> {
    let args_hash = secsec_proto::prune::args_prune(
        &secsec_proto::prune::dead_set_hash(&dead),
        all_heads_hash,
        roster_seq,
    );
    let req = Request::Prune {
        dead,
        all_heads_hash: *all_heads_hash,
        roster_seq,
    };
    send_authed(conn, &req, |nonce| {
        WriteAuth {
            op: secsec_proto::op::PRUNE,
            args_hash,
            session_transcript: transcript,
            server_nonce: nonce,
        }
        .sign(device)
        .map_err(map_proto_sig)
    })
    .await
}

/// The shared per-op stream dance: open a bidi stream, read the server's fresh per-op nonce, build the
/// `op_sig` via `sign` (given the nonce), send the [`AuthedRequest`], read the [`Response`].
async fn send_authed<F>(conn: &Connection, request: &Request, sign: F) -> Result<Response, RpcError>
where
    F: FnOnce([u8; NONCE_LEN]) -> Result<Vec<u8>, RpcError>,
{
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| RpcError::Stream(e.to_string()))?;

    // A QUIC bidi stream is not announced to the peer until the opener writes; send an empty
    // open-marker frame so the server's `accept_bi` fires before it tries to challenge us.
    write_frame(&mut send, &[]).await?;

    // The server's fresh per-op nonce (used by writes; reads ignore it).
    let nonce: [u8; NONCE_LEN] = read_frame(&mut recv, NONCE_LEN)
        .await?
        .try_into()
        .map_err(|_| RpcError::BadNonce)?;

    let op_sig = sign(nonce)?;
    write_frame(
        &mut send,
        &AuthedRequest {
            op_sig,
            request: request.clone(),
        }
        .encode(),
    )
    .await?;
    let _ = send.finish();

    let resp = Response::decode(&read_frame(&mut recv, MAX_FRAME_LEN).await?)?;
    Ok(resp)
}

/// `secsec_proto::ProtoError` only wraps a `SigError` here (the sign path), so unwrap it back.
fn map_proto_sig(e: secsec_proto::ProtoError) -> RpcError {
    match e {
        secsec_proto::ProtoError::Sig(e) => RpcError::Sig(e),
        secsec_proto::ProtoError::BadSignature => RpcError::BadNonce, // unreachable on sign
    }
}
