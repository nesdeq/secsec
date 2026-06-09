//! Client-side per-op RPC over a handshaken QUIC connection (`finaldesign.md` §12). Each request is
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

    let (op_label, args_hash, is_write) = op_and_args(&request);
    let op_sig = if is_write {
        WriteAuth {
            op: op_label,
            args_hash,
            session_transcript: transcript,
            server_nonce: nonce,
        }
        .sign(device)
        .map_err(map_proto_sig)?
    } else {
        ReadAuth {
            op: op_label,
            args_hash,
            session_transcript: transcript,
        }
        .sign(device)
        .map_err(map_proto_sig)?
    };

    write_frame(&mut send, &AuthedRequest { op_sig, request }.encode()).await?;
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
