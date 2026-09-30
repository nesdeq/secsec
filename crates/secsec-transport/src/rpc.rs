//! Client per-op RPC (`secsec-Design.md` §12): one bidi stream per request, signed against the stream's server nonce.

use crate::auth::NONCE_LEN;
use crate::frame::{read_frame, write_frame, FrameError};
use quinn::Connection;
use secsec_proto::wire::{AuthedRequest, Request, Response, WireError, MAX_RESPONSE_LEN};
use secsec_proto::{op_and_args, ReadAuth, WriteAuth};
use secsec_sig::{DeviceKey, SigError};

/// Errors from a client RPC.
#[derive(Debug)]
pub enum RpcError {
    /// Stream framing/I/O error.
    Frame(FrameError),
    /// The request failed its write-side bounds, or the response failed to decode.
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

/// Issue one authorized request on a fresh stream; the request is bounds-checked before anything is sent.
pub async fn request(
    conn: &Connection,
    transcript: [u8; 32],
    device: &DeviceKey,
    request: Request,
) -> Result<Response, RpcError> {
    request.validate()?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| RpcError::Stream(e.to_string()))?;

    // A bidi stream is not announced until the opener writes; the empty frame lets the server challenge us.
    write_frame(&mut send, &[]).await?;

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
    } else {
        ReadAuth {
            op: op_label,
            args_hash,
            session_transcript: transcript,
        }
        .sign(device)
    }
    .map_err(|e| match e {
        secsec_proto::ProtoError::Sig(e) => RpcError::Sig(e),
        secsec_proto::ProtoError::BadSignature => RpcError::BadNonce,
    })?;

    write_frame(&mut send, &AuthedRequest { op_sig, request }.encode()).await?;
    let _ = send.finish();
    Ok(Response::decode(
        &read_frame(&mut recv, MAX_RESPONSE_LEN).await?,
    )?)
}
