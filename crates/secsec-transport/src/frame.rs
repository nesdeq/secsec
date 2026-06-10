//! Length-prefixed message framing over QUIC streams (`secsec-Design.md` §11/§12). Each protocol
//! message (handshake hello, RPC request/response) is sent as `le32(len) ‖ payload` on a stream, with
//! the length bounded by [`MAX_FRAME_LEN`] **before allocation** (alloc-bomb guard, §9.1/§19).

use quinn::{RecvStream, SendStream};
use secsec_frame::MAX_BLOB_SIZE;

/// Maximum framed payload: a 16 MiB object blob (§19) plus modest protocol-envelope overhead.
pub const MAX_FRAME_LEN: usize = MAX_BLOB_SIZE + 4096;

/// Errors reading/writing a stream frame.
#[derive(Debug)]
pub enum FrameError {
    /// The frame's declared length exceeded the caller's maximum (or `u32`).
    TooLarge(usize),
    /// The stream ended before a full frame was read.
    Truncated,
    /// Underlying QUIC stream I/O error.
    Io(String),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::TooLarge(n) => write!(f, "frame length {n} exceeds maximum"),
            FrameError::Truncated => f.write_str("stream ended mid-frame"),
            FrameError::Io(e) => write!(f, "stream io: {e}"),
        }
    }
}
impl std::error::Error for FrameError {}

/// Write one length-prefixed frame: `le32(len) ‖ payload`.
pub async fn write_frame(send: &mut SendStream, payload: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(payload.len()))?;
    send.write_all(&len.to_le_bytes())
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    send.write_all(payload)
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    Ok(())
}

/// Read one length-prefixed frame, rejecting any declared length greater than `max` **before**
/// allocating the body.
pub async fn read_frame(recv: &mut RecvStream, max: usize) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    read_exact(recv, &mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    read_exact(recv, &mut buf).await?;
    Ok(buf)
}

async fn read_exact(recv: &mut RecvStream, buf: &mut [u8]) -> Result<(), FrameError> {
    recv.read_exact(buf).await.map_err(|e| match e {
        quinn::ReadExactError::FinishedEarly(_) => FrameError::Truncated,
        quinn::ReadExactError::ReadError(e) => FrameError::Io(e.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{client_config, server_config};
    use crate::HostPin;
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use secsec_proto::wire::{ErrorCode, Request, Response};
    use std::net::{Ipv4Addr, SocketAddr};

    fn loopback() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    /// End-to-end over a live QUIC connection: the client sends a framed `Request`, the server reads
    /// then decodes it, replies with a framed `Response`, and the client decodes that — proving the
    /// wire model flows through the real transport with framing.
    #[test]
    fn framed_request_response_over_quic() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
            let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
            let pin = HostPin::from_cert(&cert).unwrap();

            let server = Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = server.local_addr().unwrap();

            // server: accept, read a framed request, reply with a framed response.
            let srv = tokio::spawn(async move {
                let conn = server.accept().await.unwrap().await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                let req_bytes = read_frame(&mut recv, MAX_FRAME_LEN).await.unwrap();
                let req = Request::decode(&req_bytes).unwrap();
                // reply Ok to a Put, NotEnrolled otherwise (just to exercise both directions).
                let resp = match req {
                    Request::Put { .. } => Response::Ok,
                    _ => Response::Err(ErrorCode::NotEnrolled),
                };
                write_frame(&mut send, &resp.encode()).await.unwrap();
                send.finish().unwrap();
                conn.closed().await;
                req
            });

            let mut client = Endpoint::client(loopback()).unwrap();
            client.set_default_client_config(client_config(pin).unwrap());
            let conn = client
                .connect(addr, "secsec.invalid")
                .unwrap()
                .await
                .unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();

            let request = Request::Put {
                id: [0x11; 32],
                declared_size: 5,
                blob: b"hello".to_vec(),
            };
            write_frame(&mut send, &request.encode()).await.unwrap();
            send.finish().unwrap();
            let resp_bytes = read_frame(&mut recv, MAX_FRAME_LEN).await.unwrap();
            assert_eq!(Response::decode(&resp_bytes).unwrap(), Response::Ok);
            conn.close(0u32.into(), b"done");

            // the server decoded exactly what we sent.
            assert_eq!(srv.await.unwrap(), request);
        });
    }
}
