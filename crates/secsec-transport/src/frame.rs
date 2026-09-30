//! Length-prefixed message framing on QUIC streams (`secsec-Design.md` §11/§12): `le32(len) ‖ payload`, bounded, allocated as it arrives.

use quinn::{RecvStream, SendStream};

/// Errors reading/writing a stream frame.
#[derive(Debug)]
pub enum FrameError {
    /// The declared length exceeded the caller's maximum (or `u32`).
    TooLarge(usize),
    /// The stream ended before a full frame arrived.
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

/// Write one frame `le32(len) ‖ payload`.
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

/// Read one frame, rejecting a declared length over `max`; memory grows only with bytes actually received.
pub async fn read_frame(recv: &mut RecvStream, max: usize) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(|e| match e {
        quinn::ReadExactError::FinishedEarly(_) => FrameError::Truncated,
        quinn::ReadExactError::ReadError(e) => FrameError::Io(e.to_string()),
    })?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = Vec::new();
    while buf.len() < len {
        match recv
            .read_chunk(len - buf.len(), true)
            .await
            .map_err(|e| FrameError::Io(e.to_string()))?
        {
            Some(chunk) => buf.extend_from_slice(&chunk.bytes),
            None => return Err(FrameError::Truncated),
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{client_config, server_config};
    use crate::HostPin;
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use secsec_proto::wire::{ErrorCode, Request, Response, MAX_REQUEST_LEN};
    use std::net::{Ipv4Addr, SocketAddr};

    fn loopback() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    /// A framed request and response flow through a live QUIC connection; an over-cap length and a short body are refused.
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

            let srv = tokio::spawn(async move {
                let conn = server.accept().await.unwrap().await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                let req = Request::decode(&read_frame(&mut recv, MAX_REQUEST_LEN).await.unwrap())
                    .unwrap();
                let resp = match req {
                    Request::Put { .. } => Response::Ok,
                    _ => Response::Err(ErrorCode::NotEnrolled),
                };
                write_frame(&mut send, &resp.encode()).await.unwrap();
                send.finish().unwrap();
                // A frame declaring more than the cap is refused before its body arrives.
                let (_s2, mut r2) = conn.accept_bi().await.unwrap();
                let big = read_frame(&mut r2, 8).await;
                // A frame whose body ends early is truncated, not padded.
                let (_s3, mut r3) = conn.accept_bi().await.unwrap();
                let short = read_frame(&mut r3, 64).await;
                (req, big, short)
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
                push_id: [0x22; 16],
                blob: b"hello".to_vec(),
            };
            write_frame(&mut send, &request.encode()).await.unwrap();
            send.finish().unwrap();
            let resp = Response::decode(&read_frame(&mut recv, 1024).await.unwrap()).unwrap();
            assert_eq!(resp, Response::Ok);

            let (mut s2, _r2) = conn.open_bi().await.unwrap();
            s2.write_all(&1_000_000u32.to_le_bytes()).await.unwrap();
            s2.finish().unwrap();
            let (mut s3, _r3) = conn.open_bi().await.unwrap();
            s3.write_all(&10u32.to_le_bytes()).await.unwrap();
            s3.write_all(b"abc").await.unwrap();
            s3.finish().unwrap();

            let (got, big, short) = srv.await.unwrap();
            conn.close(0u32.into(), b"done");
            assert_eq!(got, request);
            assert!(matches!(big, Err(FrameError::TooLarge(1_000_000))));
            assert!(matches!(short, Err(FrameError::Truncated)));
        });
    }
}
