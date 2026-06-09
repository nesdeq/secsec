//! The authenticated serve loop (`finaldesign.md` §11/§12): run the application handshake on a QUIC
//! connection, confirm the client is rostered (keyslot existence), then dispatch each per-op request
//! stream through [`Server::handle`].
//!
//! Per request stream: issue a fresh `server_nonce`, send it, read the [`AuthedRequest`], run the §12
//! pipeline, reply with the [`Response`]. The handshake binds the connection to one authenticated
//! key + transcript; every request reuses that transcript and a fresh single-use nonce.

use crate::{Incoming, Server};
use quinn::Connection;
use secsec_proto::wire::{AuthedRequest, Response};
use secsec_transport::frame::{read_frame, write_frame, MAX_FRAME_LEN};
use secsec_transport::handshake::{server_handshake, HandshakeError};

/// Errors from serving a connection.
#[derive(Debug)]
pub enum ServeError {
    /// The application handshake failed.
    Handshake(HandshakeError),
    /// The authenticated key owns no keyslot (§12).
    NotEnrolled,
    /// A store error while checking enrollment.
    Store(String),
    /// A framing/decode error on a request stream.
    Wire(String),
}

impl core::fmt::Display for ServeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServeError::Handshake(e) => write!(f, "handshake: {e}"),
            ServeError::NotEnrolled => f.write_str("connecting key is not enrolled"),
            ServeError::Store(e) => write!(f, "store: {e}"),
            ServeError::Wire(e) => write!(f, "wire: {e}"),
        }
    }
}
impl std::error::Error for ServeError {}
impl From<HandshakeError> for ServeError {
    fn from(e: HandshakeError) -> Self {
        ServeError::Handshake(e)
    }
}

fn random32() -> [u8; 32] {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n).expect("OS CSPRNG");
    n
}

/// Handshake the connection and serve its request streams until it closes. `host_id` is the server's
/// own `host_id`; `now` is the wall-clock (unix seconds) used for nonce TTLs and rate limits.
pub async fn serve_connection(
    conn: &Connection,
    server: &mut Server,
    host_id: [u8; 32],
    now: u64,
) -> Result<(), ServeError> {
    // §11 application handshake: authenticate the connecting key.
    let session = server_handshake(conn, host_id, random32()).await?;

    // §12 keyslot existence: the authenticated key must be rostered.
    let device_id = session
        .pubkey
        .device_id()
        .map_err(|e| ServeError::Store(e.to_string()))?;
    if !server
        .store()
        .keyslot_exists(&device_id)
        .map_err(|e| ServeError::Store(e.to_string()))?
    {
        return Err(ServeError::NotEnrolled);
    }

    // Request loop: one bidi stream per op.
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        // Consume the client's empty open-marker (it announces the stream so this `accept_bi` fired).
        if read_frame(&mut recv, 0).await.is_err() {
            break;
        }
        // Issue a fresh single-use per-op nonce and challenge the client with it.
        let nonce = random32();
        server.issue_nonce(nonce, now);
        write_frame(&mut send, &nonce)
            .await
            .map_err(|e| ServeError::Wire(e.to_string()))?;

        let bytes = read_frame(&mut recv, MAX_FRAME_LEN)
            .await
            .map_err(|e| ServeError::Wire(e.to_string()))?;
        let resp = match AuthedRequest::decode(&bytes) {
            Ok(ar) => server.handle(
                Incoming {
                    pubkey: &session.pubkey,
                    request: ar.request,
                    op_sig: ar.op_sig,
                    session_transcript: session.transcript,
                    server_nonce: Some(nonce),
                },
                now,
            ),
            Err(_) => Response::Err(secsec_proto::wire::ErrorCode::BadRequest),
        };

        write_frame(&mut send, &resp.encode())
            .await
            .map_err(|e| ServeError::Wire(e.to_string()))?;
        let _ = send.finish();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Server;
    use rcgen::generate_simple_self_signed;
    use secsec_proto::wire::{Request, Response};
    use secsec_sig::DeviceKey;
    use secsec_store::Store;
    use secsec_transport::handshake::client_handshake;
    use secsec_transport::quic::{client_config, server_config};
    use secsec_transport::rpc::request;
    use secsec_transport::HostPin;
    use std::net::{Ipv4Addr, SocketAddr};

    fn loopback() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    /// Full authenticated RPC: a pinned client connects, completes the §11 handshake, then issues an
    /// authorized `put` and `get` that the server runs through the §12 pipeline against its store.
    #[test]
    fn end_to_end_authenticated_put_and_get() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // server host key + a server over a temp store, with the client device enrolled.
            let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
            let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
            let pin = HostPin::from_cert(&cert).unwrap();
            let host_id = pin.host_id();

            let device = DeviceKey::generate().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(dir.path().join("s.redb")).unwrap();
            store
                .put_keyslot(&device.device_id().unwrap(), 1, b"keyslot")
                .unwrap(); // enroll
            let mut server = Server::new(store);

            let endpoint =
                quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = endpoint.local_addr().unwrap();

            let srv = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                // serve until the client closes (the loop ends on connection close).
                let _ = serve_connection(&conn, &mut server, host_id, 1_000).await;
            });

            // client connects + handshakes.
            let mut client = quinn::Endpoint::client(loopback()).unwrap();
            client.set_default_client_config(client_config(pin).unwrap());
            let conn = client
                .connect(addr, "secsec.invalid")
                .unwrap()
                .await
                .unwrap();
            let sess = client_handshake(&conn, &device, host_id, [0x11; 32])
                .await
                .unwrap();

            // authorized put.
            let id = [0x42; 32];
            let blob = b"end-to-end-bytes".to_vec();
            let put = Request::Put {
                id,
                declared_size: blob.len() as u32,
                blob: blob.clone(),
            };
            assert_eq!(
                request(&conn, sess.transcript, &device, put).await.unwrap(),
                Response::Ok
            );

            // authorized get returns the stored blob.
            let got = request(&conn, sess.transcript, &device, Request::Get { id })
                .await
                .unwrap();
            assert_eq!(got, Response::Blob(Some(blob)));

            // an absent id.
            let miss = request(
                &conn,
                sess.transcript,
                &device,
                Request::Get { id: [0x99; 32] },
            )
            .await
            .unwrap();
            assert_eq!(miss, Response::Blob(None));

            conn.close(0u32.into(), b"done");
            let _ = srv.await;
        });
    }
}
