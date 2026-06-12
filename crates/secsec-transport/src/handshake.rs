//! The §11 application-layer handshake on a control stream after the pinned TLS handshake:
//! ClientHello → ServerHello → both build the [`SessionTranscript`] and the TLS-exporter channel
//! binding → client sends `ClientAuth` (the `secsec-auth-v1` signature, [`ConnectionAuth`]) →
//! server verifies. Both sides return the transcript every later per-op request signs (§9.6); the
//! server also returns the authenticated client key (keyslot check is the caller's, §12).

use crate::auth::{ConnectionAuth, SessionTranscript, NONCE_LEN, SECSEC_VERSION};
use crate::frame::{read_frame, write_frame, FrameError, MAX_FRAME_LEN};
use quinn::Connection;
use secsec_proto::wire::{ClientAuth, ClientHello, ServerHello, WireError};
use secsec_sig::{DeviceKey, DevicePublic};

/// TLS exporter label for the channel binding (§11).
const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";
/// Channel-binding length, bytes (§11: 32).
const CHANNEL_BINDING_LEN: usize = 32;
/// The server's post-auth acknowledgement byte (sent only after the client is authenticated).
const AUTH_OK: u8 = 1;

/// Errors from the application-layer handshake.
#[derive(Debug)]
pub enum HandshakeError {
    /// Stream framing/I/O error.
    Frame(FrameError),
    /// A handshake message failed to decode.
    Wire(WireError),
    /// The server presented a `host_id` other than the one the client pinned.
    HostIdMismatch,
    /// The connection-auth signature did not verify (or the presented key was malformed).
    Auth,
    /// The TLS keying-material exporter was unavailable.
    Exporter,
    /// Opening/accepting the control stream failed.
    Stream(String),
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HandshakeError::Frame(e) => write!(f, "frame: {e}"),
            HandshakeError::Wire(e) => write!(f, "wire: {e}"),
            HandshakeError::HostIdMismatch => f.write_str("server host_id does not match the pin"),
            HandshakeError::Auth => f.write_str("connection auth failed"),
            HandshakeError::Exporter => f.write_str("TLS exporter unavailable"),
            HandshakeError::Stream(e) => write!(f, "stream: {e}"),
        }
    }
}
impl std::error::Error for HandshakeError {}
impl From<FrameError> for HandshakeError {
    fn from(e: FrameError) -> Self {
        HandshakeError::Frame(e)
    }
}
impl From<WireError> for HandshakeError {
    fn from(e: WireError) -> Self {
        HandshakeError::Wire(e)
    }
}

/// The client's post-handshake session: the transcript to bind into every per-op signature (§9.6).
pub struct ClientSession {
    /// The per-connection session transcript.
    pub transcript: [u8; 32],
}

/// The server's post-handshake session: the authenticated client key + the transcript.
pub struct ServerSession {
    /// The authenticated client public key (the caller must still confirm it owns a keyslot, §12).
    pub pubkey: DevicePublic,
    /// The per-connection session transcript.
    pub transcript: [u8; 32],
}

fn channel_binding(conn: &Connection) -> Result<[u8; CHANNEL_BINDING_LEN], HandshakeError> {
    let mut out = [0u8; CHANNEL_BINDING_LEN];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, b"")
        .map_err(|_| HandshakeError::Exporter)?;
    Ok(out)
}

/// Run the client side of the handshake. `host_id` is the client's **pinned** `host_id`
/// ([`crate::HostPin::host_id`]); `client_nonce` is freshly random.
pub async fn client_handshake(
    conn: &Connection,
    device: &DeviceKey,
    host_id: [u8; 32],
    client_nonce: [u8; NONCE_LEN],
) -> Result<ClientSession, HandshakeError> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| HandshakeError::Stream(e.to_string()))?;

    let hello = ClientHello {
        version: SECSEC_VERSION,
        client_nonce,
    };
    write_frame(&mut send, &hello.encode()).await?;

    let server_hello = ServerHello::decode(&read_frame(&mut recv, MAX_FRAME_LEN).await?)?;
    // Cross-check: the server must claim the host_id we already pinned (the TLS pin guaranteed it).
    if server_hello.host_id != host_id {
        return Err(HandshakeError::HostIdMismatch);
    }

    let mut transcript = SessionTranscript::new();
    transcript
        .client_hello(SECSEC_VERSION, &client_nonce)
        .server_hello(SECSEC_VERSION, &server_hello.server_nonce, &host_id);
    let transcript = transcript.finalize();

    let cb = channel_binding(conn)?;
    let ctx = ConnectionAuth {
        channel_binding: &cb,
        host_id,
        session_transcript: transcript,
        server_nonce: server_hello.server_nonce,
    };
    let sig = ctx.sign(device).map_err(|_| HandshakeError::Auth)?;
    let pubkey = device
        .public()
        .to_canonical()
        .map_err(|_| HandshakeError::Auth)?;
    write_frame(&mut send, &ClientAuth { pubkey, sig }.encode()).await?;
    let _ = send.finish();

    // Wait for the server's acknowledgement: it is sent only after auth succeeds, so its receipt
    // confirms we are authenticated (and keeps the connection up until the server has processed).
    let ack = read_frame(&mut recv, 1).await?;
    if ack.as_slice() != [AUTH_OK] {
        return Err(HandshakeError::Auth);
    }

    Ok(ClientSession { transcript })
}

/// Run the server side of the handshake. `host_id` is the server's own `host_id`; `server_nonce` is
/// freshly random. Returns the authenticated client key; the caller MUST then check keyslot
/// existence (§12) before honouring requests.
pub async fn server_handshake(
    conn: &Connection,
    host_id: [u8; 32],
    server_nonce: [u8; NONCE_LEN],
) -> Result<ServerSession, HandshakeError> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| HandshakeError::Stream(e.to_string()))?;

    let client_hello = ClientHello::decode(&read_frame(&mut recv, MAX_FRAME_LEN).await?)?;
    let server_hello = ServerHello {
        version: SECSEC_VERSION,
        server_nonce,
        host_id,
    };
    write_frame(&mut send, &server_hello.encode()).await?;

    let mut transcript = SessionTranscript::new();
    transcript
        .client_hello(SECSEC_VERSION, &client_hello.client_nonce)
        .server_hello(SECSEC_VERSION, &server_nonce, &host_id);
    let transcript = transcript.finalize();

    let cb = channel_binding(conn)?;
    let client_auth = ClientAuth::decode(&read_frame(&mut recv, MAX_FRAME_LEN).await?)?;
    let pubkey =
        DevicePublic::from_canonical(&client_auth.pubkey).map_err(|_| HandshakeError::Auth)?;
    let ctx = ConnectionAuth {
        channel_binding: &cb,
        host_id,
        session_transcript: transcript,
        server_nonce,
    };
    ctx.verify(&pubkey, &client_auth.sig)
        .map_err(|_| HandshakeError::Auth)?;

    // Acknowledge: only sent on success, so the client learns it is authenticated.
    write_frame(&mut send, &[AUTH_OK]).await?;
    let _ = send.finish();

    Ok(ServerSession { pubkey, transcript })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{client_config, server_config};
    use crate::HostPin;
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use std::net::{Ipv4Addr, SocketAddr};

    fn loopback() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Full handshake over a live pinned QUIC connection: the server authenticates the client and
    /// the two ends agree on the transcript; an enrolled, correctly-signing client succeeds.
    #[test]
    fn handshake_authenticates_the_client() {
        runtime().block_on(async {
            let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
            let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
            let pin = HostPin::from_cert(&cert).unwrap();
            let host_id = pin.host_id();

            let device = DeviceKey::generate().unwrap();
            let device_pub_id = device.device_id().unwrap();

            let server = Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = server.local_addr().unwrap();

            let srv = tokio::spawn(async move {
                let conn = server.accept().await.unwrap().await.unwrap();
                let sess = match server_handshake(&conn, host_id, [0xAB; 32]).await {
                    Ok(s) => s,
                    Err(e) => panic!("server handshake: {e}"),
                };
                conn.closed().await;
                (sess.pubkey.device_id().unwrap(), sess.transcript)
            });

            let mut client = Endpoint::client(loopback()).unwrap();
            client.set_default_client_config(client_config(pin).unwrap());
            let conn = client
                .connect(addr, "secsec.invalid")
                .unwrap()
                .await
                .unwrap();
            let csess = match client_handshake(&conn, &device, host_id, [0xCD; 32]).await {
                Ok(s) => s,
                Err(e) => panic!("client handshake: {e}"),
            };
            conn.close(0u32.into(), b"done");

            let (srv_pubid, srv_transcript) = srv.await.unwrap();
            // the server authenticated *this* client key, and both derived the same transcript.
            assert_eq!(srv_pubid, device_pub_id);
            assert_eq!(srv_transcript, csess.transcript);
        });
    }
}
