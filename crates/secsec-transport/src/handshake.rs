//! The §11 application handshake after pinned TLS: hellos → transcript + exporter binding → `ClientAuth` → server verifies.

use crate::auth::{ConnectionAuth, SessionTranscript, NONCE_LEN, SECSEC_VERSION};
use crate::frame::{read_frame, write_frame, FrameError};
use quinn::Connection;
use secsec_proto::wire::{ClientAuth, ClientHello, ServerHello, WireError};
use secsec_sig::{DeviceKey, DevicePublic};

/// TLS exporter label for the channel binding (§11).
const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";
/// Channel-binding length, bytes (§11).
const CHANNEL_BINDING_LEN: usize = 32;
/// The server's post-auth acknowledgement byte.
const AUTH_OK: u8 = 1;

/// Errors from the application handshake.
#[derive(Debug)]
pub enum HandshakeError {
    /// Stream framing/I/O error.
    Frame(FrameError),
    /// A handshake message failed to decode.
    Wire(WireError),
    /// The server presented a `host_id` other than the pin.
    HostIdMismatch,
    /// The peer speaks another `secsec_version`; fatal, named so the cause is clear.
    VersionMismatch {
        /// This build's version.
        ours: u16,
        /// The peer's version.
        theirs: u16,
    },
    /// The connection-auth signature did not verify (or the key was malformed).
    Auth,
    /// The TLS exporter was unavailable.
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
            HandshakeError::VersionMismatch { ours, theirs } => {
                write!(
                    f,
                    "peer speaks secsec_version {theirs}, this build speaks {ours}"
                )
            }
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

/// The client's post-handshake session: the transcript every per-op signature binds (§9.6).
pub struct ClientSession {
    /// The per-connection session transcript.
    pub transcript: [u8; 32],
}

/// The server's post-handshake session: the authenticated key and the transcript.
pub struct ServerSession {
    /// The authenticated client public key (keyslot checks are per op, §12).
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

/// Client side: `host_id` is the locally pinned value, `client_nonce` fresh random.
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

    let server_hello = ServerHello::decode(&read_frame(&mut recv, ServerHello::LEN).await?)?;
    if server_hello.version != SECSEC_VERSION {
        return Err(HandshakeError::VersionMismatch {
            ours: SECSEC_VERSION,
            theirs: server_hello.version,
        });
    }
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

    // The acknowledgement is sent only after auth succeeds.
    let ack = read_frame(&mut recv, 1).await?;
    if ack.as_slice() != [AUTH_OK] {
        return Err(HandshakeError::Auth);
    }
    Ok(ClientSession { transcript })
}

/// Server side: every read is capped at its message's size bound; the caller bounds the whole call in time.
pub async fn server_handshake(
    conn: &Connection,
    host_id: [u8; 32],
    server_nonce: [u8; NONCE_LEN],
) -> Result<ServerSession, HandshakeError> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| HandshakeError::Stream(e.to_string()))?;

    let client_hello = ClientHello::decode(&read_frame(&mut recv, ClientHello::LEN).await?)?;
    if client_hello.version != SECSEC_VERSION {
        return Err(HandshakeError::VersionMismatch {
            ours: SECSEC_VERSION,
            theirs: client_hello.version,
        });
    }
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
    let client_auth = ClientAuth::decode(&read_frame(&mut recv, ClientAuth::MAX_LEN).await?)?;
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

    /// Over live pinned QUIC the server authenticates the client and both agree on the transcript.
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
            assert_eq!(srv_pubid, device_pub_id);
            assert_eq!(srv_transcript, csess.transcript);
        });
    }

    /// A client hello longer than its fixed size is refused before any allocation for it.
    #[test]
    fn oversized_hello_is_refused() {
        runtime().block_on(async {
            let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
            let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
            let pin = HostPin::from_cert(&cert).unwrap();
            let host_id = pin.host_id();
            let server = Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = server.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                let conn = server.accept().await.unwrap().await.unwrap();
                server_handshake(&conn, host_id, [0xAB; 32]).await.err()
            });
            let mut client = Endpoint::client(loopback()).unwrap();
            client.set_default_client_config(client_config(pin).unwrap());
            let conn = client
                .connect(addr, "secsec.invalid")
                .unwrap()
                .await
                .unwrap();
            let (mut send, _recv) = conn.open_bi().await.unwrap();
            write_frame(&mut send, &[0u8; ClientHello::LEN + 1])
                .await
                .unwrap();
            let err = srv.await.unwrap();
            assert!(matches!(
                err,
                Some(HandshakeError::Frame(FrameError::TooLarge(_)))
            ));
            conn.close(0u32.into(), b"done");
        });
    }
}
