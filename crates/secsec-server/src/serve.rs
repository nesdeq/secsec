//! The authenticated serve loop (`secsec-Design.md` §11, §12): a time-bounded handshake, then each request stream through [`Server::handle`].

use crate::{Incoming, IssuedNonce, Server};
use quinn::Connection;
use secsec_proto::server::limits::SERVER_NONCE_TTL_SECS;
use secsec_proto::wire::{
    AuthedRequest, ErrorCode, Response, WireError, MAX_AUTHED_LEN, MAX_UNENROLLED_AUTHED_LEN,
};
use secsec_transport::frame::{read_frame, write_frame, FrameError};
use secsec_transport::handshake::{server_handshake, HandshakeError};
use std::sync::Arc;
use std::time::Duration;

/// Errors from serving a connection.
#[derive(Debug)]
pub enum ServeError {
    /// The application handshake failed.
    Handshake(HandshakeError),
    /// The handshake did not finish inside its deadline.
    HandshakeTimeout,
    /// The authenticated key is not (or no longer) in `authorized_keys`.
    NotAuthorized,
    /// The authenticated key already holds the maximum concurrent connections (§19).
    TooManyConnections,
    /// The authenticated public key has no device id.
    Key(String),
    /// The OS CSPRNG failed.
    Rng,
    /// A framing error on a request stream.
    Wire(String),
}

impl core::fmt::Display for ServeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServeError::Handshake(e) => write!(f, "handshake: {e}"),
            ServeError::HandshakeTimeout => f.write_str("handshake timed out"),
            ServeError::NotAuthorized => f.write_str("connecting key is not in authorized_keys"),
            ServeError::TooManyConnections => {
                f.write_str("too many concurrent connections for this key")
            }
            ServeError::Key(e) => write!(f, "key: {e}"),
            ServeError::Rng => f.write_str("OS CSPRNG failure"),
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

/// A per-key concurrent-connection slot (§19), released when the connection task ends however it ends.
struct ConnGuard<'a> {
    server: &'a Server,
    device_id: secsec_sig::DeviceId,
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        self.server.release_conn(self.device_id);
    }
}

fn random32() -> Result<[u8; 32], ServeError> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n).map_err(|_| ServeError::Rng)?;
    Ok(n)
}

fn wire(e: FrameError) -> ServeError {
    ServeError::Wire(e.to_string())
}

/// Serve one connection until it closes: handshake within `handshake_deadline`, then requests; `now` is unix seconds.
pub async fn serve_connection<F>(
    conn: &Connection,
    server: Arc<Server>,
    host_id: [u8; 32],
    handshake_deadline: Duration,
    now: F,
) -> Result<(), ServeError>
where
    F: Fn() -> u64,
{
    let session = tokio::time::timeout(
        handshake_deadline,
        server_handshake(conn, host_id, random32()?),
    )
    .await
    .map_err(|_| ServeError::HandshakeTimeout)??;
    let device_id = session
        .pubkey
        .device_id()
        .map_err(|e| ServeError::Key(e.to_string()))?;
    if !server.is_authorized(&device_id) {
        return Err(ServeError::NotAuthorized);
    }
    if !server.acquire_conn(device_id) {
        return Err(ServeError::TooManyConnections);
    }
    let _guard = ConnGuard {
        server: &server,
        device_id,
    };

    // Membership is per op in `Server::handle`, so an authorized joiner can still reach the §7 mailbox.
    let mut authorized_at = now();
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let t = now();
        if t.saturating_sub(authorized_at) >= SERVER_NONCE_TTL_SECS {
            if !server.is_authorized(&device_id) {
                conn.close(0u32.into(), b"unauthorized");
                return Err(ServeError::NotAuthorized);
            }
            authorized_at = t;
        }
        // The client's empty open-marker announces the stream; the reply is this stream's challenge.
        read_frame(&mut recv, 0).await.map_err(wire)?;
        let issued = IssuedNonce {
            nonce: random32()?,
            issued_at: now(),
        };
        write_frame(&mut send, &issued.nonce).await.map_err(wire)?;

        let enrolled = server.is_enrolled(&device_id).unwrap_or(false);
        let cap = if enrolled {
            MAX_AUTHED_LEN
        } else {
            MAX_UNENROLLED_AUTHED_LEN
        };
        let resp = match read_frame(&mut recv, cap).await {
            Ok(bytes) => match AuthedRequest::decode(&bytes) {
                Ok(ar) => {
                    let server = server.clone();
                    let pubkey = session.pubkey.clone();
                    let transcript = session.transcript;
                    let t = now();
                    tokio::task::spawn_blocking(move || {
                        server.handle(
                            Incoming {
                                pubkey: &pubkey,
                                request: ar.request,
                                op_sig: ar.op_sig,
                                session_transcript: transcript,
                                server_nonce: Some(issued),
                            },
                            t,
                        )
                    })
                    .await
                    .unwrap_or(Response::Err(ErrorCode::Internal))
                }
                Err(WireError::TooLarge) => Response::Err(ErrorCode::TooManyIds),
                Err(_) => Response::Err(ErrorCode::BadRequest),
            },
            // An over-cap frame is refused unread; an unenrolled key is told why.
            Err(FrameError::TooLarge(_)) => {
                let _ = recv.stop(0u32.into());
                Response::Err(if enrolled {
                    ErrorCode::BadRequest
                } else {
                    ErrorCode::NotEnrolled
                })
            }
            Err(e) => return Err(wire(e)),
        };
        write_frame(&mut send, &resp.encode()).await.map_err(wire)?;
        let _ = send.finish();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use secsec_proto::wire::Request;
    use secsec_sig::DeviceKey;
    use secsec_store::Store;
    use secsec_transport::handshake::client_handshake;
    use secsec_transport::quic::{client_config, server_config};
    use secsec_transport::rpc::request;
    use secsec_transport::HostPin;
    use std::net::{Ipv4Addr, SocketAddr};

    const DEADLINE: Duration = Duration::from_secs(30);

    fn loopback() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    /// A server over a temp store with `devices` enrolled, accepting connections until the test ends.
    fn spawn_server(devices: &[&DeviceKey]) -> (SocketAddr, HostPin, tempfile::TempDir) {
        let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
        let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
        let pin = HostPin::from_cert(&cert).unwrap();
        let host_id = pin.host_id();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("s.redb")).unwrap();
        for d in devices {
            store
                .put_keyslot(&d.device_id().unwrap(), 1, b"keyslot")
                .unwrap();
        }
        let server = Arc::new(Server::new(store));
        let endpoint =
            quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let server = server.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        let _ = serve_connection(&conn, server, host_id, DEADLINE, || 1_000).await;
                    }
                });
            }
        });
        (addr, pin, dir)
    }

    async fn connect(
        addr: SocketAddr,
        pin: &HostPin,
        dev: &DeviceKey,
        cn: u8,
    ) -> (quinn::Endpoint, quinn::Connection, [u8; 32]) {
        let mut ep = quinn::Endpoint::client(loopback()).unwrap();
        ep.set_default_client_config(client_config(pin.clone()).unwrap());
        let conn = ep.connect(addr, "secsec.invalid").unwrap().await.unwrap();
        let t = client_handshake(&conn, dev, pin.host_id(), [cn; 32])
            .await
            .unwrap()
            .transcript;
        (ep, conn, t)
    }

    fn put(id: [u8; 32], blob: &[u8], push: [u8; 16]) -> Request {
        Request::Put {
            id,
            declared_size: blob.len() as u32,
            push_id: push,
            blob: blob.to_vec(),
        }
    }

    fn cas(ref_h: [u8; 32], blob: &[u8], push: [u8; 16]) -> Request {
        Request::CasHead {
            ref_h,
            old_head: [0u8; 32],
            new_head: *blake3::hash(blob).as_bytes(),
            promote: push,
            new_blob: blob.to_vec(),
        }
    }

    /// A pinned client handshakes, then a put is invisible until its cas-head promotes it.
    #[test]
    fn end_to_end_authenticated_put_and_get() {
        runtime().block_on(async {
            let device = DeviceKey::generate().unwrap();
            let (addr, pin, _dir) = spawn_server(&[&device]);
            let (_ep, conn, t) = connect(addr, &pin, &device, 0x11).await;
            let id = [0x42; 32];
            let push = [0x55; 16];
            assert_eq!(
                request(&conn, t, &device, put(id, b"end-to-end", push))
                    .await
                    .unwrap(),
                Response::Ok
            );
            assert_eq!(
                request(&conn, t, &device, Request::Get { id })
                    .await
                    .unwrap(),
                Response::Blob(None)
            );
            assert_eq!(
                request(&conn, t, &device, cas([0x66; 32], b"head", push))
                    .await
                    .unwrap(),
                Response::Ok
            );
            assert_eq!(
                request(&conn, t, &device, Request::Get { id })
                    .await
                    .unwrap(),
                Response::Blob(Some(b"end-to-end".to_vec()))
            );
            conn.close(0u32.into(), b"done");
        });
    }

    /// An idle connection never blocks another client.
    #[test]
    fn serves_two_clients_concurrently() {
        runtime().block_on(async {
            let dev_a = DeviceKey::generate().unwrap();
            let dev_b = DeviceKey::generate().unwrap();
            let (addr, pin, _dir) = spawn_server(&[&dev_a, &dev_b]);
            let (_ea, conn_a, _ta) = connect(addr, &pin, &dev_a, 0x01).await;
            let (_eb, conn_b, tb) = connect(addr, &pin, &dev_b, 0x02).await;
            let id = [0x77; 32];
            let push = [0x88; 16];
            assert_eq!(
                request(&conn_b, tb, &dev_b, put(id, b"concurrent", push))
                    .await
                    .unwrap(),
                Response::Ok
            );
            assert_eq!(
                request(&conn_b, tb, &dev_b, cas([0x99; 32], b"h", push))
                    .await
                    .unwrap(),
                Response::Ok
            );
            assert_eq!(
                request(&conn_b, tb, &dev_b, Request::Get { id })
                    .await
                    .unwrap(),
                Response::Blob(Some(b"concurrent".to_vec()))
            );
            conn_a.close(0u32.into(), b"done");
            conn_b.close(0u32.into(), b"done");
        });
    }

    /// Two clients racing cas-head on one absent ref: exactly one wins.
    #[test]
    fn two_clients_racing_cas_head_one_wins() {
        runtime().block_on(async {
            let dev_a = DeviceKey::generate().unwrap();
            let dev_b = DeviceKey::generate().unwrap();
            let (addr, pin, _dir) = spawn_server(&[&dev_a, &dev_b]);
            let (_ea, conn_a, ta) = connect(addr, &pin, &dev_a, 0x01).await;
            let (_eb, conn_b, tb) = connect(addr, &pin, &dev_b, 0x02).await;
            let (ra, rb) = tokio::join!(
                request(
                    &conn_a,
                    ta,
                    &dev_a,
                    cas([0x55; 32], b"head-from-A", [0; 16])
                ),
                request(
                    &conn_b,
                    tb,
                    &dev_b,
                    cas([0x55; 32], b"head-from-B", [0; 16])
                ),
            );
            let mut got = [ra.unwrap(), rb.unwrap()];
            got.sort_by_key(|r| r.encode());
            assert_eq!(
                got,
                [Response::Ok, Response::Err(ErrorCode::CasConflict)],
                "exactly one racing writer wins"
            );
            conn_a.close(0u32.into(), b"done");
            conn_b.close(0u32.into(), b"done");
        });
    }

    /// An unenrolled key's frame above the unenrolled cap is refused unread with NotEnrolled.
    #[test]
    fn unenrolled_key_is_capped_before_reading() {
        runtime().block_on(async {
            let stranger = DeviceKey::generate().unwrap();
            let (addr, pin, _dir) = spawn_server(&[]);
            let (_ep, conn, t) = connect(addr, &pin, &stranger, 0x33).await;
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            write_frame(&mut send, &[]).await.unwrap();
            read_frame(&mut recv, 32).await.unwrap();
            let declared = u32::try_from(MAX_UNENROLLED_AUTHED_LEN + 1).unwrap();
            send.write_all(&declared.to_le_bytes()).await.unwrap();
            assert_eq!(
                Response::decode(&read_frame(&mut recv, 64).await.unwrap()).unwrap(),
                Response::Err(ErrorCode::NotEnrolled)
            );
            assert_eq!(
                request(&conn, t, &stranger, Request::Get { id: [1; 32] })
                    .await
                    .unwrap(),
                Response::Err(ErrorCode::NotEnrolled),
                "the connection survives the refusal"
            );
            conn.close(0u32.into(), b"done");
        });
    }

    /// A peer that never completes the handshake is dropped at the deadline.
    #[test]
    fn stalled_handshake_times_out() {
        runtime().block_on(async {
            let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
            let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
            let pin = HostPin::from_cert(&cert).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let server = Arc::new(Server::new(Store::open(dir.path().join("s.redb")).unwrap()));
            let endpoint =
                quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            let host_id = pin.host_id();
            let srv = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                serve_connection(&conn, server, host_id, Duration::from_millis(200), || 1_000)
                    .await
                    .err()
            });
            let mut ep = quinn::Endpoint::client(loopback()).unwrap();
            ep.set_default_client_config(client_config(pin).unwrap());
            let conn = ep.connect(addr, "secsec.invalid").unwrap().await.unwrap();
            let err = srv.await.unwrap();
            assert!(matches!(err, Some(ServeError::HandshakeTimeout)));
            conn.close(0u32.into(), b"done");
        });
    }
}
