//! The authenticated serve loop (`secsec-Design.md` §11/§12): handshake the QUIC connection (binding
//! it to one authenticated key + transcript), then dispatch each per-op request stream through
//! [`Server::handle`] — per stream: issue a fresh single-use `server_nonce`, read the
//! [`AuthedRequest`], run the §12 pipeline, reply.

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
    /// The authenticated key already holds the maximum concurrent connections (§19).
    TooManyConnections,
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
            ServeError::TooManyConnections => {
                f.write_str("too many concurrent connections for this key")
            }
            ServeError::Store(e) => write!(f, "store: {e}"),
            ServeError::Wire(e) => write!(f, "wire: {e}"),
        }
    }
}

/// RAII reservation of a per-key concurrent-connection slot (§19): acquired after the handshake
/// authenticates a key, released when the connection task drops (normal close, error, or cancel).
struct ConnGuard<'a> {
    server: &'a Server,
    device_id: secsec_sig::DeviceId,
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        self.server.release_conn(self.device_id);
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

/// Handshake the connection and serve its request streams until it closes. `now` (unix seconds) is
/// read fresh per request so nonce TTLs stay current on a long-lived connection; `server` is shared
/// (typically `Arc<Server>`) and serves many connections concurrently.
pub async fn serve_connection<F>(
    conn: &Connection,
    server: &Server,
    host_id: [u8; 32],
    now: F,
) -> Result<(), ServeError>
where
    F: Fn() -> u64,
{
    // §11 application handshake: authenticate the connecting key.
    let session = server_handshake(conn, host_id, random32()).await?;

    // Connection allow-list (the operator's `~/.ssh/authorized_keys`, if configured): a key not on it
    // cannot open a session at all. Defense in depth — not the membership ACL.
    let device_id = session
        .pubkey
        .device_id()
        .map_err(|e| ServeError::Store(e.to_string()))?;
    if !server.is_authorized(&device_id) {
        return Err(ServeError::NotEnrolled);
    }

    // §19 connection limit: at most `MAX_CONCURRENT_CONNS_PER_KEY` live connections per authenticated
    // key. The guard releases the slot when this task ends (close, error, or cancellation).
    if !server.acquire_conn(device_id) {
        return Err(ServeError::TooManyConnections);
    }
    let _conn_guard = ConnGuard { server, device_id };

    // Membership is enforced per op inside `Server::handle` (§12 keyslot check) — NOT here, so an
    // authorized-but-unenrolled joiner can still run the §7 pairing ops to get enrolled.

    // Request loop: one bidi stream per op.
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        // Consume the client's empty open-marker (it announces the stream so this `accept_bi` fired).
        if read_frame(&mut recv, 0).await.is_err() {
            break;
        }
        // Issue a fresh single-use per-op nonce and challenge the client.
        let nonce = random32();
        server.issue_nonce(nonce, now());
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
                now(),
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
    use secsec_proto::wire::{ErrorCode, Request, Response};
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
            let server = Server::new(store);

            let endpoint =
                quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = endpoint.local_addr().unwrap();

            let srv = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                // serve until the client closes (the loop ends on connection close).
                let _ = serve_connection(&conn, &server, host_id, || 1_000).await;
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

            // authorized put stages the object under a push (not yet durable).
            let id = [0x42; 32];
            let blob = b"end-to-end-bytes".to_vec();
            let push = [0x55; 16];
            let put = Request::Put {
                id,
                declared_size: blob.len() as u32,
                push_id: push,
                blob: blob.clone(),
            };
            assert_eq!(
                request(&conn, sess.transcript, &device, put)
                    .await
                    .unwrap(),
                Response::Ok
            );
            // a get does not see a staged object until it is promoted.
            assert_eq!(
                request(&conn, sess.transcript, &device, Request::Get { id })
                    .await
                    .unwrap(),
                Response::Blob(None)
            );

            // a cas-head under the push promotes the staged object durably.
            let head = b"head-blob".to_vec();
            let cas = Request::CasHead {
                ref_h: [0x66; 32],
                old_head: [0u8; 32],
                new_head: *blake3::hash(&head).as_bytes(),
                promote: push,
                new_blob: head,
            };
            assert_eq!(
                request(&conn, sess.transcript, &device, cas)
                    .await
                    .unwrap(),
                Response::Ok
            );

            // now an authorized get returns the promoted blob.
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

    /// Two clients are served at the same time: one holds an idle connection while the other
    /// completes a put+get — an idle connection must never block another client.
    #[test]
    fn serves_two_clients_concurrently() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
            let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
            let pin = HostPin::from_cert(&cert).unwrap();
            let host_id = pin.host_id();

            let dev_a = DeviceKey::generate().unwrap();
            let dev_b = DeviceKey::generate().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(dir.path().join("s.redb")).unwrap();
            store
                .put_keyslot(&dev_a.device_id().unwrap(), 1, b"keyslot")
                .unwrap();
            store
                .put_keyslot(&dev_b.device_id().unwrap(), 1, b"keyslot")
                .unwrap();
            let server = std::sync::Arc::new(Server::new(store));

            let endpoint =
                quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            // Concurrent accept loop: a task per connection (as `secsec serve` does).
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let server = server.clone();
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            let _ = serve_connection(&conn, &server, host_id, || 1_000).await;
                        }
                    });
                }
            });

            // Client A connects and then sits IDLE (opens no request stream). Keep `_ca`/`_conn_a`
            // alive so its connection stays open the whole time.
            let mut ca = quinn::Endpoint::client(loopback()).unwrap();
            ca.set_default_client_config(client_config(pin.clone()).unwrap());
            let conn_a = ca.connect(addr, "secsec.invalid").unwrap().await.unwrap();
            let _sess_a = client_handshake(&conn_a, &dev_a, host_id, [0x01; 32])
                .await
                .unwrap();

            // Client B, concurrently, does a full put + get — must succeed despite A holding a conn.
            let mut cb = quinn::Endpoint::client(loopback()).unwrap();
            cb.set_default_client_config(client_config(pin).unwrap());
            let conn_b = cb.connect(addr, "secsec.invalid").unwrap().await.unwrap();
            let tb = client_handshake(&conn_b, &dev_b, host_id, [0x02; 32])
                .await
                .unwrap()
                .transcript;
            let id = [0x77; 32];
            let blob = b"concurrent-bytes".to_vec();
            let push = [0x88; 16];
            assert_eq!(
                request(
                    &conn_b,
                    tb,
                    &dev_b,
                    Request::Put {
                        id,
                        declared_size: blob.len() as u32,
                        push_id: push,
                        blob: blob.clone(),
                    },
                )
                .await
                .unwrap(),
                Response::Ok
            );
            let head = b"h".to_vec();
            assert_eq!(
                request(
                    &conn_b,
                    tb,
                    &dev_b,
                    Request::CasHead {
                        ref_h: [0x99; 32],
                        old_head: [0u8; 32],
                        new_head: *blake3::hash(&head).as_bytes(),
                        promote: push,
                        new_blob: head,
                    },
                )
                .await
                .unwrap(),
                Response::Ok
            );
            assert_eq!(
                request(&conn_b, tb, &dev_b, Request::Get { id })
                    .await
                    .unwrap(),
                Response::Blob(Some(blob)),
                "B was served while A held an idle connection"
            );

            conn_b.close(0u32.into(), b"done");
        });
    }

    /// Two clients race `cas-head` on the same ref (both expecting absent): exactly one must win;
    /// the other gets `CasConflict` and would re-fetch + merge (§10).
    #[test]
    fn two_clients_racing_cas_head_one_wins() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
            let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
            let pin = HostPin::from_cert(&cert).unwrap();
            let host_id = pin.host_id();

            let dev_a = DeviceKey::generate().unwrap();
            let dev_b = DeviceKey::generate().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(dir.path().join("s.redb")).unwrap();
            for d in [&dev_a, &dev_b] {
                store
                    .put_keyslot(&d.device_id().unwrap(), 1, b"keyslot")
                    .unwrap();
            }
            let server = std::sync::Arc::new(Server::new(store));

            let endpoint =
                quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let server = server.clone();
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            let _ = serve_connection(&conn, &server, host_id, || 1_000).await;
                        }
                    });
                }
            });

            let mut ca = quinn::Endpoint::client(loopback()).unwrap();
            ca.set_default_client_config(client_config(pin.clone()).unwrap());
            let conn_a = ca.connect(addr, "secsec.invalid").unwrap().await.unwrap();
            let ta = client_handshake(&conn_a, &dev_a, host_id, [0x01; 32])
                .await
                .unwrap()
                .transcript;
            let mut cb = quinn::Endpoint::client(loopback()).unwrap();
            cb.set_default_client_config(client_config(pin).unwrap());
            let conn_b = cb.connect(addr, "secsec.invalid").unwrap().await.unwrap();
            let tb = client_handshake(&conn_b, &dev_b, host_id, [0x02; 32])
                .await
                .unwrap()
                .transcript;

            // Both cas-head the SAME ref, both expecting absent (all-zero old), with distinct blobs.
            let ref_h = [0x55; 32];
            let cas = |blob: Vec<u8>| Request::CasHead {
                ref_h,
                old_head: [0u8; 32],
                new_head: *blake3::hash(&blob).as_bytes(),
                promote: [0u8; 16],
                new_blob: blob,
            };
            let (ra, rb) = tokio::join!(
                request(&conn_a, ta, &dev_a, cas(b"head-from-A".to_vec())),
                request(&conn_b, tb, &dev_b, cas(b"head-from-B".to_vec())),
            );
            let (ra, rb) = (ra.unwrap(), rb.unwrap());

            // Exactly one Ok, exactly one CasConflict — never two winners, never two losers.
            let oks = [&ra, &rb].iter().filter(|r| ***r == Response::Ok).count();
            let conflicts = [&ra, &rb]
                .iter()
                .filter(|r| ***r == Response::Err(ErrorCode::CasConflict))
                .count();
            assert_eq!(
                oks, 1,
                "exactly one racing writer must win: {ra:?} / {rb:?}"
            );
            assert_eq!(
                conflicts, 1,
                "the other must get CasConflict: {ra:?} / {rb:?}"
            );

            conn_a.close(0u32.into(), b"done");
            conn_b.close(0u32.into(), b"done");
        });
    }
}
