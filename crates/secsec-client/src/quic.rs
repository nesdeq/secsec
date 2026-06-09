//! QUIC [`Remote`] adapter — the thin mapping from the abstract remote surface to the §12 wire RPC
//! over a handshaken `quinn` connection. Each [`Remote`] method becomes one authorized
//! [`secsec_transport::rpc::request`] (the per-op `secsec-read-v1` / `secsec-write-v1` signature is
//! applied inside `request`); the orchestration in the crate root is unchanged whether the remote is
//! in-process or this.

use crate::{Remote, RemoteError};
use quinn::Connection;
use secsec_object::Id;
use secsec_proto::wire::{ErrorCode, Request, Response};
use secsec_sig::DeviceKey;
use secsec_transport::rpc::request as rpc_request;

/// A [`Remote`] backed by a live, handshaken QUIC connection to a `secsec serve` server.
pub struct QuicRemote<'a> {
    conn: &'a Connection,
    transcript: [u8; 32],
    device: &'a DeviceKey,
}

impl<'a> QuicRemote<'a> {
    /// Wrap a connection whose §11 handshake already produced `transcript`; `device` signs each per-op
    /// authorization (it must be the same key that completed `secsec-auth-v1`, §11).
    #[must_use]
    pub fn new(conn: &'a Connection, transcript: [u8; 32], device: &'a DeviceKey) -> Self {
        Self {
            conn,
            transcript,
            device,
        }
    }

    async fn call(&self, req: Request) -> Result<Response, RemoteError> {
        rpc_request(self.conn, self.transcript, self.device, req)
            .await
            .map_err(|e| RemoteError(e.to_string()))
    }
}

/// Map a `Response::Blob` reply (used by both `get` and `get-ref`) to the optional blob.
fn expect_blob(op: &str, resp: Response) -> Result<Option<Vec<u8>>, RemoteError> {
    match resp {
        Response::Blob(b) => Ok(b),
        Response::Err(c) => Err(RemoteError(format!("{op}: {c:?}"))),
        other => Err(RemoteError(format!("{op}: unexpected {other:?}"))),
    }
}

impl Remote for QuicRemote<'_> {
    async fn get_blob(&self, id: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        expect_blob("get", self.call(Request::Get { id: *id }).await?)
    }

    async fn put_blob(&self, id: &Id, blob: &[u8]) -> Result<(), RemoteError> {
        // Blobs are bounded by the §19 16 MiB object cap, so the length fits a u32 declared_size.
        let declared_size = blob.len() as u32;
        match self
            .call(Request::Put {
                id: *id,
                declared_size,
                blob: blob.to_vec(),
            })
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(c) => Err(RemoteError(format!("put: {c:?}"))),
            other => Err(RemoteError(format!("put: unexpected {other:?}"))),
        }
    }

    async fn get_ref(&self, ref_h: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        expect_blob(
            "get-ref",
            self.call(Request::GetRef { ref_h: *ref_h }).await?,
        )
    }

    async fn cas_head(
        &self,
        ref_h: &Id,
        expected_old: &Id,
        new_blob: &[u8],
    ) -> Result<bool, RemoteError> {
        // The wire carries the new head-id token (§12: BLAKE3 of the stored blob); the server
        // re-derives the old token from its current ref blob and CASes.
        let new_head = *blake3::hash(new_blob).as_bytes();
        match self
            .call(Request::CasHead {
                ref_h: *ref_h,
                old_head: *expected_old,
                new_head,
                new_blob: new_blob.to_vec(),
            })
            .await?
        {
            Response::Ok => Ok(true),
            Response::Err(ErrorCode::CasConflict) => Ok(false),
            Response::Err(c) => Err(RemoteError(format!("cas-head: {c:?}"))),
            other => Err(RemoteError(format!("cas-head: unexpected {other:?}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fetch_head, pull_restore, push_head, push_objects};
    use rcgen::generate_simple_self_signed;
    use secsec_kdf::MasterKey;
    use secsec_server::{serve::serve_connection, Server};
    use secsec_store::Store;
    use secsec_transport::handshake::client_handshake;
    use secsec_transport::quic::{client_config, server_config};
    use secsec_transport::HostPin;
    use std::net::{Ipv4Addr, SocketAddr};

    fn loopback() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    fn read_tree(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(root).unwrap() {
            let e = e.unwrap();
            out.push((
                e.file_name().to_str().unwrap().to_owned(),
                std::fs::read(e.path()).unwrap(),
            ));
        }
        out.sort();
        out
    }

    /// End-to-end over **live QUIC**: a pinned client handshakes, wraps the connection in
    /// [`QuicRemote`], pushes a signed commit + head (exercising `put` and the new `cas-head`/`get-ref`
    /// wire ops), then pulls and restores into a fresh store — all through the §12 authorization
    /// pipeline against a blind server.
    #[test]
    fn push_and_pull_over_live_quic() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
            let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
            let pin = HostPin::from_cert(&cert).unwrap();
            let host_id = pin.host_id();

            let m = MasterKey::new(1, [0x44; 32]);
            let device = DeviceKey::generate().unwrap();
            let srv_dir = tempfile::tempdir().unwrap();
            let srv_store = Store::open(srv_dir.path().join("s.redb")).unwrap();
            srv_store
                .put_keyslot(&device.device_id().unwrap(), 1, b"keyslot")
                .unwrap(); // enroll the client device
            let mut server = Server::new(srv_store);

            let endpoint =
                quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let _ = serve_connection(&conn, &mut server, host_id, 1_000).await;
            });

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
            let remote = QuicRemote::new(&conn, sess.transcript, &device);

            // author a snapshot + signed commit locally, push it + the head over QUIC.
            let src = tempfile::tempdir().unwrap();
            std::fs::write(src.path().join("a.txt"), b"over-quic").unwrap();
            std::fs::write(src.path().join("b.txt"), [9u8; 5000]).unwrap();
            let a_store = Store::open(srv_dir.path().join("a.redb")).unwrap();
            let (rt_id, rs) =
                secsec_snapshot::snapshot_tree(src.path(), &m, &a_store, None).unwrap();
            let commit = secsec_snapshot::Commit {
                root_tree: rt_id,
                root_salt: rs,
                parents: vec![],
                device_id: device.device_id().unwrap(),
                version: 1,
                roster_seq: 0,
                last_seen_head: [0u8; 32],
                ts: 0,
            };
            let commit_id =
                secsec_snapshot::seal_signed_commit(&m, &a_store, &device, &commit).unwrap();
            push_objects(&remote, &a_store, &m, &commit_id)
                .await
                .unwrap();
            let (head, _) = push_head(&remote, &m, &device, "main", commit_id, 0, None)
                .await
                .unwrap();

            // a fresh reader pulls the head (get-ref) + closure (get) and restores it.
            let b_store = Store::open(srv_dir.path().join("b.redb")).unwrap();
            let dst = tempfile::tempdir().unwrap();
            let got = pull_restore(&remote, &b_store, &m, &device.public(), "main", dst.path())
                .await
                .unwrap()
                .expect("ref present");
            assert_eq!(got, head);
            assert_eq!(read_tree(src.path()), read_tree(dst.path()));

            // an absent ref returns None over the wire.
            assert!(fetch_head(&remote, &m, "does-not-exist")
                .await
                .unwrap()
                .is_none());

            conn.close(0u32.into(), b"done");
            let _ = srv.await;
        });
    }
}
