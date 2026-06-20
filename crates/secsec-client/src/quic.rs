//! QUIC [`Remote`] adapter — the thin mapping from the abstract remote surface to the §12 wire RPC
//! over a handshaken `quinn` connection. Each [`Remote`] method becomes one authorized
//! [`secsec_transport::rpc::request`] (the per-op `secsec-read-v1` / `secsec-write-v1` signature is
//! applied inside `request`); the orchestration in the crate root is unchanged whether the remote is
//! in-process or this.

use crate::{Remote, RemoteError};
use quinn::Connection;
use secsec_object::Id;
use secsec_proto::server::limits::MAX_HAS_IDS;
use secsec_proto::wire::{ErrorCode, Request, Response};
use secsec_proto::PUSH_ID_LEN;
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

    async fn put_blob(
        &self,
        id: &Id,
        blob: &[u8],
        push_id: &[u8; PUSH_ID_LEN],
    ) -> Result<(), RemoteError> {
        // Blobs are bounded by the §19 16 MiB object cap, so the length fits a u32 declared_size.
        let declared_size = blob.len() as u32;
        match self
            .call(Request::Put {
                id: *id,
                declared_size,
                push_id: *push_id,
                blob: blob.to_vec(),
            })
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(c) => Err(RemoteError(format!("put: {c:?}"))),
            other => Err(RemoteError(format!("put: unexpected {other:?}"))),
        }
    }

    async fn has(&self, ids: &[Id]) -> Result<Vec<bool>, RemoteError> {
        let mut out = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(MAX_HAS_IDS) {
            match self.call(Request::Has { ids: chunk.to_vec() }).await? {
                Response::Exists(bits) => out.extend(bits),
                Response::Err(c) => return Err(RemoteError(format!("has: {c:?}"))),
                other => return Err(RemoteError(format!("has: unexpected {other:?}"))),
            }
        }
        Ok(out)
    }

    async fn has_for_push(
        &self,
        _push_id: &[u8; PUSH_ID_LEN],
        ids: &[Id],
    ) -> Result<Vec<bool>, RemoteError> {
        // The blind server reports durable existence only (I3); a push's own staging is not queryable
        // over the wire, so a resumed push re-stages its still-unpromoted objects (idempotently) and
        // relies on durable dedup for everything an earlier push already promoted.
        self.has(ids).await
    }

    async fn get_ref(&self, ref_h: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        expect_blob(
            "get-ref",
            self.call(Request::GetRef { ref_h: *ref_h }).await?,
        )
    }

    async fn get_roster_entry(&self, seq: u64) -> Result<Option<Vec<u8>>, RemoteError> {
        expect_blob(
            "get-roster",
            self.call(Request::GetRosterEntry { seq }).await?,
        )
    }

    async fn get_keyslot(&self, device_id: &Id, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        expect_blob(
            "get-keyslot",
            self.call(Request::GetKeyslot {
                device_id: *device_id,
                gen,
            })
            .await?,
        )
    }

    async fn get_roster_keyhist(&self, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        expect_blob(
            "get-roster-keyhist",
            self.call(Request::GetRosterKeyhist { gen }).await?,
        )
    }

    async fn get_keyhist(&self, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        expect_blob("get-keyhist", self.call(Request::GetKeyhist { gen }).await?)
    }

    async fn cas_head(
        &self,
        ref_h: &Id,
        expected_old: &Id,
        new_blob: &[u8],
        promote: &[u8; PUSH_ID_LEN],
    ) -> Result<bool, RemoteError> {
        // The wire carries the new head-id token (§12: BLAKE3 of the stored blob); the server
        // re-derives the old token from its current ref blob, CASes, and promotes `promote`'s staging.
        let new_head = *blake3::hash(new_blob).as_bytes();
        match self
            .call(Request::CasHead {
                ref_h: *ref_h,
                old_head: *expected_old,
                new_head,
                promote: *promote,
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

    async fn put_keyslot(&self, device_id: &Id, gen: u32, blob: &[u8]) -> Result<(), RemoteError> {
        match self
            .call(Request::PutKeyslot {
                device_id: *device_id,
                gen,
                blob: blob.to_vec(),
            })
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(c) => Err(RemoteError(format!("put-keyslot: {c:?}"))),
            other => Err(RemoteError(format!("put-keyslot: unexpected {other:?}"))),
        }
    }

    async fn roster_append(&self, old_tip: &Id, entry: &[u8]) -> Result<bool, RemoteError> {
        match self
            .call(Request::RosterAppend {
                old_tip: *old_tip,
                entry: entry.to_vec(),
            })
            .await?
        {
            Response::Ok => Ok(true),
            Response::Err(ErrorCode::CasConflict) => Ok(false),
            Response::Err(c) => Err(RemoteError(format!("roster-append: {c:?}"))),
            other => Err(RemoteError(format!("roster-append: unexpected {other:?}"))),
        }
    }

    async fn pair_put(&self, slot: &Id, blob: &[u8]) -> Result<(), RemoteError> {
        match self
            .call(Request::PairPut {
                slot: *slot,
                blob: blob.to_vec(),
            })
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(c) => Err(RemoteError(format!("pair-put: {c:?}"))),
            other => Err(RemoteError(format!("pair-put: unexpected {other:?}"))),
        }
    }

    async fn pair_get(&self, slot: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        match self.call(Request::PairGet { slot: *slot }).await? {
            Response::Blob(b) => Ok(b),
            Response::Err(c) => Err(RemoteError(format!("pair-get: {c:?}"))),
            other => Err(RemoteError(format!("pair-get: unexpected {other:?}"))),
        }
    }

    async fn put_keyhist(&self, gen: u32, blob: &[u8]) -> Result<(), RemoteError> {
        match self
            .call(Request::PutKeyhist {
                gen,
                blob: blob.to_vec(),
            })
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(c) => Err(RemoteError(format!("put-keyhist: {c:?}"))),
            other => Err(RemoteError(format!("put-keyhist: unexpected {other:?}"))),
        }
    }

    async fn put_roster_keyhist(&self, gen: u32, blob: &[u8]) -> Result<(), RemoteError> {
        match self
            .call(Request::PutRosterKeyhist {
                gen,
                blob: blob.to_vec(),
            })
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(c) => Err(RemoteError(format!("put-roster-keyhist: {c:?}"))),
            other => Err(RemoteError(format!(
                "put-roster-keyhist: unexpected {other:?}"
            ))),
        }
    }

    async fn delete_keyslot(&self, device_id: &Id, gen: u32) -> Result<(), RemoteError> {
        match self
            .call(Request::DeleteKeyslot {
                device_id: *device_id,
                gen,
            })
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(c) => Err(RemoteError(format!("delete-keyslot: {c:?}"))),
            other => Err(RemoteError(format!("delete-keyslot: unexpected {other:?}"))),
        }
    }

    async fn prune(
        &self,
        dead: &[Id],
        all_heads_hash: &[u8; 32],
        roster_seq: u64,
    ) -> Result<bool, RemoteError> {
        // prune signs over the full args_prune (the §5 head-binding CAS), so it uses the dedicated
        // request_prune path rather than self.call (which would sign the op_and_args placeholder).
        let resp = secsec_transport::rpc::request_prune(
            self.conn,
            self.transcript,
            self.device,
            dead.to_vec(),
            all_heads_hash,
            roster_seq,
        )
        .await
        .map_err(|e| RemoteError(e.to_string()))?;
        match resp {
            Response::Ok => Ok(true),
            // BadAuth ⇒ the recomputed args_prune differs from the client's signed one — the server's
            // head/roster state moved since the client read it (the §5 CAS failed).
            Response::Err(ErrorCode::BadAuth) => Ok(false),
            Response::Err(c) => Err(RemoteError(format!("prune: {c:?}"))),
            other => Err(RemoteError(format!("prune: unexpected {other:?}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fetch_closure, fetch_head, push_head, push_objects};
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
            let server = Server::new(srv_store);

            let endpoint =
                quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let _ = serve_connection(&conn, &server, host_id, || 1_000).await;
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
            push_objects(&remote, &a_store, &m, &commit_id, &[0x70; 16])
                .await
                .unwrap();
            let (head, _) = push_head(&remote, &m, &device, "main", commit_id, 0, None, &[0x70; 16])
                .await
                .unwrap();

            // a fresh reader pulls the head (get-ref) + closure (get), verifies, and restores it.
            let b_store = Store::open(srv_dir.path().join("b.redb")).unwrap();
            let dst = tempfile::tempdir().unwrap();
            let (got, sig, _) = fetch_head(&remote, &m, "main")
                .await
                .unwrap()
                .expect("ref present");
            assert_eq!(got, head);
            secsec_sync::verify_head(&device.public(), &got, &sig).unwrap();
            fetch_closure(&remote, &b_store, &m, &got.commit_id)
                .await
                .unwrap();
            let (commit, csig) =
                secsec_snapshot::open_signed_commit(&got.commit_id, &m, &b_store).unwrap();
            secsec_snapshot::verify_commit(&device.public(), &commit, &csig).unwrap();
            secsec_snapshot::restore_commit_tree(&commit, &m, &b_store, dst.path()).unwrap();
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

    /// Cold-start a repository **over live QUIC** (§8.1): the server's store is genesis-initialized
    /// (`init_repo`); a pinned client handshakes and recovers its master key + roster by fetching the
    /// sigchain + keyslot over the wire (`get-roster` / `get-keyslot`) and folding — never trusting
    /// the blind server.
    #[test]
    fn cold_start_over_live_quic() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
            let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
            let pin = HostPin::from_cert(&cert).unwrap();
            let host_id = pin.host_id();

            let device = DeviceKey::generate().unwrap();
            let srv_dir = tempfile::tempdir().unwrap();
            let srv_store = Store::open(srv_dir.path().join("s.redb")).unwrap();
            // genesis: writes the roster entry + this device's keyslot into the served store.
            let rfp = crate::repo::init_repo(&srv_store, &device, 0).unwrap();
            let server = Server::new(srv_store);

            let endpoint =
                quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let _ = serve_connection(&conn, &server, host_id, || 1_000).await;
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

            // recover identity over the wire, anchored to the out-of-band RFP.
            let (mk, state, _) = crate::repo::open_repo_remote(&remote, &device, &rfp, None)
                .await
                .unwrap();
            assert_eq!(mk.generation(), 1);
            assert!(state.is_member(&device.device_id().unwrap()));

            // a wrong RFP fails the fold (the genesis anchor must match).
            assert!(
                crate::repo::open_repo_remote(&remote, &device, &[0xAB; 32], None)
                    .await
                    .is_err()
            );

            conn.close(0u32.into(), b"done");
            let _ = srv.await;
        });
    }

    /// §8.2/§8.4 **rotation-era cold-start over live QUIC**: the served store is rotated to generation
    /// 2 (writing the roster-key history), then a pinned client cold-starts over the wire — fetching
    /// the sigchain, keyslot, AND roster-key-history (`get-roster-keyhist`) to peel back to genesis and
    /// recover generation 2.
    #[test]
    fn rotation_era_cold_start_over_live_quic() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
            let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
            let pin = HostPin::from_cert(&cert).unwrap();
            let host_id = pin.host_id();

            let device = DeviceKey::generate().unwrap();
            let srv_dir = tempfile::tempdir().unwrap();
            let srv_store = Store::open(srv_dir.path().join("s.redb")).unwrap();
            // genesis + rotate the SERVED store to generation 2 (in-process; writes roster-keyhist).
            let rfp = crate::repo::init_repo(&srv_store, &device, 0).unwrap();
            let (mk1, st1) = crate::repo::open_repo(&srv_store, &device, &rfp).unwrap();
            let (mk2, _st2) =
                crate::repo::rotate_repo(&srv_store, &device, &mk1, &st1, &rfp, None, 0).unwrap();
            assert_eq!(mk2.generation(), 2);
            let server = Server::new(srv_store);

            let endpoint =
                quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let _ = serve_connection(&conn, &server, host_id, || 1_000).await;
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

            // cold-start over the wire recovers generation 2 (peeling roster-keyhist to genesis).
            let (mk_cs, state, _) = crate::repo::open_repo_remote(&remote, &device, &rfp, None)
                .await
                .unwrap();
            assert_eq!(
                mk_cs.generation(),
                2,
                "rotated generation recovered over QUIC"
            );
            assert!(state.is_member(&device.device_id().unwrap()));
            assert!(state.mk_commits.contains_key(&1) && state.mk_commits.contains_key(&2));

            // §8.2 DATA key-history over the wire: peel master_key_1 + master_key_2 via get-keyhist,
            // so a cold-started device could read pre-rotation object content.
            let keyring = crate::repo::data_keyring_remote(&remote, &mk_cs)
                .await
                .unwrap();
            assert_eq!(
                keyring.len(),
                2,
                "data keyring peels both generations over QUIC"
            );
            assert!(keyring.contains_key(&1) && keyring.contains_key(&2));

            conn.close(0u32.into(), b"done");
            let _ = srv.await;
        });
    }

    /// §5 retention prune over **live QUIC**: stage the snapshot closure plus two extra durable
    /// "garbage" blobs and promote them under one head, then prune one — it is deleted while the other
    /// and the reachable closure survive. A prune bound to a STALE `all_heads_hash` fails the §5
    /// head-binding compare-and-swap.
    #[test]
    fn prune_deletes_garbage_and_rejects_stale_cas_over_live_quic() {
        use crate::{push_head, push_objects};
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
                .unwrap();
            let server = Server::new(srv_store);

            let endpoint =
                quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let _ = serve_connection(&conn, &server, host_id, || 1_000).await;
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

            // Stage the snapshot closure AND two extra garbage blobs under one push; a single cas-head
            // promotes them all durably under one ref ("main").
            let src = tempfile::tempdir().unwrap();
            std::fs::write(src.path().join("keep.txt"), b"reachable-data").unwrap();
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
            let push = [0x99; 16];
            let g1 = [0xAA; 32];
            let g2 = [0xBB; 32];
            push_objects(&remote, &a_store, &m, &commit_id, &push)
                .await
                .unwrap();
            remote.put_blob(&g1, b"garbage-one", &push).await.unwrap();
            remote.put_blob(&g2, b"garbage-two", &push).await.unwrap();
            let (_head, head_blob) =
                push_head(&remote, &m, &device, "main", commit_id, 0, None, &push)
                    .await
                    .unwrap();
            assert!(remote.get_blob(&g1).await.unwrap().is_some());
            assert!(remote.get_blob(&g2).await.unwrap().is_some());
            assert!(remote.get_blob(&commit_id).await.unwrap().is_some());

            // The head-binding CAS token over the single "main" ref; no sigchain → roster_seq 0.
            let rnk = *m.ref_name_key();
            let ref_h = secsec_sync::ref_hash(&rnk, "main");
            let ahh = secsec_proto::prune::all_heads_hash(&[(
                ref_h,
                *blake3::hash(&head_blob).as_bytes(),
            )]);

            // prune g1 with the correct CAS token: deleted; g2 + the reachable closure survive.
            assert!(remote.prune(&[g1], &ahh, 0).await.unwrap());
            assert!(remote.get_blob(&g1).await.unwrap().is_none(), "g1 pruned");
            assert!(
                remote.get_blob(&g2).await.unwrap().is_some(),
                "g2 not in the delete-set"
            );
            assert!(
                remote.get_blob(&commit_id).await.unwrap().is_some(),
                "reachable closure kept"
            );

            // a prune bound to a STALE all_heads_hash fails the §5 compare-and-swap (returns false).
            assert!(
                !remote.prune(&[g2], &[0u8; 32], 0).await.unwrap(),
                "stale CAS rejected"
            );
            assert!(
                remote.get_blob(&g2).await.unwrap().is_some(),
                "stale CAS must not delete"
            );

            conn.close(0u32.into(), b"done");
            let _ = srv.await;
        });
    }
}
