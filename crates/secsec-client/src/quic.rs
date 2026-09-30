//! The QUIC [`Remote`]: each method issues authorized §12 RPCs on a handshaken connection.

use crate::{Remote, RemoteError, RosterWrite};
use quinn::Connection;
use secsec_object::Id;
use secsec_proto::op;
use secsec_proto::server::limits::MAX_HAS_IDS;
use secsec_proto::wire::{ErrorCode, Request, Response};
use secsec_proto::PUSH_ID_LEN;
use secsec_sig::DeviceKey;
use secsec_transport::rpc::request as rpc_request;

/// A [`Remote`] over a live connection whose §11 handshake produced `transcript`, signing ops with the same `device`.
pub struct QuicRemote<'a> {
    conn: &'a Connection,
    transcript: [u8; 32],
    device: &'a DeviceKey,
}

impl<'a> QuicRemote<'a> {
    /// Wrap a handshaken connection.
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
            .map_err(|e| RemoteError::Transport(e.to_string()))
    }
}

fn blob(op: &'static str, resp: Response) -> Result<Option<Vec<u8>>, RemoteError> {
    match resp {
        Response::Blob(b) => Ok(b),
        Response::Err(c) => Err(RemoteError::Refused(op, c)),
        _ => Err(RemoteError::Protocol(op)),
    }
}

fn done(op: &'static str, resp: Response) -> Result<(), RemoteError> {
    match resp {
        Response::Ok => Ok(()),
        Response::Err(c) => Err(RemoteError::Refused(op, c)),
        _ => Err(RemoteError::Protocol(op)),
    }
}

/// A CAS reply: `Ok` swapped, `CasConflict` lost.
fn swapped(op: &'static str, resp: Response) -> Result<bool, RemoteError> {
    match resp {
        Response::Ok => Ok(true),
        Response::Err(ErrorCode::CasConflict) => Ok(false),
        Response::Err(c) => Err(RemoteError::Refused(op, c)),
        _ => Err(RemoteError::Protocol(op)),
    }
}

impl Remote for QuicRemote<'_> {
    async fn get_blob(&self, id: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        blob(op::GET, self.call(Request::Get { id: *id }).await?)
    }

    async fn put_blob(
        &self,
        id: &Id,
        blob: &[u8],
        push_id: &[u8; PUSH_ID_LEN],
    ) -> Result<(), RemoteError> {
        let declared_size = u32::try_from(blob.len()).map_err(|_| {
            RemoteError::Transport(format!(
                "a {} byte object exceeds the wire bound",
                blob.len()
            ))
        })?;
        let req = Request::Put {
            id: *id,
            declared_size,
            push_id: *push_id,
            blob: blob.to_vec(),
        };
        done(op::PUT, self.call(req).await?)
    }

    async fn has(&self, ids: &[Id]) -> Result<Vec<bool>, RemoteError> {
        let mut out = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(MAX_HAS_IDS) {
            let req = Request::Has {
                ids: chunk.to_vec(),
            };
            match self.call(req).await? {
                Response::Exists(bits) if bits.len() == chunk.len() => out.extend(bits),
                Response::Err(c) => return Err(RemoteError::Refused(op::HAS, c)),
                _ => return Err(RemoteError::Protocol(op::HAS)),
            }
        }
        Ok(out)
    }

    async fn get_ref(&self, ref_h: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        blob(
            op::GET_REF,
            self.call(Request::GetRef { ref_h: *ref_h }).await?,
        )
    }

    async fn get_roster_entry(&self, seq: u64) -> Result<Option<Vec<u8>>, RemoteError> {
        blob(
            op::GET_ROSTER,
            self.call(Request::GetRosterEntry { seq }).await?,
        )
    }

    async fn get_keyslot(&self, device_id: &Id, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        let req = Request::GetKeyslot {
            device_id: *device_id,
            gen,
        };
        blob(op::GET_KEYSLOT, self.call(req).await?)
    }

    async fn get_roster_keyhist(&self, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        blob(
            op::GET_ROSTER_KEYHIST,
            self.call(Request::GetRosterKeyhist { gen }).await?,
        )
    }

    async fn get_keyhist(&self, gen: u32) -> Result<Option<Vec<u8>>, RemoteError> {
        blob(
            op::GET_KEYHIST,
            self.call(Request::GetKeyhist { gen }).await?,
        )
    }

    async fn cas_head(
        &self,
        ref_h: &Id,
        expected_old: &Id,
        new_blob: &[u8],
        promote: &[u8; PUSH_ID_LEN],
    ) -> Result<bool, RemoteError> {
        let req = Request::CasHead {
            ref_h: *ref_h,
            old_head: *expected_old,
            new_head: *blake3::hash(new_blob).as_bytes(),
            promote: *promote,
            new_blob: new_blob.to_vec(),
        };
        swapped(op::CAS_HEAD, self.call(req).await?)
    }

    async fn roster_batch(&self, w: &RosterWrite) -> Result<bool, RemoteError> {
        let req = Request::RosterBatch {
            old_tip: w.old_tip,
            entries: w.entries.clone(),
            keyslots: w.keyslots.clone(),
            keyhist: w.keyhist.clone(),
            roster_keyhist: w.roster_keyhist.clone(),
            revoke: w.revoke.clone(),
            head: w.head.clone(),
        };
        swapped(op::ROSTER_BATCH, self.call(req).await?)
    }

    async fn prune(
        &self,
        dead: &[Id],
        all_heads_hash: &[u8; 32],
        roster_len: u64,
    ) -> Result<bool, RemoteError> {
        let req = Request::Prune {
            dead: dead.to_vec(),
            all_heads_hash: *all_heads_hash,
            roster_len,
        };
        swapped(op::PRUNE, self.call(req).await?)
    }

    async fn pair_put(&self, slot: &Id, blob: &[u8]) -> Result<(), RemoteError> {
        let req = Request::PairPut {
            slot: *slot,
            blob: blob.to_vec(),
        };
        done(op::PAIR_PUT, self.call(req).await?)
    }

    async fn pair_get(&self, slot: &Id) -> Result<Option<Vec<u8>>, RemoteError> {
        blob(
            op::PAIR_GET,
            self.call(Request::PairGet { slot: *slot }).await?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::{
        data_keyring_remote, init_repo_remote, open_repo_remote, rotate_repo_remote, Revoke,
    };
    use crate::sync::{sync_once, SyncInput, SyncKind};
    use crate::{fetch_head, push_head, push_objects, ClientError};
    use rcgen::generate_simple_self_signed;
    use secsec_server::{serve::serve_connection, Server};
    use secsec_snapshot::SnapshotMemo;
    use secsec_store::Store;
    use secsec_sync::rollback::SyncFrontier;
    use secsec_transport::handshake::client_handshake;
    use secsec_transport::quic::{client_config, server_config};
    use secsec_transport::HostPin;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    const DEADLINE: Duration = Duration::from_secs(30);

    fn loopback() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    /// A live server over `store`, accepting until the test ends.
    fn serve(store: Store) -> (SocketAddr, HostPin) {
        let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
        let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
        let pin = HostPin::from_cert(&cert).unwrap();
        let host_id = pin.host_id();
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
        (addr, pin)
    }

    async fn dial(
        addr: SocketAddr,
        pin: &HostPin,
        dev: &DeviceKey,
    ) -> (quinn::Endpoint, Connection, [u8; 32]) {
        let mut ep = quinn::Endpoint::client(loopback()).unwrap();
        ep.set_default_client_config(client_config(pin.clone()).unwrap());
        let conn = ep.connect(addr, "secsec.invalid").unwrap().await.unwrap();
        let t = client_handshake(&conn, dev, pin.host_id(), [0x11; 32])
            .await
            .unwrap()
            .transcript;
        (ep, conn, t)
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    /// Create, sync, clone, revoke, and cold-start entirely over live QUIC against a blind server.
    #[test]
    fn a_repo_lives_its_whole_life_over_quic() {
        runtime().block_on(async {
            let srv = tempfile::tempdir().unwrap();
            let (addr, pin) = serve(Store::open(srv.path().join("s.redb")).unwrap());
            let a = DeviceKey::generate().unwrap();
            let (_ea, conn_a, ta) = dial(addr, &pin, &a).await;
            let ra = QuicRemote::new(&conn_a, ta, &a);
            let rfp = init_repo_remote(&ra, &a, 0).await.unwrap();
            assert!(matches!(
                init_repo_remote(&ra, &a, 0).await,
                Err(crate::repo::RepoError::AlreadyEnrolled)
            ));
            let stranger = DeviceKey::generate().unwrap();
            let (_es, conn_s, ts) = dial(addr, &pin, &stranger).await;
            assert!(matches!(
                init_repo_remote(&QuicRemote::new(&conn_s, ts, &stranger), &stranger, 0).await,
                Err(crate::repo::RepoError::AlreadyInitialized)
            ));

            let (mk, st, anchor) = open_repo_remote(&ra, &a, &rfp, None).await.unwrap();
            let ring = data_keyring_remote(&ra, &mk, &st).await.unwrap();
            let cache = Store::open(srv.path().join("a.redb")).unwrap();
            let work = tempfile::tempdir().unwrap();
            std::fs::write(work.path().join("a.txt"), b"over-quic").unwrap();
            std::fs::write(work.path().join("b.bin"), vec![9u8; 90_000]).unwrap();
            let seal = |_: &SyncFrontier| Ok::<(), ClientError>(());
            let input = SyncInput {
                store: &cache,
                dir: work.path(),
                keys: &ring,
                device: &a,
                roster: &st,
                ref_name: "main",
                ts: 0,
                push_id: &[0x70; 16],
                seal: &seal,
            };
            let out = sync_once(
                &ra,
                &input,
                &SyncFrontier::default(),
                None,
                &mut SnapshotMemo::default(),
            )
            .await
            .unwrap();
            assert_eq!(out.kind, SyncKind::Published);

            // A second device, invited through the mailbox, clones the folder.
            let b = DeviceKey::generate().unwrap();
            let (_eb, conn_b, tb) = dial(addr, &pin, &b).await;
            let rb = QuicRemote::new(&conn_b, tb, &b);
            let (code, _) = crate::pair::new_invite().unwrap();
            let host_id = pin.host_id();
            let (hosted, joined) = tokio::join!(
                crate::pair::run_host(&ra, &a, &rfp, Some(anchor), &host_id, &code, 20, 0),
                crate::pair::run_join(&rb, &b, &code, &host_id, 20),
            );
            let (_, anchor) = hosted.unwrap();
            assert_eq!(joined.unwrap(), rfp);
            let (mk_b, st_b, _) = open_repo_remote(&rb, &b, &rfp, None).await.unwrap();
            let ring_b = data_keyring_remote(&rb, &mk_b, &st_b).await.unwrap();
            let cache_b = Store::open(srv.path().join("b.redb")).unwrap();
            let clone = tempfile::tempdir().unwrap();
            let input_b = SyncInput {
                store: &cache_b,
                dir: clone.path(),
                keys: &ring_b,
                device: &b,
                roster: &st_b,
                ref_name: "main",
                ts: 0,
                push_id: &[0x71; 16],
                seal: &seal,
            };
            let out = sync_once(
                &rb,
                &input_b,
                &SyncFrontier::default(),
                None,
                &mut SnapshotMemo::default(),
            )
            .await
            .unwrap();
            assert_eq!(out.kind, SyncKind::Cloned);
            assert_eq!(
                std::fs::read(clone.path().join("b.bin")).unwrap(),
                vec![9u8; 90_000]
            );

            // Revoking B rotates to generation 2; B is locked out, A cold-starts onto it and still reads the head.
            let rot = rotate_repo_remote(
                &ra,
                &a,
                &rfp,
                Some(anchor),
                Some(Revoke {
                    device: b.device_id().unwrap(),
                    after_seq: anchor.max_seq + 1,
                }),
                "main",
                0,
            )
            .await
            .unwrap();
            assert_eq!(rot.mk.generation(), 2);
            assert!(open_repo_remote(&rb, &b, &rfp, None).await.is_err());
            let ring2 = data_keyring_remote(&ra, &rot.mk, &rot.state).await.unwrap();
            let (head, _, _) = fetch_head(&ra, &ring2, "main").await.unwrap().unwrap();
            assert_eq!(Some(head.commit_id), out.base);
            conn_a.close(0u32.into(), b"done");
            conn_b.close(0u32.into(), b"done");
            conn_s.close(0u32.into(), b"done");
        });
    }

    /// §15 prune over QUIC: a correct claim deletes, a stale one is a CAS conflict that deletes nothing.
    #[test]
    fn prune_over_quic_is_bound_to_the_servers_state() {
        runtime().block_on(async {
            let srv = tempfile::tempdir().unwrap();
            let store = Store::open(srv.path().join("s.redb")).unwrap();
            let dev = DeviceKey::generate().unwrap();
            store
                .put_keyslot(&dev.device_id().unwrap(), 1, b"keyslot")
                .unwrap();
            let (addr, pin) = serve(store);
            let (_e, conn, t) = dial(addr, &pin, &dev).await;
            let r = QuicRemote::new(&conn, t, &dev);
            let m = secsec_kdf::MasterKey::new(1, [0x44; 32]);
            let cache = Store::open(srv.path().join("c.redb")).unwrap();
            let work = tempfile::tempdir().unwrap();
            std::fs::write(work.path().join("keep.txt"), b"reachable").unwrap();
            let snap = secsec_snapshot::snapshot_tree(
                work.path(),
                &m,
                &cache,
                None,
                &mut SnapshotMemo::default(),
            )
            .unwrap();
            let commit = secsec_snapshot::Commit {
                root_tree: snap.root,
                root_salt: snap.salt,
                parents: vec![],
                device_id: dev.device_id().unwrap(),
                version: 1,
                roster_seq: 0,
                last_seen_head: [0; 32],
                ts: 0,
            };
            let id = secsec_snapshot::seal_signed_commit(&m, &cache, &dev, &commit).unwrap();
            let push = [0x99; 16];
            push_objects(&r, &cache, &m, &id, None, &push)
                .await
                .unwrap();
            let (g1, g2) = ([0xAA; 32], [0xBB; 32]);
            r.put_blob(&g1, b"garbage-one", &push).await.unwrap();
            r.put_blob(&g2, b"garbage-two", &push).await.unwrap();
            let (_, head_blob) = push_head(&r, &m, &dev, "main", id, 0, None, &push)
                .await
                .unwrap();
            assert_eq!(r.has(&[g1, g2, id]).await.unwrap(), vec![true, true, true]);
            let ref_h = secsec_sync::ref_hash(&m.ref_name_key(), "main");
            let ahh = secsec_proto::prune::all_heads_hash(&[(
                ref_h,
                *blake3::hash(&head_blob).as_bytes(),
            )]);
            assert!(r.prune(&[g1], &ahh, 0).await.unwrap());
            assert!(r.get_blob(&g1).await.unwrap().is_none());
            assert!(!r.prune(&[g2], &[0; 32], 0).await.unwrap());
            assert!(!r.prune(&[g2], &ahh, 1).await.unwrap());
            assert!(r.get_blob(&g2).await.unwrap().is_some());
            assert!(r.get_blob(&id).await.unwrap().is_some());
            conn.close(0u32.into(), b"done");
        });
    }
}
