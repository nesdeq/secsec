//! End-to-end over **live QUIC**: three devices set up and enroll entirely **over the wire** — no
//! `init`/`grant` against a local store, no file copying. Device A creates the repo (`init_repo_remote`);
//! devices B and C join by **invite pairing** (`pair::run_host` ⇄ `pair::run_join`) through the blind
//! server. All three end up holding the same master key and seeing the full 3-member roster. This is
//! the proof that the network-enrollment hole is closed.

use secsec_client::pair;
use secsec_client::quic::QuicRemote;
use secsec_client::repo::{init_repo_remote, open_repo_remote};
use secsec_server::{serve::serve_connection, Server};
use secsec_sig::DeviceKey;
use secsec_store::Store;
use secsec_transport::handshake::client_handshake;
use secsec_transport::quic::{client_config, server_config};
use secsec_transport::HostPin;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

/// ~20 s of pairing-mailbox polling (40 × 500 ms) — pairing actually completes in well under a second.
const ROUNDS: u32 = 40;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_devices_enroll_over_the_wire() {
    let ck = rcgen::generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
    let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
    let pin = HostPin::from_cert(&cert).unwrap();
    let host_id = pin.host_id();

    // A blind server over an EMPTY store — no device is pre-enrolled by touching the file.
    let srv_dir = tempfile::tempdir().unwrap();
    let srv_store = Store::open(srv_dir.path().join("s.redb")).unwrap();
    let server = Arc::new(Server::new(srv_store));
    let endpoint =
        quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    {
        let server = server.clone();
        tokio::spawn(async move {
            while let Some(inc) = endpoint.accept().await {
                let s = server.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = inc.await {
                        let _ = serve_connection(&conn, &s, host_id, || 1_000).await;
                    }
                });
            }
        });
    }

    let mut client = quinn::Endpoint::client(loopback()).unwrap();
    client.set_default_client_config(client_config(pin).unwrap());

    // --- Device A: create the repo entirely over the wire ---
    let dev_a = DeviceKey::generate().unwrap();
    let conn_a = client
        .connect(addr, "secsec.invalid")
        .unwrap()
        .await
        .unwrap();
    let sess_a = client_handshake(&conn_a, &dev_a, host_id, [0x0a; 32])
        .await
        .unwrap();
    let rem_a = QuicRemote::new(&conn_a, sess_a.transcript, &dev_a);

    let rfp = init_repo_remote(&rem_a, &dev_a, 0).await.unwrap();
    let (mk_a, st_a) = open_repo_remote(&rem_a, &dev_a, &rfp).await.unwrap();
    assert_eq!(mk_a.generation(), 1);
    assert!(st_a.is_member(&dev_a.device_id().unwrap()));
    assert_eq!(st_a.members.len(), 1);

    // --- Device B: join by invite pairing (host=A) ---
    let dev_b = DeviceKey::generate().unwrap();
    let conn_b = client
        .connect(addr, "secsec.invalid")
        .unwrap()
        .await
        .unwrap();
    let sess_b = client_handshake(&conn_b, &dev_b, host_id, [0x0b; 32])
        .await
        .unwrap();
    let rem_b = QuicRemote::new(&conn_b, sess_b.transcript, &dev_b);

    let (code_b, _disp) = pair::new_invite().unwrap();
    let (host_res, join_res) = tokio::join!(
        pair::run_host(&rem_a, &dev_a, &mk_a, &rfp, &host_id, &code_b, ROUNDS, 0),
        pair::run_join(&rem_b, &dev_b, &code_b, &host_id, ROUNDS),
    );
    assert_eq!(host_res.unwrap(), dev_b.device_id().unwrap());
    assert_eq!(
        join_res.unwrap(),
        rfp,
        "B learns the genuine RFP through the code"
    );

    let (mk_b, st_b) = open_repo_remote(&rem_b, &dev_b, &rfp).await.unwrap();
    assert_eq!(
        mk_b.mk_commit(),
        mk_a.mk_commit(),
        "B unwrapped the same master key"
    );
    assert!(st_b.is_member(&dev_b.device_id().unwrap()));
    assert!(st_b.is_member(&dev_a.device_id().unwrap()));
    assert_eq!(st_b.members.len(), 2);

    // --- Device C: join by invite pairing, this time hosted by B ---
    let dev_c = DeviceKey::generate().unwrap();
    let conn_c = client
        .connect(addr, "secsec.invalid")
        .unwrap()
        .await
        .unwrap();
    let sess_c = client_handshake(&conn_c, &dev_c, host_id, [0x0c; 32])
        .await
        .unwrap();
    let rem_c = QuicRemote::new(&conn_c, sess_c.transcript, &dev_c);

    let (code_c, _disp) = pair::new_invite().unwrap();
    let (host_res, join_res) = tokio::join!(
        pair::run_host(&rem_b, &dev_b, &mk_b, &rfp, &host_id, &code_c, ROUNDS, 0),
        pair::run_join(&rem_c, &dev_c, &code_c, &host_id, ROUNDS),
    );
    host_res.unwrap();
    assert_eq!(join_res.unwrap(), rfp);

    let (mk_c, st_c) = open_repo_remote(&rem_c, &dev_c, &rfp).await.unwrap();
    assert_eq!(mk_c.mk_commit(), mk_a.mk_commit());
    assert_eq!(st_c.members.len(), 3, "all three devices are rostered");
    assert!(st_c.is_member(&dev_c.device_id().unwrap()));

    // A wrong invite code must fail to pair (the code-MAC rejects it).
    let dev_x = DeviceKey::generate().unwrap();
    let conn_x = client
        .connect(addr, "secsec.invalid")
        .unwrap()
        .await
        .unwrap();
    let sess_x = client_handshake(&conn_x, &dev_x, host_id, [0x0e; 32])
        .await
        .unwrap();
    let rem_x = QuicRemote::new(&conn_x, sess_x.transcript, &dev_x);
    let (good, _) = pair::new_invite().unwrap();
    let mut wrong = good;
    wrong[0] ^= 0xff;
    // host expects `good`, joiner sends `wrong` → the host's await_join MAC check rejects it.
    let (host_res, _join_res) = tokio::join!(
        pair::run_host(&rem_a, &dev_a, &mk_a, &rfp, &host_id, &good, 6, 0),
        pair::run_join(&rem_x, &dev_x, &wrong, &host_id, 6),
    );
    assert!(
        host_res.is_err(),
        "a mismatched invite code does not enroll"
    );
}
