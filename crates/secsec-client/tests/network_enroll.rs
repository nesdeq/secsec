//! Three devices set up and enroll entirely over live QUIC: A creates the repo, B and C join by invite pairing.

use secsec_client::pair;
use secsec_client::quic::QuicRemote;
use secsec_client::repo::{init_repo_remote, open_repo_remote, RepoError, RosterAnchor};
use secsec_server::{serve::serve_connection, Server};
use secsec_sig::DeviceKey;
use secsec_store::Store;
use secsec_transport::handshake::client_handshake;
use secsec_transport::quic::{client_config, server_config};
use secsec_transport::HostPin;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

/// Pairing-mailbox polls a test allows (500 ms apart); pairing completes in well under a second.
const ROUNDS: u32 = 40;

/// Connect and run the §11 handshake; returns the connection and its session transcript.
async fn dial(
    client: &quinn::Endpoint,
    addr: SocketAddr,
    dev: &DeviceKey,
    host_id: [u8; 32],
    nonce: u8,
) -> (quinn::Connection, [u8; 32]) {
    let conn = client
        .connect(addr, "secsec.invalid")
        .unwrap()
        .await
        .unwrap();
    let t = client_handshake(&conn, dev, host_id, [nonce; 32])
        .await
        .unwrap()
        .transcript;
    (conn, t)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_devices_enroll_over_the_wire() {
    let ck = rcgen::generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
    let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
    let pin = HostPin::from_cert(&cert).unwrap();
    let host_id = pin.host_id();

    // A blind server over an empty store: nobody is pre-enrolled.
    let srv_dir = tempfile::tempdir().unwrap();
    let server = Arc::new(Server::new(
        Store::open(srv_dir.path().join("s.redb")).unwrap(),
    ));
    let endpoint =
        quinn::Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(inc) = endpoint.accept().await {
            let s = server.clone();
            tokio::spawn(async move {
                if let Ok(conn) = inc.await {
                    let _ = serve_connection(&conn, s, host_id, Duration::from_secs(30), || 1_000)
                        .await;
                }
            });
        }
    });
    let mut client = quinn::Endpoint::client(loopback()).unwrap();
    client.set_default_client_config(client_config(pin).unwrap());

    // Device A creates the repo over the wire.
    let dev_a = DeviceKey::generate().unwrap();
    let (conn_a, t_a) = dial(&client, addr, &dev_a, host_id, 0x0a).await;
    let rem_a = QuicRemote::new(&conn_a, t_a, &dev_a);
    let rfp = init_repo_remote(&rem_a, &dev_a, 0).await.unwrap();
    let (mk_a, st_a, anchor_a) = open_repo_remote(&rem_a, &dev_a, &rfp, None).await.unwrap();
    assert_eq!(mk_a.generation(), 1);
    assert_eq!(st_a.members.len(), 1);

    // §8.1 anti-rollback (P7): the chain must extend the persisted anchor.
    assert!(open_repo_remote(&rem_a, &dev_a, &rfp, Some(anchor_a))
        .await
        .is_ok());
    for bad in [
        RosterAnchor {
            max_seq: anchor_a.max_seq,
            tip_hash: [0xFF; 32],
        },
        RosterAnchor {
            max_seq: anchor_a.max_seq + 5,
            tip_hash: anchor_a.tip_hash,
        },
    ] {
        assert!(matches!(
            open_repo_remote(&rem_a, &dev_a, &rfp, Some(bad)).await,
            Err(RepoError::Rollback)
        ));
    }

    // Device B joins, hosted by A.
    let dev_b = DeviceKey::generate().unwrap();
    let (conn_b, t_b) = dial(&client, addr, &dev_b, host_id, 0x0b).await;
    let rem_b = QuicRemote::new(&conn_b, t_b, &dev_b);
    let (code_b, _) = pair::new_invite().unwrap();
    let (host_res, join_res) = tokio::join!(
        pair::run_host(
            &rem_a,
            &dev_a,
            &rfp,
            Some(anchor_a),
            &host_id,
            &code_b,
            ROUNDS,
            0
        ),
        pair::run_join(&rem_b, &dev_b, &code_b, &host_id, ROUNDS),
    );
    assert_eq!(host_res.unwrap().0, dev_b.device_id().unwrap());
    assert_eq!(
        join_res.unwrap(),
        rfp,
        "B learns the genuine RFP through the code"
    );
    let (mk_b, st_b, anchor_b) = open_repo_remote(&rem_b, &dev_b, &rfp, None).await.unwrap();
    assert_eq!(
        mk_b.mk_commit(),
        mk_a.mk_commit(),
        "B unwrapped the same master key"
    );
    assert_eq!(st_b.members.len(), 2);

    // Device C joins, hosted by B.
    let dev_c = DeviceKey::generate().unwrap();
    let (conn_c, t_c) = dial(&client, addr, &dev_c, host_id, 0x0c).await;
    let rem_c = QuicRemote::new(&conn_c, t_c, &dev_c);
    let (code_c, _) = pair::new_invite().unwrap();
    let (host_res, join_res) = tokio::join!(
        pair::run_host(
            &rem_b,
            &dev_b,
            &rfp,
            Some(anchor_b),
            &host_id,
            &code_c,
            ROUNDS,
            0
        ),
        pair::run_join(&rem_c, &dev_c, &code_c, &host_id, ROUNDS),
    );
    host_res.unwrap();
    assert_eq!(join_res.unwrap(), rfp);
    let (mk_c, st_c, _) = open_repo_remote(&rem_c, &dev_c, &rfp, None).await.unwrap();
    assert_eq!(mk_c.mk_commit(), mk_a.mk_commit());
    assert_eq!(st_c.members.len(), 3, "all three devices are rostered");

    // A wrong invite code never pairs: the joiner posts to a slot the host never reads.
    let dev_x = DeviceKey::generate().unwrap();
    let (conn_x, t_x) = dial(&client, addr, &dev_x, host_id, 0x0e).await;
    let rem_x = QuicRemote::new(&conn_x, t_x, &dev_x);
    let (good, _) = pair::new_invite().unwrap();
    let mut wrong = good;
    wrong[0] ^= 0xff;
    let (host_res, _) = tokio::join!(
        pair::run_host(&rem_a, &dev_a, &rfp, None, &host_id, &good, 6, 0),
        pair::run_join(&rem_x, &dev_x, &wrong, &host_id, 6),
    );
    assert!(
        host_res.is_err(),
        "a mismatched invite code does not enroll"
    );
}
