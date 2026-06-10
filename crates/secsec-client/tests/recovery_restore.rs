//! End-to-end §8.6 recovery: publish a working tree into a store, then — from the recovery code
//! alone (no device key) — reconstruct the master key, peel the data keyring, and restore the ref's
//! working tree byte-for-byte. Exercises [`create_recovery`] → [`recover_master`] →
//! [`restore_ref_local`] against the real public surface, mirroring the first-publish write path.

use secsec_client::repo::{create_recovery, data_keyring, init_repo, open_repo, recover_master};
use secsec_client::sync::restore_ref_local;
use secsec_sig::DeviceKey;
use secsec_snapshot::{seal_signed_commit, snapshot_tree, Commit};
use secsec_store::{Store, ABSENT_HEAD};
use secsec_sync::{build_head, ref_hash, seal_head, sign_head, HEAD_NONCE_LEN, NO_PREV_HEAD};

#[test]
fn recover_and_restore_working_tree_end_to_end() {
    let srv = tempfile::tempdir().unwrap(); // stands in for the server's store (holds the objects)
    let work = tempfile::tempdir().unwrap(); // the original working dir
    let out = tempfile::tempdir().unwrap(); // where recovery restores the tree

    // Author a small tree with a nested dir and a multi-chunk file.
    std::fs::write(work.path().join("a.txt"), b"hello recovery").unwrap();
    std::fs::create_dir(work.path().join("sub")).unwrap();
    std::fs::write(work.path().join("sub").join("b.bin"), vec![7u8; 5000]).unwrap();

    let store = Store::open(srv.path().join("s.redb")).unwrap();
    let device = DeviceKey::generate().unwrap();
    let rfp = init_repo(&store, &device, 0).unwrap();
    let (mk, st) = open_repo(&store, &device, &rfp).unwrap();

    // --- publish a head into the store, mirroring sync_once's first-publish path ---
    let (root_tree, root_salt) = snapshot_tree(work.path(), &mk, &store, None).unwrap();
    let commit = Commit {
        root_tree,
        root_salt,
        parents: vec![],
        device_id: device.device_id().unwrap(),
        version: 1,
        roster_seq: 0,
        last_seen_head: NO_PREV_HEAD,
        ts: 0,
    };
    let commit_id = seal_signed_commit(&mk, &store, &device, &commit).unwrap();
    let head = build_head("main", commit_id, 0, None);
    let sig = sign_head(&device, &head).unwrap();
    let rnk = mk.ref_name_key();
    let nonce = [0u8; HEAD_NONCE_LEN]; // test-only fixed nonce; production uses random_nonce (§9.8).
    let blob = seal_head(&mk, &rnk, &head, &sig, &nonce);
    let h = ref_hash(&rnk, "main");
    assert!(store.cas_ref(&h, &ABSENT_HEAD, &blob).unwrap());

    // --- create the recovery keyslot, then recover from the code ALONE (device key not used) ---
    let code = create_recovery(&store, &device, &mk).unwrap();
    let (mk_r, st_r) = recover_master(&store, &code, &rfp).unwrap();
    assert_eq!(mk_r.generation(), 1);
    assert_eq!(mk_r.mk_commit(), mk.mk_commit());
    assert!(st_r.is_member(&device.device_id().unwrap()));

    // peel the §8.2 data keyring from the recovered key, then restore the ref locally.
    let keyring = data_keyring(&store, &mk_r).unwrap();
    let restored = restore_ref_local(&store, &keyring, &st_r.members, "main", out.path()).unwrap();
    assert_eq!(restored, Some(commit_id), "restored the published commit");

    // the restored tree is byte-identical to the original.
    assert_eq!(
        std::fs::read(out.path().join("a.txt")).unwrap(),
        b"hello recovery"
    );
    assert_eq!(
        std::fs::read(out.path().join("sub").join("b.bin")).unwrap(),
        vec![7u8; 5000]
    );
    let _ = st;
}

#[test]
fn recover_restores_nothing_when_ref_never_published() {
    let srv = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let store = Store::open(srv.path().join("s.redb")).unwrap();
    let device = DeviceKey::generate().unwrap();
    let rfp = init_repo(&store, &device, 0).unwrap();
    let (mk, _st) = open_repo(&store, &device, &rfp).unwrap();
    let code = create_recovery(&store, &device, &mk).unwrap();

    // recover succeeds (master key + roster), but with no head there is nothing to restore.
    let (mk_r, st_r) = recover_master(&store, &code, &rfp).unwrap();
    let keyring = data_keyring(&store, &mk_r).unwrap();
    let restored = restore_ref_local(&store, &keyring, &st_r.members, "main", out.path()).unwrap();
    assert_eq!(restored, None);
}
