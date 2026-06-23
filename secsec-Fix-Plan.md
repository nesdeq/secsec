# secsec — Remediation Plan

Surgical fix plan for every finding in [`secsec-Audit.md`](secsec-Audit.md). Each entry: root cause,
the exact file/function, the minimal edit, and the test to add/update. Verification commands at the end.

Two corrections from re-validating the findings while planning:
- **F14 is a non-issue** — a folder switch does not change the SSH key, so the cached passphrase is
  still valid; clearing it (as F14 suggested) would force a needless re-prompt. No fix.
- **F4 / F5 have no sane code fix** — a *blind* server cannot verify revocation-linkage, and the
  binary already mandates the connection gate. They become documentation-only.

Ordering by blast radius: F1 first (the only security-relevant change), then the tiny code edits
(F2, F3, F13), then the KAT addition (F11), then pure docs (F6–F10, F12), then the doc-only rationale
items (F4, F5).

---

## F1 (HIGH) — close the pull-path head rollback

**Root cause.** `sync_once`'s no-local-changes branch calls `pull_to`, which restores any head that
passes gate 1 (`roster_seq`) + gate 2b (`head_version_hwm[signer]`). It never applies §10's rule "a
sibling that is an ancestor of (or equal to) the client's head is a no-op **before** the gates" — the
rule the merge path *does* apply (`secsec-sync/src/rollback.rs:118`,
`if is_ancestor(sibling.commit_id, our_head) → AlreadyHave`). Because `head_version` is tracked
per-device, gate 2b cannot substitute for it: a replayed ancestor head signed by a device whose HWM
≤ that head's version passes both gates and is silently restored → working-dir rollback (violates P8).

**Fix.** `crates/secsec-client/src/sync.rs`, the `if unchanged { … }` block: replace the bespoke
`pull_to` call with the *same* rollback-gated DAG decision the merge path uses, reusing the public,
already-tested `secsec_engine::load_commit_dag` + `secsec_sync::rollback::evaluate_merge`. Only a
genuine **FastForward** restores; an ancestor replay or a (cas-unreachable) incomparable fork is a
no-op; a head that regresses below the frontier alarms.

```rust
// No local changes: reconcile a differing remote head, or we are already up to date.
if unchanged {
    let Some((h, sig, _blob)) = &head else {
        return Ok(SyncOutcome { kind: SyncKind::UpToDate, base, frontier: frontier.clone(), conflicts: Vec::new() });
    };
    if Some(h.commit_id) == base {
        return Ok(SyncOutcome { kind: SyncKind::UpToDate, base, frontier: frontier.clone(), conflicts: Vec::new() });
    }
    // The remote head differs from our base and we have no local changes. Classify it against base
    // with the SAME rollback-gated DAG decision the merge path uses (§10): only a genuine
    // fast-forward is restored. A replayed ancestor head — or a cas-unreachable incomparable fork —
    // is NOT restored, so a malicious server cannot silently roll the working dir back (the §10
    // "ancestor sibling is a no-op before the gates" rule; closes the pull-path rollback).
    let signer = resolve_head_signer(members, h, sig).ok_or(ClientError::HeadNotMember)?;
    fetch_closure(remote, store, keys, &h.commit_id).await?;
    let our = base.expect("the no-base clone path is handled above");
    let (parents, meta) = secsec_engine::load_commit_dag(&[our, h.commit_id], keys, store)?;
    let sibling = SiblingHead {
        device_id: signer,
        head_version: h.head_version,
        roster_seq: h.roster_seq,
        commit_id: h.commit_id,
    };
    return match evaluate_merge(frontier, &our, &sibling, &device_id, &parents, &meta) {
        Ok(MergeDecision::FastForward) => {
            let (commit, csig) = open_signed_commit(&h.commit_id, keys, store)?;
            verify_commit(author_key(members, &commit)?, &commit, &csig)?;
            restore_commit_tree(&commit, keys, store, dir)?;
            let mut f = frontier.clone();
            f.observe(&sibling, &parents, &meta);
            Ok(SyncOutcome { kind: SyncKind::Pulled, base: Some(h.commit_id), frontier: f, conflicts: Vec::new() })
        }
        // Ancestor of our base (replayed) or a cas-unreachable incomparable fork: do not restore.
        // A genuine fork reconciles keep-both on this device's next local change (the merge path).
        Ok(MergeDecision::AlreadyHave | MergeDecision::Merge) =>
            Ok(SyncOutcome { kind: SyncKind::UpToDate, base, frontier: frontier.clone(), conflicts: Vec::new() }),
        Err(reject) => Err(ClientError::Merge(MergeError::Rollback(reject))),
    };
}
```

Import add in `sync.rs`: `use secsec_sync::rollback::{evaluate_merge, MergeDecision, MergeReject, SiblingHead, SyncFrontier};`
(`load_commit_dag` is already used in `pull_to`; `MergeError` is already imported).

**Notes**
- `pull_to` is **left unchanged** — it remains the correct primitive for the **clone** branch
  (`base.is_none()`, the §21 reinstall-freshness residual where no base exists to compare against).
- The fix is strictly *stronger* than before: the pull path now also runs gate 2a (via
  `evaluate_merge`), and an ancestor-with-stale-`roster_seq` correctly becomes a no-op (matches §10's
  late-fold carve-out — not a false alarm).
- `base` is always `Some` inside `unchanged` (it requires `prev = Some`, which requires `base = Some`),
  so the `.expect()` cannot fire.

**Backward compatibility.** The only case the old code handled correctly — a legit fast-forward pull —
maps to `MergeDecision::FastForward` and behaves identically (verify → restore → observe → `Pulled`).
The existing tests `two_clients_publish_clone_edit_pull` and
`deletion_propagates_and_does_not_resurrect` exercise exactly that and keep passing.

**Test — add `pull_path_refuses_ancestor_head_replay` to `sync.rs` tests:**

```rust
#[tokio::test]
async fn pull_path_refuses_ancestor_head_replay() {
    use crate::{fetch_closure, fetch_head, push_head, push_objects};
    use secsec_snapshot::{open_signed_commit, restore_commit_tree, seal_signed_commit, snapshot_tree, Commit};
    use secsec_sync::ref_hash;

    let dir = tempfile::tempdir().unwrap();
    let m = MasterKey::new(1, [0x55; 32]);
    let dev_a = DeviceKey::generate().unwrap();
    let dev_b = DeviceKey::generate().unwrap();
    let (ida, idb) = (dev_a.device_id().unwrap(), dev_b.device_id().unwrap());
    let members: BTreeMap<DeviceId, DevicePublic> =
        [(ida, dev_a.public()), (idb, dev_b.public())].into_iter().collect();
    let remote = MemRemote::new(Store::open(dir.path().join("r.redb")).unwrap());
    let auth = Store::open(dir.path().join("auth.redb")).unwrap();

    // B publishes C_b (head v1).
    let wb = tempfile::tempdir().unwrap();
    std::fs::write(wb.path().join("f"), b"vB").unwrap();
    let (tb, sb) = snapshot_tree(wb.path(), &m, &auth, None).unwrap();
    let c_b = seal_signed_commit(&m, &auth, &dev_b, &Commit {
        root_tree: tb, root_salt: sb, parents: vec![], device_id: idb,
        version: 1, roster_seq: 0, last_seen_head: [0; 32], ts: 0 }).unwrap();
    push_objects(&remote, &auth, &m, &c_b, &[1; 16]).await.unwrap();
    let (head_b, blob_b) = push_head(&remote, &m, &dev_b, "main", c_b, 0, None, &[1; 16]).await.unwrap();

    // A advances to C_a (head v2, descends from C_b).
    std::fs::write(wb.path().join("f"), b"vA").unwrap();
    let (ta, sa) = snapshot_tree(wb.path(), &m, &auth, Some((&tb, &sb))).unwrap();
    let c_a = seal_signed_commit(&m, &auth, &dev_a, &Commit {
        root_tree: ta, root_salt: sa, parents: vec![c_b], device_id: ida,
        version: 1, roster_seq: 0, last_seen_head: c_b, ts: 0 }).unwrap();
    push_objects(&remote, &auth, &m, &c_a, &[2; 16]).await.unwrap();
    let (_head_a, blob_a) = push_head(&remote, &m, &dev_a, "main", c_a, 0, Some((&head_b, &blob_b)), &[2; 16]).await.unwrap();

    // Our device: at base C_a, working dir == C_a, frontier observed both heads.
    let c_store = Store::open(dir.path().join("c.redb")).unwrap();
    fetch_closure(&remote, &c_store, &m, &c_a).await.unwrap();
    let work = tempfile::tempdir().unwrap();
    let (ca_commit, _) = open_signed_commit(&c_a, &m, &c_store).unwrap();
    restore_commit_tree(&ca_commit, &m, &c_store, work.path()).unwrap();
    let frontier = SyncFrontier {
        roster_seq: 0,
        head_version_hwm: BTreeMap::from([(ida, 2), (idb, 1)]),
        commit_version_hwm: BTreeMap::from([(ida, 1), (idb, 1)]),
    };

    // Malicious server rolls /refs/main back to C_b's head.
    let ref_h = ref_hash(&m.ref_name_key(), "main");
    remote.store.cas_ref(&ref_h, blake3::hash(&blob_a).as_bytes(), &blob_b, &[0; 16]).unwrap();
    assert_eq!(fetch_head(&remote, &m, "main").await.unwrap().unwrap().0.commit_id, c_b);

    // Sync with no local change: must NOT roll the working dir back to C_b.
    let seal = |_: &SyncFrontier| Ok::<(), ClientError>(());
    let out = sync_once(&remote, &c_store, work.path(), &m, &dev_a, &members, &frontier,
                        "main", 0, Some(c_a), 0, &[3; 16], &seal).await.unwrap();
    assert_eq!(out.kind, SyncKind::UpToDate, "ancestor-head replay must be a no-op, not a rollback");
    assert_eq!(out.base, Some(c_a), "base must stay at C_a");
    assert_eq!(std::fs::read(work.path().join("f")).unwrap(), b"vA", "working dir must not roll back");
}
```

(With the pre-fix code this restores `C_b` — the exact regression the test pins.)

---

## F2 (LOW) — authenticate the sibling tip commit on the merge path

**Root cause.** `secsec-engine::load_commit_dag` / `merge_heads` read each commit's `(device_id,
version)` for the gates via `open_signed_commit` without `verify_commit`; the engine doc-comment makes
that a caller precondition, but `sync_ref` verifies only the head signature. (The pull path already
verifies the tip commit.)

**Fix.** `crates/secsec-client/src/lib.rs`, in `sync_ref`, immediately after `fetch_closure(...)`:

```rust
// Authenticate the sibling's tip commit against the roster (P3) before its metadata feeds the
// rollback gates — mirrors the pull path. Ancestors are authenticated transitively by the
// member-signed head + content-addressing (§9.2).
let (sib_c, sib_sig) = secsec_snapshot::open_signed_commit(&remote_head.commit_id, keys, store)?;
let sib_author = members.get(&sib_c.device_id).ok_or(ClientError::HeadNotMember)?;
secsec_snapshot::verify_commit(sib_author, &sib_c, &sib_sig)?;
```

**Doc edit.** `crates/secsec-engine/src/lib.rs`, `merge_heads` doc-comment: change
"the caller signature-verified the sibling and **reachable** commits against the roster" →
"the caller signature-verified the sibling head and its **tip** commit; ancestor commits are
authenticated transitively by the member-signed head + content-addressing (§9.2/§9.6)." (Full
per-commit verification is unnecessary against the in-scope server adversary and is only relevant to a
malicious *current* member, which is out of §3 scope.)

**Test (optional, nice-to-have).** Build a commit with `device_id = A` but signed by `B`
(`seal_signed_commit` signs with the passed device and stamps `device_id` from the struct), publish a
B-signed head over it, and assert `sync_ref` rejects (`HeadNotMember` / `BadSignature`).

---

## F3 (latent) — block a rotation that cannot satisfy `min_algo`

**Fix.** `crates/secsec-client/src/repo.rs`, in `rotate_repo` and `rotate_repo_remote`, before the
keyslot re-wrap loop:

```rust
// §16: a rotation must wrap to keyslots ≥ the chain's floor; with X-Wing the only algorithm, a
// higher floor cannot be met — abort rather than write keyslots every member rejects at cold-start.
if state.min_algo > ALGO_XWING {
    return Err(RepoError::AlgoTooWeak { got: ALGO_XWING, floor: state.min_algo });
}
```

The grant path needs nothing extra: a joiner's `open_repo_remote` already runs `enforce_min_algo` and
rejects a too-weak keyslot at cold-start. Fully latent today (`SetMinAlgo` has no CLI surface, so
`min_algo == MIN_ALGO_ID == ALGO_XWING`). No test required (no reachable trigger); a unit test could
fold a synthetic `SetMinAlgo(2)` chain and assert `rotate_repo` returns `AlgoTooWeak`.

---

## F13 (LOW) — zero the revealed passphrase after writing it to the child

**Fix.** `ui/macos/secsec-menubar.swift`, `spawn()`:

```swift
if var pass = cache.reveal() {
    try? stdinPipe.fileHandleForWriting.write(contentsOf: pass)
    pass.resetBytes(in: 0..<pass.count)   // scrub the transient plaintext copy
}
```

---

## F11 (INFO) — make "every derivation is KAT'd" true (add the missing `data_keyhist_key` KAT)

**Steps**
1. `xtask/src/vectors.rs` `computed()`: import `data_keyhist_key` and add
   `put("data_keyhist_key(master_key[g=1], 1)", hx(&data_keyhist_key(&[0x11; 32], 1)[..]));`.
2. Run `cargo xtask vectors` to print the computed hex.
3. Paste it into `vectors/secsec-kat-v1.txt` under `[kdf]`:
   `data_keyhist_key(master_key[g=1], 1) = <hex>`.
4. Add the same assertion to `secsec-kdf` `tests::kat_frozen`.
5. Fix the wording in `secsec-Design.md §9.5` and `crates/secsec-kdf/README.md`: "nine derivations
   (the eight `derive_key`s + `mk_commit`)" → "ten `derive_key` derivations (the eight in §9.5 plus
   `k_obj` §9.4 and `k_keyhist` §8.2) + the `mk_commit` `keyed_hash`."

`cargo xtask vectors --check` (and its `committed_vectors_match_live_code` test) then enforce the new
vector against live code.

---

## Pure documentation fixes

- **F6** — `secsec-Design.md §15.1`: reword the `has_for_push` sentence. Over the blind QUIC server, a
  crash-resumed push re-stages its not-yet-promoted set **idempotently** (`has` reports durable
  existence only, I3); `has_for_push(push_id, ids)` is the in-process-store variant, not a wire op.
  (No protocol change — the behavior is correct; only the claim was optimistic.)
- **F7** — `bin/secsec/README.md`: delete the nonexistent `[--name ref]` (also contradicts §2); fix
  the `sync` flags to `[--once] [--key F] [--passphrase-stdin]`; add table rows for `hostpin`, `log`,
  `restore`, `reset`.
- **F8** — `crates/secsec-engine/README.md`: remove the invented `reconcile(...)`; describe the real
  API (`merge_heads` drives the private three-way merge over LCA/ours/theirs).
- **F9** — `crates/secsec-sync/README.md`: remove `is_head_successor` (does not exist).
- **F10** — `crates/secsec-server/README.md`: `Authorized (Any / Static / File)` → `(Any / File)`;
  drop `with_authorized(set)` (only `with_authorized_file` exists).
- **F12** — README hygiene: remove `x25519_public` from `crates/secsec-sig/README.md` (no such method;
  `x25519_secret` is crate-internal) and add the public `history` module to
  `crates/secsec-client/README.md`. Trim remaining `pub`-vs-`pub(crate)` mislabels opportunistically.

---

## Documentation-only rationale (no code change)

- **F4** — `delete-keyslot` cannot be bound to a legitimate revocation because the server is *blind*
  (it cannot fold the encrypted roster). Add one sentence to `secsec-Design.md §8.4`/residuals: it is
  unprivileged among rostered keys — a griefing vector inside the flat-trust member set, not reachable
  by the in-scope adversaries. No code fix is possible without making the server non-blind.
- **F5** — add a `# Safety` doc-comment to `Server::new`: it is **open by default**, and
  `with_authorized_file` is mandatory for any networked deployment (the binary already enforces this
  and refuses to start without `authorized_keys`). Flipping the default would churn every test for no
  production benefit.
- **F14** — **non-issue (re-validated).** A folder switch leaves the SSH key (hence its passphrase)
  unchanged, so reusing the cache is correct; `chooseKey`/`clearKey` clear *because the key changed*.
  No fix.

---

## Verification (after the edits)

```sh
cargo test --workspace                                   # incl. the new F1 regression test
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask vectors --check                              # F11 KAT drift guard
```

Expected: the new `pull_path_refuses_ancestor_head_replay` passes; all existing client/sync/engine
tests still pass (the legit fast-forward path is unchanged); the KAT set gains one vector with no drift.
