# secsec — Correctness & Security Audit

Full read-through audit of the entire repository: both design docs (`secsec-Design.md`,
`secsec-Implementation.md`), the top-level `README.md`, all 51 Rust source files (~21.6k LOC including
tests), every per-crate `README.md`, the GNOME/macOS desktop UIs, the install/build scripts, the
committed KAT vectors and their generator, the fuzz harness, and the Cargo/audit manifests. Every
finding below was validated twice against the actual code and docs.

## Bottom line

The cryptographic and protocol core is strong and closely matches the spec. Reference- and KAT-checked
CTX/CMT-4 AEAD; X-Wing keyslot conformant to draft-10 Appendix C; the SSHSIG roster sigchain with the
transitive revoke-closure; the persisted anti-rollback ROSTER anchor (P7); the pinned-TLS verifier with
its mandatory negative tests; per-op authorization with single-use nonces; QUIC Retry + per-IP rate
limiting on a real wall-clock; atomic staged-promote (I1); the prune head-binding CAS; and the
setuid/path-traversal/control-character guards are all present and correct.

There is **one real security gap (F1, HIGH)**, a handful of minor or out-of-threat-model issues, and a
cluster of documentation drift.

---

## Security / correctness

### F1 — HIGH — The pull path can be silently rolled back by a malicious server (violates P8)

**Where:** `crates/secsec-client/src/sync.rs` — `pull_to`, reached from the `unchanged` (no-local-change)
and clone branches of `sync_once`.

**What:** Design §10 catches an ancestor-head replay with the rule *"a sibling that is an ancestor of
(or equal to) the client's head is already held and is accepted as a no-op **before** the gates."* The
**merge** path implements it (`secsec-sync/src/rollback.rs:118`,
`if is_ancestor(parents, &sibling.commit_id, our_head) → Ok(MergeDecision::AlreadyHave)`). The
**no-local-changes pull** path does **not**: `pull_to` runs only gate 1 (`roster_seq`) and gate 2b
(`head_version_hwm[signer]`), then calls `restore_commit_tree`, with no comparison to the current base.

Because `head_version` is tracked **per device** (`SyncFrontier.head_version_hwm: Map<device_id,u64>`),
gate 2b only compares a replayed head against *its own signer's* high-water — and `observe`
(`rollback.rs:185`) only ever raises the entry for `sibling.device_id`. So a malicious server that
retained an older head blob (signed by device B at the last head version B published) can replay it to a
client whose current base is a later head signed by device A:

- gate 1 passes when no rotation has happened since (the common case — same `roster_seq`);
- gate 2b passes because `head_version_hwm[B]` is at most that value (or `0` by default if no B-signed
  head was ever observed);

and `pull_to` then restores the **older** tree. No alarm fires. The client's working directory is
silently rolled back to stale content, and `base` is set to the old commit — sticky for as long as the
server keeps presenting it. This is an in-scope adversary (malicious server), it contradicts P8
("Rollback/replay of … per-ref head state is detected"), and it is not covered by any §21 residual
(the reinstall-freshness residual is for a device that has *lost* its frontier; here the frontier is
intact and still fails to catch the rollback).

**Downstream:** the rolled-back device's newer content is now unreferenced by its head; if the malicious
server also drops that content (it controls its own store), the user's recent work is unrecoverable from
that device. The certain, immediate harm is the **undetected silent rollback**; data loss is a plausible
escalation.

**Fix:** in the pull path, mirror `evaluate_merge` — treat `is_ancestor(remote_head_commit, base)` as a
no-op (`AlreadyHave`) and a DAG-incomparable head as a merge, not a blind restore. Alternatively, add a
single per-ref `head_version` high-water to `SyncFrontier` and reject any head below it regardless of
signer.

### F2 — LOW — Merge path doesn't verify per-commit signatures against the roster

`secsec-engine::load_commit_dag` / `merge_heads` read each commit's `(device_id, version)` for the
rollback gates via `open_signed_commit` **without** calling `verify_commit`. The engine's own doc-comment
states this as a caller precondition ("the caller signature-verified … reachable commits against the
roster"), but the caller `sync_ref` verifies only the **head** signature (`resolve_head_signer`). (The
pull path `pull_to` *does* call `verify_commit` on the head's commit.) Not exploitable by the in-scope
server adversary — the object AEAD + content-addressing + the member-signed head transitively
authenticate the whole reachable chain, so P3 holds — but the stated precondition is unmet, and a
malicious *current member* (outside the §3 threat model) could feed forged `device_id`/`version` into
another device's gate high-waters. Defense-in-depth + doc gap.

### F3 — LOW (latent) — §16 grant-side `min_algo` floor not enforced

`crates/secsec-client/src/repo.rs` hardcodes `ALGO_XWING` in `wrap_keyslot`; `enforce_min_algo` runs only
at cold-start (`open_repo` / `open_repo_remote`). §16 requires the granting/rotating device to select a
keyslot `algo_id ≥ min_algo` or abort. Benign today (X-Wing is the only algorithm), but a future
`SetMinAlgo(>1)` would make grants/rotations write keyslots the recipient rejects at cold-start
(`AlgoTooWeak`), bricking enrollment. Unreachable in practice — `SetMinAlgo` has no CLI surface.

### F4 — LOW (out of threat model) — `delete-keyslot` is a generic authorized write

`crates/secsec-server/src/lib.rs` `Request::DeleteKeyslot` requires only write-auth + the caller's own
keyslot existence; it is not bound to a legitimate revocation, so any rostered key can delete any
device's keyslot (a peer cold-start DoS). Moot against the in-scope adversaries (a malicious server
mutates its own store directly; a revoked device is rejected by `keyslot_exists`). Noted for the
flat-trust member model.

### F5 — INFO — `Server::new` defaults to `Authorized::Any`

`crates/secsec-server/src/lib.rs`. The deployed binary always calls `with_authorized_file` and
`run_serve` refuses to start without a usable `authorized_keys`, so production is gated. A library
consumer that constructs `Server::new` without `with_authorized_file` gets no connection gate. Footgun.

---

## Documentation vs code / doc vs doc

### F6 — LOW — `has_for_push(push_id, ids)` (§15 / I3) is not wired over QUIC

Design §15.1/I3 says a crash-resumed push uses `has_for_push(push_id, ids)` to re-upload only the
still-missing gap, but `secsec-proto::wire::Request` has no such variant and
`secsec-client::quic::QuicRemote::has_for_push` falls back to durable-only `has`. The result is correct
(re-staging is idempotent) but re-uploads the whole not-yet-promoted set on resume rather than the gap.
The in-process `MemRemote` implements the real semantics; the QUIC transport does not.

### F7 — LOW — `bin/secsec/README.md` invents a `--name ref` flag and omits subcommands

The README documents `sync <dir> … [--name ref]`. No such clap argument exists (the `Sync` variant has
`dir`, `--server`, `--invite`, `--once`, `--key`, `--passphrase-stdin`; `ref_name` is hardcoded `"main"`),
and design §2 explicitly states "there is **no `--name`/multi-ref capability**." The subcommand table
also omits `hostpin`, `log`, `restore`, and `reset`, all of which are implemented (design §2 scopes
`hostpin`/`log`/`restore`).

### F8 — LOW — `secsec-engine/README.md` documents a nonexistent public `reconcile(...)`

It lists `reconcile(base, ours, theirs, …) -> Reconciled` as public API; the code has a private
`merge_node_maps` plus the public `merge_heads`.

### F9 — LOW — `secsec-sync/README.md` lists a nonexistent `is_head_successor`

No such function exists in `secsec-sync`.

### F10 — LOW — `secsec-server/README.md` lists a nonexistent `Authorized::Static` and `with_authorized(set)`

The code's `Authorized` enum has only `Any` and `File`, and the only setter is `with_authorized_file`.

### F11 — INFO — "nine derivations" undercount

Design §9.5 and `secsec-kdf/README.md` say there are nine KAT'd derivations (eight `derive_key` +
`mk_commit`). The code actually has ten `derive_key` sites — the §9.5 eight plus `obj_key` (§9.4) and
`data_keyhist_key` (§8.2). `data_keyhist_key` has a round-trip test (in `secsec-roster`) and a
distinctness test (in `secsec-kdf`) but no frozen KAT vector.

### F12 — INFO — Per-crate README "Public API" sections list `pub(crate)`/test-only items

Several READMEs describe crate-internal helpers as public API — e.g. transport
(`PinnedServerVerifier`, `ConnectionAuth`, `client_config`/`server_config`, `SECSEC_VERSION`,
`NONCE_LEN`), proto (`args_*`), roster (`fold`, `entry_hash`, `peel_roster_keys`, `open_*_keyhist`), sig
(lists a nonexistent `x25519_public`; `x25519_secret` is `pub(crate)`), frame/object/chunk/pq constants,
snapshot (`sign_commit`, `MAX_NAME`), engine (`load_nodes`/`seal_nodes`); the client README omits the
public `history` module. Drift from the visibility-minimization pass (commit `6918e4a`).

---

## UI (minor)

### F13 — LOW — macOS `SecretCache.reveal()` returns un-zeroed plaintext

`ui/macos/secsec-menubar.swift:146-152`. `store()` scrubs its transient plaintext copy, but `reveal()`
builds a fresh `[UInt8]`/`Data` for the child's stdin and never zeroes it (left to ARC). The code itself
disclaims memory-dump resistance, so this is minor hardening only.

### F14 — INFO — macOS `chooseFolder()` doesn't clear the session passphrase cache

`ui/macos/secsec-menubar.swift:438-452`, unlike `chooseKey()`/`clearKey()` which both call
`cache.clear()`. A folder-only change reuses the cached passphrase (usually the same key — usually fine).

---

## Checked and confirmed NOT problems

- **Passphrase never in argv.** Both desktop UIs feed it over a stdin pipe; there is **no
  `--passphrase <value>` CLI flag**, so the systemd `SECSEC_OPTS` path cannot leak it (headless = an
  unencrypted `--key` only).
- **AEAD nonce reuse is impossible by construction.** Per-object unique `k_obj` (content-derived id)
  makes the fixed `nonce=0` sound; the Head and the sealed frontier use a fresh random nonce per write;
  keyslot and key-history keys are unique per wrap. KAT-frozen and byte-checked against the audited
  `chacha20poly1305` crate.
- The anti-rollback ROSTER anchor (P7), the genesis-bootstrap exception (own-keyslot only), the
  transitive revoke add-by closure, the prune head-binding CAS, atomic promote (I1), QUIC Retry + per-IP
  connection rate limiting with a real wall-clock `now()`, the setuid/path-traversal/control-character
  restore guards, X-Wing draft-10 conformance, and the cold-start `min_algo` floor are all implemented
  correctly.
- The `cargo-audit` ignore of `RUSTSEC-2023-0071` (`rsa` Marvin attack) is justified — `rsa` is an
  optional `ssh-key` dependency never compiled in (Ed25519-only), so it is not in the build graph.
