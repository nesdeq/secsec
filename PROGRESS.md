# secsec — progress tracker

Running status of milestones (M), risks (R), and forward-carried debts. Updated as work lands.
(`finaldesign.md` = spec; `IMPLEMENTATION.md` = plan.)

## Snapshot

- **20 crates + `secsec` binary** (+ `xtask` tooling, `fuzz/` cargo-fuzz layout) · 258 tests · clippy
  `-D warnings` + fmt clean · spec↔code↔doc consistent.
- **Full-source audit (2026-06-10):** read all ~18.3k LoC + the spec. Found **one** soundness/conformance
  defect — `secsec-pq` was non-conformant X-Wing (label-first + two independent seeds, hidden by an
  ignored KAT). Fixed + KAT-proven against the draft-10 vector. Then closed the §8.2 DATA key-history
  gap. Everything else is conformant; the rest are unbuilt spec features (below).
- **The product runs:** `secsec init` / `serve` / `sync` (+ `--watch`) — two devices live-sync a folder through a
  blind server over QUIC, concurrent, no data loss. Verified end-to-end with real processes.
- **All forward-carried debt (#6–16) closed.** M0–M7 functionally complete for v1 (RSA + WebDAV dropped).

## Milestones

| M | Scope | Status |
|---|---|---|
| M0 Foundation | canon/aead/kdf/frame | ✅ done |
| M1 Object plane | object/chunk/store, snapshot/restore | ✅ done |
| M2 Identity & roster | sigchain, keyslots, generations, rotate/revoke, SAS primitives | ✅ done · ⚠️ interactive grant ceremony not wired |
| M3 Sync | head, dag, merge, rollback gates, fork detection | ✅ done |
| M4 Transport | QUIC pinned verifier, §12 wire + server pipeline, limits | ✅ done |
| M5 Live sync | watcher, concurrent multi-client, clone/publish/pull/merge, init, frontier seal, `sync --watch` | ✅ done |
| M6 Durability & recovery | see below | ✅ **done** |
| M7 Later | PQ keyslot (X-Wing), stdio/SSH transport | ✅ **done** (RSA + WebDAV **dropped**) |

### M7 detail — done

- ✅ §17 hybrid-PQ keyslot (`secsec-pq`: X-Wing = ML-KEM-768 + X25519). **draft-10 conformant:**
  single-seed `SHAKE256(sk,96)` key expansion, **label-LAST** combiner, FIPS 203 §7.1 PCT.
  `xwing_kat` asserts byte-identity vs the draft-10 Appendix C vector (passing, **not** ignored).
  (Was non-conformant — label-first + two independent seeds — concealed by the ignored KAT; fixed.)
  **Not yet wired** into the `algo_id`/keyslot flow (reachable via a future `SetMinAlgo` bump).
- ✅ §11 stdio/SSH transport core: `SessionTranscript::new_stdio(H)` channel-binds the SSH exchange hash;
  `stream.rs` length-prefixed framing over any `AsyncRead`/`AsyncWrite` (alloc-bomb-guarded), `host_id =
  BLAKE3(K_S)`. **Follow-up (deployment-only, no security gain over pinned QUIC):** wiring a live `russh`
  subsystem to source `H`/`K_S` — this module is the transport-agnostic framing it rides on.

### M6 detail — all done

- ✅ §8.5 local frontier persistence (sealed under SSH-key)
- ✅ §8.6 recovery keyslot (`secsec-recovery`: code + passphrase/Argon2id, mk_commit-verified)
- ✅ §16 min-algo — verified complete for v1 (min_algo folded + compile-time floor; per-fetch algo check is M7)
- ✅ §15 `all_heads_hash` bug fixed (server-visible head-blob hashes, not encrypted head_version)
- ✅ §15 GC orchestration — arrival receipts + `gc` wire op + CAS-serialized handler + client driver
  (live-QUIC proven: sweeps garbage, keeps reachable, CAS fails on stale state). **R6 fully closed.**
- ✅ §14 multi-remote + quorum — `client::multiremote`: quorum put→get→verify (P15), sigchain
  cross-remote reconciliation (longest valid chain + rollback alarms), per-ref head-rollback detection.
- ✅ §10/§14 gossip — `client::gossip::cross_remote_fork_scan`: DAG-incomparable head detection across
  remotes → ForkEvent audit records (§10 step 3).

**M6 follow-ups (all done):** ✅ receipt host-key signature (§15 defence-in-depth); ✅ fork-event
log to disk; ✅ device-to-device gossip transport (thin layer over the same fork check).

## Risks

R1 verifier, R2 CTX, R3 HPKE, R4 rollback-merge, R5 fold/cold-start, R6 GC, R7 canonical, R8 keyed-CDC
— **all closed**.

## Forward-carried debts — all closed (tasks #6–16)

Worked through smallest→largest, tested+committed per slice:

- [x] #6 drop RSA + WebDAV from scope (spec/plan/tracking)
- [x] #7 `--host-fp` fingerprint pinning (verifier hash-compare path; CLI flag)
- [x] #8 fork-event log to disk (§10 step 3 audit persistence)
- [x] #9 receipt host-key signature (§15 defence-in-depth)
- [x] #10 device-to-device gossip transport (thin layer over fork_check)
- [x] #11 **fuzz targets** (§3 CI gate — one per decoder + stable robustness harness)
- [x] #12 `xtask` (reproducible musl build recipe + mechanical vector generation, 26 KATs)
- [x] #13 rotation flow + rotation-era cold-start (§8.2/§8.4; removes genesis-only restriction)
- [x] #14 interactive grant ceremony (§7 SAS enrollment of a 2nd device)
- [x] #15 M7 hybrid-PQ keyslot (X-Wing)
- [x] #16 M7 stdio/SSH transport (transcript channel-binding + generic byte-stream framing)

Dropped from scope: RSA device keys, WebDAV.
## Audit + closure (2026-06-10)

Full-source audit read all ~18.3k LoC + the spec. Found **one** soundness/conformance defect —
`secsec-pq` was non-conformant X-Wing (label-first combiner + two independent seeds, hidden by an
ignored KAT). Everything else was conformant. Fixed the defect and closed the unbuilt-feature gaps:

- ✅ **X-Wing conformance** — rewritten to draft-10 (single-seed `SHAKE256` keygen, label-LAST
  combiner, FIPS 203 §7.1 PCT). `xwing_kat` proves byte-identity vs the draft-10 vector (not ignored).
- ✅ **§8.2 DATA key-history** — layer (kdf/roster/store/wire/producer/peel) **+** the cross-generation
  read consumer: `open_object` resolves each object's generation via a `MasterKeys` resolver, so every
  fetch/push/merge/sync path crosses rotation boundaries (single-gen callers unchanged); the CLI builds
  the keyring at cold-start. Proven in-process, over live QUIC, and across a rotation boundary.
- ✅ **X-Wing `algo_id` integration** — keyslots are algo-tagged (`algo_id ‖ body`); a device's X-Wing
  key derives from its SSH private scalar (`xwing_seed`), its X-Wing public is published in the roster
  (`Genesis`/`AddDevice`), and init/grant/rotate wrap at the repo's `min_algo`. **§16** floor enforced
  at cold-start (reject a keyslot below `min_algo`). Proven by `xwing_keyslot_cold_start_and_min_algo_floor`.
- ✅ **§8.1 `HistoryReanchor`** — **removed** (spec-unsound per `finalrew.md`, never in code); both
  key-histories are never-trimmed.
- ✅ **CLI `rotate` / `grant` / `enroll-pubkey`** — membership management over the tested cores; the
  full lifecycle (init → enroll-pubkey → grant → rotate --revoke) is verified end-to-end with real SSH keys.

**Genuinely remaining** (each needs a real prerequisite, not deferral-avoidance):
- **CLI `recover`** — needs a recovery-keyslot *creation* flow first (`secsec_recovery` is tested, but
  no command/store-path ever creates a `/recovery` blob).
- **CLI `gc`** — `gc_collect` is tested over live QUIC, but a safe `gc_gen` needs persisted arrival
  receipts (the sync loop doesn't persist them yet); a manual `gc_gen` would bypass the §15 grace window.
- **§7 SAS rate-limit** (5/hr per D_pubkey) — belongs to an *automated two-party SAS protocol*; the SAS
  is human-mediated today (primitives `sas_commit`/`sas_value` exist), so the limit has no automated home.
- Live `russh` stdio `H`/`K_S` wiring (deployment-only, no security gain over pinned QUIC).

Residual (not debt): §8.5 seal-before-push ordering is conservative (crash-safe via FF retry).

## Log (most recent first)

- **All debt closed.** #16 stdio/SSH transport: `new_stdio(H)` transcript binding + generic
  `AsyncRead`/`AsyncWrite` framing (alloc-guarded). #15 X-Wing PQ keyslot (`secsec-pq`). #14 grant
  ceremony (`grant_device`, SAS commitment). #13 rotation (`rotate_repo`, multi-gen cold-start,
  per-gen sealing). #12 `xtask` (musl recipe + 26-KAT generator). #11 fuzz (7 targets + robustness
  harness). #10 gossip codec + fork log. #9 signed arrival receipts. #8 fork-event disk log. #7
  `--host-fp` pinning. #6 RSA/WebDAV dropped.
- Fixed §15 `all_heads_hash` (head-blob hashes). Recovery crate (§8.6). Min-algo verified (§16).
- Closed concurrency caveats: lock-free store (interior-mutable server state, `Arc<Server>`), racing-writers test.
- `restore` preserves mtime/mode → snapshot idempotent (fixed clone-then-sync CommitReplay).
- `sync --watch` continuous loop; server now serves clients concurrently.
- `secsec sync` runnable; bidirectional `sync_once` with base-tracking; cold-start over remote.
- `secsec init` (§7 genesis) + cold-start; get-roster/get-keyslot/get-ref wire ops.
