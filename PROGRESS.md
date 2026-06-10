# secsec — progress tracker

Running status of milestones (M), risks (R), and forward-carried debts. Updated as work lands.
(`finaldesign.md` = spec; `IMPLEMENTATION.md` = plan.)

## Snapshot

- **18 crates + `secsec` binary** · ~230 tests · clippy `-D warnings` + fmt clean · spec↔code↔doc consistent.
- **The product runs:** `secsec init` / `serve` / `sync` (+ `--watch`) — two devices live-sync a folder through a
  blind server over QUIC, concurrent, no data loss. Verified end-to-end with real processes.

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
| M7 Later | PQ keyslot (X-Wing), stdio/SSH transport | ⏳ in scope (RSA + WebDAV **dropped**) |

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

**M6 follow-ups (small, non-blocking):** receipt host-key signature (§15 defence-in-depth); fork-event
log to disk; device-to-device gossip transport (thin layer over the same fork check).

## Risks

R1 verifier, R2 CTX, R3 HPKE, R4 rollback-merge, R5 fold/cold-start, R6 GC, R7 canonical, R8 keyed-CDC
— **all closed**.

## Forward-carried debts — active work plan (tasks #6–16)

Being worked through smallest→largest, tested+committed per slice:

- [ ] #7 `--host-fp` fingerprint pinning (verifier hash-compare path; CLI flag)
- [ ] #8 fork-event log to disk (§10 step 3 audit persistence)
- [ ] #9 receipt host-key signature (§15 defence-in-depth)
- [ ] #10 device-to-device gossip transport (thin layer over fork_check)
- [ ] #11 **fuzz targets** (§3 CI gate — one per decoder)
- [ ] #12 `xtask` (reproducible musl build + mechanical vector generation)
- [ ] #13 rotation flow + rotation-era cold-start (§8.2/§8.4; removes genesis-only restriction)
- [ ] #14 interactive grant ceremony (§7 SAS enrollment of a 2nd device)
- [ ] #15 M7 hybrid-PQ keyslot (X-Wing)
- [ ] #16 M7 stdio/SSH transport

Dropped from scope: RSA device keys, WebDAV.
Residual (not a debt): §8.5 seal-before-push ordering is conservative (crash-safe via FF retry).

## Log (most recent first)

- Fixed §15 `all_heads_hash` (head-blob hashes). Recovery crate (§8.6). Min-algo verified (§16).
- Closed concurrency caveats: lock-free store (interior-mutable server state, `Arc<Server>`), racing-writers test.
- `restore` preserves mtime/mode → snapshot idempotent (fixed clone-then-sync CommitReplay).
- `sync --watch` continuous loop; server now serves clients concurrently.
- `secsec sync` runnable; bidirectional `sync_once` with base-tracking; cold-start over remote.
- `secsec init` (§7 genesis) + cold-start; get-roster/get-keyslot/get-ref wire ops.
