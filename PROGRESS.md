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
| M6 Durability & recovery | see below | 🟡 in progress |
| M7 Later | PQ keyslot, stdio, RSA, WebDAV | ❌ deferred |

### M6 detail

- ✅ §8.5 local frontier persistence (sealed under SSH-key)
- ✅ §8.6 recovery keyslot (`secsec-recovery`: code + passphrase/Argon2id, mk_commit-verified)
- ✅ §16 min-algo — verified complete for v1 (min_algo folded + compile-time floor; per-fetch algo check is M7)
- ✅ §15 `all_heads_hash` bug fixed (server-visible head-blob hashes, not encrypted head_version)
- ✅ §15 GC orchestration — arrival receipts + `gc` wire op + CAS-serialized handler + client driver
  (live-QUIC proven: sweeps garbage, keeps reachable, CAS fails on stale state). **R6 fully closed.**
  Receipt *signature* (host-key SIG, §15 defence-in-depth) is the one follow-up.
- ⏳ §14 multi-remote + quorum (`secsec-remote`)
- ⏳ §10/§14 gossip (head-hash cross-check)

## Risks

R1 verifier, R2 CTX, R3 HPKE, R4 rollback-merge, R5 fold/cold-start, R7 canonical, R8 keyed-CDC — all closed.
R6 hardened GC — risk **closed** (fail-safe keep-set + serialization + sweep, all tested); orchestration wiring ⏳.

## Forward-carried debts

1. **Fuzz targets** — §3 CI gate, still zero (no `fuzz/`).
2. GC orchestration (§15) — in progress.
3. Multi-remote + quorum (§14) — not built.
4. Rotation flow + rotation-era cold-start — genesis-only today.
5. Grant ceremony (§7) — SAS primitives exist; interactive flow not wired.
6. `--host-fp` fingerprint pinning — verifier compares full SPKI (uses `--host-cert`).
7. `xtask` / reproducible build + mechanical vector generation — not built.
8. §8.5 seal-before-push ordering — conservative (crash-safe via FF retry), not strictly enforced in `sync_ref`.

## Log (most recent first)

- Fixed §15 `all_heads_hash` (head-blob hashes). Recovery crate (§8.6). Min-algo verified (§16).
- Closed concurrency caveats: lock-free store (interior-mutable server state, `Arc<Server>`), racing-writers test.
- `restore` preserves mtime/mode → snapshot idempotent (fixed clone-then-sync CommitReplay).
- `sync --watch` continuous loop; server now serves clients concurrently.
- `secsec sync` runnable; bidirectional `sync_once` with base-tracking; cold-start over remote.
- `secsec init` (§7 genesis) + cold-start; get-roster/get-keyslot/get-ref wire ops.
