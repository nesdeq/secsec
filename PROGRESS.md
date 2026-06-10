# secsec — progress tracker

Status of milestones (M) and risks (R). (`finaldesign.md` = spec; `IMPLEMENTATION.md` = plan.)

## Snapshot

- **19 crates + `secsec` binary** (+ `xtask` tooling, `fuzz/` cargo-fuzz layout) · **257 tests** · clippy
  `-D warnings` + fmt clean · spec ↔ code ↔ doc consistent.
- **Transport is QUIC/TLS-only.** RSA device keys, WebDAV, and the stdio/SSH transport were **dropped
  from scope** (cut from code *and* spec): stdio adds nothing over the pinned QUIC host key, and RSA is
  superseded by the Ed25519-only device key. The spec describes exactly what ships.
- **Post-quantum is mandatory.** X-Wing (ML-KEM-768 ⊕ X25519, draft-10) is the **only** keyslot
  algorithm; there is no classical keyslot to downgrade to.
- **The product runs end-to-end** with real processes over QUIC: `init` / `serve` / `sync` (+ `--watch`)
  / `rotate` / `enroll-pubkey` / `grant` / `recovery-init` / `recover` / `gc`.

## Milestones — all done

| M | Scope | Status |
|---|---|---|
| M0 Foundation | canon/aead/kdf/frame | ✅ done |
| M1 Object plane | object/chunk/store, snapshot/restore | ✅ done |
| M2 Identity & roster | sigchain, keyslots, generations, rotate/revoke, SAS | ✅ done |
| M3 Sync | head, dag, merge, rollback gates, fork detection | ✅ done |
| M4 Transport | QUIC pinned verifier, §12 wire + server pipeline, limits | ✅ done |
| M5 Live sync | watcher, concurrent multi-client, clone/publish/pull/merge, init, frontier seal, `--watch` | ✅ done |
| M6 Durability & recovery | frontier seal, recovery keyslot + `recover`, min-algo, GC, multi-remote, gossip | ✅ done |
| M7 PQ keyslot | X-Wing (mandatory), full algo_id/keyslot integration | ✅ done |

## Risks — all closed

R1 verifier · R2 CTX committing AEAD · R3 keyslot KEM (now X-Wing) · R4 rollback-merge · R5
fold/cold-start · R6 GC · R7 canonical encoding · R8 keyed-CDC.

## What each surface does

- **§17 hybrid-PQ keyslot (`secsec-pq`):** X-Wing = ML-KEM-768 + X25519, **draft-10 conformant** —
  single-seed `SHAKE256(sk,96)` key expansion, **label-LAST** combiner, FIPS 203 §7.1 PCT. `xwing_kat`
  asserts byte-identity vs the draft-10 Appendix C vector (passing, not ignored). The device's X-Wing
  seed is `derive_key("secsec-xwing-seed-v1", ed25519_seed)` — derived from the raw Ed25519 **seed**,
  not the clamped scalar, so a quantum adversary cannot reconstruct it from the public Ed25519 key (§8.3).
- **PQ-mandatory keyslot integration (`repo.rs`):** keyslots are `algo_id ‖ body` with X-Wing
  (`algo_id = 2`) the only algorithm; `init`/`grant`/`rotate` wrap to each member's roster-published
  X-Wing public; cold-start dispatches by `algo_id` and enforces the §16 floor (`min_algo.max(X-Wing)`).
- **§8.2 DATA key-history:** the cross-generation read path — `open_object` resolves each object's
  generation via a `MasterKeys` resolver, so fetch/push/merge/sync cross rotation boundaries; the CLI
  builds the keyring at cold-start. Proven in-process, over live QUIC, and across a rotation.
- **§8.6 recovery (`secsec-recovery` + `repo.rs` + CLI):** `recovery-init` seals the master key under a
  fresh 256-bit code (CTX/CMT-4); `recover` reconstructs the key from the code alone (anchored to the
  RFP via the chain fold) and restores the ref's tree locally (`restore_ref_local`). Round-trip,
  wrong-code, stale-after-rotation, and byte-identical-restore tests pass.
- **§15 GC end-to-end:** `sync` surfaces arrival receipts and persists them to a local receipt log;
  `gc` reads the log, picks a grace-aged `gc_gen` + `put_epoch`, fetches the keep-set local (fail-safe),
  and issues the CAS sweep. The sweep + CAS-conflict path are proven over live QUIC.
- **§7 SAS grant rate-limit (`enroll.rs`):** the granter caps SAS/grant sessions at 5 per `D_pubkey`
  per rolling hour in local state; the `grant` CLI enforces it against a log beside the store.
- **§14/§10 multi-remote + gossip:** quorum put→get→verify, cross-remote sigchain reconciliation
  (longest valid chain + rollback alarms), DAG-incomparable fork detection → audit records.

## Log (most recent first)

- **Final push — project complete.** PQ made mandatory (X-Wing the only keyslot; classical removed).
  `recovery-init`/`recover` finished end-to-end (creation → recover → local restore). GC finished
  end-to-end (sync persists arrival receipts → `gc` consumes them → CAS sweep). §7 grant rate-limit
  wired into the `grant` CLI. stdio/SSH transport **cut** from code and spec (QUIC-only); RSA
  references purged from the spec (Ed25519-only). Full workspace: 257 tests, clippy `-D warnings`, fmt.
- X-Wing rewritten to draft-10 (the one audit defect) + KAT-proven; X-Wing seed derived from the
  Ed25519 seed (PQ-safe). `HistoryReanchor` removed (spec-unsound). `secsec-keyslot` crate deleted.
- `all_heads_hash` fixed (server-visible head-blob hashes). Recovery crate (§8.6). Min-algo (§16).
- Lock-free store (`Arc<Server>`); `restore` preserves mtime/mode (idempotent snapshot).
- `sync --watch` continuous loop; concurrent server. `init` genesis + cold-start over the wire.
