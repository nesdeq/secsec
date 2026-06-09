# secsec — Implementation Plan

Blueprint for building the system specified in `finaldesign.md`. This document is the agreed
plan **before** code: verified crate selection, workspace layout, test/assurance strategy, the
risk register for the security-critical cores, and phased milestones. It does not restate the
design — read `finaldesign.md` for *what*; this is *how*.

> **Posture.** secsec is a security-critical cryptosystem whose entire value is "the server
> cannot read your data." A subtle bug is silent and total, so **correctness and provability
> dominate speed**. Two hard rules: (1) no security-critical module is trusted until its tests
> prove it (KATs + property + negative tests, committed *with* the code); (2) the finished
> implementation gets an **independent professional cryptographic review before it touches real
> data**. This plan gets us to audit-*ready*; it does not replace the audit.

**v1 scope (locked 2026-06-09):** transport is **QUIC-only** (stdio/SSH mode deferred post-v1);
device keys are **Ed25519-only** (RSA/OAEP deferred); targets are **Linux, macOS, Windows**.
Implications: the custom QUIC verifier (R1) is the *sole* transport-auth path and thus top
priority; `host_id` = pinned-SPKI hash; the `rsa` crate and `russh` drop out of the v1 dependency
set; the §11 stdio channel-binding work is out of v1 scope; key-memory locking needs a
cross-platform shim (`mlock` / `VirtualLock`). `finaldesign.md` remains the full spec — RSA and
stdio are valid parts of it, just not v1.

---

## 1. Crate selection (verified June 2026)

Versions are pinned at implementation start; the **capability** column is what was verified now.
"⚠ verify" = re-check at first use before depending on it.

| Role | Crate | Status / capability verified | Notes & risks |
|---|---|---|---|
| SSHSIG signing | `ssh-key` (RustCrypto) | ✓ SSHSIG with **namespace** domain-sep: `PrivateKey::sign(ns, hash, msg)` / `PublicKey::verify(ns, msg, sig)`; low-level "message to sign" hook for agent/hardware keys. MSRV 1.85. | Exactly matches §9.6's namespaced design. Enable per-alg crypto features. |
| Transport | `quinn` + `rustls` 0.23 | ✓ Custom `ServerCertVerifier` lives in `rustls::client::danger`; must impl `verify_server_cert` + `verify_tls12/tls13_signature` + `supported_verify_schemes`. | **H2 hotspot.** Use the safe pattern: compare leaf SPKI to the pin, **delegate** `verify_tls13_signature` to the provider helper (never stub). ⚠ verify current `quinn` exposes `export_keying_material` on `Connection` (was historically a plumbing gap) — else the §11 TLS-exporter channel binding needs the documented fallback. |
| Committing AEAD (CTX) | `chacha20poly1305` + `poly1305` (+ `chacha20`) | ✓ Detached-tag API exists; standalone `poly1305` crate exists. | **CTX hotspot.** No drop-in committing-AEAD crate. We build `secsec-aead`: derive one-time Poly1305 key from ChaCha20 block 0, recompute `T` over `(AD, ct)`, then `ctx_tag = BLAKE3::keyed_hash(...)`. `T` is never stored (§9.4). Fiddly; gets the most tests. |
| Hash / KDF | `blake3` | ✓ `keyed_hash` + `derive_key` (context-string KDF). | Backbone of §9.5; one `keyed_hash` exception (`mk_commit`). |
| ECDH / sign keys | `x25519-dalek`, `ed25519-dalek` | ✓ mature. | Ed25519→X25519 birational map (age/ssh-to-age precedent). ⚠ enforce low-order-point rejection (see HPKE row). |
| Classical keyslot KEM | `hpke` (rozbb/rust-hpke) | ✓ RFC 9180 base mode, custom `info`, `X25519HkdfSha256` + `ChaCha20Poly1305`; Cloudflare-reviewed v0.8. | **Prefer `hpke` over `hpke-rs`:** `hpke-rs` had **two CVEs disclosed May 2026** — missing RFC 9180 §7.1.4 zero-shared-secret check (low-order point → all-zero SS) and a `u32` seq-counter nonce wrap. Whatever we pick MUST do the zero-SS check; add a low-order-point negative test. |
| PQ KEM (later) | ML-KEM: `libcrux-ml-kem`; hybrid: `x-wing` | ✓ `libcrux-ml-kem` is **formally verified** (FIPS 203, all sizes, includes pubkey/privkey validation). `x-wing` (RustCrypto) is `0.1.0-rc.0`. | **Mismatch:** `x-wing` tracks draft-06; `finaldesign §17` cites draft-10 (label-first combiner). Resolve before PQ work: either pin the crate's draft and footnote the spec, or wait for a draft-10/final crate. Deferred to M7 regardless. RustCrypto KEMs are **unaudited**; `libcrux` is the assurance pick for ML-KEM. |
| RSA keyslot | `rsa` | **Deferred (post-v1)** — Ed25519-only for v1. | When added: OAEP, label `b"secsec-keyslot-v1"`, SHA-256, MGF1-SHA-256. |
| Passphrase KDF | `argon2` | ✓ Argon2id, params configurable (§19: m=64 MiB, t=3, p=1). | Recovery path only. |
| Chunking | `fastcdc` | ⚠ **verify gear-table seeding** from `cdc_seed[gen]` (§9.7 keyed CDC). | If the crate doesn't expose a custom/keyed gear table, fork or implement keyed FastCDC. Material risk — check early. |
| Index / store | `redb` | ⚠ verify current stable; embedded, no external DB. | Server index holds only `{id,size,gen,pack-offset}` (§13). |
| FS watch | `notify` | ✓ inotify/FSEvents/ReadDirectoryChangesW. | Drives commit-on-change (§10). |
| stdio/SSH mode | `russh` | **Deferred (post-v1)** — QUIC-only for v1. | When added: verify `session_id()`/exchange hash `H` is reachable from a subsystem (§11 binding depends on it). |
| Serialization | `serde` + `postcard` | ⚠ canonical profile / **verify-over-received-bytes** discipline. | §9.3 canonicality is load-bearing for ids & signatures. Verify signatures over the exact received bytes; reject trailing/non-canonical input. Fuzz the decoder. |
| Async | `tokio` | ✓ | — |
| Key hygiene | `zeroize`, `secrecy`, `subtle`, `getrandom`, `region` | ✓ (`region` = cross-platform lock) | §18: zeroize + cross-platform lock (`mlock`/`VirtualLock` via `region`), constant-time via `subtle`, OS CSPRNG only. |

---

## 2. Workspace & module layout

One repository, a Cargo **workspace**, producing a single static binary (`secsec`) whose
subcommands are client; `secsec serve` is the server. Split into focused libs so the
security-critical cores are small, independently testable, and separately reviewable.

```
secsec/
├── crates/
│   ├── secsec-canon/     §9.3  canonical serialization; verify-over-received-bytes; fuzzed
│   ├── secsec-aead/      §9.4  CTX/CMT-4 committing AEAD (the foundation primitive)
│   ├── secsec-kdf/       §5,§9.5  BLAKE3 key hierarchy, mk_commit, all derivations + KATs
│   ├── secsec-frame/     §9.1  FRAME, object types, pre-alloc bounds (decompression/alloc-bomb guards)
│   ├── secsec-object/    §9.2  content-addressing, seal/open + 3-way verify, chunk padding
│   ├── secsec-chunk/     §9.7  keyed FastCDC + padding
│   ├── secsec-snapshot/  §6    Tree/Commit object graph + directory snapshot/restore
│   ├── secsec-store/     §13   redb content-addressed blob store (server side)
│   ├── secsec-sig/       §9.6  SSHSIG namespaces, verifier (alg pinning, negative tests)
│   ├── secsec-keyslot/   §8.3  HPKE master-key wrap, mk_commit authenticity
│   ├── secsec-roster/    §8    sigchain fold/succession, per-entry AEAD, roster-key history, generations, enrollment
│   ├── secsec-sync/      §10   refs, cas-head, rollback-aware merge (storage-free Node model), fork detection
│   ├── secsec-engine/    §10   snapshot-tree ↔ merge-node bridge, three-way reconcile to the store
│   ├── secsec-remote/    §14,§15  multi-remote reconcile, quorum, hardened GC
│   ├── secsec-transport/ §11   QUIC+TLS pinned verifier, stdio mode, auth, channel binding
│   ├── secsec-proto/     §12   wire protocol, RPC framing, write/read-auth, rate limits
│   ├── secsec-client/          orchestration: watcher, commit, sync loop, recovery
│   └── secsec-server/          serve loop, quota/rate-limit enforcement, GC executor
├── bin/secsec            thin CLI over the crates
├── vectors/              committed KAT / cross-impl test vectors (per §9.5: all 8 derivations, etc.)
├── fuzz/                 cargo-fuzz targets, one per decoder
└── xtask/                build/release (reproducible musl), vector generation
```

Dependency direction is strictly downward (canon → aead/kdf/frame → object/sig/chunk →
snapshot/store/keyslot/roster → sync → engine → remote/transport/proto → client/server). No security-critical
crate depends on a higher layer. (`secsec-object`, `secsec-snapshot`, `secsec-keyslot` were split
out as their own crates from the original `object`/`roster` grouping, keeping each core small and
separately reviewable. `secsec-engine` is split from `secsec-sync` on the same principle: §10's
merge/dag/rollback logic stays **storage-free and purely testable** inside `secsec-sync`, while the
bridge that materializes stored trees into the merge model, re-seals the result, and authors the
signed merge commit — the only §10 code that touches `store`+`snapshot` — lives in `secsec-engine`.
`secsec-client` orchestrates the watcher, push/pull, and multi-remote loop on top of it.)

---

## 3. Test & assurance strategy (non-negotiable)

Per security-critical crate, **before it is built upon**:

- **Known-answer vectors** committed in `vectors/`: every §9.5 derivation (all 8), CTX
  encrypt/decrypt, `mk_commit`, SAS, HPKE seal/open, content-ids. Where an external standard
  exists (HPKE RFC 9180 §A, X-Wing draft §A), test against **its** published vectors.
- **Property tests** (`proptest`): AEAD round-trips; tamper-any-byte ⇒ reject; CTX commitment —
  *no ciphertext opens under two distinct (key, AD) pairs*; canonical encode/decode is a bijection
  and rejects non-canonical input; merge is commutative/associative where the spec says so.
- **Mandatory negative tests** (these are the ship-broken spots):
  - rustls verifier: wrong pinned key fails; tampered handshake fails; `rsa-sha2-256` sig fails.
  - HPKE: low-order / identity public key ⇒ rejected (the `hpke-rs` 2026 bug class).
  - SSHSIG: wrong namespace fails; cross-namespace reuse fails.
  - rollback merge: stale sibling below frontier ⇒ rejected & alarmed.
- **Fuzzing** (`cargo-fuzz`): one target per decoder (frame, object, sigchain entry, wire RPC);
  must survive the pre-alloc bounds of §19 without OOM/panic.
- **Differential / model tests:** sigchain fold against a reference state-machine model; GC
  keep-set against a brute-force reference on small graphs; multi-writer GC race simulation.
- **Nonce-misuse guard by construction:** key types are single-use newtypes; there is no API that
  takes a long-lived key + a caller-supplied counter (this is exactly the bug that bit `hpke-rs`).

**CI gates (must be green to merge):** `clippy -D warnings`, `cargo test`, `cargo fuzz` smoke,
`cargo-audit`, `cargo-vet`, all committed vectors. Reproducible static `musl` build via `xtask`.
No OpenSSL anywhere.

---

## 4. Risk register — the cores that get the most scrutiny

| # | Hotspot | Failure mode | Mitigation |
|---|---|---|---|
| R1 | Custom rustls verifier (§11) | `return Ok(())` / stubbed sig check silently disables auth | Safe pattern (SPKI pin + delegated `verify_tls13_signature`); negative tests gate CI |
| R2 | CTX from raw Poly1305 (§9.4) | wrong T recomputation; using high-level open; non-constant-time | `secsec-aead` isolated; KATs; committing property test; `subtle` compares |
| R3 | HPKE keyslot seal (§8.3) | low-order point → zero shared secret; nonce wrap | crate with §7.1.4 check; low-order-point negative test; single-shot only |
| R4 | Rollback-aware merge (§10) | replayed old commit steers merge; lost write | frontier/version/HWM gates; adversarial replay property tests; keep-both default |
| R5 | Sigchain fold + cold-start + roster-key peel (§8) | mis-fold → wrong membership; bootstrap deadlock | model-based tests; explicit cold-start order; RFP-anchor + mk_commit checks |
| R6 | Hardened GC (§15) | deletes live data under concurrency / ref-hiding | fail-safe-on-missing; serialization CAS (all_heads_hash/roster_seq/put_epoch); keep-everything default; multi-writer sim |
| R7 | Canonical serialization (§9.3) | malleability → signature bypass | verify over received bytes; reject non-canonical; fuzz |
| R8 | Keyed FastCDC (§9.7) | crate can't seed gear table → unkeyed boundaries | verify/fork early (M2 gating decision) |

---

## 5. Phased milestones (exit criteria, not dates)

- **M0 — Foundation.** Workspace, CI, `secsec-canon`, `secsec-frame`, `secsec-aead`,
  `secsec-kdf`. **Exit:** all derivation + CTX KATs committed and green; fuzz targets run;
  committing property test passes. *Nothing builds on these until this is done.*
- **M1 — Object plane.** `secsec-object`, `secsec-chunk`, `secsec-store`; push/pull/restore
  against a local in-process fake server. **Exit:** round-trip a real directory tree; fetch
  re-verifies every id; keyed-CDC decision resolved (R8).
- **M2 — Identity & roster.** `secsec-roster`: keyslots (HPKE), enrollment (RFP/SAS commitment),
  generations/rotation, roster-key history, fold/succession, write/read-auth gate.
  **Exit:** model-based fold tests; enrollment MITM negative tests; revoke⇒rotate works.
- **M3 — Sync.** `secsec-sync`: refs, `cas-head`, rollback-aware three-way merge, fork detection.
  **Exit:** adversarial replay/rollback tests; conflict keep-both verified.
- **M4 — Transport.** `secsec-transport` + `secsec-proto`: QUIC + pinned verifier, channel-bound
  auth, rate limits/quotas. **Exit:** verifier negative tests (wrong key / tampered handshake /
  non-`ssh-ed25519` alg all fail); relay/MITM tests.
- **M5 — Live sync.** `secsec-engine` reconcile (snapshot-tree ↔ merge-node bridge, rollback gates,
  signed two-parent merge commits); head push/pull wiring (`build_head` → `cas-head`, fetch → verify
  → `merge_heads` → push); `notify` watcher → commit-on-change; the `secsec-client`/`secsec-server`
  orchestration end-to-end on one machine, then two.
- **M6 — Durability & recovery.** Multi-remote reconcile + quorum, hardened GC, recovery flow,
  downgrade/min-algo enforcement, gossip. **Exit:** multi-writer GC sim; quorum put→get→verify.
- **M7 — Later.** Hybrid-PQ keyslot (resolve X-Wing draft mismatch first), stdio/SSH transport,
  RSA device keys, WebDAV browse.
- **Audit gate.** Independent cryptographic review of the implementation before any production
  data. Treat its findings like §22 was treated: fix or consciously document.

---

## 6. How we work together

- **Vertical, test-anchored slices**, each reviewable and revertible; commit per slice.
- **Test-first on every crypto core** — the tests land in the same change as the code; I do not
  claim a security-critical module is correct without the tests that prove it.
- **Your review at each crypto boundary** (R1–R8). I draft; you (or an expert) sign off before we
  build on top.
- **Interactive main-thread loop** for the cores; **bounded workflows** only for parallel breadth
  (generating vector suites, scaffolding many similar modules) — never open-ended "until perfect"
  loops, never monolithic single-file mega-writes. (Both failure modes were observed during
  hardening; the guardrails are deliberate.)

---

## 7. Decisions

**Locked (2026-06-09):**
1. **Transport:** **QUIC-only** for v1 (stdio/SSH deferred). The custom verifier (R1) is the sole
   transport-auth path → top scrutiny.
2. **Device keys:** **Ed25519-only** for v1 (RSA/OAEP deferred). Keyslots seal via HPKE over the
   Ed25519→X25519 key; signing is `ssh-ed25519` only; the verifier rejects every other algorithm.
3. **Platforms:** **Linux, macOS, Windows.** Cross-platform `notify`; key-lock via `region`; no
   FUSE (WebDAV is the later browse path); reproducible static build is Linux/`musl`, with
   signed binaries on macOS/Windows.

**Recommended defaults (accepted unless you object):**
4. **HPKE crate:** `hpke` (rozbb, typed, Cloudflare-reviewed) — *not* pre-fix `hpke-rs`.
5. **ML-KEM crate (M7):** `libcrux-ml-kem` (formally verified); X-Wing draft mismatch resolved at M7.

**Still open (not blocking M0):**
6. **Audit sourcing** — who reviews the cores and when (per-milestone vs final gate).
