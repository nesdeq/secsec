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

**v1 scope (locked 2026-06-09; RSA/WebDAV/stdio dropped 2026-06-10):** transport is **QUIC/TLS-only**
— the stdio/SSH mode was cut from code *and* spec (it adds nothing over the pinned QUIC host key, §11).
Device keys are **Ed25519-only** (RSA dropped from scope); targets are **Linux, macOS, Windows**.
**WebDAV browse is dropped.** Implications: the custom QUIC verifier (R1) is the *sole* transport-auth
path and thus top priority; `host_id` = pinned-SPKI hash; the `rsa` and `russh` crates drop out
entirely; key-memory locking needs a cross-platform shim (`mlock` / `VirtualLock`). `finaldesign.md`
describes exactly what ships — QUIC-only, Ed25519-only, X-Wing-mandatory; the dropped paths are gone
from the spec, not merely demoted.

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
| ECDH / sign keys | `x25519-dalek`, `ed25519-dalek` | ✓ mature. | Ed25519→X25519 birational map (age/ssh-to-age precedent); the X25519 half of the X-Wing keyslot derives from the Ed25519 seed. ⚠ enforce low-order-point rejection (see the Keyslot KEM row). |
| Keyslot KEM (the only one) | ML-KEM: `libcrux-ml-kem`; X-Wing in-crate (`secsec-pq`) + `x25519-dalek` | ✓ `libcrux-ml-kem` 0.0.9 is **formally verified** (FIPS 203 final, all sizes). X-Wing built directly on it (no third-party X-Wing crate). | **Done + mandatory.** `secsec-pq` implements draft-connolly-cfrg-xwing-kem-**10** exactly: single-seed `SHAKE256(sk,96)` key expansion, **label-LAST** combiner, derand encaps, FIPS 203 §7.1 PCT. `xwing_kat` asserts byte-identity vs the draft-10 Appendix C vector. **Wired + mandatory:** keyslots are `algo_id ‖ body` with X-Wing (`algo_id = 2`) the only algorithm; init/grant/rotate wrap it; cold-start enforces the §16 floor. The classical X25519/HPKE keyslot and the RSA-OAEP variant were **removed** (a pre-quantum keyslot is the one harvestable asymmetric exposure, §17) — so no `hpke` or `rsa` crate is used. |
| Passphrase KDF | `argon2` | ✓ Argon2id, params configurable (§19: m=64 MiB, t=3, p=1). | Recovery path only. |
| Chunking | `fastcdc` | ⚠ **verify gear-table seeding** from `cdc_seed[gen]` (§9.7 keyed CDC). | If the crate doesn't expose a custom/keyed gear table, fork or implement keyed FastCDC. Material risk — check early. |
| Index / store | `redb` | ⚠ verify current stable; embedded, no external DB. | Server index holds only `{id,size,gen,pack-offset}` (§13). |
| FS watch | `notify` | ✓ inotify/FSEvents/ReadDirectoryChangesW. | Drives commit-on-change (§10). |
| stdio/SSH mode | — | **Dropped from scope** — QUIC/TLS is the sole transport. | No `russh`. stdio adds nothing over the pinned QUIC host key (§11); cut from code and spec. |
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
│   ├── secsec-pq/        §8.3,§17  X-Wing keyslot (ML-KEM-768 ⊕ X25519, the only keyslot), mk_commit authenticity, draft-10 KAT
│   ├── secsec-recovery/  §8.6  recovery-code / passphrase (Argon2id) master-key wrap; RFP-anchored
│   ├── secsec-roster/    §8    sigchain fold/succession, per-entry AEAD, roster-key history, generations, enrollment
│   ├── secsec-sync/      §10   refs, cas-head, rollback-aware merge (storage-free Node model), fork detection
│   ├── secsec-engine/    §10   snapshot-tree ↔ merge-node bridge, three-way reconcile to the store
│   ├── secsec-transport/ §11   QUIC+TLS pinned verifier, auth, channel binding
│   ├── secsec-proto/     §12   wire protocol, RPC framing, write/read-auth, rate limits, gc serialization (§15)
│   ├── secsec-client/    §10,§14,§15  orchestration: cold-start, watcher, sync loop, GC driver, multi-remote+quorum, recovery
│   └── secsec-server/          serve loop, quota/rate-limit + gc CAS enforcement, GC executor
├── bin/secsec            thin CLI over the crates
├── vectors/              committed KAT / cross-impl test vectors (per §9.5: all 8 derivations, etc.)
├── fuzz/                 cargo-fuzz targets, one per decoder
└── xtask/                build/release (reproducible musl), vector generation
```

Dependency direction is strictly downward (canon → aead/kdf/frame → object/sig/chunk →
snapshot/store/keyslot/roster → sync → engine → transport/proto → client/server). No security-critical
crate depends on a higher layer. (`secsec-object`, `secsec-snapshot`, `secsec-keyslot` were split
out as their own crates from the original `object`/`roster` grouping, keeping each core small and
separately reviewable. `secsec-engine` is split from `secsec-sync` on the same principle: §10's
merge/dag/rollback logic stays **storage-free and purely testable** inside `secsec-sync`, while the
bridge that materializes stored trees into the merge model, re-seals the result, and authors the
signed merge commit — the only §10 code that touches `store`+`snapshot` — lives in `secsec-engine`.
`secsec-client` orchestrates the watcher, push/pull, and multi-remote loop on top of it.)

> **Deviation (signed off):** the plan listed a separate `secsec-remote` crate (§14/§15) *below*
> `client`. In implementation, §14 multi-remote/quorum and the §15 GC driver both build **on** the
> `Remote` trait, which lives in `secsec-client` (the abstraction over an object+ref store, in-process
> or over QUIC). A crate below `client` therefore cannot host them without inverting the layering.
> They live in `secsec-client` (`multiremote.rs`, `gc.rs`); the §15 *serialization hashes* are in
> `secsec-proto::gc` and the *executor + CAS enforcement* in `secsec-store`/`secsec-server`. The
> `secsec-remote` crate is dropped, not deferred.

---

## 3. Test & assurance strategy (non-negotiable)

Per security-critical crate, **before it is built upon**:

- **Known-answer vectors** committed in `vectors/`: every §9.5 derivation (all 8), CTX
  encrypt/decrypt, `mk_commit`, SAS, X-Wing keyslot wrap/unwrap, content-ids. Where an external
  standard exists (X-Wing draft-10 Appendix C), test against **its** published vectors.
- **Property tests** (`proptest`): AEAD round-trips; tamper-any-byte ⇒ reject; CTX commitment —
  *no ciphertext opens under two distinct (key, AD) pairs*; canonical encode/decode is a bijection
  and rejects non-canonical input; merge is commutative/associative where the spec says so.
- **Mandatory negative tests** (these are the ship-broken spots):
  - rustls verifier: wrong pinned key fails; tampered handshake fails; any non-`ssh-ed25519` sig
    algorithm fails (device keys are Ed25519-only).
  - X-Wing keyslot: a non-X-Wing `algo_id` ⇒ rejected; a keyslot below `min_algo` ⇒ rejected (§16).
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
| R3 | X-Wing keyslot seal (§8.3/§17) | non-conformant combiner/seed handling; low-order X25519 point | draft-10 KAT (byte-identity); FIPS 203 §7.1 PCT; X-Wing seed from the Ed25519 seed (not the scalar); CTX-committing AEAD over the wrap |
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
- **M7 — Hybrid-PQ keyslot (done).** X-Wing (draft-10 conformant) is **mandatory** — the only keyslot
  algorithm, fully wired through `algo_id`/init/grant/rotate and the §16 floor. **(RSA device keys,
  WebDAV browse, and the stdio/SSH transport are dropped from scope — cut from code *and* spec, not
  deferred. Ed25519 is strictly better than RSA; WebDAV is a convenience the core sync does not need;
  stdio adds nothing over the pinned QUIC host key.)**
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

**Locked:**
1. **Transport:** **QUIC/TLS-only** — stdio/SSH cut from scope. The custom verifier (R1) is the sole
   transport-auth path → top scrutiny.
2. **Device keys:** **Ed25519-only** (RSA dropped). The keyslot seals via **X-Wing** over the
   Ed25519-derived X25519 half + ML-KEM-768; signing is `ssh-ed25519` only; the verifier rejects
   every other algorithm.
3. **Platforms:** **Linux, macOS, Windows.** Cross-platform `notify`; key-lock via `region`; no
   FUSE/WebDAV; reproducible static build is Linux/`musl`, with signed binaries on macOS/Windows.
4. **Keyslot KEM:** **X-Wing** (`libcrux-ml-kem`, formally verified, + `x25519-dalek`) — mandatory,
   the only keyslot algorithm. No `hpke`/`rsa` (the classical and RSA keyslots were removed).

**Still open (not blocking M0):**
6. **Audit sourcing** — who reviews the cores and when (per-milestone vs final gate).
