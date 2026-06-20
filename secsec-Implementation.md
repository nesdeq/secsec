# secsec — Implementation notes

How the system specified in [`secsec-Design.md`](secsec-Design.md) is built: the crate layout, the
key dependencies and why they were chosen, the test/assurance strategy, the security-critical risk
register, and what each component does. It does not restate the design — read `secsec-Design.md` for
*what*; this is *how*.

> **Posture.** secsec is a security-critical cryptosystem whose entire value is "the server cannot
> read your data." A subtle bug is silent and total, so **correctness and provability dominate
> speed**. Two rules: (1) no security-critical module is trusted until its tests prove it — KATs +
> property + negative tests, committed *with* the code; (2) the implementation is built to be
> **audit-ready** and should get an **independent professional cryptographic review before it touches
> irreplaceable data** — this does not replace that review.

**Scope.** Transport is **QUIC/TLS-only** (the pinned self-signed host key is the sole trust anchor;
no CA, no stdio/SSH mode). Device keys are **Ed25519-only**. The keyslot KEM is **X-Wing**
(ML-KEM-768 ⊕ X25519) — post-quantum, the harvestable asymmetric exposure. Targets are Linux, macOS,
and Windows. secsec is **single-host**: one repo on one blind server (`secsec sync` takes one
`--server`).

---

## 1. Workspace & module layout

One repository, a Cargo **workspace**, producing a single static binary (`secsec`) whose subcommands
are the client; `secsec serve` is the server. It is split into focused libraries so the
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
│   ├── secsec-pq/        §8.3,§17  X-Wing keyslot (ML-KEM-768 ⊕ X25519), mk_commit authenticity, draft-10 KAT
│   ├── secsec-roster/    §8    sigchain fold/succession, per-entry AEAD, roster-key history, generations, enrollment
│   ├── secsec-sync/      §10   refs, cas-head, rollback-aware merge (storage-free Node model), fork detection
│   ├── secsec-engine/    §10   snapshot-tree ↔ merge-node bridge, three-way reconcile to the store
│   ├── secsec-transport/ §11   QUIC+TLS pinned verifier, auth, channel binding
│   ├── secsec-proto/     §12   wire protocol, RPC framing, write/read-auth, rate limits, transactional-push + prune serialization (§15)
│   ├── secsec-client/    §7,§10,§15  orchestration: cold-start, watcher, sync loop, history retention, invite-pairing
│   └── secsec-server/          serve loop, transactional promote + prune head-CAS, idle-staging reclaim
├── bin/secsec            thin CLI over the crates
├── vectors/              committed KAT / cross-impl test vectors
├── fuzz/                 cargo-fuzz targets, one per decoder
└── xtask/                build/release tooling, vector generation + drift check
```

Dependency direction is strictly downward (canon → aead/kdf/frame → object/sig/chunk →
snapshot/store/pq/roster → sync → engine → transport/proto → client/server). No security-critical
crate depends on a higher layer. `secsec-sync` keeps §10's merge/dag/rollback logic **storage-free
and purely testable**; `secsec-engine` is the only §10 code that touches `store`+`snapshot` (it
materializes stored trees into the merge model, re-seals the result, and authors the signed merge
commit). The §15 transactional-push + retention driver builds on the `Remote` trait, which lives in
`secsec-client`; the `prune`/`all_heads_hash` serialization hashes are in `secsec-proto`, and the
staged promote + prune head-CAS in `secsec-store`/`secsec-server`.

---

## 2. Key dependencies

Pinned, minimal, no OpenSSL. The security-relevant choices:

- **`libcrux-ml-kem`** — ML-KEM-768, **formally verified** (FIPS 203 final). The X-Wing keyslot
  (`secsec-pq`) is built directly on it (single-seed `SHAKE256(sk,96)` expansion, label-last
  combiner, FIPS 203 §7.1 PCT), so no third-party X-Wing crate is trusted. No `hpke` / `rsa`: the
  keyslot is X-Wing, so the one harvestable asymmetric exposure is post-quantum (§17).
- **`chacha20poly1305` + `poly1305` + `chacha20`** — there is no drop-in committing-AEAD crate, so
  `secsec-aead` builds the CTX/CMT-4 construction from these primitives (one-time Poly1305 key from
  ChaCha20 block 0, `ctx_tag = BLAKE3::keyed_hash(...)`, `T` never stored). This is the fiddliest
  primitive and gets the most tests.
- **`ssh-key` (RustCrypto)** — SSHSIG with per-namespace domain separation (§9.6); Ed25519-only.
- **`quinn` + `rustls`** — QUIC/TLS 1.3; the custom pinned `ServerCertVerifier` (R1) is the sole
  transport-auth path.
- **`blake3`** — the KDF/hash backbone (§9.5); `x25519-dalek`/`ed25519-dalek` for the
  Ed25519→X25519 map; `fastcdc` (keyed gear table, §9.7); `redb` (embedded store); `notify`
  (filesystem watch); `zeroize`/`secrecy`/`subtle`/`getrandom`/`region` for key hygiene.

---

## 3. Test & assurance strategy

Every security-critical crate carries, in the same change as the code:

- **Known-answer vectors** in `vectors/`: every §9.5 derivation, the CTX AEAD, `mk_commit`, the §7
  invite-code pairing MAC, the X-Wing keyslot, content-ids. Where an external standard exists
  (X-Wing draft-10 Appendix C) the test asserts byte-identity against *its* published vector.
  `cargo xtask vectors --check` recomputes every value from the live code and fails on drift.
- **Property tests** (`proptest`): AEAD round-trips; tamper-any-byte ⇒ reject; the CTX commitment
  (no ciphertext opens under two distinct `(key, AD)` pairs); canonical encode/decode is a bijection
  and rejects non-canonical input.
- **Mandatory negative tests** (the ship-broken spots):
  - rustls verifier: wrong pinned key fails; tampered handshake fails; any non-`ssh-ed25519`
    signature algorithm fails.
  - X-Wing keyslot: a non-X-Wing `algo_id` is rejected; a keyslot below `min_algo` is rejected (§16).
  - SSHSIG: wrong namespace fails; cross-namespace reuse fails.
  - rollback merge: a stale sibling below the frontier is rejected and alarmed.
- **Fuzzing** (`cargo-fuzz`): one target per decoder (frame, object, sigchain entry, head, tree,
  commit, wire RPC). The same corpus runs on **stable** as a normal test, so the "no panic / no OOM
  on arbitrary input" property (§18/§19) is CI-enforced without the nightly toolchain.
- **Nonce-misuse-resistant by construction:** the committing AEAD derives a unique key per object and
  fixes the nonce; the mutable AEAD takes a caller-supplied fresh random nonce. There is no API that
  pairs a long-lived key with a caller-supplied counter.

**CI gates** (must be green to merge): `clippy -D warnings`, `cargo test`, the fuzz corpus, the
committed vectors, and `cargo-audit`. Reproducible static `musl` build via `xtask`. No OpenSSL.

---

## 4. Risk register — the cores that get the most scrutiny

| # | Hotspot | Failure mode | Mitigation |
|---|---|---|---|
| R1 | Custom rustls verifier (§11) | `return Ok(())` / stubbed sig check silently disables auth | SPKI pin + delegated `verify_tls13_signature` (never stubbed); negative tests gate CI |
| R2 | CTX from raw Poly1305 (§9.4) | wrong `T` recomputation; using high-level open; non-constant-time | `secsec-aead` isolated; KATs; committing property test; `subtle` compares; decrypt only after the commit check |
| R3 | X-Wing keyslot seal (§8.3/§17) | non-conformant combiner/seed handling; low-order X25519 point | draft-10 KAT (byte-identity); FIPS 203 §7.1 PCT; X-Wing seed from the Ed25519 seed (not the scalar); CTX-committing AEAD over the wrap |
| R4 | Rollback-aware merge (§10) | replayed old commit steers merge; lost write | frontier/version/HWM gates; adversarial replay tests; keep-both default (no data loss) |
| R5 | Sigchain fold + cold-start + roster-key peel (§8) | mis-fold → wrong membership; bootstrap deadlock | model-based tests; explicit cold-start order; RFP-anchor + `mk_commit` checks; persisted anti-rollback anchor (P7) |
| R6 | Transactional push + retention (§15) | a promoted head references a non-durable object, or retention deletes live data | promote+ref-swap in one redb txn (I1); count-based prune under a head-binding `all_heads_hash`/`roster_seq` CAS; keep-everything when `retention_keep_versions=0` |
| R7 | Canonical serialization (§9.3) | malleability → signature bypass | verify over received bytes (re-encode guard); reject non-canonical; fuzz |
| R8 | Keyed FastCDC (§9.7) | unkeyed boundaries → cross-repo size fingerprinting | gear table seeded from `cdc_seed[gen]`; default-on padding is the load-bearing privacy mechanism (§21) |

---

## 5. What each component does

- **Committing AEAD (`secsec-aead`, §9.4).** CTX/CMT-4 over ChaCha20-Poly1305: a unique per-object
  key, fixed zero nonce, and `ctx_tag = BLAKE3::keyed_hash(key, "secsec-ctx-v1" ‖ AD ‖ T)` where `T`
  (the raw Poly1305 tag) is recomputed on open and **never stored**. Open is three-phase — MAC,
  constant-time commit check, then decrypt — so no plaintext is produced before the commitment
  verifies. A separate fresh-nonce variant serves the mutable Head and sealed local state (§9.8).

- **Key hierarchy (`secsec-kdf`, §5/§9.5).** Every subkey is `BLAKE3::derive_key(label, IKM)` with a
  distinct hardcoded label and the secret in the IKM role; `mk_commit` is the one `keyed_hash`
  exception, binding the generation. The `MasterKeys` resolver lets a current member open objects
  sealed under any past generation (§8.2 cross-rotation reads).

- **Object plane (`secsec-object`/`secsec-frame`/`secsec-chunk`, §9.1/§9.2/§9.7).** Objects are
  `FRAME ‖ ctx_tag ‖ ciphertext`, content-addressed by a keyed BLAKE3 of the plaintext. On fetch,
  substitution is caught three independent ways (id re-derivation, AEAD/CTX tag under the
  id-derived key, FRAME match). Decoders enforce the §19 bounds before allocation. Files are split
  by keyed FastCDC (repo-specific boundaries) and padded by default.

- **Hybrid-PQ keyslot (`secsec-pq`, §8.3/§17).** X-Wing = ML-KEM-768 ⊕ X25519, draft-10 conformant
  (label-last combiner, single-seed expansion, FIPS 203 §7.1 PCT); `xwing_kat` asserts byte-identity
  against the draft-10 vector. The device's X-Wing seed is `derive_key("secsec-xwing-seed-v1",
  ed25519_seed)` — from the raw Ed25519 *seed*, not the clamped scalar, so a quantum adversary
  cannot reconstruct it from the public Ed25519 key. Keyslots are `algo_id ‖ body`; genesis/grant/
  rotate wrap to each member's roster-published X-Wing public; cold-start dispatches by `algo_id` and
  enforces the §16 floor. Authenticity rests on the `mk_commit` check, not the wrap.

- **Roster / membership (`secsec-roster`, §8).** An append-only, hash-chained, SSHSIG-signed
  sigchain anchored by the genesis hash (RFP). `fold` enforces succession (every entry's signer must
  be a current member of the prefix), the `prev`-hash chain, and per-entry signatures; `decode_entry`
  re-encodes to guard malleability. `cold_start_fold` ties RFP + succession + the `mk_commit`
  anti-fake-key check. `revoke⇒rotate` computes the transitive add-by closure (closing the nested
  sleeper), mints a new generation, re-wraps to remaining members, and deletes the revoked keyslots.
  The never-trimmed roster-key and data-key histories let a member peel back to genesis.

- **Invite-code pairing (`secsec-client::pair`, §7).** A joining device carries one single-use 96-bit
  code. The protocol MACs `{D_pubkey, D_xwing}` → host and `{RFP, host_id}` → joiner under
  `derive_key("secsec-pair-mac-v1", code)`, relayed through the server's transient, TTL'd mailbox at
  slots `BLAKE3::derive_key(label, code)` — so the blind server never learns the code, cannot swap the joiner's
  key, and cannot substitute the repo. The joiner confirms `host_id` against its TOFU pin and
  `mk_commit` at cold-start.

- **Transport & connection auth (`secsec-transport`/`secsec-proto`, §11/§12).** QUIC + TLS 1.3 to a
  pinned self-signed host key. Both ends derive the TLS keying-material exporter and the joiner
  cross-checks `host_id` against its pin; the client signs `secsec-auth-v1` over
  `channel_binding ‖ host_id ‖ transcript ‖ server_nonce`. Every per-op request is individually
  signed (`secsec-write-v1` / `secsec-read-v1`); the wire decoders bound every length before
  allocation and reject trailing bytes.

- **`authorized_keys` gate + server pipeline (`secsec-server`, §11/§12).** `secsec serve` reads
  `~/.ssh/authorized_keys` (re-read per connection, fail-closed) and refuses to start without it; an
  unlisted key cannot open a session. Per op the server checks keyslot existence (presence only, no
  decryption), verifies the signature over a server-recomputed `args_hash`, consumes the single-use
  nonce, and enforces the §19 rate/quota limits. The genesis-bootstrap exception lets the first
  device create an empty repo while the roster is empty.

- **Sync plane (`secsec-sync`/`secsec-engine`, §10).** Commit-on-change snapshots are pushed as an
  object closure; the per-ref Head is signed *and* encrypted, addressed at a **generation-stable** ref
  path (the ref key is genesis-derived, so the head does not move on rotation; readers peel the key
  ring to open a head sealed under an older generation), and advanced by a blind-server
  compare-and-swap. A sibling already in our history is a no-op *before* the gates (so a peer that
  folds the roster late does not trip the roster_seq gate); a genuinely new divergent sibling is
  admitted only through the rollback gates (roster_seq, per-device commit-version and head-version
  high-waters) and then reconciled by a per-path three-way merge that keeps both sides on a genuine
  conflict — **no silent data loss**. Materializing the result back to the working folder reconciles
  it to the tree, so an upstream **deletion is applied** (and not resurrected), while untracked
  symlinks/special files are left alone. The cold-start carries a persisted anti-rollback anchor
  (highest seq + tip-blob hash) that refuses a server-truncated or re-forked sigchain (P7).

- **History retention (`secsec-client::prune`, §15).** There is no `gc`/`prune` command. `sync` runs
  `local_sweep` over the local cache (dropping orphans unreachable from the head) and one best-effort
  `prune_history` pass per session: it keeps the last N versions per file and deletes the superseded
  content under the head-binding CAS — the server recomputes `all_heads_hash` over every stored ref
  (with `roster_seq`), so a prune that doesn't account for them all is rejected. Commit objects are
  kept forever so `log` stays whole. A failure is logged and never fatal.

- **Devices / revoke (CLI + `rotate_repo_remote`).** `secsec devices` lists the folded roster with
  each device's `SHA256:…` SSH fingerprint and a self-marker; `secsec revoke <prefix>` resolves the
  id (refusing self-revocation) and rotates the key away from the target and its add-by closure over
  the wire, deleting its keyslots.
