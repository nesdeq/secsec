# secsec: Implementation notes

How the system specified in [`secsec-Design.md`](secsec-Design.md) is built: the crate layout, the key
dependencies and why they were chosen, the test and assurance strategy, the security-critical risk
register, and what each component does. It does not restate the design: `secsec-Design.md` says
*what*, this says *how*.

> **Posture.** secsec is a security-critical cryptosystem whose entire value is "the server cannot
> read your data." A subtle bug is silent and total, so **correctness and provability dominate
> speed**. Two rules: (1) no security-critical module is trusted until its tests prove it (KATs,
> property tests, and negative tests, committed *with* the code); (2) the implementation is built to
> be **audit-ready** and should get an **independent professional cryptographic review before it
> touches irreplaceable data**. This document does not replace that review.

**What the tests cannot establish.** The CMT-4 guarantee is a theorem of the CTX paper; the tests
show the construction matches it byte for byte and rejects cross-key opens, not the reduction.
Constant-time behavior is by construction (`subtle` compares), not measured on hardware. The
primitive crates (`blake3`, `ssh-key`, `libcrux-ml-kem`, `x25519-dalek`, `chacha20`, `poly1305`) are
trusted as vetted; the tests check secsec's use of them (labels, input layouts, combiner order)
against external references where those exist.

**Scope.** Transport is **QUIC/TLS-only** (the pinned self-signed host key is the sole trust anchor;
no CA, no stdio/SSH mode). Device keys are **Ed25519-only**. The keyslot KEM is **X-Wing**
(ML-KEM-768 ⊕ X25519): post-quantum, the one harvestable asymmetric exposure. Targets are Linux,
macOS, and Windows (x86_64 and aarch64). secsec is **single-host**: one repo on one blind server
(`secsec sync` takes one `--server`).

---

## 1. Workspace & module layout

One repository, a Cargo **workspace**, producing a single binary (`secsec`) whose subcommands are the
client and whose `serve` subcommand is the server. It is split into focused libraries so the
security-critical cores are small, independently testable, and separately reviewable.

```
secsec/
├── crates/
│   ├── secsec-canon/      §9.3        canonical encoding: fixed-width LE, bounded lengths, re-encode guard
│   ├── secsec-aead/       §9.4, §9.8  CTX/CMT-4 committing AEAD, plus the fresh-nonce AEAD for mutable blobs
│   ├── secsec-kdf/        §5, §9.5    master-key generations, every derive_key family, mk_commit, the key ring
│   ├── secsec-chunk/      §9.7        keyed FastCDC-style chunker (gear table from cdc_seed)
│   ├── secsec-sig/        §5, §9.6    device key loading, Ed25519-only SSHSIG, seal and X-Wing seeds
│   ├── secsec-frame/      §9.1, §19   FRAME, object types, the §19 decoder bounds
│   ├── secsec-object/     §9.2, §9.7  content addressing, seal/open with three-way verify, chunk padding
│   ├── secsec-store/      §13, §15    redb blob store: server repository and client object cache
│   ├── secsec-pq/         §8.3, §17   X-Wing keyslot wrap, draft-10 conformant
│   ├── secsec-roster/     §8          sigchain fold/succession, per-entry AEAD, key histories, revoke closure
│   ├── secsec-sync/       §8.5, §10   signed+encrypted Head, DAG ancestry, three-way merge, rollback gates, frontier
│   ├── secsec-proto/      §12, §15    wire codecs, per-op args_hash and auth, prune hashes, server limits
│   ├── secsec-snapshot/   §6, §10     Tree/Commit graph, directory snapshot and reconciling restore
│   ├── secsec-transport/  §11         pinned/TOFU QUIC configs, application handshake, stream framing, client RPC
│   ├── secsec-engine/     §10         stored-tree ↔ merge-node bridge, sibling acceptance, signed merge commits
│   ├── secsec-server/     §11, §12    per-op pipeline, authorized_keys gate, serve loop
│   ├── secsec-client/     §7, §8, §10, §15  Remote trait, repo lifecycle, pairing, sync, history, retention, watcher
│   └── secsec-fuzz/       §18         one harness body per decoder of untrusted bytes
├── bin/secsec/            the CLI and the server entry point
├── fuzz/                  cargo-fuzz targets (nightly), one per secsec-fuzz body; outside the workspace
├── vectors/               committed known-answer vectors
├── xtask/                 the KAT anti-drift check and the release recipe
├── ui/                    GNOME Shell extension, macOS menu-bar app, their installer
├── install.sh             release installer: client, --server, --binary
├── assets/                brand SVGs
└── .github/workflows/     ci.yml, release.yml
```

**Dependency layering** (strictly downward; no crate depends on a higher layer):

| Layer | Crates | Internal dependencies |
|---|---|---|
| 0 | `canon`, `aead`, `kdf`, `chunk`, `sig` | none |
| 1 | `frame` | canon |
| 2 | `object`, `store`, `pq`, `roster`, `sync`, `proto` | object: kdf, frame, aead · store: frame · pq: aead, canon · roster: sig, frame, canon, aead, kdf · sync: canon, frame, kdf, sig, aead · proto: sig, canon, frame |
| 3 | `snapshot`, `transport` | snapshot: canon, frame, kdf, object, chunk, store, sig · transport: sig, canon, frame, proto |
| 4 | `engine`, `server` | engine: snapshot, sync, store, kdf, object, frame, sig · server: proto, store, sig, frame, transport |
| 5 | `client` | store, snapshot, object, frame, kdf, canon, sync, engine, roster, pq, sig, transport, proto |
| 6 | `fuzz`, `bin/secsec`, `xtask` | the crates they exercise |

`secsec-sync` keeps the §10 merge, DAG, and rollback logic **storage-free and purely testable**;
`secsec-engine` is the only §10 code that touches `store` and `snapshot` (it loads stored trees into
the merge model, re-seals the result, and authors the signed merge commit). The `Remote` trait lives
in `secsec-client`, with two implementations: `QuicRemote` over a live connection and a test-only
in-process `MemRemote` over a real store.

---

## 2. Key dependencies

Pinned by `Cargo.lock`, minimal, no OpenSSL. The security-relevant choices:

- **`libcrux-ml-kem`**: ML-KEM-768, **formally verified** (FIPS 203). The X-Wing keyslot
  (`secsec-pq`) is built directly on it (single-seed `SHAKE256(sk, 96)` expansion via `sha3`,
  label-last combiner, the FIPS 203 §7.1 pairwise check at every derivation, §7.2 validation of every
  published key), so no third-party X-Wing crate is trusted. `x25519-dalek` supplies the X25519 half,
  whose secret comes from that same expansion, never from the Ed25519 key.
- **`chacha20` + `poly1305`**: there is no drop-in committing-AEAD crate, so `secsec-aead` builds
  the CTX/CMT-4 construction from the raw primitives (one-time Poly1305 key from ChaCha20 block 0,
  `ctx_tag = BLAKE3::keyed_hash(...)`, `T` never stored). `chacha20poly1305` is a **dev-dependency**
  only: tests cross-check the keystream and tag against it byte for byte.
- **`ssh-key`** (RustCrypto, features `std`, `ed25519`, `encryption`): SSHSIG with per-namespace
  domain separation (§9.6), Ed25519-only, passphrase-encrypted private keys decrypted in memory.
  `sha2` serves only the legacy v1 local-seal key (the clamped scalar), read for migration.
- **`quinn` + `rustls`** (the `ring` provider): QUIC over TLS 1.3 with a pinned suite list and X25519
  key exchange; the custom pinned `ServerCertVerifier` (R1) is the sole transport-auth path.
  `x509-cert` extracts the certificate SPKI; `rcgen` generates the server's self-signed host key.
- **`blake3`**: the KDF and hash backbone (§9.5); the keyed chunker's gear table is composed
  directly on its XOF rather than a third-party chunking crate.
- **`redb`** (embedded store, one file), **`notify`** (filesystem watch), **`filetime`** (restored
  mtimes), **`zeroize` / `subtle` / `getrandom`** for key hygiene, constant-time compares, and the OS
  CSPRNG. `secrecy`, `region`, and `mlock` are **NOT WIRED**.
- The CLI adds `clap`, `rpassword` (no-echo passphrase prompt), `socket2` (dual-stack UDP bind),
  `tempfile`, `tokio`, and `rustix` (unix signals for `secsec stop`).

---

## 3. Test & assurance strategy

Every security-critical crate carries, in the same change as the code:

- **Known-answer vectors.** `vectors/secsec-kat-v1.txt` pins nine sections: all eleven §9.5
  `derive_key` families plus `mk_commit`, the FRAME, the CTX AEAD, an object, a head blob, the session
  transcript, v1 and v2 roster entries and a roster-key-history wrap, chunker cut points, and the §7
  pairing slots and MACs. Each section names the inline test that asserts it, and `cargo xtask
  vectors --check` (also the test `committed_vectors_match_live_code`) recomputes every value from
  live code and fails on drift. X-Wing is checked against *its* published vector: `xwing_kat` in
  `secsec-pq` asserts byte-identity with draft-10 Appendix C.
- **Property tests** (`proptest`): AEAD round trips, wrong keys, and single-bit flips; canonical
  round trips and appended-byte rejection; the sigchain fold against an independent reference model
  (R5). `secsec-aead`, `secsec-canon`, and `secsec-frame` each carry a `tests/robustness.rs` that
  feeds arbitrary bytes to the decoder and requires no panic.
- **Mandatory negative tests** (the ship-broken spots):
  - the TLS verifier: another key fails the pin; a garbage handshake signature fails; TLS 1.2 is
    refused; a MITM key fails a real TLS and QUIC handshake; TOFU records nothing before the signature
    verifies.
  - SSHSIG: a genuine ECDSA signature and an ECDSA key are rejected; a wrong namespace fails.
  - keyslots: an `algo_id` above this build's asks for an upgrade, one below is unsupported; a forged
    keyslot fails `mk_commit`; a grant refuses an invalid X-Wing public key before writing anything.
  - rollback: a roster, commit-version, or head-version rollback is rejected; a DAG missing gate
    metadata fails closed; a forged ancestor commit is rejected before any gate reads it.
  - storage: a lost `cas-head` promotes nothing; a stale prune deletes nothing; a prune racing a push
    cannot dangle the new head.
- **Fuzzing.** `secsec-fuzz` holds eleven harness bodies (frame, wire, roster_entry, keyhist, keyslot,
  object, head, frontier, tree, commit, pairing); `fuzz/` wraps each as a `cargo-fuzz` target. On
  stable, `every_decoder_survives_arbitrary_input` runs every body over a fixed-seed corpus, and
  `fuzz_manifest_lists_every_target` keeps `fuzz/Cargo.toml` in step with the harness.
- **Misuse-resistant by construction:** the committing AEAD takes a `UniqueKey` (a key bound to one
  sealing) and fixes the nonce; the mutable AEAD takes a `FreshNonce` from the OS CSPRNG. No API pairs
  a long-lived key with a caller-supplied counter.
- **Lints:** `unsafe_code = "forbid"` and clippy `all = "deny"` for every member, which an xtask test
  (`every_workspace_member_inherits_the_workspace_lints`) enforces; release builds keep overflow
  checks and abort on panic.

**CI** (`ci.yml`, six jobs, `RUSTFLAGS=-D warnings`): `lint` (`cargo fmt --check`, `cargo clippy
--all-targets --all-features -D warnings`, `cargo xtask vectors --check`); `test` (`cargo test --all
--all-features` on Linux, macOS, and Windows); `msrv` (`cargo check` on Rust 1.89); `audit`
(`cargo audit`, ignoring only `RUSTSEC-2023-0071` in `.cargo/audit.toml`: the optional `rsa`
dependency of `ssh-key` this workspace never enables); `scripts` (shellcheck of `install.sh`, `ui/install.sh`, `ui/macos/build.sh`, and `node
--check` of the GNOME extension); `menubar` (builds the macOS app). Every cargo step runs `--locked`.

**Release** (`release.yml`, on `rc*` and `v*` tags): runs CI, builds `secsec` for Linux (static
`musl`, stripped), macOS, and Windows on x86_64 and aarch64 with the tag stamped in as `SECSEC_RELEASE`
(what `secsec --version` prints; other builds print the crate version), packages the GNOME extension and the
macOS app, and publishes them with `SHA256SUMS` and build-provenance attestations, which `install.sh`
verifies with `gh attestation verify` when the GitHub CLI is signed in. `cargo xtask release` prints a
reproducible build recipe (fixed `SOURCE_DATE_EPOCH`, remapped paths) that the release workflow does
not follow (**NOT WIRED**).

---

## 4. Risk register: the cores that get the most scrutiny

| # | Hotspot | Failure mode | Mitigation |
|---|---|---|---|
| R1 | Custom rustls verifier (§11) | `return Ok(())` or a stubbed signature check silently disables auth | SPKI pin compared in constant time; `verify_tls13_signature` delegated, never stubbed; TLS 1.2 refused; negative and MITM tests gate CI |
| R2 | CTX from raw Poly1305 (§9.4) | wrong `T` recomputation, a high-level open, a non-constant-time compare | `secsec-aead` isolated; reference cross-check and KATs; commit check in constant time before any decryption |
| R3 | X-Wing keyslot (§8.3, §17) | a non-conformant combiner or seed expansion; a keyslot derived from public data | draft-10 KAT (byte-identity); FIPS 203 §7.1 check and §7.2 validation; the X-Wing seed derives from the Ed25519 seed, never the scalar; CTX-committing AEAD over the wrap |
| R4 | Rollback-aware merge (§10) | a replayed old commit or head steers the merge; a lost write | ancestor no-op before the gates; roster, commit-version, and head-version gates; frontier sealed before every ref-advancing push; keep-both merge |
| R5 | Sigchain fold, cold start, roster-key peel (§8) | a mis-fold gives the wrong membership; a bootstrap deadlock | model-based fold test; explicit cold-start order; RFP and `mk_commit` checks; persisted anti-rollback anchor (P7) |
| R6 | Transactional push and retention (§15) | a promoted head references a missing object, or retention deletes live data | promote and ref swap in one redb transaction (I1); pushes stage everything outside the remote head's tree, durable ids included; chunk-only prune under the `all_heads_hash` + `roster_len` CAS; `retention_keep_versions = 0` keeps everything |
| R7 | Canonical serialization (§9.3) | malleability leads to a signature bypass | bounded lengths, no trailing bytes, re-encode guard over received bytes; fuzzed |
| R8 | Keyed chunking (§9.7) | unkeyed boundaries allow cross-repo size fingerprinting | gear table from the generation-scoped `cdc_seed`; power-of-two chunk padding blurs the size signal (§21) |

---

## 5. What each component does

- **Canonical encoding (`secsec-canon`, §9.3).** A hand-written writer and strict reader: fixed-width
  little-endian integers, `le32(len) ‖ bytes` strings whose length is checked against a
  caller-supplied bound before the body is read, raw fixed fields, and `finish()` rejecting trailing
  bytes. `verify_reencode` enforces that signed or hashed bytes decode to a value that re-encodes to
  exactly those bytes.

- **Committing AEAD (`secsec-aead`, §9.4, §9.8).** CTX/CMT-4 over ChaCha20-Poly1305: a unique key per
  sealing, a fixed zero nonce, and `ctx_tag = BLAKE3::keyed_hash(key, "secsec-ctx-v1" ‖ AD ‖ T)` where
  the raw Poly1305 tag `T` is recomputed on open and **never stored**. Open is three-phase (MAC,
  constant-time commit check, then decrypt), so no plaintext exists before the commitment verifies.
  A separate fresh-nonce RFC 8439 variant (`seal_mut`/`open_mut`) serves the mutable head blob and the
  sealed local frontier.

- **Key hierarchy (`secsec-kdf`, §5, §9.5).** `MasterKey` holds a generation and its key (zeroized on
  drop); every subkey is `BLAKE3::derive_key(label, IKM)` streamed through a wiped hasher, and
  `mk_commit` is the one `keyed_hash`. The `MasterKeys` trait resolves a generation to its key, so a
  key ring opens objects and heads sealed under any past generation, and `ref_name_key` always comes
  from generation 1.

- **Chunking (`secsec-chunk`, §9.7).** A gear rolling hash with normalized two-mask cut points
  (16/64/256 KiB), the 256-entry gear table drawn from `BLAKE3::keyed_hash(cdc_seed,
  "secsec-cdc-gear-v1")` in XOF mode and wiped on drop. `chunk_stream` holds at most one maximum chunk
  in memory and cuts byte-identically to the in-memory path.

- **Object plane (`secsec-frame`, `secsec-object`, §9.1, §9.2).** Objects are `FRAME ‖ ctx_tag ‖
  ciphertext`, content-addressed by `keyed_hash(id_key[g][t], FRAME ‖ path_salt ‖ plaintext)`. On open
  the generation resolves through the key ring, the FRAME must equal the expected one, the CTX tag
  verifies under the id-derived key, and the id is re-derived and compared in constant time. Chunks
  are padded to the next power of two above their length before sealing. `secsec-frame` also owns the
  §19 constants every decoder checks before allocating.

- **Device identity (`secsec-sig`, §5, §9.6).** Loads an OpenSSH Ed25519 private key (decrypting a
  passphrase-protected one in memory), signs SSHSIG under the six disjoint namespaces, and verifies
  only when both key and signature are Ed25519. It derives the two private-seed secrets: the v2 local
  seal key and the X-Wing seed (plus the legacy v1 seal key for migration).

- **Hybrid-PQ keyslot (`secsec-pq`, §8.3, §17).** X-Wing = ML-KEM-768 ⊕ X25519, draft-10 conformant.
  A keyslot body is `ct_MLKEM ‖ ct_X ‖ ctx_tag ‖ ct`: the shared secret keys the CTX AEAD over the
  master key with AD `"secsec-keyslot-v1" ‖ device_id ‖ le32(gen)`. Authenticity rests on the caller's
  `mk_commit` check, not on the wrap.

- **Roster (`secsec-roster`, §8).** An append-only, hash-chained, SSHSIG-signed sigchain anchored by
  the genesis hash (RFP). `fold` enforces succession, the `prev` chain, per-entry signatures, and the
  current `mk_commit` on every `AddDevice`, and keeps `ever_members` so a revoked author's history
  still verifies. Entries seal as v2 (per-seal random salt, §9.5) and open as v2 or legacy v1 by their
  FRAME. `cold_start_fold` peels the roster keys, opens each entry under the generation its FRAME
  names, folds, and checks the candidate master key. `revoke_closure` walks the add-by tree
  transitively, collecting grants at or after the revoker's reference point and never the revoker;
  the data and roster key histories are 64-byte wraps peeled back to generation 1, each data key
  checked against its `mk_commit`.

- **Blob store (`secsec-store`, §13, §15).** One redb file with tables for objects, per-push staging
  and its activity clock, keyslots, refs, roster entries, and both key histories. `stage` always
  stages (even an id already durable); `cas_ref` promotes a push's staging and swaps the ref in one
  transaction; `roster_batch` applies a whole sigchain operation atomically under the tip CAS (purging
  pre-genesis keyslots on genesis and refusing to replace a key-history wrap the chain has rotated
  past); `prune_if` deletes only when the caller's predicate accepts the live refs and roster length
  inside the same transaction; `reclaim_staging` drops idle pushes. Clients use the same store as
  their encrypted object cache.

- **Wire and authorization (`secsec-proto`, §12, §15, §19).** Strict codecs for the hellos, client
  auth, every request and response, each list count and length bounded before allocation, and
  write-side `validate` identical to the decoder's bounds. `op_and_args` maps a request to its op
  label, `args_hash`, and read/write class for both ends. `WriteAuth` and `ReadAuth` build the signed
  payloads. `prune` holds `dead_set_hash`, `all_heads_hash`, and `args_prune`; `server` holds the §19
  limits, token buckets, trailing-window counters, and the per-session quota.

- **Snapshot and restore (`secsec-snapshot`, §6, §10).** Walks the working folder into sealed trees
  and chunks, reusing path salts from a prior tree (this device's own with the size and nanosecond
  mtime fast path, or another device's head to seed salts on first contact), skipping symlinks,
  special files, unsafe names, and restore temps, freezing unreadable or oversized paths at their last
  synced entry, and carrying unmaterializable entries forward. Restore reconciles the folder to a tree
  against this device's snapshot (deleting only tracked, unchanged entries, keeping local edits as
  keep-both copies, writing through fsynced temp files, never following a symlink, and removing a lone
  macOS `Icon\r` only when its folder is going). `restore_path` is the explicit-restore overwrite,
  confined to the synced folder.

- **Sync plane (`secsec-sync`, `secsec-engine`, §8.5, §10).** The per-ref Head is signed, then sealed
  under the current generation with a fresh nonce at the generation-stable path `/refs/<H>`.
  `dag` gives ancestry, new-commit sets, and lowest common ancestors; `merge` is the pure per-path
  three-way merge with keep-both naming; `rollback` holds the gates, the high-water rules, and the
  sealed frontier. `secsec-engine` loads a sibling's commit DAG, treats an ancestor sibling as a
  no-op before the gates, verifies every new commit's signature against `ever_members`, runs the
  gates, and either fast-forwards or authors a signed two-parent merge commit against the lowest-id
  merge base (an empty base, flagged, when that tree is gone).

- **Transport (`secsec-transport`, §11).** `PinnedServerVerifier` accepts exactly one SPKI hash;
  `TofuVerifier` records it only after the TLS 1.3 handshake signature verifies. Both configs pin the
  cipher suites and X25519 and refuse TLS 1.2; only the client sends keepalives. The application
  handshake exchanges fixed-size hellos, builds the session transcript, and has the client sign
  `secsec-auth-v1` over the TLS exporter, `host_id`, transcript, and server nonce. `frame` reads
  length-prefixed messages under a cap, allocating only as bytes arrive; `rpc::request` opens one
  stream per request, reads its challenge, and sends the signed request.

- **Server (`secsec-server`, §11, §12).** `serve_connection` runs the handshake under the idle-timeout
  deadline, checks `authorized_keys` and the per-key connection cap, then serves each request stream:
  a fresh 32-byte challenge, a frame cap chosen by enrollment, and `Server::handle`, which dispatches
  the pairing mailbox before the enrollment check, then requires a keyslot (the genesis batch
  excepted), verifies the per-op signature (a write within 60 s of its challenge), charges rate
  limits, and executes. `authorized_keys` is re-parsed when its size or mtime changes and denies when
  unreadable; the connection re-checks it on the first request after 60 s. `admit` hands the accept
  loop a server-wide connection slot, freed when its guard drops. `reclaim` drops idle staging and
  idle rate-limit state on the serve loop's timer.

- **Client (`secsec-client`, §7, §8, §10, §15).** `repo` creates the repository (one genesis batch),
  cold-starts it against the persisted anchor, peels the data key ring, grants a device, and rotates
  (with or without a revocation) as one batch, retrying only while the tip or the head moves. `pair`
  runs the invite exchange over the mailbox (code MACs under `secsec-pair-mac-v2`, length-framed
  parts). `sync_once` fetches and verifies the head, snapshots, and publishes, pulls, merges, or clones,
  sealing the frontier before any ref-advancing push and returning the base and frontier for the
  caller to persist in that order. `push_objects` stages the new commits and every object outside the
  remote head's tree. `history` serves `log` and `restore` with chunks fetched on demand; `prune`
  runs the per-session cache sweep and the count-based retention prune; `watcher` turns filesystem
  bursts into one callback; `quic::QuicRemote` implements `Remote` over authorized RPCs.

- **CLI (`bin/secsec`).** Loads `secsec.config` (writing the template on first use, clamping on load),
  resolves the per-folder state directory, takes the folder lock, and drives `sync_once` in a loop on
  watcher events and the poll timer: reconnecting with a verified round trip, probing the sigchain
  for growth and refolding when it moved, persisting the push id around each round, writing the
  status file, and running the retention prune once per session. `serve` binds dual-stack UDP,
  compacts the store, answers unvalidated sources with a QUIC Retry, enforces the per-IP rate and
  the server-wide connection cap, and spawns `serve_connection` per admitted connection.

- **Desktop UIs and installers (`ui/`, `install.sh`).** The GNOME extension and the macOS menu-bar app
  prompt for the key passphrase, start `secsec sync <folder> --passphrase-stdin` with the passphrase on
  a pipe, poll `secsec status`, and use `secsec stop` to stop the sync holding the folder.
  `install.sh` installs the binary with checksum (and, with `gh`, provenance) verification, the UI or a
  systemd sync unit for the client, or the server as a systemd user service with lingering (Linux) or
  a LaunchAgent (macOS).
