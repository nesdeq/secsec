# secsec

**Self-hosted, zero-knowledge, end-to-end-encrypted, live two-way file sync.** A single static Rust
binary (server + client). The server is **blind** — it stores only ciphertext and never learns file
contents, names, structure, or sizes beyond a bounded, documented residual. The only credential is an
**SSH key**.

- **Zero-knowledge against an untrusted server** — content *and* metadata are encrypted; the server
  holds opaque, content-addressed blobs and can neither read nor forge them.
- **Live two-way sync** — edit on any device; changes propagate; conflicts are resolved by a
  rollback-gated three-way merge with **no silent data loss**; full version history is a by-product.
- **Post-quantum by default** — the harvestable keyslot wrap is **X-Wing** (ML-KEM-768 ⊕ X25519); the
  symmetric data plane is already PQ-safe. PQ is mandatory, not opt-in.
- **One binary, no CA, no database** — the server self-signs a host key (pinned TOFU, like `sshd`);
  storage is a single embedded `redb` file.

The authoritative specification is [`secsec-Design.md`](secsec-Design.md); the build plan, crate
layout, risk register, and status are in [`secsec-Implementation.md`](secsec-Implementation.md).

> **Status / maturity.** Feature-complete for v1 and exercised end-to-end with real processes
> (multiple clients converging through a blind server, including a concurrent-edit three-way merge,
> with a zero-plaintext-leak check on the server store). It has **not** had an independent professional
> cryptographic review — do not trust it with irreplaceable data until it has (see
> `secsec-Implementation.md` §8).

## How it works (one paragraph)

Files are split with **keyed FastCDC**, each chunk/tree/commit sealed with a per-object
**fully-committing (CMT-4) AEAD** and content-addressed by a keyed BLAKE3 of its plaintext (re-verified
on every fetch). Membership is an append-only, hash-chained, **SSHSIG-signed roster sigchain** anchored
out-of-band by the repository fingerprint (**RFP**); the master key is wrapped to each device's X-Wing
keyslot and authenticated against a commitment in that chain, so the server can never feed a device a
forged key or a fake repository. The per-ref **head** is signed *and* encrypted; the blind server only
ever does a compare-and-swap on the hash of an opaque blob. Transport is QUIC + TLS 1.3 to a **pinned**
self-signed host key, with every per-op request individually signed by a rostered key.

## Quickstart

Build the binary:

```sh
cargo build --release      # target/release/secsec
```

**Server operator** — initialize the repository directly on the server's store (a local admin op,
like `git init`), then run the blind server:

```sh
secsec init    --store /srv/repo.redb --key ~/.ssh/id_ed25519   # prints the RFP — record it out-of-band
secsec hostkey --hostkey-dir /srv/hostkey                       # prints the host pin (host_id)
secsec serve   --store /srv/repo.redb --hostkey-dir /srv/hostkey --listen 0.0.0.0:8899
```

**Device** — sync a directory, pinning the host by its fingerprint and anchoring trust to the RFP:

```sh
secsec sync \
  --remote server.example:8899 --host-fp <host_id-hex> \
  --key ~/.ssh/id_ed25519 --rfp <RFP-hex> \
  --dir ~/Sync --store ~/.secsec/objects.redb --state ~/.secsec/state \
  --watch        # optional: keep running, re-sync on file changes + a periodic poll
```

**Enroll another device** (`grant` is a local-store admin op the operator runs after verifying the new
device's keys out-of-band via the SAS):

```sh
# on the new device:
secsec enroll-pubkey --key ~/.ssh/id_ed25519     # prints its ssh + X-Wing public keys
# on the operator's box, against the repo store:
secsec grant --store /srv/repo.redb --key ~/.ssh/operator_ed25519 --rfp <RFP-hex> \
             --device-pub <ssh-hex> --xwing-pub <xwing-hex>
```

Other commands: `rotate [--revoke <device-id>]` (mint a new key generation; `revoke ⇒ rotate` for
forward secrecy), `recovery-init` / `recover` (break-glass 256-bit recovery code, §8.6), and `gc`
(client-driven, grace-windowed garbage collection, §15). Run `secsec <command> --help` for flags.

## Architecture

A Cargo workspace of small, separately reviewable crates, layered strictly downward (each has its own
`README.md`):

| Layer | Crates |
|---|---|
| Foundation | [`secsec-canon`](crates/secsec-canon) · [`secsec-aead`](crates/secsec-aead) · [`secsec-kdf`](crates/secsec-kdf) · [`secsec-frame`](crates/secsec-frame) |
| Object plane | [`secsec-object`](crates/secsec-object) · [`secsec-chunk`](crates/secsec-chunk) · [`secsec-snapshot`](crates/secsec-snapshot) · [`secsec-store`](crates/secsec-store) |
| Identity & keys | [`secsec-sig`](crates/secsec-sig) · [`secsec-pq`](crates/secsec-pq) · [`secsec-recovery`](crates/secsec-recovery) · [`secsec-roster`](crates/secsec-roster) |
| Sync plane | [`secsec-sync`](crates/secsec-sync) · [`secsec-engine`](crates/secsec-engine) |
| Transport & wire | [`secsec-transport`](crates/secsec-transport) · [`secsec-proto`](crates/secsec-proto) |
| Orchestration | [`secsec-client`](crates/secsec-client) · [`secsec-server`](crates/secsec-server) |
| Tooling | [`secsec-fuzz`](crates/secsec-fuzz) · [`bin/secsec`](bin/secsec) (the CLI) · `xtask` |

Cross-implementation known-answer vectors live in [`vectors/`](vectors); the cargo-fuzz harness in
[`fuzz/`](fuzz).

## Build & test

```sh
cargo test --workspace                              # the full suite
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo xtask vectors --check                         # KATs match the live code
cargo audit                                         # supply-chain advisory scan
```

CI (`.github/workflows/ci.yml`) runs lint, the test suite on Linux/macOS/Windows, and the advisory
scan on every push.

## Threat model (summary)

The adversary is a **malicious/compromised server** (primary), a **network attacker**, a **revoked
device**, and a **stolen client**. We trust only the device's SSH key and the user's out-of-band
channel (reading a fingerprint off a screen). Each security property in `secsec-Design.md` §4 (P1–P15)
is paired with the exact mechanism that earns it; the bounded, proven-minimal residuals (availability,
reinstall freshness, pre-rotation data for a colluding revoked device, the concurrent
mutual-revocation race, metadata leakage within padding/timing bounds) are enumerated in §22.

## License

MIT OR Apache-2.0.
