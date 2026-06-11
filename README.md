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
- **`authorized_keys` is the gate** — the server lists permitted device keys in `~/.ssh/authorized_keys`
  (re-read per connection) and refuses to start without it; only listed keys can connect at all. New
  devices join with a single-use **invite code**. There is no separate recovery secret — the SSH key
  is both credential and backup.
- **One binary, no CA, no database** — the server self-signs a host key (pinned TOFU, like `sshd`);
  storage is a single embedded `repo.secsec` file, and the synced folder holds nothing but your files.

The authoritative specification is [`secsec-Design.md`](secsec-Design.md); the build plan, crate
layout, risk register, and status are in [`secsec-Implementation.md`](secsec-Implementation.md).

> **Status / maturity.** Feature-complete and exercised end-to-end with real processes
> (multiple clients converging through a blind server, including a concurrent-edit three-way merge,
> with a zero-plaintext-leak check on the server store). secsec is **single-host by design** — one
> repo lives on one blind server; every enrolled device is a full plaintext replica, so durability
> rests on those device replicas plus the SSH-key backup, not on server replication. It has **not**
> had an independent professional cryptographic review — do not trust it with irreplaceable data until
> it has (see `secsec-Implementation.md` §8).

## How it works (one paragraph)

Files are split with **keyed FastCDC**, each chunk/tree/commit sealed with a per-object
**fully-committing (CMT-4) AEAD** and content-addressed by a keyed BLAKE3 of its plaintext (re-verified
on every fetch). Membership is an append-only, hash-chained, **SSHSIG-signed roster sigchain** anchored
out-of-band by the repository fingerprint (**RFP**); the master key is wrapped to each device's X-Wing
keyslot and authenticated against a commitment in that chain, so the server can never feed a device a
forged key or a fake repository. New devices enrol over the wire via a single-use **invite code** that
MACs the key-exchange end-to-end through the blind server (which never learns the code). The per-ref
**head** is signed *and* encrypted; the blind server only ever does a compare-and-swap on the hash of
an opaque blob. Transport is QUIC + TLS 1.3 to a **pinned** self-signed host key; connections are
gated on `~/.ssh/authorized_keys`, and every per-op request is individually signed by a rostered key.

## Quickstart

Build the binary:

```sh
cargo build --release      # target/release/secsec
```

The whole CLI is eight commands: `serve · sync · invite · devices · hostpin · log · restore · revoke`.

**Server — run the blind server.** Its only configuration is `~/.ssh/authorized_keys`: list the
**public** key of every device allowed to connect (standard OpenSSH format, one per line). The server
re-reads the file on every connection and **refuses to start without it** — it is the mandatory
connection gate. The server holds no SSH key and no master key; it stores only opaque ciphertext in a
single `repo.secsec` file.

```sh
cat device1.pub device2.pub >> ~/.ssh/authorized_keys   # who may connect
secsec serve /srv/data 8899        # dir defaults to the current dir, port to 8899
# prints the host pin (verify it out-of-band) and the authorized_keys path it is gating on
```

The host pin is `BLAKE3` of the server's self-signed cert. A client trusts it on first contact (TOFU)
and pins it; to confirm there was no first-contact MITM, compare the server's printed `host pin`
against `secsec hostpin <dir>` on the client (it prints the value that folder pinned).

**Device 1 — create the repository and sync.** The first device to sync a folder *creates* the repo
(genesis). It uses `~/.ssh/id_ed25519` (prompting for its passphrase if the key is encrypted). Name
the server once; afterwards just `secsec sync <dir>`.

```sh
secsec sync ~/Sync --server server.example:8899
# "created new repository" → then continuous two-way sync (watches for changes); Ctrl-C to stop
```

**Device 2+ — join with a one-time invite.** Add the new device's public key to the server's
`authorized_keys` first (above). Then, on an already-enrolled device, print an invite; on the new
device, sync with it:

```sh
# on device 1 (enrolled, online):
secsec invite ~/Sync                       # prints a one-time INVITE CODE, then waits
# on device 2:
secsec sync ~/Sync --server server.example:8899 --invite <code>
# "sync: Cloned" → device 2 converges with device 1
```

Both devices sync to the same repo under the default ref (`main`), so they converge even if the local
folders are named differently. The invite code authenticates the join end-to-end through the blind
server (which never learns it), so the server cannot substitute the new device's key or feed it a fake
repository.

**Manage devices.** List the enrolled devices (with their SSH fingerprints, so you can tell which is
which) and revoke a lost one over the wire from any enrolled device:

```sh
secsec devices ~/Sync                       # short id + SHA256:… SSH fingerprint per device
secsec revoke <device-id-prefix> ~/Sync     # rotate the key away from it (forward secrecy)
# then remove its line from the server's ~/.ssh/authorized_keys so it can't reconnect
```

Revocation mints a new key generation the revoked device cannot derive, so it can read nothing written
afterward. Garbage collection runs **automatically** inside `sync` — there is no `gc` command. Run
`secsec <command> --help` for flags.

**History & restore.** Every sync is a signed commit, so the full version history is a by-product. Run
these **inside the synced folder**:

```sh
secsec log                       # the whole repo's change log, newest first
secsec log notes.md              # the version history of one file (or folder)
secsec restore notes.md          # bring back the previous version of notes.md
secsec restore notes.md <id>     # restore the version at a commit id from `secsec log notes.md`
```

`restore` writes the historic file/folder over the current one in your working folder; the running
`sync` then propagates it to your other devices like any edit — no history rewrite, and a concurrent
change still three-way-merges. The whole feature is read-side over the existing encrypted objects (no
server, protocol, or key changes).

## Architecture

A Cargo workspace of small, separately reviewable crates, layered strictly downward (each has its own
`README.md`):

| Layer | Crates |
|---|---|
| Foundation | [`secsec-canon`](crates/secsec-canon) · [`secsec-aead`](crates/secsec-aead) · [`secsec-kdf`](crates/secsec-kdf) · [`secsec-frame`](crates/secsec-frame) |
| Object plane | [`secsec-object`](crates/secsec-object) · [`secsec-chunk`](crates/secsec-chunk) · [`secsec-snapshot`](crates/secsec-snapshot) · [`secsec-store`](crates/secsec-store) |
| Identity & keys | [`secsec-sig`](crates/secsec-sig) · [`secsec-pq`](crates/secsec-pq) · [`secsec-roster`](crates/secsec-roster) |
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
channel (carrying an invite code, or reading a fingerprint off a screen). Each security property in
`secsec-Design.md` §4 (P1–P14) is paired with the exact mechanism that earns it; the bounded,
proven-minimal residuals (availability, reinstall freshness, pre-rotation data for a colluding revoked
device, the concurrent mutual-revocation race, metadata leakage within padding/timing bounds) are
enumerated in §21.

## License

GNU General Public License, version 2 (`GPL-2.0-only`) — see [`LICENSE`](LICENSE).
