# secsec

**Self-hosted, zero-knowledge, end-to-end-encrypted, live two-way file sync.** One static Rust
binary is both server and client. The server is **blind**: it stores only ciphertext and can neither
read nor forge your data. The only credential is your **SSH key**.

- **Zero-knowledge server** — content *and* metadata (names, structure, sizes within padding bounds)
  are encrypted; the server holds opaque, content-addressed blobs.
- **Live two-way sync** — edit on any device; conflicts resolve by three-way merge with **no silent
  data loss**; full version history is a by-product.
- **Post-quantum by default** — key wraps use X-Wing (ML-KEM-768 ⊕ X25519); mandatory, not opt-in.
- **SSH key is the only credential** — `~/.ssh/authorized_keys` gates connections; `~/.ssh/id_ed25519`
  is identity *and* backup. No CA, no database, no extra secrets.
- **One repo = one synced tree** — every enrolled device converges on the same content, regardless
  of local folder names. An independent tree is an independent repo (its own server store).

The authoritative spec is [`secsec-Design.md`](secsec-Design.md); crate layout, risk register, and
assurance strategy are in [`secsec-Implementation.md`](secsec-Implementation.md).

> **Maturity.** Feature-complete and exercised end-to-end, but it has **not had an independent
> professional cryptographic review** — do not trust it with irreplaceable data until it has.
> Durability rests on your device replicas and SSH-key backup, not on server replication.

## Quick start

```sh
cargo build --release        # → target/release/secsec
```

**1 — Server.** List each device's *public* key in `~/.ssh/authorized_keys` (standard OpenSSH
format; re-read on every connection, so changes need no restart), then:

```sh
secsec serve /srv/data            # prints the host pin — verify it out-of-band
```

**2 — First device.** The first device to sync creates the repository:

```sh
secsec sync ~/Sync --server server.example:8899
# "created new repository" → continuous sync; Ctrl-C to stop. Later just: secsec sync ~/Sync
```

Compare the fingerprint it prints (`secsec hostpin ~/Sync` re-shows it) against the server's
`host pin` to rule out a first-contact MITM.

**3 — More devices.** Add the new device's public key to the server's `authorized_keys`, then:

```sh
secsec invite ~/Sync                                            # on an enrolled device: prints a one-time code, waits
secsec sync ~/Sync --server server.example:8899 --invite <code> # on the new device
```

The code authenticates the join end-to-end through the blind server (which never learns it), so the
server cannot swap the new device's key or serve a fake repository.

## Command reference

`<arg>` required · `[arg]` optional · `[dir]` defaults to the current directory.

| Command | What it does |
|---|---|
| `serve [dir] [port]` | Run the blind server. Stores the encrypted repo (`repo.secsec`) and host key under `dir`; listens on UDP `port` (default 8899). Refuses to start without a usable `~/.ssh/authorized_keys`. |
| `sync [dir] [--server host[:port]] [--invite code] [--once]` | Link `dir` to a repo and sync continuously. `--server` is required only the first time; `--invite` joins an existing repo; `--once` syncs once and exits instead of watching. |
| `invite [dir]` | Print a one-time invite code and wait for the new device to pair. Run on an enrolled device. |
| `devices [dir]` | List enrolled devices: short id + `SHA256:…` SSH fingerprint, with a marker for the current device. |
| `revoke <device> [dir]` | Revoke a device by id prefix (from `devices`): rotates the master key away from it so it cannot read anything written afterward. Then remove its key from the server's `authorized_keys`. Self-revocation is refused. |
| `hostpin [dir]` | Show the host pin this folder trusts (offline), for out-of-band comparison with the server's printed `host pin`. |
| `log [path]` | Change log of the whole repo, or the version history of one file/folder. Run **inside** the synced folder. |
| `restore <path> [version]` | Write a historic version of `path` back into the working folder; the next sync propagates it like any edit. `version` is a commit-id prefix from `log`; omit it for the previous version (or, if `path` was deleted, the last version that existed). Run **inside** the synced folder. |
| `reset [dir] [-y/--yes]` | Wipe secsec's state at `dir` — the client link/cache of a synced folder and/or a server's repo + host key — leaving your files and `~/.ssh` untouched. Prompts unless `-y`. Stop a running sync/serve first. |

Every command supports `--help`. There is no `gc` command — garbage collection runs automatically
inside `sync` (deletes nothing newer than 48 h, never anything reachable).

## Behaviour notes

- **Device key:** `~/.ssh/id_ed25519` (Ed25519 only). A passphrase-encrypted key is prompted for and
  decrypted in memory; the on-disk key is never modified. An ssh-agent is not enough — secsec derives
  encryption keys from the private key itself.
- **What syncs:** regular files and directories. Symlinks, FIFOs, sockets, and devices are skipped
  (never an error, never deleted on peers). setuid/setgid/sticky bits are not preserved.
- **Deletions propagate.** A file deleted on one device is removed on the others.
- **Conflicts keep both sides:** a concurrent edit yields `name.conflict-<device>-<commit>.ext`
  alongside your version, and the sync prints which paths conflicted.
- **Client state** lives out-of-tree under `~/.local/state/secsec/` — the synced folder holds nothing
  but your files.

## How it works

Files are chunked with keyed FastCDC; every chunk/tree/commit is sealed with a fully-committing
(CMT-4) AEAD and content-addressed by a keyed BLAKE3 of its plaintext, re-verified on every fetch.
Membership is an append-only, hash-chained, SSHSIG-signed roster anchored by the repository
fingerprint; the master key is wrapped to each device's X-Wing keyslot and verified against a
commitment in that chain, so the server can never feed a device a forged key or a fake repository.
The per-folder head is signed *and* encrypted; the blind server only compare-and-swaps opaque blobs.
Transport is QUIC + TLS 1.3 to a pinned, self-signed host key; every request is individually signed
by an enrolled key.

**Threat model:** the adversary is a malicious/compromised server, a network attacker, a revoked
device, and a stolen client. Trusted: your devices' SSH keys and one out-of-band channel (carrying
an invite code or comparing a fingerprint). Each claim in `secsec-Design.md` §4 is paired with its
mechanism; the proven-minimal residuals are enumerated in §21.

## Development

```sh
cargo test --workspace                                # full suite
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo xtask vectors --check                           # KATs match the live code
cargo audit                                           # supply-chain advisories
```

A Cargo workspace of small, strictly-layered crates (each with its own README): foundation
(`canon`, `aead`, `kdf`, `frame`) → object plane (`object`, `chunk`, `snapshot`, `store`) →
identity (`sig`, `pq`, `roster`) → sync (`sync`, `engine`) → wire (`transport`, `proto`) →
orchestration (`client`, `server`, `bin/secsec`). Known-answer vectors live in
[`vectors/`](vectors), fuzz targets in [`fuzz/`](fuzz). CI runs lint, tests on
Linux/macOS/Windows, and the advisory scan; `rc*`/`v*` tags build release binaries.

## License

GPL-2.0-only — see [`LICENSE`](LICENSE).
