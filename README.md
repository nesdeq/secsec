# secsec

**Self-hosted, zero-knowledge, end-to-end-encrypted, live two-way file sync.** One static binary is
both server and client. The server is **blind**: it stores only ciphertext and can neither read nor
forge your data. The only credential is your **SSH key**.

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

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/nesdeq/secsec/main/install.sh | sh
```

Detects OS/arch (Linux/macOS, x86_64/aarch64), fetches the latest
[release](https://github.com/nesdeq/secsec/releases), verifies its checksum, and installs to
`/usr/local/bin` or `~/.local/bin` (override with `SECSEC_INSTALL_DIR`). Windows: download the
`.zip` from the releases page. Building from source instead: `cargo build --release`.

## Quick start

All examples use `server.example` as the server and the default port (udp/8899). Conventions:
`<arg>` is required, `[arg]` is optional, `[dir]` defaults to the current directory.

**Device keys.** Each device uses its standard SSH key, `~/.ssh/id_ed25519`. A device that doesn't
have one yet generates it the usual way (it's a normal SSH key — usable for ssh too; a passphrase is
fine, secsec prompts for it):

```sh
ssh-keygen -t ed25519               # creates ~/.ssh/id_ed25519 and ~/.ssh/id_ed25519.pub
```

**Server.** The connection gate is the `~/.ssh/authorized_keys` of the user running `secsec serve` —
the same file sshd uses, so any key that can already SSH into that account is **accepted by
default**. Append only the keys not already in it (each device's `id_ed25519.pub`); the file is
re-read on every connection (no restart needed).

```sh
cat laptop.pub phone.pub >> ~/.ssh/authorized_keys   # the devices' id_ed25519.pub files
secsec serve /srv/data                               # prints the host pin
```

**First device** — creates the repository:

```sh
secsec sync ~/Sync --server server.example
```

Compare the fingerprint it prints against the server's `host pin` out-of-band (later:
`secsec hostpin ~/Sync`) to rule out a first-contact MITM.

**Every further device** — authorize its key on the server (above), then pair with a one-time code:

```sh
secsec invite ~/Sync                                          # on an enrolled device: prints a code, waits
secsec sync ~/Sync --server server.example --invite <code>    # on the new device
```

The code authenticates the join end-to-end through the blind server (which never learns it), so the
server cannot swap the new device's key or serve a fake repository. From then on, each device just
runs `secsec sync ~/Sync`.

## Commands

### `secsec serve [dir] [port]`

Run the blind server. Stores the encrypted repo (`repo.secsec`) and host key under `dir`; refuses to
start without a usable `~/.ssh/authorized_keys`.

```sh
secsec serve                        # serve ./ on udp/8899
secsec serve /srv/data              # serve /srv/data on udp/8899
secsec serve /srv/data 9000         # custom port
```

### `secsec sync [dir] [--server host[:port]] [--invite code] [--once]`

Link a folder to a repo and keep it in continuous two-way sync (watches for changes; Ctrl-C stops).
`--server` is needed only the first time — the link is remembered per folder. The first device to
reach an empty server creates the repository; joining an existing one requires `--invite`.

```sh
secsec sync                                                   # sync ./ (already linked)
secsec sync ~/Sync                                            # sync a linked folder
secsec sync ~/Sync --server server.example                    # first time: create the repo
secsec sync ~/Sync --server server.example --invite <code>    # first time: join an existing repo
secsec sync ~/Sync --once                                     # one pass, then exit (cron/scripts)
```

### `secsec invite [dir]`

Print a one-time invite code and wait for the new device to pair (it runs `sync --invite`). Run on
an enrolled device.

```sh
secsec invite                       # invite into the repo ./ is linked to
secsec invite ~/Sync                # invite into the repo ~/Sync is linked to
```

### `secsec devices [dir]`

List enrolled devices: short device id + `SHA256:…` SSH fingerprint (as `ssh-keygen -lf` prints it),
with a marker for the current device.

```sh
secsec devices
secsec devices ~/Sync
```

### `secsec revoke <device> [dir]`

Revoke a device by id prefix (from `devices`): rotates the master key away from it, so it cannot
read anything written afterward. Self-revocation is refused. Afterwards, remove its key from the
server's `authorized_keys` so it cannot reconnect.

```sh
secsec revoke 3fa8                  # device-id prefix; repo of ./
secsec revoke 3fa8 ~/Sync           # repo of ~/Sync
```

### `secsec hostpin [dir]`

Show the host pin this folder trusts (offline — reads the local link). Compare it out-of-band with
the `host pin` the server prints on startup.

```sh
secsec hostpin
secsec hostpin ~/Sync
```

### `secsec log [path]`

Change log of the whole repo, or the version history of one file/folder. Run **inside** the synced
folder.

```sh
secsec log                          # whole repo, newest first
secsec log notes.md                 # one file's versions
secsec log docs/                    # one folder's versions
```

### `secsec restore <path> [version]`

Write a historic version of `path` back into the working folder; the next sync propagates it like
any edit. Without `version`: the previous version — or, if `path` was deleted, the last version that
existed (undo-delete). Run **inside** the synced folder.

```sh
secsec restore notes.md             # previous version (or undo a deletion)
secsec restore notes.md 3fa8b2      # version at a commit-id prefix from `secsec log notes.md`
secsec restore docs/                # restore a whole folder
```

### `secsec reset [dir] [-y|--yes]`

Wipe secsec's state at `dir` — the client link/cache of a synced folder, and/or a server's
`repo.secsec` + host key — leaving your files and `~/.ssh` untouched. Prompts with the exact paths
unless `-y`. Stop a running sync/serve first.

```sh
secsec reset                        # reset ./ (asks first)
secsec reset ~/Sync -y              # no prompt
```

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
