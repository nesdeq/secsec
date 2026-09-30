<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/secsec.svg">
    <img alt="secsec" src="assets/secsec-light.svg" width="132">
  </picture>
</p>

# secsec

[![ci](https://github.com/nesdeq/secsec/actions/workflows/ci.yml/badge.svg)](https://github.com/nesdeq/secsec/actions/workflows/ci.yml)
[![license: GPL-2.0-only](https://img.shields.io/badge/license-GPL--2.0--only-blue.svg)](LICENSE)

**Self-hosted, end-to-end-encrypted, two-way file sync, keyed and authenticated entirely by your SSH keys.**

secsec is the open-source, fully encrypted, no-frills alternative to iCloud, OneDrive, and Google
Drive. One small binary is both client and server, and the server is *blind*: it stores only
ciphertext and can never read or forge your data. Your SSH keys are the only credential: they do
both the encryption and the authentication, so there are no accounts, no certificate authority, and
no second password to manage. **Already have a box you can SSH into? That's your server.**

## Features

- **Zero-knowledge.** File contents, file names, and the directory structure are encrypted; the server holds only opaque, content-addressed blobs and sees their sizes (file chunks padded to powers of two).
- **Live two-way sync.** Edit on any device; a three-way merge keeps both sides of a conflict (no silent data loss), and each file keeps its last 8 versions by default.
- **Post-quantum key wraps.** The repository key is wrapped to each device with X-Wing (ML-KEM-768 ⊕ X25519), so the harvest-now-decrypt-later target is quantum-safe today.
- **Just SSH keys.** `~/.ssh/authorized_keys` gates access and `~/.ssh/id_ed25519` is your identity *and* backup. No CA, no database, no accounts, no recovery secret.
- **Self-hosted, one binary.** Client and server in a single self-contained executable with an embedded store.
- **One repo, one synced tree.** Every enrolled device converges on the same content, whatever the local folder is named.

> **Status:** feature-complete and tested end to end, but **not yet independently audited.** The protocol is a bespoke construction over standard primitives; don't trust it with irreplaceable data until it has had a professional cryptographic review.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/nesdeq/secsec/main/install.sh | sh                  # client
curl -fsSL https://raw.githubusercontent.com/nesdeq/secsec/main/install.sh | sh -s -- --server   # server
```

Linux and macOS on x86_64 and aarch64. Windows: download the `.zip` from
[releases](https://github.com/nesdeq/secsec/releases). From source: `cargo build --release --locked`.

The installer verifies every download against the release's `SHA256SUMS` (and its build provenance
with `gh attestation verify` when the GitHub CLI is signed in), puts `secsec` in
`SECSEC_INSTALL_DIR`, else `/usr/local/bin` when writable, else `~/.local/bin`, and asks what it needs
on the terminal (also under `curl | sh`). Re-running a mode updates it in place.

- **Client** (default): the binary, the desktop UI (the GNOME extension or the macOS menu-bar app),
  and an optional guided link of a folder to a server. Without a UI on Linux it offers a systemd user
  service for the folder instead.
- **`--server`**: the binary and `secsec serve` as a user service (systemd with lingering on Linux, a
  LaunchAgent on macOS), with its data directory, UDP port, and the device keys it admits.
- **`--binary`**: only the binary.

Flags answer the questions up front: `--folder`, `--link HOST[:PORT]`, `--pin`, `--invite`,
`--no-ui` for the client; `--dir`, `--port`, `--authorize "ssh-ed25519 ..."` for the server;
`--version TAG`, and `-y` to take flags and defaults without prompting. `--help` lists them all.

## Quick start

Every device authenticates with its own SSH key (`~/.ssh/id_ed25519`; run `ssh-keygen -t ed25519` if
you have none). The server admits only keys listed in its `~/.ssh/authorized_keys`.

```sh
# Server: authorize your devices, then serve a directory (udp/8899)
cat device.pub >> ~/.ssh/authorized_keys
secsec hostpin --serve /srv/data             # the host pin devices check
secsec serve /srv/data

# First device: creates the repository
secsec sync ~/cloud --server server.example --pin <host pin>

# Another device: pair with a one-time invite code
secsec invite ~/cloud                                                # on an enrolled device
secsec sync ~/cloud --server server.example --pin <host pin> --invite   # on the new device; prompts for the code
```

Without `--pin` the first connection trusts the server's key on first use and prints its pin for you
to compare. A folder is remembered after its first sync: afterwards, just `secsec sync ~/cloud`.

## Commands

| Command | |
|---|---|
| `secsec serve [dir] [--port P]` | Run the blind server; it admits only keys in `~/.ssh/authorized_keys`. |
| `secsec sync [dir] [--server H[:P]] [--pin PIN] [--invite [CODE]] [--once]` | Link a folder (first time) and keep it in two-way sync. |
| `secsec stop [dir]` | Stop the sync running for a folder. |
| `secsec status [dir]` | Whether a folder's sync is running and how it last went, as `key=value` lines. |
| `secsec invite [dir]` | Print a one-time code and pair a new device. |
| `secsec devices [dir]` | List enrolled devices with their SSH key fingerprints. |
| `secsec revoke <device> [dir] [-y]` | Revoke a device (and the devices it granted since you last checked), rotating the key away from them. |
| `secsec hostpin [dir]` / `secsec hostpin --serve <dir>` | Print the host pin a folder trusts, or a server's own. |
| `secsec log [path]` | The repository's change log, or one file's or folder's versions. |
| `secsec restore <path> [version]` | Write an earlier version into the folder (default: the previous one). |
| `secsec reset [dir] [-y]` | Remove secsec's own state for a folder and/or serve directory; your files and `~/.ssh` stay. |

`dir` defaults to the current directory; `stop`, `status`, `invite`, `devices`, `revoke`, and
`hostpin` also accept any path inside a synced folder, and `log` and `restore` take paths relative to
where you are inside one. `sync`, `invite`, `devices`, `revoke`, `log`, and
`restore` load your device key: `--key <file>` picks another than `~/.ssh/id_ed25519`, and
`--passphrase-stdin` reads its passphrase from stdin instead of prompting (for launchers: the
passphrase travels over a pipe, never the command line). Every command takes `--help`.

Tunable settings (retention, poll interval, QUIC timeouts, server rates and limits) live in
`~/.config/secsec/secsec.config` (`$XDG_CONFIG_HOME/secsec/` when set), written with defaults on first
use and clamped to safe ranges on load. Retention prunes old versions automatically inside `sync`.

## Run as a service

`install.sh --server` sets the server up as a service. By hand on Linux, the installer's units are:

```sh
systemctl --user enable --now secsec-serve.service                              # the server
systemctl --user enable --now secsec-sync@$(systemd-escape -p ~/cloud).service   # a client folder
loginctl enable-linger                                                          # run from boot, without a login
```

A service cannot type a passphrase, so a headless client needs a key without one:
put `SECSEC_OPTS=--key <file>` in `~/.config/secsec/sync@<escaped path>.conf`. Link the folder once by
hand first. On macOS the installer uses LaunchAgents (`com.secsec.serve`, and `com.secsec.ui` for the
menu-bar app).

## Desktop UIs

Optional panel apps: a **GNOME Shell extension** and a **macOS menu-bar app**. Each asks for your
key passphrase at login, runs `secsec sync` in the background (the passphrase travels over a pipe,
never the command line), lets you set the folder and SSH key, and shows the sync's status. Link the
folder once by hand, then let the UI drive it. Setup: [`ui/README.md`](ui/README.md).

## How it works

Files are split by keyed content-defined chunking and sealed object by object with a fully committing
AEAD (CTX/CMT-4 over ChaCha20-Poly1305), each addressed by a keyed BLAKE3 of its plaintext and
re-verified on every fetch. Membership is an append-only, SSHSIG-signed roster anchored to a
repository fingerprint that travels inside the authenticated invite; the repository key is wrapped to
each device's post-quantum X-Wing keyslot and checked against a commitment in that roster, so the
server can never hand a device a forged key or a fake repository. The repository head is signed *and*
encrypted; the blind server only compare-and-swaps opaque blobs. Transport is QUIC + TLS 1.3 to a
pinned, self-signed host key, with every request individually signed.

The primitives are standard (Ed25519/SSHSIG, X25519, ML-KEM-768, BLAKE3, ChaCha20-Poly1305, TLS 1.3);
the protocol that combines them is bespoke. The full threat model (malicious server, network
attacker, revoked device, stolen client), with the mechanism behind every claim, is in
[`secsec-Design.md`](secsec-Design.md).

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all --all-features
cargo xtask vectors --check
```

A strictly layered Rust workspace (primitives, then the object plane, roster, and sync plane, then
transport, then client and server), with committed known-answer vectors and a `cargo-fuzz` target per
decoder. Crate map, CI, and risk register: [`secsec-Implementation.md`](secsec-Implementation.md).

## Authorship

Designed, built, and reviewed by Claude Opus 4.8 (1M context), Claude Fable 5, and humans, fully in
the open, every line on GitHub. Nothing hidden; read the code and the [design spec](secsec-Design.md).

## License

[GPL-2.0-only](LICENSE).
