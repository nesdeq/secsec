<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/secsec.svg">
    <img alt="secsec" src="assets/secsec-light.svg" width="132">
  </picture>
</p>

# secsec

[![ci](https://github.com/nesdeq/secsec/actions/workflows/ci.yml/badge.svg)](https://github.com/nesdeq/secsec/actions/workflows/ci.yml)
[![license: GPL-2.0-only](https://img.shields.io/badge/license-GPL--2.0--only-blue.svg)](LICENSE)

**Self-hosted, end-to-end-encrypted, two-way file sync — keyed and authenticated entirely by your SSH keys.**

secsec is the open-source, fully-encrypted, no-frills alternative to iCloud, OneDrive, and Google
Drive. One small binary is both client and server, and the server is *blind* — it stores only
ciphertext and can never read or forge your data. Your SSH keys are the only credential: they do
both the encryption and the authentication, so there are no accounts, no certificate authority, and
no second password to manage. **Already have a box you can SSH into? That's your server.**

## Features

- **Zero-knowledge** — file *contents and metadata* (names, directory structure, sizes within padding) are encrypted; the server holds only opaque, content-addressed blobs.
- **Live two-way sync** — edit on any device; a three-way merge keeps both sides on a conflict (no silent data loss), and full version history comes for free.
- **Post-quantum key wraps** — device keys are sealed with X-Wing (ML-KEM-768 ⊕ X25519), so the harvest-now-decrypt-later target is quantum-safe today.
- **Just SSH keys** — `~/.ssh/authorized_keys` gates access and `~/.ssh/id_ed25519` is your identity *and* backup. No CA, no database, no accounts, no recovery secret.
- **Self-hosted, one binary** — client and server in a single self-contained executable with an embedded store; no external database.
- **One repo, one synced tree** — every enrolled device converges on the same content, whatever the local folder is named.

> **Status:** feature-complete and tested end-to-end, but **not yet independently audited.** The protocol is a bespoke construction over standard primitives — don't trust it with irreplaceable data until it has had a professional cryptographic review.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/nesdeq/secsec/main/install.sh | sh
```

Linux/macOS, x86_64/aarch64. Windows: download the `.zip` from
[releases](https://github.com/nesdeq/secsec/releases). From source: `cargo build --release`.

The installer puts `secsec` on your `PATH` and, on Linux, adds `systemctl --user` service templates;
`--binary` / `--systemd` / `--all` select components (`--help` lists them).

## Quick start

Every device authenticates with its own SSH key (`~/.ssh/id_ed25519`; run `ssh-keygen -t ed25519` if
you have none). The server admits only keys listed in its `~/.ssh/authorized_keys`.

```sh
# Server — authorize your devices, then serve a directory (udp/8899)
cat device.pub >> ~/.ssh/authorized_keys
secsec serve /srv/data                       # prints a host fingerprint to verify out-of-band

# First device — creates the repository
secsec sync ~/cloud --server server.example

# Another device — pair with a one-time invite code
secsec invite ~/cloud                                       # on an enrolled device
secsec sync ~/cloud --server server.example --invite CODE   # on the new device
```

A folder is remembered after its first sync — afterwards, just `secsec sync ~/cloud`.

## Commands

| Command | |
|---|---|
| `secsec serve [dir] [port]` | Run the blind server (gated on `~/.ssh/authorized_keys`). |
| `secsec sync [dir] [--server H] [--invite C] [--once] [--key F] [--passphrase-stdin]` | Link a folder and sync continuously. |
| `secsec invite [dir]` | Print a one-time code to enroll another device. |
| `secsec devices [dir]` | List enrolled devices and key fingerprints. |
| `secsec revoke <device> [dir]` | Rotate the master key away from a device. |
| `secsec hostpin [dir]` | Show the server pin this folder trusts (offline). |
| `secsec log [path]` | Repo or per-file change history. |
| `secsec restore <path> [version]` | Restore a historic version into the folder. |
| `secsec reset [dir]` | Wipe local secsec state (your files and `~/.ssh` are untouched). |

Every command takes `--help`; all client commands accept `--key <file>` to use a key other than the
default, and `--passphrase-stdin` to read the key's passphrase from stdin instead of prompting (for
headless/GUI launchers — the passphrase travels over a pipe, never the command line). History
retention (keeping the last few versions of each file) runs automatically inside `sync`.

## Run as a service

On Linux the installer adds two `systemctl --user` templates. Serve, or enroll a device, once by
hand; then:

```sh
systemctl --user enable --now secsec-serve@$(systemd-escape -p /srv/data).service   # server
systemctl --user enable --now secsec-sync@$(systemd-escape -p ~/cloud).service       # client
```

A service can't prompt, so a headless client either uses an empty-passphrase key (pass it with
`--key`) or feeds the passphrase over stdin with `--passphrase-stdin` — the launcher writes it to the
process's stdin, so it never appears on the command line or in `ps`/`top`. To run at boot without
logging in: `loginctl enable-linger`.

## Desktop menu-bar UIs

Optional native launchers for a passphrase-protected key: a **GNOME Shell extension** and a **macOS
menu-bar app**. Each prompts for your key passphrase at login, runs `secsec sync` in the background
(passphrase fed over a pipe, never the command line), lets you set the folder + SSH key, and shows a
connect-status indicator. Link the folder once by hand, then let the UI drive it. Setup:
[`ui/README.md`](ui/README.md).

## How it works

Files are split with keyed FastCDC and sealed object-by-object with a fully-committing AEAD
(CTX/CMT-4 over ChaCha20-Poly1305), each addressed by a keyed BLAKE3 of its plaintext and re-verified
on every fetch. Membership is an append-only, SSHSIG-signed roster anchored to an out-of-band
repository fingerprint; the master key is wrapped to each device's post-quantum X-Wing keyslot and
checked against a commitment, so the server can never hand a device a forged key or a fake
repository. Per-folder heads are signed *and* encrypted; the blind server only compare-and-swaps
opaque blobs. Transport is QUIC + TLS 1.3 to a pinned, self-signed host key, with every request
individually signed.

The primitives are standard (Ed25519/SSHSIG, X25519, ML-KEM-768, BLAKE3, ChaCha20-Poly1305, TLS 1.3);
the protocol that combines them is bespoke. The full threat model — malicious server, network
attacker, revoked device, stolen client — with the mechanism behind every claim, is in
[`secsec-Design.md`](secsec-Design.md).

## Development

```sh
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
```

A strictly-layered Rust workspace (committing AEAD → key hierarchy → object plane → identity/roster →
sync → transport → client/server), with committed known-answer vectors and a `cargo-fuzz` target per
decoder. Crate map and risk register: [`secsec-Implementation.md`](secsec-Implementation.md).

## Authorship

Designed, built, and reviewed by Claude Opus 4.8 (1M context), Claude Fable 5, and humans — fully in
the open, every line on GitHub. Nothing hidden; read the code and the [design spec](secsec-Design.md).

## License

[GPL-2.0-only](LICENSE).
