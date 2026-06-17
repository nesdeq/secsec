# secsec (binary)

The `secsec` command-line binary — a thin CLI over the workspace crates (`secsec-Design.md` §11, §12).
One server command plus the everyday client commands, all over the network against the blind server.
See the [top-level README](../../README.md) for a quickstart and
[`secsec-Design.md`](../../secsec-Design.md) for the protocol.

## Subcommands

| Command | Purpose (spec) |
|---|---|
| `serve [dir] [port]` | Run the blind sync server (§11/§12). Reads `~/.ssh/authorized_keys` as a **mandatory** connection gate (re-read per connection; refuses to start without it); stores ciphertext in `dir/repo.secsec`; signs §15 arrival receipts. `dir` defaults to the current dir, `port` to 8899. |
| `sync <dir> [--server host[:port]] [--invite code] [--name ref]` | Link a folder to a repo and keep it in continuous two-way sync (§8.1/§10). The first device to a fresh server **creates** the repo (genesis); others join with `--invite`. Name the server once; afterwards just `secsec sync <dir>`. Runs automatic GC (§15) and watches for changes unless `--once`. Uses `~/.ssh/id_ed25519`. |
| `invite <dir>` | On an enrolled device, print a one-time **invite code** and pair a new device over the wire (§7 invite-code pairing). |
| `devices <dir>` | List the repo's enrolled devices: short id + each key's `SHA256:…` SSH fingerprint + a self-marker. |
| `revoke <device> <dir>` | Revoke a device by an id prefix (from `devices`): rotate the master key away from it (and its add-by closure) over the wire so it can read nothing written afterward (§8.4). Then remove its key from the server's `authorized_keys`. |

Every command operates **over the network** against a pinned, RFP-anchored remote (the host key is
pinned trust-on-first-use on the first `sync`; the pin, RFP, and ref are persisted in a per-folder
link under `~/.config/secsec/folders/`). There are no local-store admin commands and no `gc` command —
GC is automatic inside `sync`. Run `secsec <command> --help` for flags.
