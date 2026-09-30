# secsec (binary)

The `secsec` command-line binary: the blind server and every client command over the workspace
crates. See the [top-level README](../../README.md) for a quick start and
[`secsec-Design.md`](../../secsec-Design.md) for the protocol.

## Subcommands

`dir` defaults to the current directory. Commands marked *key* load the device key: `--key <file>`
picks another than `~/.ssh/id_ed25519`, and `--passphrase-stdin` reads its passphrase from stdin
instead of prompting (up to three tries).

| Command | Purpose (spec) |
|---|---|
| `serve [dir] [--port P]` | Run the blind server (§11, §12). Refuses to start without an Ed25519 key in `~/.ssh/authorized_keys`, the mandatory connection gate (re-parsed when the file changes). Keeps the repository in `dir/repo.secsec` and the self-signed host key in `dir/hostkey/`; compacts the repository at start, reclaims idle staging on a timer (§15), answers unvalidated sources with a QUIC Retry, limits new connections per source IP, and caps concurrent connections server-wide. The port defaults to `listen_port` in `secsec.config` (8899). |
| `sync [dir] [--server H[:P]] [--pin PIN] [--invite [CODE]] [--once]` *key* | Link a folder to a repository and keep it in two-way sync (§7, §10). The first device on an empty server creates the repository; another joins with `--invite` (the code is prompted for when omitted). `--pin` pins the host up front; without it the first connection trusts on first use and prints the pin, and a `--pin` that disagrees with a linked folder's pin is refused. Afterwards `secsec sync <dir>` suffices. Watches the folder and polls the server until stopped, or syncs once with `--once`. |
| `stop [dir]` | Stop the sync running for a folder: signal the pid its lock names, and kill it if it outlives the QUIC idle timeout. |
| `status [dir]` | Print `folder`, `server`, `running`, and the running sync's last `state`, `last_sync`, `last_result`, `conflicts`, `skipped`, and `message`, as `key=value` lines. |
| `invite [dir]` *key* | On an enrolled device, print a one-time invite code and the join command, then pair the new device over the wire (§7); waits up to 10 minutes. |
| `devices [dir]` *key* | List the enrolled devices: short id, the key's `SHA256:…` SSH fingerprint, and a marker for this device. |
| `revoke <device> [dir] [-y]` *key* | Revoke a device by an id prefix from `devices`, with every device it granted since this device last verified the roster (§8.1, §8.4): preview them, confirm (`-y` skips it), then rotate the key away in one batch. Refuses to revoke the device it runs on. Afterwards remove their keys from the server's `authorized_keys`. |
| `hostpin [dir]` / `hostpin --serve <dir>` | Print the host pin a linked folder trusts (offline), or a serve directory's own, creating its host key if absent. |
| `log [path]` *key* | The repository's change log, or one file's or folder's versions (§15). |
| `restore <path> [version]` *key* | Write a version of a file or folder into the synced folder, overwriting what is there (§10); `version` is a commit-id prefix from `log <path>`, default the previous version. The running sync propagates it. |
| `reset [dir] [-y]` | Remove secsec's own state: a folder's state directory and/or a serve directory's `repo.secsec` and host key, after confirmation (`-y` skips it). Your files and `~/.ssh` stay. Refuses while a sync or `serve` holds them. |

`stop`, `status`, `invite`, `devices`, `revoke`, and `hostpin` accept any path inside a synced folder;
`log` and `restore` take paths relative to the current directory, which must be inside one.

## Files

State lives under `$XDG_CONFIG_HOME/secsec` when that is an absolute path, else `~/.config/secsec`:

- `secsec.config`: the operator-tunable settings (§19), written with defaults by the first command
  that loads it and clamped to their ranges on load.
- `folders/<hex BLAKE3 of the canonical folder path>/`, per synced folder (§13): `link` (server,
  pinned `host_id`, RFP, and the roster anchor), `link.lock`, `objects.secsec` (the encrypted object
  cache), `frontier` (the sealed rollback state), `base`, `push_id`, `lock` (one sync per folder,
  naming its pid), and `status`.

A folder that contains this state directory is refused, so it can never sync itself. There is no
`prune` or `gc` command: retention runs inside `sync` (§15). Run `secsec <command> --help` for flags;
`secsec --version` prints the release tag a release build carries, else the crate version.
