# secsec (binary)

The `secsec` command-line binary — a thin CLI over the workspace crates (`secsec-Design.md` §11, §12).
Client subcommands plus `serve` (the blind server). See the [top-level README](../../README.md) for a
quickstart and [`secsec-Design.md`](../../secsec-Design.md) for the protocol.

## Subcommands

| Command | Purpose (spec) |
|---|---|
| `init` | Repository genesis (§7): write the genesis roster + this device's keyslot into the store; print the **RFP** anchor. |
| `serve` | Run the blind sync server (signs §15 arrival receipts with its host receipt key). |
| `hostkey` | Print the server's host pin (`host_id`) that clients pin via `--host-fp`. |
| `sync` | Cold-start over the wire, then reconcile a working dir with a ref (§8.1/§10); `--watch` for continuous live sync. Persists arrival receipts for a later `gc`. |
| `rotate` | Mint a new master-key generation (§8.4); `--revoke <device-id>` for the `revoke ⇒ rotate` forward-secrecy flow. |
| `enroll-pubkey` | Print this device's SSH + X-Wing public keys to hand to a granter (§7). |
| `grant` | Enroll a new device whose keys were SAS-verified out-of-band (§7); enforces the per-`D_pubkey` rate limit. |
| `recovery-init` | Create the §8.6 recovery keyslot; print the 256-bit recovery code once. |
| `recover` | Break-glass recovery from the code alone; restore a ref's tree into a directory (§8.6). |
| `gc` | Client-driven, grace-windowed garbage-collection sweep against the remote (§15). |

`init` / `rotate` / `grant` / `recovery-init` / `recover` operate **directly on a local store** (admin
ops); `sync` / `gc` operate **over the network** against a pinned, RFP-anchored remote. Run
`secsec <command> --help` for flags.
