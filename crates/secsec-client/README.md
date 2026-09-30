# secsec-client

Client orchestration over a [`Remote`] (`secsec-Design.md` §7, §8, §10, §12, §15): the top of the
library stack, plumbing the proven cores into the end-to-end flows the `secsec` binary drives.

The remote is the [`Remote`] trait, the §12 server surface; `quic::QuicRemote` implements it over a
handshaken connection, and a test-only in-process implementation runs the same flows against a real
store with the server's CAS, batch, prune, and mailbox semantics. Every object fetched is verified
before it is stored (§9.2).

## Modules / public API

- **`repo`**: the repository lifecycle over the wire. `init_repo_remote` (one genesis batch: the
  entry and this device's keyslot), `open_repo_remote` (the §8.1 cold start against the persisted
  `RosterAnchor`), `roster_grew` (the cheap per-tick probe), `data_keyring_remote` (the §8.2 key
  ring), `rotate_repo_remote` (one atomic batch, optionally with a `Revoke`, re-signing the head when
  its signer goes; retries only while the tip or the head moves), `revoke_preview`, `Rotation`,
  `RepoError`.
- **`pair`** (§7): invite-code pairing through the server's mailbox. `new_invite`, `decode_code`,
  `run_host` (`secsec invite`: await the joiner, grant it, send the RFP and host pin) and `run_join`
  (`secsec sync --invite`: post the keys, check the vouched pin against the connected server);
  `PairError`.
- **`sync`**: `sync_once` (clone, publish, push, pull, or merge in one call), `SyncInput` (its
  `seal` callback persists the frontier before any ref-advancing push), `SyncKind`, `SyncOutcome` (the
  new base and frontier for the caller to persist in that order, the keep-both `conflicts`, the
  `skipped` paths, and `base_missing`).
- **`history`** (§15): the read side of `secsec log` and `secsec restore`. `fetch_history` (commits
  signature-checked against `ever_members`, trees as held), `repo_log`, `path_history`, `commit_ids`,
  `restore` (fetching only the chunks the path needs); `LogEntry`, `PathVersion`.
- **`prune`** (§15): `local_sweep` (drops cache objects the head does not reach) and `prune_history`
  (keep each file's last `keep` versions, delete other chunks locally and on the server under the
  head-binding CAS; `Ok(false)` means retry later). Driven by the `sync` loop; there is no `prune`
  command.
- **`quic`**: `QuicRemote`.
- **`watcher`**: `watch_dir` turns a burst of filesystem events into one callback after a quiet
  interval or a maximum delay; `WatchError`.
- Crate root: `Remote`, `RemoteError`, `RosterWrite`, `fetch_head`, `fetch_verified_head` /
  `RemoteHead` (a head only a current member signed), `load_frontier` / `save_frontier` /
  `FrontierLoad` (the §8.5 sealed state, migrating a v1 seal), `write_private_atomic`, `ClientError`.

The primitives `sync_once` composes (`push_objects`, `push_head`, `fetch_commits`, `fetch_tree`,
`fetch_closure`) and the grant `grant_device_remote` are crate-internal: driving them individually is
how the §8.5 seal-before-publish ordering gets skipped.

A fork (a DAG-incomparable head) is reconciled by the three-way merge, with divergent paths kept both
ways as `name.conflict-*` copies and surfaced to the user; there is no multi-remote or gossip layer
(single-host by design).
