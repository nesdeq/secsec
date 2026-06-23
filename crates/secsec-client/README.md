# secsec-client

Client orchestration over a [`Remote`] (`secsec-Design.md` §10, §12, §15). The top of the
library stack — it plumbs the proven cores into the end-to-end flows the `secsec` binary drives.

It pushes the reachable **object closure** of a commit, advances the per-ref **head** via the
blind-server compare-and-swap (§12), and on the read side fetches a head, fetches a commit's closure
**verifying every object on arrival** (§9.2), and restores it. The remote is abstracted as the
[`Remote`] trait, so the orchestration is exercised against the real blind-CAS semantics in-process;
the QUIC adapter (`quic.rs`, over `secsec-transport`) is a thin layer on top.

## Modules / public API

- **`repo`** — repository lifecycle. The networked path the CLI uses: `init_repo_remote` (first-device
  genesis), `open_repo_remote` (§8.1 cold-start fold), `grant_device_remote`, `rotate_repo_remote`
  (also the engine of `revoke`), `data_keyring_remote` (§8.2 key ring), `fetch_roster_entries`. Local
  in-process variants (`init_repo` / `open_repo` / `rotate_repo` / `data_keyring`) back the tests.
  `device_xwing_pub`, `RepoError`, `ALGO_XWING`.
- **`pair`** (§7) — **invite-code pairing**, the shipped enrollment flow: `new_invite` / `encode_code`
  / `decode_code`, `run_host` (`secsec invite`) and `run_join` (`secsec sync --invite`) — MAC-under-code
  through the server's transient mailbox; `PairError`.
- **`sync`** — `sync_once` (clone / publish / pull / merge in one call), `SyncKind`, `SyncOutcome`.
- Push/pull primitives: `push_objects` / `push_head`, `fetch_head` / `fetch_closure`,
  `sync_ref` (+ `resolve_head_signer`).
- **`history`** (§10/§15) — the read side of `secsec log` / `secsec restore`: `fetch_history`,
  `repo_log`, `path_history`, `commit_ids`, `restore`.
- **`prune`** (§15) — `local_sweep` (drops cache orphans unreachable from the head) and
  `prune_history` (count-based retention: keep the last N versions per file, delete the rest under the
  head-CAS). (Driven automatically from the `sync` loop — no `prune` command.)
- **`watcher`** — `notify`-driven debounced change ticks for live sync.
- Frontier persistence: `load_frontier` / `save_frontier` (§8.5), `Remote`, `ClientError`.

Fork detection is the **same-server DAG-incomparable check** in the merge path (a divergence is kept
both-sides as a `name.conflict-*` copy and surfaced to the user); there is no multi-remote or gossip
layer (single-host by design).
