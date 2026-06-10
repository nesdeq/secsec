# secsec-client

Client orchestration over a [`Remote`] (`secsec-Design.md` §10, §12, §14, §15). The top of the
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
  in-process variants (`init_repo` / `open_repo` / `rotate_repo` / `grant_device` / `data_keyring`) back
  the tests. `device_xwing_pub`, `RepoError`, `ALGO_XWING`.
- **`pair`** (§7) — **invite-code pairing**, the shipped enrollment flow: `new_invite` / `encode_code`
  / `decode_code`, `run_host` (`secsec invite`) and `run_join` (`secsec sync --invite`) — MAC-under-code
  through the server's transient mailbox; `PairError`.
- **`sync`** — `sync_once` (clone / publish / pull / merge in one call), `SyncKind`, `SyncOutcome`.
- Push/pull primitives: `push_objects` / `push_head`, `fetch_head` / `fetch_closure` /
  `pull_restore`, `sync_ref` (+ `resolve_head_signer`).
- **`gc`** (§15) — `gc_collect`, the arrival-receipt log (`parse_receipt_log` / `serialize_receipt_log`
  / `merge_receipts`), `gc_gen_from_log` / `gc_gen_from_receipts`, `put_epoch_from_log`,
  `GC_GRACE_WINDOW_SECS`, `GcOutcome`. (Driven automatically from the `sync` loop — no `gc` command.)
- **`multiremote`** (§14) — `quorum_put_objects`, `reconcile_roster_tips`, `detect_head_rollback`.
- **`gossip`** (§10) — `cross_remote_fork_scan`, `check_peer_head`, the fork-event log.
- **`enroll`** (§7/§9.6) — the rate-limit for the lower-level **direct-grant** primitive
  (`record_grant_attempt`, `MAX_GRANT_SESSIONS_PER_HOUR`); the shipped invite-pairing path in `pair`
  bounds online guessing by the single-use code + mailbox TTL instead.
- **`watcher`** — `notify`-driven debounced change ticks for live sync.
- Frontier persistence: `load_frontier` / `save_frontier` (§8.5), `Receipt`, `Remote`, `ClientError`.
