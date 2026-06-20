# secsec-proto

Per-operation authorization and the wire protocol for the server API (`secsec-Design.md` §12, §9.6,
§15).

**Every** repo operation — including reads — requires a per-op signature from a key that owns a
keyslot (a rostered device); connection-level auth alone is not enough (§12). This crate builds the
two signed payloads and the per-op `args_hash` that binds the exact operation:

- **Write** ops (`put` (binds `push_id`), `cas-head` (binds `promote`), `roster-append`,
  `put-keyslot`, `delete-keyslot`, `put-keyhist`, `put-roster-keyhist`, `prune`): sign under
  `NS_WRITE` over
  `op ‖ args_hash ‖ session_transcript ‖ server_nonce` (§9.6). The server supplies only the fresh
  single-use `server_nonce`; the client constructs `op`/`args`.
- **Read** ops (`get`, `get-ref`, `get-roster`, `get-keyslot`, `has`, and the §7 `pair-put`/`pair-get`
  invite-mailbox relay): sign under `NS_READ` over `op ‖ args_hash ‖ session_transcript` — no
  `server_nonce`, since `session_transcript` provides per-connection freshness.

## Public API

- `args_*` — the normative per-op `args_hash` binders: `args_put`, `args_cas_head`,
  `args_roster_append`, `args_get_roster`, `args_get_keyslot`, `args_put_keyslot`, `args_keyhist`,
  `args_pair`, `args_read`.
- `prune` (§15) — `all_heads_hash`, `dead_set_hash` (canonical ascending id-list), `args_prune` (the
  head-binding CAS input).
- `Request` / `Response` — the wire messages (`encode` / `decode`, bounded by `MAX_REQUEST_LEN`).
- The server-side replay/rate-limit state: a single-use **nonce** issuer (`issue` / `consume` /
  `evict_expired`), a token-bucket rate limiter, and concurrency counters.
- `ErrorCode`, `ProtoError`, `WireError`, `MAX_PUBKEY`, `MAX_SIG`.
