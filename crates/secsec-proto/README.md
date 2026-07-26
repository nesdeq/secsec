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

- `op_and_args(request) -> (op, args_hash, is_write)` — the single shared binding. Client and server
  both call it, so neither can disagree about what a signature covers. The individual `args_*` binders
  behind it are crate-internal on purpose: computing one by hand at a call site is how the two sides
  drift apart.
- `op` — the op-label constants (`PUT`, `CAS_HEAD`, `ROSTER_APPEND`, `PRUNE`, `GET`, …).
- `WriteAuth` / `ReadAuth` — `sign` / `verify` over `op ‖ args_hash ‖ transcript` (+ `server_nonce`
  for writes, §9.6).
- `prune` (§15) — `all_heads_hash`, `dead_set_hash` (canonical ascending id-list), `args_prune` (the
  head-binding CAS input). Public because `prune`'s binding is state-dependent, so it is computed
  outside `op_and_args` by both the client driver and the server handler.
- `wire` — `Request` / `Response` / `ClientHello` / `ServerHello` / `ClientAuth` / `AuthedRequest`
  (`encode` / `decode`), `ErrorCode`, `WireError`.
- `server` — the enforcement state, clock-injected: `NonceStore` (single-use `server_nonce`),
  `TokenBucket`, `WindowCounter`, `StorageQuota`, `Limits`, and the normative `limits` constants.
- `Id`, `PUSH_ID_LEN`, `ProtoError`.
