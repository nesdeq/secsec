# secsec-proto

The wire protocol and per-operation authorization for the server API (`secsec-Design.md` §9.6, §12,
§15, §19).

**Every** repo operation, reads included, carries a per-op signature; the server additionally
requires the signer to own a keyslot, except for the pairing mailbox and the genesis batch (§12).
This crate builds the two signed payloads and the `args_hash` that binds the exact operation:

- **Write** ops (`put`, which binds `push_id`; `cas-head`, which binds `promote`; `roster-batch`,
  which binds the hash of its whole encoding; `prune`): signed under `NS_WRITE` over
  `bytes(op) ‖ args_hash ‖ session_transcript ‖ server_nonce` (§9.6). The server supplies only the
  per-stream `server_nonce`; the client constructs op and args.
- **Read** ops (`get`, `has`, `get-ref`, `get-roster`, `get-keyslot`, `get-keyhist`,
  `get-roster-keyhist`, and the §7 `pair-put` / `pair-get` mailbox relay): signed under `NS_READ` over
  `bytes(op) ‖ args_hash ‖ session_transcript`; no nonce, since the transcript binds the connection.

## Public API

- `op_and_args(request) -> (op, args_hash, is_write)`: the single shared binding. Client and server
  both call it, so neither can disagree about what a signature covers; the per-op binders behind it
  are crate-internal.
- `op`: the op-label constants (`PUT`, `CAS_HEAD`, `ROSTER_BATCH`, `PRUNE`, `GET`, `HAS`, `GET_REF`,
  `GET_ROSTER`, `GET_KEYSLOT`, `GET_KEYHIST`, `GET_ROSTER_KEYHIST`, `PAIR_PUT`, `PAIR_GET`).
- `WriteAuth` / `ReadAuth`: `sign` / `verify` over the payloads above.
- `prune` (§15): `dead_set_hash` (ids sorted and deduplicated), `all_heads_hash` (refs sorted,
  exact duplicates folded), and `args_prune(dead_set_hash, all_heads_hash, roster_len)`, public so the
  server's store predicate recomputes them against its own state.
- `wire`: `Request` / `Response` / `ClientHello` / `ServerHello` / `ClientAuth` / `AuthedRequest`
  (`encode`, strict `decode`; `Request::validate` applies the decoder's bounds on the write side),
  `KeyslotPut`, `HeadPut`, `ErrorCode`, `WireError`, and the frame caps `MAX_REQUEST_LEN`,
  `MAX_RESPONSE_LEN`, `MAX_AUTHED_LEN`, and `MAX_UNENROLLED_AUTHED_LEN` (just the genesis batch or a
  pairing message).
- `server`: the enforcement primitives, clock-injected: `TokenBucket`, `WindowCounter` (record and
  refund batches), `StorageQuota`, the operator-tunable `Limits`, and the normative `limits`
  constants (60 s nonce TTL, 1,024 ids per `has` or `prune`, 60 sigchain entries per key per hour,
  10,000 entries in total, the byte rates and connection limits).
- `Id`, `PUSH_ID_LEN`, `ProtoError`.
