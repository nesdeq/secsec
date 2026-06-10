# secsec-server

The server request handler (`secsec-Design.md` §11, §12, §19). Two gates protect the store — a coarse
connection allow-list and the fine per-op crypto check:

0. **connection gate (§11)** — `serve_connection` rejects any key absent from the operator's
   `~/.ssh/authorized_keys` (`Authorized::File`, re-read per connection, fail-closed;
   `parse_authorized_keys`). `secsec serve` refuses to start without a usable key. Necessary, not
   sufficient.

Then the §12 per-op pipeline (`Server::handle`) runs for every request over the content-addressed
object store ([`secsec_store::Store`]):

1. **keyslot existence** — the connecting key must own a keyslot (be rostered); else `not-enrolled`.
   Two bounded exceptions: the §7 `pair-put`/`pair-get` invite mailbox is dispatched *pre*-enrollment
   (read-auth only, TTL'd, rate-limited), and the **genesis-bootstrap** exception lets the first
   device write its genesis roster entry + keyslot while `roster_len == 0`;
2. **per-op authorization** — verify the `secsec-write-v1` / `secsec-read-v1` signature over the op's
   `args_hash` + the session transcript (+ `server_nonce` for writes), recomputing `args_hash` from
   the request so the client can't lie about what it signed;
3. **nonce freshness** — consume the `server_nonce` exactly once (writes), defeating replay;
4. **limits** — per-key write byte-rate + burst and storage quota (§19), the `has` id cap;
5. **execute** — against the blob store.

The server is **blind**: it stores opaque blobs by id and never reads or verifies their content
(content-addressing is re-checked by *clients* on fetch, §9.2). The mutable ops CAS on a `BLAKE3` of
the stored (encrypted) tip blob. The handler is pure and clock-injected (`now`), so the whole §12
pipeline is unit-testable by calling `Server::handle` directly — no sockets.

## Public API

- `Server` — `new(store)`, `with_receipts(seed, host_id)` (§15 signed arrival receipts),
  `with_authorized(set)` / `with_authorized_file(path)` (the §11 connection gate), `is_authorized`,
  `handle(request, now)` (the pure pipeline), `issue_nonce`, `store()`.
- `parse_authorized_keys`, `Authorized` (`Any` / `Static` / `File`).
- `serve` — `serve_connection` (the QUIC serve loop over `secsec-transport`; enforces the gate).
- `Incoming`, `ServeError`.
