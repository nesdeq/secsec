# secsec-server

The server request handler (`secsec-Design.md` §12, §19). The §12 authorization pipeline a
`secsec serve` loop runs for every per-op request, over the content-addressed object store
([`secsec_store::Store`]):

1. **keyslot existence** — the connecting key must own a keyslot (be rostered); else `not-enrolled`;
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
  `handle(request, now)` (the pure pipeline), `issue_nonce`, `store()`.
- `serve` — `serve_connection` (the QUIC serve loop over `secsec-transport`).
- `Incoming`, `ServeError`.
