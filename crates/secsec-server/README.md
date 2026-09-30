# secsec-server

The blind server (`secsec-Design.md` §11, §12, §19). Two gates protect the store: a coarse connection
allow-list and the fine per-op cryptographic check.

0. **Connection gate (§11).** Before any handshake, the accept loop takes a server-wide slot
   (`Server::admit`, 256 concurrent by default, held until the connection ends) or refuses the
   connection. `serve_connection` then rejects any key absent from the operator's
   `~/.ssh/authorized_keys` (`with_authorized_file`; `parse_authorized_keys` takes each bare
   `ssh-ed25519` line). The file is re-parsed whenever its size or mtime changes, an unreadable file
   denies, and an open connection re-checks it on its first request after 60 s, closing if the key is
   gone. Then the per-key concurrent-connection cap applies. `secsec serve` refuses to start without a
   usable key. Necessary, not sufficient.

Each request then travels on its own stream: the server answers the stream's opening with a fresh
32-byte challenge (`IssuedNonce`), caps the request frame by enrollment (the full request size, or just
the genesis batch and pairing messages for a key without a keyslot), and runs the §12 pipeline
(`Server::handle`) over the content-addressed store:

1. **Pairing mailbox first.** `pair-put` / `pair-get` are dispatched *before* the enrollment check (a
   joiner owns no keyslot yet), authorized by their read signature alone; the mailbox holds at most
   256 slots for 600 s, a take removes the message, a post charges the write rate and a take the read
   rate.
2. **Keyslot existence.** The key must own a keyslot at any generation; else `NotEnrolled`, with one
   exception: the exact genesis batch (one entry, one keyslot owned by the signer, nothing else) onto
   an empty roster.
3. **Per-op authorization.** The `secsec-write-v1` / `secsec-read-v1` signature over the recomputed
   `args_hash` and the session transcript (plus, for a write, the stream's challenge, which must be
   under 60 s old).
4. **Limits, then execute.** Size rules, the per-key byte rates (a 1 GiB burst), the id caps, the
   sigchain limits (60 entries per key per hour, refunded on a lost CAS; 10,000 in total), and the
   per-session write cap charged on the bytes a promote makes durable.

The server is **blind**: it stores opaque blobs and never reads or verifies their content (clients
re-check content addressing on fetch, §9.2). `cas-head` compares `BLAKE3` of the stored head blob and
promotes the push's staging in the same transaction; `roster-batch` compares the tip entry blob's hash;
`prune` deletes only if its signed `all_heads_hash` and `roster_len` still describe the store. The
handler is clock-injected, so the whole pipeline is unit-tested without sockets.

## Public API

- `Server`: `new(store)`, `with_limits(Limits)` (the operator-tunable limits of `secsec.config`),
  `with_authorized_file(path)`, `is_authorized(device_id)`, `is_enrolled(device_id)`,
  `conn_rate_per_sec()`, `admit()` (on an `Arc<Server>`: a server-wide connection slot, or `None` at
  the cap), and `reclaim(now, ttl)`, which drops pushes idle past the TTL and forgets idle rate-limit
  state (the serve loop calls it on a timer). `handle(incoming, now)` is crate-internal.
- `Admission` (the slot `admit` returns, freed when dropped), `parse_authorized_keys`, `IssuedNonce`,
  `Incoming`.
- `serve`: `serve_connection(conn, server, host_id, handshake_deadline, now)` (the handshake under the
  deadline, the gate, then one request per stream until the connection closes), `ServeError`.
