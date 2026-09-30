# secsec-store

The content-addressed blob store (`secsec-Design.md` §13, §15): the server's repository, and each
client's encrypted object cache.

One embedded `redb` file. Its tables hold durable objects by 32-byte id, per-push **staging**
(`push_id ‖ id`) and each push's last-activity time, the **keyslots** (`device_id ‖ le32(g)`), the
encrypted per-ref **heads**, the **sigchain** by seq (the tip is the last entry, CAS-guarded by the
`BLAKE3` of its blob), and the two never-trimmed **key histories**. Every blob is opaque ciphertext;
the one plaintext field the store reads is a roster entry's `FRAME.gen` (via `secsec-frame`), to decide
whether a key-history wrap may still be replaced.

## Public API

- Objects: `put` / `put_many` (first write wins), `get`, `has` (durable only), `object_count`,
  `delete_objects`, `retain(keep)` (the client cache's orphan sweep), `compact`.
- Transactional push (§15): `stage(push_id, id, blob, now)` (always stages, even an id already
  durable, so a racing prune cannot strand it), `staged_bytes`, `cas_ref(ref_h, expected_old,
  new_blob, promote)` (promotes the push's staging and swaps the ref in one transaction; returns a
  `CasOutcome` whose `promoted_bytes` the per-key cap charges), `reclaim_staging(now, ttl)`.
- Prune (§15): `prune_if(ids, accept)` hands the live `(ref, blob hash)` list and the roster length to
  `accept` and deletes only if it approves, inside the same transaction; `ref_blob_hashes`.
- Sigchain side: `roster_batch(&RosterBatch)` applies one sigchain operation atomically (entries,
  `KeyslotWrite`s, both key-history wraps, revoked devices' keyslots at every generation, an optional
  `HeadSwap`) under the tip CAS, purging any pre-genesis keyslot on genesis and refusing to replace a
  wrap the chain has rotated past; `roster_len`, `get_roster_entry`, `get_keyhist`,
  `get_roster_keyhist`.
- Keyslots: `get_keyslot`, `keyslot_exists` (over any generation; the §12 enrollment check),
  `put_keyslot` (direct writes, for tests; production writes go through `roster_batch`).
- Refs: `get_ref`, `ABSENT_HEAD` (the "expect absent" CAS token).
- `Store`, `StoreError`, `RefBlobHash`, `CasOutcome`, `RosterBatch`, `KeyslotWrite`, `HeadSwap`.

Every operation is its own redb transaction and redb serializes writers, so one `Store` is shared
across a server's connections; redb also locks the file, so a second process cannot open it.
