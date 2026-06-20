# secsec-store

The server's content-addressed blob store (`secsec-Design.md` §13, §15).

Objects are opaque, content-addressed ciphertext blobs keyed by their 32-byte id, stored in a single
embedded `redb` database (its B-tree *is* the packing — the server is never flooded with tiny files).
The store holds opaque durable blobs (`{id, blob}`) plus a per-push **staging** area, the per-device **keyslots**
(`/keyslots/<device_id>/<g>`), the sigchain (`/roster/<seq>` + the CAS-guarded `/roster-head`), the
two never-trimmed key-histories (`/keyhist/<g>`, `/roster-keyhist/<g>`), and the encrypted per-ref
heads (`/refs/<H>`). It never sees plaintext or plaintext-derived metadata — device_ids and every blob
are opaque.

## Public API

- Objects: `put` (idempotent durable dedup by id), `get`, `has` (durable-only),
  `has_for_push(push_id, ids)`, `object_count`.
- Transactional push (§15): `stage(push_id, id, blob, now)` (buffers a blob under `push_id`),
  `staged_bytes`, `cas_ref(ref_h, expected_old, new_blob, promote)` (promotes the named push's
  staging into durable objects and swaps the ref in one redb txn), `reclaim_staging(now, ttl)`
  (drops idle pushes), `retain(keep)` (count-based history retention), `delete_objects(ids)`,
  `compact`.
- Keyslots: `put_keyslot` / `get_keyslot` / `keyslot_exists` (drives the §12 keyslot-existence auth
  check) / `delete_keyslot` (§8.4 revocation).
- Refs: `cas_ref` (blind compare-and-swap on `BLAKE3` of the stored tip blob, §12), `get_ref`,
  `ref_blob_hashes`, `ABSENT_HEAD`.
- Sigchain: `append_roster`, `get_roster_entry`, `roster_len`.
- Key-histories: `put_keyhist` / `get_keyhist`, `put_roster_keyhist` / `get_roster_keyhist`.
- `Store`, `StoreError`, `RefBlobHash`.

The store is lock-free (redb-transactional), so a `serve` loop can share one `Store` across
connections concurrently.
