# secsec-object

The object plane: content addressing, authenticated seal/open with re-verification, and chunk
padding (`secsec-Design.md` §9.2, §9.4, §9.7).

Composes the foundation — `secsec-kdf` (keys), `secsec-frame` (framing + AD), `secsec-aead`
(committing AEAD). An object is stored as `FRAME ‖ ctx_tag ‖ ciphertext`, content-addressed by

```text
id = BLAKE3::keyed_hash(id_key[gen][type], FRAME ‖ path_salt ‖ plaintext)   // §9.2
```

On fetch, substitution is caught **three independent ways** (§9.2): the AEAD/CTX tag fails for the
wrong key (the per-object key is derived from the requested id), the FRAME must equal what the client
expected (§18), and the id is **re-derived from the recovered plaintext** and constant-time compared
to the requested id.

## Public API

- `seal_object(keys, type, path_salt, plaintext) -> (Id, blob)` — derive the per-object key, frame,
  commit, and content-address.
- `open_object(keys, type, path_salt, id, blob) -> plaintext` — the three-way-verified open
  (generic over `MasterKeys`, so it resolves the blob's own generation across rotations, §8.2).
- `pad_chunk` / `unpad_chunk` + `Padding` — reversible size-bucket padding that blurs object sizes
  (§9.7). Two policies are wired: `PowerOfTwo` (the default) and `None` (opt out); the §9.7 *uniform*
  policy is not implemented. (Re-deriving an id from plaintext — `content_id` — is crate-internal;
  `open_object` does it as part of its three-way verify.)
- `Id`, `PathSalt`, `ZERO_SALT` (the fixed empty salt for commits/heads/roster entries), `ObjError`.
