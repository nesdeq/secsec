# secsec-object

The object plane: content addressing, authenticated seal and open with re-verification, and chunk
padding (`secsec-Design.md` §9.2, §9.4, §9.7).

Composes `secsec-kdf` (keys), `secsec-frame` (framing and AD), and `secsec-aead` (the committing
AEAD). An object is stored as `FRAME ‖ ctx_tag ‖ ciphertext`, content-addressed by

```text
id = BLAKE3::keyed_hash(id_key[gen][type], FRAME ‖ path_salt ‖ plaintext)   // §9.2
```

and sealed under `k_obj = derive_key("secsec-obj-key-v1", enc_key[gen][type] ‖ id)`, so identical
plaintext at the same path, generation, and type seals to identical bytes (dedup). On fetch,
substitution is caught **three independent ways** (§9.2): the CTX tag fails under the key derived
from the requested id, the FRAME must equal what the client expected (§18), and the id is re-derived
from the recovered plaintext and compared in constant time.

## Public API

- `seal_object(mk, type, path_salt, plaintext) -> (Id, blob)`: seal under the given generation's
  keys (new objects always use the current one).
- `open_object(keys, type, path_salt, id, blob) -> plaintext`: the three-way-verified open, generic
  over `MasterKeys`, so the blob's own `FRAME.gen` selects its key after a rotation (§8.2).
- `pad_chunk` / `unpad_chunk` + `Padding`: reversible ISO/IEC 7816-4 padding. `PowerOfTwo` (pad to
  the next power of two above the length) is what every chunk uses; `None` exists for tests and is
  not wired to any setting, and the §9.7 uniform policy is **NOT WIRED**.
- `Id`, `PathSalt`, `ZERO_SALT` (the fixed salt of commits, the one content-addressed object with no
  path), `ObjError` (including `UnknownGeneration` for a generation the key ring does not hold).

(`content_id` is crate-internal; `open_object` re-derives it as part of its verify.)
