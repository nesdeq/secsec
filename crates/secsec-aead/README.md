# secsec-aead

The per-object **fully-committing (CMT-4)** AEAD (`secsec-Design.md` §9.4), built as the CTX
construction (Chan & Rogaway, ESORICS 2022) over ChaCha20-Poly1305.

```text
nonce   = 0                                   // safe ONLY because `key` is unique per object
ct, T   = ChaCha20Poly1305_raw(key, 0, AD, plaintext)   // T = raw 16-byte Poly1305 tag
ctx_tag = BLAKE3::keyed_hash(key, "secsec-ctx-v1" ‖ AD ‖ T)
stored  = ctx_tag(32) ‖ ct                    // T is NOT stored
```

On open, `T` is **recomputed** from `(AD, ct)`, `ctx_tag` is recomputed and compared in constant
time, and only then is the ciphertext decrypted. `ctx_tag` binds the key, the AD, and — via `T` —
the plaintext, so no ciphertext opens under two distinct `(key, AD)` pairs (CMT-4), closing
partitioning-oracle / invisible-salamander attacks across the multi-generation, multi-recipient
surface. There is no stored `T`, and the high-level AEAD "open" is never used.

**Contract:** `key` is `k_obj` (§9.4) and MUST be unique per sealed object — the fixed `nonce=0` is
sound only under that uniqueness. Never `seal` twice with the same key and different plaintext.

## Public API

- `seal(key, ad, plaintext) -> (CtxTag, ct)` / `open(key, ad, ctx_tag, ct) -> plaintext` — the
  committing construction above.
- `seal_mut(key, nonce, ad, pt)` / `open_mut(key, nonce, ad, tag, ct)` — the **mutable** variant
  (§9.8): plain RFC 8439 ChaCha20-Poly1305 with a caller-supplied **fresh nonce per write**, for
  re-encrypted-in-place objects (the per-ref Head, local sealed state). Deliberately *not*
  key-committing; its contract is a fresh random nonce, not a unique key.
- `CtxTag`, `AeadError`.

The foundation primitive; gets the most tests (KATs, committing property tests, a byte-for-byte
cross-check against the reference `chacha20poly1305` crate).
