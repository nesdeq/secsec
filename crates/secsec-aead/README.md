# secsec-aead

The per-object **fully committing (CMT-4)** AEAD (`secsec-Design.md` §9.4), built as the CTX
construction (Chan & Rogaway, ESORICS 2022) over ChaCha20-Poly1305, plus the fresh-nonce AEAD for
mutable blobs (§9.8).

```text
nonce   = 0                                             // safe ONLY because `key` is unique per sealing
ct, T   = ChaCha20Poly1305_raw(key, 0, AD, plaintext)   // T = raw 16-byte Poly1305 tag
ctx_tag = BLAKE3::keyed_hash(key, "secsec-ctx-v1" ‖ AD ‖ T)
stored  = ctx_tag(32) ‖ ct                              // T is NOT stored
```

On open, `T` is **recomputed** from `(AD, ct)`, `ctx_tag` is recomputed and compared in constant
time, and only then is the ciphertext decrypted. `ctx_tag` binds the key, the AD, and (via `T`) the
plaintext, so no ciphertext opens under two distinct `(key, AD)` pairs (CMT-4), closing
partitioning-oracle and invisible-salamander attacks across the multi-generation, multi-recipient
surface. There is no stored `T`, and the high-level AEAD open is never used.

**Contract:** a `seal` key MUST be bound to one sealing (a per-object key, a per-seal salted roster
key, a fresh KEM secret, or a per-generation key-history key); the fixed nonce is sound only under
that uniqueness. The `UniqueKey` type carries the obligation.

## Public API

- `seal(UniqueKey, ad, plaintext) -> (CtxTag, ct)` / `open(key, ad, ctx_tag, ct) -> plaintext`: the
  committing construction above.
- `seal_mut(key, FreshNonce, ad, pt) -> (tag, ct)` / `open_mut(key, nonce, ad, tag, ct)`: the
  **mutable** variant (§9.8), plain RFC 8439 ChaCha20-Poly1305 with a fresh random nonce per write,
  for blobs re-encrypted in place under a stable key (the per-ref head, the sealed local frontier).
  Deliberately *not* key-committing; its contract is the fresh nonce, not a unique key.
- `UniqueKey` / `FreshNonce`: the two contracts the compiler cannot check, carried as types.
  `unsafe_code = "forbid"` rules out `unsafe fn` as the marker, so each `UniqueKey::new` and
  `FreshNonce::new` is a proof site one search enumerates. Opening carries no such obligation, so
  `open` and `open_mut` take the raw key and nonce.
- `CtxTag`, `AeadError`.

Tested with a frozen KAT (`vectors/ [aead]`), a byte-for-byte keystream and tag cross-check against
the `chacha20poly1305` crate (a dev-dependency), tamper and wrong-key tests, property tests, and a
no-panic robustness test over arbitrary input.
