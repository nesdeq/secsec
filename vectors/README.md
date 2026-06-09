# secsec — known-answer test vectors

Language-agnostic KATs that pin the canonical outputs of the foundation primitives, so any
implementation (or a re-implementation of a primitive) can self-check against the reference.

- `secsec-kat-v1.txt` — hex vectors for `secsec-kdf` (§5/§9.5 derivations) and `secsec-frame`
  (§9.1 framing). Each value is the exact output of the reference Rust implementation.

These are currently asserted inline in the crates' unit tests (e.g. `secsec-kdf`'s `kat_frozen`,
`secsec-frame`'s `frame_encode_kat`). A follow-up will add a loader test that reads this file
directly so the vectors and the asserts cannot drift.

Still to add (tracked): `secsec-aead` CTX vectors — AEAD correctness is currently pinned by a
byte-for-byte cross-check against the audited `chacha20poly1305` reference crate
(`ciphertext_and_tag_match_reference`); a frozen `(key, ad, pt) → (ctx_tag, ct)` vector will be
captured here alongside it.
