# secsec — known-answer test vectors

Language-agnostic KATs that pin the canonical outputs of the protocol's primitives, so any
implementation (or a re-implementation of a primitive) can self-check against the reference.

- **`secsec-kat-v1.txt`** — hex vectors chained from one root key (`master_key = 0x11×32`, generation
  `g = 1`), covering every layer: `[kdf]` (the §5/§9.5 derivations + `mk_commit`), `[frame]` (§9.1),
  `[aead]` (the §9.4 CTX/CMT-4 committing AEAD), `[object]` (§9.2 content-id + stored blob), `[head]`
  (§9.8 mutable head blob), `[gc]` (§15 serialization hashes), `[auth]` (§11 session transcript),
  `[sas]` (§7 enrollment short-auth-string), and `[roster]` (§9.5 per-entry AEAD + §8.2 roster-key
  history). Each value is the exact output of the reference Rust implementation.

## How the vectors are kept honest

Every value is pinned **twice** against the live code, so the export can never silently drift:

1. **Inline crate `#[test]`s** — each section names the test that asserts it (e.g. `secsec-kdf`'s
   `tests::kat_frozen`, `secsec-aead`'s `tests::ctx_kat`, `secsec-sync`'s `tests::head_kat`). These
   are the per-crate regression guards.
2. **The loader / anti-drift check** — `xtask` recomputes every value straight from the live code
   paths and compares it to this file:

   ```sh
   cargo xtask vectors --check     # recompute + compare; non-zero exit on any drift
   cargo xtask vectors             # print the live-computed values (to update the file after a change)
   ```

   The same comparison runs in normal `cargo test` as the xtask test
   `committed_vectors_match_live_code`, so a drift between this file and the code fails CI without
   needing the `xtask` invocation.

A second implementation MUST reproduce every value byte-for-byte.
