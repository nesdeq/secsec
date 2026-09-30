# secsec: known-answer test vectors

Language-agnostic KATs that pin the canonical outputs of the protocol's primitives, so any
implementation (or a re-implementation of one primitive) can check itself against the reference.

**`secsec-kat-v1.txt`** holds nine sections, lowercase hex unless a line says otherwise:

| Section | Pins | Inputs |
|---|---|---|
| `[kdf]` | all eleven `derive_key` families of §8.2/§9.4/§9.5 plus `mk_commit` | `master_key = 0x11×32`, `g = 1` |
| `[frame]` | the 11-byte FRAME, v1 and v2 (§9.1) | fixed fields |
| `[aead]` | the §9.4 CTX/CMT-4 committing AEAD | its own key `0x42×32` |
| `[object]` | a §9.2 content id and its stored blob | the `[kdf]` root key |
| `[head]` | the §9.8 head blob and its ref hash | the `[kdf]` root key, a fixed nonce |
| `[auth]` | the §11 session transcript | fixed nonces and `host_id` |
| `[roster]` | a legacy v1 and a v2 roster entry (§9.5) and a roster-key-history wrap (§8.2) | `roster_key[g=1]` of the root key |
| `[chunk]` | keyed chunker cut points (§9.7) | `cdc_seed = 0x33×32`, 1 MiB of `BLAKE3-XOF("secsec-chunk-kat")` |
| `[pair]` | the §7 pairing slot ids and code MACs | code `0x0c×12` |

The X-Wing keyslot KEM is checked against draft-connolly-cfrg-xwing-kem-10 Appendix C by
`secsec-pq`'s own tests, not in this file.

## How the vectors are kept honest

Every value is pinned twice against the live code:

1. **Inline crate tests.** Each section header names the test that asserts it
   (`# asserts: <crate> <test>`), for example `secsec-kdf tests::kat_frozen`.
2. **The anti-drift check.** `xtask` recomputes every output from the live code paths and compares
   it with this file. It also fails when a line is neither a computed output nor a documented input,
   when a section names no asserting test, or when the named test does not exist:

   ```sh
   cargo xtask vectors --check     # recompute and compare; non-zero exit on any drift
   cargo xtask vectors             # also print the live values (to update the file after a change)
   ```

   The same comparison runs under `cargo test` as the xtask test `committed_vectors_match_live_code`,
   so drift fails CI without a separate `xtask` step.

A second implementation MUST reproduce every value byte for byte.
