# secsec-kdf

The key-derivation hierarchy (`secsec-Design.md` §5, §9.5).

Every subkey is `BLAKE3::derive_key(context_label, IKM)` with a **distinct, hardcoded** context
label (the §9.5 domain separation) and the secret in the IKM/message role. The IKM is built with
[`secsec_canon::Writer`] so the fixed-width little-endian `gen`/`seq`/`type` encodings match the rest
of the codebase exactly. The sole exception is `mk_commit_g`, which uses
`BLAKE3::keyed_hash(master_key_g, …)` — the one place the master key occupies the PRF *key* role
(§9.5 note); it is a public commitment, not a secret. All secret outputs are `Zeroizing`.

## Public API

- `MasterKey` — a generation-tagged 256-bit master key (RAM-only, zeroized on drop). Its methods
  derive the subkeys that hang off the master key itself: `enc_key` / `id_key` (per `gen`,`type`),
  `cdc_seed`, `head_key`, `roster_key`, `ref_name_key`, and the public `mk_commit`;
  `generation()` / `expose_secret()`.
- Free functions for the subkeys derived from *another* subkey rather than from the master key:
  `obj_key(enc_key, id)`, `roster_entry_key(roster_key_g, seq)`,
  `roster_keyhist_key(roster_key_next, g)`, `data_keyhist_key(master_key_next, g)`.
- `MasterKeys` — a resolver trait (`current()`, `for_gen(g)`) so cross-generation readers can select
  the right-generation key after a rotation (§8.2); implemented for `MasterKey` and
  `BTreeMap<u32, MasterKey>` (the peeled key ring).
- `SecretKey` (a `Zeroizing<[u8;32]>` alias).

Pure derivation — key generation/storage policy lives in the key-management layer. Test vectors are
provided for all ten `derive_key` derivations (the eight in §9.5 plus `obj_key` and
`data_keyhist_key`) plus `mk_commit`; they are frozen as KATs.
