# secsec-kdf

The key-derivation hierarchy (`secsec-Design.md` §5, §9.5).

Every subkey is `BLAKE3::derive_key(context_label, IKM)` with a **distinct, hardcoded** context label
(the §9.5 domain separation) and the secret in the IKM role, the parts streamed in order (`gen` as
`le32`, `seq` as `le64`, `type` as one byte) through a hasher that is wiped afterwards. The one
exception is `mk_commit_g`, which uses `BLAKE3::keyed_hash(master_key_g, "secsec-mk-commit-v1" ‖
le32(g))`: the one place the master key occupies the PRF *key* role; it is a public commitment, not
a secret. Every secret output is `Zeroizing`.

## Public API

- `MasterKey`: a generation-tagged 256-bit master key (RAM-only, zeroized on drop), with
  `generation()` and `expose_secret()`. Its methods derive the subkeys that hang off the master key:
  `enc_key` / `id_key` (per `gen` and `type`), `cdc_seed`, `head_key`, `roster_key`,
  `ref_name_key`, and the public `mk_commit`.
- Free functions for keys derived from another key: `obj_key(enc_key, id)`,
  `roster_entry_key_v2(roster_key_g, seq, salt)`, the read-only legacy
  `roster_entry_key(roster_key_g, seq)`, `roster_keyhist_key(roster_key_next, g)`, and
  `data_keyhist_key(master_key_next, g)`.
- `MasterKeys`: a resolver trait (`for_gen(g)`, `current()`) so readers open objects and heads sealed
  under any generation after a rotation (§8.2); its `ref_name_key()` always derives from generation 1
  (when held), so the ref path is stable across rotations. Implemented for `MasterKey` and
  `BTreeMap<u32, MasterKey>` (the peeled key ring).
- `SecretKey` (a `Zeroizing<[u8; 32]>` alias), `ROSTER_ENTRY_SALT_LEN`.

Pure derivation: key generation and storage policy live in `secsec-roster` and `secsec-client`. All
eleven `derive_key` families and `mk_commit` are frozen as KATs (`vectors/ [kdf]`).
