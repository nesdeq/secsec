# secsec-frame

Object framing, type tags, and decoder bounds (`secsec-Design.md` §9.1, §19).

Every stored object is `blob = FRAME ‖ ctx_tag(32) ‖ ciphertext`, where
`FRAME = MAGIC(4) ‖ format_version(u8) ‖ algo_id(u8) ‖ gen(u32) ‖ type(u8)` (11 bytes). The FRAME
doubles as the AEAD associated data (`AD = FRAME ‖ id`, §9.4), so framing, key derivation
(`type`/`gen` feed `secsec-kdf`), and the committing AEAD are bound together.

Two spec rules are enforced here:

- **Don't trust attacker-set FRAME fields** (§18) — `parse_blob` takes the `Frame` the client
  *expects* for the id it requested and rejects any blob whose decoded FRAME differs.
- **Bounds before allocation** (§9.1/§19) — every size is range-checked before any work, defeating
  alloc/recursion/decompression bombs.

## Public API

- `Frame` — `v1(gen, type)`, `encode()` / `decode()`, `aead_ad(id)`.
- `ObjType` — `Chunk` / `Tree` / `Commit` / `Head` / `Roster` / … (`as_u8` / `from_u8`).
- `assemble_blob` / `parse_blob` — build / strictly verify `FRAME ‖ ctx_tag ‖ ct`.
- Normative constants (§19): `FRAME_LEN`, `ID_LEN`, `CTX_TAG_LEN`, `MAGIC`, `MAX_BLOB_SIZE`,
  `MAX_TREE_DEPTH`, `MAX_TREE_FANOUT`, `MAX_ROSTER_ENTRY_SIZE`, `MAX_LIST_ELEMENTS`, `MIN_ALGO_ID`,
  `MIN_FORMAT_VERSION`, `FORMAT_VERSION_V1`.
- `FrameError`.

The decoder is fuzzed (one of the §3 targets).
