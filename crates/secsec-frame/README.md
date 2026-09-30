# secsec-frame

Object framing, type tags, and decoder bounds (`secsec-Design.md` §9.1, §19).

Every stored object starts with the 11-byte
`FRAME = MAGIC("ssec") ‖ format_version(u8) ‖ algo_id(u8) ‖ le32(gen) ‖ type(u8)`. Content objects
(chunks, trees, commits) are `FRAME ‖ ctx_tag(32) ‖ ciphertext`; a v2 roster entry inserts its 32-byte
salt after the FRAME, and a head stores `nonce ‖ tag` instead of a `ctx_tag`. The FRAME is part of
every AEAD's associated data (`AD = FRAME ‖ id` for objects, §9.4), so framing, key derivation
(`type` and `gen` select the keys), and the committing AEAD are bound together.

Two spec rules are enforced here:

- **Don't trust attacker-set FRAME fields** (§18): `parse_blob` and `parse_frame_prefix` take the
  `Frame` the client *expects* and reject any blob whose decoded FRAME differs.
- **Bounds before allocation** (§9.1, §19): the size cap is checked before any work, and every
  decoder reads its limits from the constants here.

## Public API

- `Frame`: `v1(gen, type)` (every object), `v2(gen, type)` (salted roster entries), `is_v2()`,
  `encode()`, `decode()` (magic, the `format_version` 1..=2 floor, the object suite `algo_id` 1, a
  known type). `aead_ad(frame, id)` builds the object AD.
- `ObjType`: `Chunk` / `Tree` / `Commit` / `Head` / `RosterEntry` / `Keyhist` / `RosterKeyhist`
  (`as_u8`; the `from_u8` parse is crate-internal).
- `assemble_blob` / `parse_blob`: build or strictly split `FRAME ‖ ctx_tag ‖ ct`;
  `parse_frame_prefix`: the size and FRAME checks alone, returning the bytes after the FRAME.
- Normative constants (§19): `FRAME_LEN`, `ID_LEN`, `CTX_TAG_LEN`, `MAX_BLOB_SIZE`, `MAX_TREE_DEPTH`,
  `MAX_TREE_FANOUT`, `MAX_ROSTER_ENTRY_SIZE`, `MAX_LIST_ELEMENTS`, `MAX_NAME_LEN`,
  `MAX_CHUNKS_PER_FILE` (= `MAX_BLOB_SIZE / ID_LEN`, the ids one tree blob can hold), `MIN_ALGO_ID`.
- `FrameError`.

(`MAGIC`, the format-version constants, and `ALGO_V1` are crate-internal: `Frame::decode` enforces
them, callers never choose them.)

Fuzzed by the `frame` target (§18) and by a no-panic robustness test over arbitrary input.
