# secsec-chunk

**Keyed** FastCDC-style content-defined chunking (`secsec-Design.md` §9.7).

Standard FastCDC uses a fixed gear table so every implementation cuts at the same boundaries. secsec
does the opposite: the 256-entry gear table is `BLAKE3::keyed_hash(cdc_seed, "secsec-cdc-gear-v1")`
in XOF mode, from the per-generation secret `cdc_seed`, so chunk boundaries are **repo-specific** and
a cross-repo size-fingerprint database does not apply. Boundary privacy is only partial (a
chosen-plaintext archiver can recover the gear key, Alexeev et al., ePrint 2025/532), so power-of-two
chunk padding (`secsec-object`) is what blurs the size signal; keyed chunking is defense in depth
against an offline dictionary (§21).

The cut points follow FastCDC's normalized chunking: a gear rolling hash, a minimum-size skip, a
stricter mask before the average point and a looser one after (`log2(avg) ± 2` one-bits), and a hard
maximum. Same `cdc_seed` and same input give the same cut points.

## Public API

- `Chunker::with_defaults(cdc_seed)`: a keyed chunker at the §19 sizes (16 / 64 / 256 KiB); the gear
  table is wiped on drop.
- `chunks(data)`: content-defined slices of an in-memory buffer.
- `chunk_stream(reader, emit)`: the same cut points over a reader, holding at most one maximum-size
  window in memory, so a file larger than RAM is never read whole. Boundaries are byte-identical to
  `chunks`, which cross-device dedup and merge content-equality rest on.
- `MAX_CHUNK_LEN`: the largest chunk any conforming chunker emits; restore rejects a longer one.
- `StreamError`.

(The gear table, the other size constants, and the `next_cut` boundary search are crate-internal.)
