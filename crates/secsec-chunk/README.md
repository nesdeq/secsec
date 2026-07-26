# secsec-chunk

**Keyed** FastCDC content-defined chunking (`secsec-Design.md` §9.7).

Standard FastCDC uses a fixed canonical gear table so every implementation cuts at the same
boundaries. secsec does the opposite: the 256-entry gear table is derived from the per-generation
secret `cdc_seed`, so chunk boundaries are **repo-specific** and a cross-repo size-fingerprint
database does not apply. (Boundary privacy is only partial — a chosen-plaintext archiver can recover
the gear key, Alexeev et al. ePrint 2025/532 — so the load-bearing privacy mechanism is default-on
chunk padding, §9.7/§21; keyed chunking is defense-in-depth against the *offline* dictionary.)

The cut-point algorithm is FastCDC v2020 normalized chunking (Xia et al.): a Gear rolling hash, a
minimum-size skip, a stricter mask before the average point and a looser one after (normalization),
and a hard maximum. Only the gear table is keyed; the algorithm is otherwise standard and
deterministic (same `cdc_seed` + same input ⇒ same cut points).

## Public API

- `Chunker::with_defaults(cdc_seed)` — a keyed chunker at the §19 sizes (16 / 64 / 256 KiB).
- `chunks(data)` — content-defined slices of an in-memory buffer.
- `chunk_stream(reader, emit)` — the same cut points over a reader, holding at most one max-size
  window in memory so a file larger than RAM is never read whole. Boundaries are byte-identical to
  `chunks`, which is what cross-device dedup and merge content-equality rest on.
- `StreamError`.

(The gear table, the size constants, and the raw `next_cut` boundary search are crate-internal.)
