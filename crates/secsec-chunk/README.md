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

- `Chunker::with_defaults(cdc_seed)` / `Chunker::new(cdc_seed, min, avg, max)` — build a keyed chunker.
- `chunks(data)` — iterate content-defined slices; `cut_points(data)` / `next_cut(...)` — the raw
  boundary positions.
- `DEFAULT_MIN` / `DEFAULT_AVG` / `DEFAULT_MAX` (16 / 64 / 256 KiB, §19).
