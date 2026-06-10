# secsec-canon

Canonical, deterministic wire encoding for hashed / signed / content-addressed structures
(`secsec-Design.md` §9.3).

ids and signatures are computed over the exact bytes produced by [`Writer`], so the encoding must be
deterministic and canonical or the whole authenticity story breaks. This crate guarantees:

- **Deterministic** — two encoders produce byte-identical output for the same value.
- **Canonical by construction** — fixed-width little-endian integers (no varints), a fixed field
  order set by the calling code, no floats, no self-describing type tags.
- **Strict decode** — every length prefix is bounded by an explicit caller-supplied maximum
  (alloc-bomb guard, §9.1/§19), truncated input is rejected, and a fully decoded buffer must be
  exhausted via [`Reader::finish`] (trailing bytes are an error).

## Public API

- `Writer` — append fields (`u8`/`u16`/`u32`/`u64`, length-prefixed `bytes`, fixed-width `raw`) →
  `finish()` / `as_bytes()`.
- `Reader` — read the same fields in the same order; `bytes(max)` enforces the bound before
  allocating; `finish()` asserts the buffer is exhausted.
- `verify_reencode(received, value, encode)` — confirms a decoded value re-encodes to the bytes that
  were actually received, closing the malleability gap on the verify path.
- `CanonError` — `UnexpectedEof` / `LengthExceedsMax` / `TrailingBytes` / `NonCanonical`.

The foundation of the workspace — every hashed/signed/addressed structure encodes through it; the
decoder is fuzzed.
