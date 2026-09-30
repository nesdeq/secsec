# secsec-canon

Canonical, deterministic encoding for hashed, signed, and content-addressed structures
(`secsec-Design.md` §9.3).

Ids and signatures are computed over the exact bytes a [`Writer`] produces, so the encoding must be
deterministic and canonical or the authenticity story breaks. This crate guarantees:

- **Deterministic:** two encoders produce byte-identical output for the same value.
- **Canonical by construction:** fixed-width little-endian integers (no varints), byte strings as
  `le32(len) ‖ bytes`, fixed-length fields raw, a field order set by the calling code, no floats, no
  self-describing tags.
- **Strict decode:** every length prefix is checked against a caller-supplied maximum before the body
  is read (the §19 allocation guard), truncated input is an error, and [`Reader::finish`] rejects
  trailing bytes.

## Public API

- `Writer`: append `u8` / `u16` / `u32` / `u64`, length-prefixed `bytes`, fixed-width `raw`, then
  `finish()`.
- `Reader`: read the same fields in the same order; `bytes(max)` enforces the bound first;
  `remaining()`; `finish()` asserts the buffer is exhausted.
- `verify_reencode(received, value, encode)`: a decoded value must re-encode to the bytes actually
  received, closing the malleability gap wherever bytes are signed or hashed.
- `CanonError`: `UnexpectedEof` / `LengthExceedsMax` / `TrailingBytes` / `NonCanonical`.

The wire messages, trees, commits, heads, roster entries, pairing messages, and the sealed frontier
all encode through it, so every fuzz target exercises its reader; `tests/robustness.rs` also feeds it
arbitrary bytes directly.
