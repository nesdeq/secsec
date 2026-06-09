//! `secsec-canon` — canonical, deterministic wire encoding for hashed / signed /
//! content-addressed structures (`finaldesign.md` §9.3).
//!
//! Guarantees this layer provides:
//!
//! - **Deterministic.** Two encoders produce byte-identical output for the same value — ids
//!   and signatures depend on it.
//! - **Canonical by construction.** Fixed-width little-endian integers (no varints, hence no
//!   non-minimal integer encodings), a fixed field order set by the calling code, no floats,
//!   and no self-describing type tags.
//! - **Strict decode.** Every length prefix is bounded by an explicit caller-supplied maximum
//!   (alloc-bomb guard, §9.1/§19), truncated input is rejected, and a fully decoded buffer MUST
//!   be exhausted via [`Reader::finish`] — trailing bytes are an error.
//!
//! ids and signatures are computed over the exact bytes produced by [`Writer`]. On the verify
//! path, [`verify_reencode`] confirms a decoded value re-encodes to the bytes that were actually
//! received, closing the malleability gap (§9.3 "two encoders must produce identical bytes").

#![forbid(unsafe_code)]

use core::fmt;

/// Errors produced by strict canonical decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonError {
    /// Input ended while `needed` more bytes were required (only `have` were left).
    UnexpectedEof {
        /// Bytes the decoder still needed.
        needed: usize,
        /// Bytes actually remaining.
        have: usize,
    },
    /// A length prefix (`len`) exceeded the caller-supplied maximum (`max`).
    LengthExceedsMax {
        /// The decoded length prefix.
        len: u64,
        /// The maximum the caller permitted.
        max: usize,
    },
    /// Bytes remained in the buffer after a top-level value was fully decoded.
    TrailingBytes {
        /// Number of unconsumed bytes.
        remaining: usize,
    },
    /// A decoded value did not re-encode to the bytes that were received (non-canonical input).
    NonCanonical,
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonError::UnexpectedEof { needed, have } => {
                write!(
                    f,
                    "unexpected end of input: needed {needed} more byte(s), had {have}"
                )
            }
            CanonError::LengthExceedsMax { len, max } => {
                write!(f, "length prefix {len} exceeds maximum {max}")
            }
            CanonError::TrailingBytes { remaining } => {
                write!(f, "{remaining} trailing byte(s) after decoding")
            }
            CanonError::NonCanonical => write!(f, "input is not canonical (re-encode mismatch)"),
        }
    }
}

impl std::error::Error for CanonError {}

/// Canonical encoder. Append fields in a fixed order; the resulting byte layout *is* the
/// encoding. There is no schema metadata on the wire, so the decoder must read the same fields
/// in the same order.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Create an empty encoder.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create an encoder with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Append a `u8`.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Append a `u16` in little-endian order.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a `u32` in little-endian order (the `le32` of the spec).
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a `u64` in little-endian order (the `le64` of the spec).
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a length-prefixed byte string: a `u32` little-endian length, then the bytes.
    ///
    /// # Panics
    /// Panics if `b.len() > u32::MAX`. Object-level length bounds (§19) keep real inputs far
    /// below this; exceeding it is an encoder bug, not attacker-reachable input.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        let len = u32::try_from(b.len()).expect("canon: byte string longer than u32::MAX");
        self.u32(len);
        self.buf.extend_from_slice(b);
        self
    }

    /// Append fixed-length raw bytes with **no** length prefix. The length is fixed by the
    /// schema (e.g. a 32-byte hash) and the decoder reads exactly that many via [`Reader::raw`].
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Borrow the encoded bytes without consuming the encoder.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the encoder and return the encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Strict canonical decoder over a borrowed buffer. Read the same fields, in the same order,
/// that the [`Writer`] wrote, then call [`Reader::finish`] to assert the buffer was exhausted.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Create a decoder over `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of unconsumed bytes.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CanonError> {
        let have = self.remaining();
        if have < n {
            return Err(CanonError::UnexpectedEof { needed: n, have });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read a `u8`.
    pub fn u8(&mut self) -> Result<u8, CanonError> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, CanonError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read a little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, CanonError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, CanonError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a length-prefixed byte string, rejecting any length prefix greater than `max`
    /// **before** consuming the body (alloc-bomb guard).
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8], CanonError> {
        let len = u64::from(self.u32()?);
        if len > max as u64 {
            return Err(CanonError::LengthExceedsMax { len, max });
        }
        // `len <= max <= usize::MAX`, so the cast is lossless here.
        self.take(len as usize)
    }

    /// Read exactly `n` fixed-length raw bytes (no length prefix).
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], CanonError> {
        self.take(n)
    }

    /// Assert the buffer is fully consumed. Call once a top-level value has been decoded;
    /// trailing bytes are rejected as non-canonical framing.
    pub fn finish(self) -> Result<(), CanonError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(CanonError::TrailingBytes { remaining })
        }
    }
}

/// Malleability guard for the verify path. Confirms that re-encoding `value` with `encode`
/// reproduces the exact `received` bytes; returns [`CanonError::NonCanonical`] otherwise.
///
/// Use this before trusting a signature or id that was computed over `received`: it ensures the
/// bytes we verified are the unique canonical encoding of the value we parsed, so an attacker
/// cannot present a second, non-canonical encoding of the same logical value. The comparison is
/// over public serialized bytes (no secrets), so a non-constant-time compare is appropriate.
pub fn verify_reencode<T>(
    received: &[u8],
    value: &T,
    encode: impl Fn(&T) -> Vec<u8>,
) -> Result<(), CanonError> {
    if encode(value) == received {
        Ok(())
    } else {
        Err(CanonError::NonCanonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn kat_layout() {
        // Known-answer: u32(1) then bytes(b"hi") => 01 00 00 00 | 02 00 00 00 | 'h' 'i'.
        let mut w = Writer::new();
        w.u32(1).bytes(b"hi");
        assert_eq!(w.finish(), vec![0x01, 0, 0, 0, 0x02, 0, 0, 0, b'h', b'i']);
    }

    #[test]
    fn kat_fixed_width_le() {
        let mut w = Writer::new();
        w.u8(0xAB)
            .u16(0x1122)
            .u32(0x0033_4455)
            .u64(0x0000_0000_dead_beef);
        assert_eq!(
            w.finish(),
            vec![
                0xAB, // u8
                0x22, 0x11, // u16 LE
                0x55, 0x44, 0x33, 0x00, // u32 LE
                0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0, // u64 LE
            ]
        );
    }

    #[test]
    fn roundtrip_primitives() {
        let mut w = Writer::new();
        w.u8(7)
            .u16(258)
            .u32(70_000)
            .u64(1 << 40)
            .bytes(b"hello")
            .raw(&[1, 2, 3, 4]);
        let buf = w.finish();

        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u16().unwrap(), 258);
        assert_eq!(r.u32().unwrap(), 70_000);
        assert_eq!(r.u64().unwrap(), 1 << 40);
        assert_eq!(r.bytes(16).unwrap(), b"hello");
        assert_eq!(r.raw(4).unwrap(), &[1, 2, 3, 4]);
        r.finish().unwrap();
    }

    #[test]
    fn rejects_trailing_bytes() {
        let buf = [0x01, 0x00, 0x00, 0x00, 0xFF]; // a u32 plus one extra byte
        let mut r = Reader::new(&buf);
        assert_eq!(r.u32().unwrap(), 1);
        assert_eq!(r.finish(), Err(CanonError::TrailingBytes { remaining: 1 }));
    }

    #[test]
    fn rejects_truncated() {
        let buf = [0x01, 0x02]; // only 2 bytes, u32 wants 4
        let mut r = Reader::new(&buf);
        assert_eq!(
            r.u32(),
            Err(CanonError::UnexpectedEof { needed: 4, have: 2 })
        );
    }

    #[test]
    fn bytes_enforces_max_before_reading_body() {
        // Length prefix says 1 MiB but max is 16; must reject on the prefix, not allocate.
        let buf = [0x00, 0x00, 0x10, 0x00]; // u32 = 0x0010_0000 = 1_048_576
        let mut r = Reader::new(&buf);
        assert_eq!(
            r.bytes(16),
            Err(CanonError::LengthExceedsMax {
                len: 1_048_576,
                max: 16
            })
        );
    }

    #[test]
    fn verify_reencode_accepts_canonical_and_rejects_mutation() {
        let encode = |v: &u32| {
            let mut w = Writer::new();
            w.u32(*v);
            w.finish()
        };
        let received = encode(&42);
        assert!(verify_reencode(&received, &42u32, encode).is_ok());
        // Bytes that decode to 42 but with a trailing byte are not the canonical encoding of 42.
        let mut non_canon = received.clone();
        non_canon.push(0x00);
        assert_eq!(
            verify_reencode(&non_canon, &42u32, encode),
            Err(CanonError::NonCanonical)
        );
    }

    proptest! {
        #[test]
        fn roundtrip_any(a: u8, b: u16, c: u32, d: u64, body in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut w = Writer::new();
            w.u8(a).u16(b).u32(c).u64(d).bytes(&body);
            let buf = w.finish();

            let mut r = Reader::new(&buf);
            prop_assert_eq!(r.u8().unwrap(), a);
            prop_assert_eq!(r.u16().unwrap(), b);
            prop_assert_eq!(r.u32().unwrap(), c);
            prop_assert_eq!(r.u64().unwrap(), d);
            prop_assert_eq!(r.bytes(512).unwrap(), &body[..]);
            prop_assert!(r.finish().is_ok());
        }

        #[test]
        fn any_appended_byte_breaks_canonicalization(v: u64, extra: u8) {
            let encode = |x: &u64| { let mut w = Writer::new(); w.u64(*x); w.finish() };
            let mut buf = encode(&v);
            buf.push(extra);
            // Re-encoding `v` yields 8 bytes; the 9-byte buffer can never match.
            prop_assert_eq!(verify_reencode(&buf, &v, encode), Err(CanonError::NonCanonical));
        }
    }
}
