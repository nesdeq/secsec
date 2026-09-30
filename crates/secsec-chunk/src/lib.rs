//! Keyed content-defined chunking: a FastCDC-style gear hash with normalized two-mask cuts, keyed by `cdc_seed` (`secsec-Design.md` §9.7).

#![forbid(unsafe_code)]

use std::io::Read;
use zeroize::Zeroize;

/// Minimum chunk size (§19).
pub(crate) const DEFAULT_MIN: usize = 16 * 1024;
/// Target average chunk size (§19).
pub(crate) const DEFAULT_AVG: usize = 64 * 1024;
/// Maximum chunk size (§19).
pub(crate) const DEFAULT_MAX: usize = 256 * 1024;
/// The largest plaintext chunk any conforming chunker emits; restore rejects longer chunks.
pub const MAX_CHUNK_LEN: usize = DEFAULT_MAX;

/// Normalization level: the pre-/post-average masks carry `log2(avg) ± 2` one-bits (§9.7).
const NORMALIZATION: u32 = 2;

/// Label keying the gear-table XOF (§9.7).
const GEAR_LABEL: &[u8] = b"secsec-cdc-gear-v1";

/// A configured keyed chunker holding the secret gear table (wiped on drop).
#[derive(Clone)]
pub struct Chunker {
    gear: [u64; 256],
    min: usize,
    avg: usize,
    max: usize,
    mask_s: u64,
    mask_l: u64,
}

impl Drop for Chunker {
    fn drop(&mut self) {
        self.gear.zeroize();
    }
}

/// An error from [`Chunker::chunk_stream`]: reading the source, or the caller's `emit` callback.
#[derive(Debug)]
pub enum StreamError<E> {
    /// Reading the input source failed.
    Read(std::io::Error),
    /// The `emit` callback returned an error (propagated unchanged).
    Emit(E),
}

impl<E: core::fmt::Display> core::fmt::Display for StreamError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StreamError::Read(e) => write!(f, "chunk-stream read: {e}"),
            StreamError::Emit(e) => write!(f, "chunk-stream emit: {e}"),
        }
    }
}

impl<E: std::error::Error> std::error::Error for StreamError<E> {}

/// Gear table: 256 little-endian `u64`s from `BLAKE3::keyed_hash(cdc_seed, "secsec-cdc-gear-v1")` in XOF mode.
fn build_gear(cdc_seed: &[u8; 32]) -> [u64; 256] {
    let mut h = blake3::Hasher::new_keyed(cdc_seed);
    h.update(GEAR_LABEL);
    let mut xof = h.finalize_xof();
    h.zeroize();
    let mut bytes = [0u8; 256 * 8];
    xof.fill(&mut bytes);
    let mut gear = [0u64; 256];
    for (i, g) in gear.iter_mut().enumerate() {
        *g = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
    }
    bytes.zeroize();
    gear
}

/// A mask with `count` one-bits at bits 63, 61, 59, …, so a cut fires with probability `2^-count` per byte.
fn spread_mask(count: u32) -> u64 {
    let count = count.clamp(1, 30);
    let mut m = 0u64;
    for j in 0..count {
        m |= 1u64 << (63 - 2 * j);
    }
    m
}

impl Chunker {
    /// A chunker with the §19 default sizes.
    #[must_use]
    pub fn with_defaults(cdc_seed: &[u8; 32]) -> Self {
        Self::new(cdc_seed, DEFAULT_MIN, DEFAULT_AVG, DEFAULT_MAX)
    }

    /// A chunker with explicit sizes; panics unless `0 < min <= avg <= max`.
    #[must_use]
    pub(crate) fn new(cdc_seed: &[u8; 32], min: usize, avg: usize, max: usize) -> Self {
        assert!(
            0 < min && min <= avg && avg <= max,
            "require 0 < min <= avg <= max"
        );
        let bits = floor_log2(avg);
        Self {
            gear: build_gear(cdc_seed),
            min,
            avg,
            max,
            mask_s: spread_mask(bits + NORMALIZATION),
            mask_l: spread_mask(bits.saturating_sub(NORMALIZATION)),
        }
    }

    /// Length of the first chunk of `data`: in `[min, max]`, or all of `data` when shorter than `min`.
    #[must_use]
    pub(crate) fn next_cut(&self, data: &[u8]) -> usize {
        let n = data.len();
        if n <= self.min {
            return n;
        }
        let end = n.min(self.max);
        let center = self.avg.min(end);
        let mut fp = 0u64;
        let mut i = self.min;
        // Stricter mask up to the average, looser after it (normalized chunking).
        while i < center {
            fp = (fp << 1).wrapping_add(self.gear[data[i] as usize]);
            if fp & self.mask_s == 0 {
                return i + 1;
            }
            i += 1;
        }
        while i < end {
            fp = (fp << 1).wrapping_add(self.gear[data[i] as usize]);
            if fp & self.mask_l == 0 {
                return i + 1;
            }
            i += 1;
        }
        end
    }

    /// Chunk end-offsets of `data`; the last equals `data.len()`.
    #[cfg(test)]
    #[must_use]
    pub fn cut_points(&self, data: &[u8]) -> Vec<usize> {
        let mut cuts = Vec::new();
        let mut off = 0usize;
        while off < data.len() {
            off += self.next_cut(&data[off..]);
            cuts.push(off);
        }
        cuts
    }

    /// Cut `data` into chunk slices.
    #[must_use]
    pub fn chunks<'a>(&self, data: &'a [u8]) -> Vec<&'a [u8]> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off < data.len() {
            let len = self.next_cut(&data[off..]);
            out.push(&data[off..off + len]);
            off += len;
        }
        out
    }

    /// Stream `reader` through `emit` holding at most `max` bytes; cuts are byte-identical to [`Chunker::chunks`].
    pub fn chunk_stream<R, E, F>(&self, mut reader: R, mut emit: F) -> Result<u64, StreamError<E>>
    where
        R: Read,
        F: FnMut(&[u8]) -> Result<(), E>,
    {
        let mut buf: Vec<u8> = Vec::with_capacity(self.max);
        let mut eof = false;
        let mut total: u64 = 0;
        loop {
            // Only a full `max` window or EOF may be cut; the tail is zeroed once per refill, not per read.
            if !eof && buf.len() < self.max {
                let mut filled = buf.len();
                buf.resize(self.max, 0);
                while filled < self.max {
                    match reader.read(&mut buf[filled..]) {
                        Ok(0) => {
                            eof = true;
                            break;
                        }
                        Ok(n) => filled += n,
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(StreamError::Read(e)),
                    }
                }
                buf.truncate(filled);
            }
            if buf.is_empty() {
                return Ok(total);
            }
            let cut = self.next_cut(&buf);
            emit(&buf[..cut]).map_err(StreamError::Emit)?;
            total += cut as u64;
            buf.drain(..cut);
        }
    }
}

/// `floor(log2(x))` for `x >= 1`.
fn floor_log2(x: usize) -> u32 {
    debug_assert!(x >= 1);
    (usize::BITS - 1) - x.leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x33; 32];

    /// Deterministic pseudo-random bytes (BLAKE3 XOF).
    fn pseudo_random(label: &str, len: usize) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(label.as_bytes());
        let mut xof = h.finalize_xof();
        let mut v = vec![0u8; len];
        xof.fill(&mut v);
        v
    }

    #[test]
    fn deterministic() {
        let c = Chunker::with_defaults(&SEED);
        let data = pseudo_random("deterministic", 2 * 1024 * 1024);
        assert_eq!(c.cut_points(&data), c.cut_points(&data));
    }

    #[test]
    fn full_coverage_and_bounds() {
        let c = Chunker::with_defaults(&SEED);
        let data = pseudo_random("coverage", 4 * 1024 * 1024);
        let chunks = c.chunks(&data);
        let joined: Vec<u8> = chunks.iter().flat_map(|s| s.iter().copied()).collect();
        assert_eq!(joined, data);
        for (idx, ch) in chunks.iter().enumerate() {
            assert!(ch.len() <= MAX_CHUNK_LEN, "chunk over max");
            if idx + 1 < chunks.len() {
                assert!(
                    ch.len() >= DEFAULT_MIN,
                    "interior chunk under min: {}",
                    ch.len()
                );
            }
        }
    }

    #[test]
    fn average_size_near_target() {
        let c = Chunker::with_defaults(&SEED);
        let data = pseudo_random("avg", 8 * 1024 * 1024);
        let chunks = c.chunks(&data);
        let mean = data.len() / chunks.len();
        assert!(
            (32 * 1024..=110 * 1024).contains(&mean),
            "mean chunk size {mean} outside expected band around {DEFAULT_AVG}"
        );
    }

    #[test]
    fn keying_changes_boundaries() {
        let data = pseudo_random("keying", 2 * 1024 * 1024);
        let a = Chunker::with_defaults(&[0x01; 32]).cut_points(&data);
        let b = Chunker::with_defaults(&[0x02; 32]).cut_points(&data);
        assert_ne!(a, b, "different cdc_seed must produce different boundaries");
    }

    #[test]
    fn small_and_empty_inputs() {
        let c = Chunker::with_defaults(&SEED);
        assert!(c.cut_points(b"").is_empty());
        assert_eq!(c.cut_points(&[0u8; 100]), vec![100]);
    }

    #[test]
    fn mask_popcount() {
        assert_eq!(spread_mask(16).count_ones(), 16);
        assert_eq!(spread_mask(1).count_ones(), 1);
        assert_eq!(floor_log2(DEFAULT_AVG), 16);
    }

    /// Frozen cut-point KAT, mirrored in `vectors/secsec-kat-v1.txt [chunk]`: seed `[0x33;32]`, 1 MiB of `BLAKE3-XOF("secsec-chunk-kat")`.
    #[test]
    fn cut_points_kat() {
        let c = Chunker::with_defaults(&SEED);
        let data = pseudo_random("secsec-chunk-kat", 1024 * 1024);
        let cuts: Vec<String> = c.cut_points(&data).iter().map(usize::to_string).collect();
        assert_eq!(
            cuts.join(","),
            "68501,148938,222181,295054,369270,443063,523306,610218,698060,764506,822342,904665,970724,1037519,1048576"
        );
    }

    /// A reader yielding at most `step` bytes per `read`.
    struct ChoppyReader<'a> {
        data: &'a [u8],
        pos: usize,
        step: usize,
    }
    impl std::io::Read for ChoppyReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = self.step.min(out.len()).min(self.data.len() - self.pos);
            out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn stream_cuts(c: &Chunker, data: &[u8], step: usize) -> Vec<usize> {
        let mut got = Vec::new();
        let total = c
            .chunk_stream(
                ChoppyReader {
                    data,
                    pos: 0,
                    step: step.max(1),
                },
                |ch| {
                    got.push(ch.len());
                    Ok::<(), ()>(())
                },
            )
            .unwrap();
        assert_eq!(total as usize, data.len(), "stream must read every byte");
        got
    }

    /// Streaming cuts equal in-RAM cuts across sizes, entropy, and read widths.
    #[test]
    fn streaming_cuts_match_in_ram_across_sizes_and_read_widths() {
        let c = Chunker::with_defaults(&SEED);
        let sizes = [
            0usize,
            1,
            2,
            DEFAULT_MIN - 1,
            DEFAULT_MIN,
            DEFAULT_MIN + 1,
            DEFAULT_AVG - 1,
            DEFAULT_AVG,
            DEFAULT_AVG + 1,
            DEFAULT_MAX - 1,
            DEFAULT_MAX,
            DEFAULT_MAX + 1,
            2 * DEFAULT_MAX,
            3 * 1024 * 1024 + 7,
        ];
        for &sz in &sizes {
            for input in [pseudo_random(&format!("stream-{sz}"), sz), vec![0u8; sz]] {
                let want: Vec<usize> = c.chunks(&input).iter().map(|s| s.len()).collect();
                for step in [1, 2, 3, 7, 13, DEFAULT_MIN, DEFAULT_MAX, DEFAULT_MAX + 1] {
                    assert_eq!(
                        stream_cuts(&c, &input, step),
                        want,
                        "size {sz}, read step {step}: streamed cuts differ from in-RAM"
                    );
                }
            }
        }
    }
}
