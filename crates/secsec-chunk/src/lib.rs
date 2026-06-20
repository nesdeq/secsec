//! `secsec-chunk` — keyed FastCDC content-defined chunking (`secsec-Design.md` §9.7).
//!
//! Standard FastCDC v2020 normalized chunking, except the 256-entry gear table is derived from the
//! per-generation secret `cdc_seed`, making boundaries repo-specific (privacy limits + the role of
//! default-on padding: §9.7/§21). Deterministic: same seed + same input ⇒ same cut points.

#![forbid(unsafe_code)]

use std::io::Read;

/// Default FastCDC sizes (§19): 16 / 64 / 256 KiB.
pub(crate) const DEFAULT_MIN: usize = 16 * 1024;
/// Default average chunk size.
pub(crate) const DEFAULT_AVG: usize = 64 * 1024;
/// Default maximum chunk size.
pub(crate) const DEFAULT_MAX: usize = 256 * 1024;

/// Normalization level (FastCDC NC): how many bits the pre-/post-average masks differ from
/// `log2(avg)`. Level 2 is the common choice; it tightens the chunk-size distribution toward `avg`.
const NORMALIZATION: u32 = 2;

/// A configured keyed chunker. Cheap to clone; holds the derived gear table and masks.
#[derive(Clone)]
pub struct Chunker {
    gear: [u64; 256],
    min: usize,
    avg: usize,
    max: usize,
    mask_s: u64,
    mask_l: u64,
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

/// Build a 256-entry gear table by expanding `cdc_seed` with BLAKE3 in XOF mode.
fn build_gear(cdc_seed: &[u8; 32]) -> [u64; 256] {
    let mut h = blake3::Hasher::new_keyed(cdc_seed);
    h.update(b"secsec-cdc-gear-v1");
    let mut xof = h.finalize_xof();
    let mut bytes = [0u8; 256 * 8];
    xof.fill(&mut bytes);
    let mut gear = [0u64; 256];
    for (i, g) in gear.iter_mut().enumerate() {
        *g = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
    }
    gear
}

/// A mask with `count` one-bits spread across the high, well-mixed bits of the 64-bit fingerprint
/// (the Gear hash accumulates entropy upward via `<< 1`). Cut probability per byte ≈ `2^-count`,
/// so `count = log2(target)` yields an average run length of `target`.
fn spread_mask(count: u32) -> u64 {
    let count = count.clamp(1, 30);
    let mut m = 0u64;
    for j in 0..count {
        m |= 1u64 << (63 - 2 * j);
    }
    m
}

impl Chunker {
    /// Build a chunker with the §19 default sizes.
    #[must_use]
    pub fn with_defaults(cdc_seed: &[u8; 32]) -> Self {
        Self::new(cdc_seed, DEFAULT_MIN, DEFAULT_AVG, DEFAULT_MAX)
    }

    /// Build a chunker with explicit `min < avg < max` sizes.
    ///
    /// # Panics
    /// Panics unless `0 < min <= avg <= max`.
    #[must_use]
    pub(crate) fn new(cdc_seed: &[u8; 32], min: usize, avg: usize, max: usize) -> Self {
        assert!(
            0 < min && min <= avg && avg <= max,
            "require 0 < min <= avg <= max"
        );
        let bits = floor_log2(avg);
        let mask_s = spread_mask(bits + NORMALIZATION); // stricter (rarer cut) before the avg point
        let mask_l = spread_mask(bits.saturating_sub(NORMALIZATION)); // looser after it
        Self {
            gear: build_gear(cdc_seed),
            min,
            avg,
            max,
            mask_s,
            mask_l,
        }
    }

    /// Length of the first chunk in `data` (the FastCDC cut point), in `[min, max]` unless `data`
    /// is shorter than `min` (then the whole of `data`).
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
        // Phase 1: stricter mask up to the normalized split point.
        while i < center {
            fp = (fp << 1).wrapping_add(self.gear[data[i] as usize]);
            if fp & self.mask_s == 0 {
                return i + 1;
            }
            i += 1;
        }
        // Phase 2: looser mask up to the end (= max, or end of data).
        while i < end {
            fp = (fp << 1).wrapping_add(self.gear[data[i] as usize]);
            if fp & self.mask_l == 0 {
                return i + 1;
            }
            i += 1;
        }
        end
    }

    /// Cut `data` into chunk end-offsets. The final offset always equals `data.len()`.
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

    /// Chunk `reader` as a stream, invoking `emit` once per content-defined chunk and holding at most
    /// `max` bytes in memory regardless of input length. Returns the total bytes read.
    ///
    /// The cut points are **byte-identical** to [`Chunker::chunks`] over the whole input, the property
    /// that keeps cross-device dedup and merge content-equality intact: a cut is decided only once the
    /// window holds at least `max` bytes, or the reader is at EOF — so the window always covers exactly
    /// the bytes the in-memory cutter (which scans at most `max` ahead) would have seen.
    pub fn chunk_stream<R, E, F>(&self, mut reader: R, mut emit: F) -> Result<u64, StreamError<E>>
    where
        R: Read,
        F: FnMut(&[u8]) -> Result<(), E>,
    {
        let mut buf: Vec<u8> = Vec::with_capacity(self.max);
        let mut eof = false;
        let mut total: u64 = 0;
        loop {
            // Refill the window up to `max` bytes; only EOF lets a shorter window be cut. The tail is
            // zeroed once here (not per `read`), so a slow drip of tiny reads stays O(n), not O(n·max).
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

/// floor(log2(x)) for x >= 1.
fn floor_log2(x: usize) -> u32 {
    debug_assert!(x >= 1);
    (usize::BITS - 1) - x.leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x33; 32];

    /// Deterministic pseudo-random bytes (BLAKE3 XOF) so size-distribution tests are reproducible.
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
        // Reassembly is exact.
        let joined: Vec<u8> = chunks.iter().flat_map(|s| s.iter().copied()).collect();
        assert_eq!(joined, data);
        // Every chunk <= max; every chunk except the last >= min.
        for (idx, ch) in chunks.iter().enumerate() {
            assert!(ch.len() <= DEFAULT_MAX, "chunk over max");
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
        // Generous band around the 64 KiB target — validates the mask popcount logic without
        // being flaky (data is deterministic).
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
        let small = [0u8; 100]; // < min
        assert_eq!(c.cut_points(&small), vec![100]);
    }

    #[test]
    fn mask_popcount() {
        assert_eq!(spread_mask(16).count_ones(), 16);
        assert_eq!(spread_mask(1).count_ones(), 1);
        assert_eq!(floor_log2(DEFAULT_AVG), 16);
    }

    /// A reader that yields at most `step` bytes per `read` — exercises read-width independence.
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

    /// The streaming cutter yields byte-identical boundaries to the in-RAM cutter, across the full
    /// size matrix, high- and low-entropy inputs, and every read width.
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
