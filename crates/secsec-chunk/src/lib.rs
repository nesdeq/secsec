//! `secsec-chunk` — **keyed** FastCDC content-defined chunking (`secsec-Design.md` §9.7).
//!
//! Standard FastCDC uses a fixed, canonical gear table so that every implementation cuts at the
//! same boundaries. secsec deliberately does the opposite: the 256-entry gear table is derived
//! from the per-generation secret `cdc_seed`, so chunk boundaries are **repo-specific** and a
//! cross-repo size-fingerprint database does not apply. (Boundary privacy is only partial — a
//! chosen-plaintext archiver can recover the gear key, Alexeev et al. ePrint 2025/532 — so the
//! load-bearing privacy mechanism is default-on chunk padding, §9.7/§21; keyed chunking is
//! defense-in-depth against the *offline* dictionary.)
//!
//! The cut-point algorithm is FastCDC v2020 normalized chunking (Xia et al.): a Gear rolling hash
//! `fp = (fp << 1) + gear[b]`, a minimum-size skip, a stricter mask before the average point and a
//! looser mask after it (normalization), and a hard maximum. Only the gear table is keyed; the
//! algorithm is otherwise standard. Determinism: same `cdc_seed` + same input ⇒ same cut points.

#![forbid(unsafe_code)]

/// Default FastCDC sizes (§19): 16 / 64 / 256 KiB.
pub const DEFAULT_MIN: usize = 16 * 1024;
/// Default average chunk size.
pub const DEFAULT_AVG: usize = 64 * 1024;
/// Default maximum chunk size.
pub const DEFAULT_MAX: usize = 256 * 1024;

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
    pub fn new(cdc_seed: &[u8; 32], min: usize, avg: usize, max: usize) -> Self {
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
    pub fn next_cut(&self, data: &[u8]) -> usize {
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
}
