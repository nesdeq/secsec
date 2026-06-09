//! Robustness: the strict decoder must **never panic** on arbitrary input — only ever return
//! `Err`. This is the stable-Rust stand-in for libFuzzer coverage of the `canon` decoder
//! (continuous libFuzzer fuzzing is a nightly follow-up; see `.github/workflows/ci.yml`).

use proptest::prelude::*;
use secsec_canon::Reader;

proptest! {
    #[test]
    fn reader_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
        max in 0usize..(1 << 20),
    ) {
        let mut r = Reader::new(&data);
        let _ = r.u8();
        let _ = r.u16();
        let _ = r.u32();
        let _ = r.u64();
        let _ = r.bytes(max);
        let _ = r.raw(13);
        let _ = r.remaining();
        // A second reader with an enormous max must stay slice-bounded (no over-allocation/panic).
        let mut r2 = Reader::new(&data);
        let _ = r2.bytes(usize::MAX);
    }
}
