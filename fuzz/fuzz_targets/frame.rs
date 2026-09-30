#![no_main]
//! cargo-fuzz target for the `frame` decoder (secsec-Design.md §18): `cargo +nightly fuzz run frame`.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    secsec_fuzz::fuzz_frame(data);
});
