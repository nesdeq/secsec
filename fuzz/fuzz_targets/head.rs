#![no_main]
//! cargo-fuzz target for the `head` decoder (secsec-Design.md §3, §18). Run:
//!   cargo +nightly fuzz run head
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    secsec_fuzz::fuzz_head(data);
});
