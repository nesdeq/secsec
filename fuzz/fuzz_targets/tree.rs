#![no_main]
//! cargo-fuzz target for the `tree` decoder (finaldesign.md §3, §18). Run:
//!   cargo +nightly fuzz run tree
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    secsec_fuzz::fuzz_tree(data);
});
