#![no_main]
//! cargo-fuzz target for the `roster_entry` decoder (finaldesign.md §3, §18). Run:
//!   cargo +nightly fuzz run roster_entry
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    secsec_fuzz::fuzz_roster_entry(data);
});
