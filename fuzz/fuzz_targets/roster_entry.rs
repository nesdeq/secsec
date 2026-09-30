#![no_main]
//! cargo-fuzz target for the `roster_entry` decoder (secsec-Design.md §18): `cargo +nightly fuzz run roster_entry`.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    secsec_fuzz::fuzz_roster_entry(data);
});
