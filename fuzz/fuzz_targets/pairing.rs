#![no_main]
//! cargo-fuzz target for the `pairing` decoder (secsec-Design.md §18): `cargo +nightly fuzz run pairing`.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    secsec_fuzz::fuzz_pairing(data);
});
