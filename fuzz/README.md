# secsec fuzz targets

`cargo-fuzz` targets — one per untrusted-input decoder (`finaldesign.md` §3, §18). Each must be
**total** on arbitrary input (never panic / OOM; the §19 pre-allocation bounds guard against
alloc/recursion/decompression bombs).

Targets: `frame`, `wire`, `roster_entry`, `object`, `head`, `tree`, `commit`.

## Run (needs nightly + cargo-fuzz + LLVM)

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run frame        # or any target name above
cargo +nightly fuzz run wire -- -max_total_time=60
```

This crate is **not** a workspace member (libfuzzer needs nightly/sanitizers; it builds out-of-band).

## Stable CI coverage (no fuzz toolchain needed)

Each target is a thin wrapper over a `secsec_fuzz::fuzz_*` function. The same functions are hammered
with a large deterministic corpus (zeros/ones/counters/huge-length-prefix/pseudo-random + single-byte
mutations) by the `secsec-fuzz` crate's `every_decoder_survives_arbitrary_input` test, so the
robustness property is checked in normal `cargo test` even without nightly. Deep, coverage-guided
fuzzing via the targets above is the additional, toolchain-gated layer.
