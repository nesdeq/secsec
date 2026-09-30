# secsec fuzz targets

`cargo-fuzz` targets, one per decoder of untrusted bytes (`secsec-Design.md` §18). Each must be
**total** on arbitrary input: never panic, never exhaust memory (the §19 bounds are checked before
allocation).

Targets: `frame`, `wire`, `roster_entry`, `keyhist`, `keyslot`, `object`, `head`, `frontier`, `tree`,
`commit`, `pairing`.

## Run (needs nightly and cargo-fuzz)

```sh
cargo install cargo-fuzz --locked
cargo +nightly fuzz list
cargo +nightly fuzz run frame                        # or any target above
cargo +nightly fuzz run wire -- -max_total_time=60   # a one-minute run
```

This package is **not** a workspace member (libFuzzer needs nightly and sanitizers; an empty
`[workspace]` table keeps cargo from adopting it).

## Stable coverage (no fuzz toolchain needed)

Each target is a thin wrapper over a `secsec_fuzz::fuzz_*` function. The same functions run over a
fixed-seed corpus (empty, all zeros, all `0xff`, counting bytes, huge length prefixes, pseudo-random
buffers, single-byte flips) in the `secsec-fuzz` crate's `every_decoder_survives_arbitrary_input`
test, so the robustness property is checked in every `cargo test`; `fuzz_manifest_lists_every_target`
keeps this package's target list identical to the harness. Coverage-guided fuzzing here is the
additional, toolchain-gated layer.
