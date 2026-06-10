# secsec-fuzz

The decoder fuzz harness (`secsec-Design.md` §3, §18). One `fuzz_*` entry per decoder that parses
**untrusted** bytes (from the network or disk). Each MUST be **total** on arbitrary input — never
panic, never OOM (the §19 pre-allocation bounds guard against alloc/recursion/decompression bombs).

These functions are the bodies of the `cargo-fuzz` targets under [`../../fuzz/`](../../fuzz)
(run with `cargo +nightly fuzz run <target>`). They are **also** exercised on **stable** by the
`tests::every_decoder_survives_arbitrary_input` test, which hammers each with a large deterministic
corpus (zeros, ones, counters, pseudo-random, and mutations of valid encodings) — so the robustness
property is checked in normal `cargo test` even without the fuzz toolchain. Deep, coverage-guided
fuzzing via the targets is the additional, toolchain-gated layer.

## Public API

- `fuzz_frame`, `fuzz_wire`, `fuzz_roster_entry`, `fuzz_object`, `fuzz_head`, `fuzz_tree`,
  `fuzz_commit` — one per untrusted-input decoder.
- `DECODERS` — the `(name, Decoder)` table the stable robustness test iterates; `Decoder` type alias.
