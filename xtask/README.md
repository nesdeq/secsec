# xtask

Workspace automation, run as `cargo xtask <command>` (an alias in `.cargo/config.toml` for a plain
binary crate; no external task runner).

## Commands

- **`cargo xtask vectors --check`**: recompute every value in
  [`../vectors/secsec-kat-v1.txt`](../vectors) from the **live code paths** and fail on any drift, on a
  line that is neither a computed output nor a documented input, or on a section whose asserting test
  does not exist (`secsec-Implementation.md` §3). Without `--check` it also prints the live values, to
  update the file after a deliberate change. The same comparison runs under `cargo test` as
  `committed_vectors_match_live_code`, so drift fails CI without the `xtask` step.
- **`cargo xtask release`**: prints the reproducible static `musl` build recipe (§18: fixed
  `SOURCE_DATE_EPOCH`, remapped paths, a stripped static binary) without running it. The release
  workflow does not follow it yet.

Its tests also check that every workspace member inherits the workspace lints
(`unsafe_code = "forbid"`, clippy `all = "deny"`). Not a security-critical crate, but the vectors
check keeps the published KATs honest against the implementation.
