# xtask

Workspace automation, run as `cargo xtask <command>` (the standard cargo-xtask pattern — a plain
binary crate, no external task runner).

## Commands

- **`cargo xtask vectors`** — recompute every value in [`../vectors/secsec-kat-v1.txt`](../vectors)
  from the **live code paths** and print them (use this to update the file after a deliberate KAT
  change). `cargo xtask vectors --check` recomputes and **fails** if the committed file differs — the
  mechanical anti-drift guard for the cross-implementation vectors (`secsec-Design.md` §3). The same
  comparison also runs in normal `cargo test` as the `committed_vectors_match_live_code` test, so drift
  fails CI without needing the `xtask` invocation.
- **`cargo xtask release`** — the reproducible static `musl` build recipe (§18).

Not a security-critical crate — it is build/release tooling — but the `vectors --check` path keeps the
published KATs honest against the implementation.
