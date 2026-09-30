# secsec-fuzz

The decoder fuzz harness (`secsec-Design.md` §18, §19). One `fuzz_*` body per decoder that parses
**untrusted** bytes from the network or disk. Each MUST be **total** on arbitrary input: never panic,
never exhaust memory (the §19 bounds are checked before allocation).

These functions are the bodies of the `cargo-fuzz` targets under [`../../fuzz/`](../../fuzz) (run with
`cargo +nightly fuzz run <target>`). They are **also** exercised on **stable** by
`tests::every_decoder_survives_arbitrary_input`, which feeds each a fixed-seed corpus (empty input,
all zeros, all `0xff`, counting bytes, huge length prefixes, pseudo-random buffers, and single-byte
flips), so the robustness property holds under a plain `cargo test`; `fuzz_manifest_lists_every_target`
checks that `fuzz/Cargo.toml` builds exactly these targets.

## Public API

- `fuzz_frame` (FRAME and the blob splitters), `fuzz_wire` (every network message), `fuzz_roster_entry`
  (the stored entry and its plaintext), `fuzz_keyhist` (a key-history peel), `fuzz_keyslot` (an X-Wing
  public key and a keyslot body), `fuzz_object` (the object opener per content type), `fuzz_head`
  (the head blob), `fuzz_frontier` (the sealed frontier and its plaintext), `fuzz_tree`,
  `fuzz_commit`, `fuzz_pairing` (both pairing-mailbox messages).

(`DECODERS`, the `(name, fn)` table the stable test iterates, and its `Decoder` alias are
`#[cfg(test)]`.)
