# secsec-roster

The roster sigchain: entries, fold and succession, and the key-management layers wrapped around it
(`secsec-Design.md` §8). This is the cryptographic membership list: who may read and write.

An append-only, hash-chained, SSHSIG-signed log. Each entry is `{seq, prev, op, ts, signer}` signed
under `NS_ROSTER`; `prev` is the BLAKE3 of the full previous entry, and the genesis entry's hash is the
repository's **RFP** (§5). The fold replays the chain with **succession**: entry `n` is valid only if
its signer is a *current member* of the state folded from entries `0..n-1`, so a non-member or a
revoked device cannot extend the chain, and every `AddDevice` must record the current generation's
`mk_commit`. The server can neither read the chain nor forge succession: each entry is sealed under a
per-seal key from `roster_key_g`, its `seq`, and a fresh random salt (the v2 format, §9.5); legacy v1
entries (keyed by `seq` alone) still open but are never written.

Beyond the plaintext sigchain it holds the per-entry CTX/CMT-4 AEAD, the never-trimmed roster-key and
data-key histories and their peels (§8.2), the cold-start fold (§8.1), and the revoke⇒rotate op
builder with its transitive add-by closure (§8.1, §8.4). Enrollment over the wire lives in
`secsec-client` (`pair`, `repo`), which also persists and enforces the §8.1 anti-rollback anchor.

## Public API

- Sigchain: `Op` (`Genesis` / `AddDevice` / `RevokeDevice` / `Rotate` / `SetMinAlgo`), `Entry`,
  `genesis` (returns the entry and the RFP), `append`, `append_many`, `encode_entry` / `decode_entry`.
- Per-entry AEAD: `seal_entry` (fresh salt), `seal_entry_with_salt` (fixed salts are for KATs only),
  `open_entry` (v2 or legacy v1 by the FRAME), `frame_gen`; `seal_entry_v1` behind the `legacy-v1`
  feature, for vector tooling.
- Key histories (§8.2): `seal_roster_keyhist`, `seal_data_keyhist`, `peel_data_keys` (every peeled key
  checked against its `mk_commit`), `ROSTER_KEYHIST_LEN`, `DATA_KEYHIST_LEN`.
- Cold start: `cold_start_fold(candidate, g_cur, rfp, roster_keyhist, entries)` peels the roster keys,
  opens each entry under the generation its FRAME names, folds, and checks the candidate master key
  against `mk_commit_{g_cur}`: the one entry point that turns a fetched chain into trusted state.
- Revocation: `revoke_closure(state, target, after_seq, revoker)` (grants at or after `after_seq` down
  the target's add-by tree, walking through earlier ones, never the revoker), `revoke_rotate_ops`.
- `State` (`members`, `ever_members`, `generation`, `min_algo`, `mk_commits`, `added_by`,
  `added_at`, `enroll_pubs`, `tip_seq`; `is_member`), `MkCommit`, `RosterError`.

The pieces `cold_start_fold` composes (`fold`, `entry_hash`, `peel_roster_keys`, the key-history
openers, `devices_added_by`) are crate-internal: folding a chain without the RFP anchor and the
`mk_commit` check is precisely the mistake the cold-start entry point exists to prevent.
