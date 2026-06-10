# secsec-roster

The roster sigchain — entries, fold/succession, the anti-rollback frontier, and the key-management
layers wrapped around it (`secsec-Design.md` §8). **This is the real ACL.**

An append-only, hash-chained, SSHSIG-signed log. Each entry is `{seq, prev, op, ts, signer}` signed
under `NS_ROSTER`; `prev` is the BLAKE3 of the full previous entry, and the genesis entry's hash is
the repository's **RFP** (§5). `fold` replays the chain with **succession**: entry `n` is valid only
if its signer is a *current member* of the state folded from entries `0..n-1` — so a non-member or
revoked device cannot extend the chain. The server can neither read the chain (entries are encrypted
per-seq under `roster_key_g`) nor forge succession.

Beyond the plaintext sigchain it also holds the layers that wrap it: the per-entry CTX/CMT-4 AEAD
(§9.5), the never-trimmed roster-key and data key-histories and their peel (§8.2), the cold-start
bootstrap fold (§8.1), the enrollment primitives (SAS commitment + grant attestation, §7/§9.6), and
the revoke⇒rotate op builder (§8.4). The SAS primitives back the lower-level **direct grant**; the
shipped CLI enrolls via **invite-code pairing** (`secsec-client::pair`), which layers on the same
`AddDevice` op + keyslot wrap without a human SAS comparison (§7).

## Public API

- Sigchain: `Op` (`Genesis`/`AddDevice`/`RevokeDevice`/`Rotate`/`SetMinAlgo`), `genesis`, `append`,
  `append_many`, `encode_entry`/`decode_entry`, `entry_hash`, `fold`, `is_member`.
- Anti-rollback: `frontier_of`, `check_frontier`.
- Per-entry AEAD: `seal_entry` / `open_entry`.
- Key-histories (§8.2): `seal_roster_keyhist`/`peel_roster_keys`/`open_roster_keyhist`,
  `seal_data_keyhist`/`peel_data_keys`/`open_data_keyhist`.
- Cold-start: `cold_start_fold` (peel, decrypt, fold, verify RFP + `mk_commit`).
- Revocation: `revoke_closure` (transitive add-by closure), `devices_added_by`, `revoke_rotate_ops`.
- Enrollment (§7): SAS commitment + value, `sign_grant` / `verify_grant`; `GRANT_NONCE_LEN`,
  `ENROLLMENT_NONCE_LEN`, `SAS_MODULUS`.
- `State`, `Frontier`, `RosterError`; `ROSTER_KEYHIST_LEN`, `DATA_KEYHIST_LEN`.
