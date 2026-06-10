# secsec-recovery

The recovery keyslot (`secsec-Design.md` §8.6, security property P14).

An optional, server-stored wrap of the master key under a key the user holds out-of-band — a 256-bit
**recovery code** (preferred) or a **passphrase** (explicitly weaker; the blob is server-stored, so a
weak passphrase can be cracked offline). It uses the §9.4 CTX committing AEAD (CMT-4) directly, so a
wrong code/passphrase fails the commitment rather than silently producing a wrong key, and a
partitioning oracle is closed. Authenticity is **not** the wrap's job: the recovered candidate is
verified against `mk_commit_g` from the RFP-anchored chain (§7 step 3) — so recovery is **not** a
server-exploitable backdoor.

Blob layout: `salt(16) ‖ ctx_tag(32) ‖ ct(32)`. The AD — `"secsec-recovery-v1" ‖ device_pubkey ‖
le32(gen)` — is recomputed by the recoverer from material it already holds, so it is not stored.

## Public API

- `recovery_key_from_code(salt, code)` — BLAKE3 KDF for the high-entropy code path.
- `recovery_key_from_passphrase(salt, passphrase)` — Argon2id (m=64 MiB, t=3, p=1, §19) for the
  weaker path.
- `seal_recovery(master_key, gen, device_pubkey, recovery_key, salt)` → blob.
- `recover` / `recover_with_code` / `recover_with_passphrase` — recover **and** verify against
  `mk_commit_g`. `recover_raw` / `recover_raw_with_code` — recover the raw candidate **without** the
  commit check, for the recovery-driven cold-start where the fold verifies `mk_commit`.
- `SALT_LEN`, `RecoveryError`.

The repo-level orchestration (store record, RFP-anchored fold, working-tree restore) and the
`recovery-init` / `recover` CLI live in `secsec-client`.
