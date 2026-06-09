# secsec — Final Design

A self-hosted, end-to-end-encrypted, **live two-way** file-sync system (server + client),
single static Rust binary. The server is **blind**: it stores only ciphertext and never learns
file contents, names, structure, or sizes beyond a bounded, documented residual. The only
credential is an SSH key. This document is implementation-ready and is the authoritative spec;
it supersedes `DESIGN.md`.

> Design principle: **every security claim in §4 is paired with the exact mechanism that
> provides it.** Anything not so backed is not claimed. The only items deferred to "residual"
> are *proven-minimal* — impossibilities for a blind, untrusted server (§22), not unfinished work.

---

## 1. Usecase

- **Single user**, many devices; each device has its own SSH key.
- **Live two-way sync**: edit on any device, changes propagate, conflicts resolved with no
  silent data loss; full version history is a by-product.
- **Zero-knowledge** against an untrusted server: content **and** metadata encrypted.
- **Self-hosted, one static binary**, no DB, no user-managed certificates, minimal deps.
- **SSH public key is the only required configuration.** Device enrollment and key recovery are
  first-class flows.

## 2. Non-goals

- Multi-tenant hosting; provider-side search/indexing.
- Hiding the bounded metadata of §4.3 (sizes/timing/equality) — reduced, not eliminated.

## 3. Threat model

Adversaries: a **malicious/compromised server** (the primary one), a **network attacker**, a
**revoked device**, and a **stolen client**. We assume the device's SSH key and the user's
out-of-band channel (reading a fingerprint off a screen) are trustworthy; everything else,
including the server and the network, is hostile.

What the server sees: framed, equal-looking ciphertext; object byte-sizes (bucketed, §9.6);
the set of device IDs (opaque); access timing. Nothing else.

---

## 4. Security properties (claim ⇄ mechanism)

Each row is a guarantee and the mechanism that earns it. Residuals in §22.

| # | Guarantee | Mechanism |
|---|---|---|
| P1 | Server cannot read content or metadata | Per-object fully-committing (CMT-4) AEAD; metadata lives inside encrypted tree/commit blobs (§9); roster entries encrypted per-entry under a per-seq derived key with CTX/CMT-4 as specified in §8.1/§9.5 |
| P2 | Server cannot alter an object without detection | Content-addressing re-verified on fetch + AEAD tag + key-commitment (§9.2–9.4) |
| P3 | Server cannot forge a commit/head/roster entry | All signed via SSHSIG with disjoint namespaces; verified against the roster (§9.5, §8) |
| P4 | Server cannot feed a new/reinstalled device a **forged repository or key** | Out-of-band **RFP** anchor + `mk_commit` verification of any unwrapped master key + SAS with commitment-before-reveal at enrollment (§7) |
| P5 | A connection ≠ the ability to read or write; unenrolled keys are rejected before any data access | Every repo RPC — including reads — requires a per-op signature from a **keyslot-owning** (rostered) key; server MUST verify keyslot existence at /keyslots/\<device_id\>/\<g\> on every per-op request, not only at connection time (§9.6, §11, §12); a revoked device with an open connection can still issue requests until keyslot deletion is checked — on cooperative servers the re-check window is ≤ the server-nonce TTL (60 s, §19); on a malicious server, keyslot deletion cannot be enforced (residual §22) |
| P6 | Revocation removes access to data created after rotation (forward secrecy) | revoke ⇒ rotate: new master-key generation, re-wrap to remaining devices, delete keyslot; pre-rotation ciphertext remains a residual (§8.4, §22) |
| P7 | Revocations cannot be lost or rolled back **by the untrusted server** | Roster is an append-only, hash-chained, signed sigchain with succession + frontier (§8). (Eviction of the legitimate device by a *compromised, online* peer racing the CAS is a separate adversary — the concurrent mutual-revocation residual, §22.) |
| P8 | Rollback/replay of sigchain state is detected; cross-remote rollback of per-ref heads and sigchain is alarmed; fork evidence is computed and alarmed when two devices exchange commits with DAG-incomparable last_seen_head values | Monotonic, signed frontiers on every counter; local frontier sealed with a key derived from **private** key material (§8.5, requires device_ed25519_scalar_clamped, not the public key); rollback-aware merge (§8.5, §10); cross-remote head-rollback alarm mirrors sigchain alarm (§14); fork detection algorithm in §10 fires when received last_seen_head is DAG-incomparable to client head |
| P9 | No cross-protocol signature reuse | Disjoint SSHSIG namespaces; server-chosen nonces confined to `auth`/`write` (§9.5) |
| P10 | No catastrophic AEAD misuse / key-confusion for object and recovery wraps | Unique per-object key, fixed nonce, CMT-4 committing AEAD via CTX construction (§9.4); recovery wrap uses same CTX pattern (§8.6); key-history wrap (§8.2) uses CTX pattern with ctx_tag_keyhist = BLAKE3::keyed_hash(k_keyhist_g, "secsec-ctx-v1" ‖ AD_keyhist ‖ T), binding master_key_g as plaintext |
| P11 | Forward secrecy after revocation | Post-rotation data uses a new generation the revoked device cannot derive (§8.4) |
| P12 | Transport is authenticated without a CA; first-init TOFU window is a documented residual | TLS 1.3 to a pinned self-signed host key (TOFU + `--host-fp`), channel-bound auth (§11); when `--host-fp` is not supplied at init, the pin rests on a one-time interactive fingerprint confirmation — this first-init TOFU window is a residual (§22) |
| P13 | No algorithm/format downgrade once a `SetMinAlgo` entry has been received | Pinned TLS & signature algorithms; `SetMinAlgo` floor in the sigchain enforced on every fetched keyslot (not only at creation); compile-time floor (§16); withheld entries detectable via multi-remote cross-check (§14, §22) |
| P14 | The single user cannot be permanently locked out | Optional recovery keyslot (Argon2id/recovery-code), authenticity-anchored to RFP (§8.6) |
| P15 | Durability despite a hostile server | Content-addressed replication to ≥2 remotes; client retains until quorum-confirmed via put→get→verify round-trip on each remote (§14) |

---
## 5. Identifiers & trust anchor

- **Device key** — an SSH keypair per device. Ed25519 (preferred) or RSA ≥3072. Roles:
  *sign* (SSHSIG; agent/hardware OK) and *unwrap* (X25519/RSA-OAEP; needs the private key as a
  file — agent/FIDO cannot do ECDH). `ecdsa`/`sk-*` keys are sign-only → enrollment-incapable.
- **`device_id`** := `BLAKE3(canonical(device_pubkey))`. Cryptographically bound to the key;
  every commit/head/roster entry is verified by checking its signature against the pubkey that
  the roster maps this id to. A signer can never act under another device's id.
- **`master_key`** — 256-bit, random, generated at `init`, **RAM-only on clients, never written
  to disk**, `zeroize`d, `mlock`ed. It has a **generation** `g` (starts at 1) advanced by rotation.
- **`mk_commit_g`** := `BLAKE3::keyed_hash(master_key_g, "secsec-mk-commit-v1" ‖ le32(g))` — a
  hiding, binding commitment recorded in the sigchain. Here `master_key_g` occupies the BLAKE3
  PRF **key** argument (not the IKM/message role); this is the only place where `master_key_g`
  serves as a BLAKE3 key argument. Binding `g` into the input prevents the
  commitment from one generation passing verification for a different generation (generation-rollback
  attack closed). Lets any holder of a candidate key prove it is the genuine generation-`g` master
  key without the server being able to forge one.
- **`host_id`** — server identity token bound into connection auth blobs and the session
  transcript. Computed by the client from locally-pinned material; MUST NOT be accepted from the
  server.
  - **QUIC / TLS mode:** `host_id = BLAKE3(canonical(server pinned SPKI bytes))`, where the SPKI
    bytes are the SubjectPublicKeyInfo DER encoding of the pinned server certificate public key.
  - **stdio / SSH mode:** `host_id = BLAKE3(canonical(K_S))`, where `K_S` is the server host key
    extracted from the SSH exchange hash `H` (RFC 4253 §8).
- **RFP (Repository FingerPrint)** := `BLAKE3(canonical(genesis sigchain entry))`. The genesis
  transitively commits to device-1's key and to `mk_commit_1`. **RFP is the one out-of-band
  anchor**: shown at `init`, and required (via SAS) at every enrollment. Everything else can be
  fetched from the untrusted server and cryptographically checked against RFP.

---
## 6. Object model

All objects are content-addressed, framed, encrypted (§9.1).

| Object | Holds | Address |
|---|---|---|
| **Chunk** | a content-defined slice of a file | id (§9.2) |
| **Tree** | dir listing: name → { mode, mtime, size, chunk-list \| subtree } | id |
| **Commit** | root tree id, parent id(s), `device_id`, `version`, `roster_seq`, `last_seen_head`, ts; SSHSIG-signed | id |
| **Head** | per-ref **signed + encrypted** pointer { commit id, `head_version`, `roster_seq`, prev-head id } (§9.8) | name |
| **Roster entry** | one signed, hash-chained sigchain record (§8) | by seq + hash |
| **Keyslot** | versioned, authenticated wrap of `master_key_g` to a device key (§8.3) | device_id + gen |

Files split by **keyed FastCDC** (§9.6); small chunks packed. Trees/commits/roster are blobs in
the same store, so the server learns no structure beyond §4.3.

---

## 7. Trust bootstrap & device enrollment

**Why enrollment needs an out-of-band anchor.** A keyslot is a wrap *to a device's public key*;
anyone who knows that public key — including the server — can fabricate a keyslot wrapping a
**fake** master key, handing a fresh device a fake key and a fully self-consistent **fake
repository** (attacker-chosen files). Possession of a keyslot therefore cannot by itself prove
authenticity. Enrollment instead authenticates the *master key itself* against an out-of-band
anchor (RFP).

**`init` (device 1):**
1. Generate `master_key_1`; compute `mk_commit_1`.
2. Write genesis sigchain entry (seq 0), self-signed, containing device-1 pubkey + `mk_commit_1`.
3. Compute and **display RFP** ("Repository fingerprint: `BLAKE3:…`" — RFP is `BLAKE3(canonical(genesis))`
   per §5, so it MUST be labeled/compared as BLAKE3, not SHA256). The user records it.
4. Optionally create a recovery keyslot (§8.6).

**`grant` (add device D), performed on an already-enrolled device E that holds `master_key`:**

The SAS protocol uses a mandatory commitment-before-reveal round. Without it, after learning
`grant_nonce` in step 2d, a relay could grind `D_pubkey_M` in ~2^SAS_bits BLAKE3 evaluations —
approximately 30 ms for a 20-bit (6-digit decimal) SAS — to find a key that produces a matching
SAS, then retroactively substitute it. The commitment `c_E` fixes `grant_nonce` before the relay
sends `D_pubkey` to E (step 2c before 2d), so the relay must choose `D_pubkey_M` without knowing
`grant_nonce`, collapsing the relay's advantage to one blind guess per session (probability
1/1,000,000).

E MUST enforce a rate limit of at most 5 SAS sessions per `D_pubkey` per hour, tracked in E's
local state, independent of sigchain operations. Sessions that abort at any step (including steps
1–3) count toward the limit. E MUST NOT begin step 2 for a `D_pubkey` that has reached the limit
within the rolling 1-hour window. Aborted sessions MUST discard `grant_nonce`; E MUST NOT reuse a
`grant_nonce` across sessions.

1. D shows its pubkey fingerprint; the human enters/confirms it on E.
2. **Commitment round (mandatory):**
   a. E generates `grant_nonce` (128 bits, OS CSPRNG).
   b. E computes and sends commitment
      `c_E = BLAKE3("secsec-sas-commit-v1" ‖ grant_nonce ‖ RFP ‖ D_pubkey)`
      to D **before** D sends anything beyond its connection request, where `D_pubkey` is the key
      confirmed by the human in step 1. Including `D_pubkey` in `c_E` means D's verification of
      `c_E` confirms E committed to exactly that key; a relay substituting `D_pubkey_M` will fail
      D's check.
   c. D sends `D_pubkey`.
   d. E MUST NOT reveal `grant_nonce` until `D_pubkey` has been received. A timeout before
      receiving `D_pubkey` is an abort — `grant_nonce` MUST never be revealed without a matching
      `D_pubkey`. E MUST verify that `BLAKE3(canonical(D_pubkey_received))` equals the fingerprint
      confirmed in step 1; mismatch aborts the session. E then reveals `grant_nonce`.
   e. D verifies `c_E`: recomputes
      `BLAKE3("secsec-sas-commit-v1" ‖ grant_nonce ‖ RFP ‖ D_pubkey)` and aborts if the result
      does not match.
3. Both compute **SAS** = `BLAKE3("secsec-sas-v1" ‖ RFP ‖ D_pubkey ‖ grant_nonce)`, take the
   integer value of the first 32 bits, compute mod 1,000,000 to obtain a **6-digit decimal**
   (000000–999999, zero-padded); effective human-verified entropy: ~20 bits. The human confirms
   the two displays match out-of-band. A relay that substitutes `D_pubkey_M` must have fixed a
   grinding target before step 2b and gets at most one blind guess per session (probability
   1/1,000,000). SAS binds `D_pubkey` **and** RFP, so a server swapping either produces a
   mismatch → human aborts.
4. E appends an `AddDevice` sigchain entry (D_pubkey, current `mk_commit_g`), signs it.
5. E generates a fresh `enrollment_nonce` (32 bytes, OS CSPRNG) and **sends it to D directly over
   the grant channel** — the same out-of-band-authenticated channel as the SAS ceremony, never via
   the server — and D records it locally. E then writes D's **keyslot** wrapping `master_key_g`
   (§8.3) and a `secsec-grant-v1` attestation (§9.5) over that same `enrollment_nonce`. E MUST
   verify that the selected keyslot `algo_id` satisfies the current `min_algo` from the folded
   sigchain before writing; if E cannot produce a keyslot at the required `algo_id`, E MUST abort
   the grant with an error.

**D's first sync (and every reinstall) — authenticity without trusting the server:**
1. D obtains **RFP** out-of-band (from E's screen / the SAS step / its printed copy).
2. D fetches the sigchain; verifies genesis hashes to **RFP** and the whole chain's succession
   (§8). A server-forged chain fails the RFP match.
3. D fetches its keyslot, unwraps → candidate `master_key_g`; **verifies
   `BLAKE3::keyed_hash(candidate, "secsec-mk-commit-v1" ‖ le32(g)) == mk_commit_g`** from the
   **highest-seq** `AddDevice` or `Rotate` entry in the RFP-anchored chain (D MUST use the entry
   with the greatest `roster_seq`, not any historical entry — using a stale entry would pass for
   a rolled-back key). A server-forged keyslot (fake key) fails this check → D refuses.
4. D verifies the `secsec-grant-v1` attestation covers the **`enrollment_nonce` D received
   directly from E over the grant channel** (step 5) — not a nonce merely read back from the
   server-fetched attestation, which would make the check vacuous and let the server replay a stale
   attestation. A nonce mismatch, or an attestation signed by a non-rostered key, aborts enrollment.
5. Only then does D trust the repo. The server can withhold or stale data (availability) but can
   never substitute a fake key or fake universe.

This reduces the unavoidable residual to **freshness only** on a state-less reinstall (cannot
prove "latest" without prior memory or a peer — §22), never authenticity.

---
## 8. Roster sigchain & key management

### 8.1 The roster is an append-only signed sigchain (closes lost-revoke & roster-rollback)

```
Entry { seq:u64, prev:hash, op, params, ts, signer:device_id, sig }
  sig = SSHSIG("secsec-roster-v1", canonical(seq‖prev‖op‖params‖ts‖signer))
  prev = BLAKE3(canonical(entry[seq-1]))      // 0 for genesis
ops: Genesis | AddDevice | RevokeDevice | Rotate | SetMinAlgo | HistoryReanchor
```

- **Succession:** entry `n` is valid iff `signer` is a *current member* of the state folded from
  entries `0..n-1`. Genesis self-authorizes device 1. The server can neither read the chain
  (it is encrypted under `roster_key`, §9.5) nor forge succession.
- **Fold → state:** a device is a member iff it has an `AddDevice`/genesis and no later
  `RevokeDevice`; generation = #`Rotate`+1; `min_algo` = max over `SetMinAlgo`.
- **No lost revoke:** updates *append*. The sigchain head is a CAS-guarded ref (`/roster-head`);
  on a CAS race the loser re-folds onto the new tip and re-appends — a `RevokeDevice` is retried
  until durably appended, never abandoned. (The sole exception is when the CAS winner's entry
  *revokes the retrying device itself* — a compromised online peer evicting the legitimate device;
  that retry necessarily fails succession. This is the §22 concurrent mutual-revocation residual,
  not a lost honest revoke.)
- **Revoke-before-add race:** an `AddDevice(C)` entry authored by a device B that is the subject
  of a concurrent `RevokeDevice(B)` is invalid when those two entries are ordered, regardless of
  which won the CAS. The revoking device MUST additionally compute the **transitive add-by closure**
  of B over the folded roster — every current member B added, every member *those* devices added,
  and so on — restricted to grants made after the revoking device's last-authored or last-witnessed
  sigchain entry, and append `RevokeDevice` for each device in that closure before finalising the
  key-history extension (§8.4 step 1). One level is insufficient: a compromised B can add C and have
  C add E, so revoking only B's direct grants would leave the nested sleeper E to survive the
  rotation and retain post-rotation access — defeating the forward secrecy `revoke⇒rotate` exists to
  provide. (A grant made *before* the revoker's reference point was witnessed and implicitly accepted
  under prior trust, so it is out of scope; a child grant trivially post-dates its parent and is
  always in scope.)
- **Anti-rollback:** clients persist `(max seq, tip hash)` and reject any chain shorter than
  their frontier or whose genesis ≠ pinned RFP.
- **Tip-hash consistency (third rejection condition):** after fetching a chain of length M, the
  client MUST verify `BLAKE3(canonical(fetched_chain[stored_max_seq])) == stored_tip_hash` before
  accepting any entry beyond `stored_max_seq`. Only if this check passes does the client extend
  its frontier to `(M, BLAKE3(canonical(entry[M])))`. A forked chain re-chained from an earlier
  entry will diverge at the stored frontier and be rejected.
- **Sigchain volume limits** (server MUST enforce at roster-append): max 60 entries per
  **authenticated connection identity** (i.e., per `BLAKE3(authenticated_pubkey)`) per hour; max
  10,000 total sigchain entries (configurable). The server enforces this by counting roster-append
  calls from each authenticated connection; it does not need to decrypt the sigchain entry to read
  the inner `signer` field. These limits do not weaken anti-rollback: retried revocations are
  bounded but succeed within minutes.

**Roster entry AEAD.** Each sigchain entry plaintext is encrypted before storage under a per-entry,
**generation-indexed** key with the CTX/CMT-4 construction — full normative spec in §9.5 ("Roster
entry AEAD"). `FRAME_roster` carries the generation `g` under which the entry was written;
decrypting entries that span generations (required to fold the chain) is defined in §9.5.

**Cold-start fold order (normative).** A device with no local roster state (fresh enrollment or
reinstall) bootstraps the chain as follows: (1) read the tip entry's plaintext `FRAME.gen` to learn
the current generation `g_cur`; (2) fetch its keyslot `/keyslots/<device_id>/<g_cur>`, unwrap →
candidate `master_key_{g_cur}`, derive `roster_key_{g_cur}`, decrypt the tip entry, and verify the
candidate against `mk_commit_{g_cur}` (§7 step 3); (3) peel the roster-key history (§8.2) back to
`roster_key_1`, decrypting and signature-verifying every entry from genesis — each entry's
`FRAME.gen` (authenticated by its AEAD AD) selects which `roster_key_g` decrypts it; (4) verify the
genesis entry hashes to the pinned RFP; (5) fold the now-readable chain to obtain the member set,
generation, and `min_algo`. Only after this does the device trust any head or commit. The
server-visible `FRAME.gen` is not trusted on its own: a wrong `g_cur` makes step 2's `mk_commit`
check or the RFP match in step 4 fail.

**`HistoryReanchor` op (normative).** Defined in full here; also referenced in §8.2 and §19.

```
HistoryReanchor {
  drop_before_gen:         u32,    // oldest generation now peelable (inclusive lower bound)
  synthetic_genesis_wrap:  bytes,  // wrap_g for gen=drop_before_gen, in §8.2 format
  mk_commit_at_reanchor:   hash    // the mk_commit_{drop_before_gen} commitment value itself (NOT a hash of it)
}
```

- **Succession:** signer MUST be a current member (same rule as all other ops).
- **Fold semantics:** membership state and generation counter are unchanged. The reanchor trims
  only the **data** key-history peeling depth (§8.2): enrolling devices need only peel the data
  history back to `drop_before_gen`. The sigchain remains fully foldable from genesis via the
  never-trimmed roster-key history (§8.2), so membership verification is unaffected.
- **Rejection rule:** a client MUST treat a `HistoryReanchor` entry whose
  `mk_commit_at_reanchor` does not match the `mk_commit_{drop_before_gen}` value from the
  RFP-anchored chain as a forgery and MUST halt. The `prev` hash chain is unaffected —
  `HistoryReanchor` is a standard appended entry.

### 8.2 Master-key generations & history

Each `Rotate` mints `master_key_{g+1}` and records `mk_commit_{g+1}`. So current members can read
*old* data, a **key-history** chain is stored encrypted: for each generation `g`,

```
k_keyhist_g  = BLAKE3::derive_key("secsec-keyhist-enc-v1",
                                   master_key_{g+1} ‖ le32(g))
AD_keyhist   = FRAME_keyhist        // FRAME encoding type=keyhist, gen=g
nonce        = 0                    // safe: k_keyhist_g is unique per (g, master_key_{g+1})
(ct_keyhist, T) = ChaCha20Poly1305_raw(k_keyhist_g, 0, AD_keyhist, master_key_g)
ctx_tag_keyhist = BLAKE3::keyed_hash(k_keyhist_g,
                  "secsec-ctx-v1" ‖ AD_keyhist ‖ T)
wrap_g       = ctx_tag_keyhist(32B) ‖ ct_keyhist   // T is NOT stored
```

Decryption: re-derive `k_keyhist_g`; evaluate Poly1305 over `(AD_keyhist, ct_keyhist)` to obtain
`T_cand`; compute expected `ctx_tag_keyhist`; constant-time compare; then apply the ChaCha20
keystream to `ct_keyhist` to obtain `master_key_g`. This is the same CTX/CMT-4 pattern used in
§9.4 and §8.6 — `T` feeds into `ctx_tag_keyhist`, binding the plaintext `master_key_g` to the
commitment and closing Invisible Salamander / partitioning-oracle attacks at the key-history layer.

Notation: `BLAKE3::derive_key(label, key_material)` — label is first, key_material second,
consistent with every other derivation in this spec and with the BLAKE3 API (`blake3::derive_key`
in Rust). The `FRAME_keyhist` AD binds the generation index and a `type` byte for `keyhist`,
so swapping `wrap_1` and `wrap_2` fails the AEAD tag.

A current member peels back `g, g-1, …, 1`, **verifying each `master_key_g` against
`mk_commit_g`** (which binds both the key and the generation `g`) from the RFP-anchored chain.
A revoked device, lacking the current key, cannot peel forward → **forward secrecy** (P11).

**Roster-key history (never trimmed).** Folding the sigchain (§8.1) requires `roster_key_g` for
**every** generation `g` present in the chain — including generations whose *data* key-history may
later be trimmed (below). To keep the roster keys derivable independently of the data key-history,
each `Rotate` also stores a tiny forward-wrap of the previous roster key:

```
k_rkh_g   = BLAKE3::derive_key("secsec-roster-keyhist-v1", roster_key_{g+1} ‖ le32(g))
(ct, T)   = ChaCha20Poly1305_raw(k_rkh_g, 0, FRAME_rkh, roster_key_g)  // FRAME_rkh: type=roster-keyhist, gen=g
ctx_tag   = BLAKE3::keyed_hash(k_rkh_g, "secsec-ctx-v1" ‖ FRAME_rkh ‖ T)
roster_keyhist_g = ctx_tag(32B) ‖ ct        // stored at /roster-keyhist/<g>; 64 bytes total
```

A current member starts from `roster_key_current` (= `derive_key(master_key_current)`) and peels
`roster_key_current → … → roster_key_1` through this chain (CTX decryption, §9.4), deriving every
`roster_key_g` needed to decrypt and signature-verify the whole sigchain from genesis (`seq 0`,
gen 1). The chain is **never trimmed**: at 64 bytes per generation, bounded by the sigchain-length
cap (§19), its total size is negligible. A revoked device lacking `roster_key_current` cannot peel
forward, so roster forward secrecy is preserved.

**Maximum data-history depth:** 256 generations of the **data** key-history `/keyhist/<g>`, which
governs readability of *old file content* only. When a rotation would exceed this depth a
`HistoryReanchor` sigchain entry is appended (see §8.1 for the full normative definition): the
oldest *data* generation is dropped and a new synthetic genesis wrap is created, signed by the
current master key. `HistoryReanchor` trims **only** the data key-history; it never affects sigchain
foldability, which relies on the never-trimmed roster-key history above. Enrolling devices need only
peel the *data* history back to the reanchor point, but always peel the roster-key history to
genesis to verify membership.

### 8.3 Keyslots — versioned, authenticated by commitment, PQ-ready

A keyslot wraps `master_key_g` to a device key. Format is `algo_id`-versioned:

- **classical (Ed25519 device key):** wrap to the device's X25519 key (Ed25519→X25519 per the
  standard birational map). HPKE base mode (RFC 9180), pinned suite
  **DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305** (RFC 9180 ciphersuite `0x0021`).
  The HPKE `info` parameter is:
  ```
  info = "secsec-keyslot-v1" ‖ canonical(device_id) ‖ le32(gen)
  ```
  This binds the keyslot ciphertext irrevocably to one device and one generation at the HPKE
  layer. The `info` value and ciphersuite are listed in the §9.6 domain-separation table.
- **classical (RSA device key):** RSA-OAEP with SHA-256 as the hash and MGF1 function. The OAEP
  label `L` is the UTF-8 string `secsec-keyslot-v1` (17 bytes); OAEP computes
  `lHash = SHA-256(b"secsec-keyslot-v1")` internally per RFC 8017 §7.1.1. The §9.6
  domain-separation table entry reads: `RSA keyslot OAEP label L = b"secsec-keyslot-v1"`
  (OAEP hash = SHA-256; MGF1 hash = SHA-256). This label provides domain separation between the
  keyslot-unwrap path and the SSHSIG signing path (which share the same RSA private key). RSA
  private key material is required on disk for OAEP unwrap; agent/FIDO cannot perform it.
- **hybrid-PQ:** wrap via **X-Wing** (§17); keyslot ciphertext = `ct_MLKEM(1088 B) ‖ ct_X(32 B)`.
  ML-KEM-768 key pairs stored exclusively in `(d, z)` seed form (§17, §8.3 note).

Authenticity does **not** rest on the wrap (a wrap-to-pubkey is forgeable by anyone): it rests on
the **`mk_commit` check** in §7 step 3. A forged keyslot decrypts to a key that fails the
commitment. (Note on key reuse: the SSH key signs *and* does ECDH; this is a deliberate,
analyzed tradeoff for the "SSH identity only" requirement — usage is domain-separated and the
Ed25519→X25519 conversion is the established one used by `age`/`ssh-to-age`.)

### 8.4 Rotation & revocation (closes "revoke is a no-op")

Against an untrusted server, `revoke` **always** rotates:
1. Append `RevokeDevice(B)`. Compute B's **transitive add-by closure** over the folded roster
   (devices B added, devices they added, …) restricted to grants after the last entry the revoking
   device authored or witnessed; append `RevokeDevice` for each device in that closure (closes the
   revoke-before-add backdoor race and its nested two-hop variant, §8.1).
2. Mint `master_key_{g+1}`, compute `mk_commit_{g+1}` = `BLAKE3::keyed_hash(master_key_{g+1},
   "secsec-mk-commit-v1" ‖ le32(g+1))`, extend the key-history chain (§8.2).
3. Append the `Rotate` entry recording `mk_commit_{g+1}`; it and every subsequent entry up to the
   next rotation are written under generation `g+1` (§9.5). (The mint in step 2 necessarily precedes
   this append, since the entry embeds `mk_commit_{g+1}`.)
4. Write fresh keyslots wrapping `master_key_{g+1}` to all remaining members; delete the revoked
   keyslot(s).
5. All new objects use generation `g+1`.

**Scope of access removal:** revocation removes access to data created *after* the rotation
(forward secrecy, P11). A revoked device that retained `master_key_g` in memory can, colluding
with the server, decrypt any gen-g ciphertext that the server still holds. Rotate-all re-encryption
(re-encrypting all existing objects as gen-g+1) is the only complete mitigation; absent it,
revocation provides forward secrecy only. See §22.

A bare `revoke` without rotate is **not offered** under this threat model.

**Concurrent mutual-revocation race (residual).** Devices are flat and equal; there is no
privileged founder. A stolen device that is unlocked, online, and actively racing can issue
`RevokeDevice(legit)+Rotate` concurrently with the user's `RevokeDevice(stolen)+Rotate`; the
`/roster-head` CAS serializes the two and whichever lands first wins, evicting the loser (whose
retry then fails succession, §8.1, because it is now revoked). A complete fix (recovery-code-gated
revocation, or a privileged device-1 key for `RevokeDevice`/`Rotate`) was considered and
deliberately **not** adopted, to preserve the flat-device model. This is an accepted residual —
full statement and mitigation in §22.

### 8.5 Counters and local sealed state (precise; closes the "one frontier" ambiguity)

Three independent monotonic counters, each signed and each with a **persisted client frontier**:
- **`head_version`** — per ref; strictly increasing; in the head signature.
- **`roster_seq`** — the sigchain sequence; strictly increasing.
- **commit `version`** — per `device_id`; clients keep per-device high-water marks; a commit with
  `version ≤` the high-water from that device is rejected as replay.
- **`per_device_head_version_hwm`** — a `Map<device_id, u64>` tracking the highest `head_version`
  observed from each peer device during merges; used by §10 gate 2 to detect sibling rollbacks
  previously observed indirectly.

**HWM update rule (normative).** After gate 2 passes and before the local merge commit is written,
the client MUST update `per_device_head_version_hwm` for the direct sibling **and** for every
device observed in the transitively reachable commit chain of the sibling (indirect observations
count). The HWM map update and the sealed frontier write MUST be atomic with respect to the local
merge commit write: seal the new frontier first; only then write the merge commit. On cold-boot
with a valid frontier, the HWM reflects only fully-sealed observations, so a partially-accepted
merge (crashed between seal and merge-commit write) is safely retried.

**Local sealed state:** all frontier data (including the above counters and per-device maps) is
stored encrypted in a local state file, sealed under a key derived solely from the device's SSH
private key — no server contact required to unseal:

```
// Ed25519 devices: derive from the private scalar (never published)
local_seal_key = BLAKE3::derive_key("secsec-local-seal-v1",
                                    device_ed25519_scalar_clamped)
// RSA devices: derive from the private key bytes
local_seal_key = BLAKE3::derive_key("secsec-local-seal-v1",
                                    SHA-256(rsa_private_key_der))
```

The `device_ed25519_scalar_clamped` is the clamped scalar from the Ed25519 private key (the
64-byte expanded seed's low 32 bytes with the standard clamping applied). This is private key
material that is never published. **Note:** `X25519(scalar, basepoint)` equals the device's
Curve25519 public key, which is derivable from the sigchain-published Ed25519 public key via the
birational map — it MUST NOT be used as the key material for `local_seal_key`. The key is
re-derived at startup from the SSH private key and never stored.

The frontier state file is encrypted with the **mutable-object AEAD of §9.8** (fresh 96-bit OS-CSPRNG
nonce per write) under `local_seal_key`, with `device_id` as the AD — no `FRAME` and no signature, as
it is local-only and unsigned:

```
nonce(12B) ‖ tag(16) ‖ ChaCha20Poly1305_ct(local_seal_key, nonce, AD=device_id, plaintext_frontiers)
```

**Cold-boot sequence (normative):**
1. Unseal local state using SSH private key → read all frontiers.
2. Connect to server; fetch chain/heads.
3. Verify server responses against persisted frontiers (§8.1 rejection conditions).

A missing, corrupted, or invalid (MAC-failing) local state file is a **lost-frontier event**:
the client MUST alarm the user prominently and treat the session as a reinstall (§22 reinstall
residual). Authenticity is not lost (RFP + `mk_commit` still verify), but freshness guarantees
do not hold until a peer confirms the current head.

### 8.6 Recovery (closes the lock-out gap, without a backdoor)

Optional, created at `init` or later:

**Preferred path — 256-bit recovery code:**
- Generate a 256-bit **recovery code** (24-word/Base32, OS CSPRNG).
- Derive `recovery_key = BLAKE3::derive_key("secsec-recovery-code-v1", salt ‖ code)` where
  `salt` is a random 16-byte value generated at keyslot-creation time via OS CSPRNG and stored
  in the recovery keyslot blob. A fresh salt is generated on each rotation re-wrap. (High
  entropy → KDF need not be slow; the 16-byte random salt prevents precomputation across
  installations.)

**Alternative path — passphrase (explicitly weaker; use only if recovery code is infeasible):**
- The 256-bit recovery code is the default and strongly preferred path. The passphrase path is
  explicitly weaker because the recovery keyslot is stored on the untrusted server and an
  exfiltratable blob with a weak passphrase can be cracked offline.
- Require passphrase ≥ 6 words or ≥ 20 characters. Estimate entropy via `zxcvbn` or equivalent;
  reject inputs below ~50 bits with an explicit error. Display a prominent warning that this path
  is weaker and re-require user confirmation before proceeding.
- Derive `recovery_key = Argon2id(passphrase, salt=random_16B, m=64 MiB, t=3, p=1, len=32)`
  (see §19 for rationale). The 16-byte salt is generated at keyslot-creation time via OS CSPRNG
  and stored in the recovery keyslot blob. A fresh salt is generated on each rotation re-wrap.
  The m=64 MiB, t=3, p=1 floor is calibrated for offline-attack resistance (RFC 9106 second
  recommended / OWASP high-security), not interactive-login DoS tradeoff.

**Recovery keyslot construction (both paths):**
- Compute `k_recovery = recovery_key` (as derived above).
- Apply the §9.4 CTX construction directly:
  ```
  AD_recovery         = "secsec-recovery-v1" ‖ device_pubkey ‖ le32(gen)
  nonce               = 0   // safe: k_recovery is unique per passphrase+salt
  (ct_recov, T)       = ChaCha20Poly1305_raw(k_recovery, nonce, AD_recovery,
                                              master_key_current_gen)
                        // T is the raw 16-byte Poly1305 tag
  ctx_tag_recov       = BLAKE3::keyed_hash(k_recovery,
                        "secsec-ctx-v1" ‖ AD_recovery ‖ T)
                        // 32-byte CTX tag; binds K, N, A, and M (via T) → CMT-4
  recovery_keyslot    = AD_recovery ‖ salt(16B) ‖ ctx_tag_recov ‖ ct_recov
                        // no separate raw tag stored; ctx_tag_recov replaces it
  ```
  The `device_pubkey` and `gen` in `AD_recovery` bind the keyslot to a specific device and
  generation; the server cannot swap recovery keyslots across users or generations. The CTX
  construction (§9.4) achieves CMT-4: `T` in the hash binds the plaintext `M`, closing
  partitioning-oracle attacks. Decryption: re-derive `k_recovery`; evaluate Poly1305 over
  `(AD_recovery, ct_recov)` to obtain `T_cand`; compute expected `ctx_tag_recov` =
  `BLAKE3::keyed_hash(k_recovery, "secsec-ctx-v1" ‖ AD_recovery ‖ T_cand)`; constant-time
  compare `stored_ctx_tag_recov == expected_ctx_tag_recov`; only if this passes, apply the
  ChaCha20 keystream to `ct_recov` to obtain the master key. T is not stored in the blob and
  MUST NOT be looked up there — it is always recomputed via Poly1305 over `(AD, ct)`.

**Recover:** the user keeps `{recovery_code, RFP}` (printed). Derive `recovery_key` →
apply the §9.4 decryption → candidate master key → **verify against `mk_commit_g`** in the
RFP-anchored chain → re-enroll a fresh device. The server cannot forge this (it lacks the code;
the commitment blocks fake keys) → **recovery is not a server-exploitable backdoor**.

**Optional Shamir split of the recovery code:** use **SSKR** (Sharded Secret Key Reconstruction,
Blockchain Commons) or **SLIP-39** as the normative Shamir implementation. Minimum useful
configuration: k-of-n where k ≥ 2 and n ≤ 5. Each share is encoded as a word list per the
chosen scheme's standard encoding. Authentication: each recovered candidate secret MUST be
verified against `mk_commit_g` from the RFP-anchored chain before accepting — this closes
silent-wrong-share attacks that would otherwise produce a wrong master key only detectable at
commitment verification. Implementors MUST NOT write bespoke GF arithmetic; use a vetted
library implementation of SSKR or SLIP-39.

---
## 9. Cryptography

### 9.1 Object framing & agility

```
FRAME = MAGIC(4) ‖ format_version(u8) ‖ algo_id(u8) ‖ gen(u32) ‖ type(u8)
blob  = FRAME ‖ ctx_tag(32) ‖ ciphertext
```

`format_version`/`algo_id` make every primitive replaceable (§16–17). Decoders enforce hard
limits **before allocation**: max object size (16 MiB), max tree depth (64 levels), max tree
fan-out (65,536 entries per node), max roster entry size (4 KiB), max list fields (4,096
elements) — defeating alloc/recursion/decompression bombs. See §19 for normative values. The
client derives keys from the **expected** `(gen, type)` and rejects any blob whose FRAME
disagrees (no trusting attacker-set type).

### 9.2 Content addressing (verified on every fetch)

```
id = BLAKE3::keyed_hash(id_key[gen][type], FRAME ‖ path_salt ‖ plaintext)   // 256-bit
```

`path_salt` is a per-path random 16-byte salt generated at first-sync time. Each tree's `path_salt`
is stored inside its **parent** tree blob; the **root** tree's `path_salt` is stored in the commit
object that references it. Objects outside the path hierarchy — commits, heads, and sigchain
entries — use a fixed empty `path_salt` (their addresses are already unique by content and they are
separately signed). On fetch the client re-derives `id` from the decrypted plaintext and
**constant-time** compares to the requested id. Substitution is caught three ways: id re-hash,
AEAD tag (id ∈ AD), CTX tag.

### 9.3 Canonical serialization (normative)

All hashed/signed/addressed structures use a single deterministic encoding: strict
length-prefixed canonical form (definite lengths, fixed field order, minimal integer encoding, no
floats, no duplicate keys). Two encoders must produce identical bytes or it is a bug; ids and
signatures depend on it. (`postcard` with a canonical profile, or canonical CBOR.)

### 9.4 Per-object key + committing AEAD (CTX construction — CMT-4)

The scheme achieves **CMT-4** (fully committing: binds K, N, A, and M) via the CTX construction
(Chan & Rogaway, ESORICS 2022). The raw Poly1305 tag `T` is fed into the commitment hash,
binding the plaintext M; the stored `ctx_tag` replaces both the separate `key_commit` field and
the raw 16-byte Poly1305 tag. `T` is **not stored** in the blob.

```
k_obj   = BLAKE3::derive_key("secsec-obj-key-v1", enc_key[gen][type] ‖ id)
nonce   = 0                              // safe: k_obj is unique per object
AD      = FRAME ‖ id
ct, T   = ChaCha20Poly1305_raw(k_obj, nonce, AD, plaintext)
              // T is the raw 16-byte Poly1305 tag; NOT stored in the blob
ctx_tag = BLAKE3::keyed_hash(k_obj, "secsec-ctx-v1" ‖ AD ‖ T)
              // 32-byte CTX tag; replaces both key_commit and raw T in the blob
blob    = FRAME ‖ ctx_tag(32) ‖ ct
```

**Decryption (three explicit phases; T is never stored and must be recomputed):**

1. **MAC evaluation:** using `k_obj` and `nonce=0`, evaluate the Poly1305 MAC over `(AD, ct)`
   to obtain `T_cand`. This is MAC computation only — no plaintext is produced at this step.
   (Block 0 of the ChaCha20 keystream generates the Poly1305 key; this is the same invocation
   reused in Phase 3.)
2. **Commit verify:** constant-time compare
   `stored_ctx_tag == BLAKE3::keyed_hash(k_obj, "secsec-ctx-v1" ‖ AD ‖ T_cand)`.
   If this check fails, reject the blob immediately.
3. **Decrypt:** only if Phase 2 passes, apply the ChaCha20 keystream (blocks 1+) to `ct` to
   obtain plaintext.

There is no "embedded T" in the stored blob; an implementation MUST NOT look for a stored T
or pass `ctx_tag` to `ChaCha20Poly1305_open` as the MAC tag.

- **Unique key per object** ⇒ nonce reuse impossible by construction.
- **CTX tag** binds K, N (=0, trivially), A (FRAME‖id), and M (via T), closing partitioning-oracle
  / "invisible-salamander" attacks across the multi-generation, multi-recipient surface. Verified
  constant-time before the AEAD open. This is the same tag-replacement approach recommended in
  the CTX paper — no ciphertext expansion.
- Determinism preserves dedup (same plaintext+gen+type → same id → same ct).

### 9.5 Key derivation hierarchy (normative)

All subkeys are derived from `master_key_g` using `BLAKE3::derive_key` (IKM role) with distinct
context strings and fixed-width encodings of `gen` and `type`. Let `g` be a `u32` encoded as
little-endian 4 bytes (`le32(g)`), and `t` be the `type` byte (`u8(t)`).

```
enc_key[g][t]  = BLAKE3::derive_key("secsec-enc-key-v1",
                                     master_key_g ‖ le32(g) ‖ u8(t))
id_key[g][t]   = BLAKE3::derive_key("secsec-id-key-v1",
                                     master_key_g ‖ le32(g) ‖ u8(t))
cdc_seed[g]    = BLAKE3::derive_key("secsec-cdc-seed-v1",
                                     master_key_g ‖ le32(g))
head_key_g     = BLAKE3::derive_key("secsec-head-enc-v1",
                                     master_key_g ‖ le32(g))   // mutable head-blob key (§9.8)
roster_key_g   = BLAKE3::derive_key("secsec-roster-enc-v1", master_key_g)   // one per generation g
ref_name_key   = BLAKE3::derive_key("secsec-ref-name-v1",  master_key_g)

// Roster entry per-sequence subkey (g = generation under which entry[seq] was written):
k_roster_entry[g][seq] = BLAKE3::derive_key("secsec-roster-entry-v1",
                                            roster_key_g ‖ le64(seq))

// Roster-key history forward-wrap key (§8.2):
k_rkh_g        = BLAKE3::derive_key("secsec-roster-keyhist-v1",
                                     roster_key_{g+1} ‖ le32(g))

// Commitment (keyed_hash exception — see note):
mk_commit_g    = BLAKE3::keyed_hash(master_key_g,
                                     "secsec-mk-commit-v1" ‖ le32(g))
```

Distinct context strings prevent `enc_key[g][t] == id_key[g][t]` for any `(g, t)`. Fixed-width
`le32(g) ‖ u8(t)` encodings prevent `enc_key[1][CHUNK]` from equalling `enc_key[2][TREE]`
(collision via variable-length concatenation). `BLAKE3::derive_key` places the context string
as the KDF key and the key material as the message, keeping the high-entropy input (`master_key_g`,
`roster_key_g`, or `roster_key_{g+1}`) in the IKM role **for all eight `derive_key` derivations
listed above**.

> **Note:** `mk_commit_g` uses `BLAKE3::keyed_hash(master_key_g, ...)` — placing `master_key_g`
> in the BLAKE3 PRF **key** role rather than the IKM/message role. This is the **only** place
> where `master_key_g` serves as a BLAKE3 key argument; the two uses are domain-separated by
> BLAKE3's internal API distinction. Implementors MUST NOT substitute `BLAKE3::derive_key` here.

**Test vectors must be provided in the implementation for all nine derivations** (the eight
`derive_key` derivations plus the `mk_commit_g` `keyed_hash`).

`roster_key_g` (= `derive_key("secsec-roster-enc-v1", master_key_g)`, **one per generation**)
encrypts the sigchain entries written under generation `g` so the server cannot read them.

**Roster entry AEAD (normative).** Each sigchain entry is encrypted under a per-entry subkey
derived from the **generation-indexed** roster key and the entry's sequence number. `FRAME_roster`
carries the generation `g` under which the entry was written:

```
k_roster_entry[g][seq] = BLAKE3::derive_key("secsec-roster-entry-v1",
                                            roster_key_g ‖ le64(seq))
nonce               = 0       // safe: k_roster_entry[g][seq] unique per (roster_key_g, seq)
AD_roster           = FRAME_roster   // includes type=roster, gen=le32(g), le64(seq)
ct_roster, T_roster = ChaCha20Poly1305_raw(k_roster_entry[g][seq], 0, AD_roster, entry_plaintext)
ctx_tag_roster      = BLAKE3::keyed_hash(k_roster_entry[g][seq],
                                          "secsec-ctx-v1" ‖ AD_roster ‖ T_roster)
stored_entry        = ctx_tag_roster(32) ‖ ct_roster
```

Decryption follows the same three-phase procedure as §9.4 (MAC evaluation → commit verify →
decrypt). This construction achieves CMT-4 for roster entries, closing the partitioning-oracle
surface over membership and revocation records.

**Decrypting across generations (normative).** A sigchain spans every generation up to the current
one, and folding it (§8.1) requires reading **all** entries from genesis. To decrypt an entry
written under generation `g`, a current member peels the key-history chain (§8.2) to recover
`master_key_g`, derives `roster_key_g`, then `k_roster_entry[g][seq]`. The generation `g` is taken
from `FRAME_roster.gen`, which is authenticated by the AEAD AD and cannot be altered by the server.
Genesis (`seq 0`) is written under generation 1. A `Rotate` entry is written under the generation
it **creates** (`g+1`): it records `mk_commit_{g+1}`, so `master_key_{g+1}` — hence
`roster_key_{g+1}` — must already be minted when the entry is sealed. Every entry from a `Rotate`
(inclusive) up to the next `Rotate` is written under that generation. Consequently the sigchain
tip's plaintext `FRAME.gen` always equals the current generation `g_cur` — the invariant the
cold-start fold (§8.1 step 1) reads to learn `g_cur`.

### 9.6 Signatures & domain separation

Every signature is an SSHSIG with a **disjoint namespace**; the client never signs server-supplied
bytes raw. Algorithm pinned to `ssh-ed25519` (or `rsa-sha2-512` for RSA) — no alg downgrade.
**The verifier MUST reject any SSHSIG blob in which the `sig_algorithm` field is not exactly
`ssh-ed25519` (for Ed25519 keys) or `rsa-sha2-512` (for RSA keys). Any other algorithm field —
including `rsa-sha2-256` — MUST cause verification failure regardless of cryptographic validity.**

| Purpose | Namespace | Message |
|---|---|---|
| Connection auth | `secsec-auth-v1` | `channel_binding ‖ host_id ‖ session_transcript ‖ server_nonce` |
| Write authorization | `secsec-write-v1` | `op ‖ args_hash ‖ session_transcript ‖ server_nonce` |
| Read authorization | `secsec-read-v1` | `op ‖ args_hash ‖ session_transcript` (`args_hash = BLAKE3(canonical(op ‖ ids))`) |
| Commit | `secsec-commit-v1` | canonical commit |
| Head update | `secsec-head-v1` | `ref ‖ commit_id ‖ head_version ‖ roster_seq ‖ prev_head` |
| Roster entry | `secsec-roster-v1` | canonical sigchain entry |
| Grant attestation | `secsec-grant-v1` | `device_pubkey ‖ mk_commit_g ‖ roster_seq ‖ enrollment_nonce` |
| RSA keyslot OAEP label | L = `b"secsec-keyslot-v1"` (OAEP hash = SHA-256; MGF1 hash = SHA-256) | (OAEP label parameter, not an SSHSIG; OAEP computes `lHash = SHA-256(b"secsec-keyslot-v1")` internally per RFC 8017) |

**Connection auth field order (canonical):** `channel_binding ‖ host_id ‖ session_transcript ‖
server_nonce`. In stdio mode `channel_binding = H` (the SSH exchange hash, RFC 4252 §7). This
order is normative; §11 cross-references this table rather than defining a separate formula.

`secsec-read-v1` provides per-op authorization for `get` and `has`: `args_hash` binds the exact
object IDs requested; `session_transcript` provides per-connection freshness without requiring
a server-supplied nonce.

`secsec-grant-v1` includes `enrollment_nonce` (32 bytes, OS CSPRNG, generated fresh by E at grant
time). E transmits the nonce to D **directly over the grant channel** (§7 step 5); D records it and,
at enrollment (§7 step 4), checks the server-fetched attestation covers exactly that
directly-received value. Anchoring the reference nonce to the out-of-band channel — not to the
server-supplied attestation — is what makes the attestation single-session and non-replayable.

Server-chosen nonces appear **only** in `auth`/`write`. A signature for one purpose is
cryptographically invalid for any other → the "server sets the challenge to `H(commit)`" forgery
is impossible.

**Revocation scope.** A revoked device cannot authenticate new connections once its keyslot is
deleted (cooperative server) or obtain new-generation master keys (malicious server — bounded by
the gen-g residual, §22). Whether a device with an already-open connection can continue issuing
reads until reconnect depends on whether the server re-verifies keyslot existence per-op; see
§12 for the normative server re-check requirement.

### 9.7 Chunking, dedup leakage & padding

- **Keyed FastCDC (default):** the gear/rolling-hash is seeded from `cdc_seed[gen]` so chunk
  boundaries are repo-specific → cross-repo size-fingerprint DBs do not apply.
  **Limitation:** keyed CDC's boundary-privacy is not maintained against an adversary who can
  cause the victim to archive chosen-plaintext data. Alexeev et al. (ePrint 2025/532) demonstrate
  that observed chunk boundaries can be used to algebraically recover the secret gear-table key
  under a chosen-plaintext archive attack. Once `cdc_seed` is recovered, the attacker can compute
  expected chunk ids for any known plaintext, defeating per-file salting for past data. Mitigation:
  `cdc_seed` is generation-scoped (rotated with each master-key rotation), so past boundary
  observations do not apply to future data; default-on object-size padding (below) eliminates the
  boundary signal required for key extraction; see §22.
- **Padding:** size-bucket padding is **on by default for metadata objects** (trees/commits/roster
  — small, cheap) and **on by default for chunk objects**. The default chunk policy pads each
  chunk to the next power-of-two size ≥ its size (reversible ISO/IEC 7816-4 bit padding), a bounded
  ≤2× overhead that blurs sizes into power-of-two buckets. This **substantially reduces — but does
  not fully eliminate** — the boundary-sequence signal (the bucket sequence still leaks coarse
  sizes). **Full elimination** requires the **uniform** policy (pad all chunks to one fixed size),
  available opt-in at higher space cost. Padding can also be turned **off** (opt-out; space/dedup
  over privacy). See §19 for the normative policy values.
- **Per-path random salt (default-on):** each path mixes a `path_salt` (16-byte random, per-path,
  generated at first sync and stored encrypted in the tree blob) into id derivation (§9.2):
  `id = BLAKE3::keyed_hash(id_key[gen][type], FRAME ‖ path_salt ‖ plaintext)`. This disables
  the **cross-session confirmation oracle** (a third party cannot confirm whether a known plaintext
  has been synced to a path without knowing the path's salt). **Opt-out** (convergent/dedup mode)
  is available for users who explicitly want cross-device dedup; enabling it re-exposes the
  confirmation oracle and must be acknowledged.
- **Intra-file temporal equality (all modes):** in default mode the `path_salt` is constant across
  all versions of a file. When a file is modified, unchanged chunks yield the same id across
  versions (same `path_salt`, same plaintext, same `gen`, same `type`). The server observes
  idempotent `put()` behavior per sync — precisely which chunk IDs are new uploads vs. already
  stored — revealing the chunk-level edit distance for each modified file without reading any
  ciphertext. This leak is present **in all modes**, not only convergent mode. Eliminating it
  would require a per-version salt, which disables intra-file dedup entirely; this is a documented
  tradeoff.
- Residual leaks (sizes within padding bounds, timing, intra-file temporal equality, intra-repo
  equality in convergent mode) are bounded and documented (§22).

### 9.8 Mutable-object AEAD (fresh-nonce) — heads & local sealed state

The committing AEAD of §9.4 relies on a **unique key per object** (so `nonce=0` is safe) and applies
only to **immutable, content-addressed** objects. Two objects are **mutable** — re-encrypted in
place under a *stable* key — so they MUST NOT use §9.4's fixed nonce (that would be catastrophic
nonce reuse). They instead use a **fresh random nonce per write**: the per-ref **Head** (§6, §13)
and the **local sealed state** (§8.5).

```
nonce          = 96-bit OS CSPRNG, fresh on EVERY write     // never a counter; reuse is fatal
ct, tag        = ChaCha20Poly1305(key, nonce, AD, plaintext)  // standard RFC 8439 AEAD; raw 16-byte tag
blob           = [FRAME] ‖ nonce(12) ‖ tag(16) ‖ ct          // FRAME present for server-stored heads
```

A fresh nonce per write makes keystream reuse impossible even though `key` is reused across updates,
so this construction does not need §9.4's per-object-unique key. It is deliberately **not**
key-committing (CMT): unnecessary here, because the key is a single high-entropy, master-key-derived
value (no multi-key / low-entropy partitioning-oracle surface, unlike keyslots/recovery), and
authenticity against other devices and the server rests on the object's **signature**, not the
symmetric tag.

**Head blob (normative).** Stored at `/refs/<H>`, `H = BLAKE3::keyed_hash(ref_name_key, ref_name)`
(§13). The head is **both signed and encrypted**:

```
sig        = SSHSIG("secsec-head-v1",                                  // §9.6
                    ref_name ‖ commit_id ‖ head_version ‖ roster_seq ‖ prev_head)
plaintext  = canonical(ref_name, commit_id, head_version, roster_seq, prev_head, sig)
key        = head_key_g = BLAKE3::derive_key("secsec-head-enc-v1", master_key_g ‖ le32(g))   // §9.5
AD         = FRAME ‖ H        // FRAME: type=Head, gen=g; binds the blob to its ref slot
head_blob  = FRAME(11) ‖ nonce(12) ‖ tag(16) ‖ ct
```

The **signature** (verified against the RFP-anchored roster, §8) is what prevents the server or a
non-member from forging or substituting a head; the AEAD hides the ref→commit linkage and the
counters from the server and binds the blob to its ref slot via `H`. `head_version` (per ref,
strictly increasing, §8.5) is covered by the signature and checked against the client's persisted
frontier and `per_device_head_version_hwm` (§8.5, §10) — replay/rollback of an old head is caught
there, not by the AEAD. The generation `g` is read from the plaintext `FRAME.gen`; a current member
already holds (or peels, §8.2) the `master_key_g` needed for `head_key_g`.

The §8.5 local sealed-state blob uses this same construction with `key = local_seal_key` and
`AD = device_id` (no `FRAME`, no signature — it is local-only and unsigned).

---
## 10. Sync semantics

- **Commit on change:** snapshot → commit (strictly increasing per-device `version`, current
  `roster_seq`, `last_seen_head`) → sign → advance the per-ref head via `cas-head`.
- **Rollback-aware merge** (closes replay-into-merge): before merging a server-presented sibling
  the client checks:
  (1) `roster_seq` from the sibling ≥ the client's persisted `roster_seq` frontier. This guards
      against branches that predate known roster state, not against sibling branch rollbacks observed
      indirectly (see gate 2).
  (2) Each merged commit's per-device `version` exceeds that device's high-water (`commit.version`
      high-water mark), AND the sibling device's `head_version` ≥ `per_device_head_version_hwm[device_id]`
      (the highest `head_version` this client has previously observed from that device, including
      via indirect merges). This is the actual defense against sibling rollbacks.
      **HWM update rule (normative):** After gate 2 passes and before the local merge commit is
      written, the client MUST update `per_device_head_version_hwm` for the direct sibling AND for
      every device observed in the transitively reachable commit chain of the sibling (indirect
      observations count). The HWM map update and the sealed frontier write MUST be atomic with
      respect to the local merge commit write: the client MUST seal the new frontier first; only
      then write the merge commit. On cold-boot with a valid frontier, the HWM reflects only
      fully-sealed observations, so a partially-accepted merge (crash before frontier seal) is
      retried from scratch — gate 2 will re-check against the last sealed HWM values.
  (3) The sibling is genuinely DAG-incomparable.
  Then a **per-path three-way merge** vs the common ancestor. **When the common ancestor is
  unavailable from all reachable remotes** (e.g., a malicious remote withholds it): the client
  MUST attempt all reachable remotes; if a required ancestor object is found on any remote and
  passes §9.2 id-verification, use it regardless of which remote provided it. If the ancestor
  remains unavailable after trying all remotes, treat every conflicting path as a **keep-both
  conflict** (safe default — no data loss). Document this fallback prominently in the user-facing
  conflict log.
  One-sided change → take; identical change → take; divergent → **conflict** (keep-both,
  `name.conflict-<device>-<commit_id_hex12>.ext` where `<commit_id_hex12>` is the first 12
  lowercase hex characters of the conflicting commit's BLAKE3 content-address (§9.2), globally
  unique by construction; if a human-readable timestamp is also desired for UX it MAY be appended
  as a non-primary suffix but MUST NOT be part of the uniqueness-bearing stem, surfaced).
  Timestamps are hints, never trusted for security.
- **Fork detection:** commits embed `last_seen_head`; once any two devices exchange one commit a
  fork is provable and alarmed. **Normative algorithm:** when the client receives a commit C_B
  with `last_seen_head = H_B`:
  (1) If H_B is known to the client and H_B is not an ancestor of the client's current head H_A,
      and H_A is not an ancestor of H_B (DAG-incomparable heads), the client MUST alarm the user,
      presenting both head IDs and refusing to auto-merge until the user acknowledges.
  (2) If H_B is unknown, the client MUST record H_B as an unresolved reference and attempt to
      fetch it from all configured remotes. If the fetch succeeds and condition (1) holds, alarm
      as above.
  (3) The tuple (H_A, H_B, C_B.device_id, wall-clock timestamp of detection) MUST be persisted
      in the local event log for user review regardless of whether the user has yet acknowledged.
  **Gossip** of head hashes (default-on when devices can reach each other, and via multi-remote
  cross-check, §14) shrinks the detection window.
- **Live trigger:** `notify` (inotify/FSEvents/ReadDirectoryChangesW) drives commit-on-change;
  periodic commits set the snapshot cadence.

---
## 11. Transport & authentication

- **QUIC + TLS 1.3** (`quinn`+`rustls`), udp/8899 (overridable). Fixed ciphersuites (ChaCha20-
  Poly1305 / AES-256-GCM) and X25519 KX — **no negotiation/downgrade**.
- **No managed certs:** the server self-signs a host key on first run (like `sshd`). The client
  **pins** it (TOFU). `init --host-fp SHA256:…` pre-seeds the pin. When `--host-fp` is absent at
  `init`, the client MUST display the fingerprint and require an explicit interactive y/N
  confirmation — the prompt MUST state that this is a one-time verification and that the user
  should independently verify the fingerprint out-of-band. Accepting without confirmation is NOT
  permitted. (Residual: §22 TOFU first-init window — a network attacker present at init without
  `--host-fp` can substitute their host key; always use `--host-fp`.)
- **host_id definition:** `host_id = BLAKE3(canonical(server pinned SPKI bytes))` (QUIC mode).
  In stdio mode, `host_id = BLAKE3(canonical(K_S))` where `K_S` is the server host key
  extracted from the SSH exchange hash `H` (RFC 4253 §8). `host_id` MUST be computed by the
  client from locally-pinned material and MUST NOT be accepted from the server.
- **Verifier (the top ship-broken risk):** the custom `rustls` `ServerCertVerifier` MUST compare
  leaf SPKI to the pin **and** fully implement `verify_tls13_signature` (never stub). Mandatory
  negative tests: wrong key fails; tampered handshake fails. Additionally, the verifier MUST
  reject any SSHSIG blob in which the `sig_algorithm` field is not exactly `ssh-ed25519` (for
  Ed25519 keys) or `rsa-sha2-512` (for RSA keys). Any other algorithm field — including
  `rsa-sha2-256` — MUST cause verification failure regardless of cryptographic validity. This is
  a mandatory negative test: a valid `rsa-sha2-256` signature MUST fail verification.
- **Session transcript:** both ends maintain `session_transcript` = running BLAKE3 over the
  ordered, length-prefixed handshake messages, defined byte-exactly per mode below. Binds the
  whole exchange against splicing/downgrade in **both** modes.
  - **stdio-mode session_transcript initialization:** In stdio mode, the `session_transcript`
    hasher MUST be initialized by feeding `H` (the SSH exchange hash, RFC 4252 §7) as its first
    length-prefixed input. Following `H`, the application-layer handshake messages are fed in
    this fixed order:
    1. Client hello: `secsec_version: u16 ‖ client_nonce: [u8; 32]` where `client_nonce` is
       drawn from the OS CSPRNG. Length-prefix: `le32(2 + 32)`.
    2. Server hello: `secsec_version: u16 ‖ server_nonce: [u8; 32] ‖ host_id: [u8; 32]`.
       Length-prefix: `le32(2 + 32 + 32)`.
    Both client and server maintain identical running hashers over these inputs in this order.
    `H` as the first input makes the transcript session-specific to the SSH channel even if
    application-level nonces collide. This ensures all per-op signatures (`secsec-write-v1` and
    `secsec-read-v1`) that include `session_transcript` are transitively bound to the SSH host
    key and session.
  - **QUIC-mode session_transcript:** byte-exact, mirroring the stdio handshake but without `H`
    (channel binding is the TLS exporter, defined under *Client→server auth* below). The hasher is
    fed, in this fixed order:
    1. Client hello: `secsec_version: u16 ‖ client_nonce: [u8; 32]` (OS CSPRNG). Length-prefix
       `le32(2 + 32)`.
    2. Server hello: `secsec_version: u16 ‖ server_nonce: [u8; 32] ‖ host_id: [u8; 32]`.
       Length-prefix `le32(2 + 32 + 32)`.
    No other inputs are hashed; raw "pubkeys" are NOT injected — the server identity is bound via
    `host_id` and the channel via the TLS exporter. The client-contributed `client_nonce` ensures
    transcript uniqueness is not solely under server control.
- **Client→server auth:** the client signs (`secsec-auth-v1`) the canonical payload defined in
  §9.6: `channel_binding ‖ host_id ‖ session_transcript ‖ server_nonce`. In stdio mode
  `channel_binding = H`; in QUIC mode `channel_binding` is the TLS exporter value below. The
  signed payload field order is authoritative in §9.6; this section cross-references it.
  - **QUIC mode:** `channel_binding` = TLS 1.3 keying material exporter computed via
    `quinn`/`rustls`'s `exported_keying_material` API: `HKDF-Expand-Label(exporter_master_secret,
    "EXPORTER-Channel-Binding", "", 32)` per RFC 9266 §3 / RFC 8446 §7.5. Note: RFC 9266 does not
    formally define `tls-exporter` for QUIC transports (an acknowledged open gap); this usage is
    intentional and documented here. The `session_transcript` provides an additional application-
    layer binding; both are included.
  - **stdio mode:** `channel_binding` = the SSH exchange hash `H` extracted from `russh`'s
    `session_id()` API (ref: RFC 4252 §7). `H` covers `V_C ‖ V_S ‖ I_C ‖ I_S ‖ K_S ‖ e ‖ f ‖ K`
    and is cryptographically bound to the server's host key and the specific SSH session. Including
    `H` prevents a relay in the stdio pipe (compromised sshd, ProxyJump, middlebox) from forwarding
    the auth blob to a different SSH session. The claim "we do not depend on an SSH session id" is
    **removed**; the subsystem CAN obtain `H` via the embedded `russh` library and MUST do so.
  - `server_nonce` is fresh & single-use. The server verifies against a **keyslot-owning** pubkey
    and checks nonce freshness. The server MUST also verify that all subsequent per-op signatures
    on the connection are signed by the same public key that completed the `secsec-auth-v1`
    challenge; a per-op signature from a different key MUST be rejected.
- **put() declared size:** The `put()` request frame MUST include a `declared_size: u32` field
  immediately preceding the blob bytes. The server MUST reject any `put()` with
  `declared_size > 16 MiB` before reading the body. `declared_size` is included in the
  `secsec-write-v1` args hash: `args_hash = BLAKE3(canonical("put" ‖ id ‖ le32(declared_size)))`.
- **DoS hardening:** QUIC Retry/address-validation (anti-amplification); request bodies accepted
  only **after** the write-auth check; per-key storage quotas; connection rate limits; bounded
  object sizes. (Values §19.)

---

## 12. Server API

| Call | Auth | Purpose |
|---|---|---|
| `auth` | — establishes identity | SSHSIG challenge/response (§11) |
| `get(id)` | **`secsec-read-v1` sig** per op | fetch an object blob (ciphertext) from `/objects/<id>` |
| `get-ref(ref_H)` | **`secsec-read-v1` sig** per op | fetch the current head blob at `/refs/<H>` (§13); the server returns the opaque §9.8 head ciphertext (or absent) and never learns the ref name behind `H`. Required to read heads for sync (§10, §14) |
| `has(ids)` | **`secsec-read-v1` sig** per op | existence check (dedup); max 1,024 IDs per call |
| `put(blob)` | **`secsec-write-v1` sig** | store an object, idempotent by id |
| `cas-head(old,new,sig)` | **`secsec-write-v1` sig** + valid `secsec-head` | atomic ref CAS |
| `roster-append(entry)` | **`secsec-write-v1` sig** + valid `secsec-roster` | grant/revoke/rotate/min-algo |
| `gc(keep-set,gen)` | **`secsec-write-v1` sig** | client-driven sweep (§15); max 100,000 IDs per keep-set |

**Every repo operation — including reads — requires a per-op signature from a key that owns a
keyslot** (i.e., a rostered device). `get`, `get-ref`, and `has` each require a fresh
`secsec-read-v1` signature covering exactly the requested IDs (for `get-ref`, the ref hash `H`,
bound as a single-id read: `args_hash = BLAKE3(canonical("get-ref" ‖ H))`); connection-level auth
alone is not sufficient.
`has(ids)` MUST reject requests with more than 1,024 IDs; the client batches larger check sets
into sequential calls. The server returns a `too-many-ids` error before performing any lookups.
`gc(keep-set, gen)` MUST reject requests with keep-sets exceeding 100,000 IDs; for repos with
more live objects the client performs GC in generation-bounded batches.

**Keyslot-existence enforcement (normative).** The server MUST verify, on every per-op request
(including `get`, `get-ref`, `has`, `put`, `cas-head`, `roster-append`, `gc`), that a keyslot blob exists at
`/keyslots/<device_id>/<any_g>` where `device_id = BLAKE3(canonical(authenticated_pubkey))` from
the connection auth step. A request from a key with no stored keyslot MUST be rejected with a
distinct `not-enrolled` error code before any read or write is performed. This check uses
filesystem presence only and does not require decrypting the sigchain. The server MUST also verify
that per-op signatures are signed by the same public key that completed the `secsec-auth-v1`
challenge on the current connection.

The server SHOULD re-verify keyslot existence on each per-op request and MUST do so at least once
per `server_nonce` TTL window (60 s, §19), closing the open-connection gap on cooperative
deployments. (A revoked device cannot authenticate new connections once its keyslot is deleted on
a cooperative server, or obtain new-generation master keys on a malicious server — bounded by the
gen-g residual, §22.)

The `authorized_keys` allow-list is only a cheap connection gate; a key in it but not granted
can open a socket and do nothing else. A server-injected key cannot read or write: it owns no
keyslot, and the server cannot mint a *valid* (commitment-matching) one. The write `args_hash`
binds the exact blob/op (the client constructs op/args; the server supplies only the nonce).

**`put()` declared size (normative).** The `put()` request frame MUST include a `declared_size`
field (`u32`) preceding the blob bytes. The server MUST reject any `put()` with
`declared_size > 16 MiB` before reading the body. `declared_size` is included in the
`secsec-write-v1` args hash:

```
args_hash = BLAKE3(canonical("put" ‖ id ‖ le32(declared_size)))
```

**Write-op `args_hash` (normative).** Every mutating RPC carries a `secsec-write-v1` signature over
`op ‖ args_hash ‖ session_transcript ‖ server_nonce` (§9.6); the client constructs `op`/`args` and
the server supplies only `server_nonce`. The `args_hash` per op is:
- `put`: `BLAKE3(canonical("put" ‖ id ‖ le32(declared_size)))`
- `cas-head`: `BLAKE3(canonical("cas-head" ‖ ref_H ‖ old_head_id ‖ new_head_id))`
- `roster-append`: `BLAKE3(canonical("roster-append" ‖ BLAKE3(canonical(entry))))`
- `gc`: the GC serialization hash defined in §15.

**`cas-head` head-id semantics (normative).** Because the server is **blind** it cannot read the
encrypted head blob, so the compare-and-swap operates on a *server-computable* token: `old_head_id`
and `new_head_id` are `BLAKE3` over the respective **stored head-blob bytes** (the §9.8 ciphertext as
written to `/refs/<H>`), **not** the client-side plaintext head identity of §6/§10. The server
atomically: computes `BLAKE3(current stored blob)` (or the all-zero sentinel if the ref is absent),
requires it to equal `old_head_id`, requires the attached new blob to hash to `new_head_id`, and only
then replaces the ref. A first write uses the all-zero `old_head_id` ("expect absent"). The client
holds both blobs (it sealed the new one and fetched the old), so both tokens are client-computable
too; this is purely a concurrency guard — the head's *authenticity* still rests on its `secsec-head-v1`
signature inside the blob (§9.8), verified by readers against the roster.

**Per-key storage quota and rate limits** (normative — server MUST enforce):
- Per-key storage quota: 10 GiB default (configurable).
- Per-key write rate: 100 MB/s sustained, burst 1 GiB.
- Per-key read rate: 200 MB/s sustained.
- Connection rate: 10 new connections/s per source IP; 3 concurrent connections per authenticated key.
- `gc()` rate: 4 calls per key per hour; the server MUST reject excess calls with a `rate-limit` error before performing any object scan.

These limits are checked after auth and before object storage. See §19.

---
## 13. Storage layout

**Server** (all opaque):
```
/objects/<id>            packed encrypted blobs (chunk/tree/commit)
/keyslots/<device_id>/<g> versioned authenticated keyslots per device per generation
/refs/<H>                each device's signed head; H = BLAKE3::keyed_hash(ref_name_key, ref_name)
/roster-head             CAS-guarded sigchain tip
/roster/<seq>            encrypted, signed sigchain entries
/keyhist/<g>             data key-history wraps (§8.2)
/roster-keyhist/<g>      roster-key history wraps (§8.2; never trimmed)
/recovery                optional recovery keyslot including 16-byte Argon2id salt (§8.6)
/hostkey                 server self-signed host identity (first run)
```

The generation component `g` is a **plaintext integer**. Opaquing it (deriving the path component
from a secret) was considered and **rejected** as unbuildable here: the server API has no `list`
operation (§12), so a device must *compute* the exact path of every object it fetches — including,
on a fresh reinstall, its own keyslot and the key-history chain it has **not yet decrypted**. A
secret-derived path component would have to come from a key the device does not yet hold (the very
key it is fetching) — a circular dependency — or be distributed out-of-band, adding a second anchor
beside RFP. Plaintext `g` avoids both. The resulting leak (master-key rotation count and timing) is
low-sensitivity metadata, enumerable by the server and documented as an accepted residual (§22), on
par with the already-accepted device-count and access-timing leaks.

Path notes:
- `/keyslots/<device_id>/<g>` replaces `/keyslots/<pubkey>/<g>` — the device's full public key
  bytes are no longer exposed in the filesystem path; the keyslot blob itself carries the public
  key for verification. `device_id = BLAKE3(canonical(pubkey))` is already opaque.
- `/refs/<H>` replaces `/refs/<device_id>` — ref names are stored under a keyed hash
  `H = BLAKE3::keyed_hash(ref_name_key, ref_name)`, where `ref_name_key` is derived from
  `master_key` (§9.5). The head blob is **signed and encrypted** (§9.8): the ref name lives **inside
  the encryption** (recoverable only by a client holding `head_key_g`), so the server sees only the
  hash `H` and ciphertext. This closes the ref-name leak.
- The `/recovery` blob includes a 16-byte random salt field (before the key_commit) for the
  Argon2id path (§8.6).

The server-side `redb` index holds **only** `{id, size, generation, pack-offset}` — never
plaintext-derived metadata. One static binary; no external DB.

---
## 14. Multi-remote durability (replicas, not new forks)

Remotes are pure **content-addressed replicas**. Objects are immutable & content-addressed →
pushing the same object to N remotes is idempotent and safe; only the mutable refs need
reconciliation, and the client is the sole reconciler.

**Sigchain cross-remote reconciliation (normative):** before processing any remote's session,
the client MUST query ALL reachable remotes for their sigchain tip (`roster-head`), collect
verified-signature tips, and adopt the one with the highest `roster_seq` that correctly chains
back to RFP (each entry's `prev` hash verified). Any remote presenting a lower `roster_seq`
than the client's current frontier, or lower than the highest seen across all reachable remotes,
is treated as a rollback alarm and reported to the user. Sigchain consistency proofs (each entry's
`prev` hash matches its predecessor) MUST be verified when advancing from an older tip to a newer one.
A remote hiding a `RevokeDevice` entry will present a lower `roster_seq` than the honest remotes
and be detected.

**Per-ref head cross-remote rollback detection (normative):** after fetching each remote's head for
a given ref, the client MUST compare `head_version` values across all reachable remotes for that
ref. Any remote presenting a `head_version` strictly lower than the maximum `head_version` seen
across all reachable remotes for the same ref, AND lower than the client's locally persisted
`per_device_head_version_hwm` for that ref's owning device, MUST be treated as a head-rollback
alarm and reported to the user. The alarm text MUST mirror the sigchain rollback alarm (identifying
the offending remote, the observed `head_version`, and the expected minimum). Cross-remote
head rollback is thereby alarmed and contributes to P8's rollback-detection guarantee (§14).

**Multi-remote sync loop:**
- Fetch each remote's heads + sigchain tip (after the reconciliation and per-ref rollback-detection
  steps above); verify signatures, freshness, and RFP-anchor.
- Adopt the **highest valid `head_version` that descends from the frontier**; if two remotes
  present DAG-incomparable heads (the user wrote to different remotes while partitioned), run the
  **same three-way merge** as device forks — no new fork model. Missing ancestors: try all remotes
  (§10).
- Lazily re-push to lagging remotes (catch-up).

**Quorum confirmation (normative definition of P15):** after `put(id, blob)` to each remote,
the client MUST immediately issue `get(id)` to that remote, fully decrypt the retrieved blob,
and re-verify the content-address (§9.2). Only a remote that passes this put→get→verify
round-trip counts toward the quorum. A malicious remote that acknowledges `put` but returns
garbage on `get` is not counted. The client retains local objects until a configured quorum
(≥2) of remotes have each passed verification.

**Sigchain-mutating operations** (`RevokeDevice`, `Rotate`) MUST be confirmed as durably
appended on ≥quorum remotes before the client proceeds to write new-generation objects or
delete old keyslots.

A malicious/dead remote is an availability event only; a fresh remote exposes a stale or
ref-hiding one (which will also fail the cross-remote sigchain reconciliation step and the
per-ref head rollback-detection step).

---
## 15. Garbage collection (hardened)

- **Keep-set** = reachable closure over the heads of **all devices in the RFP-anchored roster**
  (each at `/refs/<H>`), unioned across all remotes — not merely the refs a server volunteers.
  If a rostered device's head is unavailable on a remote, GC **fails safe** (keeps that remote's
  objects) → server **ref-hiding cannot trick GC into deleting**. If any object (commit, tree, or
  subtree node) required during keep-set traversal is unavailable after trying all reachable
  remotes, the client **MUST abort GC on that remote entirely** and report the missing object to
  the user. Partial traversal **MUST NOT** proceed to a `gc()` call. GC keep-set per call is
  capped at 100,000 IDs (§12, §19); larger repos use generation-bounded batches.

- **`keep_set_hash` canonical encoding:** `keep_set_hash = BLAKE3(canonical_id_list(keep_set))`
  where `canonical_id_list` encodes the keep-set as `le64(count) ‖ id[0] ‖ id[1] ‖ … ‖ id[count-1]`
  with IDs in **ascending byte-lexicographic order**. Both client and server MUST use this exact
  encoding when computing or verifying `args_hash` for a `gc` call. A test vector appears in §19.

- **Generation + grace:** the server tags objects with an arrival generation; `gc(keep-set, gc_gen)`
  sweeps only `generation ≤ gc_gen ∧ ∉ keep-set`; in-flight/newer puts get a higher generation; a
  **grace window** (`GC_GRACE_WINDOW = 48 h`) shields recent arrivals. The client derives `gc_gen`
  from its own stored arrival receipts (see below) — not from a server-asserted generation counter.

- **Arrival receipts:** on each successful `put(id, blob)`, the server returns a signed receipt:
  `SIG_hostkey(id ‖ host_id ‖ arrival_generation ‖ put_epoch ‖ timestamp)` where `host_id` is the SPKI hash
  of the remote's pinned host key. The client verifies the receipt signature against the remote's
  pinned key and checks that the `host_id` field matches that remote. The client records
  `(id, arrival_generation, local_receipt_time)` at the moment the receipt is stored, where
  `local_receipt_time` is the client's own wall-clock time. The client **MUST segregate arrival
  receipts by the remote that issued them** (keyed by `host_id`); a receipt from remote-R **MUST
  NOT** influence the `gc_gen` computation for any other remote.

  `gc_gen` is the largest `arrival_generation` such that **all** objects with that generation
  have `local_receipt_time < now − GC_GRACE_WINDOW`. The grace window eligibility check MUST use
  `local_receipt_time`, regardless of the server-embedded `timestamp` field. The server-provided
  `timestamp` is informational only and MUST NOT be used to determine GC eligibility.

- **Client-verifiable GC serialization:** the `secsec-write-v1` args_hash for a `gc` call MUST
  bind the client's view of all mutable state at gc-request time:
  `args_hash = BLAKE3(canonical("gc" ‖ keep_set_hash ‖ gc_gen ‖ all_heads_hash ‖ roster_seq ‖ put_epoch))`,
  where
  `all_heads_hash = BLAKE3(le64(n) ‖ (ref_H[0] ‖ le64(head_version[0])) ‖ … ‖ (ref_H[n-1] ‖ le64(head_version[n-1])))`
  is computed over all `n` active refs, the pairs sorted by `ref_H` in ascending byte-lexicographic
  order. `head_version` is **per-ref** (§6, §8.5), so a single scalar cannot serialize a multi-ref
  repo; the aggregate does. `put_epoch` is a single **global (per-repository) monotonic counter**
  maintained by the server and incremented on **every** successful `put` regardless of which device
  issued it — a per-device counter could not catch a concurrent in-flight `put` from another device.
  The client learns the current `put_epoch` from the **highest value carried in any signed arrival
  receipt** it has received from that remote (receipts include `put_epoch`, above); it binds that
  value, making `gc` a compare-and-swap. The server MUST reject a `gc` call if the `all_heads_hash`
  or `roster_seq` in the args_hash differs
  from the server's current values, or if the `put_epoch` in the args_hash is lower than the
  server's current `put_epoch` — serializing `gc` against concurrent `cas-head`, `roster-append`,
  and any `put` from any device. Concurrent execution fails rather than proceeding silently. **Note:** a malicious server can still elect
  to execute a stale-`put_epoch` GC request; the defence-in-depth for cross-device in-flight
  objects is multi-remote replication (an object deleted on one remote is recoverable from another).

- **Destructive-op containment:** `gc` is a signed `secsec-write` op; deletions are bounded by the
  grace window and by multi-remote replicas (a wipe on one remote is recoverable from another). The
  delete log is an advisory record on a cooperative server; actual deletion integrity relies on
  content-addressing and multi-remote replication — a malicious server can omit or fabricate log
  entries. The GC signed-receipt mechanism (above) provides client-verifiable evidence of what was
  swept. Retention default is **keep-everything**; pruning is explicit and opt-in. No silent
  deletion. The `gc()` call is rate-limited to **4 calls per key per hour** (normative limit
  defined in §12; test parameters in §19); the server MUST reject excess calls before performing
  any object scan.

---
## 16. Downgrade protection & crypto agility

- TLS ciphersuites/KX and SSHSIG signature algorithm are **fixed**, not negotiated.
- A **compile-time absolute floor** rejects any `algo_id`/`format_version` below the minimum the
  build supports.
- A **`SetMinAlgo` sigchain entry** raises the floor repo-wide after an upgrade. `min_algo` is
  checked against the `algo_id` of **every fetched keyslot**, not only at keyslot creation time.
  A returned keyslot with `algo_id < current min_algo` is rejected with an error — the server
  cannot replay an older/weaker keyslot after a `SetMinAlgo` bump. A device whose existing key
  does not satisfy the new `min_algo` MUST generate a new keypair satisfying it and complete the
  grant flow before the old keyslot is deleted. Clients MUST enforce `min_algo` for all new
  writes: (a) new object blobs — the `algo_id` in FRAME MUST be ≥ `min_algo`; (b) new keyslot
  writes during the grant flow (§7 step 5) — the granting device E MUST select a keyslot
  `algo_id` ≥ `min_algo`; if E cannot produce a keyslot at the required `algo_id`, E MUST abort
  the grant with an error.
- **`SetMinAlgo` withholding:** anti-rollback prevents the server from rolling back a
  `SetMinAlgo` entry once a client has advanced its frontier past it. A device that has never
  received a `SetMinAlgo` entry (because the server withheld it) cannot benefit from the
  downgrade protection that entry provides; the cross-remote sigchain reconciliation (§14) detects
  this — a remote hiding the entry presents a lower `roster_seq` than the honest remotes. See P13
  qualification in §4 and §22.
## 17. Post-quantum posture

Symmetric layer (ChaCha20-Poly1305, BLAKE3, 256-bit keys) is PQ-safe. The harvestable exposure is
the asymmetric keyslot wrap. The `algo_id` mechanism supports a **hybrid keyslot** using **X-Wing**
(draft-connolly-cfrg-xwing-kem-10 / ePrint 2024/039) as the normative hybrid KEM.

**X-Wing combiner (normative):**
```
ss = SHA3-256(
    0x5c2e2f2f5e5c ‖  // 6-byte domain label (XWingLabel, FIRST per ePrint 2024/039 §3)
    ss_MLKEM  ‖       // 32 B: ML-KEM-768 shared secret
    ss_X25519 ‖       // 32 B: X25519 shared secret
    ct_X      ‖       // 32 B: X25519 ephemeral public key (ciphertext)
    pk_X              // 32 B: recipient X25519 static public key
)
keyslot_ct = ct_MLKEM(1088 B) ‖ ct_X(32 B)   // total: 1120 B
```

All inputs are fixed-width (6+32+32+32+32 = 134 bytes); the label-first order is normative per
ePrint 2024/039 §3 and draft-connolly-cfrg-xwing-kem-10 §4.1. Implementations MUST verify
byte-identical shared secrets against the test vectors in ePrint 2024/039 §A (equivalently,
draft-connolly-cfrg-xwing-kem-10 Appendix A) before any implementation is accepted as conformant.

This achieves IND-CCA security (classical: gap-CDH in ROM; post-quantum: ML-KEM-768 IND-CCA) and
satisfies MAL-BIND-K-CT and MAL-BIND-K-PK when ML-KEM-768 keys are stored in `(d, z)` seed form.
The `ct_MLKEM` omission from the KDF is proven safe for ML-KEM-768 specifically (FO transform
guarantees ciphertext collision resistance); this optimisation MUST NOT be generalised to other PQ
KEMs.

**ML-KEM-768 key storage:** key pairs are stored exclusively in `(d, z)` seed form (two 32-byte
seeds); the expanded keypair `(ek, dk)` is derived at runtime via SHAKE256 per FIPS 203 §7.1. At
key generation the FIPS 203 §7.1 keypair consistency check MUST be performed; failure is fatal. The
expanded `ek` is never stored persistently. This requirement prevents MAL-BIND-K-CT and MAL-BIND-K-PK
failures that arise under the expanded-key representation (Schmieg, ePrint 2024/523).

Signatures are lower urgency (forgery is online, not harvestable). Rollout is a `SetMinAlgo` bump (§16).
Until the hybrid-PQ keyslot is implemented, §4 P1/P10 mechanism columns reference the classical
path only.
## 18. Implementation hardening

- **Memory:** `master_key`, all derived subkeys, `recovery_key`, SSH private material → `secrecy`
  wrappers, `zeroize` on drop, `mlock` where supported; never serialized to disk.
- **Constant-time:** all tag/commit/MAC/SAS/fingerprint comparisons via `subtle`.
- **RNG:** OS CSPRNG (`getrandom`) only; no userspace PRNGs for keys/nonces.
- **Parsers:** size/depth/fan-out/length bounds enforced pre-allocation per §19 normative constants;
  `cargo-fuzz` targets for every decoder; reject non-canonical encodings.
- **Secrets never logged;** structured redaction; no key material in error messages.
- **Supply chain:** minimal pinned deps; `cargo-audit` + `cargo-vet` in CI; reproducible static
  `musl` build; no OpenSSL.
- Do not trust returned FRAME fields; derive from expected `(gen, type)` and verify equality.

## 19. Constants _(normative — required for conformance)_

| Knob | Value | Note |
|---|---|---|
| FastCDC min/avg/max | 16 / 64 / 256 KiB | sync responsiveness vs object count |
| Pack target | 8 MiB | bundle small chunks |
| Listen port | udp/8899 | overridable |
| QUIC idle / keepalive | 30 s / 10 s | reconnect vs wakeups |
| `server_nonce` size / TTL | 32 B / 60 s | single-use; replay bound; server SHOULD re-verify keyslot existence on each per-op request and MUST do so at least once per this TTL window (§9.6, §12) |
| GC grace window | 48 h | `GC_GRACE_WINDOW`; shields recent arrivals during multi-day offline periods; normative definition in §15 — this value MUST match §15 exactly |
| Metadata padding buckets | powers of two | default-on (small objects) |
| Chunk padding policy | power-of-two (default) / uniform (opt-in) / off (opt-out) | default pads to next power-of-two ≥ size (≤2× overhead) — *reduces* the boundary signal; uniform pads all chunks to one fixed size — *eliminates* it at higher cost; off saves space |
| Per-key storage quota | 10 GiB default | configurable; server MUST enforce |
| Per-key write rate | 100 MB/s sustained, burst 1 GiB | server MUST enforce after auth |
| Per-key read rate | 200 MB/s sustained | server MUST enforce after auth; matches 2× write rate to allow sync catch-up without unbounded egress |
| Connection rate limit | 10 new/s per source IP; 3 concurrent per authenticated key | server MUST enforce |
| Min RSA / preferred | 3072 / Ed25519 | reject weak RSA |
| Argon2id (passphrase recovery) | m=64 MiB, t=3, p=1, salt=16 B random | offline-attack floor (RFC 9106 second recommended / OWASP high-security); high-entropy code path uses HKDF |
| Argon2id salt | 16 bytes, OS CSPRNG, per-keyslot, rotated on re-wrap | RFC 9106 §4 mandatory; stored in /recovery blob |
| HPKE ciphersuite (Ed25519 keyslots) | DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 (RFC 9180 ciphersuite 0x0021); info = "secsec-keyslot-v1" ‖ canonical(device_id) ‖ le32(gen) | consistent with ChaCha20Poly1305 used elsewhere; info binding makes each keyslot ciphertext irrevocably device- and generation-specific at the HPKE layer |
| Durability quorum | 2 remotes (put→get→verify round-trip each) | availability under hostile server |
| Retention | keep-all; prune opt-in | no silent deletion |
| SAS length | ~20 bits human-verified (6-digit decimal, mod 1,000,000 of 32-bit BLAKE3 truncation) | NIST SP 800-63B-4 floor: ≥20 bits met; the 6-digit decimal encoding conveys log₂(1,000,000) ≈ 19.93 bits of human-verified entropy — the ZRTP 32-bit claim does not apply to this decimal encoding |
| SAS grant attempt cap | 5 SAS sessions per D_pubkey per hour | E MUST enforce at the SAS protocol layer, tracked in E's local state, independent of sigchain operations; sessions that abort at any step (including steps 1–3) count toward the limit; E MUST NOT begin step 2 for a D_pubkey that has reached the limit within the rolling 1-hour window |
| Max has() IDs per call | 1,024 | server rejects with too-many-ids before any lookup |
| Max gc() keep-set IDs per call | 100,000 | server rejects before processing |
| Max gc() calls per key per hour | 4 | server MUST enforce; prevents disk-scan amplification; 4 calls/hour supports normal operation (daily GC in batches of up to 100,000 IDs each) while blocking sustained scan abuse |
| keep_set_hash canonical encoding | BLAKE3(le64(count) ‖ id[0] ‖ … ‖ id[count-1]), IDs in ascending byte-lexicographic order | normative for gc() args_hash (§15); both client and server MUST use this exact encoding; test vector required |
| Max sigchain entries per authenticated connection identity per hour | 60 | server enforces by counting roster-append calls per BLAKE3(authenticated_pubkey); server does not decrypt the entry to read the inner signer field; server MUST enforce at roster-append |
| Max total sigchain length | 10,000 entries (configurable) | server MUST enforce |
| Max key-history depth (generations) | 256 | beyond this, HistoryReanchor entry required (§8.2) |
| Max blob size (any object type) | 16 MiB | decoders reject before allocating |
| Max tree depth | 64 levels | decoders reject before allocating |
| Max tree fan-out per node | 65,536 entries | decoders reject before allocating |
| Max roster entry size | 4 KiB | decoders reject before allocating |
| Max list fields (sigchain, keyhist, etc.) | 4,096 elements | decoders reject before allocating |
## 20. Build order

1. Object store: framing + canonical serialization + per-object-key committing AEAD (CTX/CMT-4) +
   content-address verify + push/pull/restore.
2. Roster sigchain + keyslots + enrollment (RFP/SAS with commitment round) + generations/rotation +
   write-auth gate + read-auth gate (secsec-read-v1).
3. Refs (keyed-hash paths) + `cas-head` + rollback-aware three-way merge.
4. `notify` watcher → live sync; conflict surfacing.
5. Multi-remote replication + reconciliation (cross-remote sigchain check); hardened GC (receipts +
   serialization); fork-detection alarms + gossip.
6. Recovery flow (committing AEAD, Argon2id at raised params). Downgrade/min-algo enforcement
   (per-fetch check, not creation-only). Local sealed state (SSH-key-derived seal).
7. *(later)* Hybrid-PQ keyslot (X-Wing); WebDAV browse (not FUSE — read-only, no Windows).

## 21. Candidate crates

`quinn`,`rustls` · `ssh-key`(SSHSIG),`ed25519-dalek`,`x25519-dalek`,`rsa` · `blake3` · `chacha20poly1305` · `hpke`/hybrid-KEM crate · `argon2` · `fastcdc` · `notify` · `redb` · `tokio`,`serde`+`postcard`(canonical) · `zeroize`,`secrecy`,`subtle`,`getrandom` · `russh` (for SSH exchange hash `H` in stdio mode) · *(future)* an audited ML-KEM crate (FIPS 203 seed-form storage required). Versions pinned at implementation; `cargo-audit`/`cargo-vet` gated.

## 22. Residuals (proven-minimal)

These are impossibilities for a blind, untrusted server, with their mitigations — not deferred work:

- **Availability/durability.** A hostile server can refuse or delete. Mitigation: ≥2 independent
  replicas + client retention (§14). Residual only if *all* replicas are hostile/dead.

- **Reinstall freshness.** A device that loses *all* local frontier state can still verify
  **authenticity** (RFP + `mk_commit`, §7) but cannot alone prove it was served the *latest* head.
  Mitigation: gossip / multi-remote cross-check (§10, §14). Residual only for a sole device with
  no peer and no prior memory — the SUNDR lower bound.

- **Sustained-partition fork detection** is *delayed*, not prevented (SUNDR). Mitigation: gossip +
  replicas; detection is guaranteed on any reconvergence.

- **Total bootstrap/recovery loss.** A user who keeps *neither* another device, RFP, nor the
  recovery code cannot recover — information-theoretic. Mitigation: printed `{recovery_code, RFP}`.

- **Compromised client.** Plaintext and `master_key` live on the client by necessity; its
  compromise is total for that device. Mitigation: prompt revoke+rotate; `mlock`/`zeroize` limit
  key scavenging.

- **Local frontier rollback by a disk-level attacker.** The sealed local-state file (§8.5) is
  encrypted under a *static* key (derived from the SSH private key), so an older sealed copy still
  verifies. An attacker with raw read/write access to the device's disk could restore an older copy
  to rewind the persisted anti-rollback frontier, after which a colluding server could replay state
  up to that point. This is largely subsumed by *compromised client* (a disk-level attacker
  generally also holds the SSH key, hence total access); a hardware monotonic counter would close it
  but is out of scope. Detection still fires on reconvergence with any honest peer (§10 fork
  detection).

- **Revoked-device access to pre-rotation data.** A revoked device that retained `master_key_g`
  in memory can, colluding with the server, decrypt any gen-g object the server still holds.
  Keyslot deletion prevents re-deriving `master_key_g` from the server, but does not affect
  in-memory copies. Rotate-all re-encryption (re-encrypting all existing objects as gen-g+1,
  GC old ones after quorum confirmation) is the only complete mitigation; absent it, revocation
  provides forward secrecy only for data created after the rotation event. This is not a narrow
  carve-out — it applies to all pre-rotation ciphertext, not merely data the device had already
  decrypted before revocation.
  A revoked device cannot authenticate **new connections** once its keyslot is deleted (cooperative
  server) or obtain **new-generation master keys** (malicious server — bounded by the gen-g residual
  above). On a cooperative server, per-op keyslot re-verification (§12) closes the open-connection
  gap; on a malicious server that refuses keyslot deletion, the revoked device retains whatever
  gen-g access it had before the rotation event.

- **Concurrent mutual-revocation race.** All devices are flat, equal members; there is no
  privileged founder (§8.4). When the legitimate device revokes a stolen one (`RevokeDevice` +
  `Rotate`), a stolen device that is unlocked, online, and racing can concurrently issue
  `RevokeDevice` + `Rotate` against the legitimate device. The `/roster-head` CAS serializes the
  two; whichever lands first wins. If the stolen device wins, the legitimate device re-folds onto
  the new tip, finds itself revoked, and its retry fails succession (§8.1) — it cannot append, the
  attacker keeps the repo, and the user is evicted. This bites **only** when the stolen device is
  unlocked, online, and actively racing — a state in which it already holds `master_key_g` and thus
  already had full data access; it is not a new exposure of data, only of repository control.
  Mitigation: revoke promptly while the legitimate device is the only one online; device
  credential/physical security. A complete fix (recovery-code-gated revocation, or a privileged
  device-1 key for `RevokeDevice`/`Rotate`) was considered and deliberately not adopted, to
  preserve the flat-device model — this race is the accepted cost. Detection still fires on
  reconvergence with any honest peer (§10 fork detection).

- **Bounded metadata leakage — cross-path (convergent mode).** Object sizes (within padding
  buckets), access timing, and cross-path chunk equality (identical chunks in different files
  yielding the same ID) leak only in convergent mode. Mitigation: default-on keyed chunking +
  default-on chunk padding + default-on per-path salt (§9.7). Residual only for users who opt into
  convergent mode.

- **Bounded metadata leakage — intra-file temporal (all modes).** In default mode the per-path
  salt is derived once at first-sync and stored in the tree blob — it is constant across all
  versions of a given file. When a file is modified, unchanged chunks produce the same chunk ID
  across sync sessions (path-salt, plaintext, gen, and type are all identical). The server observes
  per-sync which chunk IDs are new uploads versus already stored, revealing the chunk-level edit
  distance for each modified file — without reading any ciphertext — in **all** modes, not only
  convergent. Per-path salt prevents a third-party attacker from computing expected IDs for a
  suspected plaintext, but does not prevent the server from observing the upload delta. Eliminating
  this leak entirely would require a per-version salt, which disables intra-file dedup. This is a
  chosen tradeoff.

- **Keyed CDC chosen-plaintext key extraction.** `cdc_seed` secrecy is contingent: an adversary
  who can cause the victim to archive chosen-plaintext data can recover the secret gear-table key
  (Alexeev et al., ePrint 2025/532). Default-on power-of-two padding substantially reduces the boundary signal (the uniform policy, opt-in, eliminates it); `cdc_seed`
  is generation-scoped so rotation limits exposure. Not an information-theoretic impossibility;
  fixed substantially by default-on padding.

- **SetMinAlgo withholding for devices that have never received the entry.** A device that has
  never been served a `SetMinAlgo` entry (server withheld it) operates without the downgrade
  protection that entry provides. Detection: cross-remote sigchain reconciliation (§14) exposes
  remotes presenting a lower `roster_seq`. Not a complete fix against a server colluding with all
  reachable remotes. Mitigated by multi-remote diversity.

- **Delete log advisory only.** The append-only delete log is advisory on a cooperative server;
  a malicious server can omit or fabricate entries. Actual deletion integrity relies on
  content-addressing, multi-remote replication, and the signed GC receipt mechanism (§15).

- **GC put-epoch integrity (defence-in-depth).** The signed GC receipt (§15) binds the set of
  surviving object IDs at the time of collection, but the server controls the arrival timestamps
  it associates with object writes. A malicious server can claim an object was written in the
  current epoch to prevent its collection, or claim an object is old to accelerate its deletion.
  Clients MUST therefore treat GC eligibility as a client-computed decision based on the signed
  sigchain frontier, not on server-supplied timestamps. This is a defence-in-depth residual:
  a cooperative server's timestamps are not load-bearing for correctness.

- **Key-rotation count and timing leakage.** The storage layout uses plaintext generation indices
  in `/keyslots/<device_id>/<g>` and `/keyhist/<g>`. A malicious server enumerating these paths
  learns the master-key rotation count (number of `Rotate` events), when each rotation occurred
  (from write timestamps), and how many devices held a keyslot at each generation. This is an
  accepted tradeoff, **not** an impossibility — but opaquing `g` is not buildable in the base
  protocol: the API has no `list` operation (§12), so a device must compute the exact path of
  objects it has not yet decrypted (its own keyslot, and the key-history chain on reinstall). A
  secret-derived path component would therefore be circular (it depends on the key being fetched)
  or require a second out-of-band anchor beside RFP (§13). The leak is low-sensitivity metadata, on
  par with the already-accepted device-count and access-timing leaks below.

- **Ref-name and path leakage (chosen tradeoff).** Ref names are stored under keyed hashes
  (§13); the server cannot read them. Device public keys are not exposed in storage paths
  (§13, `device_id`). The set of `device_id`s is enumerable from `/keyslots/*` paths, which
  reveals the number of enrolled devices, and (per the rotation-count entry above) the generation
  components in those paths reveal the rotation history. These are chosen tradeoffs, not
  impossibilities.

- **First-init TOFU window.** When `secsec init` is run without `--host-fp SHA256:…`, the server
  host key is accepted on first use based on a one-time human fingerprint comparison that is not
  mechanically enforced. A network attacker present at init time can substitute their own host key;
  once accepted, all subsequent connections verify against the attacker's key, giving them a
  persistent MITM position. Mitigation: always supply `--host-fp` at init; when absent, the client
  MUST display the fingerprint and require explicit interactive confirmation with a warning that
  this is a one-time, irrevocable verification. The window is bounded to the init moment — after
  pinning, no further TOFU exposure exists.

---

## Provenance

This specification is the settled output of several adversarial security-review rounds. The
detailed finding→fix history lives in `securityreview.md` and the `_backup/` revisions, not
in this document — every normative requirement above stands on its own. Constants in §19 are
normative and required for conformance.
