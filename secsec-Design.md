# secsec — Design

A self-hosted, end-to-end-encrypted, **live two-way** file-sync system (server + client),
single static Rust binary. The server is **blind**: it stores only ciphertext and never learns
file contents, names, structure, or sizes beyond a bounded, documented residual. The only
credential is an SSH key. This document is implementation-ready and is the authoritative spec.
The build plan, status, and assurance strategy live in `secsec-Implementation.md`.

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
- **SSH key is the only required configuration and the only credential.** The operator lists
  permitted device public keys in the server's `~/.ssh/authorized_keys` (the mandatory connection
  gate, §11); each device holds its `~/.ssh/id_ed25519`. Device onboarding is a first-class flow
  (genesis for the first device, a one-time **invite code** for the rest, §7). There is **no
  separate recovery secret**: the SSH key is both the credential and the backup — a device that
  holds it is a full replica and can re-join from any peer via an invite.

## 2. Non-goals

- Multi-tenant hosting; provider-side search/indexing.
- Hiding the bounded metadata of §4.3 (sizes/timing/equality) — reduced, not eliminated.

## 3. Threat model

Adversaries: a **malicious/compromised server** (the primary one), a **network attacker**, a
**revoked device**, and a **stolen client**. We assume the device's SSH key and the user's
out-of-band channel (carrying an invite code or reading a fingerprint off a screen) are
trustworthy; everything else, including the server and the network, is hostile.

A key not listed in the server's `~/.ssh/authorized_keys` cannot open a connection at all (§11) —
the mandatory connection gate. This gate is necessary but **not** sufficient for data access:
even a listed key reads or writes nothing without a valid keyslot (§12), so the security claims
below never rest on the gate alone.

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
| P4 | Server cannot feed a new/reinstalled device a **forged repository or key** | Out-of-band **RFP** anchor + `mk_commit` verification of any unwrapped master key (§7); for a *joining* device, a single-use **invite code** authenticates the enrollment key-exchange end-to-end through the blind server (MAC-under-code — the server never learns the code, §7) and the joiner confirms the inviter-vouched `host_id` equals the server it actually connected to |
| P5 | A connection ≠ the ability to read or write; unlisted keys cannot even connect, and listed-but-unenrolled keys are rejected before any data access | **Two layers:** (a) the server refuses any connection from a key absent from `~/.ssh/authorized_keys`, re-read per connection (§11); (b) every repo RPC — including reads — requires a per-op signature from a **keyslot-owning** (rostered) key; server MUST verify keyslot existence at /keyslots/\<device_id\>/\<g\> on every per-op request, not only at connection time (§9.6, §11, §12). A revoked device with an open connection can still issue requests until keyslot deletion is checked — on cooperative servers the re-check window is ≤ the server-nonce TTL (60 s, §19); on a malicious server, keyslot deletion cannot be enforced (residual §22) |
| P6 | Revocation removes access to data created after rotation (forward secrecy) | revoke ⇒ rotate: new master-key generation, re-wrap to remaining devices, delete keyslot; pre-rotation ciphertext remains a residual (§8.4, §22) |
| P7 | Revocations cannot be lost or rolled back **by the untrusted server** | Roster is an append-only, hash-chained, signed sigchain with succession + frontier (§8). (Eviction of the legitimate device by a *compromised, online* peer racing the CAS is a separate adversary — the concurrent mutual-revocation residual, §22.) |
| P8 | Rollback/replay of sigchain state is detected; cross-remote rollback of per-ref heads and sigchain is alarmed; fork evidence is computed and alarmed when two devices exchange commits with DAG-incomparable last_seen_head values | Monotonic, signed frontiers on every counter; local frontier sealed with a key derived from **private** key material (§8.5, requires device_ed25519_scalar_clamped, not the public key); rollback-aware merge (§8.5, §10); cross-remote head-rollback alarm mirrors sigchain alarm (§14); fork detection algorithm in §10 fires when received last_seen_head is DAG-incomparable to client head |
| P9 | No cross-protocol signature reuse | Disjoint SSHSIG namespaces; server-chosen nonces confined to `auth`/`write` (§9.5) |
| P10 | No catastrophic AEAD misuse / key-confusion for object, keyslot, and key-history wraps | Unique per-object key, fixed nonce, CMT-4 committing AEAD via CTX construction (§9.4); key-history wrap (§8.2) uses CTX pattern with ctx_tag_keyhist = BLAKE3::keyed_hash(k_keyhist_g, "secsec-ctx-v1" ‖ AD_keyhist ‖ T), binding master_key_g as plaintext |
| P11 | Forward secrecy after revocation | Post-rotation data uses a new generation the revoked device cannot derive (§8.4) |
| P12 | Transport is authenticated without a CA; first-contact TOFU window is a documented residual | TLS 1.3 to a pinned self-signed host key (TOFU on the first `sync`, fingerprint printed for out-of-band confirmation, then persisted in the folder link), channel-bound auth (§11); the pin rests on that one-time confirmation — the first-contact TOFU window is a residual (§22). A *joining* device additionally checks `host_id` under the invite-code MAC (§7) |
| P13 | No algorithm/format downgrade once a `SetMinAlgo` entry has been received | Pinned TLS & signature algorithms; `SetMinAlgo` floor in the sigchain enforced on every fetched keyslot (not only at creation); compile-time floor (§16); withheld entries detectable via multi-remote cross-check (§14, §22) |
| P14 | No server-stored recovery blob to crack; lockout is avoided by backing up the SSH key, not a second secret | The SSH key is both credential and backup. A device holding it is a full plaintext replica; a reinstalled one re-joins via an invite from any peer (§7). Losing *every* device **and** the SSH key is unrecoverable by construction — the §22 total-loss residual. (A passphrase-wrapped recovery keyslot on an untrusted server was considered and **removed** as a net liability: it adds an offline-crackable, server-exfiltratable target for a backup the SSH key already provides.) |
| P15 | Durability despite a hostile server | Content-addressed replication to ≥2 remotes; client retains until quorum-confirmed via put→get→verify round-trip on each remote (§14) |

---
## 5. Identifiers & trust anchor

- **Device key** — an **Ed25519** SSH keypair per device (v1 is Ed25519-only; RSA was dropped from
  scope). Roles: *sign* (SSHSIG; agent/hardware OK) and *unwrap* (the X-Wing keyslot's X25519 half
  is derived from the Ed25519 key — §8.3 — so unwrap needs the private key as a file; agent/FIDO
  cannot do it). `ecdsa`/`sk-*`/RSA keys do not parse → enrollment-incapable.
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
  - `host_id = BLAKE3(canonical(server pinned SPKI bytes))`, where the SPKI bytes are the
    SubjectPublicKeyInfo DER encoding of the pinned server certificate public key (QUIC/TLS — the
    single v1 transport).
- **RFP (Repository FingerPrint)** := `BLAKE3(canonical(genesis sigchain entry))`. The genesis
  transitively commits to device-1's key and to `mk_commit_1`. **RFP is the one out-of-band
  anchor**: established when the first device creates the repo, and delivered to each joining
  device **inside the invite code's authenticated pairing exchange** (§7) — the inviting member
  vouches for it under the code's MAC, so the blind server cannot substitute it. Everything else can
  be fetched from the untrusted server and cryptographically checked against RFP. After enrollment a
  device persists the RFP in its per-folder link, so subsequent syncs need no out-of-band step.

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

**Creating the repo (first device).** The first device runs `secsec sync <dir> --server host[:port]`
with **no** `--invite`. It:
1. Generates `master_key_1`; computes `mk_commit_1`.
2. Writes the genesis sigchain entry (seq 0), self-signed, containing device-1's pubkey +
   `mk_commit_1`, **and** its own X-Wing keyslot wrapping `master_key_1`. Both writes are accepted
   under the **genesis-bootstrap exception** (§12): the server permits `roster-append`/`put-keyslot`
   from a not-yet-enrolled key **only while the roster is empty** (`roster_len == 0`). Combined with
   the `authorized_keys` gate (§11) — only a key the operator listed can reach this path — this
   closes the "whoever connects first seizes an empty repo" race.
3. The genesis fixes **RFP** = `BLAKE3(canonical(genesis))` (labeled/compared as BLAKE3, never
   SHA256). RFP is persisted in the folder's link and later handed to joining devices via the invite
   exchange below; the user need not transcribe it by hand.

(On first contact the device prints the server's host fingerprint for out-of-band confirmation,
then pins it — TOFU, §11.)

**Adding a device — invite-code pairing.** Onboarding the second/third/… device needs exactly one
out-of-band secret: a single-use **invite code**. This replaces the older manual ceremony
(typing D's fingerprint into E, then comparing a 6-digit SAS by eye): one carried 96-bit code is
higher-entropy than a 20-bit SAS and authenticates the whole key-exchange *mechanically*, so there
is no digit-by-digit human comparison to mis-read, and no grinding window to defend against.

Operator (one-time): add D's SSH **public** key to the server's `~/.ssh/authorized_keys` so D can
connect at all (§11). On the **inviting** (enrolled, online) device E: `secsec invite <dir>` —
prints a one-time code and waits. On the **joining** device D:
`secsec sync <dir> --server host[:port] --invite <code>`.

The pairing protocol (every message relayed through the server's transient, TTL'd **pairing
mailbox** — `pair-put`/`pair-get`, §12 — whose slot ids are `BLAKE3(label ‖ code)` so the server
cannot reverse them; every message MAC'd under `mac_key = BLAKE3::derive_key("secsec-pair-mac-v1",
code)`):

1. **D → slot `d`:** `{D_pubkey, D_xwing_pub, tag_d}` with
   `tag_d = BLAKE3::keyed_hash(mac_key, "d" ‖ D_pubkey ‖ D_xwing_pub)`. Only a code-holder can
   produce `tag_d`, so the server cannot substitute D's key.
2. **E** reads slot `d`, verifies `tag_d`, then runs the networked grant (`grant_device_remote`):
   appends `AddDevice(D_pubkey, mk_commit_g, D_xwing_pub)` onto the sigchain tip (CAS-guarded) and
   writes D's X-Wing **keyslot** wrapping `master_key_g` (§8.3). E selects a keyslot `algo_id` ≥ the
   folded `min_algo` (§16). E then posts **slot `e`:** `{RFP, host_id, tag_e}` with
   `tag_e = BLAKE3::keyed_hash(mac_key, "e" ‖ RFP ‖ host_id)`.
3. **D** reads slot `e`, verifies `tag_e` → learns the genuine RFP and the `host_id` E vouches for.
   D **confirms `host_id` equals the server it actually connected to** (the TOFU-captured pin, §11);
   a mismatch is a possible MITM and aborts. D then cold-starts (below) and unwraps the keyslot E
   wrote, verifying it against `mk_commit` — a forged keyslot fails.

Why this defeats the blind server: it relays only ciphertext-opaque mailbox blobs and never learns
the code, so it cannot forge `tag_d`/`tag_e`, cannot swap D's key (P4), and cannot substitute RFP or
`host_id`. The code is single-use with a bounded mailbox TTL (`PAIR_TTL`, §19); a replayed pairing
message finds its slot consumed or expired, and the code is never reused. Online code-guessing is
the only residual attack surface and is infeasible: a 96-bit code, single-use, behind the
`authorized_keys` connection gate (§11) and the mailbox's per-key write rate limit (§12). The gate
and the code are complementary layers — the gate keeps unlisted keys off the mailbox entirely; the
code authenticates the exchange among listed keys; neither alone suffices.

**D's cold-start (and every reinstall) — authenticity without trusting the server:**
1. D has **RFP** — from the pairing exchange (step 3) on first join, or from its persisted
   per-folder link on every later sync.
2. D fetches the sigchain; verifies genesis hashes to **RFP** and the whole chain's succession
   (§8). A server-forged chain fails the RFP match.
3. D fetches its keyslot, unwraps → candidate `master_key_g`; **verifies
   `BLAKE3::keyed_hash(candidate, "secsec-mk-commit-v1" ‖ le32(g)) == mk_commit_g`** from the
   **highest-seq** `AddDevice` or `Rotate` entry in the RFP-anchored chain (D MUST use the entry
   with the greatest `roster_seq`, not any historical entry — using a stale entry would pass for
   a rolled-back key). A server-forged keyslot (fake key) fails this check → D refuses.
4. Only then does D trust the repo. The server can withhold or stale data (availability) but can
   never substitute a fake key or fake universe.

This reduces the unavoidable residual to **freshness only** on a state-less reinstall (cannot
prove "latest" without prior memory or a peer — §22), never authenticity.

> The lower-level `grant_device` primitive (direct, non-mailbox enrollment) additionally signs a
> `secsec-grant-v1` attestation over an out-of-band `enrollment_nonce` (§9.6) for freshness; the
> shipped invite-pairing path obtains that freshness from the single-use code + mailbox TTL instead,
> so it does not carry the attestation.

---
## 8. Roster sigchain & key management

### 8.1 The roster is an append-only signed sigchain (closes lost-revoke & roster-rollback)

```
Entry { seq:u64, prev:hash, op, params, ts, signer:device_id, sig }
  sig = SSHSIG("secsec-roster-v1", canonical(seq‖prev‖op‖params‖ts‖signer))
  prev = BLAKE3(canonical(entry[seq-1]))      // 0 for genesis
ops: Genesis | AddDevice | RevokeDevice | Rotate | SetMinAlgo
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

**Data key-history is never trimmed.** Like the roster-key history above, `/keyhist/<g>` keeps a
forward-wrap of `master_key_g` under `master_key_{g+1}` for **every** generation, so a current member
can peel back to `master_key_1` and read *old file content* sealed under any past generation. At 64
bytes per generation, bounded by the sigchain-length cap (§19), the total size is negligible — there
is no depth limit and no trimming. (An earlier draft trimmed at 256 generations via a `HistoryReanchor`
op; that was **removed** — it added a fresh-device fold hazard for marginal space savings in a
single-user repo that will essentially never reach hundreds of rotations.)

### 8.3 Keyslots — versioned, authenticated by commitment, PQ-ready

A keyslot wraps `master_key_g` to a device. It is stored `algo_id(1B) ‖ body`. **Post-quantum is
mandatory: X-Wing is the *only* keyslot algorithm** (`algo_id = 2`). The classical X25519/HPKE wrap
(and the RSA-OAEP variant) were **removed** — after the harvest-now-decrypt-later argument of §17, a
pre-quantum keyslot is the one harvestable asymmetric exposure, so shipping it as an option is
incoherent. The `algo_id` tag and the §16 `min_algo` floor remain for forward agility (a future PQ KEM
bumps the floor); any keyslot below X-Wing is rejected at cold-start.

- **X-Wing (the only keyslot, §17):** keyslot ciphertext = `ct_MLKEM(1088 B) ‖ ct_X(32 B)`, AEAD AD =
  `info = "secsec-keyslot-v1" ‖ canonical(device_id) ‖ le32(gen)` (binds it to one device + generation).
  ML-KEM-768 key pairs stored exclusively in `(d, z)` seed form (§17). The device's X-Wing
  decapsulation seed is `BLAKE3::derive_key("secsec-xwing-seed-v1", ed25519_private_seed)` — derived
  from the raw 32-byte Ed25519 **seed**, **NOT** the clamped scalar `a = clamp(SHA-512(seed)[..32])`.
  This is load-bearing for the post-quantum property: a quantum adversary recovers `a` from the
  device's *public* Ed25519 key via Shor (discrete log), so deriving the X-Wing seed from `a` would let
  that adversary reconstruct the whole X-Wing secret — including the ML-KEM half — from public data and
  break the harvested keyslot. The Ed25519 seed is quantum-hard to recover from the public key (SHA-512
  preimage), so the ML-KEM private key stays secret against a quantum attacker. The X25519 half may be
  broken by Shor (its public is birationally derivable from the Ed25519 public), but X-Wing remains
  IND-CCA on the ML-KEM half alone — that is exactly what hybrid buys.

Authenticity does **not** rest on the wrap (a wrap-to-pubkey is forgeable by anyone): it rests on
the **`mk_commit` check** in §7 step 3. A forged keyslot decrypts to a key that fails the
commitment. (Note on key reuse: the SSH key signs *and* does ECDH; this is a deliberate,
analyzed tradeoff for the "SSH identity only" requirement — usage is domain-separated and the
Ed25519→X25519 conversion is the established one used by `age`/`ssh-to-age`.)

### 8.4 Rotation & revocation (closes "revoke is a no-op")

Revocation runs over the wire from any enrolled device: `secsec devices <dir>` lists the roster
(short device id + each key's `SHA256:…` SSH fingerprint), and `secsec revoke <device> <dir>`
removes one by an id prefix (`rotate_repo_remote` with a revoke target). A device may not revoke
itself. Against an untrusted server, `revoke` **always** rotates:
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
// Ed25519 device key (v1 is Ed25519-only): derive from the private scalar (never published)
local_seal_key = BLAKE3::derive_key("secsec-local-seal-v1",
                                    device_ed25519_scalar_clamped)
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

### 8.6 Recovery — removed (the SSH key is the backup)

Earlier drafts offered an optional **recovery keyslot**: a passphrase- or recovery-code-wrapped copy
of the master key, stored on the server, recoverable into a fresh device. It was **removed entirely**
(the `secsec-recovery` crate and the `recover` command deleted).

Rationale: the SSH key is already both the credential and the backup (§1, P14). Any device holding it
is a full plaintext replica and can re-join from any peer via an invite (§7); there is nothing a
server-stored recovery blob recovers that backing up the one SSH key does not. Against that marginal
benefit, the recovery keyslot was a **net liability** — a second secret for the user to manage and,
in the passphrase variant, an **offline-crackable, server-exfiltratable** target sitting on the
untrusted server (precisely the asset the rest of this design works to deny it). Total loss of
*every* device **and** the SSH key is the information-theoretic §22 residual; the honest mitigation is
to back up the single credential, not to mint and store a second one. No recovery KDF (Argon2id),
recovery keyslot, or `/recovery` server path exists in v1.

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
bytes raw. Algorithm pinned to `ssh-ed25519` (v1 is Ed25519-only) — no alg downgrade. **The
verifier MUST reject any SSHSIG blob whose `sig_algorithm` field is not exactly `ssh-ed25519`. Any
other algorithm field MUST cause verification failure regardless of cryptographic validity.**

| Purpose | Namespace | Message |
|---|---|---|
| Connection auth | `secsec-auth-v1` | `channel_binding ‖ host_id ‖ session_transcript ‖ server_nonce` |
| Write authorization | `secsec-write-v1` | `op ‖ args_hash ‖ session_transcript ‖ server_nonce` |
| Read authorization | `secsec-read-v1` | `op ‖ args_hash ‖ session_transcript` (`args_hash = BLAKE3(canonical(op ‖ ids))`) |
| Commit | `secsec-commit-v1` | canonical commit |
| Head update | `secsec-head-v1` | `ref ‖ commit_id ‖ head_version ‖ roster_seq ‖ prev_head` |
| Roster entry | `secsec-roster-v1` | canonical sigchain entry |
| Grant attestation | `secsec-grant-v1` | `device_pubkey ‖ mk_commit_g ‖ roster_seq ‖ enrollment_nonce` |

**Connection auth field order (canonical):** `channel_binding ‖ host_id ‖ session_transcript ‖
server_nonce`, where `channel_binding` is the TLS 1.3 keying-material exporter (§11). This order is
normative; §11 cross-references this table rather than defining a separate formula.

`secsec-read-v1` provides per-op authorization for `get` and `has`: `args_hash` binds the exact
object IDs requested; `session_transcript` provides per-connection freshness without requiring
a server-supplied nonce.

`secsec-grant-v1` is the **direct-grant** primitive's attestation: it includes `enrollment_nonce`
(32 bytes, OS CSPRNG, generated fresh by the granting device E and transmitted to D over the
out-of-band grant channel); D checks the server-fetched attestation covers exactly that
directly-received value, which makes it single-session and non-replayable. The **shipped invite-code
pairing** path (§7) does not carry this attestation — it obtains the same freshness from the
single-use code and the pairing mailbox's bounded TTL — so `secsec-grant-v1` applies only when a
device is enrolled via the lower-level direct grant rather than an invite.

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
- **`authorized_keys` is the mandatory connection gate.** `secsec serve` reads the operator's
  `~/.ssh/authorized_keys` (standard OpenSSH format, Ed25519 lines) and **refuses to start** if it
  is missing or has no usable key. After the handshake, the server computes
  `device_id = BLAKE3(canonical(authenticated_pubkey))` and rejects the connection unless that id is
  present in the file — which is **re-read on every connection**, so adding or removing a device
  takes effect with no restart, and an unreadable file fails **closed** (deny). The authenticating
  key is proven by the channel-bound `secsec-auth-v1` signature below, so a key cannot be spoofed by
  client-supplied bytes. This gate is necessary but not sufficient: a listed key still owns no data
  without a keyslot (§12). The two layers are independent — `authorized_keys` is the operator's coarse
  allow-list (who may open a socket); the keyslot roster is the cryptographic membership (who may read
  or write). Revoking a device is therefore two acts: `secsec revoke` (rotate the key away, §8.4) and
  removing its line from `authorized_keys` (stop it reconnecting).
- **No managed certs:** the server self-signs a host key on first run (like `sshd`). The client
  **pins** it **trust-on-first-use**: the first `secsec sync` to a server captures the host key's
  SPKI hash, **prints the fingerprint** for the user to verify out-of-band, and persists it as
  `host_id` in the folder's link; every later connection pins that stored value (a mismatch aborts).
  v1 ships TOFU only — there is no pre-seed flag — so the first contact is the trust anchor for the
  host identity. (Residual: §22 first-init TOFU window — a network attacker present at that first
  contact can substitute their host key; verify the printed fingerprint out-of-band.)
- **host_id definition:** `host_id = BLAKE3(canonical(server pinned SPKI bytes))`. `host_id` MUST
  be computed by the client from locally-pinned material and MUST NOT be accepted from the server.
- **Verifier (the top ship-broken risk):** the custom `rustls` `ServerCertVerifier` MUST compare
  leaf SPKI to the pin **and** fully implement `verify_tls13_signature` (never stub). Mandatory
  negative tests: wrong key fails; tampered handshake fails. Device keys are **Ed25519-only**:
  the verifier MUST reject any SSHSIG blob whose `sig_algorithm` field is not exactly
  `ssh-ed25519`. Any other algorithm field MUST cause verification failure regardless of
  cryptographic validity (a mandatory negative test).
- **Session transcript:** both ends maintain `session_transcript` = running BLAKE3 over the
  ordered, length-prefixed handshake messages, defined byte-exactly below. Binds the whole
  exchange against splicing/downgrade. The hasher is fed, in this fixed order:
    1. Client hello: `secsec_version: u16 ‖ client_nonce: [u8; 32]` (OS CSPRNG). Length-prefix
       `le32(2 + 32)`.
    2. Server hello: `secsec_version: u16 ‖ server_nonce: [u8; 32] ‖ host_id: [u8; 32]`.
       Length-prefix `le32(2 + 32 + 32)`.
  No other inputs are hashed; raw "pubkeys" are NOT injected — the server identity is bound via
  `host_id` and the channel via the TLS exporter. The client-contributed `client_nonce` ensures
  transcript uniqueness is not solely under server control.
- **Client→server auth:** the client signs (`secsec-auth-v1`) the canonical payload defined in
  §9.6: `channel_binding ‖ host_id ‖ session_transcript ‖ server_nonce`. The signed payload field
  order is authoritative in §9.6; this section cross-references it.
  - `channel_binding` = TLS 1.3 keying material exporter computed via `quinn`/`rustls`'s
    `exported_keying_material` API: `HKDF-Expand-Label(exporter_master_secret,
    "EXPORTER-Channel-Binding", "", 32)` per RFC 9266 §3 / RFC 8446 §7.5. Note: RFC 9266 does not
    formally define `tls-exporter` for QUIC transports (an acknowledged open gap); this usage is
    intentional and documented here. The `session_transcript` provides an additional application-
    layer binding; both are included.
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
| `put-keyslot(device_id,gen,blob)` | **`secsec-write-v1` sig** | write a device's keyslot at enrollment/rotation (§8.3); permitted from a not-yet-enrolled key **only** under the genesis-bootstrap exception (`roster_len == 0`) |
| `delete-keyslot(device_id,gen)` | **`secsec-write-v1` sig** | remove a revoked device's keyslot on rotation (§8.4) |
| `put-keyhist(gen,blob)` / `put-roster-keyhist(gen,blob)` | **`secsec-write-v1` sig** | store the §8.2 data- and roster-key-history forward-wraps minted by a rotation |
| `pair-put(slot,blob)` / `pair-get(slot)` | **`secsec-read-v1` sig** | §7 invite-pairing mailbox: a TTL'd relay of code-MAC'd blobs at `slot = BLAKE3(label ‖ code)`. Dispatched **pre-enrollment** (a joining device owns no keyslot yet); the server learns neither the code nor the contents |
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
(including `get`, `get-ref`, `has`, `put`, `cas-head`, `roster-append`, `put-keyslot`,
`delete-keyslot`, `put-keyhist`, `put-roster-keyhist`, `gc`), that a keyslot blob exists at
`/keyslots/<device_id>/<any_g>` where `device_id = BLAKE3(canonical(authenticated_pubkey))` from
the connection auth step. A request from a key with no stored keyslot MUST be rejected with a
distinct `not-enrolled` error code before any read or write is performed. This check uses
filesystem presence only and does not require decrypting the sigchain. The server MUST also verify
that per-op signatures are signed by the same public key that completed the `secsec-auth-v1`
challenge on the current connection. **Two exceptions, both bounded:** (a) `pair-put`/`pair-get` are
dispatched *before* this check — a joining device owns no keyslot yet — and are authorized by their
`secsec-read-v1` signature alone (their payload is independently code-MAC'd, §7); (b) the
**genesis-bootstrap exception** permits `roster-append`/`put-keyslot` from an unenrolled key **only
while the roster is empty** (`roster_len == 0`), letting the first device create the repo. Every
other op from an unenrolled key is rejected.

The server SHOULD re-verify keyslot existence on each per-op request and MUST do so at least once
per `server_nonce` TTL window (60 s, §19), closing the open-connection gap on cooperative
deployments. (A revoked device cannot authenticate new connections once its keyslot is deleted on
a cooperative server, or obtain new-generation master keys on a malicious server — bounded by the
gen-g residual, §22.)

The `authorized_keys` allow-list is the **mandatory** connection gate (§11): `secsec serve` refuses
to start without it and re-reads it per connection, so an unlisted key never reaches any op above. A
listed-but-unrostered key can open a socket and do nothing else — it owns no keyslot, so every op but
the two bounded exceptions above is rejected, and the server cannot mint a *valid*
(commitment-matching) keyslot for an injected key of its own. The write `args_hash` binds the exact
blob/op (the client constructs op/args; the server supplies only the nonce).

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

**Server.** All state lives in one file, `repo.secsec` (a `redb` database, not a directory tree — the
paths below are logical key namespaces inside it), in the directory passed to `secsec serve` (default
the current dir). Alongside it the server keeps its self-signed host identity (`hostkey/`) and receipt
key. All repo state is opaque:
```
/objects/<id>            packed encrypted blobs (chunk/tree/commit)
/keyslots/<device_id>/<g> versioned authenticated keyslots per device per generation
/refs/<H>                each device's signed head; H = BLAKE3::keyed_hash(ref_name_key, ref_name)
/roster-head             CAS-guarded sigchain tip
/roster/<seq>            encrypted, signed sigchain entries
/keyhist/<g>             data key-history wraps (§8.2)
/roster-keyhist/<g>      roster-key history wraps (§8.2; never trimmed)
/hostkey                 server self-signed host identity (first run)
```
(There is **no** `/recovery` namespace — recovery was removed, §8.6.) The transient invite-pairing
mailbox (§7) is **in-memory only**, never persisted: TTL'd slots keyed by `BLAKE3(label ‖ code)`.

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
The server-side `redb` index holds **only** `{id, size, generation, pack-offset}` — never
plaintext-derived metadata. One static binary; no external DB.

**Client.** The synced folder holds **nothing but the user's plaintext files** — no control files
clutter it. All per-folder client state lives out of tree under
`~/.local/state/secsec/<BLAKE3(abs_folder_path)>/`:
```
link            the repo binding (git-remote analogue): server address, pinned host_id, RFP, ref name
objects.secsec  the encrypted object cache (so a re-sync need not re-fetch/re-encrypt unchanged data)
frontier        the §8.5 local sealed state (anti-rollback counters), sealed under the SSH key
base, receipts  the last-synced root and the §15 arrival-receipt log (for auto-GC)
```
The object cache is encrypted (it is the same content-addressed blobs pushed to the server) and is a
*cache*, not the source of truth — the plaintext folder is. This is why no `redb` file sits in the
user's working directory.

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

**GC is automatic and client-driven — there is no `gc` command.** The blind server cannot compute
reachability (every head/commit/tree is ciphertext to it), so a client must initiate; but *which*
client and *when* is not a decision to push onto the user. `secsec sync` therefore runs one
best-effort GC pass per session (after the first sync): it fetches the reachable closure over its
ref, derives `gc_gen` from its own §15 arrival-receipt log (only generations whose every object has
aged past the `GC_GRACE_WINDOW`), and issues the compare-and-swap `gc` op below. A failure is
logged and skipped — never fatal to the sync. Retention is keep-everything until an object both
falls out of the keep-set and ages past the grace window; nothing is deleted silently. The
mechanism is unchanged from prior drafts; only the *trigger* moved from a manual command into the
sync loop.

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
  `all_heads_hash = BLAKE3(le64(n) ‖ (ref_H[0] ‖ head_blob_hash[0]) ‖ … ‖ (ref_H[n-1] ‖ head_blob_hash[n-1]))`
  is computed over all `n` active refs, the pairs sorted by `ref_H` in ascending byte-lexicographic
  order, where `head_blob_hash = BLAKE3(stored §9.8 head blob)` — the **server-visible** per-ref token
  (the same value `cas-head` compares on, §12). It MUST be the blob hash, **not** `head_version`: the
  blind server cannot read the encrypted `head_version`, so it could not recompute the hash to verify
  the compare-and-swap; the blob hash is computable by both sides from the stored bytes, and any
  concurrent `cas-head` changes it (a single scalar cannot serialize a multi-ref repo; the aggregate
  does). `put_epoch` is a single **global (per-repository) monotonic counter**
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

**X-Wing decapsulation-key seed (normative).** The X-Wing secret key is a **single 32-byte seed**
`sk`; the ML-KEM and X25519 secrets are *derived* from it (draft-connolly-cfrg-xwing-kem-10 §6
`expandDecapsulationKey`), never drawn independently:
```
expanded = SHAKE256(sk, 96)                      // 96 bytes
(d, z)   = expanded[0:32], expanded[32:64]       // ML-KEM-768 KeyGen_internal seed
sk_X     = expanded[64:96]                        // X25519 static secret
pk_X     = X25519(sk_X, X25519_BASE)
```

**X-Wing combiner (normative):**
```
ss = SHA3-256(
    ss_MLKEM  ‖       // 32 B: ML-KEM-768 shared secret
    ss_X25519 ‖       // 32 B: X25519 shared secret
    ct_X      ‖       // 32 B: X25519 ephemeral public key (ciphertext)
    pk_X      ‖       // 32 B: recipient X25519 static public key
    0x5c2e2f2f5e5c    // 6-byte domain label (XWingLabel, LAST per draft-10 §6)
)
keyslot_ct = ct_MLKEM(1088 B) ‖ ct_X(32 B)   // total: 1120 B
// encapsulation randomness eseed(64 B): m = eseed[0:32] (ML-KEM), ek_X = eseed[32:64] (X25519)
```

All inputs are fixed-width (32+32+32+32+6 = 134 bytes); the **label-last** order is normative per
draft-connolly-cfrg-xwing-kem-10 §6 (the obsolete draft-02 placed it first — do not use that order).
Implementations MUST verify a byte-identical shared secret against the draft-10 Appendix C test
vectors before being accepted as conformant. (Cross-check: seed
`7f9c2ba4…ef26`, eseed `3cb1eea9…85b2` ⇒ ss `d2df0522…e384`.)

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

The hybrid-PQ keyslot is **mandatory and the only keyslot** (§8.3): every keyslot — at `init`, `grant`,
and every `rotate` — is X-Wing, so the harvestable asymmetric exposure is post-quantum by default, not
opt-in. **Signatures**, by contrast, remain classical (Ed25519): forgery is *online*, not harvestable
(an attacker needs the quantum computer at the moment of the attack, and a recorded signature broken
later is worthless), so a PQ signature is lower urgency and is added later via the same `algo_id` /
`SetMinAlgo` agility when quantum is imminent. Confidentiality (the symmetric data plane + the X-Wing
keyslot) is the harvest-now-decrypt-later target, and it is PQ-safe today.
## 18. Implementation hardening

- **Memory:** `master_key`, all derived subkeys, SSH private material → `secrecy`
  wrappers, `zeroize` on drop, `mlock` where supported; never serialized to disk.
- **Constant-time:** all tag/commit/MAC/invite-code-MAC/fingerprint comparisons via `subtle`.
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
| Device key algorithm | **Ed25519 only** | RSA/ECDSA/`sk-*` keys are rejected at parse (v1 scope) |
| Connection gate | `~/.ssh/authorized_keys`, re-read per connection, fail-closed | mandatory — `secsec serve` refuses to start without a usable key (§11, §12) |
| Keyslot KEM (mandatory) | **X-Wing** (ML-KEM-768 ⊕ X25519, draft-connolly-cfrg-xwing-kem-10), `algo_id = 2`; CTX AEAD AD = "secsec-keyslot-v1" ‖ canonical(device_id) ‖ le32(gen); device X-Wing seed = `derive_key("secsec-xwing-seed-v1", ed25519_seed)` | post-quantum mandatory — the only keyslot algorithm; classical X25519/HPKE removed (§8.3). Floor enforced at cold-start (§16) |
| Durability quorum | 2 remotes (put→get→verify round-trip each) | availability under hostile server |
| Retention | keep-all; prune opt-in | no silent deletion |
| Invite code length | 96 bits (12 bytes, OS CSPRNG), single-use; displayed as dash-grouped lowercase hex | the §7 out-of-band pairing secret; single-use + the mailbox TTL + the `authorized_keys` gate bound online guessing. Replaces the older 20-bit human-compared SAS |
| Pairing mailbox TTL (`PAIR_TTL`) | 600 s | server-side lifetime of an invite-pairing slot; an expired or consumed slot ends the exchange (§7, §12) |
| Pairing mailbox slot cap / poll | 256 slots / 500 ms poll | bounds mailbox memory; pairing blobs are also charged against the connecting key's write-rate bucket (anti-flood) |
| Max has() IDs per call | 1,024 | server rejects with too-many-ids before any lookup |
| Max gc() keep-set IDs per call | 100,000 | server rejects before processing |
| Max gc() calls per key per hour | 4 | server MUST enforce; prevents disk-scan amplification; 4 calls/hour supports normal operation (daily GC in batches of up to 100,000 IDs each) while blocking sustained scan abuse |
| keep_set_hash canonical encoding | BLAKE3(le64(count) ‖ id[0] ‖ … ‖ id[count-1]), IDs in ascending byte-lexicographic order | normative for gc() args_hash (§15); both client and server MUST use this exact encoding; test vector required |
| Max sigchain entries per authenticated connection identity per hour | 60 | server enforces by counting roster-append calls per BLAKE3(authenticated_pubkey); server does not decrypt the entry to read the inner signer field; server MUST enforce at roster-append |
| Max total sigchain length | 10,000 entries (configurable) | server MUST enforce |
| Key-history depth (generations) | unbounded (never trimmed) | both the data and roster key-histories keep one 64-byte wrap per generation; total is bounded by the sigchain-length cap (§8.2) |
| Max blob size (any object type) | 16 MiB | decoders reject before allocating |
| Max tree depth | 64 levels | decoders reject before allocating |
| Max tree fan-out per node | 65,536 entries | decoders reject before allocating |
| Max roster entry size | 4 KiB | decoders reject before allocating |
| Max list fields (sigchain, keyhist, etc.) | 4,096 elements | decoders reject before allocating |
## 20. Build order

1. Object store: framing + canonical serialization + per-object-key committing AEAD (CTX/CMT-4) +
   content-address verify + push/pull/restore.
2. Roster sigchain + keyslots + enrollment (RFP anchor, `mk_commit` verification) +
   generations/rotation + write-auth gate + read-auth gate (secsec-read-v1).
3. Refs (keyed-hash paths) + `cas-head` + rollback-aware three-way merge.
4. `notify` watcher → live sync; conflict surfacing.
5. Multi-remote replication + reconciliation (cross-remote sigchain check); hardened GC (receipts +
   serialization), run automatically inside the sync loop; fork-detection alarms + gossip.
6. Downgrade/min-algo enforcement (per-fetch check, not creation-only). Local sealed state
   (SSH-key-derived seal). `authorized_keys` mandatory connection gate (§11).
7. Hybrid-PQ keyslot (X-Wing, **mandatory** — §17). Networked enrollment over the wire:
   invite-code pairing (`secsec invite` / `sync --invite`), networked `revoke`, and `devices`.

## 21. Crates

`quinn`,`rustls` · `ssh-key`(SSHSIG, Ed25519-only),`ed25519-dalek`,`x25519-dalek` · `libcrux-ml-kem`
(ML-KEM-768 for the X-Wing keyslot),`sha3` · `blake3` · `chacha20`+`poly1305` (the §9.4 CTX
committing AEAD) · `fastcdc` · `notify` · `redb` · `tokio` · `zeroize`,`subtle`,`getrandom`.
Transport is **QUIC/TLS-only** (no SSH/stdio mode — it adds nothing over the pinned host key, §11).
(`argon2` was dropped with the recovery keyslot, §8.6.) Versions pinned; `cargo-audit`/`cargo-vet`
gated.

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

- **Total credential loss.** A user who loses *every* enrolled device **and** every backup of the
  SSH key cannot recover — information-theoretic. Mitigation: back up the SSH private key (the one
  credential); any device holding it is a full replica and re-joins via an invite (§7). There is
  deliberately **no** server-stored recovery blob (§8.6) — adding one would create an
  offline-crackable target on the untrusted server to back up what the SSH key already covers.

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

- **First-init TOFU window.** The first `secsec sync` to a server accepts the host key on first use:
  it captures the key's SPKI hash and prints the fingerprint for a one-time human comparison that is
  not mechanically enforced. A network attacker present at that first contact can substitute their
  own host key; once accepted, all subsequent connections verify against the attacker's key, giving
  them a persistent MITM position. Mitigation: verify the printed fingerprint out-of-band before
  continuing. (A joining device additionally re-derives this exposure away: the inviting member
  vouches for the genuine `host_id` under the invite-code MAC, and the joiner aborts if it does not
  match the server it connected to — §7.) The window is bounded to the first contact — after the
  pin is persisted in the folder's link, no further TOFU exposure exists.

---

## 23. Design review & closure

An independent end-to-end trace of the design (the former `finalrew.md`). These held up under review:

- **CTX/CMT-4 AEAD (§9.4)** — `T` recomputed not stored, binds K/N/A/M; `nonce=0` is safe because
  `k_obj` is unique per object. The three-phase decrypt is correct.
- **Content-addressing ↔ key derivation** has no circularity (id from plaintext → `k_obj` from id →
  re-verify id on fetch).
- **KDF domain separation (§9.5)** — distinct labels, fixed-width `le32(g)‖u8(t)`, the `mk_commit`
  keyed_hash exception is correctly called out.
- **Signature namespacing (§9.6)** — server-chosen nonces confined to auth/write; cross-protocol
  reuse is genuinely closed.
- **Enrollment (§7)** — the shipped path is **invite-code pairing**: a single-use 96-bit code,
  carried out-of-band, MACs the key-exchange end-to-end through the blind server's TTL'd mailbox
  (server never learns the code), the joiner confirms the inviter-vouched `host_id` against its
  TOFU pin, and the `mk_commit` highest-seq check anchors the unwrapped key to RFP. The
  fake-universe attack is closed without any human digit comparison. Layered under the mandatory
  `authorized_keys` connection gate (§11). (The lower-level direct-grant primitive's
  `secsec-grant-v1`/`enrollment_nonce` attestation, §9.6, remains for non-mailbox enrollment.)
- **X-Wing keyslot (`secsec-pq`)** — draft-10 conformant: single 32-byte seed expanded via
  `SHAKE256(sk,96)` to the ML-KEM `(d,z)` seed + X25519 `sk_X`; **label-LAST** combiner
  `SHA3-256(ss_M‖ss_X‖ct_X‖pk_X‖XWingLabel)`; verified byte-identical to the draft-10 Appendix C
  vector (`xwing_kat`, not ignored). (An earlier draft of this review and §17 wrongly said
  label-first — the obsolete draft-02 order; fixed.)
- **Keep-everything default + multi-remote** makes the GC blast radius small and honest.

The residuals in §22 are honest and genuinely minimal.

**The flagged gaps — with resolution (closed 2026-06-10):**

- **[HIGH → DOCUMENTED as a §22 residual] Concurrent mutual revocation has no tiebreak** — a stolen,
  online device can win the CAS race and lock out the legitimate one. All devices are flat, equal
  members; there is no privileged founder. When E does `RevokeDevice(B)+Rotate`, a compromised online
  B can concurrently do `RevokeDevice(E)+Rotate`; the `/roster-head` CAS serializes them and whoever
  lands first wins. It only bites when the stolen device is unlocked, online, and racing (in which
  case it already had data access). **Resolution:** the flat model is retained by design (there is no
  privileged founder — "the SSH key is the only credential"); the race is now explicitly acknowledged
  as the **concurrent mutual-revocation residual** in §22 and on the P7 row (§3 "revoked device"
  adversary). The privileged-founder / recovery-code-authorized-revocation alternative was considered
  and deliberately not adopted (it would break the flat single-user model). Documented, not silently
  undercutting P7.
- **[RESOLVED — removed] HistoryReanchor broke sigchain folding** — trimming key-history below
  `drop_before_gen` left a freshly-enrolled device unable to derive `roster_key_g` for the dropped
  generations, so it couldn't verify succession from genesis. Rather than add a signed
  membership-snapshot baseline, the op was **removed entirely**: both key-histories are now
  never-trimmed (64 bytes/generation, negligible for a single-user repo). The hazard is gone with the
  feature. It was never implemented in code.
- **[LOW → RESOLVED] Spec-completeness items:**
  - Cold-boot bootstrap order — now stated and implemented (§8.1 step 1): read the tip entry's
    plaintext `FRAME.gen` → fetch that keyslot → decrypt the tip → peel.
  - The client learns the current `put_epoch` from its persisted §15 arrival-receipt log, bound into
    the GC compare-and-swap.
  - The root tree/commit `path_salt` is the commit's `root_salt` field (commits seal under
    `ZERO_SALT`); every non-root salt lives in its parent tree.
  - Local-state-file rollback by a disk-level attacker is documented as subsumed by "client
    compromise = total" (§22).

**UX redesign (2026-06-10) — security held, ergonomics improved.** The credential model was reworked
without weakening any §4 claim: (1) `~/.ssh/authorized_keys` became a **mandatory** server-side
connection gate (§11), closing the "first connector seizes an empty repo" race that a network-only
model exposed — layered over, never replacing, the keyslot roster; (2) device onboarding moved fully
over the wire via **invite-code pairing** (§7), replacing the manual fingerprint+SAS ceremony with a
single carried 96-bit code (higher entropy, no human digit comparison); (3) **recovery was removed**
entirely (§8.6) as a net liability — the SSH key is credential and backup; (4) **GC became automatic**
inside the sync loop (§15) rather than a manual command; (5) revocation is now a networked
`revoke`/`devices` pair (§8.4). The CLI is `serve · sync · invite · devices · revoke`; the client
keeps no control files in the synced folder (§13). The genesis-bootstrap exception (§12) and the
invite-code MAC (§7) were the two mechanisms added; both were adversarially traced above.

**Verdict.** Crypto and data-plane: built and tested. Revocation/key-management: the mutual-revocation
race is documented as a §22 residual (the flat model is intentional); the reanchor/fold hazard was
removed with the feature. The UX redesign preserved every §4 guarantee. All flagged items are
resolved or consciously documented — nothing open.

---

## Provenance

This specification is the settled output of several adversarial security-review rounds; the
review's end-to-end trace and gap closure are folded into §23 above. Every normative requirement
stands on its own. Constants in §19 are normative and required for conformance.
