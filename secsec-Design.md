# secsec: Design

A self-hosted, end-to-end-encrypted, **live two-way** file-sync system (server + client),
single Rust binary. The server is **blind**: it stores only ciphertext and never learns file
contents, names, or directory structure beyond a bounded, documented residual (§21). The only
credential is an SSH key. This document is the authoritative spec. The crate structure,
dependencies, and assurance strategy are in `secsec-Implementation.md`.

> Design principle: **every security claim in §4 is paired with the exact mechanism that
> provides it.** Anything not so backed is not claimed, and anything specified but not built is
> marked **NOT WIRED**. The items deferred to "residual" are *proven-minimal*: impossibilities for
> a blind, untrusted server, or chosen tradeoffs, each stated in §21.

---

## 1. Usecase

- **Single user**, many devices; each device has its own SSH key.
- **Live two-way sync**: edit on any device, changes propagate, conflicts resolved with no
  silent data loss; version history is a by-product (bounded by retention, §15).
- **Zero-knowledge** against an untrusted server: content **and** metadata encrypted.
- **Self-hosted, one binary**, no external database, no user-managed certificates, minimal deps.
- **SSH key is the only required configuration and the only credential.** The operator lists
  permitted device public keys in the server's `~/.ssh/authorized_keys` (the mandatory connection
  gate, §11); each device holds its `~/.ssh/id_ed25519`. Device onboarding is a first-class flow
  (genesis for the first device, a one-time **invite code** for the rest, §7). There is **no
  separate recovery secret**: the SSH key is both the credential and the backup, and a device that
  holds it can re-join from any peer via an invite.

## 2. Non-goals

- Multi-tenant hosting; provider-side search/indexing.
- **Multi-server replication / quorum durability.** secsec is **single-host**: one repo lives on one
  blind server. A hostile or dead server is an availability event only; the mitigation is that every
  enrolled device holds the working set and the SSH key is the backup (§14, §21), not server-side
  replication.
- **Multiple synced trees per repo.** One repo holds **exactly one** synced tree, under the single
  ref `main`; there is no `--name`/multi-ref capability. Two devices converge on `main` regardless of
  their local folder names. An independent tree is an independent repo (its own genesis/RFP), which,
  since one server store carries one roster sigchain, means its own server store.
- Hiding the bounded metadata of §21 (object sizes, timing, equality): reduced, not eliminated.

> **Scope.** secsec is single-host: `secsec sync` takes one `--server`, and every guarantee in §4
> holds against that one blind server. One repo = one synced tree (ref `main`). The whole CLI is
> `serve · sync · stop · status · invite · devices · revoke · hostpin · log · restore · reset`.
> A fork (two DAG-incomparable heads) is reconciled by the keep-both three-way merge (§10).

## 3. Threat model

Adversaries: a **malicious/compromised server** (the primary one), a **network attacker**, a
**revoked device**, and a **stolen client**. We assume the device's SSH key and the user's
out-of-band channel (carrying an invite code or reading a host pin off a screen) are trustworthy;
everything else, including the server and the network, is hostile.

A key not listed in the server's `~/.ssh/authorized_keys` cannot hold a connection at all (§11):
the mandatory connection gate. This gate is necessary but **not** sufficient for data access: even
a listed key reads or writes nothing without a keyslot (§12), so the security claims below never
rest on the gate alone.

What the server sees: framed ciphertext; object byte-sizes (chunk sizes bucketed by padding, §9.7;
tree, commit, head, and roster-entry sizes exact, §21); the set of device IDs (opaque); access
timing. Nothing else.

---

## 4. Security properties (claim ⇄ mechanism)

Each row is a guarantee and the mechanism that earns it. Residuals in §21.

| # | Guarantee | Mechanism |
|---|---|---|
| P1 | Server cannot read content or metadata | Per-object fully-committing (CMT-4) AEAD; metadata lives inside encrypted tree/commit blobs (§9); roster entries encrypted per entry under a salted per-seal key with the CTX/CMT-4 construction (§9.5). Object sizes are the bounded residual (§21) |
| P2 | Server cannot alter an object without detection | Content-addressing re-verified on fetch + CTX tag + FRAME match (§9.2 to §9.4) |
| P3 | Server cannot forge a commit/head/roster entry | All signed via SSHSIG with disjoint namespaces; verified against the roster (§9.6, §8) |
| P4 | Server cannot feed a new/reinstalled device a **forged repository or key** | Out-of-band **RFP** anchor + `mk_commit` verification of any unwrapped master key (§7); for a *joining* device, a single-use **invite code** authenticates the enrollment exchange end-to-end through the blind server (MAC under the code, which the server never learns, §7), and the joiner confirms the inviter-vouched `host_id` equals the server it actually connected to |
| P5 | A connection ≠ the ability to read or write; unlisted keys cannot hold a connection, and listed-but-unenrolled keys are rejected before any data access | **Two layers:** (a) the server refuses a connection from a key absent from `~/.ssh/authorized_keys`, checked at connect and again on the first request after 60 s since the last check (§11); (b) every repo RPC, reads included, requires a per-op signature from a key that owns a keyslot, checked on **every** request against `/keyslots/<device_id>/<any g>` (§9.6, §11, §12). A revoked device is refused on its next request once the revocation batch deletes its keyslots (§8.4); on a malicious server keyslot deletion cannot be enforced (§21) |
| P6 | Revocation removes access to data created after rotation (forward secrecy) | revoke ⇒ rotate: new master-key generation, re-wrap to remaining devices, delete every keyslot of the revoked devices, one atomic batch (§8.4); pre-rotation ciphertext remains a residual (§21) |
| P7 | Revocations cannot be lost or rolled back **by the untrusted server** | Roster is an append-only, hash-chained, signed sigchain with succession, plus a persisted anti-rollback anchor (§8.1). (Eviction of the legitimate device by a *compromised, online* peer racing the tip CAS is a separate adversary: the concurrent mutual-revocation residual, §21) |
| P8 | Rollback/replay of sigchain and head state is detected | The same-server sigchain anti-rollback (persisted seq + tip-blob hash, §8.1); a local frontier sealed under a key derived from **private** key material (§8.5); rollback gates reject a replayed head or commit below the persisted frontier on every path that adopts a sibling (§10). A DAG-incomparable sibling (a fork) is reconciled keep-both by the three-way merge, never silently dropped (§10) |
| P9 | No cross-protocol signature reuse | Disjoint SSHSIG namespaces; server-chosen nonces confined to `auth`/`write` (§9.6) |
| P10 | No catastrophic AEAD misuse / key-confusion for object, keyslot, roster-entry, and key-history wraps | A key unique per sealing with a fixed nonce and the CTX commitment (§9.4): per-object keys, per-seal salted roster-entry keys (§9.5), fresh KEM secrets for keyslots (§8.3), per-generation key-history keys (§8.2) |
| P11 | Forward secrecy after revocation | Post-rotation data uses a new generation the revoked device cannot derive (§8.4) |
| P12 | Transport is authenticated without a CA; a first-contact TOFU window is a documented residual | TLS 1.3 to a pinned self-signed host key, pinned up front with `sync --pin` or trust-on-first-use on the first `sync` (the host pin is printed for out-of-band confirmation), then persisted in the folder link; channel-bound auth (§11). A *joining* device additionally checks `host_id` under the invite-code MAC (§7). The TOFU window is a residual (§21) |
| P13 | No algorithm/format downgrade | Pinned TLS & signature algorithms; a compile-time `algo_id`/`format_version` floor (§16); a keyslot of an algorithm this build does not speak, or a sigchain `min_algo` above it, stops the client instead of degrading (§16) |
| P14 | No server-stored recovery blob to crack; lockout is avoided by backing up the SSH key, not a second secret | The SSH key is both credential and backup. A reinstalled device re-joins via an invite from any peer (§7). Losing *every* device **and** the SSH key is unrecoverable by construction: the §21 total-loss residual. There is no server-stored recovery secret (§8.6) |

---
## 5. Identifiers & trust anchor

- **Device key**: an **Ed25519** SSH keypair per device (Ed25519-only). secsec loads the private key
  file (decrypting a passphrase-protected one in memory) and uses it in-process for both roles:
  *sign* (SSHSIG) and *unwrap* (the X-Wing keyslot key is derived from the Ed25519 seed, §8.3). An
  SSH agent or hardware token cannot serve either role. `ecdsa`/`sk-*`/RSA keys are rejected when
  loaded, so they cannot enroll.
- **`device_id`** := `BLAKE3(canonical(device_pubkey))`. Cryptographically bound to the key;
  every commit/head/roster entry is verified by checking its signature against the pubkey that
  the roster maps this id to. A signer can never act under another device's id.
- **`master_key`**: 256-bit, random, generated when the first device creates the repo, **RAM-only
  on clients, never written to disk**, held in `Zeroizing` (zeroized on drop). (Page-pinning via
  `mlock` is **NOT WIRED**; §18.) It has a **generation** `g` (starts at 1) advanced by rotation.
- **`mk_commit_g`** := `BLAKE3::keyed_hash(master_key_g, "secsec-mk-commit-v1" ‖ le32(g))`: a
  hiding, binding commitment recorded in the sigchain. Here `master_key_g` occupies the BLAKE3
  PRF **key** argument (not the IKM/message role); this is the only place where `master_key_g`
  serves as a BLAKE3 key argument. Binding `g` into the input prevents the commitment from one
  generation passing verification for a different generation. It lets any holder of a candidate
  key prove it is the genuine generation-`g` master key without the server being able to forge one.
- **`host_id`**: server identity token bound into connection auth and the session transcript.
  Computed by the client from locally-pinned material; MUST NOT be accepted from the server.
  - `host_id = BLAKE3(SPKI)`, where the SPKI bytes are the SubjectPublicKeyInfo DER of the pinned
    server certificate's public key (QUIC/TLS is the only transport). The CLI calls it the
    **host pin**.
- **RFP (Repository FingerPrint)** := `BLAKE3(canonical(genesis sigchain entry))`. The genesis
  transitively commits to device-1's key and to `mk_commit_1`. **RFP is the one out-of-band
  anchor**: established when the first device creates the repo, and delivered to each joining
  device **inside the invite code's authenticated pairing exchange** (§7): the inviting member
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

Files split by **keyed FastCDC-style chunking** (§9.7). (Small-chunk **packing** into 8 MiB packs is
**NOT WIRED**: each chunk is stored as its own object; §19.) Trees/commits/roster are blobs in the
same store, so the server learns no structure beyond the bounded metadata of §21.

The synced object model is **regular files and directories only**. A symlink, FIFO, socket, or
device node in the working folder is **skipped**: not synced, and **not** an error (a single such
entry must never fail the whole snapshot). The recorded `mode` is the 9 standard permission bits
only: file-type bits are redundant (the entry kind already distinguishes file vs directory) and the
**setuid / setgid / sticky** bits are deliberately dropped on both snapshot and restore (§18), so a
compromised member cannot author a tree that plants a setuid/setgid file on every device. Tree entry
names are a single path component: never empty, `.`/`..`, a path separator, or a control character
(§18 path-traversal and terminal-escape guards). A working-folder entry whose name is **not** a
valid tree entry name (non-UTF-8, one of the above, or a restore temp name `.secsec-tmp-*`) is
**skipped** on snapshot exactly like a symlink, symmetric with the decode-side guard, so an
unsyncable name is never authored (macOS's `Icon\r` custom-folder-icon file, for one, is silently
not synced rather than failing the snapshot, and a restore leaves it in place, §10).

**Every §19 decoder bound is enforced symmetrically on the write side**, so a snapshot can never
author an object no device (the author included) is able to decode:
- A file needing more than the §19 chunk-id cap, or a file or directory that cannot be read, is
  **skipped and reported to the user**. If the path was already synced it keeps its **previous** tree
  entry: an omitted name reaches every other device as a *deletion*, so a file that outgrows the limit
  freezes at its last syncable version rather than disappearing from everyone's folder.
- A directory that would exceed the fan-out cap or whose encoded tree would exceed the object cap is
  a hard **error** naming the directory. Neither is attributable to one entry, and silently truncating
  a directory would read as a bulk deletion downstream.
- An entry this device's filesystem cannot create (OS name rules) is skipped on restore and rides
  forward unchanged in the next snapshot, so it never reads as a deletion.

---

## 7. Trust bootstrap & device enrollment

**Why enrollment needs an out-of-band anchor.** A keyslot is a wrap *to a device's public key*;
anyone who knows that public key, the server included, can fabricate a keyslot wrapping a **fake**
master key, handing a fresh device a fake key and a fully self-consistent **fake repository**
(attacker-chosen files). Possession of a keyslot therefore cannot by itself prove authenticity.
Enrollment instead authenticates the *master key itself* against an out-of-band anchor (RFP).

**Creating the repo (first device).** The first device runs `secsec sync <dir> --server host[:port]`
(optionally `--pin <host pin>`) with **no** `--invite`. It:
1. Generates `master_key_1`; computes `mk_commit_1`.
2. Writes, in **one atomic `roster-batch`** (§12), the genesis sigchain entry (seq 0, self-signed,
   recording device-1's pubkey, its X-Wing public key, and `mk_commit_1`) **and** its own X-Wing
   keyslot wrapping `master_key_1`. The server admits this batch from a not-yet-enrolled key under
   the **genesis-bootstrap exception** (§12): exactly this shape (one entry, one keyslot owned by the
   signer, nothing else, onto an empty roster) and only while the roster is empty. Combined with the
   `authorized_keys` gate (§11), only a key the operator listed can reach this path, which closes the
   "whoever connects first seizes an empty repo" race. The genesis batch also purges any keyslot that
   predates it.
3. The genesis fixes **RFP** = `BLAKE3(canonical(genesis))`. RFP is persisted in the folder's link
   and later handed to joining devices via the invite exchange below; the user never transcribes it.

(On first contact without `--pin`, the device prints the server's host pin for out-of-band
confirmation, then pins it: TOFU, §11.)

**Adding a device: invite-code pairing.** Onboarding the second/third/… device needs exactly one
out-of-band secret: a single-use **invite code**. One carried 96-bit code authenticates the whole
key exchange *mechanically*, so there is no digit-by-digit human comparison to mis-read, and no
grinding window to defend against.

Operator (one-time): add D's SSH **public** key to the server's `~/.ssh/authorized_keys` so D can
connect at all (§11). On the **inviting** (enrolled, online) device E: `secsec invite <dir>` prints a
one-time code and the join command, and waits. On the **joining** device D:
`secsec sync <dir> --server host[:port] --pin <host pin> --invite` (prompting for the code).

The pairing protocol relays every message through the server's transient, TTL'd **pairing
mailbox** (`pair-put`/`pair-get`, §12). Slot ids are `BLAKE3::derive_key("secsec-pair-slot-d-v1",
code)` and `BLAKE3::derive_key("secsec-pair-slot-e-v1", code)`, so the server cannot reverse them.
Every message is MAC'd under `mac_key = BLAKE3::derive_key("secsec-pair-mac-v2", code)`, over a label
byte and length-framed parts: `MAC(label, parts) = BLAKE3::keyed_hash(mac_key, label ‖ (le64(len(p))
‖ p)…)`, so part boundaries cannot shift.

1. **D → slot `d`:** `bytes(D_pubkey) ‖ bytes(D_xwing_pub) ‖ tag_d` with
   `tag_d = MAC('d', [canonical(D_pubkey), D_xwing_pub])`. Only a code-holder can produce `tag_d`,
   so the server cannot substitute D's key.
2. **E** takes slot `d`, verifies `tag_d`, validates D's X-Wing public key, then runs the networked
   grant: one `roster-batch` appending `AddDevice(D_pubkey, mk_commit_g, D_xwing_pub)` onto the
   sigchain tip (tip CAS) together with D's X-Wing **keyslot** wrapping `master_key_g` (§8.3),
   refolding and retrying while the tip moves. E then posts **slot `e`:** `RFP ‖ host_id ‖ tag_e`
   with `tag_e = MAC('e', [RFP, host_id])`.
3. **D** takes slot `e`, verifies `tag_e`, and learns the genuine RFP and the `host_id` E vouches
   for. D **confirms `host_id` equals the server it actually connected to** (its pin, §11); a
   mismatch is a possible MITM and aborts. D then cold-starts (below) and unwraps the keyslot E
   wrote, verifying it against `mk_commit`: a forged keyslot fails.

Why this defeats the blind server: the mailbox blobs are MAC'd, not encrypted (the server can read
the public keys, RFP, and `host_id` it relays), but the server never learns the code, so it cannot
forge `tag_d`/`tag_e`, swap D's key (P4), or substitute RFP or `host_id`. A `pair-get` takes the
message (a slot is delivered once), slots expire after `PAIR_TTL` (§19), and the code is never
reused. Online code-guessing is the only residual attack surface and is infeasible: a 96-bit code,
single-use, behind the `authorized_keys` connection gate (§11), with the mailbox capped at 256 slots
and charged against the connecting key's rate limits (§12, §19). The gate and the code are
complementary layers: the gate keeps unlisted keys off the mailbox entirely; the code authenticates
the exchange among listed keys; neither alone suffices.

**D's cold-start (and every reinstall): authenticity without trusting the server:**
1. D has **RFP**: from the pairing exchange (step 3) on first join, or from its persisted
   per-folder link on every later sync.
2. D fetches the sigchain and its keyslot at the tip's generation, unwraps it to a candidate
   `master_key_{g_cur}`, and folds the chain (§8.1): genesis must hash to **RFP** and every entry
   must pass succession. A server-forged chain fails the RFP match.
3. D **verifies `BLAKE3::keyed_hash(candidate, "secsec-mk-commit-v1" ‖ le32(g_cur)) ==
   mk_commit_{g_cur}`**, the commitment recorded by genesis (`g = 1`) or by the `Rotate` that created
   `g_cur` in the RFP-anchored chain (every `AddDevice` must carry the same current value or the fold
   rejects it). A server-forged keyslot (fake key) fails this check, so D refuses.
4. Only then does D trust the repo. The server can withhold or stale data (availability) but can
   never substitute a fake key or fake universe.

This reduces the unavoidable residual to **freshness only** on a state-less reinstall (cannot
prove "latest" without prior memory or a peer, §21), never authenticity.

---
## 8. Roster sigchain & key management

### 8.1 The roster is an append-only signed sigchain

```
Entry { seq:u64, prev:hash, op, ts, signer:device_id, sig }
  sig  = SSHSIG("secsec-roster-v1", canonical(seq ‖ prev ‖ op ‖ ts ‖ signer))
  prev = BLAKE3(canonical(entry[seq-1]))      // 0 for genesis
ops: Genesis | AddDevice | RevokeDevice | Rotate | SetMinAlgo
```

- **Succession:** entry `n` is valid iff `signer` is a *current member* of the state folded from
  entries `0..n-1`. Genesis self-authorizes device 1. The server can neither read the chain
  (entries are encrypted, §9.5) nor forge succession.
- **Fold → state:** a device is a member iff it has an `AddDevice`/genesis and no later
  `RevokeDevice`; generation = #`Rotate`+1; `min_algo` = max over `SetMinAlgo`. An `AddDevice` must
  record the current generation's `mk_commit`. The fold also keeps every device ever admitted
  (`ever_members`), so a revoked device's historical commits still verify.
- **No lost revoke:** updates *append*. The server applies each sigchain operation as one
  `roster-batch` under a compare-and-swap on `BLAKE3` of the stored tip entry blob (the absent-tip
  sentinel for genesis). On a CAS race the loser refolds onto the new tip and re-appends, retrying
  while the tip (or the head a revocation re-signs) keeps moving; a conflict against an unchanged
  state, or any other refusal, ends the attempt with an error for the user to rerun. (A CAS winner
  whose entry *revokes the retrying device itself*, a compromised online peer evicting the
  legitimate device, makes that retry fail succession: the §21 concurrent mutual-revocation
  residual, not a lost honest revoke.)
- **Revoke-before-add race:** an `AddDevice(C)` entry authored by a device B that is the subject of a
  concurrent `RevokeDevice(B)` is invalid when those two entries are ordered, regardless of which won
  the CAS. The revoking device additionally computes the **transitive add-by closure** of B over the
  folded roster (every current member B added, every member *those* devices added, and so on),
  restricted to grants at or after the revoking device's reference point, and appends
  `RevokeDevice` for each device in that closure in the same batch as the rotation (§8.4). One level
  is insufficient: a compromised B can add C and have C add E, so revoking only B's direct grants
  would leave the nested sleeper E to survive the rotation. The reference point is one past the
  highest sigchain seq this device had verified (its persisted anchor, below): a grant it had already
  witnessed was accepted under prior trust. The walk passes through earlier grants to reach later
  ones, and never collects the revoker itself.
- **Anti-rollback:** clients persist `(max seq, tip hash)` and reject any chain that does not extend
  it, or whose genesis ≠ pinned RFP. The cold start (`open_repo_remote`) carries a persisted
  `RosterAnchor` (the highest accepted seq and the BLAKE3 of the *stored* sealed entry blob at that
  seq) in the per-folder link, and refuses a fetched chain whose blob at that seq does not hash to it.
  The stored-blob hash is used instead of a plaintext entry hash so the check needs no decryption; it
  is equally rollback- and re-fork-sound. This closes P7 against a malicious **server**; a
  disk-level rewrite of the link is the §21 client-compromise residual.
- **Tip-hash consistency:** after fetching a chain of length M, the client verifies that the stored
  blob at `stored_max_seq` hashes to `stored_tip_hash` before accepting any entry beyond it. Only if
  this check passes does the client extend its anchor to `(M-1, BLAKE3(stored tip blob))`. A forked
  chain re-chained from an earlier entry diverges at the stored anchor and is rejected.
- **Sigchain volume limits** (server-enforced at `roster-batch`): at most 60 entries per
  **authenticated key** (`device_id`) per trailing hour, counted per appended entry and refunded when
  a batch loses its CAS; at most 10,000 total sigchain entries (compiled in). The server needs no
  decryption to count. The client refuses a fetched chain past the same total. These limits do not
  weaken anti-rollback: retried revocations are bounded but succeed within minutes.

**Roster entry AEAD.** Each sigchain entry plaintext is encrypted before storage under a per-seal,
**generation-indexed**, salted key with the CTX/CMT-4 construction; full normative spec in §9.5
("Roster entry AEAD"). The entry's FRAME carries the generation `g` it was written under; decrypting
entries that span generations (required to fold the chain) is defined in §9.5.

**Cold-start fold order (normative).** A device with no local roster state (fresh enrollment or
reinstall) bootstraps the chain as follows: (1) fetch the whole chain and check it extends the
persisted anchor, if any; (2) read the tip entry's plaintext `FRAME.gen` to learn the current
generation `g_cur`; (3) fetch its keyslot `/keyslots/<device_id>/<g_cur>` and unwrap it to a
candidate `master_key_{g_cur}`; (4) fetch the roster-key history and peel `roster_key_{g_cur}` back
to `roster_key_1` (§8.2); (5) decrypt every entry from genesis, each under the `roster_key_g` its
AEAD-authenticated `FRAME.gen` selects; (6) fold the chain: genesis hashes to the pinned RFP,
succession and signatures hold; (7) verify the candidate against `mk_commit_{g_cur}` (§7 step 3).
Only after this does the device trust any head or commit. The server-visible `FRAME.gen` is not
trusted on its own: a wrong `g_cur` makes the decryption, the RFP match, or the `mk_commit` check
fail.

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
`T_cand`; compute the expected `ctx_tag_keyhist`; constant-time compare; then apply the ChaCha20
keystream to `ct_keyhist` to obtain `master_key_g`. This is the same CTX/CMT-4 pattern as §9.4 and
§9.5: `T` feeds into `ctx_tag_keyhist`, binding the plaintext `master_key_g` to the commitment and
closing Invisible Salamander / partitioning-oracle attacks at the key-history layer.

Notation: `BLAKE3::derive_key(label, key_material)`: label first, key material second, consistent
with every other derivation in this spec and with the BLAKE3 API (`blake3::derive_key` in Rust). The
`FRAME_keyhist` AD binds the generation index and a `type` byte for `keyhist`, so swapping `wrap_1`
and `wrap_2` fails the AEAD tag.

A current member peels back `g, g-1, …, 1`, **verifying each `master_key_g` against `mk_commit_g`**
(which binds both the key and the generation `g`) from the RFP-anchored chain. A revoked device,
lacking the current key, cannot peel forward: **forward secrecy** (P11).

**Roster-key history (never trimmed).** Folding the sigchain (§8.1) requires `roster_key_g` for
**every** generation `g` present in the chain. To keep the roster keys derivable independently of
the data key-history, each `Rotate` also stores a tiny forward-wrap of the previous roster key:

```
k_rkh_g   = BLAKE3::derive_key("secsec-roster-keyhist-v1", roster_key_{g+1} ‖ le32(g))
(ct, T)   = ChaCha20Poly1305_raw(k_rkh_g, 0, FRAME_rkh, roster_key_g)  // FRAME_rkh: type=roster-keyhist, gen=g
ctx_tag   = BLAKE3::keyed_hash(k_rkh_g, "secsec-ctx-v1" ‖ FRAME_rkh ‖ T)
roster_keyhist_g = ctx_tag(32B) ‖ ct        // stored at /roster-keyhist/<g>; 64 bytes total
```

A current member starts from `roster_key_current` (= `derive_key(master_key_current)`) and peels
`roster_key_current → … → roster_key_1` through this chain (CTX decryption, §9.4), deriving every
`roster_key_g` needed to decrypt and signature-verify the whole sigchain from genesis (`seq 0`, gen
1). The chain is **never trimmed**: at 64 bytes per generation, bounded by the sigchain-length cap
(§19), its total size is negligible. A revoked device lacking `roster_key_current` cannot peel
forward, so roster forward secrecy is preserved.

**Data key-history is never trimmed.** Like the roster-key history above, `/keyhist/<g>` keeps a
forward-wrap of `master_key_g` under `master_key_{g+1}` for **every** generation, so a current member
can peel back to `master_key_1` and read *old file content* sealed under any past generation. At 64
bytes per generation, bounded by the sigchain-length cap (§19), the total size is negligible.

Both key-history wraps are written only inside a rotation batch (§8.4). The server refuses to
replace a wrap for a generation the chain has already rotated past; a wrap left at the tip's own
generation (by an aborted rotation) is replaceable.

### 8.3 Keyslots: versioned, authenticated by commitment, post-quantum

A keyslot wraps `master_key_g` to a device. It is stored `algo_id(1B) ‖ body`. The keyslot KEM is
**X-Wing** (`algo_id = 1`), so the one harvestable asymmetric exposure is **post-quantum** (the
harvest-now-decrypt-later target of §17). The `algo_id` tag and the §16 floor give the protocol
crypto agility.

- **X-Wing (§17):** `body = ct_MLKEM(1088 B) ‖ ct_X(32 B) ‖ ctx_tag(32) ‖ ct(32)`: the X-Wing shared
  secret keys the §9.4 CTX AEAD over `master_key_g`, with AD `"secsec-keyslot-v1" ‖ device_id ‖
  le32(gen)` (binding the wrap to one device and generation). ML-KEM-768 key pairs are held
  exclusively in seed form (§17). The device's X-Wing decapsulation seed is
  `BLAKE3::derive_key("secsec-xwing-seed-v1", ed25519_private_seed)`, derived from the raw 32-byte
  Ed25519 **seed**, **NOT** the clamped scalar `a = clamp(SHA-512(seed)[..32])`. This is load-bearing
  for the post-quantum property: a quantum adversary recovers `a` from the device's *public* Ed25519
  key via Shor (discrete log), so deriving the X-Wing seed from `a` would let that adversary rebuild
  the whole X-Wing secret, the ML-KEM half included, from public data and break the harvested
  keyslot. The Ed25519 seed is quantum-hard to recover from the public key (a SHA-512 preimage), so
  the ML-KEM private key stays secret against a quantum attacker. The X-Wing X25519 key is expanded
  from that seed (§17), independent of the Ed25519 key; Shor recovers it from its published public
  key, but X-Wing remains IND-CCA on the ML-KEM half alone: that is exactly what hybrid buys.
- Each device publishes its X-Wing public key in its `Genesis`/`AddDevice` entry; rotations re-wrap
  to the published keys, and a grant validates the joiner's key before writing anything.

Authenticity does **not** rest on the wrap (a wrap-to-pubkey is forgeable by anyone): it rests on
the **`mk_commit` check** of §7. A forged keyslot decrypts to a key that fails the commitment.
(Key reuse: the one SSH key both signs and seeds the keyslot KEM; the two are domain-separated
derivations, and no Ed25519-to-X25519 conversion is involved.)

### 8.4 Rotation & revocation

Revocation runs over the wire from any enrolled device: `secsec devices <dir>` lists the roster
(short device id + each key's `SHA256:…` SSH fingerprint), and `secsec revoke <device> <dir>`
removes one by an id prefix. It previews every device the revocation takes, asks for confirmation
(`-y` skips it), and refuses to revoke the device it runs on. Against an untrusted server, `revoke`
**always** rotates, and the whole operation is **one atomic `roster-batch`** under the tip CAS:
1. Entries: `RevokeDevice(B)`, then `RevokeDevice` for each device in B's transitive add-by closure
   granted at or after the revoking device's reference point (§8.1), all sealed under generation `g`.
2. A fresh `master_key_{g+1}` and `mk_commit_{g+1}` = `BLAKE3::keyed_hash(master_key_{g+1},
   "secsec-mk-commit-v1" ‖ le32(g+1))`; the `Rotate` entry recording it is sealed under `g+1` (§9.5),
   as is every later entry up to the next rotation.
3. Both key-history wraps for `g` (§8.2).
4. Fresh `g+1` keyslots for every remaining member; the revoked devices' keyslots at **every**
   generation are deleted.
5. When the current head was signed by a revoked device, the same commit re-signed by the revoking
   device and sealed under `g+1`, as a head swap under its own CAS.

The server applies all of it or none of it; the revoking device retries while the tip or the head
keeps moving (§8.1). All new objects then use generation `g+1`.

**Scope of access removal:** revocation removes access to data created *after* the rotation
(forward secrecy, P11). A revoked device that retained `master_key_g` in memory can, colluding with
the server, decrypt any gen-g ciphertext that the server still holds. Rotate-all re-encryption
(re-encrypting all existing objects as gen-g+1) is the only complete mitigation; absent it,
revocation provides forward secrecy only. See §21.

A bare `revoke` without rotate is **not offered** under this threat model.

**Concurrent mutual-revocation race (residual).** Devices are flat and equal; there is no
privileged founder. A stolen device that is unlocked, online, and actively racing can issue
`RevokeDevice(legit)+Rotate` concurrently with the user's `RevokeDevice(stolen)+Rotate`; the tip CAS
serializes the two and whichever lands first wins, evicting the loser (whose retry then fails
succession, §8.1, because it is now revoked). The flat-device model accepts this race as the cost of
having no privileged founder key or recovery-code gate on revocation; full statement and mitigation
in §21.

### 8.5 Counters and local sealed state

Three independent monotonic counters, each signed and each with a **persisted client frontier**:
- **`head_version`**: per ref; strictly increasing; in the head signature.
- **`roster_seq`**: the sigchain sequence; strictly increasing.
- **commit `version`**: per `device_id`; clients keep per-device high-water marks
  (`commit_version_hwm`); a new commit from another device with `version ≤` its high-water is
  rejected as replay.
- **`head_version_hwm`**: a `Map<device_id, u64>` of the highest `head_version` observed from each
  signing device; used by §10 gate 2b to detect head rollbacks.

**HWM update rule (normative).** Adopting a sibling (§10) raises `roster_seq`, the sibling signer's
`head_version_hwm`, and `commit_version_hwm` for the author of every commit new to this device
(indirect observations count; commits carry no `head_version`, so only the signer's head high-water
moves). Before a ref-advancing push the client seals a frontier carrying the observed roster and head
high-waters and its own commit version, but **not** the merged-in commits' version high-waters; those
are sealed only after the pull or merge lands and the new base is persisted (base first, then
frontier). A crash between the two therefore leaves the gates at the last fully-applied state, and
the adoption is safely retried.

**Local sealed state:** all frontier data is stored encrypted in a local state file, sealed under a
key derived solely from the device's SSH private key, so no server contact is needed to unseal:

```
local_seal_key = BLAKE3::derive_key("secsec-local-seal-v2", ed25519_private_seed)
```

The key is derived from the raw 32-byte Ed25519 **seed**, private material that is never published,
and re-derived at startup, never stored. (A frontier sealed under the legacy key
`derive_key("secsec-local-seal-v1", clamp(SHA-512(seed)[..32]))` still opens and is resealed under
v2 on first load.)

The frontier state file is encrypted with the **mutable-object AEAD of §9.8** (fresh 96-bit OS-CSPRNG
nonce per write) under `local_seal_key`, with `device_id` as the AD; there is no `FRAME` and no
signature, as it is local-only and unsigned:

```
nonce(12B) ‖ tag(16) ‖ ChaCha20Poly1305_ct(local_seal_key, nonce, AD=device_id, plaintext_frontiers)
```

**Cold-boot sequence (normative):**
1. Connect to the server and cold-start the roster against the anchor in the folder link (§8.1).
2. Unseal the local frontier with the SSH private key.
3. Verify every head and commit the server offers against the frontier (§10 gates).

A frontier that exists but fails to open (MAC failure) raises an **ALARM** and the session is treated
as a reinstall; a missing frontier for an already-linked folder is reported with a warning and
treated the same way (§21 reinstall residual). Authenticity is not lost (RFP + `mk_commit` still
verify), but freshness guarantees do not hold until a peer confirms the current head.

### 8.6 Backup: the SSH key is the only secret

There is **no server-stored recovery secret**. The SSH key is both the credential and the backup
(§1, P14): any device holding it can re-join from any peer via an invite (§7), so a server-stored
recovery blob would recover nothing that backing up the one SSH key does not, while adding a second
secret for the user to manage and, in any passphrase form, an offline-crackable,
server-exfiltratable target on the untrusted server (precisely the asset the rest of this design
denies it). The backup is therefore the single SSH credential. Total loss of *every* device **and**
the SSH key is the information-theoretic §21 residual.

---
## 9. Cryptography

### 9.1 Object framing & agility

```
FRAME = MAGIC("ssec", 4) ‖ format_version(u8) ‖ algo_id(u8) ‖ le32(gen) ‖ type(u8)     // 11 bytes
blob  = FRAME ‖ ctx_tag(32) ‖ ciphertext                                            // chunks, trees, commits
```

`format_version` is 1 for every object, and 2 for a salted roster entry (§9.5), whose stored form
inserts the salt after the FRAME. The head (§9.8) stores `nonce ‖ tag` after its FRAME instead of a
`ctx_tag`. `format_version`/`algo_id` make every primitive replaceable (§16 to §17); the FRAME
`algo_id` names the object AEAD suite, a namespace separate from the keyslot KEM id (§8.3). Decoders
enforce hard limits **before allocation**: max object size (16 MiB), max tree depth (64 levels), max
tree fan-out (65,536 entries per node), max roster entry size (4 KiB), max list fields (4,096
elements), max name length (4 KiB), defeating allocation and recursion bombs. See §19 for normative
values. The client derives keys for the **expected** `type`, resolves the blob's `gen` through its key
ring (§8.2), and rejects any blob whose FRAME differs from the expected one (no trusting
attacker-set fields).

### 9.2 Content addressing (verified on every fetch)

```
id = BLAKE3::keyed_hash(id_key[gen][type], FRAME ‖ path_salt ‖ plaintext)   // 256-bit
```

`path_salt` is a per-path random 16-byte salt generated at first-sync time. Each tree's `path_salt`
is stored inside its **parent** tree blob; the **root** tree's `path_salt` is stored in the commit
object that references it. Commits use a fixed all-zero `path_salt` (their addresses are already
unique by content and they are separately signed); heads and sigchain entries are not
content-addressed at all (§9.5, §9.8). On fetch the client re-derives `id` from the decrypted
plaintext and **constant-time** compares it to the requested id. Substitution is caught three ways:
the CTX tag under the id-derived key (the AEAD tag feeds it, §9.4), the FRAME match (§9.1), and the
id re-derivation.

### 9.3 Canonical serialization (normative)

All hashed/signed/addressed structures use a single deterministic encoding, the hand-written
`secsec-canon` codec: fixed-width little-endian integers (`u8`/`u16`/`le32`/`le64`, no varints),
byte strings as `le32(len) ‖ bytes`, fixed-length fields raw, a fixed field order set by each
structure, no floats, no self-describing tags. Decoders bound every length prefix before consuming
the body and reject trailing bytes; where bytes are signed or hashed, a decoded value must re-encode
to exactly the received bytes. Two encoders must produce identical bytes or it is a bug; ids and
signatures depend on it.

### 9.4 Per-object key + committing AEAD (CTX construction, CMT-4)

The scheme achieves **CMT-4** (fully committing: binds K, N, A, and M) via the CTX construction
(Chan & Rogaway, ESORICS 2022). The raw Poly1305 tag `T` is fed into the commitment hash, binding the
plaintext M; the stored `ctx_tag` replaces both a separate key commitment and the raw 16-byte
Poly1305 tag. `T` is **not stored** in the blob.

```
k_obj   = BLAKE3::derive_key("secsec-obj-key-v1", enc_key[gen][type] ‖ id)
nonce   = 0                              // safe: k_obj is unique per object
AD      = FRAME ‖ id
ct, T   = ChaCha20Poly1305_raw(k_obj, nonce, AD, plaintext)
              // T is the raw 16-byte Poly1305 tag; NOT stored in the blob
ctx_tag = BLAKE3::keyed_hash(k_obj, "secsec-ctx-v1" ‖ AD ‖ T)
              // 32-byte CTX tag; replaces both a key commitment and raw T in the blob
blob    = FRAME ‖ ctx_tag(32) ‖ ct
```

**Decryption (three explicit phases; T is never stored and must be recomputed):**

1. **MAC evaluation:** using `k_obj` and `nonce=0`, evaluate the Poly1305 MAC over `(AD, ct)`
   to obtain `T_cand`. This is MAC computation only; no plaintext is produced at this step.
   (Block 0 of the ChaCha20 keystream generates the Poly1305 key; this is the same invocation
   reused in Phase 3.)
2. **Commit verify:** constant-time compare
   `stored_ctx_tag == BLAKE3::keyed_hash(k_obj, "secsec-ctx-v1" ‖ AD ‖ T_cand)`.
   If this check fails, reject the blob immediately.
3. **Decrypt:** only if Phase 2 passes, apply the ChaCha20 keystream (blocks 1+) to `ct` to
   obtain the plaintext.

There is no "embedded T" in the stored blob; an implementation MUST NOT look for a stored T or pass
`ctx_tag` to `ChaCha20Poly1305_open` as the MAC tag.

- **Unique key per sealing** ⇒ nonce reuse impossible by construction.
- **CTX tag** binds K, N (=0, trivially), A (FRAME‖id), and M (via T), closing partitioning-oracle
  / "invisible-salamander" attacks across the multi-generation, multi-recipient surface. Verified
  constant-time before the AEAD open. This is the tag-replacement approach the CTX paper
  recommends: no ciphertext expansion.
- Determinism preserves dedup (same plaintext+gen+type+salt → same id → same ct).

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
ref_name_key   = BLAKE3::derive_key("secsec-ref-name-v1",  master_key_1)   // GENESIS gen: stable across rotations

// Roster entry per-seal subkey (g = generation under which the entry is written, salt fresh per seal):
k_roster_entry[g][seq][salt] = BLAKE3::derive_key("secsec-roster-entry-v2",
                                                  roster_key_g ‖ le64(seq) ‖ salt(32))
// Legacy v1 roster entries (read-only; never written):
k_roster_entry_v1[g][seq]    = BLAKE3::derive_key("secsec-roster-entry-v1",
                                                  roster_key_g ‖ le64(seq))

// Roster-key history forward-wrap key (§8.2):
k_rkh_g        = BLAKE3::derive_key("secsec-roster-keyhist-v1",
                                     roster_key_{g+1} ‖ le32(g))

// Commitment (keyed_hash exception; see note):
mk_commit_g    = BLAKE3::keyed_hash(master_key_g,
                                     "secsec-mk-commit-v1" ‖ le32(g))
```

Distinct context strings prevent `enc_key[g][t] == id_key[g][t]` for any `(g, t)`. Fixed-width
`le32(g) ‖ u8(t)` encodings prevent `enc_key[1][CHUNK]` from equalling `enc_key[2][TREE]`
(collision via variable-length concatenation). `BLAKE3::derive_key` places the context string as the
KDF key and the key material as the message, keeping the high-entropy input (`master_key_g`,
`roster_key_g`, or `roster_key_{g+1}`) in the IKM role **for all nine `derive_key` derivations
listed above**.

> **Note:** `mk_commit_g` uses `BLAKE3::keyed_hash(master_key_g, ...)`, placing `master_key_g` in the
> BLAKE3 PRF **key** role rather than the IKM/message role. This is the **only** place where
> `master_key_g` serves as a BLAKE3 key argument; the two uses are domain-separated by BLAKE3's
> internal API distinction. Implementors MUST NOT substitute `BLAKE3::derive_key` here.

**Test vectors are provided for all eleven `derive_key` derivations** (the nine listed above plus
`k_obj` (§9.4) and `k_keyhist` (§8.2)) **plus the `mk_commit_g` `keyed_hash`** (`vectors/`).

`roster_key_g` (**one per generation**) keys the sigchain entries written under generation `g`, so
the server cannot read them.

`ref_name_key` is derived from `master_key_1` (the **genesis** generation), so it is **stable across
rotations**: a ref's storage path `H = keyed_hash(ref_name_key, ref_name)` (§13) does **not** move
when the master key rotates. (Every current member can recover `master_key_1` by peeling the §8.2
data-key history; the server never holds it, so `H` leaks nothing it does not already see as the
storage path.) The head *blob* is still sealed under the **current** generation's `head_key_g`, so a
revoked device cannot read post-rotation head metadata (forward secrecy, §9.8); a reader at a newer
generation peels its key ring to open a head written under an older one (§9.8). Were `ref_name_key`
generation-scoped, a rotation would relocate the head ref to an empty slot until republished, and a
fresh clone reaching that empty slot could mistakenly publish its empty directory as the head.

**Roster entry AEAD (normative).** Each sigchain entry is encrypted under a per-seal subkey derived
from the **generation-indexed** roster key, the entry's sequence number, and a fresh random 32-byte
salt. The salt makes every sealing's key unique even when two devices race to write the same `seq`
(a CAS race whose loser re-seals), so the fixed nonce never repeats under one key:

```
salt                = 32 bytes, OS CSPRNG, fresh per seal
k                   = k_roster_entry[g][seq][salt]
FRAME_roster        = FRAME(format_version=2, type=roster, gen=g)
AD_roster           = FRAME_roster ‖ le64(seq) ‖ salt
ct_roster, T_roster = ChaCha20Poly1305_raw(k, 0, AD_roster, entry_plaintext)
ctx_tag_roster      = BLAKE3::keyed_hash(k, "secsec-ctx-v1" ‖ AD_roster ‖ T_roster)
stored_entry        = FRAME_roster ‖ salt ‖ ctx_tag_roster(32) ‖ ct_roster
```

Decryption follows the same three-phase procedure as §9.4 (MAC evaluation → commit verify →
decrypt). This construction achieves CMT-4 for roster entries, closing the partitioning-oracle
surface over membership and revocation records. An entry whose FRAME carries `format_version` 1 is
a legacy v1 entry, `FRAME ‖ ctx_tag ‖ ct` under `k_roster_entry_v1` with AD `FRAME ‖ le64(seq)`: it is
read, never written.

**Decrypting across generations (normative).** A sigchain spans every generation up to the current
one, and folding it (§8.1) requires reading **all** entries from genesis. To decrypt an entry written
under generation `g`, a current member peels the roster-key history (§8.2) to `roster_key_g`, then
derives the entry key. The generation `g` is taken from the entry's `FRAME.gen`, which is
authenticated by the AEAD AD and cannot be altered by the server. Genesis (`seq 0`) is written under
generation 1. A `Rotate` entry is written under the generation it **creates** (`g+1`): it records
`mk_commit_{g+1}`, so `master_key_{g+1}` (hence `roster_key_{g+1}`) is minted before the entry is
sealed. Every entry from a `Rotate` (inclusive) up to the next `Rotate` is written under that
generation. Consequently the sigchain tip's plaintext `FRAME.gen` always equals the current
generation `g_cur`: the invariant the cold-start fold (§8.1) reads to learn `g_cur`.

### 9.6 Signatures & domain separation

Every signature is an SSHSIG with a **disjoint namespace**; the client never signs server-supplied
bytes raw. Algorithm pinned to `ssh-ed25519` (Ed25519-only), with no algorithm downgrade. **The
verifier MUST reject any SSHSIG blob whose `sig_algorithm` field is not exactly `ssh-ed25519`. Any
other algorithm field MUST cause verification failure regardless of cryptographic validity.**

| Purpose | Namespace | Message |
|---|---|---|
| Connection auth | `secsec-auth-v1` | `bytes(channel_binding) ‖ host_id ‖ session_transcript ‖ server_nonce` |
| Write authorization | `secsec-write-v1` | `bytes(op) ‖ args_hash ‖ session_transcript ‖ server_nonce` |
| Read authorization | `secsec-read-v1` | `bytes(op) ‖ args_hash ‖ session_transcript` |
| Commit | `secsec-commit-v1` | canonical commit |
| Head update | `secsec-head-v1` | `bytes(ref) ‖ commit_id ‖ head_version ‖ roster_seq ‖ prev_head` |
| Roster entry | `secsec-roster-v1` | canonical sigchain entry (all fields but `sig`) |

**Connection auth field order (canonical):** `channel_binding ‖ host_id ‖ session_transcript ‖
server_nonce`, where `channel_binding` is the TLS 1.3 keying-material exporter (§11) and
`server_nonce` the ServerHello's. This order is normative; §11 cross-references this table rather
than defining a separate formula.

`secsec-read-v1` authorizes every read op (§12): `args_hash` binds the op and the exact ids,
sequence number, or generation requested, and `session_transcript` provides per-connection freshness
without a server-supplied nonce, so a read signature is replayable only on its own connection, where
it repeats a read its signer may already make. The pairing mailbox ops are read-authorized too (§12). Enrollment
freshness for a joining device comes from the single-use invite code and the mailbox's bounded TTL
(§7), so no separate grant-attestation signature is used.

Server-chosen nonces appear **only** in `auth`/`write`. A signature for one purpose is
cryptographically invalid for any other, so the "server sets the challenge to `H(commit)`" forgery
is impossible.

**Revocation scope.** Connection auth checks the signature and the `authorized_keys` gate only;
keyslot ownership is checked on every request (§12). A revoked device whose line remains in
`authorized_keys` can therefore still connect, but every repo op it sends is refused once the
revocation batch has deleted its keyslots (cooperative server). A malicious server can ignore the
deletion, bounded by the gen-g residual (§21). Removing the device's line from `authorized_keys`
stops it connecting at all.

### 9.7 Chunking, dedup leakage & padding

- **Keyed FastCDC-style chunking:** a gear rolling hash with normalized two-mask cut points
  (min 16 KiB, average 64 KiB, max 256 KiB), whose 256-entry gear table is derived from
  `cdc_seed[gen]` (`BLAKE3::keyed_hash(cdc_seed, "secsec-cdc-gear-v1")` in XOF mode), so chunk
  boundaries are repo-specific and cross-repo size-fingerprint databases do not apply.
  **Limitation:** keyed CDC's boundary privacy is not maintained against an adversary who can
  cause the victim to archive chosen-plaintext data. Alexeev et al. (ePrint 2025/532) demonstrate
  that observed chunk boundaries can be used to algebraically recover the secret gear-table key
  under a chosen-plaintext archive attack. Once `cdc_seed` is recovered, the attacker can compute
  expected chunk ids for any known plaintext of a known path salt. Mitigation: `cdc_seed` is
  generation-scoped (rotated with each master-key rotation), so past boundary observations do not
  apply to future data, and default-on chunk padding (below) reduces the boundary signal key
  extraction needs; see §21.
- **Padding:** every chunk object is padded before sealing to the next power of two above its
  length (reversible ISO/IEC 7816-4 bit padding: `0x80` then zeros, so a chunk of exactly `2^k`
  bytes pads to `2^(k+1)`), a bounded ≤2× overhead that blurs sizes into power-of-two buckets. This
  **substantially reduces, but does not fully eliminate,** the boundary-sequence signal (the bucket
  sequence still leaks coarse sizes). A **uniform** policy (pad all chunks to one fixed size) and a
  padding opt-out are **NOT WIRED**: padding is always power-of-two. Padding of **metadata objects**
  (trees/commits/heads/roster) is **NOT WIRED** either: they are sealed at their true size (§21).
- **Per-path random salt (always on):** each path mixes a `path_salt` (16-byte random, per-path,
  generated at first sync and stored encrypted in the parent tree) into id derivation (§9.2). This
  disables the **cross-session confirmation oracle** (a third party cannot confirm whether a known
  plaintext has been synced to a path without knowing the path's salt) and makes identical content
  at different paths yield different ids. A convergent (salt-free, cross-path dedup) mode is **NOT
  WIRED**. A device joining with an existing folder seeds its salts from the head tree for the same
  paths (§10), so identical files at the same path get identical ids.
- **Intra-file temporal equality:** the `path_salt` is constant across all versions of a file. When a
  file is modified, unchanged chunks yield the same id across versions (same `path_salt`, same
  plaintext, same `gen`, same `type`). The server observes which chunk ids each push uploads, which
  reveals the chunk-level edit distance for each modified file without reading any ciphertext.
  Eliminating it would require a per-version salt, which disables intra-file dedup entirely; this is
  a documented tradeoff.
- Residual leaks (sizes within padding buckets, exact metadata sizes, timing, intra-file temporal
  equality) are bounded and documented (§21).

### 9.8 Mutable-object AEAD (fresh nonce): heads & local sealed state

The committing AEAD of §9.4 relies on a **unique key per sealing** (so `nonce=0` is safe) and applies
only to **immutable** objects. Two objects are **mutable** (re-encrypted in place under a *stable*
key), so they MUST NOT use §9.4's fixed nonce (that would be catastrophic nonce reuse). They instead
use a **fresh random nonce per write**: the per-ref **Head** (§6, §13) and the **local sealed state**
(§8.5).

```
nonce          = 96-bit OS CSPRNG, fresh on EVERY write     // never a counter; reuse is fatal
ct, tag        = ChaCha20Poly1305(key, nonce, AD, plaintext)  // standard RFC 8439 AEAD; raw 16-byte tag
blob           = [FRAME] ‖ nonce(12) ‖ tag(16) ‖ ct          // FRAME present for server-stored heads
```

A fresh nonce per write makes keystream reuse impossible even though `key` is reused across updates,
so this construction does not need §9.4's unique key. It is deliberately **not** key-committing
(CMT): unnecessary here, because the key is a single high-entropy, master-key-derived value (no
multi-key / low-entropy partitioning-oracle surface, unlike the keyslots), and authenticity against
other devices and the server rests on the object's **signature**, not the symmetric tag.

**Head blob (normative).** Stored at `/refs/<H>`, `H = BLAKE3::keyed_hash(ref_name_key, ref_name)`
(§13), where `ref_name_key` is the **genesis-generation, rotation-stable** key of §9.5, so a ref's
slot does not move across rotations. The head is **both signed and encrypted**:

```
sig        = SSHSIG("secsec-head-v1",                                  // §9.6
                    bytes(ref_name) ‖ commit_id ‖ head_version ‖ roster_seq ‖ prev_head)
plaintext  = canonical(ref_name, commit_id, head_version, roster_seq, prev_head, sig)
key        = head_key_g = BLAKE3::derive_key("secsec-head-enc-v1", master_key_g ‖ le32(g))   // §9.5
AD         = FRAME ‖ H        // FRAME: type=Head, gen=g; binds the blob to its ref slot
head_blob  = FRAME(11) ‖ nonce(12) ‖ tag(16) ‖ ct
```

The **signature** (verified against the RFP-anchored roster, §8) is what prevents the server or a
non-member from forging or substituting a head; the AEAD hides the ref→commit linkage and the
counters from the server and binds the blob to its ref slot via `H`. `head_version` (per ref,
strictly increasing, §8.5) is covered by the signature and checked against the client's persisted
`head_version_hwm` (§8.5, §10): replay/rollback of an old head is caught there, not by the AEAD. The
generation `g` of the head **blob** is read from the plaintext `FRAME.gen` and resolved against the
reader's key ring: a head is sealed under the generation current at write time, and a current member
opens it under that generation's `head_key_g`, **peeling** the §8.2 key history to read a head
written before a rotation. A member that does not yet hold the head's generation (a newer device
rotated past it) refolds and retries. New heads are always sealed under the **current** generation,
so a revoked device cannot read post-rotation head metadata.

The §8.5 local sealed-state blob uses this same construction with `key = local_seal_key` and
`AD = device_id` (no `FRAME`, no signature: it is local-only and unsigned).

---
## 10. Sync semantics

- **Sync round:** each round (on a debounced change or the poll tick, below) fetches and verifies the
  remote head, snapshots the folder, and reconciles: an unchanged folder with an unmoved head is
  idle; a local change becomes a commit (strictly increasing per-device `version`, current
  `roster_seq`, `last_seen_head`, signed) published via `cas-head`; a moved head is adopted
  (fast-forward) or merged; the result is restored into the folder.
- **Rollback-aware adoption** (closes replay-into-merge): a sibling that is an **ancestor of (or
  equal to)** the client's head is already held and is accepted as a no-op **before** the gates below:
  a commit already in the client's history can never be a rollback. The gates therefore apply only to
  the adoption of *genuinely new* sibling state (so a peer that merely folds the roster later, and thus
  stamps an **older** `roster_seq` on a commit the client already holds, does not trip gate 1). Every
  commit new to the client is first verified against its author among the members past and present
  (P3). Then:
  (1) The sibling's `roster_seq` ≥ the client's persisted `roster_seq` frontier.
  (2a) Each new commit's per-device `version` exceeds that device's `commit_version_hwm` (commits by
      the client's own device are its own history and exempt).
  (2b) The sibling signer's `head_version` ≥ its `head_version_hwm`.
  A DAG that lacks metadata for a commit the gates must examine fails closed. The high-waters then
  advance per the §8.5 rule. A sibling whose history contains the client's head is a
  **fast-forward** (adopted, no merge); a DAG-incomparable one is **merged**: a **per-path three-way
  merge** against the merge base (the lowest-id lowest common ancestor, so every device picks the
  same one). **When the base tree is unavailable** (a malicious server withholds it): the merge runs
  against an empty base, treating every divergent path as a **keep-both conflict** (safe default: no
  data loss), and the fallback is surfaced to the user. One-sided change → take; identical change →
  take; a one-sided mode change survives; divergent content → **conflict** (keep-both: ours under the
  name, theirs as `name.conflict-<device>-<commit_id>.ext`, where `<device>` and `<commit_id>` are
  the first 12 lowercase hex characters of the sibling signer's device id and the sibling commit id,
  a `-2`, `-3`, … suffix is added on a name collision, and the stem is truncated to the name bound);
  modify vs delete keeps the modified side and flags it. The merge commit has both heads as parents
  and is signed by the merging device. Timestamps are hints, never trusted for security.
- **Forks:** commits embed `last_seen_head`. A server-presented sibling whose head is
  **DAG-incomparable** to the client's own (neither an ancestor of the other) is a genuine divergence,
  and the three-way merge above reconciles it: both sides are kept, **no data loss**, and every
  conflicting path is surfaced to the user. There is no separate fork alarm: `last_seen_head` is
  recorded, not checked. Reconvergence happens on any sync to the shared server; a sustained
  partition delays it (the SUNDR lower bound, §21) but does not prevent it.
- **Materialize (normative):** writing a pulled or merged tree back to the working folder
  **reconciles** the folder *to* the tree **against this device's own snapshot** of it, taken at the
  start of the sync. An entry on disk but absent from the tree is removed only when that snapshot
  tracked it and it is unchanged since (same size and nanosecond mtime), so an upstream deletion
  takes effect and is not re-added by the next snapshot. Everything the snapshot never tracked stays:
  files created or edited since, symlinks and special files (never traversed), and names no tree can
  carry (§6). The one exception is macOS's `Icon\r` custom-folder-icon file: it is never deleted
  while its folder lives, and goes with a folder another device deleted or replaced only when it is
  the last thing left in it, so that folder does not come back empty on every device. A file whose
  content upstream left alone stays as it is on disk (edited or not). An incoming file replaces an
  on-disk one only if that file is unchanged since the snapshot; a local edit made meanwhile is kept
  and the incoming version lands beside it as a keep-both copy
  (`name.conflict-<device>-<commit_id>.ext`, labelled by the restored commit's author and id). Files
  are written through a same-directory `.secsec-tmp-*` temp file, fsynced and renamed into place. A
  symlink in the way of a write is unlinked, never followed. An entry this device's filesystem cannot
  create is skipped and rides forward unchanged in the next snapshot, so it never reads as a deletion.
  Explicit `secsec restore` is the one overwrite: the restored version replaces the file or folder at
  that path. **First contact is never a bare restore:** a folder with no sync state (no base) clones
  only when it holds nothing a snapshot would track; otherwise it becomes a parentless commit
  three-way merged (empty common ancestor) with the head, union plus keep-both, with its path salts
  seeded from the head tree so identical files get identical ids, because reconciling a tree that has
  never seen the folder's local-only files would delete them.
- **Live trigger:** `notify` (inotify/FSEvents/ReadDirectoryChangesW) watches the folder; a burst of
  events ends after `watch_debounce_ms` of quiet (or `poll_interval_secs` after it began) and runs one
  sync round. A periodic round every `poll_interval_secs` picks up remote changes, probes the sigchain
  for growth, and retries a pending retention prune (§15). If the watcher cannot start, sync runs on
  the poll timer alone.

---
## 11. Transport & authentication

- **QUIC + TLS 1.3** (`quinn`+`rustls`), udp/8899 (overridable). The suite list and key exchange are
  **pinned, not negotiated**: X25519 only, and exactly the TLS 1.3 AEADs ChaCha20-Poly1305,
  AES-256-GCM, and AES-128-GCM. The last is not optional: RFC 9001 §5.2 fixes QUIC Initial packet
  protection to AEAD_AES_128_GCM, and rustls derives those keys from the same suite list, so removing
  it makes the transport unusable. Initial packets carry no secrecy regardless (their keys derive
  from the public connection ID). TLS 1.2 is refused outright by the verifier: **no downgrade**.
- **`authorized_keys` is the mandatory connection gate.** `secsec serve` reads the operator's
  `~/.ssh/authorized_keys` (one bare `ssh-ed25519 <base64> [comment]` key per line; other key types
  and option-prefixed lines are skipped) and **refuses to start** if it is missing or has no usable
  key. After the handshake, the server computes `device_id = BLAKE3(canonical(authenticated_pubkey))`
  and rejects the connection unless that id is in the file. The file is re-parsed whenever its size
  or mtime changes and checked at connect, then again on an open connection's first request once 60 s
  have passed since the last check (the connection is closed if its key is gone); an unreadable file
  fails **closed** (deny). Adding or removing a device
  takes effect with no restart. The authenticating key is proven by the channel-bound
  `secsec-auth-v1` signature below, so a key cannot be spoofed by client-supplied bytes. This gate is
  necessary but not sufficient: a listed key still owns no data without a keyslot (§12). The two
  layers are independent: `authorized_keys` is the operator's coarse allow-list (who may open a
  socket); the keyslot roster is the cryptographic membership (who may read or write). Revoking a
  device is therefore two acts: `secsec revoke` (rotate the key away, §8.4) and removing its line from
  `authorized_keys` (stop it reconnecting). The file also grants SSH logins to its account, so a
  server that should not admit those devices as shell users runs as a dedicated account.
- **No managed certs:** the server self-signs a host key on first run (like `sshd`);
  `secsec hostpin --serve <dir>` prints its host pin. The client **pins** it: given up front with
  `secsec sync --pin <host pin>`, or **trust-on-first-use** on the first `sync` without one, which
  captures the host key's SPKI hash only after the TLS handshake signature verifies, **prints the
  host pin** for the user to verify out-of-band, and persists it as `host_id` in the folder's link.
  Every later connection pins that stored value (a mismatch aborts, and a `--pin` that disagrees with
  a linked folder's pin is refused). (Residual: §21 first-contact TOFU window when `--pin` is not
  used.)
- **host_id definition:** `host_id = BLAKE3(SPKI)`. `host_id` MUST be computed by the client from
  locally-pinned material and MUST NOT be accepted from the server; a ServerHello carrying another
  `host_id` aborts the handshake.
- **Verifier (the top ship-broken risk):** the custom `rustls` `ServerCertVerifier` MUST compare leaf
  SPKI to the pin **and** fully implement `verify_tls13_signature` (never stub). Mandatory negative
  tests: wrong key fails; tampered handshake fails. Device keys are **Ed25519-only**: SSHSIG
  verification MUST reject any signature whose `sig_algorithm` field is not exactly `ssh-ed25519`
  (a mandatory negative test).
- **Session transcript:** both ends maintain `session_transcript` = BLAKE3 over the ordered,
  length-prefixed handshake messages, defined byte-exactly below. It binds the whole exchange against
  splicing/downgrade. The hasher is fed, in this fixed order:
    1. Client hello: `le32(2 + 32) ‖ secsec_version: u16 ‖ client_nonce: [u8; 32]` (OS CSPRNG).
    2. Server hello: `le32(2 + 32 + 32) ‖ secsec_version: u16 ‖ server_nonce: [u8; 32] ‖
       host_id: [u8; 32]`.
  No other inputs are hashed; raw public keys are NOT injected: the server identity is bound via
  `host_id` and the channel via the TLS exporter. The client-contributed `client_nonce` ensures
  transcript uniqueness is not solely under server control. `secsec_version` is 3; a peer speaking
  another version is refused with a named error, never negotiated.
- **Client→server auth:** the client signs (`secsec-auth-v1`) the canonical payload defined in §9.6,
  `channel_binding ‖ host_id ‖ session_transcript ‖ server_nonce`, and sends it with its canonical
  public key; the server verifies it and acknowledges.
  - `channel_binding` = the TLS 1.3 keying-material exporter via `quinn`'s `export_keying_material`
    with label `"EXPORTER-Channel-Binding"` and an empty context, 32 bytes (RFC 9266 §3 / RFC 8446
    §7.5). RFC 9266 does not formally define `tls-exporter` for QUIC transports (an acknowledged open
    gap); this usage is intentional. The `session_transcript` provides an additional
    application-layer binding; both are included.
  - The whole application handshake runs under a deadline (the QUIC idle timeout); a peer that
    stalls is dropped.
  - Every later per-op signature on the connection is verified against the public key that completed
    this handshake.
- **Per-op nonces:** each request travels on its own bidirectional stream, and the server answers the
  stream's opening with a fresh 32-byte challenge. A write is signed over that challenge and must
  arrive within 60 s of its issue (§19); one challenge serves exactly one request. Reads sign no
  challenge (the transcript binds them to the connection).
- **Request bounds:** the server caps every request frame before reading it: at the full request size
  (a 16 MiB object plus envelope) for an enrolled key, and at just what the genesis batch and pairing
  messages need for a key without a keyslot, refusing an over-cap frame unread. A `put` carries a
  `declared_size`, bound into its `args_hash`; the server rejects one above 16 MiB or not equal to the
  blob's length.
- **DoS hardening:** the server issues a stateless **QUIC Retry** to any un-validated source address
  before allocating connection state (anti-amplification, and so the per-source-IP connection-rate
  limit cannot be evaded by address spoofing); per-IP new-connection rates and a server-wide cap on
  concurrent connections (handshakes in flight included) are enforced before the handshake, and
  per-key concurrent connections after it; per-key byte rates and quotas; bounded object sizes.
  (Values §19.)

---

## 12. Server API

| Call | Auth | Purpose |
|---|---|---|
| `auth` | establishes identity | SSHSIG challenge/response (§11) |
| `get(id)` | `secsec-read-v1` | fetch a durable object blob from `/objects/<id>` |
| `has(ids)` | `secsec-read-v1` | durable existence per id; max 1,024 ids per call |
| `get-ref(H)` | `secsec-read-v1` | fetch the head blob at `/refs/<H>` (§13), or absent; the server never learns the ref name behind `H` |
| `get-roster(seq)` | `secsec-read-v1` | fetch the sigchain entry blob at `/roster/<seq>`, absent past the tip |
| `get-keyslot(device_id, g)` | `secsec-read-v1` | fetch `/keyslots/<device_id>/<g>` |
| `get-keyhist(g)` / `get-roster-keyhist(g)` | `secsec-read-v1` | fetch the §8.2 data- and roster-key-history wraps |
| `put(id, declared_size, push_id, blob)` | `secsec-write-v1` | stage an object under an in-flight push (§15) |
| `cas-head(H, old, new, promote, blob)` | `secsec-write-v1` | atomic ref CAS; promotes the named push's staged objects durably (§15) |
| `roster-batch(old_tip, entries, keyslots, keyhist, roster_keyhist, revoke, head)` | `secsec-write-v1` | one sigchain operation, applied atomically under the tip CAS (§7, §8.4) |
| `prune(dead, all_heads_hash, roster_len)` | `secsec-write-v1` | client-driven retention deletion under a head-binding CAS (§15); `dead` ≤ 1,024 ids |
| `pair-put(slot, blob)` / `pair-get(slot)` | `secsec-read-v1` | §7 invite-pairing mailbox: a TTL'd relay of code-MAC'd blobs; `pair-get` takes the message. Dispatched **pre-enrollment** (a joining device owns no keyslot yet) |

The blind server validates no content signature: a `cas-head` checks only that the new blob hashes
to `new` and that the ref still holds `old`; a `roster-batch` checks the tip CAS, sizes, and rate
limits. Readers verify every head, commit, and roster signature against the RFP-anchored roster.

**`roster-batch` (normative).** Fields: `old_tip` (`BLAKE3` of the stored tip entry blob, all-zero
for genesis), `entries` (sealed entry blobs, appended in order; at least one), `keyslots`
(`(device_id, g, blob)` writes), `keyhist` and `roster_keyhist` (optional `(g, wrap)`), `revoke`
(devices whose keyslots at **every** generation are deleted), and `head` (an optional head swap
`(H, old, blob)` under its own CAS). The server applies it in one transaction only if the tip still
matches, the head (if any) still matches, and no key-history wrap would replace one the chain has
rotated past; otherwise nothing changes and the reply is a CAS conflict. Grants, rotations, and
revocations are all batches; there is no standalone keyslot write or delete.

**Every repo operation, reads included, requires a per-op signature from a key that owns a keyslot**
(a rostered device); connection-level auth alone is not sufficient. `has` and `prune` batches longer
than 1,024 ids are rejected with `too-many-ids` before any lookup, and the client batches larger
sets.

**Keyslot-existence enforcement (normative).** On **every** request the server verifies that a
keyslot exists at `/keyslots/<device_id>/<any g>`, where `device_id = BLAKE3(canonical(pubkey))` of
the key that authenticated the connection. A request from a key with no keyslot is rejected with a
distinct `not-enrolled` error before any read or write is performed. This check is a key-range
lookup in the store and needs no decryption. **Two exceptions, both bounded:** (a) `pair-put`/
`pair-get` are dispatched *before* this check (a joining device owns no keyslot yet) and are
authorized by their `secsec-read-v1` signature alone (their payload is independently code-MAC'd,
§7); (b) the **genesis-bootstrap exception** admits, from an unenrolled key, exactly the genesis
batch (all-zero `old_tip`, one entry, one keyslot owned by the signer, no key-history wraps, no
revocations, no head) and only while the roster is empty. Every other op from an unenrolled key is
rejected.

A revocation's keyslot deletion rides inside a `roster-batch` with at least one appended entry,
from any rostered key. The **blind** server cannot fold the encrypted sigchain to confirm that the
batch corresponds to a legitimate revocation, so a compromised *current member* could delete another
member's keyslots (a cold-start denial of service on that peer): a griefing vector inside the
flat-trust member set (§8.4), not reachable by the threat-model adversaries (a malicious server
mutates its own store directly regardless, and a revoked device is already rejected by the
keyslot-existence check). Closing it would require a non-blind server.

The `authorized_keys` allow-list is the **mandatory** connection gate (§11): `secsec serve` refuses
to start without it, so an unlisted key never reaches any op above. A listed-but-unrostered key can
open a socket and do nothing else: it owns no keyslot, so every op but the two bounded exceptions
above is rejected, and the server cannot mint a *valid* (commitment-matching) keyslot for an
injected key of its own.

**`args_hash` (normative).** Every per-op signature covers `args_hash = BLAKE3(bytes(op) ‖ fields)`,
recomputed by the server from the request, so the client cannot lie about what it signed. The client
constructs op and args; the server supplies only `server_nonce` (writes):
- `get`, `has`, `get-ref`: `bytes(op) ‖ le64(n) ‖ id…` (order-bound).
- `get-roster`: `bytes(op) ‖ le64(seq)`; `get-keyslot`: `bytes(op) ‖ device_id ‖ le32(g)`;
  `get-keyhist` / `get-roster-keyhist`: `bytes(op) ‖ le32(g)`.
- `put`: `bytes("put") ‖ id ‖ le32(declared_size) ‖ push_id` (the blob is bound by its content
  address).
- `cas-head`: `bytes("cas-head") ‖ H ‖ old ‖ new ‖ promote` (the blob is bound by `new`).
- `roster-batch`: `bytes("roster-batch") ‖ BLAKE3(encoded request)`, binding every field.
- `prune`: `bytes("prune") ‖ dead_set_hash ‖ all_heads_hash ‖ le64(roster_len)` (§15); the server
  recomputes `all_heads_hash` and `roster_len` from its own state and refuses on mismatch.
- `pair-put` / `pair-get`: `bytes(op) ‖ slot` (the `pair-put` blob carries its own code MAC).

**`cas-head` head-id semantics (normative).** Because the server is **blind** it cannot read the
encrypted head blob, so the compare-and-swap operates on a *server-computable* token: `old` and `new`
are `BLAKE3` over the respective **stored head-blob bytes** (the §9.8 ciphertext as written to
`/refs/<H>`), **not** the client-side plaintext head identity of §6/§10. The server atomically
computes `BLAKE3(current stored blob)` (or the all-zero sentinel if the ref is absent), requires it
to equal `old`, requires the attached new blob to hash to `new`, and only then replaces the ref and
promotes. A first write uses the all-zero `old` ("expect absent"). The client holds both blobs (it
sealed the new one and fetched the old), so both tokens are client-computable too; this is purely a
concurrency guard: the head's *authenticity* still rests on its `secsec-head-v1` signature inside
the blob (§9.8), verified by readers against the roster.

**Per-key storage quota and rate limits** (normative; the server MUST enforce):
- Per-key storage quota: **unlimited by default** (configurable, §15.3). **Scope:** the store is
  content-addressed and deduplicated, so an object is not owned by the key that wrote it (another
  key's tree may reference it) and a precise *durable* per-key byte attribution is undefined. A finite
  cap bounds the volume of **new** objects a single key introduces **per server session** (an
  anti-flood cap, reset on restart), charged on the bytes a `cas-head` actually makes durable, so
  idempotent re-puts and abandoned staging are never counted. Durable protection against disk
  exhaustion is the operator's filesystem quota on the store directory (§15.3).
- Per-key write rate: 100 MB/s sustained, burst 1 GiB (the burst stays ≥ the 16 MiB object cap so a
  single object always fits regardless of the configured rate).
- Per-key read rate: 200 MB/s sustained (sharing the 1 GiB burst).
- Connection rate: 10 new connections/s per source IP, enforced after the **QUIC Retry** address
  validation (§11) and before the handshake, so a spoofed source cannot exhaust the per-IP budget;
  256 concurrent connections server-wide, handshakes in flight included, taken at accept and held
  until the connection ends, so many addresses together cannot hold unbounded handshake state;
  3 concurrent connections per authenticated key, enforced after the handshake.
- The pairing mailbox holds at most 256 slots server-wide; `pair-put` is charged to the posting
  key's write rate and `pair-get` to the taking key's read rate.

The storage cap, the byte rates, and the connection limits are operator-tunable (§19
`secsec.config`); the burst is compiled-in. Byte rates and the quota are checked after per-op
authorization and before any storage.

---
## 13. Storage layout

**Server.** All repository state lives in one file, `repo.secsec` (a `redb` database, not a directory
tree: the paths below are logical key namespaces inside it), in the directory passed to `secsec
serve` (default the current dir). Alongside it the server keeps its self-signed host identity in
`hostkey/hostkey.crt` and `hostkey/hostkey.key` (owner-only). All repo state is opaque:
```
/objects/<id>             encrypted blobs (chunk/tree/commit), one object per id
/staging/<push_id>/<id>   objects staged by an in-flight push, invisible until promoted (§15)
/staging-meta/<push_id>   the push's last-activity time, the idle reclaimer's clock
/keyslots/<device_id>/<g> versioned authenticated keyslots per device per generation
/refs/<H>                 the repo's single signed head (ref `main`); H = BLAKE3::keyed_hash(ref_name_key, ref_name)
/roster/<seq>             encrypted, signed sigchain entries; the last one is the tip the CAS compares
/keyhist/<g>              data key-history wraps (§8.2)
/roster-keyhist/<g>       roster-key history wraps (§8.2; never trimmed)
```
The transient invite-pairing mailbox (§7) is **in-memory only**, never persisted. There is no
server-stored recovery secret (§8.6).

The generation component `g` is a **plaintext integer**: it is not opaqued (a secret-derived path
component) because the server API has no `list` operation (§12), so a device must *compute* the exact
path of everything it fetches, including, on a fresh reinstall, its own keyslot and the key-history
chain it has **not yet decrypted**. A secret-derived path component would have to come from a key the
device does not yet hold (the very key it is fetching), a circular dependency, or be distributed
out-of-band, adding a second anchor beside RFP. The resulting leak (master-key rotation count and
timing) is low-sensitivity metadata, enumerable by the server and an accepted residual (§21), on par
with the device-count and access-timing leaks.

Path notes:
- `/keyslots/<device_id>/<g>` keys by `device_id`, not the raw public key: the device's full public
  key bytes are never exposed in a path. `device_id = BLAKE3(canonical(pubkey))` is already opaque.
- `/refs/<H>` keys by a keyed hash `H = BLAKE3::keyed_hash(ref_name_key, ref_name)`, not the ref name
  or device id, where `ref_name_key` is derived from the **genesis** `master_key_1` (§9.5), so the
  path is **stable across rotations**. The head blob is **signed and encrypted** (§9.8): the ref name
  lives **inside the encryption**, so the server sees only the hash `H` and ciphertext.

The server-side `redb` store maps each `id` to its opaque blob and holds no plaintext-derived
metadata; the only plaintext it reads is the `FRAME.gen` of stored roster entries, which it compares
to decide whether a key-history wrap may still be replaced (§8.2). One binary; no external DB.
(A packed-blob index carrying `{size, generation, pack-offset}` is **NOT WIRED**: objects are stored
one per id, unpacked.) The server compacts the file at startup, so space freed by prunes is returned.

**Client.** The synced folder holds **nothing but the user's plaintext files**, apart from the
`.secsec-tmp-*` files a restore writes and renames into place (§10), which the next restore of that
directory removes if a crash left one behind. All client state lives under a **single client root**:
`$XDG_CONFIG_HOME/secsec` if that variable is an absolute path, else `~/.config/secsec`. Per synced
folder, state lives at `<root>/folders/<hex BLAKE3(canonical folder path)>/`:
```
link            the repo binding: server address, pinned host_id, RFP, and the §8.1 roster anchor (seq, tip-blob hash)
link.lock       a lock serializing anchor updates to the link
objects.secsec  the encrypted object cache (so a re-sync need not re-fetch or re-encrypt unchanged data)
frontier        the §8.5 local sealed state (anti-rollback counters), sealed under the SSH key
base            the id of the last-synced commit
push_id         the in-flight push id, persisted for crash-resume (§15)
lock            the folder's sync lock (one sync per folder), naming the holder's pid
status          key=value state for `secsec status` and the desktop UIs
```
The same root holds `secsec.config` (§19), the desktop UI's `ui.conf` and `ui/sync.log`, the
installer's `server.env` (the serve directory and port it configured, read back on a re-run), and
the optional per-folder `sync@<escaped path>.conf` env files of the systemd sync service. The systemd
**units** live in `$XDG_CONFIG_HOME/systemd/user/` (else `~/.config/systemd/user/`): the
`secsec-sync@.service` template (one instance per folder) and `secsec-serve.service`; on macOS the
installer writes LaunchAgents `com.secsec.ui` (the menu-bar app) and `com.secsec.serve`. The object
cache is encrypted (it is the same content-addressed blobs pushed to the server) and is a *cache*,
not the source of truth: the plaintext folder is. The client compacts it at the start of every sync
session.

---
## 14. Durability (single-host)

secsec stores one repo on **one** blind server; there is no server-side replication or quorum. A
hostile or dead server is therefore an **availability** event, not a confidentiality or integrity
one: it can refuse, stale, or delete ciphertext, but never read or forge it (§4). Durability rests on
two facts:

- **Every enrolled device holds the working set.** The synced folder *is* the data; a device holding
  the SSH key and a copy of the folder can re-establish the repo (genesis a fresh server) and re-enroll
  the others via invites (§7). A device's object cache holds the history it has fetched; older versions
  are fetched from the server on demand (`log`/`restore`, §15), so history the server loses is lost
  unless some cache still holds it.
- **The SSH key is the backup** (P14): losing the server costs no current data if any device (or a
  backup of its `~/.ssh/id_ed25519` plus the folder) survives. Losing *every* device **and** the key
  is the information-theoretic total-loss residual (§21).

This is the deliberate single-host tradeoff (§2): the operator runs their own server, and the device
replicas are the redundancy for current content.

---
## 15. Storage lifecycle: transactional push, retention, reclaim

The blind server cannot compute reachability (every head/commit/tree is ciphertext to it), so storage
is kept tidy by two client-driven mechanisms that never ask the server to traverse the object graph: a
**transactional staged push** that leaves no orphans, and **count-based retention** that bounds
history. There is no reachability sweep and no `gc` command.

### 15.1 Transactional staged push

A push is atomic at the granularity of a head advance. Each push **attempt** has a random `push_id`
(`PUSH_ID_LEN` = 16 bytes), and every object it uploads is written to a per-push **staging** area
keyed `push_id ‖ id`, never directly to durable storage. The winning `cas-head` names that `push_id`
as its `promote` argument, and the server **promotes the whole staged set into durable storage and
swaps the ref in one redb write transaction**, inserting each staged object that is not already
durable:

> **I1 (atomic promote).** A durable head never references a non-durable object: promote + ref-swap
> are one write transaction, so a crash never leaves a durable head pointing at a staged or absent
> object, and no separate sweep is ever needed to collect a half-finished push.

What a push uploads: the new commits, the head commit's full tree closure minus everything in the
remote head's tree (which is durable there), and the older new commits' trees and chunks that are
still held locally. Nothing is skipped on the strength of a `has` answer: staging an object the
server already holds costs a re-upload, but keeps I1 true against a concurrent prune (§15.2). The
server stages every uploaded object, durable or not, and `has(ids)` reports durable existence only.

Consequences:
- A crash-resumed attempt re-stages idempotently: re-staging overwrites the same `push_id ‖ id` key.
- A `push_id` is **per attempt**, not per repo. A `cas-head` conflict (another device advanced the
  ref) makes the merge retry use a fresh `push_id`; the losing attempt's staged objects are never
  promoted (its `cas-head` never ran), so a winning promote carries exactly that attempt's closure, no
  orphans. The client persists the `push_id` to its folder state when a sync round begins and removes
  it when the round ends, so a crash mid-push resumes the same attempt on the next start.

**Idle-TTL reclaim.** Each push carries one sliding clock (`staging-meta[push_id] = last_activity`),
refreshed on every staged `put`: per push, not per object, so a live upload of however many objects
is never reaped. A server background timer (every `reclaim_tick_minutes`, since an idle accept loop
never runs) drops the **whole** staging range of any push idle past `staging_ttl_hours` and **never
touches durable storage**. An abandoned push (objects staged, head never advanced) thus reclaims
itself; no committed data is ever at risk, because a promoted set is no longer staging.

### 15.2 Count-based retention

History is bounded by keeping, **per file, the last `keep` versions** (`retention_keep_versions`,
default 8; `0` = keep everything). A "version" of a file is a commit in which that file's content
changed against its first parent: one row of `secsec log <path>`. The policy is per file, not per
repo snapshot (eight whole-repo snapshots would be seconds of history under commit-on-change).
Versions are counted in the history's topological order (children before parents); where commits are
DAG-incomparable, their author timestamps order them, so timestamps can decide which versions of a
concurrently edited file fall inside the window, never whether the head's own content is kept.

What is kept and what is pruned rests on two invariants:

> **I4 (commits and trees are kept).** Every **commit object** and every **tree** reachable from the
> head is kept forever (they are small), so the parent-graph walk, `secsec log`, and every diff always
> resolve. Only **chunks** are pruned.

> **I5 (horizon implicit in presence).** Pruned content is simply **absent**; there is no horizon
> predicate threaded through the code. Content walks are therefore **strict on the head commit's own
> tree** (a missing *current* object is a real error) and **skip-missing on ancestor content** (a
> pruned old version). A fresh clone fetches current content plus the commit and tree skeleton;
> historic chunks are fetched on demand by `log`/`restore`.

The kept set is the head's full current content plus, per file, the chunks of its last `keep`
changing versions. Every other chunk reachable only from older versions is pruned. Restoring a pruned
version is a clean `PrunedBeyondRetention` error.

**The prune** is the only client-driven server deletion, run once per sync session after its first
successful round. The client computes the **dead set** (chunk ids) locally, drops it from its own
cache, and asks the server to delete it:

```
Request::Prune { dead: Vec<Id>, all_heads_hash: [u8;32], roster_len: u64 }                     // batched ≤ 1,024
args_hash = BLAKE3(bytes("prune") ‖ dead_set_hash ‖ all_heads_hash ‖ le64(roster_len))       // secsec-write-v1
```

`roster_len` is the number of sigchain entries (the tip seq plus one; 0 for an empty roster). The
server **recomputes `all_heads_hash`** (over every stored ref: the same per-ref blob-hash token
`cas-head` compares on, §12) and the roster length, and deletes in the same write transaction only if
both still match: a **head-binding compare-and-swap**. A moved head or roster makes the prune a CAS
conflict that deletes nothing; the client retries on a later poll tick. Because it is a **delete-set,
not a keep-set**, an omitted id only means *delete fewer*, never *destroy live data*: there is no
completeness requirement and no keep-set size cap.

**The resurrection-via-dedup race is closed.** A device that reverts a file re-derives an old chunk
id. Were it to skip that upload because the server held the chunk, a prune landing between its upload
phase and its `cas-head` could delete the chunk and leave the new head referencing a missing object.
The push never skips on `has` (§15.1): the reverted chunk is staged, and the promote reinstates it if
the prune removed the durable copy meanwhile. A prune computed after the `cas-head` sees the chunk as
live; one computed before it is a CAS conflict.

### 15.3 Per-key write cap

`StorageQuota` is a per-key cumulative **new-write** cap for one serve session, charged on the bytes
a promote actually makes durable (§12), so idempotent re-puts and abandoned staging are never
counted. It is **unlimited by default** (secsec is single-user self-hosted; the filesystem quota is
the durable bound and retention bounds version growth), while a finite `storage_cap_gib` limits a
**compromised device's** blast radius. A commit whose newly durable bytes exceed the remaining budget
has its promote rejected with a clear `RateLimit`, never silently; a finite cap below a single
commit's footprint hard-blocks that file until raised, but the default never hits this. Durable
protection against disk exhaustion is the operator's filesystem quota on the store directory, the
standard control for a self-hosted, single-user server.

### 15.4 Local cache hygiene

The content-addressed cache the client pushes from (`objects.secsec`) is swept once per session by
`local_sweep`: it drops objects unreachable from the last-synced head (orphans from cas-conflict
retries) and keeps the head's full reachable closure (no grace window; the cache serves only this
device). The cache is then compacted, so the freed pages shrink the file.

---
## 16. Downgrade protection & crypto agility

- TLS ciphersuites/KX and the SSHSIG signature algorithm are **fixed**, not negotiated.
- A **compile-time floor** rejects any FRAME `algo_id`/`format_version` outside the set this build
  decodes (`format_version` 1 and 2, object suite 1).
- Keyslots carry an `algo_id`. This build speaks exactly one, X-Wing (`algo_id = 1`): every keyslot
  it writes uses it, a fetched keyslot of a lower id is rejected as unsupported, and one of a higher
  id stops the client with an upgrade-required error instead of being misread.
- A **`SetMinAlgo` sigchain entry** raises the repository's `min_algo` floor; the fold takes the
  maximum. A client whose build cannot meet the folded floor stops with an upgrade-required error at
  every cold start. No command authors a `SetMinAlgo` entry yet (**NOT WIRED** in the CLI); the fold,
  the floor check, and the anti-rollback that keeps an entry once seen are in place for the next
  keyslot algorithm, whose grants MUST then wrap at or above the floor.
- **`SetMinAlgo` withholding:** anti-rollback prevents the server from rolling back a `SetMinAlgo`
  entry once a client has advanced its anchor past it (§8.1). A device that has *never* received a
  `SetMinAlgo` entry (because the server withheld it from genesis) cannot benefit from the downgrade
  protection that entry provides; on a single host there is no second remote to expose the omission,
  so this is an accepted residual (§21), bounded by the compile-time floor, which no withholding can
  lower.

## 17. Post-quantum posture

The symmetric layer (ChaCha20-Poly1305, BLAKE3, 256-bit keys) is PQ-safe. The harvestable exposure
is the asymmetric keyslot wrap. Every keyslot is a **hybrid** keyslot using **X-Wing**
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
draft-connolly-cfrg-xwing-kem-10 §6. Implementations MUST verify a byte-identical shared secret
against the draft-10 Appendix C test vectors before being accepted as conformant. (Cross-check: seed
`7f9c2ba4…ef26`, eseed `3cb1eea9…85b2` ⇒ ss `d2df0522…e384`.)

This achieves IND-CCA security (classical: gap-CDH in ROM; post-quantum: ML-KEM-768 IND-CCA) and
satisfies MAL-BIND-K-CT and MAL-BIND-K-PK when ML-KEM-768 keys are held in seed form. The `ct_MLKEM`
omission from the KDF is proven safe for ML-KEM-768 specifically (the FO transform guarantees
ciphertext collision resistance); this optimisation MUST NOT be generalised to other PQ KEMs.

**ML-KEM-768 key storage:** key pairs are held exclusively in seed form; the expanded keypair
`(ek, dk)` is derived at runtime per FIPS 203 §7.1. At every derivation the FIPS 203 §7.1 keypair
consistency check is performed (the encapsulation key is validated and an encapsulate/decapsulate
round trip must agree); failure is fatal. A published X-Wing public key is validated (FIPS 203 §7.2)
before any keyslot is wrapped to it. The expanded `ek` is never stored persistently. This requirement
prevents MAL-BIND-K-CT and MAL-BIND-K-PK failures that arise under the expanded-key representation
(Schmieg, ePrint 2024/523).

Every keyslot (at genesis, enrollment, and every rotation) is the **hybrid-PQ X-Wing** keyslot
(§8.3), so the harvestable asymmetric exposure is post-quantum by construction. **Signatures** are
classical (Ed25519): forgery is *online*, not harvestable (an attacker needs the quantum computer at
the moment of the attack, and a recorded signature broken later is worthless), so a PQ signature is
lower urgency and can be added through the same `algo_id` / `SetMinAlgo` agility if quantum becomes
imminent. Confidentiality (the symmetric data plane + the X-Wing keyslot) is the
harvest-now-decrypt-later target, and it is PQ-safe today.

## 18. Implementation hardening

- **Memory:** `master_key`, all derived subkeys, and SSH private material are held in
  `zeroize::Zeroizing` (zeroized on drop), RAM-only, never serialized to disk. (`secrecy` wrappers
  and `mlock`/`region` page-pinning are **NOT WIRED**; full-disk encryption covers swap and
  hibernation images. A blanket `mlockall` is ruled out: it would pin the memory-mapped redb files.)
- **Constant-time:** every comparison of secret-derived values (AEAD and CTX tags, content ids on
  fetch, invite-code MACs, the pinned host key in the TLS verifier, the vouched `host_id` during
  pairing) uses `subtle`. Public values (RFP, `mk_commit`, a pin compared to a folder's own link) use
  plain equality.
- **RNG:** OS CSPRNG (`getrandom`) only; no userspace PRNGs for keys, salts, or nonces.
- **Parsers:** size/depth/fan-out/length bounds enforced before allocation per the §19 normative
  constants; `cargo-fuzz` targets for every decoder of untrusted bytes, also run on stable as a test
  corpus; non-canonical encodings rejected.
- **Secrets never logged;** no key material in error messages.
- **On-disk state is owner-only** (0600 files / 0700 directories on unix, set at creation so the bytes
  are never briefly world-readable): the server's self-signed TLS host key, and every client trust
  anchor: the per-folder `link` (pinned `host_id`, RFP, anti-rollback anchor), the sealed `frontier`,
  `base`, and `push_id`, plus the desktop UI's config and log. The host key grants no data access
  (the server is blind), but leaking it hands an attacker a MITM position against clients that
  already pinned it; the link and frontier are the §21 disk-level rollback surface. A client refuses a
  private key file readable by others, as `ssh` does.
- **Restore hygiene:** tree entry names are single path components with no separators, no `.`/`..`,
  and **no control characters** (path-traversal + terminal-escape guards, enforced at decode and
  skipped symmetrically at snapshot, §6); the restored `mode` is the 9 standard permission bits only
  (**setuid / setgid / sticky are dropped**), so a compromised member cannot plant a setuid/setgid
  file on every device; a restored file never exceeds its declared size or a chunk the chunker's
  maximum. Writing a tree back to the working folder reconciles it against this device's snapshot,
  never following a symlink and never deleting what that snapshot did not track, a lone macOS folder
  icon leaving with its deleted folder aside (§6, §10). An explicit restore writes only inside the
  synced folder: it refuses `..` and any symlink or non-directory on the way.
- **Supply chain:** minimal pinned deps (`Cargo.lock`, `--locked` everywhere); `cargo-audit` in CI,
  with one ignored advisory (`RUSTSEC-2023-0071`, `rsa`, an optional `ssh-key` dependency this
  workspace never enables; `.cargo/audit.toml`); `cargo-vet` is **NOT WIRED**; no OpenSSL. The PQ KEM
  rests on the formally verified `libcrux-ml-kem`. Linux release binaries are static `musl` builds;
  `cargo xtask release` prints a reproducible build recipe (fixed `SOURCE_DATE_EPOCH`, remapped
  paths), which the release workflow does not yet follow (**NOT WIRED**).
- Do not trust returned FRAME fields; derive keys from the expected type, resolve the generation
  through the key ring, and verify FRAME equality.

## 19. Constants _(normative: required for conformance)_

Values marked **operator-tunable** are read from `secsec.config` (`$XDG_CONFIG_HOME/secsec/secsec.config`,
else `~/.config/secsec/secsec.config`), written with these defaults by the first command that loads
it, and **range-clamped on load**, so a config can never produce a breaking value. Everything else is
compiled in: a constant that must be identical across peers (changing it would alter a content id or
the wire contract) or that bounds an attacker is **not** configurable. The `[client]` and `[server]`
headers only group the keys: `serve` also uses `quic_idle_secs` (only a client sends keepalives).

| Knob | Value | Note |
|---|---|---|
| Chunking min/avg/max | 16 / 64 / 256 KiB | keyed FastCDC-style cut points (§9.7) |
| Pack target | 8 MiB | small-chunk **packing** is **NOT WIRED** (one object per chunk); target reserved for it |
| Listen port | udp/8899 default | operator-tunable (`listen_port`; `serve --port` overrides) |
| QUIC idle / keepalive | 30 s / 10 s default | operator-tunable; idle ≥ 5 s and also the server's handshake deadline; keepalive forced below idle |
| Watch debounce | 1,000 ms default | operator-tunable (`watch_debounce_ms`, ≥ 100) |
| Poll interval | 15 s default | operator-tunable (`poll_interval_secs`, ≥ 5); also the longest a burst of edits waits |
| `server_nonce` size / TTL | 32 B / 60 s | one fresh challenge per request stream; a write must arrive within the TTL of its challenge; an open connection's first request after this long since the last `authorized_keys` check re-checks it (§11) |
| Push id length | 16 B | `PUSH_ID_LEN`; the per-attempt staging key (§15) |
| Staging idle TTL | 24 h default | an abandoned push's staging is reclaimed past this idle window (§15); operator-tunable (`staging_ttl_hours`) |
| Reclaim sweep cadence | 60 min default | how often the server sweeps idle staging (§15); operator-tunable (`reclaim_tick_minutes`) |
| Metadata padding buckets | powers of two | **NOT WIRED**: trees/commits/heads/roster entries are sealed at true size (§21) |
| Chunk padding policy | power-of-two | pads to the next power of two above the length (≤2× overhead); the uniform and off policies are **NOT WIRED** (§9.7) |
| Per-key storage quota | unlimited default | operator-tunable (`storage_cap_gib`); a finite cap is a per-session new-write anti-flood charge at promote (a dedup store has no durable per-key byte ownership, §12, §15.3); durable disk limits are the operator's filesystem quota |
| Per-key write / read rate | 100 / 200 MB/s sustained default | operator-tunable (`write_rate_mb_s`, `read_rate_mb_s`); enforced after auth; 2× read allows sync catch-up without unbounded egress |
| Write burst | 1 GiB | compiled-in; ≥ the 16 MiB object cap so a single object always fits regardless of the configured rate |
| Connection limits | 10 new/s per source IP; 256 concurrent server-wide, handshakes in flight included; 3 concurrent per authenticated key (defaults) | operator-tunable (`conn_rate_per_ip`, `max_connections`, `max_conns_per_key`, each ≥ 1); a full server-wide cap refuses new connections until one ends |
| Device key algorithm | **Ed25519 only** | RSA/ECDSA/`sk-*` keys are rejected at load (scope) |
| Connection gate | `~/.ssh/authorized_keys`, re-parsed on change, checked at connect and on the first request after 60 s, fail-closed | mandatory: `secsec serve` refuses to start without a usable key (§11, §12) |
| Keyslot KEM | **X-Wing** (ML-KEM-768 ⊕ X25519, draft-connolly-cfrg-xwing-kem-10), `algo_id = 1`; CTX AEAD AD = "secsec-keyslot-v1" ‖ device_id ‖ le32(gen); device X-Wing seed = `derive_key("secsec-xwing-seed-v1", ed25519_seed)` | post-quantum; the keyslot KEM (§8.3) |
| Retention | last 8 versions per file default | `retention_keep_versions` (0 = keep everything); count-based, client-driven chunk prune under a head-CAS (§15); operator-tunable |
| Invite code length | 96 bits (12 bytes, OS CSPRNG), single-use; displayed as dash-grouped lowercase hex | the §7 out-of-band pairing secret; single-use + the mailbox TTL + the `authorized_keys` gate bound online guessing |
| Pairing mailbox TTL (`PAIR_TTL`) | 600 s | server-side lifetime of an invite-pairing slot; an expired or taken slot ends the exchange (§7, §12) |
| Pairing mailbox slot cap / poll | 256 slots / 500 ms poll | bounds mailbox memory; pairing blobs are also charged against the connecting key's rate limits (§12) |
| Invite wait | 1,200 polls (10 min) inviting, 240 polls (2 min) joining | how long each side waits for the other |
| Max has() ids per call | 1,024 | server rejects with too-many-ids before any lookup |
| Max prune() dead-set ids per call | 1,024 | server rejects with too-many-ids; the client batches larger sets (§15) |
| dead_set_hash canonical encoding | BLAKE3(le64(count) ‖ id[0] ‖ … ‖ id[count-1]), ids ascending byte-lexicographic and deduplicated | normative for the prune `args_hash` (§15); both sides MUST use this exact encoding |
| all_heads_hash canonical encoding | BLAKE3(le64(n) ‖ (H ‖ BLAKE3(head blob))…), refs sorted, exact duplicates folded | normative for the prune `args_hash` (§15) |
| Max sigchain entries per authenticated key per hour | 60 | counted per entry a `roster-batch` appends, per `device_id`, in a trailing hour; refunded when the batch loses its CAS |
| Max total sigchain length | 10,000 entries | compiled-in; the server refuses a batch past it and the client refuses a fetched chain past it |
| Key-history depth (generations) | unbounded (never trimmed) | both the data and roster key-histories keep one 64-byte wrap per generation; total is bounded by the sigchain-length cap (§8.2) |
| Max blob size (any object type) | 16 MiB | decoders reject before allocating |
| Max tree depth | 64 levels | decoders reject before allocating |
| Max tree fan-out per node | 65,536 entries | decoders reject before allocating |
| Max tree entry name | 4,096 bytes | decoders reject before allocating; keep-both names are truncated to fit |
| Max roster entry size | 4 KiB | decoders reject before allocating; also bounds keyslot, key-history, and pairing blobs |
| Max list fields (sigchain batches, keyslots, revocations, frontier maps) | 4,096 elements | decoders reject before allocating |
| Max chunk ids per file | 524,288 (= max blob size / 32) | derived, not chosen: exactly what a 16 MiB tree blob can hold at one 32-byte id each. The **binding** limit is the encoded tree, which is a per-directory budget: chunk ids from all of a directory's files share the same 16 MiB. Enforced on **both** sides (§6): a decoder rejects a longer list, and a snapshot never authors one |

## 20. Crates

`quinn`,`rustls` (with the `ring` provider), `rustls-webpki`, `x509-cert`, `rcgen` (host-key
generation) · `ssh-key` (SSHSIG, Ed25519-only), `x25519-dalek`, `sha2`, `rand_core` · `libcrux-ml-kem`
(ML-KEM-768 for the X-Wing keyslot), `sha3` · `blake3` (hashing, KDF, and the keyed chunker's gear
table) · `chacha20`+`poly1305` (the §9.4 CTX committing AEAD, built from the raw primitives) ·
`notify` · `redb` · `tokio` · `zeroize`, `subtle`, `getrandom` · the CLI's `clap`, `rpassword`,
`socket2`, `filetime`, `tempfile`, and `rustix` (unix signals). Transport is **QUIC/TLS-only** (no
SSH/stdio mode; it adds nothing over the pinned host key, §11). Versions are pinned by `Cargo.lock`;
`cargo-audit` gated (`cargo-vet` **NOT WIRED**). The keyed chunker's gear table is hand-composed on
`blake3`, not the `fastcdc` crate.

## 21. Residuals (proven-minimal)

These are impossibilities for a blind, untrusted server, or chosen tradeoffs, with their
mitigations; not deferred work:

- **Availability/durability.** A hostile or dead server can refuse or delete. secsec is single-host
  (§14), so there is no server-side replica to fail over to; the mitigation is that every enrolled
  device holds the working set and can re-establish the repo on a replacement server. History beyond
  what device caches hold lives only on the server, and history beyond `keep` versions per file is
  intentionally pruned: `restore`/deep `log` content is bounded to the retained window. A
  staged-but-uncommitted push reclaimed by the idle TTL costs no committed data (the head never
  advanced).

- **Reinstall freshness.** A device that loses *all* local frontier state can still verify
  **authenticity** (RFP + `mk_commit`, §7) but cannot alone prove it was served the *latest* head.
  On a single host there is no peer/replica cross-check to appeal to, so this residual applies on
  every reinstall until another live device reconverges on the same server. (A frontier that fails
  to open raises an alarm; a missing one on a linked folder a warning, §8.5.) The SUNDR lower bound is
  the floor.

- **Sustained-partition forks** are *delayed*, not prevented (SUNDR). The same-server keep-both merge
  (§10) reconciles a fork on any reconvergence; a sustained partition simply delays that
  reconvergence.

- **Total credential loss.** A user who loses *every* enrolled device **and** every backup of the SSH
  key cannot recover: information-theoretic. Mitigation: back up the SSH private key (the one
  credential); a device holding it re-joins via an invite (§7). There is deliberately **no**
  server-stored recovery blob (§8.6): adding one would create an offline-crackable target on the
  untrusted server to back up what the SSH key already covers.

- **Compromised client.** Plaintext and `master_key` live on the client by necessity; its compromise
  is total for that device. Mitigation: prompt revoke+rotate; `zeroize` (keys are RAM-only, zeroized
  on drop) limits key scavenging. (`mlock` page-pinning is **NOT WIRED**; full-disk encryption covers
  swap, §18.)

- **Local frontier rollback by a disk-level attacker.** The sealed local-state file (§8.5) is encrypted
  under a *static* key (derived from the SSH private key), so an older sealed copy still verifies. An
  attacker with raw read/write access to the device's disk could restore an older copy to rewind the
  persisted anti-rollback frontier (or the link's anchor), after which a colluding server could replay
  state up to that point. This is largely subsumed by *compromised client* (a disk-level attacker
  generally also holds the SSH key, hence total access); a hardware monotonic counter would close it
  but is out of scope.

- **Revoked-device access to pre-rotation data.** A revoked device that retained `master_key_g` in
  memory can, colluding with the server, decrypt any gen-g object the server still holds. Keyslot
  deletion prevents re-deriving `master_key_g` from the server, but does not affect in-memory copies.
  Rotate-all re-encryption (re-encrypting all existing objects as gen-g+1, then deleting the old ones)
  is the only complete mitigation; absent it, revocation provides forward secrecy only for data
  created after the rotation event. This is not a narrow carve-out: it applies to all pre-rotation
  ciphertext, not merely data the device had already decrypted before revocation. A revoked device
  still listed in `authorized_keys` can connect but is refused every repo op once its keyslots are
  deleted (cooperative server); on a malicious server that ignores the deletion, it retains whatever
  gen-g access it had before the rotation.

- **Concurrent mutual-revocation race.** All devices are flat, equal members; there is no privileged
  founder (§8.4). When the legitimate device revokes a stolen one (`RevokeDevice` + `Rotate`), a
  stolen device that is unlocked, online, and racing can concurrently issue `RevokeDevice` + `Rotate`
  against the legitimate device. The tip CAS serializes the two; whichever lands first wins. If the
  stolen device wins, the legitimate device re-folds onto the new tip, finds itself revoked, and its
  retry fails succession (§8.1): it cannot append, the attacker keeps the repo, and the user is
  evicted. This bites **only** when the stolen device is unlocked, online, and actively racing, a
  state in which it already holds `master_key_g` and thus already had full data access; it is not a
  new exposure of data, only of repository control. Mitigation: revoke promptly while the legitimate
  device is the only one online; device credential/physical security. The flat-device model has no
  privileged founder key or recovery-code gate on revocation, so this race is its accepted cost.

- **Bounded metadata leakage: object sizes.** Chunk sizes leak within power-of-two buckets (§9.7).
  Metadata objects are sealed at their **exact** size (metadata padding is **NOT WIRED**): a tree
  blob's size reveals how many entries and chunk ids its directory aggregates (the coarse shape of
  the directory tree, never names or contents), a head's size is near-constant, and a roster entry's
  size distinguishes an `AddDevice`/`Genesis` (which carries a ~1.2 KB X-Wing public key) from a
  `RevokeDevice`/`Rotate`/`SetMinAlgo`, so the server can read the class of each membership event by
  size alone. Access timing leaks. Identical content at different paths never yields equal ids (the
  per-path salt, §9.7), so the server sees no cross-path equality.

- **Bounded metadata leakage: intra-file temporal.** The per-path salt is generated once at first
  sync and is constant across all versions of a file. When a file is modified, unchanged chunks
  produce the same chunk id across sync sessions, so the server observes per push which chunk ids are
  new, revealing the chunk-level edit distance for each modified file without reading any ciphertext.
  The per-path salt prevents a third party from computing expected ids for a suspected plaintext, but
  not the server from observing the upload delta. Eliminating this leak entirely would require a
  per-version salt, which disables intra-file dedup. This is a chosen tradeoff.

- **Keyed chunking chosen-plaintext key extraction.** `cdc_seed` secrecy is contingent: an adversary
  who can cause the victim to archive chosen-plaintext data can recover the secret gear-table key
  (Alexeev et al., ePrint 2025/532). Power-of-two chunk padding substantially reduces the boundary
  signal (a uniform policy would eliminate it, but is **NOT WIRED**); `cdc_seed` is generation-scoped,
  so rotation limits exposure. Not an information-theoretic impossibility.

- **SetMinAlgo withholding for devices that have never received the entry.** A device that has never
  been served a `SetMinAlgo` entry (the server withheld it from genesis) operates at the
  **compile-time algorithm floor** (§16) rather than any higher floor that entry would set. The
  compile-time floor, which no withholding can lower, is the bound; once a client *has* received a
  `SetMinAlgo` entry, anti-rollback (the persisted anchor) keeps it from being dropped later.

- **Retention prune is best-effort against a malicious server.** The prune (§15) deletes under a
  head-binding CAS, so a *concurrent* head or roster change makes it a no-op rather than a live-data
  delete, and a push stages everything its head needs outside the remote head, so a racing prune
  cannot dangle it. A malicious server can still simply ignore a prune (keeping old ciphertext it
  should have dropped) or delete beyond it (the deleting-server case above). Neither reads plaintext;
  the bound is the device-side replicas (§14).

- **Key-rotation count and timing leakage.** The storage layout uses plaintext generation indices in
  `/keyslots/<device_id>/<g>` and `/keyhist/<g>`. A malicious server enumerating these paths learns
  the master-key rotation count (number of `Rotate` events), when each rotation occurred (from write
  timestamps), and how many devices held a keyslot at each generation. This is an accepted tradeoff,
  **not** an impossibility, but opaquing `g` is not buildable in the base protocol: the API has no
  `list` operation (§12), so a device must compute the exact path of objects it has not yet
  decrypted (its own keyslot, and the key-history chain on reinstall). A secret-derived path component
  would therefore be circular (it depends on the key being fetched) or require a second out-of-band
  anchor beside RFP (§13). The leak is low-sensitivity metadata, on par with the device-count and
  access-timing leaks below.

- **Ref-name and path leakage (chosen tradeoff).** Ref names are stored under keyed hashes (§13); the
  server cannot read them. Device public keys are not exposed in storage paths (§13, `device_id`), but
  the pairing mailbox relays a joining device's public keys in the clear (MAC'd, §7). The set of
  `device_id`s is enumerable from `/keyslots/*` paths, which reveals the number of enrolled devices,
  and (per the rotation-count entry above) the generation components in those paths reveal the
  rotation history. These are chosen tradeoffs, not impossibilities.

- **First-contact TOFU window.** A first `secsec sync` without `--pin` accepts the host key on first
  use: it captures the key's SPKI hash and prints the host pin for a one-time human comparison that
  is not mechanically enforced. A network attacker present at that first contact can substitute
  their own host key; once accepted, all subsequent connections verify against the attacker's key,
  giving them a persistent MITM position. Mitigation: pass `--pin` (the installer prompts for it), or
  verify the printed pin out-of-band before continuing. (A joining device additionally removes this
  exposure: the inviting member vouches for the genuine `host_id` under the invite-code MAC, and the
  joiner aborts if it does not match the server it connected to, §7.) The window is bounded to the
  first contact: after the pin is persisted in the folder's link, no further TOFU exposure exists.
