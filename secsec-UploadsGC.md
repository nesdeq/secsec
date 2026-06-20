# secsec — Uploads, staging, retention, and config

Implementation-ready design for: streaming/resumable large-file uploads; replacing reachability
garbage collection with transactional push; bounding storage with **count-based** per-file version
retention; and moving the safely-tunable constants into a `secsec.config`. Companion to
[`secsec-Design.md`](secsec-Design.md) (`§N` → there) and
[`secsec-Implementation.md`](secsec-Implementation.md). Line refs are to the **current** tree; this
doc is the forward plan — the current GC/receipt design it replaces is in Design §13/§15/§19/§21.

> **Ground rules (standing).** Zero users → **break freely, no backward compatibility, no migration
> code, ever.** Tightest correct code wins. Hard wire break: bump `SECSEC_VERSION` 1→2; `Store::open`
> materializes the new schema; any pre-existing `repo.secsec` is incompatible and discarded.

> **Two storage problems, two fixes.** *Orphans* (objects uploaded whose head never landed) →
> **transactional staged push** (§3); no GC. *History growth* (old versions kept forever) →
> **count-based retention** (§5): keep the last N versions per file via a tiny delete-set op guarded
> by a head-binding CAS — the only client-driven server deletion that survives.

> **Load-bearing invariants** (cited inline):
> - **I1** A durable head never references a non-durable object — promote + ref-swap are one redb txn.
> - **I2** The streaming chunker yields byte-identical FastCDC cut points to today's `Chunker`.
> - **I3** `has()` reports **durable-only**; a push queries its own staging via `has_for_push`.
> - **I4** Commit *objects* are kept forever (parent-graph walk always resolves); only tree/chunk
>   *content* of beyond-window versions is pruned.
> - **I5** Content walks are **strict on the head commit's own tree** (current content complete or
>   error) and **skip-missing on ancestor content** (pruned old versions). The retention horizon is
>   *implicit in presence*, not a predicate threaded everywhere.

---

## 1. Space model (read this first)

What an edit costs, and why we chunk:

- **FastCDC dedup is the per-edit lever.** Content-defined boundaries mean an edit to an uncompressed
  file re-chunks only locally (the chunk(s) at the edit, ~one chunk; insert/delete re-syncs at the
  next content boundary, no cascade). Unchanged chunks keep identical `content_id` → `put` is a no-op
  and `has()` skips the upload. **A 1-byte edit to a 20 GB uncompressed file stores/uploads ~low MB,
  not 20 GB.** Without CDC every save re-uploads the whole file — CDC *is* incremental sync.
- **Where dedup can't help (be honest):** pre-scrambled data — an already-encrypted volume, a
  compressed archive (`.zip`/`.gz`), a DB that rewrites pages — diffuses a small logical change across
  every byte, so every chunk changes → each edit ≈ full file. This is a fundamental CDC limit (any
  byte-differ fails the same way), not a bug. Retention bounds *how many* such versions are kept; it
  doesn't make each cheap. secsec chunks+encrypts **plaintext** per chunk (the only way to get dedup
  *and* E2E) — syncing a pre-encrypted blob through it defeats its own dedup.
- **Rotation re-store (a real cost, separate from edits):** `content_id` binds the generation
  (`seal_object` → `Frame::v1(mk.generation(), …)` + `id_key[gen]`). So a key **rotation** (forced by
  `revoke`, on purpose — forward secrecy) makes the next `snapshot` re-seal current content under the
  new generation → new ids → a full re-upload of the working set, with the old-gen copies kept until
  they age out of retention (≈2× transiently). **Mitigation (load-bearing, not just perf):** the
  §4.4 mtime/size fast-path reuses an unchanged file's prior chunk ids (old generation) verbatim, so
  a rotation does **not** trigger a full re-seal. Cross-generation object references are already
  legal (a member peels the §8.2 key ring to read them).

**Net model with the proposed defaults:** per-edit cost = changed chunks only (× ≤2 padding, §9.7);
storage = working set + the last `keep=8` versions per file; a revoke re-stores the working set once
(mitigated by the fast-path).

---

## 2. At a glance

| # | Goal | Mechanism |
|---|---|---|
| U1 | Files > RAM | streaming chunker (snapshot) + streaming restore; peak RAM ≈ `DEFAULT_MAX` |
| U2 | Resume across sessions/crashes | per-folder persisted `push_id`; `has_for_push` skips already-staged |
| U3 | Don't re-send what the server holds | `Remote::has` (durable, **I3**) pre-filter in `push_objects` |
| U4 | Throughput | bounded-concurrent in-flight puts |
| U5 | No re-seal of unchanged files (rotation) | mtime/size fast-path reuses prior chunk ids |
| T1 | Atomic push | stage under `push_id`; `cas-head` promotes the set ∧ swaps the ref in one redb txn (**I1**) |
| T2 | Abandoned pushes reclaim themselves | server-local sliding **idle-TTL** sweep (background task) |
| G1 | Reachability-GC deleted | no keep-set, `gc_gen`, grace, receipts, `put_epoch`, ARRIVAL, 100k cap, 4/hr cap, `Gc` op |
| H1 | Bounded storage | **count-based** retention: keep last N versions per file; delete-set + head-CAS (§5) |
| F1 | Per-key flood isolation | per-key new-write cap, charged at promote; configurable, **default unlimited** (§6) |
| C1 | Safe tuning | `secsec.config`, defaults on first run, out-of-range clamped (§7) |

---

## 3. Transactional staged push

### 3.1 Store API (`secsec-store/src/lib.rs`)

`OBJECTS` (existing) **is** durable. Add one table; delete two.

```
+ STAGING:       key = push_id(16) ‖ id(32)  ->  blob
+ STAGING_META:  key = push_id(16)           ->  last_activity(u64 le)   # ONE sliding-TTL clock per push (not per object)
- ARRIVAL  (15)            # id -> put_epoch  : reachability-GC only
- COUNTERS (17) / PUT_EPOCH(29)              : reachability-GC only
```

Materialize `STAGING` in `open()` (92–99); stop opening `ARRIVAL`/`COUNTERS`.

```rust
fn put(&self, id:&[u8;32], blob:&[u8], push_id:&[u8;16], now:u64) -> Result<(), StoreError>;
    // id in OBJECTS -> no-op (durable dedup). else STAGING[push_id‖id]=blob; STAGING_META[push_id]=now (slide the clock).
fn has(&self, ids:&[[u8;32]]) -> Result<Vec<bool>, StoreError>;                 // OBJECTS only (I3) — body unchanged
fn has_for_push(&self, push_id:&[u8;16], ids:&[[u8;32]]) -> Result<Vec<bool>, StoreError>; // OBJECTS ∨ STAGING[push_id‖·]
fn cas_ref(&self, ref_h:&[u8;32], expected_old:&[u8;32], new_blob:&[u8], promote:&[u8;16])
    -> Result<CasOutcome, StoreError>;   // one txn (I1): if token!=old -> {swapped:false}; else range-scan STAGING[promote‖·]
                                         // move each into OBJECTS, remove its STAGING row + STAGING_META[promote], insert REFS. -> {swapped:true, promoted_bytes}
fn reclaim_staging(&self, now:u64, ttl_secs:u64) -> Result<u64, StoreError>;    // for each STAGING_META idle past ttl, drop its STAGING range + the META row; NEVER touch OBJECTS
fn delete_objects(&self, ids:&[[u8;32]]) -> Result<u64, StoreError>;            // §5 prune + local_sweep backing (replaces gc())
```

Delete `gc()` (348), `put_epoch()` (332), `arrival_epoch()` (339). Move `ref_blob_hashes()` (196) /
`RefBlobHash` (35) → `proto/prune.rs` (the §5 head-CAS input). Keep `compact`, `object_count`, `has`,
keyslot/ref/roster/keyhist ops.

> **I1.** `cas_ref` does promote + ref-swap in one `begin_write()`/`commit()` (extend store:218–233).
> redb makes it all-or-nothing: a crash never leaves a durable head pointing at staging.

### 3.2 `push_id` lifecycle — per **attempt**

> A naive "one `push_id` reused across cas-conflict retries, promote the whole bucket" strands garbage
> (each retry's `engine::seal_nodes` 119–158 re-seals a distinct tree spine; the conflict label embeds
> `sibling.commit_id`, engine:377). **Per-attempt minting** makes a winning promote carry exactly that
> attempt's head closure — no superset, no orphans.

| event | action | effect |
|---|---|---|
| new local change | mint random `PUSH_ID_LEN` id, persist temp+rename **before** first stage `put` | self-contained bucket |
| crash → resume same attempt | reuse persisted `push_id`; `has_for_push` skips staged | no re-upload of progress |
| cas-head conflict → merge retry | **re-mint**; prior bucket idle-TTL reclaims | abandoned spine never promotes → zero orphans |
| cas-head Ok | delete the `push_id` file | done |

Cost: a concurrent writer winning the head race mid-upload makes the next attempt re-stage its content
(the abandoned bucket TTL-reclaims) — rare on single-writer-per-folder; no worse than today. (`discard_staging`
to avoid it: deferred, not built.)

### 3.3 Idle-TTL reclaimer + driver

`reclaim_staging` reaps a push's **whole** `STAGING` range when its single `STAGING_META.last_activity`
is idle past `staging_ttl`. The clock is **per push, not per object** — every `put` under a `push_id`
refreshes that one `STAGING_META` row, so a live upload (however many objects it is mid-staging) is
never reaped while active. It **never touches `OBJECTS`**. `run_serve` spawns a
`tokio::time::interval(reclaim_tick)` task holding `Arc<Server>` —
**not** the per-connection accept-loop `last_prune` block (main.rs ~501–515), which never fires on an
idle server.

### 3.4 Server `handle` (`secsec-server/src/lib.rs`)

- **Put** (504–536): take `push_id`; keep size/`declared_size` (511–516) + `take_write` (518);
  **remove** `add_quota` + the `present` probe (521–525); `store.put(id,blob,push_id,now)`; return
  `Response::Ok`.
- **CasHead** (537–556): take `promote`; keep `BLAKE3(new_blob)==new_head` (544) + `take_write` (547);
  `store.cas_ref(…, promote)`; on `swapped`, charge `promoted_bytes` to the §6 cap (RateLimit if over);
  else `CasConflict`.
- **+ Prune** handler (§5). **Delete** `handle_gc` (637), the early `Gc` dispatch (438),
  `quotas`/`gc_calls` (51–52), `add_quota`/`gc_record`/`gc_allow`, the local `GC_WINDOW_SECS` (21 →
  `sigchain_record` uses `limits::HOUR_SECS`), `receipt()` (384), `with_receipts` (228), the
  `receipts` field. `has` is already durable-only (add an I3 test). + `reclaim_staging` wrapper.

### 3.5 Client `Remote` + push (`secsec-client/src/{lib,quic,testmem}.rs`)

```rust
async fn put_blob(&self, id:&Id, blob:&[u8], push_id:&[u8;16]) -> Result<(), RemoteError>;
async fn has(&self, ids:&[Id]) -> Result<Vec<bool>, RemoteError>;              // batch ≤ MAX_HAS_IDS (1024)
async fn has_for_push(&self, push_id:&[u8;16], ids:&[Id]) -> Result<Vec<bool>, RemoteError>;
async fn cas_head(&self, ref_h:&Id, expected_old:&Id, new_blob:&[u8], promote:&[u8;16]) -> Result<bool, RemoteError>;
async fn prune(&self, dead:&[Id], all_heads_hash:&[u8;32], roster_seq:u64) -> Result<bool, RemoteError>; // §5
// DELETE Remote::gc + GcOutcome + Receipt.
```

`push_objects(remote, store, keys, commit_id, push_id)`:
1. `ids = reachable_objects(...)` (head's own tree **strict**, ancestors **skip-missing**, I5).
2. `has_for_push(push_id, ids)` in ≤1024 batches → the missing set.
3. upload the missing via `put_blob(id,blob,push_id)`, bounded-concurrent (`upload_inflight` window).
4. return. `push_head` (357) passes `promote = push_id` to `cas_head`. Ordering (all puts awaited
   before `cas_head`) already correct (lib:566–571, sync:277–278). `QuicRemote` adds `expect_exists`
   (mirror `expect_blob`, 41); `MemRemote` forwards.

---

## 4. Upload hardening

### 4.1 Streaming chunker (I2) — `secsec-chunk/src/lib.rs`

`next_cut` (90–116) resets `fp=0` per call and reads only `data[min..end]`, `end=min(remaining,max)`.
Add a streaming driver over a bounded buffer.

> **I2 invariant (necessary & sufficient; red-team-verified across all size/read-width regimes):**
> never decide a cut while `buffered-after-offset < DEFAULT_MAX` unless real EOF is in the buffer.
> Then `next_cut(window) == next_cut(full_remainder)` byte-for-byte. A divergent cut changes
> content-ids → breaks dedup/merge-equality (a §9.7 *correctness* property; integrity holds —
> mismatched ids just fail verification). **Ship a byte-identical-cut KAT vs today's `Chunker` as a
> CI gate before the streaming path replaces `chunks()`.**

### 4.2 Streaming snapshot & restore — `secsec-snapshot/src/lib.rs`

- `snapshot_dir` (511–597): replace `std::fs::read` (539) + `chunks(&data)` (546) with the streaming
  driver — `pad_chunk`+`seal_object`+`store.put` per cut; accumulate only the id `Vec` + a running
  byte count for `size`. Salt reuse (541), `Entry::File` (552) unchanged.
- `restore_tree` (642–664) / `restore_path` (958–966): after `clear_for_regular_file`, create the
  file, `fetch_open → unpad_chunk → write_all` per chunk with a running counter; assert
  `counter==size` (655/963). Per-chunk §9.2 verify unchanged.

### 4.3 has-filter + concurrency — `secsec-client/src/lib.rs`

`push_objects` (319–333) is serial, one-RPC-per-object, no filter. → §3.5: `has_for_push` filter +
bounded-concurrent puts into staging.

### 4.4 mtime/size fast-path (U5 — fixes rotation re-store) — `secsec-snapshot/src/lib.rs`

In the `is_file()` arm: if `prev_entry` is `Entry::File` with matching on-disk `mtime` **and** `size`,
reuse its `chunks`+`path_salt` verbatim (skip read/chunk/seal). Reusing the prior ids means an
unchanged file is **not** re-sealed under a new generation after a rotation — the headline space win.
Untrusted (a wrong mtime only forces a re-chunk; the id is still the content address); the §3.5 has-filter
still runs on the reused ids.

### 4.5 Resume state — `bin/secsec/src/main.rs`

Crash-safe `push_id` file under `state_dir_for` (292), temp+rename **before** the first stage put,
reused on crash/cas-conflict-resume, deleted on the committing `cas_head` Ok. Thread `push_id` through
`sync_once → sync_ref → push_objects → push_head`.

---

## 5. Bounded history retention (count-based)

### 5.1 Policy

Keep the **last `keep` versions per file** (`config: retention_keep_versions`, default **8**; `0` =
keep-everything). A "version" of a file = a commit where that file's content changed = one row of
`secsec log <path>`. Per-file, not per-commit (8 repo-snapshots = seconds under commit-on-change).
Topology-based — **no timestamp trust.** Client-driven, best-effort, in the sync loop. Set the same
`keep` on all devices for consistent behavior; the server reflects the union of what any device prunes.

### 5.2 Kept vs pruned

- **Kept forever (I4):** every **commit object** reachable from the head (tiny; keeps `log` and the
  parent-graph walk total).
- **Kept:** the tree/chunk **content** of the head's full tree **and**, per file, the content of its
  last `keep` changing-versions (the file's chunk-lists + the tree spines that resolve them).
- **Pruned:** content reachable only from versions older than each file's last `keep` — i.e.
  superseded old chunks/trees not shared with any kept version.

### 5.3 The prune (the only client-driven server deletion)

Wire op (replaces `Gc`):

```rust
Request::Prune { dead: Vec<Id>, all_heads_hash: [u8;32], roster_seq: u64 }   // batchable
```

`args_hash = BLAKE3("prune" ‖ dead_hash ‖ all_heads_hash ‖ roster_seq)` (`secsec-write-v1`). The
server **recomputes** `all_heads_hash` (over its refs) + `roster_seq` and **rejects on mismatch** —
the head-binding **CAS** that defeats the resurrection-via-dedup race: a device reverting a file
re-derives an old chunk id and `has`-skips its upload, then `cas-head`s a new head referencing it; the
moved `all_heads_hash` makes a concurrent `Prune` `CasConflict`, so the client re-pulls, recomputes
(the now-reachable id drops out of `dead`), and retries. Then `store.delete_objects(dead)`.

> Delete-set, not keep-set: an omitted id just means *delete fewer*, never *destroy live data* → no
> completeness, **no 100k cap**; batch freely. The head-CAS handles the temporal race.

Client driver (`secsec-client/src/gc.rs` → `prune.rs`; most of the old file is deleted):

```
prune_history(remote, store, keys, head, keep, roster_seq):
  if keep == 0: return
  kept = reachable_content(head, strict=head)                 # head's full closure
  seen = {}                                                   # path -> versions kept
  for commit in topo_order(head):                             # newest->oldest; commits all present (I4)
      for path in changed_paths(commit vs first_parent):
          if seen[path] < keep:
              seen[path] += 1
              kept ∪= resolve_content(path @ commit)          # chunk-list + tree spine
  dead = reachable_content_all(head, skip_missing=true) \ kept   # locally-present old content not kept
  store.delete_objects(dead)                                  # prune local cache symmetrically
  for batch in dead.chunks(PRUNE_BATCH):                      # head-CAS; CasConflict -> re-pull + retry
      remote.prune(batch, all_heads_hash(refs), roster_seq)
```

### 5.4 Horizon-aware walks (I5) — content skips-missing; the head's own tree is strict

The horizon is **implicit in presence** (pruned content is simply absent), so the only change to the
content walks is: **strict on the head commit's own tree** (a missing *current* object is a real error),
**skip-missing on ancestor commits' content** (pruned). The commit-graph walk is untouched (I4).

- `collect_tree` (snapshot:807) / `reachable_objects` (775): add a `strict_head` flag — error on a
  missing object under the head's own tree; skip a missing subtree/chunk under an ancestor. The prune's
  `reachable_content_all` walk is fully lenient (skip-missing everywhere).
- `fetch_closure` (client lib:397): head's tree strict, ancestors skip-missing — a fresh clone pulls
  current content + the commit skeleton; historic versions are fetched **on demand** by
  `log`/`restore` (the existing `fetch_history`/`fetch_path_content` path), not pre-fetched.
- `merge_heads` (engine:332): the LCA *commit* is present (I4); if its `root_tree` content is pruned,
  `load_nodes` is missing → **empty-ancestor keep-both merge** (§10 already specifies this; wire the
  catch at engine:364–371).
- `restore`/`resolve_path` (snapshot:937, history:200): a pruned target → clean
  `SnapError::PrunedBeyondRetention(path)`, not a crash.
- `repo_log`/`changed_paths` (snapshot:983, history:215): `log` lists all commits (present); a
  beyond-window commit whose trees are pruned shows without a diff (catch the missing tree in
  `changed_paths`).

### 5.5 CLI tie-in (no new switches)

- `secsec log <path>` — lists the file's versions (commits kept forever, so the full list shows). The
  newest `keep` are restorable; older rows are marked `(pruned)`.
- `secsec restore <path> [version]` — `version` is a commit-id prefix from `log`; restores any kept
  version, clean `pruned beyond keep=N` error otherwise. **Signature unchanged.**
- `secsec log` (no path) and `--key`/`--passphrase-stdin` — orthogonal, untouched.

---

## 6. Per-key flood isolation (cap at promote)

`StorageQuota` (proto/server.rs:216) is the per-key **new-write** cap for one serve-session (reset on
restart; idempotent re-puts already exempt). The write token bucket bounds only *flow*. Keep it as the
per-key isolation, but **move the charge from per-`Put` to per-promote** (§3.4) on `promoted_bytes`, so
abandoned staging and idempotent re-puts are never charged. **Default unlimited** (secsec is
single-user self-hosted; the FS quota is the durable bound, retention bounds version growth); a finite
cap (`config: storage_cap_gib`) limits a **compromised device's** blast radius. A commit whose new
bytes exceed the remaining budget has its atomic promote rejected with a clear `RateLimit` — **never
silently** (it errors actionably: raise the cap; never corrupts), though a finite cap below a single
commit's footprint *does* hard-block that file until raised; default 0 never hits this. Keep the write
`TokenBucket` + per-IP/connection limits.

---

## 7. `secsec.config` — safe tuning only

A TOML file at `$XDG_CONFIG_HOME/secsec/secsec.config` (else `~/.config/secsec/secsec.config`),
written with defaults on the first `serve`/`sync`. The binary reads `[server]` keys for `serve` and
`[client]` keys for `sync`/etc. **A user MUST NOT be able to produce a breaking config:** every value
is range-checked on load and **clamped** to its safe range (logged warning); unknown keys are ignored.

**The partition rule:** a constant is configurable **only if** changing it cannot alter a `content_id`,
the wire contract, or an attacker bound — i.e. anything that must be identical across devices/peers for
correctness, or that bounds an adversary, stays **compiled-in**.

### 7.1 Configurable (safe; clamped to range)

| Key | Default | Range / clamp | Replaces (current hardcode) |
|---|---|---|---|
| `client.retention_keep_versions` | 8 | ≥ 0 (0 = keep-everything) | new |
| `client.upload_inflight` | 16 | 1 – 256 | new |
| `client.watch_debounce_ms` | 1000 | ≥ 100 | main.rs `Duration::from_millis(1000)` |
| `client.poll_interval_secs` | 15 | ≥ 5 | main.rs `interval(Duration::from_secs(15))` |
| `client.quic_idle_secs` | 30 | ≥ 5 | transport `IDLE_TIMEOUT_SECS` |
| `client.quic_keepalive_secs` | 10 | 1 .. `quic_idle_secs` | transport `KEEPALIVE_SECS` |
| `server.listen_port` | 8899 | 1 – 65535 | `DEFAULT_PORT` |
| `server.storage_cap_gib` | 0 (unlimited) | ≥ 0 | `PER_KEY_STORAGE_QUOTA` (relocated, §6) |
| `server.write_rate_mb_s` | 100 | ≥ 1 | `WRITE_RATE_BYTES_PER_SEC` — units **MB/s = megabytes/s** |
| `server.read_rate_mb_s` | 200 | ≥ 1 | `READ_RATE_BYTES_PER_SEC` — units **MB/s = megabytes/s** |
| `server.conn_rate_per_ip` | 10 | ≥ 1 | `CONN_RATE_PER_SEC` |
| `server.max_conns_per_key` | 3 | ≥ 1 | `MAX_CONCURRENT_CONNS_PER_KEY` |
| `server.staging_ttl_hours` | 24 | ≥ 1 | new (`TTL_STAGING`) |
| `server.reclaim_tick_minutes` | 60 | ≥ 1 | new (`RECLAIM_TICK`) |

### 7.2 Compiled-in (NOT configurable — would break content-ids / wire / security)

- **content-ids (must be identical across all devices):** FastCDC `min/avg/max` (16/64/256 KiB),
  the padding policy (`PowerOfTwo`), the gear construction. Different values ⇒ different chunk ids ⇒
  no cross-device dedup/convergence.
- **wire contract / decoder bounds:** `MAX_BLOB_SIZE` (16 MiB), `MAX_TREE_DEPTH` (64),
  `MAX_TREE_FANOUT` (65 536), `MAX_ROSTER_ENTRY_SIZE` (4 KiB), `MAX_LIST_ELEMENTS` (4096),
  `MAX_HAS_IDS` (1024), `PRUNE_BATCH`, `PUSH_ID_LEN` (16), `FORMAT_VERSION_V1`/`ALGO_V1`,
  `SECSEC_VERSION`. A mismatch makes one peer produce blobs/requests another rejects.
- **security parameters / attacker bounds:** invite-code length (96-bit), `SERVER_NONCE_TTL_SECS`
  (60) + size (32 B), device key algorithm (Ed25519), keyslot KEM (X-Wing) + the §16 algo floor, the
  fixed TLS 1.3 ciphersuites/KX. Lowering any weakens a guarantee.
- **anti-abuse caps (kept hardcoded — a too-low value would block enrollment/revocation):**
  `MAX_TOTAL_SIGCHAIN` (10 000), `MAX_SIGCHAIN_ENTRIES_PER_CONN_PER_HOUR` (60), the pairing-mailbox
  `PAIR_TTL`/slot caps, and the rate-limiter burst **`WRITE_BURST_BYTES` (1 GiB)** — the token-bucket
  capacity, which **MUST stay ≥ `MAX_BLOB_SIZE`** so a single `Put` always fits regardless of the
  configurable refill rate (this is why `write_rate_mb_s = 1` never stalls a single op).

### 7.3 Loading

`fn load_config() -> Config`: read the TOML if present (else write defaults), parse, **clamp** each
key to §7.1's range, log any clamp, return. `Config` carries only §7.1 values; everything in §7.2 is a
`const`. Retention is global (applies to all synced folders); a per-folder override can be added to the
folder `link` later if needed.

---

## 8. What's deleted, what survives

**Delete (reachability-GC + receipts):** client `gc.rs` `GC_GRACE_WINDOW_SECS`/`gc_gen_*`/
`put_epoch_*`/`ReceiptRecord`+receipt-log/`gc_collect`; `Remote::gc`+`GcOutcome`; `Receipt`+`verify`;
`SyncReport.receipts`/`SyncOutcome.receipts`; `QuicRemote::gc`, transport `request_gc`,
`MemRemote::gc`. Server `handle_gc`, receipt/quota machinery, host receipt key
(`load_or_generate_receipt_key`, `hostkey.receipt`). Proto **`receipt.rs` (whole file)**, `op::GC`,
`Request::Gc`/`T_GC`, `MAX_GC_KEEP_SET_IDS`, `MAX_GC_CALLS_PER_HOUR`. Store `ARRIVAL`,
`COUNTERS`/`put_epoch`, `arrival_epoch`, old `gc()`. Bin: receipt verify+log, auto-gc block, receipt
key. Vectors: the `[gc]` KAT block (`vectors.rs:84–89` + `secsec-kat-v1.txt`) in lockstep.

**Survives / reworked:** `reachable_objects` (push + prune use it; + the `strict_head` flag);
`local_sweep` (local orphan sweep, now backed by `delete_objects`); the `all_heads_hash` head-CAS →
`proto/prune.rs` for the `Prune` op (`ref_blob_hashes` moves there); `ErrorCode::TooManyIds`,
`MAX_HAS_IDS`, `WindowCounter`, `HOUR_SECS`; the §8.2 `/keyhist` + `/roster-keyhist` tables
(forward-secrecy — **NOT** GC scaffolding; do not confuse with `put_epoch`/`ARRIVAL`).

---

## 9. Wire / version

Bump `SECSEC_VERSION` 1→2 (`secsec-transport/src/auth.rs:10`). `Request::Put` + `push_id`,
`Request::CasHead` + `promote`, `Response::Stored` → bare ack, `Request::Gc` removed, `Request::Prune`
added; `args_put` binds `push_id`, `args_cas_head` binds `promote`. **Do NOT** touch
`FORMAT_VERSION_V1`/`ALGO_V1` — sealed object/commit/head bytes and `object_kat` are byte-identical.
Old store discarded; no migration.

---

## 10. Threat-model impact (§4 / §21)

- **P1 / blind server** — sealing, content-addressing, keyed-hash paths unchanged; `push_id`
  client-random, not plaintext-derived; promote flips a *client-assembled* set; `Prune`'s `dead` is
  computed client-side. The server never traverses opaque commit→tree→chunk edges (*less* cognition
  than today's GC).
- **P2/P3/P9** integrity & forgery, **P7/P8** anti-rollback (RosterAnchor + sealed frontier +
  head-version HWM, none read receipts/`put_epoch`/`ARRIVAL`), **P6/P11** forward secrecy
  (revoke⇒rotate + the **kept** §8.2 key-histories) — all untouched.
- **Metadata** — `has`-durable leaks new-vs-stored exactly as today's idempotent-`put` receipt
  (§9.7/§21 intra-file-temporal); `push_id` grouping ⊆ the put-burst timing already observed. No new
  residual.

**§21 edits:** delete three moot residuals — *GC put-epoch integrity*, *delete-log advisory*, *GC
keep-set scaling/100k*. Keep all others. Add: (a) a push that stages then crashes before `cas-head`
loses its staged objects after the idle-TTL — no committed data lost (head never advanced),
re-pushable from any replica; (b) history beyond `keep` versions per file is pruned — `restore`/deep
`log` are bounded to the last `keep`; the working set + last `keep` versions are recoverable from
replicas (§14). The §5.3 head-CAS is the resurrection guard.

---

## 11. Crate touch-point map

| Crate | Touch |
|---|---|
| `secsec-chunk` | + streaming cutter (**I2**); `next_cut`/`chunks` stay; + byte-identical-cut KAT |
| `secsec-snapshot` | `snapshot_dir` stream (drop 539); `restore_tree`/`restore_path` stream-write; `collect_tree`/`reachable_objects` `strict_head` skip-missing (**I5**); `restore`/`resolve_path` `PrunedBeyondRetention`; `changed_paths` tolerate missing; + mtime/size fast-path |
| `secsec-store` | + `STAGING`; `put(…,push_id,now)`; `cas_ref(…,promote)`→`CasOutcome` (**I1**); + `has_for_push`/`reclaim_staging`/`delete_objects`; **− `ARRIVAL`/`COUNTERS`/`put_epoch`/`arrival_epoch`/`gc()`**; `ref_blob_hashes`→proto |
| `secsec-proto` | wire: `Put.push_id`, `CasHead.promote`, `Stored`→ack, **− `Gc`/`T_GC`**, **+ `Prune`**; `args_put`/`args_cas_head` bind new fields; **− `receipt.rs`**, `op::GC`, `MAX_GC_*`; **+ `prune.rs`** (`all_heads_hash`/`dead_hash`/`args_prune`, `ref_blob_hashes`); + `Config` loader; relocate the per-key new-write cap (charge at promote) |
| `secsec-server` | `Put` stage+rate+ack; `CasHead` promote + §6 cap; **+ `Prune` (head-CAS)**; **+ `reclaim_staging`**; **− `handle_gc`/receipt/quota/gc-rate**; `sigchain_record`→`HOUR_SECS` |
| `secsec-transport` | `SECSEC_VERSION` 1→2; **− `request_gc`**, **+ `request_prune`**; `IDLE_TIMEOUT_SECS`/`KEEPALIVE_SECS` ← config |
| `secsec-engine` | `merge_heads` (332): pruned-base-tree → empty-ancestor keep-both |
| `secsec-client` | `Remote`: + `has`/`has_for_push`/`prune`, `put_blob(…,push_id)`→ack, `cas_head(…,promote)`, **− `gc`/`GcOutcome`/`Receipt`**; `push_objects(…,push_id)` filter+concurrent+I5; `gc.rs`→**− receipt/gc_collect**, **+ `prune_history`**, keep `local_sweep`; `fetch_closure`/`history` I5; `QuicRemote`/`MemRemote` mirror |
| `bin/secsec` | `run_serve`: + reclaim task, + config, − receipt key; `run_sync`: + `push_id` persistence, + `prune_history` (replaces auto-gc), − receipt+auto-gc, + config; `Reset` label |
| `xtask`/`vectors` | remove the `[gc]` KAT block in lockstep |

---

## 12. Test & assurance plan

- **I2 streaming-cut KAT** (CI gate before rollout): streamed `cut_points` == in-RAM across read
  widths {1,2,3,7,13,min±1,max±1,1 MiB} × sizes {0,1,min±1,avg±1,max±1,2·max,multi-MiB,low-entropy}.
- **I1 promote atomicity:** crash between stage and commit leaves `OBJECTS`+`REFS` unchanged; a
  winning promote moves exactly the `push_id` rows and swaps `REFS` in one step.
- **Promote-superset regression:** ≥2 cas-conflict retries (distinct spines) then a winning cas-head ⇒
  no durable-but-unreachable objects (passes only under per-attempt `push_id`).
- **Crash-resume + clone:** stage part, crash pre-cas-head, restart ⇒ reuse `push_id`, re-stage only
  missing via `has_for_push`, promote full closure; a fresh clone before resume sees the pre-push head
  with a fully-fetchable closure (no `MissingRemote`).
- **I3 durable-only `has`:** staged-uncommitted id ⇒ `has`==false/`get`==None until promote.
- **Idle-TTL driver:** `reclaim_staging` fires on a server with zero connections after the TTL; never
  deletes `OBJECTS`.
- **Retention count semantics:** an edited file's >Nth-old chunks are pruned while the current content
  and the last `keep` versions survive; `restore` past the window → `PrunedBeyondRetention`; `merge`
  with a pruned LCA tree → keep-both; `log` lists all commits, marks pruned rows.
- **Prune head-CAS:** A computes `dead` for a cut; B reverts content (re-deriving an id), `has`-skips,
  cas-heads C+1 ⇒ A's `Prune` is CasConflict'd and live data survives.
- **Rotation re-store / fast-path:** rotate, then re-snapshot an unchanged file ⇒ with the mtime/size
  fast-path the chunk ids are reused (no re-upload); without it, ids change (documents the cost).
- **Config safety:** out-of-range values clamp to the §7.1 range (no breaking config); a §7.2 const is
  not readable from the file.
- **§6 cap:** a single key's new durable bytes rejected past a finite cap at promote, isolating others.
- **Version break / KAT lockstep:** a v1 client fails the hello vs a v2 server; new args round-trip; a
  v1 sig BadAuths; `[gc]` vectors removed, build green, `object_kat` frozen.

---

## 13. Risk register (adds to `secsec-Implementation.md` §4)

| # | Hotspot | Failure mode | Mitigation |
|---|---|---|---|
| R9 | Atomic promote (I1) | durable head references a staging/absent object | promote+ref-swap one redb txn; resume/clone tests |
| R10 | `push_id` reuse | promote-superset strands spines | per-attempt `push_id`; superset test |
| R11 | Streaming chunker (I2) | divergent cut breaks dedup/merge-equality | byte-identical-cut KAT CI gate |
| R12 | Idle-TTL driver | no reclaim on an idle server | dedicated `interval` task, not the accept loop |
| R13 | Quota | unbounded per-key new-write flood | per-key new-write cap charged at promote (default unlimited; finite via config) |
| R14 | Retention prune | resurrection-via-dedup deletes live data | head-binding `all_heads_hash` CAS; compute after pull-to-head |
| R15 | Horizon walks (I5) | a content walk errors on a pruned ancestor / skips a missing *current* object | `strict_head`: strict head tree, skip-missing ancestors; merge→keep-both, restore→clean error |
| R16 | Config | a user sets a breaking value | clamp every key to §7.1; content-id/wire/security consts stay compiled-in (§7.2) |

---

## 14. Phased rollout

1. **Upload hardening, no wire change** — streaming chunk + restore (RAM) and `Remote::has` +
   has-filter + bounded-concurrent `push_objects` + the mtime/size fast-path. Highest-leverage; ship
   first (resume + no re-upload + no rotation re-store).
2. **Transactional staging + GC removal** — `STAGING`, promote-on-`cas-head` (I1), per-attempt
   `push_id`, idle-TTL + driver, the GC/receipt deletion. The v2 wire break.
3. **Retention** — `strict_head` skip-missing walks, `Prune` op + head-CAS, `prune_history` (keep=8)
   in the sync loop, the `log`/`restore` pruned-version behavior.
4. **Config** — `secsec.config` loader + the §7.1 keys (incl. the relocated cap).
