I traced these end-to-end and they hold up:

- CTX/CMT-4 AEAD (§9.4) — T recomputed not stored, binds K/N/A/M; nonce=0 is safe because k_obj is unique per object. The three-phase decrypt is correct.
- Content-addressing ↔ key derivation has no circularity (id from plaintext → k_obj from id → re-verify id on fetch).
- KDF domain separation (§9.5) — distinct labels, fixed-width le32(g)‖u8(t), the mk_commit keyed_hash exception is correctly called out.
- Signature namespacing (§9.6) — server-chosen nonces confined to auth/write; cross-protocol reuse is genuinely closed.
- Enrollment (§7) — full fingerprint carried out-of-band by the human in step 1, commitment-before-reveal SAS over RFP+D_pubkey, mk_commit highest-seq check, in-band enrollment_nonce. The fake-universe attack is closed.
- X-Wing keyslot (`secsec-pq`) — draft-10 conformant: single 32-byte seed expanded via `SHAKE256(sk,96)` to the ML-KEM `(d,z)` seed + X25519 `sk_X`; **label-LAST** combiner `SHA3-256(ss_M‖ss_X‖ct_X‖pk_X‖XWingLabel)`; verified byte-identical to the draft-10 Appendix C vector (`xwing_kat`, not ignored). (An earlier draft of this file and §17 wrongly said label-first — the obsolete draft-02 order; fixed.)
- Keep-everything default + multi-remote makes the GC blast radius small and honest.

The residuals in §22 are honest and genuinely minimal.

The real remaining gaps

[HIGH] Concurrent mutual revocation has no tiebreak — a stolen, online device can win the race and lock out the legitimate one. All devices are flat, equal members; there is no privileged founder. When E does RevokeDevice(B)+Rotate, a compromised online B can concurrently do RevokeDevice(E)+Rotate. The /roster-head CAS serializes them — whoever lands first wins. If B wins, E re-folds onto the new tip, finds itself revoked, and its retry fails succession (§8.1's "retry until appended" can't help: E is no longer a member). The attacker keeps the repo; the user is evicted. This directly undercuts P7 and the "revoked device" adversary in §3. It only bites when the stolen device is unlocked, online, and racing (in which case it already had data access), but the document doesn't acknowledge it at all. Fix: designate the genesis/device-1 key (or possession of the recovery code) as privileged for RevokeDevice/Rotate, or require revocation to be authorized by the recovery code — so a device alone cannot evict the founder. At minimum, document it as a residual. This is the one thing I'd resolve before trusting revocation.

[RESOLVED — removed] HistoryReanchor broke sigchain folding: trimming key-history below drop_before_gen left a freshly-enrolled device unable to derive roster_key_g for the dropped generations, so it couldn't verify succession from genesis — unsound in that corner. Rather than add a signed membership-snapshot baseline, the op was **removed entirely** (2026-06-10): both key-histories are now never-trimmed (64 bytes/generation, negligible for a single-user repo that won't reach hundreds of rotations). The hazard is gone with the feature. It was never implemented in code.

[LOW] Spec-completeness items (not unsafe, but an implementer will hit them):
- The cold-boot bootstrap order isn't stated: a device reads the tip entry's plaintext FRAME.gen → fetches that keyslot → decrypts the tip → peels. It's sound but should be written down explicitly.
- How the client learns the current put_epoch to bind in the GC args_hash is unspecified (needs a status read).
- Where the root tree/commit's path_salt lives (every other salt is in the parent tree; the root has no parent).
- Local-state-file rollback by a disk-level attacker (the seal key is static, so an old sealed frontier still verifies) — largely subsumed by "client compromise = total," but worth a line.

Verdict

Crypto and data-plane: yes, build it. Revocation/key-management: not yet — resolve the mutual-revocation race (HIGH) and the reanchor/fold interaction (MEDIUM) first. Neither is a rewrite; both are localized to §8. Want me to draft the fixes for those two into the doc?