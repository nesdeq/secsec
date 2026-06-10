I traced these end-to-end and they hold up:

- CTX/CMT-4 AEAD (§9.4) — T recomputed not stored, binds K/N/A/M; nonce=0 is safe because k_obj is unique per object. The three-phase decrypt is correct.
- Content-addressing ↔ key derivation has no circularity (id from plaintext → k_obj from id → re-verify id on fetch).
- KDF domain separation (§9.5) — distinct labels, fixed-width le32(g)‖u8(t), the mk_commit keyed_hash exception is correctly called out.
- Signature namespacing (§9.6) — server-chosen nonces confined to auth/write; cross-protocol reuse is genuinely closed.
- Enrollment (§7) — full fingerprint carried out-of-band by the human in step 1, commitment-before-reveal SAS over RFP+D_pubkey, mk_commit highest-seq check, in-band enrollment_nonce. The fake-universe attack is closed.
- X-Wing keyslot (`secsec-pq`) — draft-10 conformant: single 32-byte seed expanded via `SHAKE256(sk,96)` to the ML-KEM `(d,z)` seed + X25519 `sk_X`; **label-LAST** combiner `SHA3-256(ss_M‖ss_X‖ct_X‖pk_X‖XWingLabel)`; verified byte-identical to the draft-10 Appendix C vector (`xwing_kat`, not ignored). (An earlier draft of this file and §17 wrongly said label-first — the obsolete draft-02 order; fixed.)
- Keep-everything default + multi-remote makes the GC blast radius small and honest.

The residuals in §22 are honest and genuinely minimal.

The flagged gaps — with resolution (closed 2026-06-10)

[HIGH → DOCUMENTED as a §22 residual] Concurrent mutual revocation has no tiebreak — a stolen, online device can win the CAS race and lock out the legitimate one. All devices are flat, equal members; there is no privileged founder. When E does RevokeDevice(B)+Rotate, a compromised online B can concurrently do RevokeDevice(E)+Rotate; the /roster-head CAS serializes them and whoever lands first wins. It only bites when the stolen device is unlocked, online, and racing (in which case it already had data access). **Resolution:** the flat model is retained by design (there is no privileged founder — "the SSH key is the only credential"); the race is now explicitly acknowledged as the **concurrent mutual-revocation residual** in §22 and called out on the P7 row (§3 "revoked device" adversary). The privileged-founder / recovery-code-authorized-revocation alternative was considered and deliberately not adopted (it would break the flat single-user model). Documented, not silently undercutting P7.

[RESOLVED — removed] HistoryReanchor broke sigchain folding: trimming key-history below drop_before_gen left a freshly-enrolled device unable to derive roster_key_g for the dropped generations, so it couldn't verify succession from genesis — unsound in that corner. Rather than add a signed membership-snapshot baseline, the op was **removed entirely** (2026-06-10): both key-histories are now never-trimmed (64 bytes/generation, negligible for a single-user repo that won't reach hundreds of rotations). The hazard is gone with the feature. It was never implemented in code.

[LOW → RESOLVED] Spec-completeness items:
- Cold-boot bootstrap order — now stated and implemented: a device reads the tip entry's plaintext `FRAME.gen` → fetches that keyslot → decrypts the tip → peels (`repo::open_repo`, §8.1 step 1).
- The client learns the current `put_epoch` from its persisted §15 arrival-receipt log (`gc::put_epoch_from_log`), bound into the GC compare-and-swap.
- The root tree/commit `path_salt` is the commit's `root_salt` field (commits seal under `ZERO_SALT`); every non-root salt lives in its parent tree.
- Local-state-file rollback by a disk-level attacker is documented as subsumed by "client compromise = total" (§22).

Verdict

Crypto and data-plane: built and tested. Revocation/key-management: the mutual-revocation race is documented as a §22 residual (the flat model is intentional); the reanchor/fold hazard was removed with the feature. All flagged items are resolved or consciously documented — nothing open.