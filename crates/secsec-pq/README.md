# secsec-pq

The hybrid post-quantum keyslot — **X-Wing** (`secsec-Design.md` §8.3, §17). The **only** keyslot
algorithm: PQ is mandatory.

Wraps `master_key_g` to a device under the X-Wing KEM (ML-KEM-768 ⊕ X25519), so the harvestable
asymmetric keyslot wrap is PQ-secure (the symmetric data plane is already PQ-safe). Byte-faithful to
draft-connolly-cfrg-xwing-kem-10 / ePrint 2024/039:

```text
// key generation (draft-10 §6 expandDecapsulationKey): a single 32-byte seed `sk`
expanded = SHAKE256(sk, 96)
(d, z)   = expanded[0:32], expanded[32:64]   // ML-KEM-768 KeyGen_internal seed (FIPS 203 §7.1)
sk_X     = expanded[64:96]                    // X25519 static secret
// combiner (draft-10 §6) — the XWingLabel is placed LAST:
ss = SHA3-256( ss_MLKEM(32) ‖ ss_X25519(32) ‖ ct_X(32) ‖ pk_X(32) ‖ XWingLabel(6) )
keyslot_ct = ct_MLKEM(1088) ‖ ct_X(32)                                       // 1120 bytes
```

The X-Wing secret key is the 32-byte `sk` seed alone; the ML-KEM `(d,z)` seed and the X25519 secret
are *derived* from it (FIPS 203 §7.1 seed form, required to avoid MAL-BIND-K-CT / MAL-BIND-K-PK
failures — Schmieg, ePrint 2024/523). The X-Wing shared secret then keys the §9.4 CTX committing AEAD
to wrap the master key; authenticity rests on the §7 `mk_commit` check, not the wrap. Built on the
formally-verified [`libcrux_ml_kem`] + `x25519-dalek` (no third-party X-Wing crate).

## Public API

- `XWingSecret` — `from_seed` / `generate` (with the FIPS 203 §7.1 PCT), `public()`.
- `XWingPublic` — `from_bytes` / `to_bytes`.
- `wrap_pq(master_key, gen, device_id, pk)` → keyslot body; `unwrap_pq` (with the commit check) /
  `unwrap_pq_raw` (cold-start, the fold verifies `mk_commit`).
- Length constants: `XWING_SEED_LEN`, `XWING_CT_LEN`, `XWING_ESEED_LEN`, `ML_KEM_*`, `X_LEN`.
- `PqError`.

## Conformance (§17, normative)

`xwing_kat` asserts a byte-identical shared secret against the draft-10 Appendix C vector — keygen,
encapsulation, and the combiner end to end. §17 mandates this gate before any implementation is
accepted as conformant; it runs in normal CI (not `#[ignore]`d).
