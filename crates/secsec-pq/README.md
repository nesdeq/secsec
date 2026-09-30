# secsec-pq

The hybrid post-quantum keyslot: **X-Wing** (`secsec-Design.md` §8.3, §17), the only keyslot
algorithm.

Wraps `master_key_g` to a device under the X-Wing KEM (ML-KEM-768 ⊕ X25519), so the harvestable
asymmetric keyslot wrap is post-quantum secure (the symmetric data plane already is). Byte-faithful to
draft-connolly-cfrg-xwing-kem-10 / ePrint 2024/039:

```text
// key generation (draft-10 §6 expandDecapsulationKey): a single 32-byte seed `sk`
expanded = SHAKE256(sk, 96)
(d, z)   = expanded[0:32], expanded[32:64]   // ML-KEM-768 KeyGen_internal seed (FIPS 203 §7.1)
sk_X     = expanded[64:96]                    // X25519 static secret
// combiner (draft-10 §6), the XWingLabel LAST:
ss = SHA3-256( ss_MLKEM(32) ‖ ss_X25519(32) ‖ ct_X(32) ‖ pk_X(32) ‖ XWingLabel(6) )
keyslot_ct = ct_MLKEM(1088) ‖ ct_X(32)                                       // 1120 bytes
```

The X-Wing secret is the 32-byte seed alone; the ML-KEM `(d, z)` seed and the X25519 secret are
*derived* from it (the FIPS 203 seed form, which avoids the MAL-BIND-K-CT and MAL-BIND-K-PK failures
of the expanded form, Schmieg, ePrint 2024/523). Every derivation runs the FIPS 203 §7.1 pairwise
consistency check, and every published public key passes FIPS 203 §7.2 validation before anything is
wrapped to it. The shared secret keys the §9.4 CTX committing AEAD over the master key with AD
`"secsec-keyslot-v1" ‖ device_id ‖ le32(gen)`; authenticity rests on the §7 `mk_commit` check, not the
wrap. Built on the formally verified `libcrux-ml-kem` and `x25519-dalek` (no third-party X-Wing
crate).

## Public API

- `XWingSecret`: `from_seed(seed)` and `generate()`, each returning `(secret, public)` after the
  consistency check; the secret is zeroized on drop.
- `XWingPublic`: `to_bytes()` (`mlkem_pk(1184) ‖ x25519_pk(32)`, the form published in the roster)
  and `from_bytes()` (length and §7.2 validation).
- `wrap_pq(master_key, gen, device_id, pk)` returns the keyslot body `xwing_ct(1120) ‖ ctx_tag(32) ‖
  ct(32)`; `unwrap_pq_raw(body, gen, device_id, sk)` recovers the raw key (checked by the cold-start
  fold's `mk_commit`, not here).
- `XWING_SEED_LEN`, `KEYSLOT_BODY_LEN`, `PqError` (`Malformed` / `Aead` / `Rng` / `Keygen`).

## Conformance (§17, normative)

`xwing_kat` asserts a byte-identical shared secret against the draft-10 Appendix C vector (keygen,
encapsulation, decapsulation, and the combiner end to end). §17 mandates this gate before an
implementation is accepted as conformant; it runs in every `cargo test`.
