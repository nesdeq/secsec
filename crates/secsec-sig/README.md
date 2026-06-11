# secsec-sig

Device identity and SSHSIG signatures (`secsec-Design.md` §5, §9.6).

A device is an **Ed25519** SSH keypair. Its `device_id` is `BLAKE3` over the canonical SSH
public-key encoding, so the id is cryptographically bound to the key (§5). All signatures are OpenSSH
"sshsig" with a **distinct namespace** per purpose (§9.6); the namespace is carried in the signature
and checked on verify, so a signature for one purpose is invalid for any other — the
"server-sets-the-challenge" forgery is impossible.

**Ed25519-only**: this crate enables only `ssh-key`'s `ed25519` feature, so non-Ed25519 keys do
not parse, and `DevicePublic::verify` additionally rejects any non-Ed25519 key or signature algorithm
(the §9.6 downgrade guard).

## Public API

- `DeviceKey` — `generate()` / `from_openssh(pem)`; `sign(namespace, msg)`, `device_id()`,
  `public()`, `to_canonical()`. Key-derived secrets: `local_seal_key` (§8.5 frontier seal),
  `x25519_secret` / `x25519_public`, and `xwing_seed()` — the X-Wing decapsulation seed derived from
  the raw Ed25519 **seed** (not the clamped scalar, so it is quantum-hard to recover from the public
  key, §8.3).
- `DevicePublic` — `from_canonical`, `verify(namespace, msg, sig)`, `device_id()`.
- Namespace constants: `NS_AUTH`, `NS_WRITE`, `NS_READ`, `NS_COMMIT`, `NS_HEAD`, `NS_ROSTER` (§9.6).
- `DeviceId`, `SigError`.
