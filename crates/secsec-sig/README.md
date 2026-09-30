# secsec-sig

Device identity and SSHSIG signatures (`secsec-Design.md` §5, §9.6).

A device is an **Ed25519** SSH keypair. Its `device_id` is `BLAKE3` over the canonical SSH
public-key encoding, so the id is cryptographically bound to the key (§5). All signatures are OpenSSH
"sshsig" (SHA-512 message hash, as `ssh-keygen -Y`) with a **distinct namespace** per purpose (§9.6);
the namespace is carried in the signature and checked on verify, so a signature for one purpose is
invalid for any other and the "server sets the challenge" forgery is impossible.

**Ed25519-only**: `ssh-key` is built with only the `std`, `ed25519`, and `encryption` features;
loading a private key of any other algorithm fails, and `DevicePublic` rejects any non-Ed25519 key,
and `verify` any non-Ed25519 signature (the §9.6 downgrade guard).

## Public API

- `DeviceKey`: `generate()`, `from_openssh(pem)` (an encrypted key is `SigError::Encrypted`),
  `from_openssh_passphrase(pem, pass)` (decrypts in memory); `sign(namespace, msg)`, `device_id()`,
  `public()`. Private-seed secrets, never stored: `local_seal_key()` (the §8.5 v2 frontier seal key),
  `local_seal_key_v1()` (the legacy scalar-derived key, only to migrate an older frontier), and
  `xwing_seed()` (the X-Wing decapsulation seed, derived from the raw Ed25519 **seed**, never the
  clamped scalar, so it is quantum-hard to recover from the public key, §8.3).
- `DevicePublic`: `from_openssh` (one `authorized_keys`-style line), `from_canonical` /
  `to_canonical`, `verify(namespace, msg, sig)`, `device_id()`, `ssh_fingerprint()` (the `SHA256:…`
  form `ssh-keygen -lf` prints).
- Namespace constants: `NS_AUTH`, `NS_WRITE`, `NS_READ`, `NS_COMMIT`, `NS_HEAD`, `NS_ROSTER` (§9.6).
- `MAX_SIG_LEN` (the decoder bound on a stored SSHSIG), `DeviceId`, `SigError`.
