# secsec-transport

QUIC + TLS 1.3 transport (`secsec-Design.md` §11) — the **only** transport (QUIC/TLS-only). Centered
on the **pinned host-key verifier** (risk **R1**, "the top ship-broken risk").

The server self-signs a host key on first run (like `sshd`); there is **no CA**. The client pins the
server's SubjectPublicKeyInfo (SPKI) trust-on-first-use on the first `sync` (the fingerprint is
printed for out-of-band confirmation, then persisted in the per-folder link), and
`host_id = BLAKE3(SPKI)` is bound into the connection-auth signature (§9.6). The verifier follows the
**safe pattern**:

- `verify_server_cert` compares the leaf SPKI to the pin in constant time and asserts nothing else
  (no CA chain, no name check — identity rests on the pin);
- `verify_tls13_signature` **delegates** to the provider helper — it is never stubbed;
- TLS 1.2 is refused outright (pinned to TLS 1.3).

The mandatory negative tests (wrong pin fails; tampered/garbage handshake fails) live here and gate CI.

## Public API

- `HostPin` — `from_cert` (what TOFU records) / `from_host_id` (re-pin a stored fingerprint);
  `host_id()`.
- `quic` — `client_config` / `server_config` (+ `_tuned` variants taking `Tuning`), and
  `client_config_tofu`, the first-contact config that captures the server's `host_id` for pinning
  (`CapturedHostPin`). Every config pins TLS 1.3, the suite list, and X25519 KX.
- `handshake` — `client_handshake` / `server_handshake` → `ClientSession` / `ServerSession`.
- `auth` — `SessionTranscript` (the §11 BLAKE3-over-hellos transcript).
- `frame` — length-prefixed framing (`read_frame` / `write_frame`, `MAX_FRAME_LEN`).
- `rpc` — per-op `request` / `request_prune` (the §15 head-binding retention prune).
- `AuthError`, `HandshakeError`, `FrameError`, `RpcError`, `PinError`, `ConfigError`.

The pieces callers must not be able to bypass or misassemble are crate-internal: the
`PinnedServerVerifier` itself (reachable only by building a config through `quic`), `ConnectionAuth`,
`SECSEC_VERSION` / `NONCE_LEN`, and the §19 idle/keepalive defaults behind `Tuning::default()`.
