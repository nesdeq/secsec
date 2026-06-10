# secsec-transport

QUIC + TLS 1.3 transport (`secsec-Design.md` §11) — the **only** transport (QUIC/TLS-only). Centered
on the **pinned host-key verifier** (risk **R1**, "the top ship-broken risk").

The server self-signs a host key on first run (like `sshd`); there is **no CA**. The client pins the
server's SubjectPublicKeyInfo (SPKI) — TOFU, or `--host-fp` at init — and `host_id = BLAKE3(SPKI)` is
bound into the connection-auth signature (§9.6). The verifier follows the **safe pattern**:

- `verify_server_cert` compares the leaf SPKI to the pin in constant time and asserts nothing else
  (no CA chain, no name check — identity rests on the pin);
- `verify_tls13_signature` **delegates** to the provider helper — it is never stubbed;
- TLS 1.2 is refused outright (pinned to TLS 1.3).

The mandatory negative tests (wrong pin fails; tampered/garbage handshake fails) live here and gate CI.

## Public API

- `HostPin` — `from_cert` / `from_spki` / `from_host_id` (`--host-fp`); `host_id()`, `spki()`.
- `PinnedServerVerifier` — the custom `rustls` `ServerCertVerifier`.
- `client_config` / `server_config` — `quinn` configs wired to the pin.
- `handshake` — `client_handshake` / `server_handshake` → `ClientSession` / `ServerSession`.
- `auth` — `SessionTranscript` (the §11 BLAKE3-over-hellos channel binding), `ConnectionAuth`
  (`secsec-auth-v1` sign/verify), `SECSEC_VERSION`, `NONCE_LEN`.
- `frame` — length-prefixed framing (`read_frame` / `write_frame`, `MAX_FRAME_LEN`).
- `rpc` — per-op `request` / `request_gc`.
- `IDLE_TIMEOUT_SECS`, `KEEPALIVE_SECS` (§19); `AuthError`, `HandshakeError`, `FrameError`,
  `RpcError`, `PinError`, `ConfigError`.
