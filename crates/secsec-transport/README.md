# secsec-transport

QUIC + TLS 1.3 transport (`secsec-Design.md` §11), the **only** transport. Centered on the **pinned
host-key verifier** (risk **R1** in `secsec-Implementation.md`, "the top ship-broken risk").

The server self-signs a host key (like `sshd`); there is **no CA**. The client pins the server's
SubjectPublicKeyInfo as `host_id = BLAKE3(SPKI)`: given up front (`secsec sync --pin`), or captured
trust-on-first-use on the first connection and then persisted in the folder's link. `host_id` is bound
into the session transcript and the connection-auth signature (§9.6). The verifiers follow the safe
pattern:

- `verify_server_cert` compares the leaf SPKI hash to the pin in constant time and asserts nothing
  else (no CA chain, no name check: identity rests on the pin);
- `verify_tls13_signature` **delegates** to the provider helper and is never stubbed; the TOFU
  verifier records the `host_id` only after that signature verifies;
- TLS 1.2 is refused outright.

Every config pins TLS 1.3, the suites ChaCha20-Poly1305, AES-256-GCM, and AES-128-GCM (which QUIC
Initial packets require), and X25519 key exchange. The mandatory negative tests (a wrong pin fails, a
garbage handshake signature fails, a MITM key fails a real TLS and QUIC handshake) live here.

## Public API

- `HostPin`: `from_cert` (the server's own, or a test's), `from_host_id` (a stored or `--pin` pin),
  `host_id()`; equality is constant-time.
- `quic`: `client_config` / `server_config` and their `_tuned` variants taking `Tuning` (idle timeout
  and client keepalive; `Tuning::MAX_IDLE_SECS`), and `client_config_tofu`, the first-contact config
  that fills a `CapturedHostPin`.
- `handshake`: `client_handshake` / `server_handshake` → `ClientSession` / `ServerSession`: fixed-size
  hellos, a named `VersionMismatch` for another `secsec_version`, the `host_id` check, the TLS exporter
  channel binding, and the signed client auth. Keyslot ownership is checked per op by the server, not
  here.
- `auth`: `SessionTranscript` (the §11 BLAKE3 over the two length-prefixed hellos).
- `frame`: `read_frame(recv, max)` / `write_frame`, `le32(len) ‖ payload`, refusing a length over
  `max` and allocating only as bytes arrive.
- `rpc`: `request`, one authorized request per stream: open, read the stream's challenge, sign
  (write or read auth), send, read the response.
- `AuthError`, `HandshakeError`, `FrameError`, `RpcError`, `PinError`, `ConfigError`.

The pieces callers must not bypass or misassemble are crate-internal: `PinnedServerVerifier` and
`TofuVerifier` (reachable only through a `quic` config), `ConnectionAuth`, `SECSEC_VERSION`,
`NONCE_LEN`, and the §19 idle and keepalive defaults behind `Tuning::default()`.
