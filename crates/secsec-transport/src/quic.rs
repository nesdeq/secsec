//! QUIC endpoint configs (`secsec-Design.md` §11): [`client_config`] verifies via the SPKI pin (a
//! MITM key fails the handshake), [`server_config`] presents the self-signed host key. Both pin
//! TLS 1.3 and the §19 tuning. The app-layer auth handshake is [`crate::handshake`]; per-op RPC is
//! [`crate::rpc`].

use crate::{HostPin, PinnedServerVerifier};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig, TransportConfig};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::Duration;

/// QUIC idle timeout (§19): 30 s.
pub(crate) const IDLE_TIMEOUT_SECS: u64 = 30;
/// QUIC keepalive interval (§19): 10 s.
pub(crate) const KEEPALIVE_SECS: u64 = 10;

/// QUIC idle/keepalive tuning (§19 `secsec.config`); defaults to the §19 values. The keepalive must
/// stay strictly below the idle timeout so a live connection refreshes before it can idle out.
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    /// Max idle timeout, seconds.
    pub idle_secs: u64,
    /// Keepalive interval, seconds.
    pub keepalive_secs: u64,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            idle_secs: IDLE_TIMEOUT_SECS,
            keepalive_secs: KEEPALIVE_SECS,
        }
    }
}

/// Failure to build a QUIC endpoint configuration.
#[derive(Debug)]
pub struct ConfigError(String);

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "quic config: {}", self.0)
    }
}
impl std::error::Error for ConfigError {}

/// The shared transport tuning (idle / keepalive) for `t`.
fn transport_config(t: Tuning) -> TransportConfig {
    let mut tc = TransportConfig::default();
    tc.max_idle_timeout(Some(
        Duration::from_secs(t.idle_secs)
            .try_into()
            .expect("idle timeout fits"),
    ));
    tc.keep_alive_interval(Some(Duration::from_secs(t.keepalive_secs)));
    tc
}

/// A pinned TLS 1.3 rustls `ClientConfig` (no ALPN here; set by the caller if needed).
fn rustls_client_config(pin: HostPin) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(pin)))
        .with_no_client_auth()
}

/// A TLS 1.3 rustls `ServerConfig` presenting `cert_der` (a self-signed host key) with `key_der`
/// (its PKCS#8 private key).
fn rustls_server_config(
    cert_der: &[u8],
    key_der: &[u8],
) -> Result<rustls::ServerConfig, ConfigError> {
    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));
    rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ConfigError(e.to_string()))
}

/// Build a `quinn::ClientConfig` that only completes a handshake against the pinned host key (§11).
pub fn client_config(pin: HostPin) -> Result<ClientConfig, ConfigError> {
    client_config_tuned(pin, Tuning::default())
}

/// Like [`client_config`] but with explicit idle/keepalive tuning (§19 `secsec.config`).
pub fn client_config_tuned(pin: HostPin, tuning: Tuning) -> Result<ClientConfig, ConfigError> {
    let qcc = QuicClientConfig::try_from(rustls_client_config(pin))
        .map_err(|e| ConfigError(e.to_string()))?;
    let mut cfg = ClientConfig::new(Arc::new(qcc));
    cfg.transport_config(Arc::new(transport_config(tuning)));
    Ok(cfg)
}

/// Shared cell into which a TOFU handshake records the server's captured `host_id` (§11).
pub type CapturedHostPin = Arc<std::sync::Mutex<Option<[u8; 32]>>>;

/// TOFU `ClientConfig` for first contact (§11): accepts any host key, records its `host_id` into
/// the returned cell; the caller confirms out-of-band and pins it ([`client_config`] thereafter).
pub fn client_config_tofu() -> Result<(ClientConfig, CapturedHostPin), ConfigError> {
    let captured = Arc::new(std::sync::Mutex::new(None));
    let rcc = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::TofuVerifier::new(captured.clone())))
        .with_no_client_auth();
    let qcc = QuicClientConfig::try_from(rcc).map_err(|e| ConfigError(e.to_string()))?;
    let mut cfg = ClientConfig::new(Arc::new(qcc));
    cfg.transport_config(Arc::new(transport_config(Tuning::default())));
    Ok((cfg, captured))
}

/// Build a `quinn::ServerConfig` presenting the self-signed host key `cert_der` / `key_der`.
pub fn server_config(cert_der: &[u8], key_der: &[u8]) -> Result<ServerConfig, ConfigError> {
    server_config_tuned(cert_der, key_der, Tuning::default())
}

/// Like [`server_config`] but with explicit idle/keepalive tuning (§19 `secsec.config`).
pub fn server_config_tuned(
    cert_der: &[u8],
    key_der: &[u8],
    tuning: Tuning,
) -> Result<ServerConfig, ConfigError> {
    let qsc = QuicServerConfig::try_from(rustls_server_config(cert_der, key_der)?)
        .map_err(|e| ConfigError(e.to_string()))?;
    let mut cfg = ServerConfig::with_crypto(Arc::new(qsc));
    cfg.transport_config(Arc::new(transport_config(tuning)));
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use std::net::{Ipv4Addr, SocketAddr};

    fn self_signed_with_key() -> (Vec<u8>, Vec<u8>) {
        let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
        (ck.cert.der().to_vec(), ck.key_pair.serialize_der())
    }

    fn loopback() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    /// Spawn a server that accepts one connection and echoes one datagram-sized message on a
    /// bidirectional stream; return its address and a handle.
    async fn run_server(
        cert: Vec<u8>,
        key: Vec<u8>,
    ) -> (SocketAddr, tokio::task::JoinHandle<bool>) {
        let endpoint = Endpoint::server(server_config(&cert, &key).unwrap(), loopback()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let Some(incoming) = endpoint.accept().await else {
                return false;
            };
            let Ok(conn) = incoming.await else {
                return false;
            };
            // echo one bidi-stream round trip
            if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let mut buf = [0u8; 16];
                if let Ok(Some(n)) = recv.read(&mut buf).await {
                    let _ = send.write_all(&buf[..n]).await;
                    let _ = send.finish();
                }
            }
            conn.closed().await;
            true
        });
        (addr, handle)
    }

    async fn try_connect(server_addr: SocketAddr, pin: HostPin) -> Result<(), String> {
        let mut endpoint = Endpoint::client(loopback()).map_err(|e| e.to_string())?;
        endpoint.set_default_client_config(client_config(pin).map_err(|e| e.to_string())?);
        let conn = endpoint
            .connect(server_addr, "secsec.invalid")
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;

        // exercise one stream to confirm the connection is actually usable.
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        send.write_all(b"ping").await.map_err(|e| e.to_string())?;
        send.finish().map_err(|e| e.to_string())?;
        let mut buf = [0u8; 16];
        let n = recv
            .read(&mut buf)
            .await
            .map_err(|e| e.to_string())?
            .unwrap_or(0);
        conn.close(0u32.into(), b"done");
        if &buf[..n] == b"ping" {
            Ok(())
        } else {
            Err("echo mismatch".into())
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn quic_handshake_succeeds_with_matching_pin() {
        runtime().block_on(async {
            let (cert, key) = self_signed_with_key();
            let pin = HostPin::from_cert(&cert).unwrap();
            let (addr, server) = run_server(cert, key).await;
            try_connect(addr, pin)
                .await
                .expect("pinned handshake + echo");
            assert!(server.await.unwrap());
        });
    }

    /// The end-to-end MITM test at the QUIC layer: connecting to a server presenting a *different*
    /// host key than the pin must fail the handshake.
    #[test]
    fn quic_handshake_fails_against_mitm_key() {
        runtime().block_on(async {
            let (real_cert, _real_key) = self_signed_with_key();
            let (mitm_cert, mitm_key) = self_signed_with_key();
            let pin = HostPin::from_cert(&real_cert).unwrap(); // pinned to the real key
            let (addr, _server) = run_server(mitm_cert, mitm_key).await; // server uses the MITM key
            let result = tokio::time::timeout(Duration::from_secs(5), try_connect(addr, pin)).await;
            // either the connect future resolves to an error, or (defensively) times out — never Ok.
            assert!(
                matches!(result, Ok(Err(_))) || result.is_err(),
                "a handshake against a non-pinned key must not succeed"
            );
        });
    }
}
