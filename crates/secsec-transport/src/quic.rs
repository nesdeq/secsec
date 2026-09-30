//! QUIC endpoint configs (`secsec-Design.md` §11): pinned client, TOFU client, and the self-signed server, all TLS 1.3 with §19 tuning.

use crate::{HostPin, PinnedServerVerifier};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use rustls::crypto::ring::{cipher_suite, default_provider, kx_group};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::Duration;

/// QUIC idle timeout default (§19).
pub(crate) const IDLE_TIMEOUT_SECS: u64 = 30;
/// QUIC keepalive interval default (§19).
pub(crate) const KEEPALIVE_SECS: u64 = 10;

/// Idle/keepalive tuning (§19 `secsec.config`); callers keep the keepalive below the idle timeout.
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    /// Max idle timeout, seconds.
    pub idle_secs: u64,
    /// Client keepalive interval, seconds.
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

impl Tuning {
    /// The largest idle timeout QUIC can express, in whole seconds (a 62-bit millisecond count).
    pub const MAX_IDLE_SECS: u64 = VarInt::MAX.into_inner() / 1000;
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

/// §11: suites and key exchange are fixed; AES-128-GCM stays because RFC 9001 §5.2 fixes Initial packets to it.
fn pinned_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: vec![
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_AES_128_GCM_SHA256,
        ],
        kx_groups: vec![kx_group::X25519],
        ..default_provider()
    }
}

/// Transport tuning shared by both ends; only a client sends keepalives, so an idle peer times out on the server.
fn transport_config(t: Tuning, keepalive: bool) -> Result<TransportConfig, ConfigError> {
    let idle = IdleTimeout::try_from(Duration::from_secs(t.idle_secs))
        .map_err(|_| ConfigError(format!("idle timeout {}s is out of range", t.idle_secs)))?;
    let mut tc = TransportConfig::default();
    tc.max_idle_timeout(Some(idle));
    tc.keep_alive_interval(keepalive.then(|| Duration::from_secs(t.keepalive_secs)));
    // secsec uses only bidirectional streams: no unidirectional streams, no datagrams.
    tc.max_concurrent_uni_streams(VarInt::from_u32(0));
    tc.datagram_receive_buffer_size(None);
    Ok(tc)
}

/// A pinned TLS 1.3 client config; no ALPN, since the §11 hello carries and checks `secsec_version` (RFC 9001 §8.1).
fn rustls_client_config(pin: HostPin) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(pinned_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(pin)))
        .with_no_client_auth()
}

/// A TLS 1.3 server config presenting `cert_der` with its PKCS#8 `key_der`.
fn rustls_server_config(
    cert_der: &[u8],
    key_der: &[u8],
) -> Result<rustls::ServerConfig, ConfigError> {
    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));
    rustls::ServerConfig::builder_with_provider(Arc::new(pinned_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ConfigError(e.to_string()))
}

/// A client config that only completes a handshake against the pinned host key (§11).
pub fn client_config(pin: HostPin) -> Result<ClientConfig, ConfigError> {
    client_config_tuned(pin, Tuning::default())
}

/// [`client_config`] with explicit tuning.
pub fn client_config_tuned(pin: HostPin, tuning: Tuning) -> Result<ClientConfig, ConfigError> {
    let qcc = QuicClientConfig::try_from(rustls_client_config(pin))
        .map_err(|e| ConfigError(e.to_string()))?;
    let mut cfg = ClientConfig::new(Arc::new(qcc));
    cfg.transport_config(Arc::new(transport_config(tuning, true)?));
    Ok(cfg)
}

/// The cell a TOFU handshake fills with the verified server's `host_id` (§11).
pub type CapturedHostPin = Arc<std::sync::Mutex<Option<[u8; 32]>>>;

/// First-contact (TOFU) client config with explicit tuning: accepts any key, records its verified `host_id`.
pub fn client_config_tofu(tuning: Tuning) -> Result<(ClientConfig, CapturedHostPin), ConfigError> {
    let captured = Arc::new(std::sync::Mutex::new(None));
    let rcc = rustls::ClientConfig::builder_with_provider(Arc::new(pinned_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::TofuVerifier::new(captured.clone())))
        .with_no_client_auth();
    let qcc = QuicClientConfig::try_from(rcc).map_err(|e| ConfigError(e.to_string()))?;
    let mut cfg = ClientConfig::new(Arc::new(qcc));
    cfg.transport_config(Arc::new(transport_config(tuning, true)?));
    Ok((cfg, captured))
}

/// A server config presenting the self-signed host key.
pub fn server_config(cert_der: &[u8], key_der: &[u8]) -> Result<ServerConfig, ConfigError> {
    server_config_tuned(cert_der, key_der, Tuning::default())
}

/// [`server_config`] with explicit tuning (idle timeout only; the server never keeps a peer alive).
pub fn server_config_tuned(
    cert_der: &[u8],
    key_der: &[u8],
    tuning: Tuning,
) -> Result<ServerConfig, ConfigError> {
    let qsc = QuicServerConfig::try_from(rustls_server_config(cert_der, key_der)?)
        .map_err(|e| ConfigError(e.to_string()))?;
    let mut cfg = ServerConfig::with_crypto(Arc::new(qsc));
    cfg.transport_config(Arc::new(transport_config(tuning, false)?));
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

    /// A server that echoes one bidi-stream message.
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

    async fn try_connect(server_addr: SocketAddr, cfg: ClientConfig) -> Result<(), String> {
        let mut endpoint = Endpoint::client(loopback()).map_err(|e| e.to_string())?;
        endpoint.set_default_client_config(cfg);
        let conn = endpoint
            .connect(server_addr, "secsec.invalid")
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;
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
    fn quic_handshake_succeeds_with_matching_pin_and_tofu() {
        runtime().block_on(async {
            let (cert, key) = self_signed_with_key();
            let pin = HostPin::from_cert(&cert).unwrap();
            let (addr, server) = run_server(cert.clone(), key.clone()).await;
            try_connect(addr, client_config(pin.clone()).unwrap())
                .await
                .expect("pinned handshake + echo");
            assert!(server.await.unwrap());

            let (addr, server) = run_server(cert, key).await;
            let (cfg, cell) = client_config_tofu(Tuning::default()).unwrap();
            try_connect(addr, cfg).await.expect("tofu handshake + echo");
            assert!(server.await.unwrap());
            assert_eq!(*cell.lock().unwrap(), Some(pin.host_id()));
        });
    }

    /// QUIC-layer MITM: a server presenting another key never completes the handshake.
    #[test]
    fn quic_handshake_fails_against_mitm_key() {
        runtime().block_on(async {
            let (real_cert, _real_key) = self_signed_with_key();
            let (mitm_cert, mitm_key) = self_signed_with_key();
            let pin = HostPin::from_cert(&real_cert).unwrap();
            let (addr, _server) = run_server(mitm_cert, mitm_key).await;
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                try_connect(addr, client_config(pin).unwrap()),
            )
            .await;
            assert!(matches!(result, Ok(Err(_))) || result.is_err());
        });
    }

    /// An idle timeout QUIC cannot express is a config error, never a panic.
    #[test]
    fn out_of_range_idle_timeout_is_an_error() {
        let bad = Tuning {
            idle_secs: u64::MAX,
            keepalive_secs: 1,
        };
        assert!(transport_config(bad, true).is_err());
        let edge = Tuning {
            idle_secs: Tuning::MAX_IDLE_SECS,
            keepalive_secs: 1,
        };
        assert!(transport_config(edge, false).is_ok());
    }
}
