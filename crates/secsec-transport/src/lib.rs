//! `secsec-transport` — QUIC + TLS 1.3 transport (`finaldesign.md` §11). This first slice is the
//! **pinned host-key verifier** (risk **R1**, "the top ship-broken risk").
//!
//! The server self-signs a host key on first run (like `sshd`); there is **no CA**. The client pins
//! the server's public key (TOFU, or `--host-fp` at init) and authenticates every later connection
//! against that pin. The pin is the server certificate's **SubjectPublicKeyInfo** (SPKI) DER, and
//! `host_id = BLAKE3(SPKI)` (§11) is the value bound into the connection-auth signature (§9.6).
//!
//! The verifier is the part most likely to be silently broken (a `return Ok(())` or a stubbed
//! signature check disables authentication entirely), so it follows the **safe pattern** mandated by
//! the build plan:
//! - [`PinnedServerVerifier::verify_server_cert`] compares the leaf SPKI to the pin in constant time
//!   and asserts nothing else (no CA chain, no name check — identity rests on the pin);
//! - [`PinnedServerVerifier::verify_tls13_signature`] **delegates** to the provider's
//!   `verify_tls13_signature` helper — it is never stubbed;
//! - TLS 1.2 is refused outright (the connection is pinned to TLS 1.3, §11).
//!
//! The mandatory negative tests (wrong pin fails; a tampered/garbage handshake signature fails) live
//! in this crate and gate CI.

#![forbid(unsafe_code)]

pub mod auth;
pub mod frame;
pub mod handshake;
pub mod quic;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::{verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use subtle::ConstantTimeEq;
use x509_cert::der::{Decode, Encode};

/// The server's pinned identity: its certificate SubjectPublicKeyInfo (SPKI) DER, plus the
/// derived `host_id` (§11). Construct from a server cert with [`HostPin::from_cert`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPin {
    spki: Vec<u8>,
}

impl HostPin {
    /// Pin to a SubjectPublicKeyInfo DER directly (e.g. recovered from a stored pin).
    #[must_use]
    pub fn from_spki(spki: Vec<u8>) -> Self {
        Self { spki }
    }

    /// Extract and pin the SPKI from a server certificate (DER). This is what `init`/TOFU records.
    pub fn from_cert(cert_der: &[u8]) -> Result<Self, PinError> {
        Ok(Self {
            spki: spki_of(cert_der)?,
        })
    }

    /// The pinned SPKI DER bytes.
    #[must_use]
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// `host_id = BLAKE3(canonical(server pinned SPKI bytes))` (§11): bound into the connection-auth
    /// signature (§9.6). MUST be computed by the client from this locally-pinned material.
    #[must_use]
    pub fn host_id(&self) -> [u8; 32] {
        *blake3::hash(&self.spki).as_bytes()
    }
}

/// Failure to parse a certificate / extract its SPKI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinError;

impl core::fmt::Display for PinError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("could not parse server certificate / SubjectPublicKeyInfo")
    }
}
impl std::error::Error for PinError {}

/// Extract the SubjectPublicKeyInfo DER from an X.509 certificate DER.
fn spki_of(cert_der: &[u8]) -> Result<Vec<u8>, PinError> {
    let cert = x509_cert::Certificate::from_der(cert_der).map_err(|_| PinError)?;
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| PinError)
}

/// A `rustls` server-certificate verifier that accepts **exactly one** pinned self-signed host key
/// (§11). It performs no CA-chain or hostname validation — identity rests entirely on the SPKI pin —
/// and delegates handshake-signature verification to the crypto provider.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    pin: HostPin,
    supported: WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    /// Build a verifier for the given host pin.
    #[must_use]
    pub fn new(pin: HostPin) -> Self {
        Self {
            pin,
            supported: default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Pin check: the leaf certificate's SPKI must equal the pinned SPKI, compared in constant
        // time. No chain building, no name verification — the pin *is* the trust anchor (§11).
        let presented = spki_of(end_entity)
            .map_err(|_| Error::General("malformed server certificate".into()))?;
        if presented.len() != self.pin.spki.len() || !bool::from(presented.ct_eq(&self.pin.spki)) {
            return Err(Error::General(
                "server certificate SPKI does not match the pinned host key".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // The connection is pinned to TLS 1.3 (§11). Refuse 1.2 outright — a downgrade guard, and a
        // mandatory negative test.
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // DELEGATE to the provider's verified implementation — never stubbed (R1). This checks the
        // handshake signature against the pinned leaf's public key using the supported algorithms.
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use rustls::internal::msgs::codec::{Codec, Reader};
    use rustls::pki_types::ServerName;

    /// Construct a `DigitallySignedStruct` from wire bytes (its `new` is crate-private): an ED25519
    /// scheme (0x0807) followed by a `u16`-length-prefixed signature.
    fn dss_ed25519(sig: &[u8]) -> DigitallySignedStruct {
        let mut bytes = vec![0x08u8, 0x07];
        bytes.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        bytes.extend_from_slice(sig);
        DigitallySignedStruct::read(&mut Reader::init(&bytes)).unwrap()
    }

    /// A fresh self-signed server cert (DER) and its SPKI DER.
    fn self_signed() -> (Vec<u8>, Vec<u8>) {
        let cert = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
        let der = cert.cert.der().to_vec();
        let spki = spki_of(&der).unwrap();
        (der, spki)
    }

    fn verify_cert(v: &PinnedServerVerifier, leaf_der: &[u8]) -> Result<ServerCertVerified, Error> {
        v.verify_server_cert(
            &CertificateDer::from(leaf_der.to_vec()),
            &[],
            &ServerName::try_from("secsec.invalid").unwrap(),
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000)),
        )
    }

    #[test]
    fn host_id_is_blake3_of_spki_and_stable() {
        let (_der, spki) = self_signed();
        let pin = HostPin::from_spki(spki.clone());
        assert_eq!(pin.host_id(), *blake3::hash(&spki).as_bytes());
        // host_id is derived only from the pinned SPKI, not the cert envelope.
        assert_eq!(HostPin::from_spki(spki).host_id(), pin.host_id());
    }

    #[test]
    fn from_cert_extracts_the_same_spki() {
        let (der, spki) = self_signed();
        assert_eq!(HostPin::from_cert(&der).unwrap().spki(), &spki[..]);
    }

    #[test]
    fn matching_pin_accepts_the_server_cert() {
        let (der, _spki) = self_signed();
        let pin = HostPin::from_cert(&der).unwrap();
        let v = PinnedServerVerifier::new(pin);
        assert!(verify_cert(&v, &der).is_ok());
    }

    /// R1 mandatory negative test: a different (wrong) server key must NOT be accepted against the
    /// pin — this is the whole point of pinning.
    #[test]
    fn wrong_pinned_key_is_rejected() {
        let (der_a, _) = self_signed();
        let (der_b, _) = self_signed(); // a different, independently-generated key
        let v = PinnedServerVerifier::new(HostPin::from_cert(&der_a).unwrap());
        assert!(
            verify_cert(&v, &der_b).is_err(),
            "a server presenting a different key than the pin must be rejected"
        );
        // ...and the genuine cert still passes under the same verifier.
        assert!(verify_cert(&v, &der_a).is_ok());
    }

    #[test]
    fn malformed_certificate_is_rejected() {
        let (der, _) = self_signed();
        let v = PinnedServerVerifier::new(HostPin::from_cert(&der).unwrap());
        assert!(verify_cert(&v, b"not a certificate").is_err());
    }

    /// R1 mandatory negative test: a tampered/garbage handshake signature MUST fail — i.e. the
    /// signature path is really delegated to the provider, not stubbed to `Ok`.
    #[test]
    fn garbage_handshake_signature_is_rejected() {
        let (der, _) = self_signed();
        let v = PinnedServerVerifier::new(HostPin::from_cert(&der).unwrap());
        let cert = CertificateDer::from(der);
        let dss = dss_ed25519(&[0u8; 64]);
        assert!(
            v.verify_tls13_signature(b"transcript bytes", &cert, &dss)
                .is_err(),
            "a bogus signature must be rejected — verify_tls13_signature must not be stubbed"
        );
    }

    #[test]
    fn tls12_is_refused() {
        let (der, _) = self_signed();
        let v = PinnedServerVerifier::new(HostPin::from_cert(&der).unwrap());
        let cert = CertificateDer::from(der);
        let dss = dss_ed25519(&[0u8; 64]);
        assert!(
            v.verify_tls12_signature(b"x", &cert, &dss).is_err(),
            "TLS 1.2 must be refused (pinned to 1.3, §11)"
        );
    }

    #[test]
    fn advertises_supported_schemes() {
        let (der, _) = self_signed();
        let v = PinnedServerVerifier::new(HostPin::from_cert(&der).unwrap());
        assert!(!v.supported_verify_schemes().is_empty());
    }

    // ---- End-to-end TLS 1.3 handshake (the definitive R1 / MITM test) ----

    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
    use std::sync::Arc;

    /// A self-signed server cert (DER) + its PKCS#8 private key (DER).
    fn self_signed_with_key() -> (Vec<u8>, Vec<u8>) {
        let ck = generate_simple_self_signed(vec!["secsec.invalid".to_string()]).unwrap();
        (ck.cert.der().to_vec(), ck.key_pair.serialize_der())
    }

    fn server_config(cert_der: &[u8], key_der: &[u8]) -> Arc<ServerConfig> {
        let certs = vec![CertificateDer::from(cert_der.to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));
        let cfg = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        Arc::new(cfg)
    }

    fn client_config(verifier: PinnedServerVerifier) -> Arc<ClientConfig> {
        let cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Arc::new(cfg)
    }

    /// Drive a full in-memory handshake; returns the client-side result (the verifier runs inside
    /// `client.process_new_packets()`, so a pin mismatch surfaces as `Err` there).
    fn do_handshake(
        client_cfg: Arc<ClientConfig>,
        server_cfg: Arc<ServerConfig>,
    ) -> Result<(), rustls::Error> {
        let name = ServerName::try_from("secsec.invalid").unwrap();
        let mut client = ClientConnection::new(client_cfg, name).unwrap();
        let mut server = ServerConnection::new(server_cfg).unwrap();

        for _ in 0..16 {
            let mut c2s = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut c2s).unwrap();
            }
            let mut cur = std::io::Cursor::new(c2s);
            while (cur.position() as usize) < cur.get_ref().len() {
                server.read_tls(&mut cur).unwrap();
            }
            server.process_new_packets().map_err(map_err)?;

            let mut s2c = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut s2c).unwrap();
            }
            let mut cur = std::io::Cursor::new(s2c);
            while (cur.position() as usize) < cur.get_ref().len() {
                client.read_tls(&mut cur).unwrap();
            }
            client.process_new_packets().map_err(map_err)?; // verifier runs here

            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Ok(())
    }

    fn map_err(e: rustls::Error) -> rustls::Error {
        e
    }

    #[test]
    fn e2e_handshake_succeeds_with_matching_pin() {
        let (cert, key) = self_signed_with_key();
        let v = PinnedServerVerifier::new(HostPin::from_cert(&cert).unwrap());
        assert!(
            do_handshake(client_config(v), server_config(&cert, &key)).is_ok(),
            "a TLS 1.3 handshake to the pinned host key must complete"
        );
    }

    /// The definitive R1 / MITM test: a man-in-the-middle presenting a *different* host key (even a
    /// valid self-signed one) must make the real handshake fail at the pin check.
    #[test]
    fn e2e_handshake_fails_against_a_mitm_key() {
        let (real_cert, _real_key) = self_signed_with_key();
        let (mitm_cert, mitm_key) = self_signed_with_key(); // attacker's own key
        let v = PinnedServerVerifier::new(HostPin::from_cert(&real_cert).unwrap()); // pinned to the real key
        assert!(
            do_handshake(client_config(v), server_config(&mitm_cert, &mitm_key)).is_err(),
            "a handshake to a non-pinned (MITM) key must fail"
        );
    }
}
