//! QUIC + TLS 1.3 to a pinned self-signed host key, no CA (`secsec-Design.md` §11; R1): SPKI pin, delegated signature checks, TLS 1.2 refused.

#![forbid(unsafe_code)]

pub mod auth;
pub mod frame;
pub mod handshake;
pub mod quic;
pub mod rpc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::{verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use subtle::ConstantTimeEq;
use x509_cert::der::{Decode, Encode};

/// The server's pinned identity `host_id = BLAKE3(SPKI)` (§11), from its certificate or the fingerprint alone.
#[derive(Clone, Debug)]
pub struct HostPin {
    host_id: [u8; 32],
}

impl PartialEq for HostPin {
    /// Two pins are equal iff they pin the same `host_id` (constant-time).
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.host_id.ct_eq(&other.host_id))
    }
}
impl Eq for HostPin {}

impl HostPin {
    /// Pin the SPKI of a server certificate (DER).
    pub fn from_cert(cert_der: &[u8]) -> Result<Self, PinError> {
        Ok(Self::from_host_id(
            *blake3::hash(&spki_of(cert_der)?).as_bytes(),
        ))
    }

    /// Pin a `host_id` fingerprint; the verifier hashes the presented SPKI and compares.
    #[must_use]
    pub fn from_host_id(host_id: [u8; 32]) -> Self {
        Self { host_id }
    }

    /// `host_id = BLAKE3(SPKI)`, computed from locally pinned material, never taken from the server (§11).
    #[must_use]
    pub fn host_id(&self) -> [u8; 32] {
        self.host_id
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

/// A verifier accepting exactly one pinned host key: no chain or name checks, handshake signatures delegated.
#[derive(Debug)]
pub(crate) struct PinnedServerVerifier {
    pin: HostPin,
    supported: WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    /// A verifier for `pin`.
    #[must_use]
    pub(crate) fn new(pin: HostPin) -> Self {
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
        // The pin is the trust anchor: constant-time BLAKE3(leaf SPKI) == host_id.
        let presented = spki_of(end_entity)
            .map_err(|_| Error::General("malformed server certificate".into()))?;
        let presented_id = *blake3::hash(&presented).as_bytes();
        if !bool::from(presented_id.ct_eq(&self.pin.host_id())) {
            return Err(Error::General(
                "server certificate host_id does not match the pinned host key".into(),
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
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// First-contact verifier (§11 TOFU): records the host_id only once the handshake signature verifies.
#[derive(Debug)]
pub(crate) struct TofuVerifier {
    captured: std::sync::Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    supported: WebPkiSupportedAlgorithms,
}

impl TofuVerifier {
    /// A TOFU verifier writing the verified server's `host_id` into `captured`.
    #[must_use]
    pub(crate) fn new(captured: std::sync::Arc<std::sync::Mutex<Option<[u8; 32]>>>) -> Self {
        Self {
            captured,
            supported: default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        spki_of(end_entity).map_err(|_| Error::General("malformed server certificate".into()))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
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
        let valid = verify_tls13_signature(message, cert, dss, &self.supported)?;
        let spki =
            spki_of(cert).map_err(|_| Error::General("malformed server certificate".into()))?;
        *self.captured.lock().expect("tofu cell") = Some(*blake3::hash(&spki).as_bytes());
        Ok(valid)
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

    /// A `DigitallySignedStruct` from wire bytes: ED25519 scheme (0x0807) + u16-prefixed signature.
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
    fn host_id_is_blake3_of_spki_and_pins_compare_by_host_id() {
        let (der, spki) = self_signed();
        let pin = HostPin::from_cert(&der).unwrap();
        assert_eq!(pin.host_id(), *blake3::hash(&spki).as_bytes());
        assert_eq!(pin, HostPin::from_host_id(pin.host_id()));
        assert_ne!(pin, HostPin::from_host_id([0; 32]));
    }

    #[test]
    fn fingerprint_pin_accepts_matching_and_rejects_wrong() {
        let (der, spki) = self_signed();
        let fp_pin = HostPin::from_host_id(*blake3::hash(&spki).as_bytes());
        let v = PinnedServerVerifier::new(fp_pin);
        assert!(verify_cert(&v, &der).is_ok());
        let (other_der, _) = self_signed();
        assert!(verify_cert(&v, &other_der).is_err());
    }

    /// R1 mandatory negative test: another key is never accepted against the pin.
    #[test]
    fn wrong_pinned_key_is_rejected() {
        let (der_a, _) = self_signed();
        let (der_b, _) = self_signed();
        let v = PinnedServerVerifier::new(HostPin::from_cert(&der_a).unwrap());
        assert!(verify_cert(&v, &der_b).is_err());
        assert!(verify_cert(&v, &der_a).is_ok());
        assert!(verify_cert(&v, b"not a certificate").is_err());
    }

    /// R1 mandatory negative test: a garbage handshake signature fails (delegated, never stubbed).
    #[test]
    fn garbage_handshake_signature_is_rejected_and_tls12_refused() {
        let (der, _) = self_signed();
        let v = PinnedServerVerifier::new(HostPin::from_cert(&der).unwrap());
        let cert = CertificateDer::from(der);
        let dss = dss_ed25519(&[0u8; 64]);
        assert!(v
            .verify_tls13_signature(b"transcript bytes", &cert, &dss)
            .is_err());
        assert!(v.verify_tls12_signature(b"x", &cert, &dss).is_err());
        assert!(!v.supported_verify_schemes().is_empty());
    }

    /// TOFU records nothing until a handshake signature has verified.
    #[test]
    fn tofu_captures_only_after_signature_verification() {
        let (der, _) = self_signed();
        let cell = std::sync::Arc::new(std::sync::Mutex::new(None));
        let v = TofuVerifier::new(cell.clone());
        let cert = CertificateDer::from(der);
        v.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("secsec.invalid").unwrap(),
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000)),
        )
        .unwrap();
        assert!(cell.lock().unwrap().is_none());
        assert!(v
            .verify_tls13_signature(b"transcript", &cert, &dss_ed25519(&[0u8; 64]))
            .is_err());
        assert!(
            cell.lock().unwrap().is_none(),
            "a bad signature captures nothing"
        );
    }

    // ---- End-to-end TLS 1.3 handshake (R1 / MITM) ----

    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
    use std::sync::Arc;

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

    fn client_config(verifier: impl ServerCertVerifier + 'static) -> Arc<ClientConfig> {
        let cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Arc::new(cfg)
    }

    /// Drive an in-memory handshake; the verifier runs in `client.process_new_packets()`.
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
            server.process_new_packets()?;
            let mut s2c = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut s2c).unwrap();
            }
            let mut cur = std::io::Cursor::new(s2c);
            while (cur.position() as usize) < cur.get_ref().len() {
                client.read_tls(&mut cur).unwrap();
            }
            client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Ok(())
    }

    #[test]
    fn e2e_handshake_succeeds_with_matching_pin_and_tofu_captures_it() {
        let (cert, key) = self_signed_with_key();
        let v = PinnedServerVerifier::new(HostPin::from_cert(&cert).unwrap());
        assert!(do_handshake(client_config(v), server_config(&cert, &key)).is_ok());
        let cell = std::sync::Arc::new(std::sync::Mutex::new(None));
        assert!(do_handshake(
            client_config(TofuVerifier::new(cell.clone())),
            server_config(&cert, &key)
        )
        .is_ok());
        assert_eq!(
            *cell.lock().unwrap(),
            Some(HostPin::from_cert(&cert).unwrap().host_id())
        );
    }

    /// R1 / MITM: a server presenting another key fails the real handshake at the pin.
    #[test]
    fn e2e_handshake_fails_against_a_mitm_key() {
        let (real_cert, _real_key) = self_signed_with_key();
        let (mitm_cert, mitm_key) = self_signed_with_key();
        let v = PinnedServerVerifier::new(HostPin::from_cert(&real_cert).unwrap());
        assert!(do_handshake(client_config(v), server_config(&mitm_cert, &mitm_key)).is_err());
    }
}
