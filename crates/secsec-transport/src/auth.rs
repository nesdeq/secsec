//! Connection authentication (`secsec-Design.md` §9.6, §11): the session transcript and the `secsec-auth-v1` payload.

use secsec_canon::Writer;
use secsec_sig::{DeviceKey, DevicePublic, NS_AUTH};

/// The wire `secsec_version` in the hellos (§11): folded into the transcript, no negotiation.
pub(crate) const SECSEC_VERSION: u16 = 3;
/// Handshake nonce length (§11).
pub(crate) const NONCE_LEN: usize = 32;

/// The §11 session transcript: BLAKE3 over exactly the two length-prefixed hellos, in order.
#[derive(Clone, Default)]
pub struct SessionTranscript {
    hasher: blake3::Hasher,
}

impl SessionTranscript {
    /// An empty transcript.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the client hello: `le32(2 + 32) ‖ version ‖ client_nonce`.
    pub fn client_hello(&mut self, version: u16, client_nonce: &[u8; NONCE_LEN]) -> &mut Self {
        let mut w = Writer::new();
        w.u32((2 + NONCE_LEN) as u32).u16(version).raw(client_nonce);
        self.hasher.update(&w.finish());
        self
    }

    /// Feed the server hello: `le32(2 + 32 + 32) ‖ version ‖ server_nonce ‖ host_id`.
    pub fn server_hello(
        &mut self,
        version: u16,
        server_nonce: &[u8; NONCE_LEN],
        host_id: &[u8; 32],
    ) -> &mut Self {
        let mut w = Writer::new();
        w.u32((2 + NONCE_LEN + 32) as u32)
            .u16(version)
            .raw(server_nonce)
            .raw(host_id);
        self.hasher.update(&w.finish());
        self
    }

    /// The 32-byte transcript so far.
    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

/// Errors from connection-auth signing/verification.
#[derive(Debug)]
pub enum AuthError {
    /// The auth signature did not verify.
    BadSignature,
    /// Signing/key error.
    Sig(secsec_sig::SigError),
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthError::BadSignature => f.write_str("connection-auth signature invalid"),
            AuthError::Sig(e) => write!(f, "sig: {e}"),
        }
    }
}
impl std::error::Error for AuthError {}
impl From<secsec_sig::SigError> for AuthError {
    fn from(e: secsec_sig::SigError) -> Self {
        AuthError::Sig(e)
    }
}

/// The `secsec-auth-v1` fields: this session, this server, this TLS channel.
#[derive(Clone, Copy)]
pub(crate) struct ConnectionAuth<'a> {
    /// The TLS 1.3 exporter (§11).
    pub channel_binding: &'a [u8],
    /// `BLAKE3(SPKI)` of the pinned server key.
    pub host_id: [u8; 32],
    /// The [`SessionTranscript`] value.
    pub session_transcript: [u8; 32],
    /// The server's handshake challenge.
    pub server_nonce: [u8; NONCE_LEN],
}

impl ConnectionAuth<'_> {
    /// The signed payload `bytes(channel_binding) ‖ host_id ‖ session_transcript ‖ server_nonce` (§9.6).
    #[must_use]
    pub(crate) fn message(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(self.channel_binding)
            .raw(&self.host_id)
            .raw(&self.session_transcript)
            .raw(&self.server_nonce);
        w.finish()
    }

    /// Sign under `NS_AUTH`.
    pub(crate) fn sign(&self, device: &DeviceKey) -> Result<Vec<u8>, AuthError> {
        Ok(device.sign(NS_AUTH, &self.message())?)
    }

    /// Verify against `pubkey`.
    pub(crate) fn verify(&self, pubkey: &DevicePublic, sig: &[u8]) -> Result<(), AuthError> {
        pubkey
            .verify(NS_AUTH, &self.message(), sig)
            .map_err(|_| AuthError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secsec_sig::NS_WRITE;

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn transcript(cn: &[u8; 32], sn: &[u8; 32], host_id: &[u8; 32]) -> [u8; 32] {
        let mut t = SessionTranscript::new();
        t.client_hello(SECSEC_VERSION, cn)
            .server_hello(SECSEC_VERSION, sn, host_id);
        t.finalize()
    }

    #[test]
    fn transcript_is_deterministic_input_and_order_sensitive() {
        let base = transcript(&[1; 32], &[2; 32], &[3; 32]);
        assert_eq!(base, transcript(&[1; 32], &[2; 32], &[3; 32]));
        assert_ne!(base, transcript(&[9; 32], &[2; 32], &[3; 32]));
        assert_ne!(base, transcript(&[1; 32], &[9; 32], &[3; 32]));
        assert_ne!(base, transcript(&[1; 32], &[2; 32], &[9; 32]));
        let mut a = SessionTranscript::new();
        a.client_hello(1, &[1; 32])
            .server_hello(1, &[2; 32], &[3; 32]);
        let mut b = SessionTranscript::new();
        b.server_hello(1, &[2; 32], &[3; 32])
            .client_hello(1, &[1; 32]);
        assert_ne!(a.finalize(), b.finalize());
    }

    #[test]
    fn auth_binds_every_field_and_signer() {
        let dev = DeviceKey::generate().unwrap();
        let base = ConnectionAuth {
            channel_binding: b"channel",
            host_id: [0xA0; 32],
            session_transcript: [0x7a; 32],
            server_nonce: [0x5e; 32],
        };
        let sig = base.sign(&dev).unwrap();
        assert!(base.verify(&dev.public(), &sig).is_ok());
        for a in [
            ConnectionAuth {
                channel_binding: b"CHANNEL!",
                ..base
            },
            ConnectionAuth {
                host_id: [0xA1; 32],
                ..base
            },
            ConnectionAuth {
                session_transcript: [0x7b; 32],
                ..base
            },
            ConnectionAuth {
                server_nonce: [0x5f; 32],
                ..base
            },
        ] {
            assert!(matches!(
                a.verify(&dev.public(), &sig),
                Err(AuthError::BadSignature)
            ));
        }
        let other = DeviceKey::generate().unwrap().public();
        assert!(matches!(
            base.verify(&other, &sig),
            Err(AuthError::BadSignature)
        ));
        assert!(dev
            .public()
            .verify(NS_WRITE, &base.message(), &sig)
            .is_err());
    }

    /// Frozen transcript KAT, mirrored in `vectors/secsec-kat-v1.txt [auth]` (fixed version 1, independent of SECSEC_VERSION).
    #[test]
    fn transcript_kat() {
        let mut t = SessionTranscript::new();
        t.client_hello(1, &[1; 32])
            .server_hello(1, &[2; 32], &[3; 32]);
        assert_eq!(
            hx(&t.finalize()),
            "d7da869b22932e7f1e55fe87d1bec0245d9c41273dc4b39e38c3c4e0328ebbde"
        );
    }
}
