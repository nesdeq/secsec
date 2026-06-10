//! Connection authentication (`finaldesign.md` §11, §9.6). The pure-crypto core of the client→server
//! handshake auth: the **session transcript** and the `secsec-auth-v1` signed payload that binds the
//! client to this specific session, server identity, and channel.
//!
//! After the TLS 1.3 handshake (verified by the pinned [`crate::PinnedServerVerifier`]), the client
//! signs, under [`secsec_sig::NS_AUTH`], the §9.6 payload
//! `channel_binding ‖ host_id ‖ session_transcript ‖ server_nonce`, where:
//! - `channel_binding` is the TLS keying-material exporter — supplied by the transport at runtime;
//! - `host_id = BLAKE3(SPKI)` ([`crate::HostPin::host_id`]) — pins the server identity;
//! - `session_transcript` is the running BLAKE3 over the ordered handshake messages ([`SessionTranscript`]);
//! - `server_nonce` is the server's fresh single-use challenge.
//!
//! The server verifies this against a **keyslot-owning** (rostered) public key and checks nonce
//! freshness (§11/§12); that enforcement is server state and lives in the proto/server layer — this
//! module provides the message construction and the signature.

use secsec_canon::Writer;
use secsec_sig::{DeviceKey, DevicePublic, NS_AUTH};

/// The wire `secsec_version` carried in the handshake hellos (§11).
pub const SECSEC_VERSION: u16 = 1;
/// Handshake nonce length (client/server), in bytes (§11).
pub const NONCE_LEN: usize = 32;

/// The §11 **session transcript**: a running BLAKE3 over the ordered, length-prefixed handshake
/// messages — exactly the client hello and the server hello (no raw pubkeys are injected — server
/// identity is bound via `host_id`, the channel via the TLS exporter).
///
/// Both ends MUST feed identical bytes in this fixed order; [`Self::finalize`] yields the 32-byte
/// transcript bound into the connection-auth signature.
#[derive(Clone, Default)]
pub struct SessionTranscript {
    hasher: blake3::Hasher,
}

impl SessionTranscript {
    /// A fresh, empty transcript (QUIC mode).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the **client hello** (§11): `le32(2 + 32) ‖ version(u16 le) ‖ client_nonce(32)`.
    pub fn client_hello(&mut self, version: u16, client_nonce: &[u8; NONCE_LEN]) -> &mut Self {
        let mut w = Writer::new();
        w.u32((2 + NONCE_LEN) as u32).u16(version).raw(client_nonce);
        self.hasher.update(&w.finish());
        self
    }

    /// Feed the **server hello** (§11): `le32(2 + 32 + 32) ‖ version(u16 le) ‖ server_nonce(32) ‖ host_id(32)`.
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

    /// The 32-byte transcript over everything fed so far.
    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

/// Errors from connection-auth signing/verification.
#[derive(Debug)]
pub enum AuthError {
    /// The auth signature did not verify (bad signature, wrong key, or any bound field altered).
    BadSignature,
    /// Underlying signing/key error.
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

/// The connection-auth context (§9.6 `secsec-auth-v1`): the fields the client signs to prove it
/// completed *this* session against *this* server over *this* channel.
#[derive(Clone, Copy)]
pub struct ConnectionAuth<'a> {
    /// TLS exporter (QUIC) or SSH exchange hash `H` (stdio) — the channel binding.
    pub channel_binding: &'a [u8],
    /// `BLAKE3(SPKI)` of the pinned server key (§11).
    pub host_id: [u8; 32],
    /// The [`SessionTranscript`] value.
    pub session_transcript: [u8; 32],
    /// The server's fresh single-use challenge.
    pub server_nonce: [u8; NONCE_LEN],
}

impl ConnectionAuth<'_> {
    /// The canonical signed payload: `channel_binding ‖ host_id ‖ session_transcript ‖ server_nonce`
    /// (§9.6 field order). `channel_binding` is length-prefixed so the encoding is unambiguous across
    /// modes (its length differs between QUIC exporter and SSH `H`); the rest are fixed-width.
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(self.channel_binding)
            .raw(&self.host_id)
            .raw(&self.session_transcript)
            .raw(&self.server_nonce);
        w.finish()
    }

    /// Sign the connection-auth payload under `NS_AUTH` (§9.6).
    pub fn sign(&self, device: &DeviceKey) -> Result<Vec<u8>, AuthError> {
        Ok(device.sign(NS_AUTH, &self.message())?)
    }

    /// Verify a connection-auth signature against `pubkey`. The server resolves `pubkey` from the
    /// roster and MUST also confirm it owns a keyslot and that `server_nonce` is fresh (§11/§12).
    pub fn verify(&self, pubkey: &DevicePublic, sig: &[u8]) -> Result<(), AuthError> {
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
    fn transcript_is_deterministic_and_input_sensitive() {
        let base = transcript(&[1; 32], &[2; 32], &[3; 32]);
        assert_eq!(base, transcript(&[1; 32], &[2; 32], &[3; 32]));
        assert_ne!(base, transcript(&[9; 32], &[2; 32], &[3; 32])); // client_nonce
        assert_ne!(base, transcript(&[1; 32], &[9; 32], &[3; 32])); // server_nonce
        assert_ne!(base, transcript(&[1; 32], &[2; 32], &[9; 32])); // host_id
    }

    #[test]
    fn order_matters() {
        // feeding the two hellos in the wrong order must change the transcript.
        let mut a = SessionTranscript::new();
        a.client_hello(1, &[1; 32])
            .server_hello(1, &[2; 32], &[3; 32]);
        let mut b = SessionTranscript::new();
        b.server_hello(1, &[2; 32], &[3; 32])
            .client_hello(1, &[1; 32]);
        assert_ne!(a.finalize(), b.finalize());
    }

    #[test]
    fn auth_round_trip() {
        let dev = DeviceKey::generate().unwrap();
        let ctx = ConnectionAuth {
            channel_binding: b"tls-exporter-32-bytes-or-ssh-hash",
            host_id: [0xA0; 32],
            session_transcript: transcript(&[1; 32], &[2; 32], &[0xA0; 32]),
            server_nonce: [0x5e; 32],
        };
        let sig = ctx.sign(&dev).unwrap();
        assert!(ctx.verify(&dev.public(), &sig).is_ok());
    }

    #[test]
    fn auth_binds_every_field() {
        let dev = DeviceKey::generate().unwrap();
        let base = ConnectionAuth {
            channel_binding: b"channel",
            host_id: [0xA0; 32],
            session_transcript: [0x7a; 32],
            server_nonce: [0x5e; 32],
        };
        let sig = base.sign(&dev).unwrap();

        // altering any bound field invalidates the signature.
        let altered = [
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
        ];
        for a in altered {
            assert!(matches!(
                a.verify(&dev.public(), &sig),
                Err(AuthError::BadSignature)
            ));
        }
        // wrong signer too.
        let other = DeviceKey::generate().unwrap().public();
        assert!(matches!(
            base.verify(&other, &sig),
            Err(AuthError::BadSignature)
        ));
    }

    #[test]
    fn auth_signature_is_namespaced() {
        // a secsec-auth-v1 signature must not verify as anything else (§9.6 cross-protocol guard).
        let dev = DeviceKey::generate().unwrap();
        let ctx = ConnectionAuth {
            channel_binding: b"c",
            host_id: [0; 32],
            session_transcript: [0; 32],
            server_nonce: [0; 32],
        };
        let sig = ctx.sign(&dev).unwrap();
        // verifying the same bytes under a different namespace must fail.
        assert!(dev.public().verify(NS_WRITE, &ctx.message(), &sig).is_err());
    }

    /// Frozen transcript KAT, mirrored in `vectors/secsec-kat-v1.txt [auth]`. version=1,
    /// client_nonce=0x01*32, server_nonce=0x02*32, host_id=0x03*32.
    #[test]
    fn transcript_kat() {
        assert_eq!(
            hx(&transcript(&[1; 32], &[2; 32], &[3; 32])),
            "d7da869b22932e7f1e55fe87d1bec0245d9c41273dc4b39e38c3c4e0328ebbde"
        );
    }
}
