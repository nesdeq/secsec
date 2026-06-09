//! `secsec-keyslot` — per-device wrap of `master_key` via HPKE (`finaldesign.md` §8.3).
//!
//! A keyslot seals `master_key_g` to a device's X25519 public key with HPKE base mode, pinned
//! suite **DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305** (RFC 9180 `0x0021`), and
//! `info = "secsec-keyslot-v1" ‖ device_id ‖ le32(gen)` binding the slot to one device and one
//! generation.
//!
//! **Authenticity rests on `mk_commit`, not the wrap.** Anyone who knows a device's public key can
//! fabricate a keyslot wrapping a *fake* key (§7's fake-universe attack), so [`unwrap`] verifies
//! the recovered key against the `mk_commit_g` from the RFP-anchored sigchain before returning it.
//!
//! The X25519 keys come from `secsec-sig`'s Ed25519→X25519 conversion. The HPKE crate (rozbb
//! `hpke`) performs the RFC 9180 §7.1.4 zero-shared-secret check; a low-order recipient key is
//! rejected (see `low_order_recipient_is_rejected`).

#![forbid(unsafe_code)]

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeR,
    OpModeS, Serializable,
};
use rand_core::OsRng;
use secsec_canon::Writer;
use secsec_kdf::MasterKey;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

/// Length of an X25519 HPKE encapsulated key, in bytes.
const ENCAPPED_LEN: usize = 32;

/// Errors from keyslot wrap/unwrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyslotError {
    /// A public/private key (or encapsulated key) was malformed or low-order.
    BadKey,
    /// HPKE seal/open failed (wrong recipient, tampered keyslot, or zero shared secret).
    Hpke,
    /// The keyslot blob was structurally malformed.
    Malformed,
    /// The unwrapped key did not match the expected `mk_commit_g` — a forged/fake keyslot (§8.3).
    CommitMismatch,
}

impl core::fmt::Display for KeyslotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeyslotError::BadKey => f.write_str("malformed or low-order key"),
            KeyslotError::Hpke => f.write_str("HPKE seal/open failed"),
            KeyslotError::Malformed => f.write_str("malformed keyslot"),
            KeyslotError::CommitMismatch => {
                f.write_str("unwrapped key fails mk_commit (forged keyslot)")
            }
        }
    }
}

impl std::error::Error for KeyslotError {}

/// `info = "secsec-keyslot-v1" ‖ device_id ‖ le32(gen)` (§8.3 / §19 HPKE binding).
fn info_bytes(device_id: &[u8; 32], gen: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(b"secsec-keyslot-v1").raw(device_id).u32(gen);
    w.finish()
}

/// Wrap `master_key` (raw generation-`g` key bytes) to a device's X25519 public key.
/// Returns the keyslot blob `encapped_key(32) ‖ hpke_ciphertext`.
pub fn wrap(
    master_key: &[u8; 32],
    gen: u32,
    device_id: &[u8; 32],
    recip_x25519_pub: &[u8; 32],
) -> Result<Vec<u8>, KeyslotError> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(recip_x25519_pub)
        .map_err(|_| KeyslotError::BadKey)?;
    let info = info_bytes(device_id, gen);
    let (encapped, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk,
        &info,
        master_key,
        &[],
        &mut OsRng,
    )
    .map_err(|_| KeyslotError::Hpke)?;

    let enc = encapped.to_bytes();
    let mut out = Vec::with_capacity(enc.len() + ct.len());
    out.extend_from_slice(enc.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap a keyslot with the device's X25519 secret, **verifying** the recovered key against
/// `expected_mk_commit` (§8.3). Returns the generation-`g` [`MasterKey`] on success.
pub fn unwrap(
    keyslot: &[u8],
    gen: u32,
    device_id: &[u8; 32],
    recip_x25519_secret: &[u8; 32],
    expected_mk_commit: &[u8; 32],
) -> Result<MasterKey, KeyslotError> {
    let mk_bytes = unwrap_raw(keyslot, gen, device_id, recip_x25519_secret)?;
    let mk = MasterKey::new(gen, *mk_bytes);
    // Authenticity: the recovered key must match the RFP-anchored commitment (§8.3).
    if !bool::from(mk.mk_commit().ct_eq(expected_mk_commit)) {
        return Err(KeyslotError::CommitMismatch);
    }
    Ok(mk)
}

/// HPKE-open a keyslot to its raw 32-byte master-key bytes **without** the `mk_commit` authenticity
/// check. This is **only** for the cold-start bootstrap (§8.1): the commitment to verify against lives
/// inside the still-encrypted sigchain, so the device must first recover this candidate, decrypt the
/// chain with it, and then verify — which [`secsec_kdf`]-keyed `cold_start_fold` does as its final
/// step. Every other caller MUST use [`unwrap`], which performs the check.
pub fn unwrap_raw(
    keyslot: &[u8],
    gen: u32,
    device_id: &[u8; 32],
    recip_x25519_secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, KeyslotError> {
    if keyslot.len() < ENCAPPED_LEN {
        return Err(KeyslotError::Malformed);
    }
    let (enc_bytes, ct) = keyslot.split_at(ENCAPPED_LEN);
    let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(recip_x25519_secret)
        .map_err(|_| KeyslotError::BadKey)?;
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|_| KeyslotError::Malformed)?;
    let info = info_bytes(device_id, gen);

    let mut pt =
        hpke::single_shot_open::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &encapped, &info, ct, &[])
            .map_err(|_| KeyslotError::Hpke)?;

    if pt.len() != 32 {
        pt.zeroize();
        return Err(KeyslotError::Malformed);
    }
    let mut mk_bytes = Zeroizing::new([0u8; 32]);
    mk_bytes.copy_from_slice(&pt);
    pt.zeroize();
    Ok(mk_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secsec_sig::DeviceKey;

    const MK: [u8; 32] = [0x77; 32];

    fn mk_commit_of(gen: u32) -> [u8; 32] {
        MasterKey::new(gen, MK).mk_commit()
    }

    #[test]
    fn wrap_unwrap_round_trip_recovers_usable_key() {
        let dev = DeviceKey::generate().unwrap();
        let did = dev.device_id().unwrap();
        let pubx = dev.x25519_public().unwrap();
        let secx = dev.x25519_secret().unwrap();

        let slot = wrap(&MK, 5, &did, &pubx).unwrap();
        let mk = unwrap(&slot, 5, &did, &secx, &mk_commit_of(5)).unwrap();

        assert_eq!(mk.generation(), 5);
        // recovered key derives identically to the original
        let orig = MasterKey::new(5, MK);
        assert_eq!(&mk.enc_key(0)[..], &orig.enc_key(0)[..]);
    }

    #[test]
    fn wrong_device_cannot_unwrap() {
        let a = DeviceKey::generate().unwrap();
        let b = DeviceKey::generate().unwrap();
        let slot = wrap(&MK, 1, &a.device_id().unwrap(), &a.x25519_public().unwrap()).unwrap();
        // B's secret cannot open A's slot.
        let r = unwrap(
            &slot,
            1,
            &a.device_id().unwrap(),
            &b.x25519_secret().unwrap(),
            &mk_commit_of(1),
        );
        assert!(matches!(r, Err(KeyslotError::Hpke)));
    }

    #[test]
    fn forged_keyslot_fails_mk_commit() {
        // A malicious party wraps a DIFFERENT (fake) key to the device. It unwraps fine at the
        // HPKE layer, but must be rejected because it doesn't match the real mk_commit (§8.3).
        let dev = DeviceKey::generate().unwrap();
        let did = dev.device_id().unwrap();
        let fake = [0x11u8; 32];
        let slot = wrap(&fake, 2, &did, &dev.x25519_public().unwrap()).unwrap();
        let r = unwrap(
            &slot,
            2,
            &did,
            &dev.x25519_secret().unwrap(),
            &mk_commit_of(2),
        );
        assert!(matches!(r, Err(KeyslotError::CommitMismatch)));
    }

    #[test]
    fn info_binds_generation() {
        // A slot wrapped at gen 3 must not unwrap as gen 4 (info mismatch -> HPKE open fails).
        let dev = DeviceKey::generate().unwrap();
        let did = dev.device_id().unwrap();
        let slot = wrap(&MK, 3, &did, &dev.x25519_public().unwrap()).unwrap();
        let r = unwrap(
            &slot,
            4,
            &did,
            &dev.x25519_secret().unwrap(),
            &mk_commit_of(4),
        );
        assert!(matches!(r, Err(KeyslotError::Hpke)));
    }

    #[test]
    fn tampered_keyslot_rejected() {
        let dev = DeviceKey::generate().unwrap();
        let did = dev.device_id().unwrap();
        let mut slot = wrap(&MK, 1, &did, &dev.x25519_public().unwrap()).unwrap();
        *slot.last_mut().unwrap() ^= 0x01;
        let r = unwrap(
            &slot,
            1,
            &did,
            &dev.x25519_secret().unwrap(),
            &mk_commit_of(1),
        );
        assert!(matches!(r, Err(KeyslotError::Hpke)));
    }

    /// R3: a low-order recipient public key (all-zeros) forces a zero shared secret and MUST be
    /// rejected (RFC 9180 §7.1.4) — the bug class that hit hpke-rs in May 2026.
    #[test]
    fn low_order_recipient_is_rejected() {
        let did = [0u8; 32];
        let r = wrap(&MK, 1, &did, &[0u8; 32]);
        assert!(r.is_err(), "wrapping to a low-order public key must fail");
    }
}
