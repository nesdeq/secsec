//! Signed arrival receipts (`secsec-Design.md` §15; defence-in-depth, §21): on each `put` the server
//! signs `id ‖ host_id ‖ arrival_gen ‖ put_epoch ‖ ts` with a dedicated Ed25519 receipt key. **Not
//! load-bearing** — GC eligibility is always client-computed; this is an audit trail against a
//! cooperative server's bookkeeping errors.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use secsec_canon::Writer;

/// Receipt signature length (Ed25519).
pub const RECEIPT_SIG_LEN: usize = 64;
/// Receipt public-key length (Ed25519).
pub const RECEIPT_PK_LEN: usize = 32;

/// Domain-separation label for the receipt signature (§15/§9.6).
const RECEIPT_LABEL: &[u8] = b"secsec-receipt-v1";

/// The canonical signed message: `"secsec-receipt-v1" ‖ id ‖ host_id ‖ le64(arrival_gen) ‖
/// le64(put_epoch) ‖ le64(ts)` (§15). Both signer and verifier build it identically.
#[must_use]
pub fn receipt_message(
    id: &[u8; 32],
    host_id: &[u8; 32],
    arrival_gen: u64,
    put_epoch: u64,
    ts: u64,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(RECEIPT_LABEL)
        .raw(id)
        .raw(host_id)
        .u64(arrival_gen)
        .u64(put_epoch)
        .u64(ts);
    w.finish()
}

/// Sign an arrival receipt with the host's Ed25519 receipt key.
#[must_use]
pub fn sign_receipt(
    key: &SigningKey,
    id: &[u8; 32],
    host_id: &[u8; 32],
    arrival_gen: u64,
    put_epoch: u64,
    ts: u64,
) -> [u8; RECEIPT_SIG_LEN] {
    let msg = receipt_message(id, host_id, arrival_gen, put_epoch, ts);
    key.sign(&msg).to_bytes()
}

/// Verify an arrival receipt against the host's receipt public key. Returns `true` iff the signature
/// is valid for the exact `(id, host_id, arrival_gen, put_epoch, ts)`. A zero public key (no receipt
/// key configured server-side) verifies nothing — returns `false`.
#[must_use]
pub fn verify_receipt(
    pubkey: &[u8; RECEIPT_PK_LEN],
    sig: &[u8; RECEIPT_SIG_LEN],
    id: &[u8; 32],
    host_id: &[u8; 32],
    arrival_gen: u64,
    put_epoch: u64,
    ts: u64,
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let msg = receipt_message(id, host_id, arrival_gen, put_epoch, ts);
    vk.verify(&msg, &Signature::from_bytes(sig)).is_ok()
}

/// The public key (32 bytes) for a host receipt `SigningKey`.
#[must_use]
pub fn receipt_public(key: &SigningKey) -> [u8; RECEIPT_PK_LEN] {
    key.verifying_key().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x33; 32])
    }

    #[test]
    fn sign_verify_round_trip_and_tamper_rejected() {
        let k = key();
        let pk = receipt_public(&k);
        let id = [1u8; 32];
        let host = [2u8; 32];
        let sig = sign_receipt(&k, &id, &host, 5, 9, 100);
        assert!(verify_receipt(&pk, &sig, &id, &host, 5, 9, 100));

        // every bound field is checked: change any one → verification fails.
        assert!(!verify_receipt(&pk, &sig, &[9; 32], &host, 5, 9, 100)); // id
        assert!(!verify_receipt(&pk, &sig, &id, &[9; 32], 5, 9, 100)); // host_id
        assert!(!verify_receipt(&pk, &sig, &id, &host, 6, 9, 100)); // arrival_gen
        assert!(!verify_receipt(&pk, &sig, &id, &host, 5, 8, 100)); // put_epoch
        assert!(!verify_receipt(&pk, &sig, &id, &host, 5, 9, 101)); // ts

        // a different host receipt key cannot verify.
        let other = receipt_public(&SigningKey::from_bytes(&[0x44; 32]));
        assert!(!verify_receipt(&other, &sig, &id, &host, 5, 9, 100));

        // a zero pubkey (no receipt key configured) verifies nothing.
        assert!(!verify_receipt(&[0u8; 32], &sig, &id, &host, 5, 9, 100));
    }
}
