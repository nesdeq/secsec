//! Recovery keyslot (`finaldesign.md` §8.6, security property P14).
//!
//! An optional, server-stored wrap of the master key under a key the user holds out-of-band — a
//! 256-bit **recovery code** (preferred) or a **passphrase** (explicitly weaker). It uses the §9.4
//! CTX committing AEAD (CMT-4) directly, so a wrong code/passphrase fails the commitment rather than
//! silently producing a wrong key, and a partitioning oracle is closed. Authenticity is **not** the
//! wrap's job: the recovered candidate is verified against `mk_commit_g` from the RFP-anchored chain
//! (§7 step 3) — so recovery is not a server-exploitable backdoor.
//!
//! Blob layout: `salt(16) ‖ ctx_tag(32) ‖ ct(32)`. The §9.4 AD — `"secsec-recovery-v1" ‖
//! device_pubkey ‖ le32(gen)` — is **recomputed** by the recoverer from the device pubkey + generation
//! it already holds (it is authenticated by the tag regardless), so it is not stored redundantly.

#![forbid(unsafe_code)]

use secsec_canon::Writer;
use secsec_kdf::MasterKey;
use zeroize::Zeroizing;

/// Recovery-code KDF label (§8.6).
const L_CODE: &str = "secsec-recovery-code-v1";
/// AD label binding a recovery keyslot to its purpose (§8.6/§9.6).
const AD_LABEL: &[u8] = b"secsec-recovery-v1";

/// Salt length (§19: 16-byte OS-CSPRNG, per-keyslot, rotated on re-wrap).
pub const SALT_LEN: usize = 16;
const TAG_LEN: usize = 32; // CTX tag
const KEY_LEN: usize = 32; // master key / ciphertext length

/// Argon2id parameters for the passphrase path (§19): m = 64 MiB, t = 3, p = 1, 32-byte output.
const ARGON2_M_KIB: u32 = 65536;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;

/// Errors from sealing / recovering a recovery keyslot.
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryError {
    /// The blob was the wrong length.
    BadBlob,
    /// The CTX AEAD failed to open — wrong code/passphrase or a tampered blob.
    Aead,
    /// The recovered key did not match `mk_commit_g` (a forged keyslot or wrong generation, §7/§8.6).
    CommitMismatch,
    /// Argon2id derivation failed (parameter or memory error).
    Argon2,
}

impl core::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecoveryError::BadBlob => f.write_str("malformed recovery blob"),
            RecoveryError::Aead => {
                f.write_str("recovery AEAD open failed (wrong code/passphrase?)")
            }
            RecoveryError::CommitMismatch => f.write_str("recovered key fails mk_commit (§8.6)"),
            RecoveryError::Argon2 => f.write_str("Argon2id derivation failed"),
        }
    }
}
impl std::error::Error for RecoveryError {}

/// `recovery_key = BLAKE3::derive_key("secsec-recovery-code-v1", salt ‖ code)` (§8.6 preferred path).
/// The 256-bit code is high-entropy, so a fast KDF suffices; the salt blocks cross-install
/// precomputation.
#[must_use]
pub fn recovery_key_from_code(salt: &[u8; SALT_LEN], code: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; SALT_LEN + 32]);
    ikm[..SALT_LEN].copy_from_slice(salt);
    ikm[SALT_LEN..].copy_from_slice(code);
    Zeroizing::new(blake3::derive_key(L_CODE, ikm.as_slice()))
}

/// `recovery_key = Argon2id(passphrase, salt, m=64 MiB, t=3, p=1, 32)` (§8.6/§19 weaker path — the
/// blob is server-exfiltratable, so the slow KDF is the offline-attack floor).
pub fn recovery_key_from_passphrase(
    salt: &[u8; SALT_LEN],
    passphrase: &[u8],
) -> Result<Zeroizing<[u8; 32]>, RecoveryError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .map_err(|_| RecoveryError::Argon2)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, out.as_mut_slice())
        .map_err(|_| RecoveryError::Argon2)?;
    Ok(out)
}

/// `AD_recovery = "secsec-recovery-v1" ‖ device_pubkey ‖ le32(gen)` (§8.6) — binds the keyslot to one
/// device and generation; the server cannot swap recovery keyslots across users/generations.
fn ad_recovery(device_pubkey: &[u8], gen: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.raw(AD_LABEL).raw(device_pubkey).u32(gen);
    w.finish()
}

/// Seal `master_key` (the generation-`gen` key bytes) into a recovery keyslot under `recovery_key`,
/// for `device_pubkey` (canonical encoding). Returns `salt ‖ ctx_tag ‖ ct`. `salt` is the value the
/// `recovery_key` was derived under (stored so the recoverer can re-derive it).
#[must_use]
pub fn seal_recovery(
    master_key: &[u8; 32],
    gen: u32,
    device_pubkey: &[u8],
    recovery_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
) -> Vec<u8> {
    let ad = ad_recovery(device_pubkey, gen);
    let (ctx_tag, ct) = secsec_aead::seal(recovery_key, &ad, master_key);
    let mut out = Vec::with_capacity(SALT_LEN + TAG_LEN + ct.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&ctx_tag);
    out.extend_from_slice(&ct);
    out
}

/// `(salt, ctx_tag, ciphertext)` parsed from a recovery blob.
type Parsed<'a> = (&'a [u8; SALT_LEN], [u8; 32], &'a [u8]);

/// Split a recovery blob into `(salt, ctx_tag, ct)`.
fn parse(blob: &[u8]) -> Result<Parsed<'_>, RecoveryError> {
    if blob.len() != SALT_LEN + TAG_LEN + KEY_LEN {
        return Err(RecoveryError::BadBlob);
    }
    let salt: &[u8; SALT_LEN] = blob[..SALT_LEN].try_into().expect("checked length");
    let ctx_tag: [u8; 32] = blob[SALT_LEN..SALT_LEN + TAG_LEN]
        .try_into()
        .expect("checked length");
    let ct = &blob[SALT_LEN + TAG_LEN..];
    Ok((salt, ctx_tag, ct))
}

/// Recover the master key from a recovery `blob` given the already-derived `recovery_key`, verifying
/// the result against `expected_mk_commit` from the RFP-anchored chain (§7 step 3). The caller derives
/// `recovery_key` from the blob's salt (via [`recovery_key_from_code`] /
/// [`recovery_key_from_passphrase`]); [`recover_with_code`] / [`recover_with_passphrase`] do both.
pub fn recover(
    blob: &[u8],
    recovery_key: &[u8; 32],
    device_pubkey: &[u8],
    gen: u32,
    expected_mk_commit: &[u8; 32],
) -> Result<MasterKey, RecoveryError> {
    let key = recover_raw(blob, recovery_key, device_pubkey, gen)?;
    let mk = MasterKey::new(gen, *key);
    // Authenticity (§8.6): the candidate MUST match the RFP-anchored commitment.
    if mk.mk_commit() != *expected_mk_commit {
        return Err(RecoveryError::CommitMismatch);
    }
    Ok(mk)
}

/// Recover the **raw** generation-`gen` master-key bytes from `blob` + `recovery_key`, **without** the
/// `mk_commit` check — for a recovery-driven §8.1 cold-start, where the commitment lives inside the
/// still-encrypted sigchain (the fold verifies it). Every other caller MUST use [`recover`].
pub fn recover_raw(
    blob: &[u8],
    recovery_key: &[u8; 32],
    device_pubkey: &[u8],
    gen: u32,
) -> Result<Zeroizing<[u8; 32]>, RecoveryError> {
    let (_salt, ctx_tag, ct) = parse(blob)?;
    let ad = ad_recovery(device_pubkey, gen);
    let pt = secsec_aead::open(recovery_key, &ad, &ctx_tag, ct).map_err(|_| RecoveryError::Aead)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&pt);
    Ok(key)
}

/// Recover the raw master-key bytes using a 256-bit recovery code (derive the key from the blob's
/// salt, then [`recover_raw`]) — for the recovery cold-start. The fold then verifies `mk_commit`.
pub fn recover_raw_with_code(
    blob: &[u8],
    code: &[u8; 32],
    device_pubkey: &[u8],
    gen: u32,
) -> Result<Zeroizing<[u8; 32]>, RecoveryError> {
    let (salt, _, _) = parse(blob)?;
    let recovery_key = recovery_key_from_code(salt, code);
    recover_raw(blob, &recovery_key, device_pubkey, gen)
}

/// Recover using a 256-bit recovery code (derives `recovery_key` from the blob's salt, then [`recover`]).
pub fn recover_with_code(
    blob: &[u8],
    code: &[u8; 32],
    device_pubkey: &[u8],
    gen: u32,
    expected_mk_commit: &[u8; 32],
) -> Result<MasterKey, RecoveryError> {
    let (salt, _, _) = parse(blob)?;
    let recovery_key = recovery_key_from_code(salt, code);
    recover(blob, &recovery_key, device_pubkey, gen, expected_mk_commit)
}

/// Recover using a passphrase (Argon2id from the blob's salt, then [`recover`]).
pub fn recover_with_passphrase(
    blob: &[u8],
    passphrase: &[u8],
    device_pubkey: &[u8],
    gen: u32,
    expected_mk_commit: &[u8; 32],
) -> Result<MasterKey, RecoveryError> {
    let (salt, _, _) = parse(blob)?;
    let recovery_key = recovery_key_from_passphrase(salt, passphrase)?;
    recover(blob, &recovery_key, device_pubkey, gen, expected_mk_commit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MK: [u8; 32] = [0x42; 32];
    const PUBKEY: &[u8] = b"device-pubkey-canonical-bytes";
    const SALT: [u8; SALT_LEN] = [0x9a; SALT_LEN];
    const GEN: u32 = 1;

    fn mk_commit() -> [u8; 32] {
        MasterKey::new(GEN, MK).mk_commit()
    }

    #[test]
    fn code_path_round_trips_and_rejects_wrong_inputs() {
        let code = [0x11u8; 32];
        let rk = recovery_key_from_code(&SALT, &code);
        let blob = seal_recovery(&MK, GEN, PUBKEY, &rk, &SALT);
        assert_eq!(blob.len(), SALT_LEN + TAG_LEN + KEY_LEN);

        // correct code recovers the exact master key (verified against mk_commit).
        let mk = recover_with_code(&blob, &code, PUBKEY, GEN, &mk_commit()).unwrap();
        assert_eq!(mk.generation(), GEN);
        assert_eq!(mk.mk_commit(), mk_commit());

        // wrong code → AEAD open fails (CMT-4, not a silent wrong key).
        assert!(matches!(
            recover_with_code(&blob, &[0x22; 32], PUBKEY, GEN, &mk_commit()),
            Err(RecoveryError::Aead)
        ));
        // wrong device pubkey (AD mismatch) → AEAD fails.
        assert!(matches!(
            recover_with_code(&blob, &code, b"other-pubkey", GEN, &mk_commit()),
            Err(RecoveryError::Aead)
        ));
        // wrong generation (AD mismatch) → AEAD fails.
        assert!(matches!(
            recover_with_code(&blob, &code, PUBKEY, 2, &mk_commit()),
            Err(RecoveryError::Aead)
        ));
        // a tampered ciphertext → AEAD fails.
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(matches!(
            recover_with_code(&bad, &code, PUBKEY, GEN, &mk_commit()),
            Err(RecoveryError::Aead)
        ));
    }

    #[test]
    fn opens_but_commit_mismatch_is_caught() {
        // A keyslot sealed for a DIFFERENT master key opens cleanly under the right code, but the
        // recovered key fails the RFP-anchored mk_commit — a server-forged keyslot is rejected here.
        let code = [0x33u8; 32];
        let rk = recovery_key_from_code(&SALT, &code);
        let fake_mk = [0x99u8; 32];
        let blob = seal_recovery(&fake_mk, GEN, PUBKEY, &rk, &SALT);
        assert!(matches!(
            recover_with_code(&blob, &code, PUBKEY, GEN, &mk_commit()),
            Err(RecoveryError::CommitMismatch)
        ));
    }

    #[test]
    fn passphrase_path_round_trips() {
        let pass = b"correct horse battery staple plus";
        let rk = recovery_key_from_passphrase(&SALT, pass).unwrap();
        let blob = seal_recovery(&MK, GEN, PUBKEY, &rk, &SALT);
        let mk = recover_with_passphrase(&blob, pass, PUBKEY, GEN, &mk_commit()).unwrap();
        assert_eq!(mk.mk_commit(), mk_commit());
        // wrong passphrase → AEAD fails.
        assert!(matches!(
            recover_with_passphrase(
                &blob,
                b"wrong passphrase here xyz",
                PUBKEY,
                GEN,
                &mk_commit()
            ),
            Err(RecoveryError::Aead)
        ));
    }
}
