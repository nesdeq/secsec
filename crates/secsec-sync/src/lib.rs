//! `secsec-sync` — the sync plane (`secsec-Design.md` §10). This module: the **Head**, the per-ref
//! mutable pointer at `/refs/<H>` — **signed** (`NS_HEAD`, §9.6) and **encrypted** (§9.8
//! fresh-nonce AEAD under `head_key_g`, AD = `FRAME ‖ H`), with `H = keyed_hash(ref_name_key,
//! ref_name)` hiding the ref name (§13). Head rollback/replay is caught by the §8.5 frontier, not
//! the AEAD. Submodules: [`dag`] (ancestry), [`merge`] (three-way merge), [`rollback`] (merge
//! gates + fork detection). Orchestration lives in `secsec-client`.

#![forbid(unsafe_code)]

pub mod dag;
pub mod merge;
pub mod rollback;

use secsec_canon::{verify_reencode, CanonError, Reader, Writer};
use secsec_frame::{Frame, FrameError, ObjType, FRAME_LEN, MAX_BLOB_SIZE};
use secsec_kdf::{MasterKey, MasterKeys};
use secsec_sig::{DeviceKey, DevicePublic, NS_HEAD};

/// A 256-bit content address (commit / prev-head id).
pub type Id = [u8; 32];

/// The keyed-hash ref-name path component `H` (§13).
pub type RefHash = [u8; 32];

/// Head-blob AEAD nonce length (§9.8): 96-bit.
pub const HEAD_NONCE_LEN: usize = 12;
/// Poly1305 tag length stored in the head blob (§9.8).
pub(crate) const HEAD_TAG_LEN: usize = 16;
/// Maximum ref-name length, in bytes (decoder bound).
pub(crate) const MAX_REF_NAME: usize = 4096;
/// Maximum stored head-signature length, in bytes (decoder bound; an SSHSIG PEM is far smaller).
pub(crate) const MAX_HEAD_SIG: usize = 4096;

/// The sentinel `prev_head` for a ref's first head (no predecessor).
pub const NO_PREV_HEAD: Id = [0u8; 32];

/// A per-ref head pointer (§6). The signature over its [`Head::signed_message`] is carried
/// alongside it (inside the encrypted blob); this struct is the plaintext payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The ref name (e.g. `"main"`). Hidden from the server via [`ref_hash`].
    pub ref_name: String,
    /// The commit this head points at.
    pub commit_id: Id,
    /// Per-ref strictly-increasing version (§8.5); the anti-rollback counter for this ref.
    pub head_version: u64,
    /// The roster sequence this head was written under (§8.5).
    pub roster_seq: u64,
    /// The previous head's id, or [`NO_PREV_HEAD`] for the first.
    pub prev_head: Id,
}

/// Errors from the head layer.
#[derive(Debug)]
pub enum HeadError {
    /// Blob exceeded the §19 maximum object size, or was too short for FRAME+nonce+tag.
    BadBlobSize,
    /// FRAME malformed or did not match the expected `(gen, type=Head)` (§18).
    Frame(FrameError),
    /// The §9.8 AEAD failed to open (wrong key/generation/ref, or tampered blob).
    Aead,
    /// The head's authenticated `FRAME.gen` had no master key in the resolver — the caller lacks that
    /// generation's key (peel the §8.2 key history), or a newer device rotated past it. Refold + retry.
    UnknownGeneration(u32),
    /// Strict canonical decode failed (truncation, over-long field, trailing bytes, non-canonical).
    Canon(CanonError),
    /// A head field was not valid UTF-8 (ref name).
    NonUtf8,
    /// The decrypted head's ref name did not match the requested ref (§13 slot binding).
    RefMismatch,
    /// The head signature did not verify against the given key (§9.6).
    BadSignature,
    /// Signing/key error.
    Sig(secsec_sig::SigError),
}

impl core::fmt::Display for HeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HeadError::BadBlobSize => f.write_str("head blob size out of bounds"),
            HeadError::Frame(e) => write!(f, "frame: {e}"),
            HeadError::Aead => f.write_str("head AEAD open failed"),
            HeadError::UnknownGeneration(g) => {
                write!(
                    f,
                    "no master key for head generation {g} (peel §8.2 keyhist)"
                )
            }
            HeadError::Canon(e) => write!(f, "canon: {e}"),
            HeadError::NonUtf8 => f.write_str("non-UTF-8 ref name"),
            HeadError::RefMismatch => {
                f.write_str("decrypted head ref does not match requested ref")
            }
            HeadError::BadSignature => f.write_str("head signature invalid"),
            HeadError::Sig(e) => write!(f, "sig: {e}"),
        }
    }
}

impl std::error::Error for HeadError {}
impl From<FrameError> for HeadError {
    fn from(e: FrameError) -> Self {
        HeadError::Frame(e)
    }
}
impl From<CanonError> for HeadError {
    fn from(e: CanonError) -> Self {
        HeadError::Canon(e)
    }
}
impl From<secsec_sig::SigError> for HeadError {
    fn from(e: secsec_sig::SigError) -> Self {
        HeadError::Sig(e)
    }
}

/// `H = BLAKE3::keyed_hash(ref_name_key, ref_name)` (§13): the opaque storage-path component for a
/// ref, so the server never learns the ref name.
#[must_use]
pub fn ref_hash(ref_name_key: &[u8; 32], ref_name: &str) -> RefHash {
    let mut h = blake3::Hasher::new_keyed(ref_name_key);
    h.update(ref_name.as_bytes());
    *h.finalize().as_bytes()
}

impl Head {
    /// The §9.6 signed message: `ref ‖ commit_id ‖ head_version ‖ roster_seq ‖ prev_head`,
    /// canonically encoded (length-prefixed ref name, fixed-width remainder).
    #[must_use]
    pub(crate) fn signed_message(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(self.ref_name.as_bytes())
            .raw(&self.commit_id)
            .u64(self.head_version)
            .u64(self.roster_seq)
            .raw(&self.prev_head);
        w.finish()
    }
}

/// Sign a head under `NS_HEAD` (§9.6). The signature is stored inside the encrypted head blob and
/// verified against the roster on read.
pub fn sign_head(device: &DeviceKey, head: &Head) -> Result<Vec<u8>, HeadError> {
    Ok(device.sign(NS_HEAD, &head.signed_message())?)
}

/// Verify a head signature against `pubkey` (which the caller resolves from the folded roster).
pub fn verify_head(pubkey: &DevicePublic, head: &Head, sig: &[u8]) -> Result<(), HeadError> {
    pubkey
        .verify(NS_HEAD, &head.signed_message(), sig)
        .map_err(|_| HeadError::BadSignature)
}

/// Deterministic head identity: `BLAKE3` of the canonical signed content (§6) — chains heads via
/// `prev_head` (the stored blob is nonce-randomized, so it cannot serve as the id).
#[must_use]
pub fn head_id(head: &Head) -> Id {
    *blake3::hash(&head.signed_message()).as_bytes()
}

/// Build the next head for a ref (§10): version `+1`, `prev_head` = id of `prev` (or
/// [`NO_PREV_HEAD`]). The caller signs, seals, and CASes it (§12).
#[must_use]
pub fn build_head(
    ref_name: impl Into<String>,
    commit_id: Id,
    roster_seq: u64,
    prev: Option<&Head>,
) -> Head {
    Head {
        ref_name: ref_name.into(),
        commit_id,
        head_version: prev.map_or(1, |p| p.head_version + 1),
        roster_seq,
        prev_head: prev.map_or(NO_PREV_HEAD, head_id),
    }
}

/// The encrypted plaintext: the head fields followed by its signature, canonically encoded.
fn encode_head(head: &Head, sig: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(head.ref_name.as_bytes())
        .raw(&head.commit_id)
        .u64(head.head_version)
        .u64(head.roster_seq)
        .raw(&head.prev_head)
        .bytes(sig);
    w.finish()
}

fn read32(r: &mut Reader<'_>) -> Result<[u8; 32], CanonError> {
    let mut out = [0u8; 32];
    out.copy_from_slice(r.raw(32)?);
    Ok(out)
}

/// Strictly decode the head plaintext (inverse of [`encode_head`]) into `(head, sig)`, with the §9.3
/// re-encode malleability guard.
fn decode_head(bytes: &[u8]) -> Result<(Head, Vec<u8>), HeadError> {
    let mut r = Reader::new(bytes);
    let ref_name =
        String::from_utf8(r.bytes(MAX_REF_NAME)?.to_vec()).map_err(|_| HeadError::NonUtf8)?;
    let commit_id = read32(&mut r)?;
    let head_version = r.u64()?;
    let roster_seq = r.u64()?;
    let prev_head = read32(&mut r)?;
    let sig = r.bytes(MAX_HEAD_SIG)?.to_vec();
    r.finish()?;
    let head = Head {
        ref_name,
        commit_id,
        head_version,
        roster_seq,
        prev_head,
    };
    verify_reencode(bytes, &(head.clone(), sig.clone()), |(h, s)| {
        encode_head(h, s)
    })?;
    Ok((head, sig))
}

/// `AD_head = FRAME ‖ H` (§9.8): binds the ciphertext to its generation, the `Head` object type, and
/// its ref slot.
fn head_ad(frame: &Frame, ref_hash: &RefHash) -> [u8; FRAME_LEN + 32] {
    let mut ad = [0u8; FRAME_LEN + 32];
    ad[..FRAME_LEN].copy_from_slice(&frame.encode());
    ad[FRAME_LEN..].copy_from_slice(ref_hash);
    ad
}

/// Seal a signed head into its stored blob `FRAME ‖ nonce ‖ tag ‖ ct` (§9.8) under `mk`'s
/// `head_key_g`. `nonce` MUST be fresh per write ([`random_nonce`]).
#[must_use]
pub fn seal_head(
    mk: &MasterKey,
    ref_name_key: &[u8; 32],
    head: &Head,
    sig: &[u8],
    nonce: &[u8; HEAD_NONCE_LEN],
) -> Vec<u8> {
    let frame = Frame::v1(mk.generation(), ObjType::Head);
    let h = ref_hash(ref_name_key, &head.ref_name);
    let ad = head_ad(&frame, &h);
    let key = mk.head_key();
    let (tag, ct) = secsec_aead::seal_mut(&key, nonce, &ad, &encode_head(head, sig));

    let mut out = Vec::with_capacity(FRAME_LEN + HEAD_NONCE_LEN + HEAD_TAG_LEN + ct.len());
    out.extend_from_slice(&frame.encode());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    out
}

/// Open a stored head blob for `ref_name`: resolve its `FRAME.gen` against `keys` (peel across
/// rotations, §9.8), AEAD-open under that generation's `head_key_g`, strictly decode, and check the
/// decrypted ref name. Returns `(head, sig)`. The caller MUST still [`verify_head`] against the
/// roster and check the §8.5 frontier — this layer gives confidentiality + slot binding only.
pub fn open_head<K: MasterKeys>(
    keys: &K,
    ref_name_key: &[u8; 32],
    ref_name: &str,
    blob: &[u8],
) -> Result<(Head, Vec<u8>), HeadError> {
    if blob.len() > MAX_BLOB_SIZE || blob.len() < FRAME_LEN + HEAD_NONCE_LEN + HEAD_TAG_LEN {
        return Err(HeadError::BadBlobSize);
    }
    let frame = Frame::decode(&blob[..FRAME_LEN])?;
    let mk = keys
        .for_gen(frame.gen)
        .ok_or(HeadError::UnknownGeneration(frame.gen))?;
    if frame != Frame::v1(mk.generation(), ObjType::Head) {
        return Err(HeadError::Frame(FrameError::FrameMismatch));
    }
    let nonce: [u8; HEAD_NONCE_LEN] = blob[FRAME_LEN..FRAME_LEN + HEAD_NONCE_LEN]
        .try_into()
        .expect("slice is exactly HEAD_NONCE_LEN");
    let tag: [u8; HEAD_TAG_LEN] = blob
        [FRAME_LEN + HEAD_NONCE_LEN..FRAME_LEN + HEAD_NONCE_LEN + HEAD_TAG_LEN]
        .try_into()
        .expect("slice is exactly HEAD_TAG_LEN");
    let ct = &blob[FRAME_LEN + HEAD_NONCE_LEN + HEAD_TAG_LEN..];

    let h = ref_hash(ref_name_key, ref_name);
    let ad = head_ad(&frame, &h);
    let key = mk.head_key();
    let pt = secsec_aead::open_mut(&key, &nonce, &ad, &tag, ct).map_err(|_| HeadError::Aead)?;

    let (head, sig) = decode_head(&pt)?;
    if head.ref_name != ref_name {
        return Err(HeadError::RefMismatch);
    }
    Ok((head, sig))
}

/// A fresh 96-bit nonce for [`seal_head`] (OS CSPRNG). Each head write MUST use a new one (§9.8).
pub fn random_nonce() -> Result<[u8; HEAD_NONCE_LEN], HeadError> {
    let mut n = [0u8; HEAD_NONCE_LEN];
    getrandom::fill(&mut n).map_err(|_| HeadError::Aead)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn mk(gen: u32) -> MasterKey {
        MasterKey::new(gen, [0x11; 32])
    }

    fn rnk(m: &MasterKey) -> [u8; 32] {
        *m.ref_name_key()
    }

    fn sample_head() -> Head {
        Head {
            ref_name: "main".to_string(),
            commit_id: [0xC0; 32],
            head_version: 3,
            roster_seq: 5,
            prev_head: [0xB0; 32],
        }
    }

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Across a rotation the ref path must stay fixed (genesis-derived [`MasterKeys::ref_name_key`])
    /// and `open_head` must peel the key ring to read an older-generation head.
    #[test]
    fn head_survives_a_rotation_via_stable_path_and_peel() {
        // Independent key bytes per generation, as a real Rotate mints (mk(gen) above reuses bytes).
        let g1 = MasterKey::new(1, [0x11; 32]);
        let g2 = MasterKey::new(2, [0x22; 32]);
        let ring: BTreeMap<u32, MasterKey> = [
            (1u32, MasterKey::new(1, [0x11; 32])),
            (2u32, MasterKey::new(2, [0x22; 32])),
        ]
        .into_iter()
        .collect();

        // The per-generation key (the *bug*) moves the path; the stable key ring keeps it fixed.
        assert_ne!(
            ref_hash(&g1.ref_name_key(), "main"),
            ref_hash(&g2.ref_name_key(), "main"),
            "the per-generation ref key moves the path — must not be used for the ref slot"
        );
        assert_eq!(
            ref_hash(&MasterKeys::ref_name_key(&ring), "main"),
            ref_hash(&g1.ref_name_key(), "main"),
            "the stable ref key is the genesis generation's, independent of the current generation"
        );

        // Seal a head under gen 1 at the stable path.
        let dev = DeviceKey::generate().unwrap();
        let head = sample_head();
        let sig = sign_head(&dev, &head).unwrap();
        let rnk = MasterKeys::ref_name_key(&ring);
        let blob = seal_head(&g1, &rnk, &head, &sig, &[0x07; 12]);

        // A member at gen 2 holding the key ring peels back and reads the gen-1 head (the fix).
        let (got, _) = open_head(&ring, &rnk, "main", &blob).unwrap();
        assert_eq!(got, head);

        // A bare gen-2 key (no gen-1 in its resolver) genuinely cannot read it.
        assert!(matches!(
            open_head(&g2, &rnk, "main", &blob),
            Err(HeadError::UnknownGeneration(1))
        ));
    }

    #[test]
    fn sign_seal_open_verify_round_trip() {
        let m = mk(1);
        let rnk = rnk(&m);
        let dev = DeviceKey::generate().unwrap();
        let head = sample_head();
        let sig = sign_head(&dev, &head).unwrap();

        let blob = seal_head(&m, &rnk, &head, &sig, &[0x07; 12]);
        let (got, got_sig) = open_head(&m, &rnk, "main", &blob).unwrap();
        assert_eq!(got, head);
        assert_eq!(got_sig, sig);
        // signature verifies against the authoring device's public key.
        assert!(verify_head(&dev.public(), &got, &got_sig).is_ok());
    }

    #[test]
    fn blob_hides_plaintext_and_is_well_formed() {
        let m = mk(1);
        let rnk = rnk(&m);
        let dev = DeviceKey::generate().unwrap();
        let head = sample_head();
        let sig = sign_head(&dev, &head).unwrap();
        let blob = seal_head(&m, &rnk, &head, &sig, &[0x07; 12]);
        // FRAME ‖ nonce ‖ tag ‖ ct
        assert!(blob.len() > FRAME_LEN + HEAD_NONCE_LEN + HEAD_TAG_LEN);
        // the ref name "main" must not appear in the ciphertext region
        let ct = &blob[FRAME_LEN + HEAD_NONCE_LEN + HEAD_TAG_LEN..];
        assert!(!ct.windows(4).any(|w| w == b"main"));
    }

    #[test]
    fn fresh_nonce_changes_blob_both_open() {
        let m = mk(1);
        let rnk = rnk(&m);
        let dev = DeviceKey::generate().unwrap();
        let head = sample_head();
        let sig = sign_head(&dev, &head).unwrap();
        let b1 = seal_head(&m, &rnk, &head, &sig, &[1u8; 12]);
        let b2 = seal_head(&m, &rnk, &head, &sig, &[2u8; 12]);
        assert_ne!(b1, b2, "a fresh nonce must change the blob");
        assert_eq!(open_head(&m, &rnk, "main", &b1).unwrap().0, head);
        assert_eq!(open_head(&m, &rnk, "main", &b2).unwrap().0, head);
    }

    #[test]
    fn open_rejects_tamper_wrong_ref_and_gen() {
        let m = mk(1);
        let rnk = rnk(&m);
        let dev = DeviceKey::generate().unwrap();
        let head = sample_head();
        let sig = sign_head(&dev, &head).unwrap();
        let blob = seal_head(&m, &rnk, &head, &sig, &[0x07; 12]);

        // tamper the last ciphertext byte
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            open_head(&m, &rnk, "main", &bad),
            Err(HeadError::Aead)
        ));

        // wrong ref name -> different H in the AD -> AEAD open fails
        assert!(matches!(
            open_head(&m, &rnk, "other", &blob),
            Err(HeadError::Aead)
        ));

        // a resolver that lacks the head's generation cannot open it (no key to peel to) — the head
        // was written under gen 1, and a bare gen-2 key holds no gen-1 key.
        let m2 = mk(2);
        assert!(matches!(
            open_head(&m2, &rnk, "main", &blob),
            Err(HeadError::UnknownGeneration(1))
        ));

        // too-short blob
        assert!(matches!(
            open_head(&m, &rnk, "main", &blob[..FRAME_LEN + 4]),
            Err(HeadError::BadBlobSize)
        ));
    }

    #[test]
    fn forged_head_by_non_member_fails_verify() {
        let dev = DeviceKey::generate().unwrap();
        let attacker = DeviceKey::generate().unwrap();
        let head = sample_head();
        let sig = sign_head(&dev, &head).unwrap();
        // a different key must not verify the head (authenticity rests on the signature, §9.8).
        assert!(matches!(
            verify_head(&attacker.public(), &head, &sig),
            Err(HeadError::BadSignature)
        ));
        // tampering a field after signing also fails.
        let mut tampered = head.clone();
        tampered.commit_id[0] ^= 0x01;
        assert!(matches!(
            verify_head(&dev.public(), &tampered, &sig),
            Err(HeadError::BadSignature)
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let head = sample_head();
        let bytes = encode_head(&head, b"sig-bytes");
        let mut extended = bytes.clone();
        extended.push(0x00);
        assert!(matches!(
            decode_head(&extended),
            Err(HeadError::Canon(CanonError::TrailingBytes { .. }))
        ));
        // and the clean bytes decode fine
        let (h, s) = decode_head(&bytes).unwrap();
        assert_eq!(h, head);
        assert_eq!(s, b"sig-bytes");
    }

    #[test]
    fn build_head_chains_and_addresses() {
        // first head: version 1, no predecessor.
        let h1 = build_head("main", [0xC1; 32], 4, None);
        assert_eq!(h1.head_version, 1);
        assert_eq!(h1.prev_head, NO_PREV_HEAD);

        // next head: version 2, prev_head = id(h1).
        let h2 = build_head("main", [0xC2; 32], 5, Some(&h1));
        assert_eq!(h2.head_version, 2);
        assert_eq!(h2.prev_head, head_id(&h1));

        // head_id is content-deterministic and distinguishes versions.
        assert_eq!(
            head_id(&h1),
            head_id(&build_head("main", [0xC1; 32], 4, None))
        );
        assert_ne!(head_id(&h1), head_id(&h2));
    }

    /// Frozen KATs, mirrored in `vectors/secsec-kat-v1.txt [head]` (fixed nonce + dummy sig pin the
    /// §9.8 wire format deterministically).
    #[test]
    fn head_kat() {
        let m = mk(1);
        let rnk = rnk(&m);
        assert_eq!(
            hx(&ref_hash(&rnk, "main")),
            "40d8bd93f870c83e494ff102e6604ee4e0d7683cc36da8e26eb24490d3e4cfa3"
        );
        let head = sample_head();
        let blob = seal_head(&m, &rnk, &head, b"dummy-sig", &[0x07; 12]);
        assert_eq!(
            hx(&blob),
            "737365630101010000000307070707070707070707070732606c8303716a667b303fd332a3e95f60a85422ed82a4d278642d1d35301852bf4992736077b620823945e522d418cf6d06d04a394f84084274abd6e7e4a3ab17594fff0cf359b5065e4d15ca901501023755da139ab87cf0f0bb0dac3c1397c683ba9c3d36eabbc92789c8d8075b9c7e0e5de5e0"
        );
        // round-trips with the dummy signature
        let (got, sig) = open_head(&m, &rnk, "main", &blob).unwrap();
        assert_eq!(got, head);
        assert_eq!(sig, b"dummy-sig");
    }
}
