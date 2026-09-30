//! The sync plane (`secsec-Design.md` §10): the signed and encrypted per-ref Head at `/refs/<H>` (§9.8, §13), plus [`dag`], [`merge`], [`rollback`].

#![forbid(unsafe_code)]

pub mod dag;
pub mod merge;
pub mod rollback;

use secsec_canon::{verify_reencode, CanonError, Reader, Writer};
use secsec_frame::{Frame, FrameError, ObjType, FRAME_LEN, MAX_BLOB_SIZE};
use secsec_kdf::{MasterKey, MasterKeys};
use secsec_sig::{DeviceKey, DevicePublic, MAX_SIG_LEN, NS_HEAD};

/// A 256-bit content address (commit / prev-head id).
pub type Id = [u8; 32];

/// The keyed-hash ref-name path component `H` (§13).
pub type RefHash = [u8; 32];

/// Head-blob AEAD nonce length (§9.8).
pub const HEAD_NONCE_LEN: usize = 12;
/// Poly1305 tag length stored in the head blob (§9.8).
pub(crate) const HEAD_TAG_LEN: usize = 16;
/// Maximum ref-name length, in bytes (decoder bound).
pub(crate) const MAX_REF_NAME: usize = 4096;

/// The `prev_head` of a ref's first head.
pub const NO_PREV_HEAD: Id = [0u8; 32];

/// A per-ref head pointer (§6); its signature travels beside it inside the encrypted blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The ref name (e.g. `"main"`), hidden from the server via [`ref_hash`].
    pub ref_name: String,
    /// The commit this head points at.
    pub commit_id: Id,
    /// Per-ref strictly-increasing version (§8.5).
    pub head_version: u64,
    /// The roster sequence this head was written under (§8.5).
    pub roster_seq: u64,
    /// The previous head's id, or [`NO_PREV_HEAD`].
    pub prev_head: Id,
}

/// Errors from the head layer.
#[derive(Debug)]
pub enum HeadError {
    /// Blob over the §19 cap or too short for FRAME+nonce+tag.
    BadBlobSize,
    /// FRAME malformed or not `(gen, Head)` (§18).
    Frame(FrameError),
    /// The §9.8 AEAD failed to open.
    Aead,
    /// No key for the head's `FRAME.gen`: peel the key history, or refold and retry.
    UnknownGeneration(u32),
    /// Strict canonical decode failed.
    Canon(CanonError),
    /// The ref name was not UTF-8.
    NonUtf8,
    /// The decrypted ref name did not match the requested ref (§13 slot binding).
    RefMismatch,
    /// The head signature did not verify (§9.6).
    BadSignature,
    /// `head_version` cannot advance past `u64::MAX`.
    VersionExhausted,
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
            HeadError::VersionExhausted => f.write_str("head_version exhausted"),
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

/// `H = BLAKE3::keyed_hash(ref_name_key, ref_name)` (§13).
#[must_use]
pub fn ref_hash(ref_name_key: &[u8; 32], ref_name: &str) -> RefHash {
    let mut h = blake3::Hasher::new_keyed(ref_name_key);
    h.update(ref_name.as_bytes());
    *h.finalize().as_bytes()
}

impl Head {
    /// The §9.6 signed message `ref ‖ commit_id ‖ head_version ‖ roster_seq ‖ prev_head`.
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

/// Sign a head under `NS_HEAD` (§9.6).
pub fn sign_head(device: &DeviceKey, head: &Head) -> Result<Vec<u8>, HeadError> {
    Ok(device.sign(NS_HEAD, &head.signed_message())?)
}

/// Verify a head signature against `pubkey`.
pub fn verify_head(pubkey: &DevicePublic, head: &Head, sig: &[u8]) -> Result<(), HeadError> {
    pubkey
        .verify(NS_HEAD, &head.signed_message(), sig)
        .map_err(|_| HeadError::BadSignature)
}

/// Deterministic head identity `BLAKE3(signed message)`, which `prev_head` chains on.
#[must_use]
pub fn head_id(head: &Head) -> Id {
    *blake3::hash(&head.signed_message()).as_bytes()
}

/// The next head for a ref: version `prev + 1` (checked), `prev_head = head_id(prev)`.
pub fn build_head(
    ref_name: impl Into<String>,
    commit_id: Id,
    roster_seq: u64,
    prev: Option<&Head>,
) -> Result<Head, HeadError> {
    let head_version = match prev {
        Some(p) => p
            .head_version
            .checked_add(1)
            .ok_or(HeadError::VersionExhausted)?,
        None => 1,
    };
    Ok(Head {
        ref_name: ref_name.into(),
        commit_id,
        head_version,
        roster_seq,
        prev_head: prev.map_or(NO_PREV_HEAD, head_id),
    })
}

/// The encrypted plaintext: head fields then its signature, canonically encoded.
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

/// Strictly decode the head plaintext into `(head, sig)`, with the §9.3 re-encode guard.
fn decode_head(bytes: &[u8]) -> Result<(Head, Vec<u8>), HeadError> {
    let mut r = Reader::new(bytes);
    let ref_name =
        String::from_utf8(r.bytes(MAX_REF_NAME)?.to_vec()).map_err(|_| HeadError::NonUtf8)?;
    let commit_id = read32(&mut r)?;
    let head_version = r.u64()?;
    let roster_seq = r.u64()?;
    let prev_head = read32(&mut r)?;
    let sig = r.bytes(MAX_SIG_LEN)?.to_vec();
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

/// `AD_head = FRAME ‖ H` (§9.8): binds generation, type, and ref slot.
fn head_ad(frame: &Frame, ref_hash: &RefHash) -> [u8; FRAME_LEN + 32] {
    let mut ad = [0u8; FRAME_LEN + 32];
    ad[..FRAME_LEN].copy_from_slice(&frame.encode());
    ad[FRAME_LEN..].copy_from_slice(ref_hash);
    ad
}

/// Seal a signed head as `FRAME ‖ nonce ‖ tag ‖ ct` under `mk`'s `head_key_g`; `nonce` MUST be fresh ([`random_nonce`]).
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
    let (tag, ct) = secsec_aead::seal_mut(
        &key,
        secsec_aead::FreshNonce::new(nonce),
        &ad,
        &encode_head(head, sig),
    );

    let mut out = Vec::with_capacity(FRAME_LEN + HEAD_NONCE_LEN + HEAD_TAG_LEN + ct.len());
    out.extend_from_slice(&frame.encode());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    out
}

/// Open a head blob for `ref_name` (confidentiality + slot binding only); callers still verify the signature and frontier.
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

/// A fresh 96-bit head nonce from the OS CSPRNG.
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

    /// Across a rotation the ref path stays fixed and `open_head` peels the key ring.
    #[test]
    fn head_survives_a_rotation_via_stable_path_and_peel() {
        let g1 = MasterKey::new(1, [0x11; 32]);
        let g2 = MasterKey::new(2, [0x22; 32]);
        let ring: BTreeMap<u32, MasterKey> = [
            (1u32, MasterKey::new(1, [0x11; 32])),
            (2u32, MasterKey::new(2, [0x22; 32])),
        ]
        .into_iter()
        .collect();

        assert_ne!(
            ref_hash(&g1.ref_name_key(), "main"),
            ref_hash(&g2.ref_name_key(), "main"),
            "a per-generation ref key would move the path"
        );
        assert_eq!(
            ref_hash(&MasterKeys::ref_name_key(&ring), "main"),
            ref_hash(&g1.ref_name_key(), "main"),
        );

        let dev = DeviceKey::generate().unwrap();
        let head = sample_head();
        let sig = sign_head(&dev, &head).unwrap();
        let rnk = MasterKeys::ref_name_key(&ring);
        let blob = seal_head(&g1, &rnk, &head, &sig, &[0x07; 12]);

        let (got, _) = open_head(&ring, &rnk, "main", &blob).unwrap();
        assert_eq!(got, head);
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
        assert!(verify_head(&dev.public(), &got, &got_sig).is_ok());
    }

    #[test]
    fn blob_hides_plaintext_and_fresh_nonce_changes_it() {
        let m = mk(1);
        let rnk = rnk(&m);
        let dev = DeviceKey::generate().unwrap();
        let head = sample_head();
        let sig = sign_head(&dev, &head).unwrap();
        let b1 = seal_head(&m, &rnk, &head, &sig, &[1u8; 12]);
        let b2 = seal_head(&m, &rnk, &head, &sig, &[2u8; 12]);
        let ct = &b1[FRAME_LEN + HEAD_NONCE_LEN + HEAD_TAG_LEN..];
        assert!(!ct.windows(4).any(|w| w == b"main"));
        assert_ne!(b1, b2);
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

        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            open_head(&m, &rnk, "main", &bad),
            Err(HeadError::Aead)
        ));
        assert!(matches!(
            open_head(&m, &rnk, "other", &blob),
            Err(HeadError::Aead)
        ));
        assert!(matches!(
            open_head(&mk(2), &rnk, "main", &blob),
            Err(HeadError::UnknownGeneration(1))
        ));
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
        assert!(matches!(
            verify_head(&attacker.public(), &head, &sig),
            Err(HeadError::BadSignature)
        ));
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
        let (h, s) = decode_head(&bytes).unwrap();
        assert_eq!(h, head);
        assert_eq!(s, b"sig-bytes");
    }

    #[test]
    fn build_head_chains_and_refuses_overflow() {
        let h1 = build_head("main", [0xC1; 32], 4, None).unwrap();
        assert_eq!(h1.head_version, 1);
        assert_eq!(h1.prev_head, NO_PREV_HEAD);
        let h2 = build_head("main", [0xC2; 32], 5, Some(&h1)).unwrap();
        assert_eq!(h2.head_version, 2);
        assert_eq!(h2.prev_head, head_id(&h1));
        assert_ne!(head_id(&h1), head_id(&h2));
        let top = Head {
            head_version: u64::MAX,
            ..h2
        };
        assert!(matches!(
            build_head("main", [0; 32], 0, Some(&top)),
            Err(HeadError::VersionExhausted)
        ));
    }

    /// Frozen KATs mirrored in `vectors/secsec-kat-v1.txt [head]`.
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
        let (got, sig) = open_head(&m, &rnk, "main", &blob).unwrap();
        assert_eq!(got, head);
        assert_eq!(sig, b"dummy-sig");
    }
}
