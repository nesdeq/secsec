//! Fuzz harness bodies, one per decoder of untrusted bytes, each total on any input (`secsec-Design.md` §18, §19).

#![forbid(unsafe_code)]

use secsec_frame::{Frame, ObjType};
use secsec_kdf::MasterKey;
use secsec_object::ZERO_SALT;
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// A fixed key for the AEAD-gated openers: fuzzing reaches the parsing and the reject path, so its value is irrelevant.
fn key() -> MasterKey {
    MasterKey::new(1, [0x5c; 32])
}

/// The fixed X-Wing secret and its public key bytes, derived once so each input runs only the decoders under test.
static XWING: LazyLock<Option<(secsec_pq::XWingSecret, Vec<u8>)>> = LazyLock::new(|| {
    let (sk, pk) = secsec_pq::XWingSecret::from_seed([0x5c; 32]).ok()?;
    Some((sk, pk.to_bytes()))
});

/// `base` with `data` XORed over its prefix: an exact-length input the fuzzer steers past a length gate.
fn overlay(base: &[u8], data: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    v.iter_mut().zip(data).for_each(|(b, d)| *b ^= d);
    v
}

/// `secsec-frame`: the FRAME header and the blob splitters built on it.
pub fn fuzz_frame(data: &[u8]) {
    let _ = Frame::decode(data);
    let _ = secsec_frame::parse_blob(data, &Frame::v1(1, ObjType::Chunk));
    let _ = secsec_frame::parse_frame_prefix(data, &Frame::v2(1, ObjType::RosterEntry));
}

/// `secsec-proto::wire`: every message a server or client decodes off the network.
pub fn fuzz_wire(data: &[u8]) {
    use secsec_proto::wire::{
        AuthedRequest, ClientAuth, ClientHello, Request, Response, ServerHello,
    };
    let _ = Request::decode(data);
    let _ = Response::decode(data);
    let _ = ClientHello::decode(data);
    let _ = ServerHello::decode(data);
    let _ = ClientAuth::decode(data);
    let _ = AuthedRequest::decode(data);
}

/// `secsec-roster`: a stored entry blob (v1 and v2 FRAME parsing, AEAD reject) and the entry plaintext decoder.
pub fn fuzz_roster_entry(data: &[u8]) {
    let _ = secsec_roster::frame_gen(data);
    let _ = secsec_roster::open_entry(&key().roster_key(), 1, 0, data);
    let _ = secsec_roster::decode_entry(data);
}

/// `secsec-roster`: a key-history wrap as a peel reads it.
pub fn fuzz_keyhist(data: &[u8]) {
    let history = BTreeMap::from([(1u32, data.to_vec())]);
    let _ = secsec_roster::peel_data_keys(&[0x5c; 32], 2, &history, &BTreeMap::new());
}

/// `secsec-pq`: a published X-Wing public key and a keyslot body under a fixed secret, raw and at their exact lengths.
pub fn fuzz_keyslot(data: &[u8]) {
    let _ = secsec_pq::XWingPublic::from_bytes(data);
    if let Some((sk, pk)) = XWING.as_ref() {
        let _ = secsec_pq::XWingPublic::from_bytes(&overlay(pk, data));
        let _ = secsec_pq::unwrap_pq_raw(data, 1, &[0; 32], sk);
        let body = overlay(&[0; secsec_pq::KEYSLOT_BODY_LEN], data);
        let _ = secsec_pq::unwrap_pq_raw(&body, 1, &[0; 32], sk);
    }
}

/// `secsec-object`: the object opener (FRAME, tag, AEAD reject) for each content type.
pub fn fuzz_object(data: &[u8]) {
    let mk = key();
    for ty in [ObjType::Chunk, ObjType::Tree, ObjType::Commit] {
        let _ = secsec_object::open_object(&mk, ty, &ZERO_SALT, &[0u8; 32], data);
    }
}

/// `secsec-sync`: the head blob opener (§9.8: FRAME, nonce, tag, ciphertext).
pub fn fuzz_head(data: &[u8]) {
    let mk = key();
    let rnk = mk.ref_name_key();
    let _ = secsec_sync::open_head(&mk, &rnk, "main", data);
}

/// `secsec-sync`: the sealed-frontier opener and its plaintext decoder.
pub fn fuzz_frontier(data: &[u8]) {
    let _ = secsec_sync::rollback::open_frontier(&[0x5c; 32], &[0; 32], data);
    secsec_sync::rollback::__fuzz_decode_frontier(data);
}

/// `secsec-snapshot`: the tree decoder (post-AEAD plaintext).
pub fn fuzz_tree(data: &[u8]) {
    secsec_snapshot::__fuzz_decode_tree(data);
}

/// `secsec-snapshot`: the signed-commit decoder.
pub fn fuzz_commit(data: &[u8]) {
    secsec_snapshot::__fuzz_decode_signed_commit(data);
}

/// `secsec-client`: the two pairing-mailbox messages the server relays.
pub fn fuzz_pairing(data: &[u8]) {
    secsec_client::pair::__fuzz_parse(data);
}

/// A named harness entry: its `cargo-fuzz` target name and function.
#[cfg(test)]
pub type Decoder = (&'static str, fn(&[u8]));

/// Every harness entry by target name; `../../fuzz/Cargo.toml` lists the same set.
#[cfg(test)]
pub const DECODERS: &[Decoder] = &[
    ("frame", fuzz_frame),
    ("wire", fuzz_wire),
    ("roster_entry", fuzz_roster_entry),
    ("keyhist", fuzz_keyhist),
    ("keyslot", fuzz_keyslot),
    ("object", fuzz_object),
    ("head", fuzz_head),
    ("frontier", fuzz_frontier),
    ("tree", fuzz_tree),
    ("commit", fuzz_commit),
    ("pairing", fuzz_pairing),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// SplitMix64, a fixed-seed PRNG for a reproducible corpus.
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| (self.next() & 0xff) as u8).collect()
        }
    }

    /// Every decoder returns on a broad corpus: empty, constant, counting, huge length prefixes, random, single-byte flips.
    #[test]
    fn every_decoder_survives_arbitrary_input() {
        let mut corpus: Vec<Vec<u8>> = vec![Vec::new()];
        for len in [1usize, 4, 11, 12, 16, 28, 33, 64, 96, 256, 1216, 4096] {
            corpus.push(vec![0u8; len]);
            corpus.push(vec![0xffu8; len]);
            corpus.push((0..len).map(|i| i as u8).collect());
            let mut huge = vec![0xffu8; len];
            if len >= 4 {
                huge[..4].copy_from_slice(&u32::MAX.to_le_bytes());
            }
            corpus.push(huge);
        }
        let mut rng = SplitMix64(0x5EC5_EC00_F0F0_1234);
        for len in [0usize, 1, 8, 13, 32, 50, 100, 500, 2000, 20_000] {
            for _ in 0..64 {
                corpus.push(rng.bytes(len));
            }
        }
        let base = rng.bytes(128);
        for i in 0..base.len() {
            let mut m = base.clone();
            m[i] ^= 0xff;
            corpus.push(m);
        }
        for (name, f) in DECODERS {
            for input in &corpus {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(input)));
                assert!(
                    r.is_ok(),
                    "decoder `{name}` panicked on a {}-byte input",
                    input.len()
                );
            }
        }
    }

    /// The cargo-fuzz manifest builds exactly the targets this harness defines.
    #[test]
    fn fuzz_manifest_lists_every_target() {
        let manifest =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/Cargo.toml");
        let text = std::fs::read_to_string(manifest).expect("fuzz manifest");
        let listed: std::collections::BTreeSet<&str> = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("name = \""))
            .filter_map(|l| l.strip_suffix('"'))
            .filter(|n| *n != "secsec-fuzz-targets")
            .collect();
        let defined: std::collections::BTreeSet<&str> = DECODERS.iter().map(|(n, _)| *n).collect();
        assert_eq!(listed, defined);
    }
}
