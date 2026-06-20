//! Decoder fuzz harness (`secsec-Design.md` §3, §18): one `fuzz_*` entry per decoder that parses
//! **untrusted** bytes. Each MUST be total on arbitrary input — never panic, never OOM (§19
//! pre-allocation bounds). These are the bodies of the `cargo-fuzz` targets under `../../fuzz/`
//! (`cargo +nightly fuzz run <target>`) and are also exercised on stable by
//! [`tests::every_decoder_survives_arbitrary_input`], so CI checks robustness without the fuzz
//! toolchain.

#![forbid(unsafe_code)]

use secsec_frame::{Frame, ObjType};
use secsec_kdf::MasterKey;
use secsec_object::ZERO_SALT;

/// A fixed master key for the AEAD-gated decoders (`open_*`): fuzzing exercises the FRAME/length
/// parsing and the AEAD-reject path before any plaintext, so the key value is irrelevant.
fn key() -> MasterKey {
    MasterKey::new(1, [0x5c; 32])
}

/// `secsec-frame`: the FRAME header (`MAGIC ‖ version ‖ algo ‖ gen ‖ type`).
pub fn fuzz_frame(data: &[u8]) {
    let _ = Frame::decode(data);
}

/// `secsec-proto::wire`: every wire decoder (server-facing and client-facing untrusted bytes).
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

/// `secsec-roster`: the sigchain-entry plaintext decoder (post-AEAD, still untrusted structure).
pub fn fuzz_roster_entry(data: &[u8]) {
    let _ = secsec_roster::decode_entry(data);
}

/// `secsec-object`: the object blob opener (FRAME + ctx_tag + ciphertext, §9.2/§9.4). Fuzzes the
/// pre-AEAD parsing and the reject path under a fixed key.
pub fn fuzz_object(data: &[u8]) {
    let mk = key();
    for ty in [ObjType::Chunk, ObjType::Tree, ObjType::Commit] {
        let _ = secsec_object::open_object(&mk, ty, &ZERO_SALT, &[0u8; 32], data);
    }
}

/// `secsec-sync`: the head blob opener (§9.8 mutable AEAD: FRAME ‖ nonce ‖ tag ‖ ct).
pub fn fuzz_head(data: &[u8]) {
    let mk = key();
    let rnk = mk.ref_name_key();
    let _ = secsec_sync::open_head(&mk, &rnk, "main", data);
}

/// `secsec-snapshot`: the tree object's canonical decoder (post-AEAD plaintext).
pub fn fuzz_tree(data: &[u8]) {
    secsec_snapshot::__fuzz_decode_tree(data);
}

/// `secsec-snapshot`: the signed-commit object's canonical decoder.
pub fn fuzz_commit(data: &[u8]) {
    secsec_snapshot::__fuzz_decode_signed_commit(data);
}

/// A named decoder fuzz entry (its `cargo-fuzz` target name and harness function).
#[cfg(test)]
pub type Decoder = (&'static str, fn(&[u8]));

/// Every harness entry, by name, for the stable robustness test and to enumerate the cargo-fuzz set.
#[cfg(test)]
pub const DECODERS: &[Decoder] = &[
    ("frame", fuzz_frame),
    ("wire", fuzz_wire),
    ("roster_entry", fuzz_roster_entry),
    ("object", fuzz_object),
    ("head", fuzz_head),
    ("tree", fuzz_tree),
    ("commit", fuzz_commit),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic SplitMix64 — a fixed-seed PRNG for reproducible fuzz corpora (test infra only).
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

    #[test]
    fn every_decoder_survives_arbitrary_input() {
        // A broad corpus: empty, all-zeros / all-ones at many lengths, byte counters, length-prefix
        // edge cases (huge claimed lengths), pseudo-random of varied sizes, and single-byte mutations
        // of each. Every decoder must return without panic/OOM on ALL of these (§18). A panic here
        // fails the test (the harness catches it).
        let mut corpus: Vec<Vec<u8>> = Vec::new();
        corpus.push(Vec::new());
        for len in [1usize, 4, 11, 12, 16, 28, 33, 64, 96, 256, 4096] {
            corpus.push(vec![0u8; len]);
            corpus.push(vec![0xffu8; len]);
            corpus.push((0..len).map(|i| i as u8).collect());
            // a giant little-endian length prefix in the first 4 bytes, to probe alloc bounds.
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
        // single-byte mutations of a base random buffer.
        let base = rng.bytes(128);
        for i in 0..base.len() {
            let mut m = base.clone();
            m[i] ^= 0xff;
            corpus.push(m);
        }

        for (name, f) in DECODERS {
            for input in &corpus {
                // catch_unwind so the failure names which decoder panicked.
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(input)));
                assert!(
                    r.is_ok(),
                    "decoder `{name}` panicked on a {}-byte input",
                    input.len()
                );
            }
        }
    }
}
