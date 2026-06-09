//! Robustness: `open` must **never panic** on arbitrary `(key, ad, tag, ciphertext)` — it must
//! return `Err(AeadError)` for anything that is not a genuine sealing. Stable-Rust stand-in for
//! libFuzzer coverage of the AEAD open path.

use proptest::prelude::*;
use secsec_aead::open;

proptest! {
    #[test]
    fn open_never_panics(
        key: [u8; 32],
        tag: [u8; 32],
        ad in proptest::collection::vec(any::<u8>(), 0..128),
        ct in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        // Random tag over random ciphertext: must reject, never panic.
        let _ = open(&key, &ad, &tag, &ct);
    }
}
