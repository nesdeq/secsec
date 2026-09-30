//! Robustness: `open` never panics on arbitrary `(key, ad, tag, ciphertext)`, only rejects.

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
        let _ = open(&key, &ad, &tag, &ct);
    }
}
