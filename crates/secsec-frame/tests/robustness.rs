//! Robustness: `Frame::decode` and `parse_blob` must **never panic** on arbitrary input — only
//! return `Err`. Stable-Rust stand-in for libFuzzer coverage of the framing decoders.

use proptest::prelude::*;
use secsec_frame::{parse_blob, Frame, ObjType};

proptest! {
    #[test]
    fn decode_and_parse_never_panic(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let expected = Frame::v1(1, ObjType::Chunk);
        let _ = parse_blob(&data, &expected);
        let _ = Frame::decode(&data);
    }
}
