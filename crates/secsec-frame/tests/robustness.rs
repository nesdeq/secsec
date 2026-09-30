//! Robustness: `Frame::decode` and `parse_blob` never panic on arbitrary input, only return `Err`.

use proptest::prelude::*;
use secsec_frame::{parse_blob, Frame, ObjType};

proptest! {
    #[test]
    fn decode_and_parse_never_panic(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = parse_blob(&data, &Frame::v1(1, ObjType::Chunk));
        let _ = parse_blob(&data, &Frame::v2(1, ObjType::RosterEntry));
        let _ = Frame::decode(&data);
    }
}
