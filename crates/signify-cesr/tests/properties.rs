//! Property and invalid-near-miss coverage for CESR foundation helpers.

use proptest::prelude::*;
use signify_cesr::{
    CesrError,
    base64::{decode_u64, decode_url_safe, encode_u64, encode_url_safe},
    bytes::{bytes_to_integer, integer_to_bytes},
};

proptest! {
    #[test]
    fn url_safe_base64_round_trips(raw in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = encode_url_safe(&raw);
        prop_assert_eq!(decode_url_safe(&encoded), Ok(raw));
    }

    #[test]
    fn integer_base64_round_trips(value in any::<u64>(), minimum_width in 1_u8..=11) {
        let encoded = encode_u64(value, minimum_width);
        prop_assert!(encoded.is_ok());
        if let Ok(encoded) = encoded {
            prop_assert_eq!(decode_u64(&encoded), Ok(value));
        }
    }

    #[test]
    fn sixteen_byte_integer_round_trips(value in any::<u128>()) {
        let encoded = integer_to_bytes(value, 16);
        prop_assert!(encoded.is_ok());
        if let Ok(encoded) = encoded {
            prop_assert_eq!(bytes_to_integer(&encoded), Ok(value));
        }
    }

    #[test]
    fn invalid_alphabet_near_misses_are_rejected(prefix in "[A-Za-z0-9_-]{0,64}") {
        let input = format!("{prefix}+");
        prop_assert!(matches!(
            decode_url_safe(&input),
            Err(CesrError::InvalidBase64Character { .. })
        ), "invalid URL-safe Base64 alphabet byte was accepted");
    }
}
