//! Property and invalid-near-miss coverage for exact CESR numbers.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::{
    CesrError, bytes::integer_to_bytes, code::DerivationCode, matter::QualifiedMaterial, number::CesrNumber,
};

fn test_value<T>(result: Result<T, CesrError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn every_u128_round_trips_in_both_qualified_domains(value in any::<u128>()) {
        let number = CesrNumber::new(value);
        let qb64 = test_value(number.qb64())?;
        let qb2 = test_value(number.qb2())?;
        prop_assert_eq!(test_value(CesrNumber::from_qb64(&qb64))?, number);
        prop_assert_eq!(test_value(CesrNumber::from_qb2(&qb2))?, number);
        prop_assert_eq!(test_value(CesrNumber::from_hex(&number.hex()))?, number);
        let full_size = number
            .code()
            .size()
            .full_size()
            .ok_or_else(|| TestCaseError::fail("numeric code has no fixed full size"))?;
        prop_assert_eq!(qb64.len(), full_size);
        prop_assert_eq!(qb2.len(), qb64.len() * 3 / 4);
    }

    #[test]
    fn stream_parsing_preserves_arbitrary_suffix(
        value in any::<u128>(),
        suffix in "[A-Za-z0-9_-]{0,64}",
    ) {
        let number = CesrNumber::new(value);
        let qb64 = test_value(number.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = test_value(CesrNumber::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.number(), number);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        if suffix.is_empty() {
            prop_assert_eq!(test_value(CesrNumber::from_qb64(&stream))?, number);
        } else {
            let rejected = matches!(
                CesrNumber::from_qb64(&stream),
                Err(CesrError::TrailingMaterial { .. })
            );
            prop_assert!(rejected);
        }
    }

    #[test]
    fn wider_code_near_misses_are_rejected(value in any::<u16>()) {
        let raw = test_value(integer_to_bytes(u128::from(value), 4))?;
        let material = test_value(QualifiedMaterial::new(DerivationCode::LONG_NUMBER, &raw))?;
        let qb64 = test_value(material.qb64())?;
        let qb2 = test_value(material.qb2())?;
        let qb64_rejected = matches!(
            CesrNumber::from_qb64(&qb64),
            Err(CesrError::NonCanonicalNumber { .. })
        );
        let qb2_rejected = matches!(
            CesrNumber::from_qb2(&qb2),
            Err(CesrError::NonCanonicalNumber { .. })
        );
        prop_assert!(qb64_rejected);
        prop_assert!(qb2_rejected);
    }

    #[test]
    fn complete_hex_parser_rejects_invalid_suffixes(value in any::<u64>()) {
        let malformed = format!("{value:x}g");
        let rejected = matches!(
            CesrNumber::from_hex(&malformed),
            Err(CesrError::InvalidHexCharacter { .. })
        );
        prop_assert!(rejected);
    }
}
