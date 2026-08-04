//! Property and invalid-near-miss coverage for fixed-width CESR sequence numbers.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::{
    CesrError,
    code::DerivationCode,
    matter::QualifiedMaterial,
    sequence::{SEQUENCE_RAW_SIZE, SequenceNumber},
};

fn test_value<T>(result: Result<T, CesrError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn every_u128_round_trips_in_all_sequence_domains(value in any::<u128>()) {
        let sequence = SequenceNumber::new(value);
        let raw = sequence.raw();
        let qb64 = test_value(sequence.qb64())?;
        let qb2 = test_value(sequence.qb2())?;
        prop_assert_eq!(raw.len(), SEQUENCE_RAW_SIZE);
        prop_assert_eq!(qb64.len(), 24);
        prop_assert_eq!(qb2.len(), 18);
        prop_assert_eq!(test_value(SequenceNumber::from_raw(&raw))?, sequence);
        prop_assert_eq!(test_value(SequenceNumber::from_qb64(&qb64))?, sequence);
        prop_assert_eq!(test_value(SequenceNumber::from_qb2(&qb2))?, sequence);
        prop_assert_eq!(test_value(SequenceNumber::from_hex(&sequence.hex()))?, sequence);
    }

    #[test]
    fn qb64_stream_parsing_preserves_arbitrary_suffix(
        value in any::<u128>(),
        suffix in "[A-Za-z0-9_-]{0,64}",
    ) {
        let sequence = SequenceNumber::new(value);
        let qb64 = test_value(sequence.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = test_value(SequenceNumber::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.sequence(), sequence);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        if suffix.is_empty() {
            prop_assert_eq!(test_value(SequenceNumber::from_qb64(&stream))?, sequence);
        } else {
            let rejected = matches!(
                SequenceNumber::from_qb64(&stream),
                Err(CesrError::TrailingMaterial { .. })
            );
            prop_assert!(rejected);
        }
    }

    #[test]
    fn raw_stream_parsing_preserves_arbitrary_suffix(
        value in any::<u128>(),
        suffix in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let sequence = SequenceNumber::new(value);
        let mut stream = sequence.raw().to_vec();
        stream.extend_from_slice(&suffix);
        let parsed = test_value(SequenceNumber::parse_raw_prefix(&stream))?;
        prop_assert_eq!(parsed.sequence(), sequence);
        prop_assert_eq!(parsed.consumed(), SEQUENCE_RAW_SIZE);
        if suffix.is_empty() {
            prop_assert_eq!(test_value(SequenceNumber::from_raw(&stream))?, sequence);
        } else {
            let rejected = matches!(
                SequenceNumber::from_raw(&stream),
                Err(CesrError::TrailingMaterial { .. })
            );
            prop_assert!(rejected);
        }
    }

    #[test]
    fn short_numeric_code_is_a_sequence_near_miss(value in any::<u16>()) {
        let raw = value.to_be_bytes();
        let material = test_value(QualifiedMaterial::new(DerivationCode::SHORT_NUMBER, &raw))?;
        let qb64 = test_value(material.qb64())?;
        let qb2 = test_value(material.qb2())?;
        let qb64_rejected = matches!(
            SequenceNumber::from_qb64(&qb64),
            Err(CesrError::InvalidSequenceCode { .. })
        );
        let qb2_rejected = matches!(
            SequenceNumber::from_qb2(&qb2),
            Err(CesrError::InvalidSequenceCode { .. })
        );
        prop_assert!(qb64_rejected);
        prop_assert!(qb2_rejected);
    }
}
