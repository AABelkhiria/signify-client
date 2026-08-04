//! Property and invalid-near-miss coverage for CESR counters.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::{
    CesrError,
    counter::{Counter, CounterCode, CounterVersion},
};

fn counter_code() -> impl Strategy<Value = CounterCode> {
    proptest::sample::select(CounterCode::ALL.to_vec())
}

fn test_value<T>(result: Result<T, CesrError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn every_code_round_trips_canonically(code in counter_code(), candidate in any::<u32>()) {
        let modulus = code
            .maximum_count()
            .checked_add(1)
            .ok_or_else(|| TestCaseError::fail("counter modulus overflow"))?;
        let count = candidate % modulus;
        let counter = test_value(Counter::new(code, count))?;
        let qb64 = test_value(counter.qb64())?;
        let qb2 = test_value(counter.qb2())?;
        prop_assert_eq!(test_value(Counter::from_qb64(&qb64))?, counter);
        prop_assert_eq!(test_value(Counter::from_qb2(&qb2))?, counter);
        prop_assert_eq!(qb64.len(), code.size().full_size());
        prop_assert_eq!(qb2.len(), code.size().full_size() * 3 / 4);
    }

    #[test]
    fn stream_parsing_preserves_arbitrary_suffix(
        code in counter_code(),
        candidate in any::<u32>(),
        suffix in "[A-Za-z0-9_-]{0,64}",
    ) {
        let modulus = code
            .maximum_count()
            .checked_add(1)
            .ok_or_else(|| TestCaseError::fail("counter modulus overflow"))?;
        let counter = test_value(Counter::new(code, candidate % modulus))?;
        let qb64 = test_value(counter.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = test_value(Counter::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.counter(), counter);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        if suffix.is_empty() {
            prop_assert_eq!(test_value(Counter::from_qb64(&stream))?, counter);
        } else {
            let rejected = matches!(
                Counter::from_qb64(&stream),
                Err(CesrError::TrailingMaterial { .. })
            );
            prop_assert!(rejected);
        }
    }

    #[test]
    fn semantic_versions_round_trip(
        major in 0_u8..64,
        minor in 0_u8..64,
        patch in 0_u8..64,
    ) {
        let version = test_value(CounterVersion::new(major, minor, patch))?;
        let counter = test_value(Counter::protocol_stack(version))?;
        prop_assert_eq!(test_value(counter.protocol_version())?, Some(version));
        prop_assert_eq!(test_value(CounterVersion::from_packed_count(version.packed_count()))?, version);
        prop_assert_eq!(version.major(), major);
        prop_assert_eq!(version.minor(), minor);
        prop_assert_eq!(version.patch(), patch);
    }

    #[test]
    fn invalid_soft_digit_near_misses_are_rejected(count in 0_u32..4_096) {
        let counter = test_value(Counter::new(CounterCode::CONTROLLER_INDEXED_SIGNATURES, count))?;
        let mut malformed = test_value(counter.qb64())?.into_bytes();
        let digit = malformed
            .get_mut(2)
            .ok_or_else(|| TestCaseError::fail("missing counter soft digit"))?;
        *digit = b'!';
        let text = String::from_utf8(malformed)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let rejected = matches!(
            Counter::from_qb64(&text),
            Err(CesrError::InvalidBase64Character { .. })
        );
        prop_assert!(rejected);
    }
}
