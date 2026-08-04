//! Property and invalid-near-miss coverage for CESR Base64-text material.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::{CesrError, bexter::Base64Text};

fn test_value<T>(result: Result<T, CesrError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn text_without_ambiguous_leading_a_round_trips_exactly(
        text in "([B-Zb-z0-9_-][A-Za-z0-9_-]{0,4095})?",
    ) {
        let value = test_value(Base64Text::new(&text))?;
        prop_assert_eq!(test_value(value.text())?, text);
        let qb64 = test_value(value.qb64())?;
        let qb2 = test_value(value.qb2())?;
        prop_assert_eq!(&test_value(Base64Text::from_qb64(&qb64))?, &value);
        prop_assert_eq!(&test_value(Base64Text::from_qb2(&qb2))?, &value);
    }

    #[test]
    fn arbitrary_valid_text_canonicalizes_idempotently(text in "[A-Za-z0-9_-]{0,4096}") {
        let value = test_value(Base64Text::new(&text))?;
        let canonical = test_value(value.text())?;
        let rebuilt = test_value(Base64Text::new(&canonical))?;
        prop_assert_eq!(&rebuilt, &value);
        prop_assert_eq!(test_value(rebuilt.text())?, canonical);
    }

    #[test]
    fn valid_qb64_streams_preserve_suffix(
        text in "[A-Za-z0-9_-]{0,1024}",
        suffix in "[A-Za-z0-9_-]{0,64}",
    ) {
        let value = test_value(Base64Text::new(&text))?;
        let qb64 = test_value(value.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = test_value(Base64Text::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.value(), &value);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        if suffix.is_empty() {
            prop_assert_eq!(test_value(Base64Text::from_qb64(&stream))?, value);
        } else {
            let rejected = matches!(
                Base64Text::from_qb64(&stream),
                Err(CesrError::TrailingMaterial { .. })
            );
            prop_assert!(rejected);
        }
    }

    #[test]
    fn one_invalid_byte_is_never_silently_normalized(
        prefix in "[A-Za-z0-9_-]{0,128}",
        suffix in "[A-Za-z0-9_-]{0,128}",
        invalid in prop::sample::select(vec!['+', '/', '=', ' ', '.', '~']),
    ) {
        let input = format!("{prefix}{invalid}{suffix}");
        let rejected = matches!(
            Base64Text::new(&input),
            Err(CesrError::InvalidBase64Character { .. })
        );
        prop_assert!(rejected);
    }
}
