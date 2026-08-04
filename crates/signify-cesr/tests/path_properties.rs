//! Property and invalid-near-miss coverage for CESR SAD paths.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::{
    CesrError,
    path::{PathComponent, SadPath},
};

fn test_value<T>(result: Result<T, CesrError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn component() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Za-z_][A-Za-z0-9_]{0,63}",
        (0_usize..1_000_000).prop_map(|value| value.to_string()),
    ]
}

proptest! {
    #[test]
    fn component_sequences_round_trip_in_every_domain(
        components in prop::collection::vec(component(), 0..32),
    ) {
        let path = test_value(SadPath::from_components(&components))?;
        let text = test_value(path.text())?;
        let qb64 = test_value(path.qb64())?;
        let qb2 = test_value(path.qb2())?;
        prop_assert!(text.starts_with('-'));
        prop_assert_eq!(path.components().len(), components.len());
        prop_assert_eq!(&test_value(SadPath::from_text(&text))?, &path);
        prop_assert_eq!(&test_value(SadPath::from_qb64(&qb64))?, &path);
        prop_assert_eq!(&test_value(SadPath::from_qb2(&qb2))?, &path);
    }

    #[test]
    fn anchoring_then_stripping_recovers_tail(
        root in prop::collection::vec(component(), 0..16),
        tail in prop::collection::vec(component(), 0..16),
    ) {
        let root = test_value(SadPath::from_components(&root))?;
        let tail = test_value(SadPath::from_components(&tail))?;
        let rooted = test_value(tail.root(&root))?;
        prop_assert!(rooted.starts_with(&root));
        prop_assert_eq!(test_value(rooted.strip(&root))?, tail);
    }

    #[test]
    fn valid_qb64_streams_preserve_suffix(
        components in prop::collection::vec(component(), 0..16),
        suffix in "[A-Za-z0-9_]{0,64}",
    ) {
        let path = test_value(SadPath::from_components(&components))?;
        let qb64 = test_value(path.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = test_value(SadPath::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.value(), &path);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        if suffix.is_empty() {
            prop_assert_eq!(test_value(SadPath::from_qb64(&stream))?, path);
        } else {
            let rejected = matches!(
                SadPath::from_qb64(&stream),
                Err(CesrError::TrailingMaterial { .. })
            );
            prop_assert!(rejected);
        }
    }

    #[test]
    fn invalid_component_near_misses_are_rejected(
        prefix in "[A-Za-z0-9_]{0,64}",
        suffix in "[A-Za-z0-9_]{0,64}",
        invalid in prop::sample::select(vec!['-', '+', '/', '=', ' ', '.', '~']),
    ) {
        let input = format!("{prefix}{invalid}{suffix}");
        prop_assert!(PathComponent::parse(&input).is_err());
    }
}
