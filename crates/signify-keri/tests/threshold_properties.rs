//! Property and invalid-near-miss coverage for exact signing thresholds.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_keri::threshold::{RationalWeight, SigningThreshold, ThresholdError};

fn threshold_value<T>(result: Result<T, ThresholdError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn numeric_sith_json_and_limen_round_trip(value in any::<u128>()) {
        let threshold = SigningThreshold::numeric(value);
        let sith = threshold.canonical_sith();
        let json = threshold.canonical_json();
        let limen = threshold_value(threshold.limen())?
            .ok_or_else(|| TestCaseError::fail("numeric threshold omitted limen"))?;
        prop_assert_eq!(threshold_value(SigningThreshold::from_sith(&sith))?, threshold.clone());
        prop_assert_eq!(threshold_value(SigningThreshold::from_json(&json))?, threshold.clone());
        prop_assert_eq!(threshold_value(SigningThreshold::from_limen(&limen))?, threshold);
    }

    #[test]
    fn rational_weights_reduce_and_reparse(
        numerator in 0_u64..=1_000_000,
        denominator in 1_u64..=1_000_000,
    ) {
        let bounded_numerator = numerator.min(denominator);
        let weight = RationalWeight::new(u128::from(bounded_numerator), u128::from(denominator))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let reparsed = RationalWeight::parse(&weight.to_string())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(reparsed, weight);
        prop_assert!(weight.numerator() <= weight.denominator());
    }

    #[test]
    fn equal_weight_clause_satisfies_at_exact_boundary(
        denominator in 1_u8..=32,
        selected_seed in proptest::collection::vec(0_usize..32, 0..64),
    ) {
        let denominator_usize = usize::from(denominator);
        let weight = RationalWeight::new(1, u128::from(denominator))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let threshold = threshold_value(SigningThreshold::weighted(vec![
            vec![weight; denominator_usize],
        ]))?;

        let selected: Vec<usize> = selected_seed
            .into_iter()
            .map(|index| index % denominator_usize)
            .collect();
        let unique_count = (0..denominator_usize)
            .filter(|index| selected.contains(index))
            .count();
        prop_assert_eq!(
            threshold_value(threshold.is_satisfied_by(&selected))?,
            unique_count == denominator_usize,
        );
    }

    #[test]
    fn canonical_weighted_json_round_trips(
        left_numerator in 0_u8..=8,
        denominator in 1_u8..=8,
    ) {
        let bounded_left = left_numerator.min(denominator);
        let right = denominator - bounded_left;
        let left_weight = RationalWeight::new(u128::from(bounded_left), u128::from(denominator))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let right_weight = RationalWeight::new(u128::from(right), u128::from(denominator))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let threshold = threshold_value(SigningThreshold::weighted(vec![vec![left_weight, right_weight]]))?;
        let json = threshold.canonical_json();
        prop_assert_eq!(threshold_value(SigningThreshold::from_json(&json))?, threshold);
    }

    #[test]
    fn malformed_weight_suffixes_never_partially_parse(
        numerator in 0_u64..=1_000_000,
        denominator in 1_u64..=1_000_000,
        suffix in "[^0-9]{1,8}",
    ) {
        let bounded_numerator = numerator.min(denominator);
        let malformed = format!("{bounded_numerator}/{denominator}{suffix}");
        prop_assert!(RationalWeight::parse(&malformed).is_err());
    }
}
