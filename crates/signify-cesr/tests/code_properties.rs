//! Property and invalid-near-miss coverage for CESR derivation codes.

use proptest::prelude::*;
use signify_cesr::code::DerivationCode;

fn derivation_code() -> impl Strategy<Value = DerivationCode> {
    proptest::sample::select(DerivationCode::ALL.to_vec())
}

proptest! {
    #[test]
    fn every_table_code_round_trips(code in derivation_code()) {
        prop_assert_eq!(code.as_str().parse::<DerivationCode>(), Ok(code));
    }

    #[test]
    fn valid_codes_with_an_extra_character_are_rejected(code in derivation_code()) {
        let near_miss = format!("{}A", code.as_str());
        prop_assert!(near_miss.parse::<DerivationCode>().is_err());
    }

    #[test]
    fn arbitrary_short_text_never_constructs_an_unlisted_code(input in ".{0,8}") {
        if let Ok(parsed) = input.parse::<DerivationCode>() {
            prop_assert!(DerivationCode::ALL.contains(&parsed));
            prop_assert_eq!(parsed.as_str(), input);
        }
    }
}
