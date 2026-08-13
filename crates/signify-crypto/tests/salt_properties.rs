//! Property tests for salt qualification and deterministic signer derivation.

use proptest::prelude::*;
use signify_crypto::{
    salt::{KeyDerivationProfile, MAX_DERIVATION_PATH_BYTES, Salt, SecurityTier},
    verifier::KeyTransferability,
};

fn tier(value: u8) -> SecurityTier {
    match value % 3 {
        0 => SecurityTier::Low,
        1 => SecurityTier::Medium,
        _ => SecurityTier::High,
    }
}

proptest! {
    #[test]
    fn every_raw_salt_round_trips_through_qb64_and_qb2(
        raw in any::<[u8; 16]>(),
        tier_selector in any::<u8>(),
    ) {
        let selected = tier(tier_selector);
        let salt = Salt::from_raw(&raw, selected)?;
        let qb64 = salt.expose_qb64()?;
        let qb64_bytes = salt.expose_qb64_bytes()?;
        let qb2 = salt.expose_qb2()?;
        prop_assert_eq!(qb64.len(), 24);
        let text_round_trip = Salt::from_qb64(&qb64, selected)?.expose_qb64()?;
        let bytes_round_trip = Salt::from_qb64_bytes(&qb64_bytes, selected)?.expose_qb64()?;
        let binary_round_trip = Salt::from_qb2(&qb2, selected)?.expose_qb64()?;
        prop_assert_eq!(text_round_trip.as_str(), qb64.as_str());
        prop_assert_eq!(bytes_round_trip.as_str(), qb64.as_str());
        prop_assert_eq!(binary_round_trip.as_str(), qb64.as_str());
    }

    #[test]
    fn strict_raw_constructor_accepts_only_sixteen_bytes(input in proptest::collection::vec(any::<u8>(), 0..=32)) {
        prop_assert_eq!(Salt::from_raw(&input, SecurityTier::Low).is_ok(), input.len() == 16);
    }

    #[test]
    fn temporary_derivation_is_deterministic(
        raw in any::<[u8; 16]>(),
        path in "[A-Za-z0-9:_/-]{0,64}",
        transferable in any::<bool>(),
    ) {
        let salt = Salt::from_raw(&raw, SecurityTier::Low)?;
        let transferability = if transferable {
            KeyTransferability::Transferable
        } else {
            KeyTransferability::NonTransferable
        };
        let first = salt.derive_signer_with_profile(
            &path,
            transferability,
            KeyDerivationProfile::Temporary,
        )?;
        let second = salt.derive_signer_with_profile(
            &path,
            transferability,
            KeyDerivationProfile::Temporary,
        )?;
        prop_assert_eq!(first.verifier(), second.verifier());
    }

    #[test]
    fn utf8_path_bound_is_measured_in_bytes(character_count in 1_usize..=2_048) {
        let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?;
        let path = "é".repeat(character_count);
        let result = salt.derive_signer_with_profile(
            &path,
            KeyTransferability::Transferable,
            KeyDerivationProfile::Temporary,
        );
        prop_assert_eq!(result.is_ok(), path.len() <= MAX_DERIVATION_PATH_BYTES);
    }
}
