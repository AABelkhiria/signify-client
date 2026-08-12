//! Property and invalid-near-miss coverage for CESR unindexed signatures.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_crypto::{
    CryptoError,
    signature::{SignatureAlgorithm, UnindexedSignature},
};

fn algorithm() -> impl Strategy<Value = SignatureAlgorithm> {
    prop_oneof![
        Just(SignatureAlgorithm::Ed25519),
        Just(SignatureAlgorithm::EcdsaSecp256k1),
        Just(SignatureAlgorithm::EcdsaP256),
    ]
}

fn value<T>(result: Result<T, CryptoError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn every_signature_kind_round_trips_canonically(
        algorithm in algorithm(),
        raw in any::<[u8; 64]>(),
    ) {
        let signature = value(UnindexedSignature::from_raw(algorithm, &raw))?;
        let qb64 = value(signature.qb64())?;
        let qb64_bytes = value(signature.qb64_bytes())?;
        let qb2 = value(signature.qb2())?;
        prop_assert_eq!(signature.algorithm(), algorithm);
        prop_assert_eq!(signature.raw(), &raw);
        prop_assert_eq!(value(UnindexedSignature::from_qb64(&qb64))?, signature.clone());
        prop_assert_eq!(value(UnindexedSignature::from_qb64_bytes(&qb64_bytes))?, signature.clone());
        prop_assert_eq!(value(UnindexedSignature::from_qb2(&qb2))?, signature);
    }

    #[test]
    fn stream_parser_preserves_arbitrary_qb64_suffix(
        algorithm in algorithm(),
        raw in any::<[u8; 64]>(),
        suffix in "[A-Za-z0-9_-]{1,64}",
    ) {
        let signature = value(UnindexedSignature::from_raw(algorithm, &raw))?;
        let qb64 = value(signature.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = value(UnindexedSignature::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.signature(), &signature);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        prop_assert!(UnindexedSignature::from_qb64(&stream).is_err());
    }

    #[test]
    fn every_wrong_raw_width_is_rejected(
        algorithm in algorithm(),
        length in 0_usize..129,
    ) {
        prop_assume!(length != 64);
        let raw = vec![0_u8; length];
        prop_assert!(UnindexedSignature::from_raw(algorithm, &raw).is_err());
    }

    #[test]
    fn changing_any_raw_byte_changes_canonical_encoding(
        algorithm in algorithm(),
        raw in any::<[u8; 64]>(),
        changed_index in 0_usize..64,
        delta in 1_u8..=u8::MAX,
    ) {
        let original = value(UnindexedSignature::from_raw(algorithm, &raw))?;
        let mut changed = raw;
        let byte = changed
            .get_mut(changed_index)
            .ok_or_else(|| TestCaseError::fail("generated signature index was out of range"))?;
        *byte ^= delta;
        let changed = value(UnindexedSignature::from_raw(algorithm, &changed))?;
        prop_assert_ne!(value(original.qb64())?, value(changed.qb64())?);
    }
}
