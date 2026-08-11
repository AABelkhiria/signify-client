//! Property and invalid-near-miss coverage for CESR-qualified digests.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_crypto::{
    CryptoError,
    digest::{DIGEST_RAW_SIZE, Digest, DigestAlgorithm},
};

fn digest_value<T>(result: Result<T, CryptoError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn arbitrary_serializations_derive_verify_and_round_trip(
        serialization in proptest::collection::vec(any::<u8>(), 0..16_384),
    ) {
        let digest = Digest::derive(DigestAlgorithm::Blake3_256, &serialization);
        let qb64 = digest_value(digest.qb64())?;
        let qb2 = digest_value(digest.qb2())?;
        prop_assert_eq!(digest.raw().len(), DIGEST_RAW_SIZE);
        prop_assert_eq!(qb64.len(), 44);
        prop_assert_eq!(qb2.len(), 33);
        prop_assert!(digest.verify(&serialization));
        prop_assert_eq!(digest_value(Digest::from_raw(digest.algorithm(), digest.raw()))?, digest);
        prop_assert_eq!(digest_value(Digest::from_qb64(&qb64))?, digest);
        prop_assert_eq!(digest_value(Digest::from_qb2(&qb2))?, digest);
    }

    #[test]
    fn arbitrary_raw_values_round_trip_canonically(raw in any::<[u8; DIGEST_RAW_SIZE]>()) {
        let digest = digest_value(Digest::from_raw(DigestAlgorithm::Blake3_256, &raw))?;
        let qb64 = digest_value(digest.qb64())?;
        let qb2 = digest_value(digest.qb2())?;
        prop_assert_eq!(digest.raw(), &raw);
        prop_assert_eq!(digest_value(Digest::from_qb64(&qb64))?, digest);
        prop_assert_eq!(digest_value(Digest::from_qb2(&qb2))?, digest);
    }

    #[test]
    fn qb64_stream_parser_preserves_suffix_and_strict_parser_rejects_it(
        serialization in proptest::collection::vec(any::<u8>(), 0..4_096),
        suffix in "[A-Za-z0-9_-]{1,64}",
    ) {
        let digest = Digest::derive(DigestAlgorithm::Blake3_256, &serialization);
        let qb64 = digest_value(digest.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = digest_value(Digest::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.digest(), digest);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        prop_assert!(Digest::from_qb64(&stream).is_err());
    }

    #[test]
    fn changed_serialization_fails_verification(
        serialization in proptest::collection::vec(any::<u8>(), 0..16_384),
        suffix in any::<u8>(),
    ) {
        let digest = Digest::derive(DigestAlgorithm::Blake3_256, &serialization);
        let mut changed = serialization;
        changed.push(suffix);
        prop_assert!(!digest.verify(&changed));
    }
}
