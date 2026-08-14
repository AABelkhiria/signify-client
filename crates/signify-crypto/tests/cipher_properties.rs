//! Property and invalid-near-miss coverage for CESR-qualified ciphertext.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_crypto::{
    CryptoError,
    cipher::{Ciphertext, CiphertextKind, SALT_CIPHERTEXT_RAW_SIZE, SEED_CIPHERTEXT_RAW_SIZE},
};

fn cipher_value<T>(result: Result<T, CryptoError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn arbitrary_seed_ciphertext_round_trips(
        raw in proptest::collection::vec(any::<u8>(), SEED_CIPHERTEXT_RAW_SIZE),
    ) {
        let ciphertext = cipher_value(Ciphertext::from_raw(CiphertextKind::QualifiedSeed, &raw))?;
        let qb64 = cipher_value(ciphertext.qb64())?;
        let qb2 = cipher_value(ciphertext.qb2())?;
        prop_assert_eq!(ciphertext.raw(), raw.as_slice());
        prop_assert_eq!(qb64.len(), 124);
        prop_assert_eq!(qb2.len(), 93);
        prop_assert_eq!(cipher_value(Ciphertext::from_qb64(&qb64))?, ciphertext.clone());
        prop_assert_eq!(cipher_value(Ciphertext::from_qb2(&qb2))?, ciphertext.clone());
        prop_assert_eq!(cipher_value(Ciphertext::infer_from_raw(&raw))?, ciphertext);
    }

    #[test]
    fn arbitrary_salt_ciphertext_round_trips(
        raw in proptest::collection::vec(any::<u8>(), SALT_CIPHERTEXT_RAW_SIZE),
    ) {
        let ciphertext = cipher_value(Ciphertext::from_raw(CiphertextKind::QualifiedSalt, &raw))?;
        let qb64 = cipher_value(ciphertext.qb64())?;
        let qb2 = cipher_value(ciphertext.qb2())?;
        prop_assert_eq!(ciphertext.raw(), raw.as_slice());
        prop_assert_eq!(qb64.len(), 100);
        prop_assert_eq!(qb2.len(), 75);
        prop_assert_eq!(cipher_value(Ciphertext::from_qb64(&qb64))?, ciphertext.clone());
        prop_assert_eq!(cipher_value(Ciphertext::from_qb2(&qb2))?, ciphertext.clone());
        prop_assert_eq!(cipher_value(Ciphertext::infer_from_raw(&raw))?, ciphertext);
    }

    #[test]
    fn qb64_stream_parser_preserves_suffix_and_strict_parser_rejects_it(
        raw in proptest::collection::vec(any::<u8>(), SALT_CIPHERTEXT_RAW_SIZE),
        suffix in "[A-Za-z0-9_-]{1,64}",
    ) {
        let ciphertext = cipher_value(Ciphertext::from_raw(CiphertextKind::QualifiedSalt, &raw))?;
        let qb64 = cipher_value(ciphertext.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = cipher_value(Ciphertext::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.ciphertext(), &ciphertext);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        prop_assert!(Ciphertext::from_qb64(&stream).is_err());
    }

    #[test]
    fn invalid_near_miss_raw_lengths_are_rejected(
        raw in proptest::collection::vec(any::<u8>(), 0..128)
            .prop_filter("exclude supported ciphertext widths", |raw| {
                !matches!(raw.len(), SALT_CIPHERTEXT_RAW_SIZE | SEED_CIPHERTEXT_RAW_SIZE)
            }),
    ) {
        let actual = match Ciphertext::infer_from_raw(&raw) {
            Err(CryptoError::InvalidCiphertextLength { actual }) => actual,
            other => return Err(TestCaseError::fail(format!("unexpected inference result: {other:?}"))),
        };
        prop_assert_eq!(actual, raw.len());
    }
}
