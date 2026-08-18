//! Property and invalid-near-miss coverage for CESR-qualified ciphertext.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::{code::DerivationCode, matter::QualifiedMaterial};
use signify_crypto::{
    CryptoError,
    cipher::{
        Ciphertext, CiphertextKind, Encrypter, SALT_CIPHERTEXT_RAW_SIZE, SEED_CIPHERTEXT_RAW_SIZE,
        X25519_PUBLIC_KEY_SIZE,
    },
    salt::{Salt, SecurityTier},
    signer::Signer,
    verifier::KeyTransferability,
};

fn cipher_value<T>(result: Result<T, CryptoError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn arbitrary_ed25519_seed_converts_and_matches(
        seed in any::<[u8; 32]>(),
    ) {
        let signer = cipher_value(Signer::from_seed(&seed, KeyTransferability::Transferable))?;
        let encrypter = cipher_value(Encrypter::from_verification_key(signer.verifier()))?;
        let qualified_seed = cipher_value(
            QualifiedMaterial::new(DerivationCode::ED25519_SEED, &seed).map_err(CryptoError::from),
        )?;
        let seed_qb64 = cipher_value(qualified_seed.qb64_bytes().map_err(CryptoError::from))?;
        prop_assert!(cipher_value(encrypter.matches_seed_qb64(&seed_qb64))?);
        prop_assert_eq!(encrypter.raw().len(), X25519_PUBLIC_KEY_SIZE);
        prop_assert_eq!(cipher_value(Encrypter::from_qb64(&cipher_value(encrypter.qb64())?))?, encrypter.clone());
        prop_assert_eq!(cipher_value(Encrypter::from_qb2(&cipher_value(encrypter.qb2())?))?, encrypter);
    }

    #[test]
    fn arbitrary_valid_plaintexts_encrypt_to_exact_kinds_and_lengths(
        seed in any::<[u8; 32]>(),
        salt_raw in any::<[u8; 16]>(),
    ) {
        let recipient = cipher_value(Signer::from_seed(&[0x5a_u8; 32], KeyTransferability::Transferable))?;
        let encrypter = cipher_value(Encrypter::from_verification_key(recipient.verifier()))?;
        let seed_qb64 = cipher_value(
            QualifiedMaterial::new(DerivationCode::ED25519_SEED, &seed)
                .and_then(|material| material.qb64_bytes())
                .map_err(CryptoError::from),
        )?;
        let seed_ciphertext = cipher_value(encrypter.encrypt_seed_qb64(&seed_qb64))?;
        prop_assert_eq!(seed_ciphertext.kind(), CiphertextKind::QualifiedSeed);
        prop_assert_eq!(seed_ciphertext.raw().len(), SEED_CIPHERTEXT_RAW_SIZE);

        let salt = cipher_value(Salt::from_raw(&salt_raw, SecurityTier::Low))?;
        let salt_ciphertext = cipher_value(encrypter.encrypt_salt(&salt))?;
        prop_assert_eq!(salt_ciphertext.kind(), CiphertextKind::QualifiedSalt);
        prop_assert_eq!(salt_ciphertext.raw().len(), SALT_CIPHERTEXT_RAW_SIZE);
    }

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

    #[test]
    fn invalid_encrypter_raw_lengths_never_parse(
        raw in proptest::collection::vec(any::<u8>(), 0..96)
            .prop_filter("exclude the exact X25519 public-key width", |raw| {
                raw.len() != X25519_PUBLIC_KEY_SIZE
            }),
    ) {
        prop_assert!(Encrypter::from_raw(&raw).is_err());
    }
}
