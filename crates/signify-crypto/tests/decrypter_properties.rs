//! Property and misuse coverage for X25519 sealed-box decryption.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::{code::DerivationCode, matter::QualifiedMaterial};
use signify_crypto::{
    CryptoError,
    cipher::{Ciphertext, CiphertextKind, Decrypter, Encrypter, X25519_PRIVATE_KEY_SIZE},
    salt::{Salt, SecurityTier},
    signer::Signer,
    verifier::KeyTransferability,
};

fn crypto_value<T>(result: Result<T, CryptoError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn transferability_strategy() -> impl Strategy<Value = KeyTransferability> {
    prop_oneof![
        Just(KeyTransferability::Transferable),
        Just(KeyTransferability::NonTransferable),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn every_encrypted_seed_round_trips_through_its_recipient(
        recipient_seed in any::<[u8; 32]>(),
        wrapped_seed in any::<[u8; 32]>(),
        transferability in transferability_strategy(),
    ) {
        let recipient = crypto_value(Signer::from_seed(&recipient_seed, KeyTransferability::Transferable))?;
        let encrypter = crypto_value(Encrypter::from_verification_key(recipient.verifier()))?;
        let decrypter = Decrypter::from_signer(&recipient);

        let qualified = crypto_value(
            QualifiedMaterial::new(DerivationCode::ED25519_SEED, &wrapped_seed).map_err(CryptoError::from),
        )?;
        let seed_qb64 = crypto_value(qualified.qb64_bytes().map_err(CryptoError::from))?;
        let ciphertext = crypto_value(encrypter.encrypt_seed_qb64(&seed_qb64))?;
        prop_assert_eq!(ciphertext.kind(), CiphertextKind::QualifiedSeed);

        let recovered = crypto_value(decrypter.decrypt_seed(&ciphertext, transferability))?;
        let expected = crypto_value(Signer::from_seed(&wrapped_seed, transferability))?;
        prop_assert_eq!(
            crypto_value(recovered.verifier().qb64())?,
            crypto_value(expected.verifier().qb64())?
        );
        prop_assert_eq!(recovered.transferability(), transferability);
    }

    #[test]
    fn every_encrypted_salt_round_trips_through_its_recipient(
        recipient_seed in any::<[u8; 32]>(),
        salt_raw in any::<[u8; 16]>(),
    ) {
        let recipient = crypto_value(Signer::from_seed(&recipient_seed, KeyTransferability::Transferable))?;
        let encrypter = crypto_value(Encrypter::from_verification_key(recipient.verifier()))?;
        let decrypter = Decrypter::from_signer(&recipient);

        let salt = crypto_value(Salt::from_raw(&salt_raw, SecurityTier::Low))?;
        let ciphertext = crypto_value(encrypter.encrypt_salt(&salt))?;
        prop_assert_eq!(ciphertext.kind(), CiphertextKind::QualifiedSalt);

        let recovered = crypto_value(decrypter.decrypt_salt(&ciphertext, SecurityTier::Low))?;
        let recovered_qb64 = crypto_value(recovered.expose_qb64())?;
        let expected_qb64 = crypto_value(salt.expose_qb64())?;
        prop_assert_eq!(recovered_qb64.as_str(), expected_qb64.as_str());
        prop_assert_eq!(recovered.tier(), SecurityTier::Low);
    }

    #[test]
    fn decrypter_material_round_trips_across_all_encodings(
        private in any::<[u8; 32]>(),
    ) {
        let decrypter = crypto_value(Decrypter::from_raw(&private))?;
        let qb64 = crypto_value(decrypter.expose_qb64())?;
        prop_assert_eq!(qb64.len(), 44);
        prop_assert!(qb64.starts_with('O'));

        let from_qb64 = crypto_value(Decrypter::from_qb64(&qb64))?;
        let from_qb64_text = crypto_value(from_qb64.expose_qb64())?;
        prop_assert_eq!(from_qb64_text.as_str(), qb64.as_str());

        let qb64_bytes = crypto_value(decrypter.expose_qb64_bytes())?;
        let from_bytes = crypto_value(Decrypter::from_qb64_bytes(qb64_bytes.as_ref()))?;
        let from_bytes_text = crypto_value(from_bytes.expose_qb64())?;
        prop_assert_eq!(from_bytes_text.as_str(), qb64.as_str());

        let qb2 = crypto_value(decrypter.expose_qb2())?;
        let from_qb2 = crypto_value(Decrypter::from_qb2(qb2.as_ref()))?;
        let from_qb2_text = crypto_value(from_qb2.expose_qb64())?;
        prop_assert_eq!(from_qb2_text.as_str(), qb64.as_str());

        let mut stream = qb64.as_bytes().to_vec();
        stream.extend_from_slice(b"XYZ");
        let parsed = crypto_value(Decrypter::parse_qb64_bytes(&stream))?;
        prop_assert_eq!(parsed.consumed(), qb64.len());
        prop_assert!(Decrypter::from_qb64_bytes(&stream).is_err());
    }

    #[test]
    fn tampering_any_ciphertext_byte_fails_decryption(
        recipient_seed in any::<[u8; 32]>(),
        salt_raw in any::<[u8; 16]>(),
        position in 0_usize..72,
        flip in 1_u8..=255,
    ) {
        let recipient = crypto_value(Signer::from_seed(&recipient_seed, KeyTransferability::Transferable))?;
        let encrypter = crypto_value(Encrypter::from_verification_key(recipient.verifier()))?;
        let decrypter = Decrypter::from_signer(&recipient);

        let salt = crypto_value(Salt::from_raw(&salt_raw, SecurityTier::Low))?;
        let ciphertext = crypto_value(encrypter.encrypt_salt(&salt))?;
        let mut tampered_raw = ciphertext.raw().to_vec();
        if let Some(byte) = tampered_raw.get_mut(position) {
            *byte ^= flip;
        }
        let tampered = crypto_value(Ciphertext::from_raw(CiphertextKind::QualifiedSalt, &tampered_raw))?;
        let tampered_fails = matches!(
            decrypter.decrypt_salt(&tampered, SecurityTier::Low),
            Err(CryptoError::DecryptionFailed { .. })
        );
        prop_assert!(tampered_fails);
    }

    #[test]
    fn wrong_recipients_and_wrong_kinds_always_fail(
        recipient_seed in any::<[u8; 32]>(),
        other_seed in any::<[u8; 32]>(),
        salt_raw in any::<[u8; 16]>(),
    ) {
        prop_assume!(recipient_seed != other_seed);
        let recipient = crypto_value(Signer::from_seed(&recipient_seed, KeyTransferability::Transferable))?;
        let stranger = crypto_value(Signer::from_seed(&other_seed, KeyTransferability::Transferable))?;
        let encrypter = crypto_value(Encrypter::from_verification_key(recipient.verifier()))?;
        let wrong_decrypter = Decrypter::from_signer(&stranger);
        let right_decrypter = Decrypter::from_signer(&recipient);

        let salt = crypto_value(Salt::from_raw(&salt_raw, SecurityTier::Low))?;
        let ciphertext = crypto_value(encrypter.encrypt_salt(&salt))?;
        let wrong_key_fails = matches!(
            wrong_decrypter.decrypt_salt(&ciphertext, SecurityTier::Low),
            Err(CryptoError::DecryptionFailed { .. })
        );
        prop_assert!(wrong_key_fails);
        let wrong_kind_fails = matches!(
            right_decrypter.decrypt_seed(&ciphertext, KeyTransferability::Transferable),
            Err(CryptoError::CiphertextKindMismatch { .. })
        );
        prop_assert!(wrong_kind_fails);

        let truncated = recipient_seed
            .get(..X25519_PRIVATE_KEY_SIZE - 1)
            .ok_or_else(|| TestCaseError::fail("seed narrower than a private key"))?;
        let short_raw_fails = matches!(Decrypter::from_raw(truncated), Err(CryptoError::Cesr { .. }));
        prop_assert!(short_raw_fails);
    }
}
