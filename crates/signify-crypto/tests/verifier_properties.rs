//! Property and invalid-near-miss coverage for CESR-qualified verification keys.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_crypto::{
    CryptoError,
    verifier::{KeyTransferability, VerificationAlgorithm, VerificationKey},
};

const MESSAGE: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const ED25519_RAW: [u8; 32] = [
    3, 161, 7, 191, 243, 206, 16, 190, 29, 112, 221, 24, 231, 75, 192, 153, 103, 228, 214, 48, 155, 165, 13, 95, 29,
    220, 134, 100, 18, 85, 49, 184,
];
const ED25519_SIGNATURE: [u8; 64] = [
    120, 221, 252, 244, 26, 66, 35, 232, 131, 66, 190, 174, 247, 217, 222, 197, 5, 156, 109, 220, 108, 52, 241, 45,
    102, 106, 79, 83, 121, 24, 18, 182, 202, 241, 137, 67, 196, 41, 195, 0, 63, 212, 165, 38, 187, 122, 178, 14, 97,
    218, 145, 47, 78, 200, 107, 99, 62, 122, 172, 207, 8, 35, 55, 14,
];
const P256_RAW: [u8; 33] = [
    3, 230, 229, 40, 20, 228, 78, 65, 4, 57, 127, 216, 171, 120, 183, 43, 22, 73, 189, 193, 218, 172, 247, 238, 253,
    202, 202, 87, 7, 31, 19, 11, 208,
];
const P256_SIGNATURE: [u8; 64] = [
    230, 114, 73, 144, 137, 97, 127, 30, 141, 40, 83, 123, 165, 18, 120, 1, 181, 58, 93, 215, 85, 94, 5, 20, 64, 8, 17,
    182, 30, 217, 77, 251, 86, 229, 180, 200, 13, 165, 96, 90, 147, 61, 229, 129, 189, 195, 185, 241, 16, 31, 60, 58,
    177, 254, 97, 129, 217, 85, 17, 120, 122, 77, 23, 205,
];

fn key_parameters() -> impl Strategy<Value = (VerificationAlgorithm, KeyTransferability)> {
    prop_oneof![
        Just((VerificationAlgorithm::Ed25519, KeyTransferability::NonTransferable)),
        Just((VerificationAlgorithm::Ed25519, KeyTransferability::Transferable)),
        Just((VerificationAlgorithm::EcdsaP256, KeyTransferability::NonTransferable,)),
        Just((VerificationAlgorithm::EcdsaP256, KeyTransferability::Transferable)),
    ]
}

fn value<T>(result: Result<T, CryptoError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn raw_for(algorithm: VerificationAlgorithm) -> &'static [u8] {
    match algorithm {
        VerificationAlgorithm::Ed25519 => &ED25519_RAW,
        VerificationAlgorithm::EcdsaP256 => &P256_RAW,
        _ => &[],
    }
}

fn signature_for(algorithm: VerificationAlgorithm) -> &'static [u8] {
    match algorithm {
        VerificationAlgorithm::Ed25519 => &ED25519_SIGNATURE,
        VerificationAlgorithm::EcdsaP256 => &P256_SIGNATURE,
        _ => &[],
    }
}

proptest! {
    #[test]
    fn every_supported_key_kind_round_trips_canonically(
        (algorithm, transferability) in key_parameters(),
    ) {
        let key = value(VerificationKey::from_raw(
            algorithm,
            transferability,
            raw_for(algorithm),
        ))?;
        let qb64 = value(key.qb64())?;
        let qb2 = value(key.qb2())?;
        prop_assert_eq!(key.algorithm(), algorithm);
        prop_assert_eq!(key.transferability(), transferability);
        prop_assert_eq!(value(VerificationKey::from_qb64(&qb64))?, key.clone());
        prop_assert_eq!(value(VerificationKey::from_qb2(&qb2))?, key);
    }

    #[test]
    fn stream_parser_preserves_arbitrary_qb64_suffix(
        (algorithm, transferability) in key_parameters(),
        suffix in "[A-Za-z0-9_-]{1,64}",
    ) {
        let key = value(VerificationKey::from_raw(
            algorithm,
            transferability,
            raw_for(algorithm),
        ))?;
        let qb64 = value(key.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = value(VerificationKey::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.key(), &key);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        prop_assert!(VerificationKey::from_qb64(&stream).is_err());
    }

    #[test]
    fn changing_any_serialization_byte_fails_verification(
        (algorithm, transferability) in key_parameters(),
        changed_index in 0_usize..MESSAGE.len(),
        delta in 1_u8..=u8::MAX,
    ) {
        let key = value(VerificationKey::from_raw(
            algorithm,
            transferability,
            raw_for(algorithm),
        ))?;
        value(key.verify(signature_for(algorithm), MESSAGE))?;
        let mut changed = MESSAGE.to_vec();
        let byte = changed
            .get_mut(changed_index)
            .ok_or_else(|| TestCaseError::fail("generated message index was out of range"))?;
        *byte ^= delta;
        let failed = matches!(
            key.verify(signature_for(algorithm), &changed),
            Err(CryptoError::VerificationFailed { .. })
        );
        prop_assert!(failed);
    }

    #[test]
    fn every_wrong_signature_width_is_typed(
        (algorithm, transferability) in key_parameters(),
        length in 0_usize..129,
    ) {
        prop_assume!(length != 64);
        let key = value(VerificationKey::from_raw(
            algorithm,
            transferability,
            raw_for(algorithm),
        ))?;
        let signature = vec![0_u8; length];
        let invalid_length = matches!(
            key.verify(&signature, MESSAGE),
            Err(CryptoError::InvalidSignatureLength { actual, .. }) if actual == length
        );
        prop_assert!(invalid_length);
    }
}
