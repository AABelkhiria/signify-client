//! Property and invalid-near-miss coverage for private Ed25519 signers.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::{code::DerivationCode, indexer::IndexerCode, matter::QualifiedMaterial};
use signify_crypto::{
    CryptoError,
    signer::{SignaturePlacement, Signer},
    verifier::KeyTransferability,
};

fn value<T>(result: Result<T, CryptoError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn cesr_value<T>(result: Result<T, signify_cesr::CesrError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn transferability(value: bool) -> KeyTransferability {
    if value {
        KeyTransferability::Transferable
    } else {
        KeyTransferability::NonTransferable
    }
}

proptest! {
    #[test]
    fn arbitrary_seeds_sign_deterministically_and_verify(
        seed in any::<[u8; 32]>(),
        message in prop::collection::vec(any::<u8>(), 0..1025),
        transferable in any::<bool>(),
    ) {
        let transferability = transferability(transferable);
        let first = value(Signer::from_seed(&seed, transferability))?;
        let second = value(Signer::from_seed(&seed, transferability))?;
        let first_signature = value(first.sign_unindexed(&message))?;
        let second_signature = value(second.sign_unindexed(&message))?;
        prop_assert_eq!(first.verifier(), second.verifier());
        prop_assert_eq!(first_signature.raw(), second_signature.raw());
        value(first.verifier().verify(first_signature.raw(), &message))?;

        let mut changed = message;
        changed.push(0xff);
        prop_assert!(first.verifier().verify(first_signature.raw(), &changed).is_err());
    }

    #[test]
    fn both_list_indices_select_canonical_small_or_big_codes(
        seed in any::<[u8; 32]>(),
        message in prop::collection::vec(any::<u8>(), 0..257),
        current in 0_u32..4096,
        prior in 0_u32..4096,
    ) {
        let signer = value(Signer::from_seed(&seed, KeyTransferability::Transferable))?;
        let placement = SignaturePlacement::both_lists_with_prior(current, prior);
        let signature = value(signer.sign_indexed(&message, placement))?;
        let expected = if current <= 63 && current == prior {
            IndexerCode::ED25519
        } else {
            IndexerCode::ED25519_BIG
        };
        prop_assert_eq!(signature.code(), expected);
        prop_assert_eq!(signature.index(), current);
        prop_assert_eq!(signature.other_index(), Some(prior));
        value(signer.verifier().verify(signature.raw(), &message))?;
    }

    #[test]
    fn current_only_indices_select_canonical_small_or_big_codes(
        seed in any::<[u8; 32]>(),
        message in prop::collection::vec(any::<u8>(), 0..257),
        current in 0_u32..4096,
    ) {
        let signer = value(Signer::from_seed(&seed, KeyTransferability::NonTransferable))?;
        let placement = SignaturePlacement::current_list(current);
        let signature = value(signer.sign_indexed(&message, placement))?;
        let expected = if current <= 63 {
            IndexerCode::ED25519_CURRENT
        } else {
            IndexerCode::ED25519_BIG_CURRENT
        };
        prop_assert_eq!(signature.code(), expected);
        prop_assert_eq!(signature.index(), current);
        prop_assert_eq!(signature.other_index(), None);
        value(signer.verifier().verify(signature.raw(), &message))?;
    }

    #[test]
    fn seed_stream_parser_preserves_arbitrary_qb64_suffix(
        seed in any::<[u8; 32]>(),
        suffix in "[A-Za-z0-9_-]{1,64}",
        transferable in any::<bool>(),
    ) {
        let material = cesr_value(QualifiedMaterial::new(DerivationCode::ED25519_SEED, &seed))?;
        let qb64 = cesr_value(material.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let transferability = transferability(transferable);
        let expected = value(Signer::from_seed(&seed, transferability))?;
        let parsed = value(Signer::parse_qb64(&stream, transferability))?;
        prop_assert_eq!(parsed.signer().verifier(), expected.verifier());
        prop_assert_eq!(parsed.consumed(), qb64.len());
        prop_assert!(Signer::from_qb64(&stream, transferability).is_err());
    }
}
