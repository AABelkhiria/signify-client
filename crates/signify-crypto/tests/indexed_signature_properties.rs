//! Property and invalid-near-miss coverage for CESR indexed signatures.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::indexer::{IndexedSignatureAlgorithm, IndexedSignatureScope, IndexerCode};
use signify_crypto::{CryptoError, signature::IndexedSignature};

fn code() -> impl Strategy<Value = IndexerCode> {
    prop_oneof![
        Just(IndexerCode::ED25519),
        Just(IndexerCode::ED25519_CURRENT),
        Just(IndexerCode::ECDSA_256K1),
        Just(IndexerCode::ECDSA_256K1_CURRENT),
        Just(IndexerCode::ECDSA_256R1),
        Just(IndexerCode::ECDSA_256R1_CURRENT),
        Just(IndexerCode::ED448),
        Just(IndexerCode::ED448_CURRENT),
        Just(IndexerCode::ED25519_BIG),
        Just(IndexerCode::ED25519_BIG_CURRENT),
        Just(IndexerCode::ECDSA_256K1_BIG),
        Just(IndexerCode::ECDSA_256K1_BIG_CURRENT),
        Just(IndexerCode::ECDSA_256R1_BIG),
        Just(IndexerCode::ECDSA_256R1_BIG_CURRENT),
        Just(IndexerCode::ED448_BIG),
        Just(IndexerCode::ED448_BIG_CURRENT),
    ]
}

fn signature_input() -> impl Strategy<Value = (IndexerCode, u32, Vec<u8>)> {
    code().prop_flat_map(|code| {
        (
            Just(code),
            0_u32..=63,
            prop::collection::vec(any::<u8>(), raw_size(code)),
        )
    })
}

fn raw_size(code: IndexerCode) -> usize {
    if code.signature_algorithm() == Some(IndexedSignatureAlgorithm::Ed448) {
        114
    } else {
        64
    }
}

fn value<T>(result: Result<T, CryptoError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn every_indexed_signature_kind_round_trips_canonically(
        (code, index, raw) in signature_input(),
    ) {
        let signature = value(IndexedSignature::from_raw(code, index, None, &raw))?;
        let qb64 = value(signature.qb64())?;
        let qb64_bytes = value(signature.qb64_bytes())?;
        let qb2 = value(signature.qb2())?;
        prop_assert_eq!(signature.code(), code);
        prop_assert_eq!(signature.index(), index);
        prop_assert_eq!(signature.raw(), raw);
        match signature.scope() {
            IndexedSignatureScope::CurrentOnly => prop_assert_eq!(signature.other_index(), None),
            IndexedSignatureScope::BothLists => prop_assert_eq!(signature.other_index(), Some(index)),
            _ => return Err(TestCaseError::fail("generated an unknown indexed-signature scope")),
        }
        prop_assert_eq!(value(IndexedSignature::from_qb64(&qb64))?, signature.clone());
        prop_assert_eq!(value(IndexedSignature::from_qb64_bytes(&qb64_bytes))?, signature.clone());
        prop_assert_eq!(value(IndexedSignature::from_qb2(&qb2))?, signature);
    }

    #[test]
    fn stream_parser_preserves_arbitrary_qb64_suffix(
        (code, index, raw) in signature_input(),
        suffix in "[A-Za-z0-9_-]{1,64}",
    ) {
        let signature = value(IndexedSignature::from_raw(code, index, None, &raw))?;
        let qb64 = value(signature.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = value(IndexedSignature::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.signature(), &signature);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        prop_assert!(IndexedSignature::from_qb64(&stream).is_err());
    }

    #[test]
    fn every_wrong_raw_width_is_rejected(
        code in code(),
        index in 0_u32..=63,
        length in 0_usize..180,
    ) {
        prop_assume!(length != raw_size(code));
        let raw = vec![0_u8; length];
        prop_assert!(IndexedSignature::from_raw(code, index, None, &raw).is_err());
    }

    #[test]
    fn changing_any_raw_byte_changes_canonical_encoding(
        (code, index, raw) in signature_input(),
        selected in any::<u16>(),
        delta in 1_u8..=u8::MAX,
    ) {
        let original = value(IndexedSignature::from_raw(code, index, None, &raw))?;
        let mut changed = raw;
        let changed_index = usize::from(selected) % changed.len();
        let byte = changed
            .get_mut(changed_index)
            .ok_or_else(|| TestCaseError::fail("generated signature index was out of range"))?;
        *byte ^= delta;
        let changed = value(IndexedSignature::from_raw(code, index, None, &changed))?;
        prop_assert_ne!(value(original.qb64())?, value(changed.qb64())?);
    }
}
