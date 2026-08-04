//! Property and invalid-near-miss coverage for indexed CESR material.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::{
    CesrError,
    indexer::{IndexedMaterial, IndexedSignatureScope, IndexerCode},
};

fn fixed_code() -> impl Strategy<Value = IndexerCode> {
    proptest::sample::select(
        IndexerCode::ALL
            .iter()
            .copied()
            .filter(|code| code.size().raw_size().is_some())
            .collect::<Vec<_>>(),
    )
}

fn test_value<T>(result: Result<T, CesrError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn every_fixed_code_round_trips_canonically(
        code in fixed_code(),
        raw_64 in any::<[u8; 64]>(),
        raw_114 in proptest::collection::vec(any::<u8>(), 114..=114),
        candidate_index in any::<u32>(),
        candidate_other in any::<u32>(),
    ) {
        let size = code.size();
        let current_width = u32::try_from(size.current_index_size())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let current_modulus = 64_u32
            .checked_pow(current_width)
            .ok_or_else(|| TestCaseError::fail("current modulus overflow"))?;
        let index = candidate_index % current_modulus;
        let other_index = match code.signature_scope() {
            Some(IndexedSignatureScope::CurrentOnly) => None,
            Some(IndexedSignatureScope::BothLists) if size.other_index_size() == 0 => Some(index),
            Some(IndexedSignatureScope::BothLists) => {
                let other_width = u32::try_from(size.other_index_size())
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                let other_modulus = 64_u32
                    .checked_pow(other_width)
                    .ok_or_else(|| TestCaseError::fail("other modulus overflow"))?;
                Some(candidate_other % other_modulus)
            }
            None => return Err(TestCaseError::fail("fixed code lacks signature scope")),
            Some(_) => return Err(TestCaseError::fail("unknown signature scope")),
        };
        let raw: &[u8] = if size.raw_size() == Some(64) { &raw_64 } else { &raw_114 };
        let material = test_value(IndexedMaterial::new(code, index, other_index, raw))?;
        let qb64 = test_value(material.qb64())?;
        let qb2 = test_value(material.qb2())?;
        let from_text = test_value(IndexedMaterial::from_qb64(&qb64))?;
        let from_binary = test_value(IndexedMaterial::from_qb2(&qb2))?;
        prop_assert_eq!(from_text, material.clone());
        prop_assert_eq!(from_binary, material);
    }

    #[test]
    fn stream_parsing_preserves_arbitrary_suffix(
        raw in any::<[u8; 64]>(),
        index in 0_u32..64,
        suffix in "[A-Za-z0-9_-]{0,64}",
    ) {
        let material = test_value(IndexedMaterial::new(IndexerCode::ED25519, index, None, &raw))?;
        let qb64 = test_value(material.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed = test_value(IndexedMaterial::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.material(), &material);
        prop_assert_eq!(parsed.consumed(), qb64.len());
        if suffix.is_empty() {
            prop_assert_eq!(test_value(IndexedMaterial::from_qb64(&stream))?, material);
        } else {
            let rejected = matches!(
                IndexedMaterial::from_qb64(&stream),
                Err(CesrError::TrailingMaterial { .. })
            );
            prop_assert!(rejected);
        }
    }

    #[test]
    fn non_zero_alignment_near_misses_are_rejected(raw in any::<[u8; 64]>()) {
        let material = test_value(IndexedMaterial::new(IndexerCode::ED25519, 0, None, &raw))?;
        let mut qb64 = test_value(material.qb64())?.into_bytes();
        let slot = qb64
            .get_mut(2)
            .ok_or_else(|| TestCaseError::fail("missing alignment character"))?;
        *slot = b'_';
        let malformed = String::from_utf8(qb64)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let rejected = matches!(
            IndexedMaterial::from_qb64(&malformed),
            Err(CesrError::NonZeroPadding { .. })
        );
        prop_assert!(rejected);
    }
}
