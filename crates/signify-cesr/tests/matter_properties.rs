//! Property and invalid-near-miss coverage for qualified CESR material.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::{
    CesrError,
    code::DerivationCode,
    matter::{ParsedMaterial, QualifiedMaterial},
};

fn variable_code() -> impl Strategy<Value = DerivationCode> {
    proptest::sample::select(
        DerivationCode::ALL
            .iter()
            .copied()
            .filter(|code| code.size().is_variable())
            .collect::<Vec<_>>(),
    )
}

fn fixed_32_byte_code() -> impl Strategy<Value = DerivationCode> {
    proptest::sample::select(vec![
        DerivationCode::ED25519_SEED,
        DerivationCode::ED25519_NONTRANSFERABLE,
        DerivationCode::X25519_PUBLIC,
        DerivationCode::ED25519,
        DerivationCode::BLAKE3_256,
        DerivationCode::BLAKE2B_256,
        DerivationCode::BLAKE2S_256,
        DerivationCode::SHA3_256,
        DerivationCode::SHA2_256,
        DerivationCode::ECDSA_256K1_SEED,
        DerivationCode::X25519_PRIVATE,
        DerivationCode::ECDSA_256R1_SEED,
    ])
}

fn test_value<T>(result: Result<T, CesrError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn variable_material_round_trips_canonically(
        raw in proptest::collection::vec(any::<u8>(), 0..16_384),
        code in variable_code(),
    ) {
        let material = test_value(QualifiedMaterial::new(code, &raw))?;
        let qb64 = test_value(material.qb64())?;
        let qb2 = test_value(material.qb2())?;
        prop_assert_eq!(qb64.len() % 4, 0);
        prop_assert_eq!(qb2.len() % 3, 0);
        let from_text = test_value(QualifiedMaterial::from_qb64(&qb64))?;
        let from_binary = test_value(QualifiedMaterial::from_qb2(&qb2))?;
        prop_assert_eq!(from_text.code(), material.code());
        prop_assert_eq!(from_text.variable_size(), material.variable_size());
        prop_assert_eq!(from_text.raw(), material.raw());
        prop_assert_eq!(from_binary.code(), material.code());
        prop_assert_eq!(from_binary.variable_size(), material.variable_size());
        prop_assert_eq!(from_binary.raw(), material.raw());
    }

    #[test]
    fn fixed_material_round_trips_for_each_32_byte_code(
        raw in any::<[u8; 32]>(),
        code in fixed_32_byte_code(),
    ) {
        let material = test_value(QualifiedMaterial::new(code, &raw))?;
        let qb64 = test_value(material.qb64())?;
        let qb2 = test_value(material.qb2())?;
        prop_assert_eq!(qb64.len(), 44);
        prop_assert_eq!(qb2.len(), 33);
        let from_text = test_value(QualifiedMaterial::from_qb64(&qb64))?;
        let from_binary = test_value(QualifiedMaterial::from_qb2(&qb2))?;
        prop_assert_eq!(from_text.code(), material.code());
        prop_assert_eq!(from_text.raw(), material.raw());
        prop_assert_eq!(from_binary.code(), material.code());
        prop_assert_eq!(from_binary.raw(), material.raw());
    }

    #[test]
    fn text_stream_parsing_retains_arbitrary_suffix(
        raw in any::<[u8; 32]>(),
        suffix in "[A-Za-z0-9_-]{0,64}",
    ) {
        let material = test_value(QualifiedMaterial::new(DerivationCode::BLAKE3_256, &raw))?;
        let qb64 = test_value(material.qb64())?;
        let stream = format!("{qb64}{suffix}");
        let parsed: ParsedMaterial = test_value(QualifiedMaterial::parse_qb64(&stream))?;
        prop_assert_eq!(parsed.material().code(), material.code());
        prop_assert_eq!(parsed.material().raw(), material.raw());
        prop_assert_eq!(parsed.consumed(), qb64.len());
        if suffix.is_empty() {
            let exact = test_value(QualifiedMaterial::from_qb64(&stream))?;
            prop_assert_eq!(exact.code(), material.code());
            prop_assert_eq!(exact.raw(), material.raw());
        } else {
            let rejected = matches!(
                QualifiedMaterial::from_qb64(&stream),
                Err(CesrError::TrailingMaterial { .. })
            );
            prop_assert!(rejected);
        }
    }

    #[test]
    fn non_zero_alignment_near_misses_are_rejected(raw in any::<[u8; 32]>()) {
        let material = test_value(QualifiedMaterial::new(DerivationCode::ED25519_SEED, &raw))?;
        let mut qb64 = test_value(material.qb64())?.into_bytes();
        let slot = qb64.get_mut(1).ok_or_else(|| TestCaseError::fail("missing alignment character"))?;
        *slot = b'Q';
        let malformed = String::from_utf8(qb64).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let rejected = matches!(
            QualifiedMaterial::from_qb64(&malformed),
            Err(CesrError::NonZeroPadding { .. })
        );
        prop_assert!(rejected);
    }
}
