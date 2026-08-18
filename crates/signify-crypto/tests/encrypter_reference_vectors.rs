//! Exact encrypter and Rust-to-TypeScript sealed-box interoperability fixtures.

use std::error::Error;

use serde::Deserialize;
use signify_cesr::{code::DerivationCode, matter::QualifiedMaterial};
use signify_crypto::{
    CryptoError,
    cipher::{Ciphertext, CiphertextKind, Encrypter},
    verifier::VerificationKey,
};

const REFERENCE_SHA: &str = "ae92eceb8e776ad57669707bff7f84db9390b711";

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    algorithm_dependencies: String,
    secret_fixture_policy: String,
    encrypter: EncrypterCase,
    rust_ciphertexts_accepted_by_reference: Vec<CipherCase>,
    rejected_cases: Vec<RejectedCase>,
    reference_quirks: ReferenceQuirks,
}

#[derive(Debug, Deserialize)]
struct EncrypterCase {
    code: String,
    raw_hex: String,
    qb64: String,
    verifier_qb64: String,
    from_verifier_qb64: String,
    crypt_seed_qb64: String,
    verifies_crypt_seed: bool,
    rejects_other_valid_seed: bool,
}

#[derive(Debug, Deserialize)]
struct CipherCase {
    name: String,
    ephemeral_secret_hex: String,
    plaintext_kind: String,
    plaintext_qb64: String,
    code: String,
    raw_hex: String,
    qb64: String,
    opened_plaintext_hex: String,
}

#[derive(Debug, Deserialize)]
struct RejectedCase {
    name: String,
    reference_error_category: String,
    reference_error_message: String,
    rust_error_category: String,
}

#[derive(Debug, Deserialize)]
struct ReferenceQuirks {
    arbitrary_matter_is_labeled_as_seed: ArbitraryMatterQuirk,
    public_key_validation: PublicKeyQuirk,
}

#[derive(Debug, Deserialize)]
struct ArbitraryMatterQuirk {
    input_code: String,
    reference_cipher_code: String,
    rust_decision: String,
    rust_error_category: String,
}

#[derive(Debug, Deserialize)]
struct PublicKeyQuirk {
    reference_accepts_non_contributory_raw_key: bool,
    rust_decision: String,
    rust_error_category: String,
}

fn fixture() -> Result<Fixture, serde_json::Error> {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/crypto-encrypter/v1.json"
    )))
}

#[test]
fn fixture_metadata_is_pinned_and_security_scoped() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.generated_on, "2026-08-14");
    assert_eq!(fixture.sources.len(), 6);
    assert!(fixture.sources.iter().any(|source| source.ends_with("encrypter.ts")));
    assert!(fixture.algorithm_dependencies.contains("crypto_box_seal_open"));
    assert!(
        fixture
            .secret_fixture_policy
            .contains("never be used as production secrets")
    );
    Ok(())
}

#[test]
fn reference_key_conversion_and_seed_checks_match_exactly() -> Result<(), Box<dyn Error>> {
    let case = fixture()?.encrypter;
    let raw = decode_hex(&case.raw_hex)?;
    let encrypter = Encrypter::from_raw(&raw)?;
    assert_eq!(encrypter.code().as_str(), case.code);
    assert_eq!(encrypter.qb64()?, case.qb64);
    assert_eq!(Encrypter::from_qb64(&case.qb64)?, encrypter);

    let verifier = VerificationKey::from_qb64(&case.verifier_qb64)?;
    let converted = Encrypter::from_verification_key(&verifier)?;
    assert_eq!(converted.qb64()?, case.from_verifier_qb64);
    assert!(case.verifies_crypt_seed);
    assert!(converted.matches_seed_qb64(case.crypt_seed_qb64.as_bytes())?);
    assert!(case.rejects_other_valid_seed);
    assert!(!converted.matches_seed_qb64(b"ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr")?);
    Ok(())
}

#[test]
fn exact_rust_ciphertexts_are_recorded_as_reference_accepted() -> Result<(), Box<dyn Error>> {
    for case in fixture()?.rust_ciphertexts_accepted_by_reference {
        let ciphertext = Ciphertext::from_qb64(&case.qb64)?;
        let kind = match case.plaintext_kind.as_str() {
            "qualified_seed" => CiphertextKind::QualifiedSeed,
            "qualified_salt" => CiphertextKind::QualifiedSalt,
            other => return Err(format!("unknown plaintext kind {other}").into()),
        };
        assert_eq!(ciphertext.kind(), kind, "kind mismatch for {}", case.name);
        assert_eq!(ciphertext.code().as_str(), case.code, "code mismatch for {}", case.name);
        assert_eq!(
            ciphertext.raw(),
            decode_hex(&case.raw_hex)?,
            "raw mismatch for {}",
            case.name
        );
        assert_eq!(case.ephemeral_secret_hex.len(), 64);
        assert_eq!(decode_hex(&case.opened_plaintext_hex)?, case.plaintext_qb64.as_bytes());
    }
    Ok(())
}

#[test]
fn reference_rejections_and_safe_divergences_are_typed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for case in fixture.rejected_cases {
        assert!(!case.reference_error_category.is_empty());
        assert!(!case.reference_error_message.is_empty());
        match case.name.as_str() {
            "empty_encrypter" => assert!(Encrypter::from_qb64("").is_err()),
            "p256_verifier" => {
                let p256 = VerificationKey::from_qb64("1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ")?;
                assert!(matches!(
                    Encrypter::from_verification_key(&p256),
                    Err(CryptoError::UnsupportedEncryptionKey { .. })
                ));
            }
            "missing_plaintext" => assert_eq!(case.rust_error_category, "TypedPlaintextRequired"),
            other => return Err(format!("unknown rejected case {other}").into()),
        }
    }

    let arbitrary = fixture.reference_quirks.arbitrary_matter_is_labeled_as_seed;
    assert_eq!(arbitrary.input_code, "E");
    assert_eq!(arbitrary.reference_cipher_code, "P");
    assert!(arbitrary.rust_decision.contains("strictly accepts"));
    let digest = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &[0_u8; 32])?;
    let encrypter = Encrypter::from_qb64("CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR")?;
    let error = encrypter
        .encrypt_seed_qb64(&digest.qb64_bytes()?)
        .err()
        .ok_or("digest was silently encrypted as a seed")?;
    assert!(matches!(error, CryptoError::InvalidSigningCode { .. }));
    assert_eq!(arbitrary.rust_error_category, "InvalidSigningCode");

    let key_quirk = fixture.reference_quirks.public_key_validation;
    assert!(key_quirk.reference_accepts_non_contributory_raw_key);
    assert!(key_quirk.rust_decision.contains("non-contributory"));
    assert_eq!(key_quirk.rust_error_category, "InvalidEncryptionKey");
    assert!(matches!(
        Encrypter::from_raw(&[0_u8; 32]),
        Err(CryptoError::InvalidEncryptionKey { .. })
    ));
    Ok(())
}

fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !input.len().is_multiple_of(2) {
        return Err("hex input has odd length".into());
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}
