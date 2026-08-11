//! CESR-qualified public verification keys and detached-signature verification.
//!
//! The pinned TypeScript `Verfer` supports Ed25519 and ECDSA over NIST P-256. This module models
//! algorithm and transferability separately, validates public-key points during construction, and
//! composes the qualified-material engine without exposing a generic crypto-material hierarchy.

use std::{fmt, str::FromStr};

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey, signature::Verifier};
use signify_cesr::{
    CesrError,
    code::DerivationCode,
    matter::{ParsedMaterial, QualifiedMaterial},
};

use crate::CryptoError;

/// Raw byte width of an Ed25519 public verification key.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// SEC1 compressed-point width of a P-256 public verification key.
pub const P256_PUBLIC_KEY_SIZE: usize = 33;
/// Raw byte width of both supported detached-signature encodings.
pub const SIGNATURE_SIZE: usize = 64;

/// A public-key verification algorithm supported by Signify.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum VerificationAlgorithm {
    /// Ed25519 detached signatures.
    Ed25519,
    /// ECDSA over NIST P-256 with SHA-256 over the complete serialization.
    EcdsaP256,
}

impl VerificationAlgorithm {
    /// Returns a stable, non-secret algorithm name for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::EcdsaP256 => "P-256 ECDSA/SHA-256",
        }
    }

    /// Returns the exact raw public-key width.
    #[must_use]
    pub const fn public_key_size(self) -> usize {
        match self {
            Self::Ed25519 => ED25519_PUBLIC_KEY_SIZE,
            Self::EcdsaP256 => P256_PUBLIC_KEY_SIZE,
        }
    }
}

/// Whether a verification key is usable as a transferable KERI identifier prefix.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyTransferability {
    /// A basic non-transferable identifier key.
    NonTransferable,
    /// A key whose identifier may rotate through KERI events.
    Transferable,
}

impl KeyTransferability {
    /// Returns whether this value denotes a transferable key.
    #[must_use]
    pub const fn is_transferable(self) -> bool {
        matches!(self, Self::Transferable)
    }
}

#[derive(Clone)]
enum VerificationMaterial {
    Ed25519 {
        raw: [u8; ED25519_PUBLIC_KEY_SIZE],
        key: Ed25519VerifyingKey,
    },
    EcdsaP256 {
        raw: [u8; P256_PUBLIC_KEY_SIZE],
        key: P256VerifyingKey,
    },
}

impl VerificationMaterial {
    const fn algorithm(&self) -> VerificationAlgorithm {
        match self {
            Self::Ed25519 { .. } => VerificationAlgorithm::Ed25519,
            Self::EcdsaP256 { .. } => VerificationAlgorithm::EcdsaP256,
        }
    }

    const fn raw(&self) -> &[u8] {
        match self {
            Self::Ed25519 { raw, .. } => raw,
            Self::EcdsaP256 { raw, .. } => raw,
        }
    }
}

/// One immutable, CESR-qualified public verification key.
///
/// Construction validates the derivation code, exact raw width, Ed25519 point and weak-key rules,
/// or compressed SEC1 P-256 point. Encoded parsers additionally require canonical CESR spelling.
/// Signature verification returns a typed error for malformed or unauthentic input.
///
/// P-256 uses SHA-256 over the complete serialization. This deliberately rejects the pinned
/// TypeScript `Verfer` behavior, which passes arbitrary serialization bytes to a prehash API and
/// authenticates only their leftmost 32 bytes when longer. The compatibility fixture records both
/// the unsafe reference signature and a safe signature made by its pinned Noble primitive with
/// explicit full-message hashing.
///
/// ```
/// use signify_crypto::verifier::VerificationKey;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let key = VerificationKey::from_qb64(
///     "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",
/// )?;
/// let signature = [
///     120, 221, 252, 244, 26, 66, 35, 232, 131, 66, 190, 174, 247, 217, 222, 197,
///     5, 156, 109, 220, 108, 52, 241, 45, 102, 106, 79, 83, 121, 24, 18, 182,
///     202, 241, 137, 67, 196, 41, 195, 0, 63, 212, 165, 38, 187, 122, 178, 14,
///     97, 218, 145, 47, 78, 200, 107, 99, 62, 122, 172, 207, 8, 35, 55, 14,
/// ];
/// key.verify(
///     &signature,
///     b"abcdefghijklmnopqrstuvwxyz0123456789",
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// Invalid verification-key state cannot be assembled directly:
///
/// ```compile_fail
/// use signify_crypto::verifier::{KeyTransferability, VerificationKey};
///
/// let invalid = VerificationKey {
///     transferability: KeyTransferability::Transferable,
///     material: (),
/// };
/// ```
#[derive(Clone)]
pub struct VerificationKey {
    transferability: KeyTransferability,
    material: VerificationMaterial,
}

/// One verification key parsed from the front of a raw, qb64, or qb2 stream.
#[derive(Clone)]
pub struct ParsedVerificationKey {
    key: VerificationKey,
    consumed: usize,
}

impl ParsedVerificationKey {
    /// Returns the parsed verification key by reference.
    #[must_use]
    pub const fn key(&self) -> &VerificationKey {
        &self.key
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the key from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (VerificationKey, usize) {
        (self.key, self.consumed)
    }
}

impl VerificationKey {
    /// Constructs one verification key from exact raw public-key bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation/trailing-material error for the wrong width or an invalid-key
    /// error when the bytes do not encode a safe public point.
    pub fn from_raw(
        algorithm: VerificationAlgorithm,
        transferability: KeyTransferability,
        input: &[u8],
    ) -> Result<Self, CryptoError> {
        let parsed = Self::parse_raw_prefix(algorithm, transferability, input)?;
        reject_trailing("verification-key raw material", input.len(), parsed.consumed)?;
        Ok(parsed.key)
    }

    /// Parses one fixed-width verification key from the beginning of a raw byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation, CESR size, or invalid-public-point error.
    pub fn parse_raw_prefix(
        algorithm: VerificationAlgorithm,
        transferability: KeyTransferability,
        input: &[u8],
    ) -> Result<ParsedVerificationKey, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_raw_prefix(
            code_for(algorithm, transferability),
            input,
            algorithm.public_key_size(),
        )?)
    }

    /// Parses one canonical qb64 verification key from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material, code, unsupported-algorithm, or invalid-public-point error.
    pub fn parse_qb64(input: &str) -> Result<ParsedVerificationKey, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qb64 verification key.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("verification-key qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.key)
    }

    /// Parses one UTF-8 qb64 verification key from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8, material, code, or invalid-public-point error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedVerificationKey, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64_bytes(input)?)
    }

    /// Parses exactly one UTF-8 qb64 verification key from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing("verification-key qualified Base64 bytes", input.len(), parsed.consumed)?;
        Ok(parsed.key)
    }

    /// Parses one canonical qualified-binary (`qb2`) verification key from the input prefix.
    ///
    /// # Errors
    ///
    /// Returns a typed material, code, unsupported-algorithm, or invalid-public-point error.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedVerificationKey, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qualified-binary (`qb2`) verification key.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("verification-key qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.key)
    }

    /// Returns the validated verification algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> VerificationAlgorithm {
        self.material.algorithm()
    }

    /// Returns the key's transferability classification.
    #[must_use]
    pub const fn transferability(&self) -> KeyTransferability {
        self.transferability
    }

    /// Returns whether the key is transferable.
    #[must_use]
    pub const fn is_transferable(&self) -> bool {
        self.transferability.is_transferable()
    }

    /// Returns the key's exact CESR derivation code.
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        code_for(self.algorithm(), self.transferability)
    }

    /// Returns the exact public verification-key bytes.
    #[must_use]
    pub const fn raw(&self) -> &[u8] {
        self.material.raw()
    }

    /// Encodes the key as canonical qualified Base64 (`qb64`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.material()?.qb64()?)
    }

    /// Encodes the key as UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb64_bytes()?)
    }

    /// Encodes the key as canonical qualified binary (`qb2`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb2(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb2()?)
    }

    /// Verifies a detached 64-byte signature over the complete serialization.
    ///
    /// Ed25519 uses strict verification, including weak-key and scalar-malleability checks. P-256
    /// hashes the complete serialization with SHA-256 and accepts the high-S and low-S encodings
    /// supported by the pinned P-256 primitive.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidSignatureLength`] for a wrong-width signature,
    /// [`CryptoError::InvalidSignatureEncoding`] for invalid P-256 scalars, or
    /// [`CryptoError::VerificationFailed`] when authentication fails.
    pub fn verify(&self, signature: &[u8], serialization: &[u8]) -> Result<(), CryptoError> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignatureLength {
                algorithm: self.algorithm().name(),
                expected: SIGNATURE_SIZE,
                actual: signature.len(),
            });
        }

        match &self.material {
            VerificationMaterial::Ed25519 { key, .. } => {
                let signature =
                    Ed25519Signature::from_slice(signature).map_err(|_| CryptoError::InvalidSignatureEncoding {
                        algorithm: VerificationAlgorithm::Ed25519.name(),
                    })?;
                key.verify_strict(serialization, &signature)
                    .map_err(|_| CryptoError::VerificationFailed {
                        algorithm: VerificationAlgorithm::Ed25519.name(),
                    })
            }
            VerificationMaterial::EcdsaP256 { key, .. } => {
                let signature =
                    P256Signature::from_slice(signature).map_err(|_| CryptoError::InvalidSignatureEncoding {
                        algorithm: VerificationAlgorithm::EcdsaP256.name(),
                    })?;
                key.verify(serialization, &signature)
                    .map_err(|_| CryptoError::VerificationFailed {
                        algorithm: VerificationAlgorithm::EcdsaP256.name(),
                    })
            }
        }
    }

    fn material(&self) -> Result<QualifiedMaterial, CryptoError> {
        Ok(QualifiedMaterial::new(self.code(), self.raw())?)
    }

    fn from_parsed_material(parsed: ParsedMaterial) -> Result<ParsedVerificationKey, CryptoError> {
        let (material, consumed) = parsed.into_parts();
        let (algorithm, transferability) = classification_for(material.code())?;
        Ok(ParsedVerificationKey {
            key: Self {
                transferability,
                material: validate_material(algorithm, material.raw())?,
            },
            consumed,
        })
    }
}

impl fmt::Debug for VerificationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationKey")
            .field("algorithm", &self.algorithm())
            .field("transferability", &self.transferability)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ParsedVerificationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedVerificationKey")
            .field("key", &self.key)
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl PartialEq for VerificationKey {
    fn eq(&self, other: &Self) -> bool {
        self.transferability == other.transferability
            && self.algorithm() == other.algorithm()
            && self.raw() == other.raw()
    }
}

impl Eq for VerificationKey {}

impl PartialEq for ParsedVerificationKey {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.consumed == other.consumed
    }
}

impl Eq for ParsedVerificationKey {}

impl TryFrom<&str> for VerificationKey {
    type Error = CryptoError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::from_qb64(input)
    }
}

impl FromStr for VerificationKey {
    type Err = CryptoError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_qb64(input)
    }
}

impl fmt::Display for VerificationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.qb64()
            .map_err(|_| fmt::Error)
            .and_then(|qb64| formatter.write_str(&qb64))
    }
}

const fn code_for(algorithm: VerificationAlgorithm, transferability: KeyTransferability) -> DerivationCode {
    match (algorithm, transferability) {
        (VerificationAlgorithm::Ed25519, KeyTransferability::NonTransferable) => {
            DerivationCode::ED25519_NONTRANSFERABLE
        }
        (VerificationAlgorithm::Ed25519, KeyTransferability::Transferable) => DerivationCode::ED25519,
        (VerificationAlgorithm::EcdsaP256, KeyTransferability::NonTransferable) => {
            DerivationCode::ECDSA_256R1_NONTRANSFERABLE
        }
        (VerificationAlgorithm::EcdsaP256, KeyTransferability::Transferable) => DerivationCode::ECDSA_256R1,
    }
}

fn classification_for(code: DerivationCode) -> Result<(VerificationAlgorithm, KeyTransferability), CryptoError> {
    match code {
        DerivationCode::ED25519_NONTRANSFERABLE => {
            Ok((VerificationAlgorithm::Ed25519, KeyTransferability::NonTransferable))
        }
        DerivationCode::ED25519 => Ok((VerificationAlgorithm::Ed25519, KeyTransferability::Transferable)),
        DerivationCode::ECDSA_256R1_NONTRANSFERABLE => {
            Ok((VerificationAlgorithm::EcdsaP256, KeyTransferability::NonTransferable))
        }
        DerivationCode::ECDSA_256R1 => Ok((VerificationAlgorithm::EcdsaP256, KeyTransferability::Transferable)),
        DerivationCode::ECDSA_256K1_NONTRANSFERABLE
        | DerivationCode::ECDSA_256K1
        | DerivationCode::ED448_NONTRANSFERABLE => {
            Err(CryptoError::UnsupportedVerificationAlgorithm { code: code.as_str() })
        }
        other => Err(CryptoError::InvalidVerificationCode { code: other.as_str() }),
    }
}

fn validate_material(algorithm: VerificationAlgorithm, raw: &[u8]) -> Result<VerificationMaterial, CryptoError> {
    match algorithm {
        VerificationAlgorithm::Ed25519 => {
            let bytes =
                <[u8; ED25519_PUBLIC_KEY_SIZE]>::try_from(raw).map_err(|_| CryptoError::InvalidVerificationKey {
                    algorithm: algorithm.name(),
                })?;
            let key = Ed25519VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidVerificationKey {
                algorithm: algorithm.name(),
            })?;
            if key.is_weak() {
                return Err(CryptoError::InvalidVerificationKey {
                    algorithm: algorithm.name(),
                });
            }
            Ok(VerificationMaterial::Ed25519 { raw: bytes, key })
        }
        VerificationAlgorithm::EcdsaP256 => {
            let bytes =
                <[u8; P256_PUBLIC_KEY_SIZE]>::try_from(raw).map_err(|_| CryptoError::InvalidVerificationKey {
                    algorithm: algorithm.name(),
                })?;
            let key = P256VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| CryptoError::InvalidVerificationKey {
                algorithm: algorithm.name(),
            })?;
            Ok(VerificationMaterial::EcdsaP256 { raw: bytes, key })
        }
    }
}

fn reject_trailing(context: &'static str, total: usize, consumed: usize) -> Result<(), CryptoError> {
    let trailing = total
        .checked_sub(consumed)
        .ok_or(CesrError::LengthOverflow { context })?;
    if trailing == 0 {
        Ok(())
    } else {
        Err(CesrError::TrailingMaterial {
            context,
            length: trailing,
        }
        .into())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    const MESSAGE: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const ED25519_QB64: &str = "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const P256_QB64: &str = "1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ";
    const ED25519_SIGNATURE: [u8; SIGNATURE_SIZE] = [
        120, 221, 252, 244, 26, 66, 35, 232, 131, 66, 190, 174, 247, 217, 222, 197, 5, 156, 109, 220, 108, 52, 241, 45,
        102, 106, 79, 83, 121, 24, 18, 182, 202, 241, 137, 67, 196, 41, 195, 0, 63, 212, 165, 38, 187, 122, 178, 14,
        97, 218, 145, 47, 78, 200, 107, 99, 62, 122, 172, 207, 8, 35, 55, 14,
    ];

    #[test]
    fn ed25519_reference_signature_verifies() -> Result<(), CryptoError> {
        let key = VerificationKey::from_qb64(ED25519_QB64)?;
        assert_eq!(key.algorithm(), VerificationAlgorithm::Ed25519);
        assert_eq!(key.transferability(), KeyTransferability::Transferable);
        assert!(key.is_transferable());
        assert_eq!(key.code(), DerivationCode::ED25519);
        assert_eq!(key.raw().len(), ED25519_PUBLIC_KEY_SIZE);
        key.verify(&ED25519_SIGNATURE, MESSAGE)?;
        assert!(matches!(
            key.verify(&ED25519_SIGNATURE, b"different"),
            Err(CryptoError::VerificationFailed { algorithm: "Ed25519" })
        ));
        Ok(())
    }

    #[test]
    fn raw_and_encoded_domains_round_trip_with_stream_boundaries() -> Result<(), CryptoError> {
        let key = VerificationKey::from_qb64(ED25519_QB64)?;
        let raw = key.raw().to_vec();
        assert_eq!(
            VerificationKey::from_raw(VerificationAlgorithm::Ed25519, KeyTransferability::Transferable, &raw,)?,
            key
        );

        let qb64 = key.qb64()?;
        let qb64_bytes = key.qb64_bytes()?;
        let qb2 = key.qb2()?;
        assert_eq!(VerificationKey::from_qb64(&qb64)?, key);
        assert_eq!(VerificationKey::try_from(qb64.as_str())?, key);
        assert_eq!(qb64.parse::<VerificationKey>()?, key);
        assert_eq!(VerificationKey::from_qb64_bytes(&qb64_bytes)?, key);
        assert_eq!(VerificationKey::from_qb2(&qb2)?, key);
        assert_eq!(key.to_string(), qb64);

        let text_stream = format!("{qb64}ABCD");
        let parsed_text = VerificationKey::parse_qb64(&text_stream)?;
        assert_eq!(parsed_text.key(), &key);
        assert_eq!(parsed_text.consumed(), qb64.len());
        assert!(VerificationKey::from_qb64(&text_stream).is_err());

        let mut raw_stream = raw;
        raw_stream.push(0xff);
        let parsed_raw = VerificationKey::parse_raw_prefix(
            VerificationAlgorithm::Ed25519,
            KeyTransferability::Transferable,
            &raw_stream,
        )?;
        assert_eq!(parsed_raw.into_parts(), (key.clone(), ED25519_PUBLIC_KEY_SIZE));
        assert!(
            VerificationKey::from_raw(
                VerificationAlgorithm::Ed25519,
                KeyTransferability::Transferable,
                &raw_stream,
            )
            .is_err()
        );

        let mut binary_stream = qb2.clone();
        binary_stream.extend_from_slice(&[1, 2, 3]);
        let parsed_binary = VerificationKey::parse_qb2(&binary_stream)?;
        assert_eq!(parsed_binary.key(), &key);
        assert_eq!(parsed_binary.consumed(), qb2.len());
        assert!(VerificationKey::from_qb2(&binary_stream).is_err());
        Ok(())
    }

    #[test]
    fn code_validation_distinguishes_invalid_and_unsupported() -> Result<(), CryptoError> {
        let unsupported = QualifiedMaterial::new(DerivationCode::ECDSA_256K1, &[2_u8; P256_PUBLIC_KEY_SIZE])?;
        assert!(matches!(
            VerificationKey::from_qb64(&unsupported.qb64()?),
            Err(CryptoError::UnsupportedVerificationAlgorithm { code: "1AAB" })
        ));

        let invalid = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &[0_u8; ED25519_PUBLIC_KEY_SIZE])?;
        assert!(matches!(
            VerificationKey::from_qb2(&invalid.qb2()?),
            Err(CryptoError::InvalidVerificationCode { code: "E" })
        ));
        Ok(())
    }

    #[test]
    fn invalid_and_weak_public_keys_are_rejected() {
        assert!(matches!(
            VerificationKey::from_raw(
                VerificationAlgorithm::Ed25519,
                KeyTransferability::Transferable,
                &[0_u8; ED25519_PUBLIC_KEY_SIZE],
            ),
            Err(CryptoError::InvalidVerificationKey { algorithm: "Ed25519" })
        ));
        assert!(matches!(
            VerificationKey::from_raw(
                VerificationAlgorithm::EcdsaP256,
                KeyTransferability::Transferable,
                &[0_u8; P256_PUBLIC_KEY_SIZE],
            ),
            Err(CryptoError::InvalidVerificationKey {
                algorithm: "P-256 ECDSA/SHA-256"
            })
        ));
    }

    #[test]
    fn signature_structure_and_ed25519_malleability_are_checked() -> Result<(), CryptoError> {
        let key = VerificationKey::from_qb64(ED25519_QB64)?;
        let truncated = ED25519_SIGNATURE
            .get(..SIGNATURE_SIZE - 1)
            .ok_or(CryptoError::InvalidSignatureLength {
                algorithm: VerificationAlgorithm::Ed25519.name(),
                expected: SIGNATURE_SIZE,
                actual: 0,
            })?;
        assert!(matches!(
            key.verify(truncated, MESSAGE),
            Err(CryptoError::InvalidSignatureLength {
                expected: SIGNATURE_SIZE,
                actual: 63,
                ..
            })
        ));

        let mut noncanonical = ED25519_SIGNATURE;
        let Some(last) = noncanonical.last_mut() else {
            return Err(CryptoError::InvalidSignatureLength {
                algorithm: VerificationAlgorithm::Ed25519.name(),
                expected: SIGNATURE_SIZE,
                actual: 0,
            });
        };
        *last = 0xff;
        assert!(matches!(
            key.verify(&noncanonical, MESSAGE),
            Err(CryptoError::VerificationFailed { .. })
        ));

        let p256 = VerificationKey::from_qb64(P256_QB64)?;
        assert!(matches!(
            p256.verify(&[0_u8; SIGNATURE_SIZE], MESSAGE),
            Err(CryptoError::InvalidSignatureEncoding {
                algorithm: "P-256 ECDSA/SHA-256"
            })
        ));
        Ok(())
    }

    #[test]
    fn crypto_error_preserves_cesr_source() {
        let error = VerificationKey::from_qb64("")
            .err()
            .ok_or("empty verifier input was accepted");
        assert!(matches!(
            error,
            Ok(CryptoError::Cesr { ref source })
                if matches!(source.as_ref(), CesrError::EmptyInput { .. })
        ));
        if let Ok(error) = error {
            assert!(error.source().is_some());
        }
    }
}
