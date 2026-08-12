//! CESR-qualified unindexed signatures and optional verifier association.
//!
//! The pinned TypeScript `Cigar` is a generic qualified-material subclass with a mutable optional
//! verifier. This module instead validates the signature code, stores the fixed-width signature in
//! a semantic value, and associates a verifier immutably only when its algorithm matches.

use std::{fmt, str::FromStr};

use signify_cesr::{
    CesrError,
    code::DerivationCode,
    matter::{ParsedMaterial, QualifiedMaterial},
};

use crate::{
    CryptoError,
    verifier::{SIGNATURE_SIZE, VerificationAlgorithm, VerificationKey},
};

/// An algorithm represented by a CESR unindexed-signature code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// Ed25519 detached signatures (`0B`).
    Ed25519,
    /// ECDSA over secp256k1 signatures (`0C`).
    EcdsaSecp256k1,
    /// ECDSA over NIST P-256 signatures (`0I`).
    EcdsaP256,
}

impl SignatureAlgorithm {
    /// Returns a stable, non-secret algorithm name for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::EcdsaSecp256k1 => "secp256k1 ECDSA",
            Self::EcdsaP256 => "P-256 ECDSA/SHA-256",
        }
    }
}

/// One immutable, fixed-width CESR unindexed signature.
///
/// Construction validates the derivation code and exact 64-byte width. It does not claim that the
/// bytes authenticate a message; cryptographic verification remains the associated
/// [`VerificationKey`]'s responsibility. A verifier may be attached only when its algorithm
/// matches the signature code. secp256k1 material can be represented for wire compatibility even
/// though the pinned reference has no corresponding verifier implementation.
///
/// ```
/// use signify_crypto::signature::{SignatureAlgorithm, UnindexedSignature};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let signature = UnindexedSignature::from_raw(SignatureAlgorithm::Ed25519, &[0_u8; 64])?;
/// assert_eq!(signature.code().as_str(), "0B");
/// assert_eq!(signature.raw().len(), 64);
/// # Ok(())
/// # }
/// ```
///
/// Invalid signature state cannot be assembled directly:
///
/// ```compile_fail
/// use signify_crypto::signature::{SignatureAlgorithm, UnindexedSignature};
///
/// let invalid = UnindexedSignature {
///     algorithm: SignatureAlgorithm::Ed25519,
///     raw: [0_u8; 64],
///     verifier: None,
/// };
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct UnindexedSignature {
    algorithm: SignatureAlgorithm,
    raw: [u8; SIGNATURE_SIZE],
    verifier: Option<VerificationKey>,
}

/// One unindexed signature parsed from the front of a raw, qb64, or qb2 stream.
#[derive(Clone, Eq, PartialEq)]
pub struct ParsedUnindexedSignature {
    signature: UnindexedSignature,
    consumed: usize,
}

impl ParsedUnindexedSignature {
    /// Returns the parsed signature by reference.
    #[must_use]
    pub const fn signature(&self) -> &UnindexedSignature {
        &self.signature
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the signature from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (UnindexedSignature, usize) {
        (self.signature, self.consumed)
    }
}

impl UnindexedSignature {
    /// Constructs one unindexed signature from exact raw bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation or trailing-material error unless `input` is exactly 64 bytes.
    pub fn from_raw(algorithm: SignatureAlgorithm, input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_raw_prefix(algorithm, input)?;
        reject_trailing("unindexed-signature raw material", input.len(), parsed.consumed)?;
        Ok(parsed.signature)
    }

    /// Constructs one exact raw signature and associates a compatible verifier.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::from_raw`] or a verifier-algorithm mismatch.
    pub fn from_raw_with_verifier(
        algorithm: SignatureAlgorithm,
        input: &[u8],
        verifier: VerificationKey,
    ) -> Result<Self, CryptoError> {
        Self::from_raw(algorithm, input)?.with_verifier(verifier)
    }

    /// Parses one fixed-width unindexed signature from the beginning of a raw byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation or CESR sizing error.
    pub fn parse_raw_prefix(
        algorithm: SignatureAlgorithm,
        input: &[u8],
    ) -> Result<ParsedUnindexedSignature, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_raw_prefix(
            code_for(algorithm),
            input,
            SIGNATURE_SIZE,
        )?)
    }

    /// Parses one canonical qb64 unindexed signature from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material or non-signature-code error.
    pub fn parse_qb64(input: &str) -> Result<ParsedUnindexedSignature, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qb64 unindexed signature.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("unindexed-signature qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.signature)
    }

    /// Parses one UTF-8 qb64 signature from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8, material, or non-signature-code error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedUnindexedSignature, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64_bytes(input)?)
    }

    /// Parses exactly one UTF-8 qb64 signature from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing(
            "unindexed-signature qualified Base64 bytes",
            input.len(),
            parsed.consumed,
        )?;
        Ok(parsed.signature)
    }

    /// Parses one canonical qualified-binary (`qb2`) signature from the input prefix.
    ///
    /// # Errors
    ///
    /// Returns a typed material or non-signature-code error.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedUnindexedSignature, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qualified-binary (`qb2`) signature.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("unindexed-signature qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.signature)
    }

    /// Returns the signature algorithm selected by its derivation code.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Returns the exact CESR derivation code.
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        code_for(self.algorithm)
    }

    /// Returns the exact 64-byte detached signature.
    #[must_use]
    pub const fn raw(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.raw
    }

    /// Returns the associated verifier, when one was supplied.
    #[must_use]
    pub const fn verifier(&self) -> Option<&VerificationKey> {
        self.verifier.as_ref()
    }

    /// Returns this signature with a compatible verifier associated.
    ///
    /// This consumes and returns the signature so association is explicit and cannot be changed
    /// through shared references.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SignatureVerifierMismatch`] when the verifier algorithm differs from
    /// the signature code, or when a secp256k1 signature is paired with an unsupported key kind.
    pub fn with_verifier(mut self, verifier: VerificationKey) -> Result<Self, CryptoError> {
        if !algorithms_match(self.algorithm, verifier.algorithm()) {
            return Err(CryptoError::SignatureVerifierMismatch {
                signature_algorithm: self.algorithm.name(),
                verifier_algorithm: verifier.algorithm().name(),
            });
        }
        self.verifier = Some(verifier);
        Ok(self)
    }

    /// Returns this signature without an associated verifier.
    #[must_use]
    pub fn without_verifier(mut self) -> Self {
        self.verifier = None;
        self
    }

    /// Encodes the signature as canonical qualified Base64 (`qb64`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.material()?.qb64()?)
    }

    /// Encodes the signature as UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb64_bytes()?)
    }

    /// Encodes the signature as canonical qualified binary (`qb2`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb2(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb2()?)
    }

    fn material(&self) -> Result<QualifiedMaterial, CryptoError> {
        Ok(QualifiedMaterial::new(self.code(), &self.raw)?)
    }

    fn from_parsed_material(parsed: ParsedMaterial) -> Result<ParsedUnindexedSignature, CryptoError> {
        let (material, consumed) = parsed.into_parts();
        let algorithm = classification_for(material.code())?;
        let raw =
            <[u8; SIGNATURE_SIZE]>::try_from(material.raw()).map_err(|_| CryptoError::InvalidSignatureLength {
                algorithm: algorithm.name(),
                expected: SIGNATURE_SIZE,
                actual: material.raw().len(),
            })?;
        Ok(ParsedUnindexedSignature {
            signature: Self {
                algorithm,
                raw,
                verifier: None,
            },
            consumed,
        })
    }
}

impl fmt::Debug for UnindexedSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnindexedSignature")
            .field("algorithm", &self.algorithm)
            .field("has_verifier", &self.verifier.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ParsedUnindexedSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedUnindexedSignature")
            .field("signature", &self.signature)
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl TryFrom<&str> for UnindexedSignature {
    type Error = CryptoError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::from_qb64(input)
    }
}

impl FromStr for UnindexedSignature {
    type Err = CryptoError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_qb64(input)
    }
}

impl fmt::Display for UnindexedSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.qb64()
            .map_err(|_| fmt::Error)
            .and_then(|qb64| formatter.write_str(&qb64))
    }
}

const fn code_for(algorithm: SignatureAlgorithm) -> DerivationCode {
    match algorithm {
        SignatureAlgorithm::Ed25519 => DerivationCode::ED25519_SIGNATURE,
        SignatureAlgorithm::EcdsaSecp256k1 => DerivationCode::ECDSA_256K1_SIGNATURE,
        SignatureAlgorithm::EcdsaP256 => DerivationCode::ECDSA_256R1_SIGNATURE,
    }
}

fn classification_for(code: DerivationCode) -> Result<SignatureAlgorithm, CryptoError> {
    match code {
        DerivationCode::ED25519_SIGNATURE => Ok(SignatureAlgorithm::Ed25519),
        DerivationCode::ECDSA_256K1_SIGNATURE => Ok(SignatureAlgorithm::EcdsaSecp256k1),
        DerivationCode::ECDSA_256R1_SIGNATURE => Ok(SignatureAlgorithm::EcdsaP256),
        other => Err(CryptoError::InvalidSignatureCode { code: other.as_str() }),
    }
}

const fn algorithms_match(signature: SignatureAlgorithm, verifier: VerificationAlgorithm) -> bool {
    matches!(
        (signature, verifier),
        (SignatureAlgorithm::Ed25519, VerificationAlgorithm::Ed25519)
            | (SignatureAlgorithm::EcdsaP256, VerificationAlgorithm::EcdsaP256)
    )
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
    use super::*;
    use crate::verifier::KeyTransferability;

    const ED25519_QB64: &str =
        "0BB43fz0GkIj6INCvq732d7FBZxt3Gw08S1mak9TeRgStsrxiUPEKcMAP9SlJrt6sg5h2pEvTshrYz56rM8IIzcO";
    const ED25519_VERIFIER_QB64: &str = "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const P256_VERIFIER_QB64: &str = "1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ";

    #[test]
    fn raw_and_encoded_domains_round_trip_with_stream_boundaries() -> Result<(), CryptoError> {
        let signature = UnindexedSignature::from_qb64(ED25519_QB64)?;
        assert_eq!(signature.algorithm(), SignatureAlgorithm::Ed25519);
        assert_eq!(signature.code(), DerivationCode::ED25519_SIGNATURE);
        assert_eq!(signature.raw().len(), SIGNATURE_SIZE);
        assert!(signature.verifier().is_none());

        let raw = signature.raw().to_vec();
        let qb64 = signature.qb64()?;
        let qb64_bytes = signature.qb64_bytes()?;
        let qb2 = signature.qb2()?;
        assert_eq!(
            UnindexedSignature::from_raw(SignatureAlgorithm::Ed25519, &raw)?,
            signature
        );
        assert_eq!(UnindexedSignature::from_qb64_bytes(&qb64_bytes)?, signature);
        assert_eq!(UnindexedSignature::from_qb2(&qb2)?, signature);
        assert_eq!(UnindexedSignature::try_from(qb64.as_str())?, signature);
        assert_eq!(qb64.parse::<UnindexedSignature>()?, signature);
        assert_eq!(signature.to_string(), qb64);

        let text_stream = format!("{qb64}ABCD");
        let parsed_text = UnindexedSignature::parse_qb64(&text_stream)?;
        assert_eq!(parsed_text.signature(), &signature);
        assert_eq!(parsed_text.consumed(), qb64.len());
        assert!(UnindexedSignature::from_qb64(&text_stream).is_err());

        let mut raw_stream = raw;
        raw_stream.push(0xff);
        let parsed_raw = UnindexedSignature::parse_raw_prefix(SignatureAlgorithm::Ed25519, &raw_stream)?;
        assert_eq!(parsed_raw.into_parts(), (signature.clone(), SIGNATURE_SIZE));
        assert!(UnindexedSignature::from_raw(SignatureAlgorithm::Ed25519, &raw_stream).is_err());

        let mut binary_stream = qb2.clone();
        binary_stream.extend_from_slice(&[1, 2, 3]);
        let parsed_binary = UnindexedSignature::parse_qb2(&binary_stream)?;
        assert_eq!(parsed_binary.signature(), &signature);
        assert_eq!(parsed_binary.consumed(), qb2.len());
        assert!(UnindexedSignature::from_qb2(&binary_stream).is_err());
        Ok(())
    }

    #[test]
    fn verifier_association_is_immutable_compatible_and_removable() -> Result<(), CryptoError> {
        let verifier = VerificationKey::from_qb64(ED25519_VERIFIER_QB64)?;
        let signature = UnindexedSignature::from_qb64(ED25519_QB64)?.with_verifier(verifier.clone())?;
        assert_eq!(signature.verifier(), Some(&verifier));
        let detached = signature.without_verifier();
        assert!(detached.verifier().is_none());

        let from_raw =
            UnindexedSignature::from_raw_with_verifier(SignatureAlgorithm::Ed25519, detached.raw(), verifier.clone())?;
        assert_eq!(from_raw.verifier(), Some(&verifier));

        let p256 = VerificationKey::from_qb64(P256_VERIFIER_QB64)?;
        assert!(matches!(
            detached.with_verifier(p256),
            Err(CryptoError::SignatureVerifierMismatch {
                signature_algorithm: "Ed25519",
                verifier_algorithm: "P-256 ECDSA/SHA-256",
            })
        ));
        Ok(())
    }

    #[test]
    fn all_signature_codes_are_classified_and_other_codes_are_rejected() -> Result<(), CryptoError> {
        for algorithm in [
            SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::EcdsaSecp256k1,
            SignatureAlgorithm::EcdsaP256,
        ] {
            let signature = UnindexedSignature::from_raw(algorithm, &[0_u8; SIGNATURE_SIZE])?;
            assert_eq!(signature.algorithm(), algorithm);
            assert_eq!(UnindexedSignature::from_qb64(&signature.qb64()?)?, signature);
        }

        let digest = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &[0_u8; 32])?;
        assert!(matches!(
            UnindexedSignature::from_qb64(&digest.qb64()?),
            Err(CryptoError::InvalidSignatureCode { code: "E" })
        ));
        Ok(())
    }

    #[test]
    fn malformed_widths_and_secp256k1_verifier_association_are_rejected() -> Result<(), CryptoError> {
        assert!(UnindexedSignature::from_raw(SignatureAlgorithm::Ed25519, &[0_u8; 63]).is_err());
        assert!(UnindexedSignature::from_raw(SignatureAlgorithm::Ed25519, &[0_u8; 65]).is_err());

        let verifier = VerificationKey::from_raw(
            VerificationAlgorithm::Ed25519,
            KeyTransferability::Transferable,
            &[
                3, 161, 7, 191, 243, 206, 16, 190, 29, 112, 221, 24, 231, 75, 192, 153, 103, 228, 214, 48, 155, 165,
                13, 95, 29, 220, 134, 100, 18, 85, 49, 184,
            ],
        )?;
        let signature = UnindexedSignature::from_raw(SignatureAlgorithm::EcdsaSecp256k1, &[0_u8; SIGNATURE_SIZE])?;
        assert!(matches!(
            signature.with_verifier(verifier),
            Err(CryptoError::SignatureVerifierMismatch {
                signature_algorithm: "secp256k1 ECDSA",
                verifier_algorithm: "Ed25519",
            })
        ));
        Ok(())
    }

    #[test]
    fn debug_output_omits_signature_and_verifier_material() -> Result<(), CryptoError> {
        let signature = UnindexedSignature::from_qb64(ED25519_QB64)?;
        let debug = format!("{signature:?}");
        assert!(debug.contains("Ed25519"));
        assert!(debug.contains("has_verifier"));
        assert!(!debug.contains(ED25519_QB64));
        assert!(!debug.contains("78ddfc"));
        Ok(())
    }
}
