//! CESR-qualified indexed and unindexed signatures with optional verifier association.
//!
//! The pinned TypeScript `Cigar` and `Siger` types inherit generic material classes and expose a
//! mutable optional verifier. This module instead validates each signature code, composes the
//! corresponding CESR material engine, and associates a verifier immutably only when its algorithm
//! matches.

use std::{fmt, str::FromStr};

use signify_cesr::{
    CesrError,
    bytes::utf8_text,
    code::DerivationCode,
    indexer::{IndexedMaterial, IndexedSignatureAlgorithm, IndexedSignatureScope, IndexerCode, ParsedIndexer},
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

/// One immutable CESR indexed signature.
///
/// The derivation code determines the signature algorithm, current/prior-list scope, raw byte
/// width, and index widths. Construction delegates those wire invariants to the verified CESR
/// indexed-material engine. It does not claim that the bytes authenticate a message; verification
/// remains the associated [`VerificationKey`]'s responsibility. Ed448 and secp256k1 material can
/// be represented for wire compatibility, but no compatible verification key exists in the
/// pinned reference.
///
/// ```
/// use signify_cesr::indexer::IndexerCode;
/// use signify_crypto::signature::IndexedSignature;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let signature = IndexedSignature::from_raw(
///     IndexerCode::ED25519,
///     3,
///     None,
///     &[0_u8; 64],
/// )?;
/// assert_eq!(signature.index(), 3);
/// assert_eq!(signature.other_index(), Some(3));
/// assert_eq!(signature.qb64()?.len(), 88);
/// # Ok(())
/// # }
/// ```
///
/// Invalid indexed-signature state cannot be assembled directly:
///
/// ```compile_fail
/// use signify_crypto::signature::IndexedSignature;
///
/// let invalid = IndexedSignature {
///     material: (),
///     algorithm: (),
///     scope: (),
///     verifier: None,
/// };
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct IndexedSignature {
    material: IndexedMaterial,
    algorithm: IndexedSignatureAlgorithm,
    scope: IndexedSignatureScope,
    verifier: Option<VerificationKey>,
}

/// One indexed signature parsed from the front of a raw, qb64, or qb2 stream.
#[derive(Clone, Eq, PartialEq)]
pub struct ParsedIndexedSignature {
    signature: IndexedSignature,
    consumed: usize,
}

impl ParsedIndexedSignature {
    /// Returns the parsed signature by reference.
    #[must_use]
    pub const fn signature(&self) -> &IndexedSignature {
        &self.signature
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the signature from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (IndexedSignature, usize) {
        (self.signature, self.consumed)
    }
}

impl IndexedSignature {
    /// Constructs one indexed signature from exact raw bytes and validated indices.
    ///
    /// Passing `None` for a both-list code defaults the prior-list index to `index`. Current-only
    /// codes require `None`.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR error for a table-only code, wrong raw width, invalid index, invalid
    /// current/prior relationship, or arithmetic overflow.
    pub fn from_raw(
        code: IndexerCode,
        index: u32,
        other_index: Option<u32>,
        input: &[u8],
    ) -> Result<Self, CryptoError> {
        let parsed = Self::parse_raw_prefix(code, index, other_index, input)?;
        reject_trailing("indexed-signature raw material", input.len(), parsed.consumed)?;
        Ok(parsed.signature)
    }

    /// Constructs one exact indexed signature and associates a compatible verifier.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::from_raw`] or a verifier-algorithm mismatch.
    pub fn from_raw_with_verifier(
        code: IndexerCode,
        index: u32,
        other_index: Option<u32>,
        input: &[u8],
        verifier: VerificationKey,
    ) -> Result<Self, CryptoError> {
        Self::from_raw(code, index, other_index, input)?.with_verifier(verifier)
    }

    /// Parses one indexed signature from the beginning of a raw byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR error for a table-only code, invalid indices, or truncated input.
    pub fn parse_raw_prefix(
        code: IndexerCode,
        index: u32,
        other_index: Option<u32>,
        input: &[u8],
    ) -> Result<ParsedIndexedSignature, CryptoError> {
        Self::from_parsed_indexer(IndexedMaterial::parse_raw_prefix(code, index, other_index, input)?)
    }

    /// Parses one canonical qb64 indexed signature from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR or non-signature-code error.
    pub fn parse_qb64(input: &str) -> Result<ParsedIndexedSignature, CryptoError> {
        Self::from_parsed_indexer(IndexedMaterial::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qb64 indexed signature.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("indexed-signature qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.signature)
    }

    /// Parses one UTF-8 qb64 signature from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8, CESR, or non-signature-code error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedIndexedSignature, CryptoError> {
        Self::parse_qb64(utf8_text(input)?)
    }

    /// Parses exactly one UTF-8 qb64 indexed signature from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing("indexed-signature qualified Base64 bytes", input.len(), parsed.consumed)?;
        Ok(parsed.signature)
    }

    /// Parses one canonical qualified-binary (`qb2`) indexed signature from the input prefix.
    ///
    /// # Errors
    ///
    /// Returns a typed CESR or non-signature-code error.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedIndexedSignature, CryptoError> {
        Self::from_parsed_indexer(IndexedMaterial::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qualified-binary (`qb2`) indexed signature.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("indexed-signature qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.signature)
    }

    /// Returns the indexed CESR derivation code.
    #[must_use]
    pub const fn code(&self) -> IndexerCode {
        self.material.code()
    }

    /// Returns the signature algorithm selected by the indexed code.
    #[must_use]
    pub const fn algorithm(&self) -> IndexedSignatureAlgorithm {
        self.algorithm
    }

    /// Returns whether the signature applies to the current list only or to both key lists.
    #[must_use]
    pub const fn scope(&self) -> IndexedSignatureScope {
        self.scope
    }

    /// Returns the current-list index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.material.index()
    }

    /// Returns the prior-list index for a both-list code, or `None` for current-only material.
    #[must_use]
    pub const fn other_index(&self) -> Option<u32> {
        self.material.other_index()
    }

    /// Returns the fixed-width raw signature bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.material.raw()
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
    /// the indexed-signature algorithm or no verifier implementation exists for that algorithm.
    pub fn with_verifier(mut self, verifier: VerificationKey) -> Result<Self, CryptoError> {
        if !indexed_algorithms_match(self.algorithm, verifier.algorithm()) {
            return Err(CryptoError::SignatureVerifierMismatch {
                signature_algorithm: indexed_algorithm_name(self.algorithm),
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
    /// Returns a typed error if index or length arithmetic fails.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.material.qb64()?)
    }

    /// Encodes the signature as UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error if canonical encoding fails.
    pub fn qb64_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material.qb64_bytes()?)
    }

    /// Encodes the signature as canonical qualified binary (`qb2`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if canonical encoding fails.
    pub fn qb2(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material.qb2()?)
    }

    fn from_material(material: IndexedMaterial) -> Result<Self, CryptoError> {
        let code = material.code();
        let algorithm = code
            .signature_algorithm()
            .ok_or(CryptoError::InvalidIndexedSignatureCode { code: code.as_str() })?;
        let scope = code
            .signature_scope()
            .ok_or(CryptoError::InvalidIndexedSignatureCode { code: code.as_str() })?;
        Ok(Self {
            material,
            algorithm,
            scope,
            verifier: None,
        })
    }

    fn from_parsed_indexer(parsed: ParsedIndexer) -> Result<ParsedIndexedSignature, CryptoError> {
        let consumed = parsed.consumed();
        Ok(ParsedIndexedSignature {
            signature: Self::from_material(parsed.into_material())?,
            consumed,
        })
    }
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

impl fmt::Debug for IndexedSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IndexedSignature")
            .field("code", &self.code())
            .field("algorithm", &self.algorithm)
            .field("scope", &self.scope)
            .field("index", &self.index())
            .field("other_index", &self.other_index())
            .field("has_verifier", &self.verifier.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ParsedIndexedSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedIndexedSignature")
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

impl TryFrom<&str> for IndexedSignature {
    type Error = CryptoError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::from_qb64(input)
    }
}

impl FromStr for IndexedSignature {
    type Err = CryptoError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_qb64(input)
    }
}

impl fmt::Display for IndexedSignature {
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

const fn indexed_algorithms_match(signature: IndexedSignatureAlgorithm, verifier: VerificationAlgorithm) -> bool {
    matches!(
        (signature, verifier),
        (IndexedSignatureAlgorithm::Ed25519, VerificationAlgorithm::Ed25519)
            | (
                IndexedSignatureAlgorithm::EcdsaSecp256r1,
                VerificationAlgorithm::EcdsaP256
            )
    )
}

const fn indexed_algorithm_name(algorithm: IndexedSignatureAlgorithm) -> &'static str {
    match algorithm {
        IndexedSignatureAlgorithm::Ed25519 => "Ed25519",
        IndexedSignatureAlgorithm::EcdsaSecp256k1 => "secp256k1 ECDSA",
        IndexedSignatureAlgorithm::EcdsaSecp256r1 => "P-256 ECDSA/SHA-256",
        IndexedSignatureAlgorithm::Ed448 => "Ed448",
        _ => "unknown indexed-signature algorithm",
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
    use super::*;
    use crate::verifier::KeyTransferability;

    const ED25519_QB64: &str =
        "0BB43fz0GkIj6INCvq732d7FBZxt3Gw08S1mak9TeRgStsrxiUPEKcMAP9SlJrt6sg5h2pEvTshrYz56rM8IIzcO";
    const ED25519_VERIFIER_QB64: &str = "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const P256_VERIFIER_QB64: &str = "1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ";
    const INDEXED_ED25519_QB64: &str =
        "AACsufRGYI-sRvS2c0rsOueSoSRtrjODaf48DYLJbLvvD8aHe7b2sWGebZ-y9ichhsxMF3Hhn-3LYSKIrnmH3oIN";

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

    #[test]
    fn indexed_domains_round_trip_with_stream_boundaries() -> Result<(), CryptoError> {
        let signature = IndexedSignature::from_qb64(INDEXED_ED25519_QB64)?;
        assert_eq!(signature.code(), IndexerCode::ED25519);
        assert_eq!(signature.algorithm(), IndexedSignatureAlgorithm::Ed25519);
        assert_eq!(signature.scope(), IndexedSignatureScope::BothLists);
        assert_eq!(signature.index(), 0);
        assert_eq!(signature.other_index(), Some(0));
        assert!(signature.verifier().is_none());

        let raw = signature.raw().to_vec();
        let qb64 = signature.qb64()?;
        let qb64_bytes = signature.qb64_bytes()?;
        let qb2 = signature.qb2()?;
        assert_eq!(
            IndexedSignature::from_raw(IndexerCode::ED25519, 0, None, &raw)?,
            signature
        );
        assert_eq!(IndexedSignature::from_qb64_bytes(&qb64_bytes)?, signature);
        assert_eq!(IndexedSignature::from_qb2(&qb2)?, signature);
        assert_eq!(IndexedSignature::try_from(qb64.as_str())?, signature);
        assert_eq!(qb64.parse::<IndexedSignature>()?, signature);
        assert_eq!(signature.to_string(), qb64);

        let text_stream = format!("{qb64}ABCD");
        let parsed_text = IndexedSignature::parse_qb64(&text_stream)?;
        assert_eq!(parsed_text.signature(), &signature);
        assert_eq!(parsed_text.consumed(), qb64.len());
        assert!(IndexedSignature::from_qb64(&text_stream).is_err());

        let mut raw_stream = raw;
        raw_stream.push(0xff);
        let parsed_raw = IndexedSignature::parse_raw_prefix(IndexerCode::ED25519, 0, None, &raw_stream)?;
        assert_eq!(parsed_raw.into_parts(), (signature.clone(), SIGNATURE_SIZE));
        assert!(IndexedSignature::from_raw(IndexerCode::ED25519, 0, None, &raw_stream).is_err());

        let mut binary_stream = qb2.clone();
        binary_stream.extend_from_slice(&[1, 2, 3]);
        let parsed_binary = IndexedSignature::parse_qb2(&binary_stream)?;
        assert_eq!(parsed_binary.signature(), &signature);
        assert_eq!(parsed_binary.consumed(), qb2.len());
        assert!(IndexedSignature::from_qb2(&binary_stream).is_err());
        Ok(())
    }

    #[test]
    fn indexed_verifier_association_is_compatible_and_removable() -> Result<(), CryptoError> {
        let ed25519 = VerificationKey::from_qb64(ED25519_VERIFIER_QB64)?;
        let signature = IndexedSignature::from_qb64(INDEXED_ED25519_QB64)?.with_verifier(ed25519.clone())?;
        assert_eq!(signature.verifier(), Some(&ed25519));
        let detached = signature.without_verifier();
        assert!(detached.verifier().is_none());

        let p256 = VerificationKey::from_qb64(P256_VERIFIER_QB64)?;
        assert!(matches!(
            detached.clone().with_verifier(p256.clone()),
            Err(CryptoError::SignatureVerifierMismatch {
                signature_algorithm: "Ed25519",
                verifier_algorithm: "P-256 ECDSA/SHA-256",
            })
        ));

        let p256_signature = IndexedSignature::from_raw_with_verifier(
            IndexerCode::ECDSA_256R1,
            2,
            None,
            &[0_u8; SIGNATURE_SIZE],
            p256.clone(),
        )?;
        assert_eq!(p256_signature.verifier(), Some(&p256));
        Ok(())
    }

    #[test]
    fn every_fixed_indexed_signature_code_is_semantically_classified() -> Result<(), CryptoError> {
        for code in IndexerCode::ALL.iter().copied() {
            let (Some(algorithm), Some(scope), Some(raw_size)) = (
                code.signature_algorithm(),
                code.signature_scope(),
                code.size().raw_size(),
            ) else {
                continue;
            };
            let raw = vec![0x5a; raw_size];
            let signature = IndexedSignature::from_raw(code, 3, None, &raw)?;
            assert_eq!(signature.code(), code);
            assert_eq!(signature.algorithm(), algorithm);
            assert_eq!(signature.scope(), scope);
            assert_eq!(signature.raw(), raw);
            assert_eq!(IndexedSignature::from_qb64(&signature.qb64()?)?, signature);
        }
        Ok(())
    }

    #[test]
    fn invalid_indexed_widths_relations_and_verifiers_are_rejected() -> Result<(), CryptoError> {
        assert!(IndexedSignature::from_raw(IndexerCode::ED25519, 0, None, &[0_u8; 63]).is_err());
        assert!(IndexedSignature::from_raw(IndexerCode::ED25519, 0, None, &[0_u8; 65]).is_err());
        assert!(
            IndexedSignature::from_raw(IndexerCode::ED25519_CURRENT, 0, Some(0), &[0_u8; SIGNATURE_SIZE],).is_err()
        );
        assert!(IndexedSignature::from_raw(IndexerCode::ED25519, 1, Some(2), &[0_u8; SIGNATURE_SIZE],).is_err());
        let variable = "0z".parse::<IndexerCode>()?;
        assert!(IndexedSignature::from_raw(variable, 0, None, &[]).is_err());

        let ed25519 = VerificationKey::from_qb64(ED25519_VERIFIER_QB64)?;
        let ed448 = IndexedSignature::from_raw(IndexerCode::ED448, 0, None, &[0_u8; 114])?;
        assert!(matches!(
            ed448.with_verifier(ed25519),
            Err(CryptoError::SignatureVerifierMismatch {
                signature_algorithm: "Ed448",
                verifier_algorithm: "Ed25519",
            })
        ));
        Ok(())
    }

    #[test]
    fn indexed_debug_output_omits_signature_and_verifier_material() -> Result<(), CryptoError> {
        let signature = IndexedSignature::from_qb64(INDEXED_ED25519_QB64)?;
        let debug = format!("{signature:?}");
        assert!(debug.contains("Ed25519"));
        assert!(debug.contains("index"));
        assert!(debug.contains("has_verifier"));
        assert!(!debug.contains(INDEXED_ED25519_QB64));
        assert!(!debug.contains("acb9f446"));
        Ok(())
    }
}
