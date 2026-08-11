//! CESR-qualified digest material and verification.
//!
//! The pinned TypeScript `Diger` supports BLAKE3-256 only. This module models that supported
//! algorithm explicitly, rejects every other CESR digest code before use, and composes the
//! qualified-material engine without exposing a generic crypto-material inheritance hierarchy.

use std::{fmt, str::FromStr};

use signify_cesr::{
    CesrError,
    code::{CodeFamily, DerivationCode},
    matter::{ParsedMaterial, QualifiedMaterial},
};

use crate::CryptoError;

/// Raw byte width of every currently supported digest.
pub const DIGEST_RAW_SIZE: usize = blake3::OUT_LEN;

/// A digest algorithm supported by the pinned Signify reference.
///
/// This enum is non-exhaustive so later reference-supported algorithms can be added without making
/// downstream exhaustive matches part of the compatibility contract.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// Unkeyed BLAKE3 with a 256-bit output and CESR code `E`.
    #[default]
    Blake3_256,
}

impl DigestAlgorithm {
    /// Returns the CESR derivation code for this digest algorithm.
    #[must_use]
    pub const fn code(self) -> DerivationCode {
        match self {
            Self::Blake3_256 => DerivationCode::BLAKE3_256,
        }
    }
}

impl TryFrom<DerivationCode> for DigestAlgorithm {
    type Error = CryptoError;

    fn try_from(code: DerivationCode) -> Result<Self, Self::Error> {
        match code {
            DerivationCode::BLAKE3_256 => Ok(Self::Blake3_256),
            other if other.belongs_to(CodeFamily::Digest) => {
                Err(CryptoError::UnsupportedDigestAlgorithm { code: other.as_str() })
            }
            other => Err(CryptoError::InvalidDigestCode { code: other.as_str() }),
        }
    }
}

/// One immutable, CESR-qualified digest.
///
/// The raw bytes are public verification material rather than a secret. Construction validates the
/// selected algorithm and exact raw width; encoded parsers additionally enforce canonical CESR
/// spelling and whole-input consumption. Equality and [`Self::verify`] compare digest bytes in
/// constant time through the audited BLAKE3 hash type.
///
/// ```
/// use signify_crypto::digest::{Digest, DigestAlgorithm};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let serialization = b"abcdefghijklmnopqrstuvwxyz0123456789";
/// let digest = Digest::derive(DigestAlgorithm::Blake3_256, serialization);
/// assert_eq!(digest.qb64()?, "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux");
/// assert!(digest.verify(serialization));
/// assert_eq!(Digest::from_qb64(&digest.qb64()?)?, digest);
/// # Ok(())
/// # }
/// ```
///
/// Invalid digest state cannot be assembled directly:
///
/// ```compile_fail
/// use signify_crypto::digest::{Digest, DigestAlgorithm};
///
/// let invalid = Digest {
///     algorithm: DigestAlgorithm::Blake3_256,
///     raw: [0_u8; 31],
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Digest {
    algorithm: DigestAlgorithm,
    raw: [u8; DIGEST_RAW_SIZE],
}

/// One digest parsed from the front of a raw, qb64, or qb2 stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedDigest {
    digest: Digest,
    consumed: usize,
}

impl ParsedDigest {
    /// Returns the parsed digest.
    #[must_use]
    pub const fn digest(self) -> Digest {
        self.digest
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(self) -> usize {
        self.consumed
    }

    /// Separates the digest from its consumed input length.
    #[must_use]
    pub const fn into_parts(self) -> (Digest, usize) {
        (self.digest, self.consumed)
    }
}

impl Digest {
    /// Derives a digest over the complete serialization.
    ///
    /// This operation is infallible because [`DigestAlgorithm`] can represent only implemented
    /// algorithms and BLAKE3 accepts an arbitrary byte slice without allocating from a declared
    /// input length.
    #[must_use]
    pub fn derive(algorithm: DigestAlgorithm, serialization: &[u8]) -> Self {
        let raw = match algorithm {
            DigestAlgorithm::Blake3_256 => *blake3::hash(serialization).as_bytes(),
        };
        Self { algorithm, raw }
    }

    /// Constructs a digest from exactly one raw digest value.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation error for short input and a trailing-material error for long
    /// input.
    pub fn from_raw(algorithm: DigestAlgorithm, input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_raw_prefix(algorithm, input)?;
        reject_trailing("digest raw material", input.len(), parsed.consumed)?;
        Ok(parsed.digest)
    }

    /// Parses one fixed-width digest from the beginning of a raw byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation or CESR size error.
    pub fn parse_raw_prefix(algorithm: DigestAlgorithm, input: &[u8]) -> Result<ParsedDigest, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_raw_prefix(
            algorithm.code(),
            input,
            DIGEST_RAW_SIZE,
        )?)
    }

    /// Parses one canonical qb64 digest from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error and rejects non-digest or unsupported digest codes.
    pub fn parse_qb64(input: &str) -> Result<ParsedDigest, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qb64 digest.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("digest qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.digest)
    }

    /// Parses one UTF-8 qb64 digest from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8, CESR, or digest-code error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedDigest, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64_bytes(input)?)
    }

    /// Parses exactly one UTF-8 qb64 digest from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing("digest qualified Base64 bytes", input.len(), parsed.consumed)?;
        Ok(parsed.digest)
    }

    /// Parses one canonical qualified-binary (`qb2`) digest from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error and rejects non-digest or unsupported digest codes.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedDigest, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qualified-binary (`qb2`) digest.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("digest qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.digest)
    }

    /// Returns the validated digest algorithm.
    #[must_use]
    pub const fn algorithm(self) -> DigestAlgorithm {
        self.algorithm
    }

    /// Returns the digest's CESR derivation code.
    #[must_use]
    pub const fn code(self) -> DerivationCode {
        self.algorithm.code()
    }

    /// Returns the exact raw digest bytes.
    #[must_use]
    pub const fn raw(&self) -> &[u8; DIGEST_RAW_SIZE] {
        &self.raw
    }

    /// Encodes the digest as canonical qualified Base64 (`qb64`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64(self) -> Result<String, CryptoError> {
        Ok(self.material()?.qb64()?)
    }

    /// Encodes the digest as UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64_bytes(self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb64_bytes()?)
    }

    /// Encodes the digest as canonical qualified binary (`qb2`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb2(self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb2()?)
    }

    /// Verifies that `serialization` hashes to this digest.
    ///
    /// The digest comparison is constant time. Serialization length is public and hashing time is
    /// necessarily proportional to it.
    #[must_use]
    pub fn verify(&self, serialization: &[u8]) -> bool {
        match self.algorithm {
            DigestAlgorithm::Blake3_256 => blake3::hash(serialization) == blake3::Hash::from_bytes(self.raw),
        }
    }

    /// Compares two digests as commitments to `serialization`.
    ///
    /// Exact encoded equality succeeds immediately. Digests using the same algorithm but different
    /// values cannot both represent the serialization. If future reference-compatible algorithms
    /// are added, different algorithms compare equal only when both independently verify the same
    /// bytes.
    ///
    /// The pinned TypeScript fast paths accidentally compare a byte array by JavaScript object
    /// identity/string coercion and return false even for identical `Diger` values. Rust implements
    /// the method's documented semantic intent; this deliberate divergence is fixture-pinned.
    #[must_use]
    pub fn compare(&self, serialization: &[u8], other: &Self) -> bool {
        if self == other {
            return true;
        }
        if self.algorithm == other.algorithm {
            return false;
        }
        self.verify(serialization) && other.verify(serialization)
    }

    fn material(self) -> Result<QualifiedMaterial, CryptoError> {
        Ok(QualifiedMaterial::new(self.code(), &self.raw)?)
    }

    fn from_parsed_material(parsed: ParsedMaterial) -> Result<ParsedDigest, CryptoError> {
        let (material, consumed) = parsed.into_parts();
        let algorithm = DigestAlgorithm::try_from(material.code())?;
        let raw = <[u8; DIGEST_RAW_SIZE]>::try_from(material.raw()).map_err(|_| {
            CryptoError::from(CesrError::RawSizeMismatch {
                context: "digest raw material",
                expected: DIGEST_RAW_SIZE,
                actual: material.raw().len(),
            })
        })?;
        Ok(ParsedDigest {
            digest: Self { algorithm, raw },
            consumed,
        })
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && blake3::Hash::from_bytes(self.raw) == blake3::Hash::from_bytes(other.raw)
    }
}

impl Eq for Digest {}

impl TryFrom<&[u8]> for Digest {
    type Error = CryptoError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::from_raw(DigestAlgorithm::default(), input)
    }
}

impl TryFrom<&str> for Digest {
    type Error = CryptoError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::from_qb64(input)
    }
}

impl FromStr for Digest {
    type Err = CryptoError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_qb64(input)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.qb64()
            .map_err(|_| fmt::Error)
            .and_then(|qb64| formatter.write_str(&qb64))
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

    const REFERENCE_SERIALIZATION: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const REFERENCE_QB64: &str = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";

    #[test]
    fn reference_digest_derives_and_verifies() -> Result<(), CryptoError> {
        let digest = Digest::derive(DigestAlgorithm::Blake3_256, REFERENCE_SERIALIZATION);
        assert_eq!(digest.algorithm(), DigestAlgorithm::Blake3_256);
        assert_eq!(digest.code(), DerivationCode::BLAKE3_256);
        assert_eq!(digest.raw().len(), DIGEST_RAW_SIZE);
        assert_eq!(digest.qb64()?, REFERENCE_QB64);
        assert_eq!(digest.to_string(), REFERENCE_QB64);
        assert!(digest.verify(REFERENCE_SERIALIZATION));
        assert!(!digest.verify(b"abcdefghijklmnopqrstuvwxyz01234567892j2idjpwjfepjtgi"));
        Ok(())
    }

    #[test]
    fn raw_and_encoded_domains_round_trip_with_stream_boundaries() -> Result<(), CryptoError> {
        let digest = Digest::derive(DigestAlgorithm::default(), REFERENCE_SERIALIZATION);
        assert_eq!(Digest::from_raw(DigestAlgorithm::default(), digest.raw())?, digest);
        assert_eq!(Digest::try_from(digest.raw().as_slice())?, digest);

        let qb64 = digest.qb64()?;
        let qb64_bytes = digest.qb64_bytes()?;
        let qb2 = digest.qb2()?;
        assert_eq!(Digest::from_qb64(&qb64)?, digest);
        assert_eq!(Digest::try_from(qb64.as_str())?, digest);
        assert_eq!(qb64.parse::<Digest>()?, digest);
        assert_eq!(Digest::from_qb64_bytes(&qb64_bytes)?, digest);
        assert_eq!(Digest::from_qb2(&qb2)?, digest);

        let text_stream = format!("{qb64}ABCD");
        let parsed_text = Digest::parse_qb64(&text_stream)?;
        assert_eq!(parsed_text.into_parts(), (digest, qb64.len()));
        assert!(matches!(
            Digest::from_qb64(&text_stream),
            Err(CryptoError::Cesr { source })
                if matches!(source.as_ref(), CesrError::TrailingMaterial { length: 4, .. })
        ));

        let mut binary_stream = qb2.clone();
        binary_stream.extend_from_slice(&[1, 2, 3]);
        let parsed_binary = Digest::parse_qb2(&binary_stream)?;
        assert_eq!(parsed_binary.digest(), digest);
        assert_eq!(parsed_binary.consumed(), qb2.len());
        assert!(Digest::from_qb2(&binary_stream).is_err());
        Ok(())
    }

    #[test]
    fn raw_width_is_strict() {
        assert!(matches!(
            Digest::from_raw(DigestAlgorithm::default(), &[0_u8; DIGEST_RAW_SIZE - 1]),
            Err(CryptoError::Cesr { source }) if matches!(source.as_ref(), CesrError::Truncated { .. })
        ));
        assert!(matches!(
            Digest::from_raw(DigestAlgorithm::default(), &[0_u8; DIGEST_RAW_SIZE + 1]),
            Err(CryptoError::Cesr { source })
                if matches!(source.as_ref(), CesrError::TrailingMaterial { length: 1, .. })
        ));
    }

    #[test]
    fn digest_code_validation_distinguishes_invalid_and_unsupported() -> Result<(), CryptoError> {
        assert!(matches!(
            DigestAlgorithm::try_from(DerivationCode::SHA3_256),
            Err(CryptoError::UnsupportedDigestAlgorithm { code: "H" })
        ));
        assert!(matches!(
            DigestAlgorithm::try_from(DerivationCode::ED25519),
            Err(CryptoError::InvalidDigestCode { code: "D" })
        ));

        let unsupported = QualifiedMaterial::new(DerivationCode::SHA3_256, &[0_u8; DIGEST_RAW_SIZE])?;
        assert!(matches!(
            Digest::from_qb64(&unsupported.qb64()?),
            Err(CryptoError::UnsupportedDigestAlgorithm { code: "H" })
        ));
        let invalid = QualifiedMaterial::new(DerivationCode::ED25519, &[0_u8; DIGEST_RAW_SIZE])?;
        assert!(matches!(
            Digest::from_qb2(&invalid.qb2()?),
            Err(CryptoError::InvalidDigestCode { code: "D" })
        ));
        Ok(())
    }

    #[test]
    fn compare_implements_digest_semantics() {
        let digest = Digest::derive(DigestAlgorithm::default(), REFERENCE_SERIALIZATION);
        let copy = digest;
        let different = Digest::derive(DigestAlgorithm::default(), b"different serialization");
        assert!(digest.compare(REFERENCE_SERIALIZATION, &copy));
        assert!(!digest.compare(REFERENCE_SERIALIZATION, &different));
    }

    #[test]
    fn crypto_error_preserves_cesr_source() {
        let error = Digest::from_qb64("").err().ok_or("empty digest input was accepted");
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
