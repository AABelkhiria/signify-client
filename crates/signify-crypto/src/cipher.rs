//! Typed CESR-qualified ciphertext material.
//!
//! The pinned TypeScript `Cipher` supports the two fixed X25519 sealed-box ciphertext codes used
//! to wrap qualified signing seeds and salts. This module models those payload forms explicitly;
//! encryption and decryption belong to later roadmap items.

use std::{fmt, str::FromStr};

use signify_cesr::{
    CesrError,
    code::DerivationCode,
    matter::{ParsedMaterial, QualifiedMaterial},
};

use crate::CryptoError;

/// Raw byte width of ciphertext wrapping a 44-character qualified signing seed.
pub const SEED_CIPHERTEXT_RAW_SIZE: usize = 92;

/// Raw byte width of ciphertext wrapping a 24-character qualified salt.
pub const SALT_CIPHERTEXT_RAW_SIZE: usize = 72;

/// The qualified plaintext form carried by a supported ciphertext.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CiphertextKind {
    /// An X25519 sealed-box ciphertext wrapping qualified signing-seed material (`P`).
    QualifiedSeed,
    /// An X25519 sealed-box ciphertext wrapping qualified salt material (`1AAH`).
    QualifiedSalt,
}

impl CiphertextKind {
    /// Returns the CESR derivation code for this ciphertext form.
    #[must_use]
    pub const fn code(self) -> DerivationCode {
        match self {
            Self::QualifiedSeed => DerivationCode::X25519_CIPHER_SEED,
            Self::QualifiedSalt => DerivationCode::X25519_CIPHER_SALT,
        }
    }

    /// Returns the exact raw ciphertext width selected by this form.
    #[must_use]
    pub const fn raw_size(self) -> usize {
        match self {
            Self::QualifiedSeed => SEED_CIPHERTEXT_RAW_SIZE,
            Self::QualifiedSalt => SALT_CIPHERTEXT_RAW_SIZE,
        }
    }
}

impl TryFrom<DerivationCode> for CiphertextKind {
    type Error = CryptoError;

    fn try_from(code: DerivationCode) -> Result<Self, Self::Error> {
        match code {
            DerivationCode::X25519_CIPHER_SEED => Ok(Self::QualifiedSeed),
            DerivationCode::X25519_CIPHER_SALT => Ok(Self::QualifiedSalt),
            other => Err(CryptoError::InvalidCiphertextCode { code: other.as_str() }),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
enum CiphertextBytes {
    QualifiedSeed([u8; SEED_CIPHERTEXT_RAW_SIZE]),
    QualifiedSalt([u8; SALT_CIPHERTEXT_RAW_SIZE]),
}

impl CiphertextBytes {
    const fn as_slice(&self) -> &[u8] {
        match self {
            Self::QualifiedSeed(raw) => raw,
            Self::QualifiedSalt(raw) => raw,
        }
    }
}

/// One immutable, CESR-qualified ciphertext.
///
/// Construction validates the ciphertext kind and exact raw width. Encoded constructors enforce
/// canonical CESR spelling and whole-input consumption, while prefix parsers report the boundary
/// of one ciphertext in a stream. Ciphertext is non-secret public transport material and may be
/// cloned, but debug output omits its bytes because it normally carries encrypted secrets.
///
/// ```
/// use signify_crypto::cipher::{Ciphertext, CiphertextKind, SALT_CIPHERTEXT_RAW_SIZE};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let ciphertext = Ciphertext::from_raw(
///     CiphertextKind::QualifiedSalt,
///     &[0_u8; SALT_CIPHERTEXT_RAW_SIZE],
/// )?;
/// assert_eq!(ciphertext.kind(), CiphertextKind::QualifiedSalt);
/// assert_eq!(Ciphertext::from_qb64(&ciphertext.qb64()?)?, ciphertext);
/// # Ok(())
/// # }
/// ```
///
/// Invalid ciphertext state cannot be assembled directly:
///
/// ```compile_fail
/// use signify_crypto::cipher::{Ciphertext, CiphertextKind};
///
/// let invalid = Ciphertext {
///     kind: CiphertextKind::QualifiedSeed,
///     raw: vec![0_u8; 3],
/// };
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Ciphertext {
    kind: CiphertextKind,
    raw: CiphertextBytes,
}

/// One ciphertext parsed from the front of a raw, qb64, or qb2 stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedCiphertext {
    ciphertext: Ciphertext,
    consumed: usize,
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ciphertext")
            .field("kind", &self.kind)
            .field("raw_length", &self.raw().len())
            .finish_non_exhaustive()
    }
}

impl ParsedCiphertext {
    /// Returns the parsed ciphertext.
    #[must_use]
    pub const fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the ciphertext from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (Ciphertext, usize) {
        (self.ciphertext, self.consumed)
    }
}

impl Ciphertext {
    /// Constructs a ciphertext from exactly one raw value of the selected kind.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation error for short input and a trailing-material error for long
    /// input.
    pub fn from_raw(kind: CiphertextKind, input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_raw_prefix(kind, input)?;
        reject_trailing("ciphertext raw material", input.len(), parsed.consumed)?;
        Ok(parsed.ciphertext)
    }

    /// Infers the ciphertext kind from an exact supported raw width.
    ///
    /// This safely replaces the pinned constructor's raw-length inference, which accidentally
    /// classifies a 92-byte seed ciphertext as a salt ciphertext and truncates it.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidCiphertextLength`] unless `input` is exactly 72 or 92 bytes.
    pub fn infer_from_raw(input: &[u8]) -> Result<Self, CryptoError> {
        let kind = match input.len() {
            SEED_CIPHERTEXT_RAW_SIZE => CiphertextKind::QualifiedSeed,
            SALT_CIPHERTEXT_RAW_SIZE => CiphertextKind::QualifiedSalt,
            actual => return Err(CryptoError::InvalidCiphertextLength { actual }),
        };
        Self::from_raw(kind, input)
    }

    /// Parses one ciphertext of `kind` from the beginning of a raw byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation or CESR size error.
    pub fn parse_raw_prefix(kind: CiphertextKind, input: &[u8]) -> Result<ParsedCiphertext, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_raw_prefix(
            kind.code(),
            input,
            kind.raw_size(),
        )?)
    }

    /// Parses one canonical qb64 ciphertext from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error and rejects every derivation code other than `P` and `1AAH`.
    pub fn parse_qb64(input: &str) -> Result<ParsedCiphertext, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qb64 ciphertext.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("ciphertext qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.ciphertext)
    }

    /// Parses one UTF-8 qb64 ciphertext from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8, CESR, or ciphertext-code error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedCiphertext, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64_bytes(input)?)
    }

    /// Parses exactly one UTF-8 qb64 ciphertext from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing("ciphertext qualified Base64 bytes", input.len(), parsed.consumed)?;
        Ok(parsed.ciphertext)
    }

    /// Parses one canonical qualified-binary (`qb2`) ciphertext from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error and rejects every derivation code other than `P` and `1AAH`.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedCiphertext, CryptoError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qualified-binary (`qb2`) ciphertext.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CryptoError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("ciphertext qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.ciphertext)
    }

    /// Returns the qualified plaintext form carried by this ciphertext.
    #[must_use]
    pub const fn kind(&self) -> CiphertextKind {
        self.kind
    }

    /// Returns the ciphertext's CESR derivation code.
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        self.kind.code()
    }

    /// Returns the exact raw ciphertext bytes.
    #[must_use]
    pub const fn raw(&self) -> &[u8] {
        self.raw.as_slice()
    }

    /// Encodes the ciphertext as canonical qualified Base64 (`qb64`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64(&self) -> Result<String, CryptoError> {
        Ok(self.material()?.qb64()?)
    }

    /// Encodes the ciphertext as UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb64_bytes()?)
    }

    /// Encodes the ciphertext as canonical qualified binary (`qb2`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb2(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.material()?.qb2()?)
    }

    fn material(&self) -> Result<QualifiedMaterial, CryptoError> {
        Ok(QualifiedMaterial::new(self.code(), self.raw())?)
    }

    fn from_parsed_material(parsed: ParsedMaterial) -> Result<ParsedCiphertext, CryptoError> {
        let (material, consumed) = parsed.into_parts();
        let kind = CiphertextKind::try_from(material.code())?;
        let raw = match kind {
            CiphertextKind::QualifiedSeed => CiphertextBytes::QualifiedSeed(
                <[u8; SEED_CIPHERTEXT_RAW_SIZE]>::try_from(material.raw()).map_err(|_| {
                    CryptoError::from(CesrError::RawSizeMismatch {
                        context: "seed ciphertext raw material",
                        expected: SEED_CIPHERTEXT_RAW_SIZE,
                        actual: material.raw().len(),
                    })
                })?,
            ),
            CiphertextKind::QualifiedSalt => CiphertextBytes::QualifiedSalt(
                <[u8; SALT_CIPHERTEXT_RAW_SIZE]>::try_from(material.raw()).map_err(|_| {
                    CryptoError::from(CesrError::RawSizeMismatch {
                        context: "salt ciphertext raw material",
                        expected: SALT_CIPHERTEXT_RAW_SIZE,
                        actual: material.raw().len(),
                    })
                })?,
            ),
        };
        Ok(ParsedCiphertext {
            ciphertext: Self { kind, raw },
            consumed,
        })
    }
}

impl TryFrom<&[u8]> for Ciphertext {
    type Error = CryptoError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::infer_from_raw(input)
    }
}

impl TryFrom<&str> for Ciphertext {
    type Error = CryptoError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::from_qb64(input)
    }
}

impl FromStr for Ciphertext {
    type Err = CryptoError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_qb64(input)
    }
}

impl fmt::Display for Ciphertext {
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
    use super::*;

    const SEED_QB64: &str = "PM9jOGWNYfjM_oLXJNaQ8UlFSAV5ACjsUY7J16xfzrlpc9Ve3A5WYrZ4o_NHtP5lhp78Usspl9fyFdnCdItNd5JyqZ6dt8SXOt6TOqOCs-gy0obrwFkPPqBvVkEw";
    const SALT_QB64: &str =
        "1AAHjlR2QR9J5Et67Wy-ZaVdTryN6T6ohg44r73GLRPnHw-5S3ABFkhWyIwLOI6TXUB_5CT13S8JvknxLxBaF8ANPK9FSOPD8tYu";

    #[test]
    fn reference_ciphertexts_parse_and_display() -> Result<(), CryptoError> {
        let seed = Ciphertext::from_qb64(SEED_QB64)?;
        assert_eq!(seed.kind(), CiphertextKind::QualifiedSeed);
        assert_eq!(seed.code(), DerivationCode::X25519_CIPHER_SEED);
        assert_eq!(seed.raw().len(), SEED_CIPHERTEXT_RAW_SIZE);
        assert_eq!(seed.to_string(), SEED_QB64);

        let salt = Ciphertext::from_qb64(SALT_QB64)?;
        assert_eq!(salt.kind(), CiphertextKind::QualifiedSalt);
        assert_eq!(salt.code(), DerivationCode::X25519_CIPHER_SALT);
        assert_eq!(salt.raw().len(), SALT_CIPHERTEXT_RAW_SIZE);
        assert_eq!(salt.to_string(), SALT_QB64);
        Ok(())
    }

    #[test]
    fn raw_and_encoded_domains_round_trip_with_stream_boundaries() -> Result<(), CryptoError> {
        for qb64 in [SEED_QB64, SALT_QB64] {
            let ciphertext = Ciphertext::from_qb64(qb64)?;
            assert_eq!(Ciphertext::from_raw(ciphertext.kind(), ciphertext.raw())?, ciphertext);
            assert_eq!(Ciphertext::infer_from_raw(ciphertext.raw())?, ciphertext);
            assert_eq!(Ciphertext::try_from(ciphertext.raw())?, ciphertext);
            assert_eq!(Ciphertext::try_from(qb64)?, ciphertext);
            assert_eq!(qb64.parse::<Ciphertext>()?, ciphertext);
            assert_eq!(Ciphertext::from_qb64_bytes(&ciphertext.qb64_bytes()?)?, ciphertext);
            assert_eq!(Ciphertext::from_qb2(&ciphertext.qb2()?)?, ciphertext);

            let text_stream = format!("{qb64}ABCD");
            let parsed_text = Ciphertext::parse_qb64(&text_stream)?;
            assert_eq!(parsed_text.ciphertext(), &ciphertext);
            assert_eq!(parsed_text.consumed(), qb64.len());
            assert!(Ciphertext::from_qb64(&text_stream).is_err());

            let mut raw_stream = ciphertext.raw().to_vec();
            raw_stream.extend_from_slice(&[1, 2, 3]);
            let parsed_raw = Ciphertext::parse_raw_prefix(ciphertext.kind(), &raw_stream)?;
            assert_eq!(parsed_raw.into_parts(), (ciphertext.clone(), ciphertext.raw().len()));
            assert!(Ciphertext::from_raw(ciphertext.kind(), &raw_stream).is_err());

            let mut binary_stream = ciphertext.qb2()?;
            let binary_length = binary_stream.len();
            binary_stream.extend_from_slice(&[1, 2, 3]);
            let parsed_binary = Ciphertext::parse_qb2(&binary_stream)?;
            assert_eq!(parsed_binary.into_parts(), (ciphertext, binary_length));
            assert!(Ciphertext::from_qb2(&binary_stream).is_err());
        }
        Ok(())
    }

    #[test]
    fn raw_widths_are_strict_and_inference_is_safe() {
        for (kind, size) in [
            (CiphertextKind::QualifiedSeed, SEED_CIPHERTEXT_RAW_SIZE),
            (CiphertextKind::QualifiedSalt, SALT_CIPHERTEXT_RAW_SIZE),
        ] {
            assert!(matches!(
                Ciphertext::from_raw(kind, &vec![0_u8; size - 1]),
                Err(CryptoError::Cesr { source })
                    if matches!(source.as_ref(), CesrError::Truncated { .. })
            ));
            assert!(matches!(
                Ciphertext::from_raw(kind, &vec![0_u8; size + 1]),
                Err(CryptoError::Cesr { source })
                    if matches!(source.as_ref(), CesrError::TrailingMaterial { length: 1, .. })
            ));
        }
        assert!(matches!(
            Ciphertext::infer_from_raw(&[0_u8; 80]),
            Err(CryptoError::InvalidCiphertextLength { actual: 80 })
        ));
        assert!(matches!(
            Ciphertext::infer_from_raw(&[0_u8; SEED_CIPHERTEXT_RAW_SIZE]),
            Ok(ciphertext) if ciphertext.kind() == CiphertextKind::QualifiedSeed
        ));
    }

    #[test]
    fn ciphertext_code_validation_rejects_other_material() -> Result<(), CryptoError> {
        assert!(matches!(
            CiphertextKind::try_from(DerivationCode::BLAKE3_256),
            Err(CryptoError::InvalidCiphertextCode { code: "E" })
        ));
        let digest = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &[0_u8; 32])?;
        assert!(matches!(
            Ciphertext::from_qb64(&digest.qb64()?),
            Err(CryptoError::InvalidCiphertextCode { code: "E" })
        ));
        assert!(matches!(
            Ciphertext::from_qb2(&digest.qb2()?),
            Err(CryptoError::InvalidCiphertextCode { code: "E" })
        ));
        Ok(())
    }

    #[test]
    fn debug_output_omits_ciphertext_bytes() -> Result<(), CryptoError> {
        let ciphertext = Ciphertext::from_raw(CiphertextKind::QualifiedSalt, &[0xab_u8; SALT_CIPHERTEXT_RAW_SIZE])?;
        let debug = format!("{ciphertext:?}");
        assert!(debug.contains("QualifiedSalt"));
        assert!(debug.contains("raw_length: 72"));
        assert!(!debug.contains("171"));
        assert!(!debug.contains("abab"));
        Ok(())
    }
}
