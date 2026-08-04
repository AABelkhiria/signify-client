//! Fixed-width CESR sequence-number material.
//!
//! Sequence numbers are unsigned 128-bit ordinals encoded in exactly sixteen raw bytes with the
//! `0A` derivation code. The same code also denotes salt material elsewhere; this semantic wrapper
//! prevents other codes and widths from entering a sequence-number API.

use std::{fmt, str::FromStr};

use crate::{
    CesrError,
    bytes::{bytes_to_integer, utf8_text},
    code::DerivationCode,
    matter::{ParsedMaterial, QualifiedMaterial},
    number::CesrNumber,
};

/// Raw byte width of every CESR sequence number.
pub const SEQUENCE_RAW_SIZE: usize = 16;

/// An exact unsigned ordinal encoded as fixed-width CESR sequence material.
///
/// The value is stored as a `u128`; raw, qb64, and qb2 forms are derived canonically with code
/// `0A`. This preserves the complete on-wire range without JavaScript number coercion or precision
/// loss.
///
/// ```
/// use signify_cesr::{CesrError, code::DerivationCode, sequence::SequenceNumber};
///
/// # fn main() -> Result<(), CesrError> {
/// let sequence = SequenceNumber::from_hex("10")?;
/// assert_eq!(sequence.value(), 16);
/// assert_eq!(sequence.code(), DerivationCode::SALT_128);
/// assert_eq!(sequence.qb64()?, "0AAAAAAAAAAAAAAAAAAAAAAQ");
/// assert_eq!(SequenceNumber::from_qb64(&sequence.qb64()?)?, sequence);
/// # Ok(())
/// # }
/// ```
///
/// Negative ordinals are excluded by the unsigned API:
///
/// ```compile_fail
/// use signify_cesr::sequence::SequenceNumber;
///
/// let sequence = SequenceNumber::new(-1);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SequenceNumber {
    value: u128,
}

/// One sequence number parsed from the front of a raw, qb64, or qb2 stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParsedSequenceNumber {
    sequence: SequenceNumber,
    consumed: usize,
}

impl ParsedSequenceNumber {
    /// Returns the parsed sequence number.
    #[must_use]
    pub const fn sequence(self) -> SequenceNumber {
        self.sequence
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(self) -> usize {
        self.consumed
    }

    /// Separates the sequence number from its consumed input length.
    #[must_use]
    pub const fn into_parts(self) -> (SequenceNumber, usize) {
        (self.sequence, self.consumed)
    }
}

impl SequenceNumber {
    /// Canonical sequence number zero.
    pub const ZERO: Self = Self { value: 0 };

    /// Constructs an exact sequence number.
    ///
    /// Every `u128` is representable by the fixed 16-byte sequence format.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self { value }
    }

    /// Parses complete, unsigned hexadecimal sequence text.
    ///
    /// Upper- and lowercase digits and leading zeroes are accepted. Signs, whitespace, `0x`
    /// prefixes, partial parses, empty text, and input wider than 32 digits are rejected.
    ///
    /// # Errors
    ///
    /// Returns a typed empty, size, character, or arithmetic error.
    pub fn from_hex(input: &str) -> Result<Self, CesrError> {
        Ok(Self::new(CesrNumber::from_hex(input)?.value()))
    }

    /// Parses exactly one 16-byte raw sequence number.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation error for short input and a trailing-material error for long
    /// input.
    pub fn from_raw(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_raw_prefix(input)?;
        reject_trailing("CESR sequence raw material", input.len(), parsed.consumed)?;
        Ok(parsed.sequence)
    }

    /// Parses one 16-byte raw sequence number from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed truncation or numeric-conversion error.
    pub fn parse_raw_prefix(input: &[u8]) -> Result<ParsedSequenceNumber, CesrError> {
        Self::from_parsed_material(QualifiedMaterial::parse_raw_prefix(
            DerivationCode::SALT_128,
            input,
            SEQUENCE_RAW_SIZE,
        )?)
    }

    /// Parses one canonical qb64 sequence number from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error and rejects every derivation code except `0A`.
    pub fn parse_qb64(input: &str) -> Result<ParsedSequenceNumber, CesrError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qb64 sequence number.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("CESR sequence qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.sequence)
    }

    /// Parses one UTF-8 qb64 sequence number from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8 or sequence-material error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedSequenceNumber, CesrError> {
        Self::parse_qb64(utf8_text(input)?)
    }

    /// Parses exactly one UTF-8 qb64 sequence number from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing("CESR sequence qualified Base64 bytes", input.len(), parsed.consumed)?;
        Ok(parsed.sequence)
    }

    /// Parses one canonical qb2 sequence number from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error and rejects every derivation code except `0A`.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedSequenceNumber, CesrError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qb2 sequence number.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("CESR sequence qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.sequence)
    }

    /// Returns the exact unsigned ordinal.
    #[must_use]
    pub const fn value(self) -> u128 {
        self.value
    }

    /// Returns lowercase hexadecimal text without leading zeroes.
    #[must_use]
    pub fn hex(self) -> String {
        format!("{:x}", self.value)
    }

    /// Returns the mandatory fixed sequence derivation code (`0A`).
    #[must_use]
    pub const fn code(self) -> DerivationCode {
        DerivationCode::SALT_128
    }

    /// Returns the exact 16-byte big-endian raw representation.
    #[must_use]
    pub const fn raw(self) -> [u8; SEQUENCE_RAW_SIZE] {
        self.value.to_be_bytes()
    }

    /// Encodes the sequence number as canonical qualified Base64 (`qb64`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64(self) -> Result<String, CesrError> {
        self.material()?.qb64()
    }

    /// Encodes the sequence number as UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb64_bytes(self) -> Result<Vec<u8>, CesrError> {
        self.material()?.qb64_bytes()
    }

    /// Encodes the sequence number as canonical qualified binary (`qb2`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if the shared fixed-code table is internally inconsistent.
    pub fn qb2(self) -> Result<Vec<u8>, CesrError> {
        self.material()?.qb2()
    }

    fn material(self) -> Result<QualifiedMaterial, CesrError> {
        QualifiedMaterial::new(self.code(), &self.raw())
    }

    fn from_parsed_material(parsed: ParsedMaterial) -> Result<ParsedSequenceNumber, CesrError> {
        let (material, consumed) = parsed.into_parts();
        let code = material.code();
        if code != DerivationCode::SALT_128 {
            return Err(CesrError::InvalidSequenceCode { code: code.as_str() });
        }
        Ok(ParsedSequenceNumber {
            sequence: Self::new(bytes_to_integer(material.raw())?),
            consumed,
        })
    }
}

impl From<u128> for SequenceNumber {
    fn from(value: u128) -> Self {
        Self::new(value)
    }
}

impl TryFrom<&[u8]> for SequenceNumber {
    type Error = CesrError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        Self::from_raw(input)
    }
}

impl FromStr for SequenceNumber {
    type Err = CesrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_hex(input)
    }
}

impl fmt::Display for SequenceNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:x}", self.value)
    }
}

fn reject_trailing(context: &'static str, total: usize, consumed: usize) -> Result<(), CesrError> {
    let trailing = total
        .checked_sub(consumed)
        .ok_or(CesrError::LengthOverflow { context })?;
    if trailing == 0 {
        Ok(())
    } else {
        Err(CesrError::TrailingMaterial {
            context,
            length: trailing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_values_have_fixed_width_exact_outputs() -> Result<(), CesrError> {
        for (value, hex, qb64) in [
            (0_u128, "0", "0AAAAAAAAAAAAAAAAAAAAAAA"),
            (1, "1", "0AAAAAAAAAAAAAAAAAAAAAAB"),
            (15, "f", "0AAAAAAAAAAAAAAAAAAAAAAP"),
            (16, "10", "0AAAAAAAAAAAAAAAAAAAAAAQ"),
        ] {
            let sequence = SequenceNumber::new(value);
            assert_eq!(sequence.value(), value);
            assert_eq!(sequence.hex(), hex);
            assert_eq!(sequence.to_string(), hex);
            assert_eq!(sequence.code(), DerivationCode::SALT_128);
            assert_eq!(sequence.raw().len(), SEQUENCE_RAW_SIZE);
            assert_eq!(sequence.qb64()?, qb64);
        }
        assert_eq!(SequenceNumber::ZERO, SequenceNumber::from_hex("0000")?);
        assert_eq!("F".parse::<SequenceNumber>()?, SequenceNumber::new(15));
        Ok(())
    }

    #[test]
    fn raw_construction_is_exact_and_stream_aware() -> Result<(), CesrError> {
        let raw = u128::MAX.to_be_bytes();
        let sequence = SequenceNumber::from_raw(&raw)?;
        assert_eq!(sequence.value(), u128::MAX);
        assert_eq!(SequenceNumber::try_from(raw.as_slice())?, sequence);

        let mut stream = raw.to_vec();
        stream.extend_from_slice(&[1, 2]);
        let parsed = SequenceNumber::parse_raw_prefix(&stream)?;
        assert_eq!(parsed.into_parts(), (sequence, SEQUENCE_RAW_SIZE));
        assert!(matches!(
            SequenceNumber::from_raw(&stream),
            Err(CesrError::TrailingMaterial { .. })
        ));
        let short = raw.get(..SEQUENCE_RAW_SIZE - 1).ok_or(CesrError::InvalidLength {
            context: "sequence unit-test raw prefix",
            length: raw.len(),
        })?;
        assert!(matches!(
            SequenceNumber::from_raw(short),
            Err(CesrError::Truncated { .. })
        ));
        Ok(())
    }

    #[test]
    fn all_encodings_round_trip_and_prefix_parsers_report_consumption() -> Result<(), CesrError> {
        for value in [0, 1, u128::from(u64::MAX) + 1, u128::MAX] {
            let sequence = SequenceNumber::new(value);
            let qb64 = sequence.qb64()?;
            let qb2 = sequence.qb2()?;
            assert_eq!(SequenceNumber::from_qb64(&qb64)?, sequence);
            assert_eq!(SequenceNumber::from_qb64_bytes(&sequence.qb64_bytes()?)?, sequence);
            assert_eq!(SequenceNumber::from_qb2(&qb2)?, sequence);

            let text_stream = format!("{qb64}ABCD");
            let parsed_text = SequenceNumber::parse_qb64(&text_stream)?;
            assert_eq!(parsed_text.sequence(), sequence);
            assert_eq!(parsed_text.consumed(), qb64.len());

            let mut binary_stream = qb2.clone();
            binary_stream.extend_from_slice(&[0, 1]);
            let parsed_binary = SequenceNumber::parse_qb2(&binary_stream)?;
            assert_eq!(parsed_binary.into_parts(), (sequence, qb2.len()));
        }
        Ok(())
    }

    #[test]
    fn wrong_codes_and_malformed_inputs_are_typed_errors() -> Result<(), CesrError> {
        let short = QualifiedMaterial::new(DerivationCode::SHORT_NUMBER, &[0_u8; 2])?;
        assert!(matches!(
            SequenceNumber::from_qb64(&short.qb64()?),
            Err(CesrError::InvalidSequenceCode { .. })
        ));
        assert!(matches!(
            SequenceNumber::from_qb2(&short.qb2()?),
            Err(CesrError::InvalidSequenceCode { .. })
        ));
        assert!(matches!(
            SequenceNumber::parse_qb64(""),
            Err(CesrError::EmptyInput { .. })
        ));
        assert!(matches!(
            SequenceNumber::from_qb64("0AAA"),
            Err(CesrError::Truncated { .. })
        ));
        assert!(matches!(
            SequenceNumber::from_qb64("0A!AAAAAAAAAAAAAAAAAAAAA"),
            Err(CesrError::InvalidBase64Character { .. })
        ));
        assert!(matches!(
            SequenceNumber::parse_qb2(&[]),
            Err(CesrError::EmptyInput { .. })
        ));
        assert!(matches!(
            SequenceNumber::from_qb64_bytes(&[0xff]),
            Err(CesrError::InvalidUtf8 { .. })
        ));
        Ok(())
    }

    #[test]
    fn malformed_hex_and_encoded_suffixes_are_rejected() -> Result<(), CesrError> {
        for input in ["", "-1", "+1", " 1", "1 ", "0x10", "fzz", "gg"] {
            assert!(SequenceNumber::from_hex(input).is_err());
        }
        assert!(matches!(
            SequenceNumber::from_hex("000000000000000000000000000000000"),
            Err(CesrError::InputTooLarge { .. })
        ));

        let sequence = SequenceNumber::new(1);
        assert!(matches!(
            SequenceNumber::from_qb64(&format!("{}A", sequence.qb64()?)),
            Err(CesrError::TrailingMaterial { .. })
        ));
        let mut qb2 = sequence.qb2()?;
        qb2.push(0);
        assert!(matches!(
            SequenceNumber::from_qb2(&qb2),
            Err(CesrError::TrailingMaterial { .. })
        ));
        Ok(())
    }
}
