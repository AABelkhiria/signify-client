//! Exact unsigned CESR numeric material.
//!
//! CESR numbers use the smallest fixed-width numeric derivation code capable of carrying the
//! value. Unlike the pinned JavaScript reference, this module represents the complete protocol
//! range exactly with `u128`.

use std::{fmt, str::FromStr};

use crate::{
    CesrError,
    bytes::{bytes_to_integer, integer_to_bytes, utf8_text},
    code::{CodeFamily, DerivationCode},
    matter::{ParsedMaterial, QualifiedMaterial},
};

/// Maximum number of hexadecimal digits accepted by [`CesrNumber::from_hex`].
pub const MAX_NUMBER_HEX_DIGITS: usize = 32;

/// An exact unsigned CESR number in the protocol's full 128-bit range.
///
/// The numeric value is the only stored state. Its derivation code and raw width are selected
/// canonically whenever the value is encoded, so a safe value cannot retain a non-minimal form.
///
/// ```
/// use signify_cesr::{CesrError, code::DerivationCode, number::CesrNumber};
///
/// # fn main() -> Result<(), CesrError> {
/// let number = CesrNumber::from_hex("10000")?;
/// assert_eq!(number.value(), 65_536);
/// assert_eq!(number.code(), DerivationCode::LONG_NUMBER);
/// assert_eq!(CesrNumber::from_qb64(&number.qb64()?)?, number);
/// # Ok(())
/// # }
/// ```
///
/// Negative values are excluded by the unsigned API:
///
/// ```compile_fail
/// use signify_cesr::number::CesrNumber;
///
/// let negative = CesrNumber::new(-1);
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CesrNumber {
    value: u128,
}

/// One exact number parsed from the front of a CESR stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParsedNumber {
    number: CesrNumber,
    consumed: usize,
}

impl ParsedNumber {
    /// Returns the parsed exact number.
    #[must_use]
    pub const fn number(self) -> CesrNumber {
        self.number
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(self) -> usize {
        self.consumed
    }

    /// Separates the number from its consumed input length.
    #[must_use]
    pub const fn into_parts(self) -> (CesrNumber, usize) {
        (self.number, self.consumed)
    }
}

impl CesrNumber {
    /// Canonical zero.
    pub const ZERO: Self = Self { value: 0 };

    /// Constructs an exact number.
    ///
    /// Every `u128` value is valid CESR numeric material, so construction is infallible.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self { value }
    }

    /// Parses complete, unsigned hexadecimal text.
    ///
    /// Upper- and lowercase digits and leading zeroes are accepted. Signs, whitespace, `0x`
    /// prefixes, partial parses, empty text, and input wider than 32 digits are rejected.
    ///
    /// # Errors
    ///
    /// Returns a typed empty, size, character, or arithmetic error.
    pub fn from_hex(input: &str) -> Result<Self, CesrError> {
        if input.is_empty() {
            return Err(CesrError::EmptyInput {
                context: "CESR hexadecimal number",
            });
        }
        if input.len() > MAX_NUMBER_HEX_DIGITS {
            return Err(CesrError::InputTooLarge {
                context: "CESR hexadecimal number",
                length: input.len(),
                maximum: MAX_NUMBER_HEX_DIGITS,
            });
        }

        let value = input.bytes().enumerate().try_fold(0_u128, |value, (index, byte)| {
            let digit = match byte {
                b'0'..=b'9' => u128::from(byte - b'0'),
                b'a'..=b'f' => u128::from(byte - b'a' + 10),
                b'A'..=b'F' => u128::from(byte - b'A' + 10),
                _ => return Err(CesrError::InvalidHexCharacter { index, byte }),
            };
            value
                .checked_mul(16)
                .and_then(|shifted| shifted.checked_add(digit))
                .ok_or(CesrError::IntegerOverflow {
                    context: "CESR hexadecimal number",
                })
        })?;
        Ok(Self::new(value))
    }

    /// Parses one canonical qualified-Base64 number from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error, rejects nonnumeric codes, and rejects a numeric code wider
    /// than the decoded value requires.
    pub fn parse_qb64(input: &str) -> Result<ParsedNumber, CesrError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qualified-Base64 number.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("CESR number qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.number)
    }

    /// Parses one UTF-8 qualified-Base64 number from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8 or numeric-material error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedNumber, CesrError> {
        Self::parse_qb64(utf8_text(input)?)
    }

    /// Parses exactly one UTF-8 qualified-Base64 number from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing("CESR number qualified Base64 bytes", input.len(), parsed.consumed)?;
        Ok(parsed.number)
    }

    /// Parses one canonical qualified-binary number from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error, rejects nonnumeric codes, and rejects a numeric code wider
    /// than the decoded value requires.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedNumber, CesrError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qualified-binary number.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("CESR number qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.number)
    }

    /// Returns the exact unsigned value.
    #[must_use]
    pub const fn value(self) -> u128 {
        self.value
    }

    /// Returns lowercase hexadecimal text without leading zeroes.
    #[must_use]
    pub fn hex(self) -> String {
        format!("{:x}", self.value)
    }

    /// Returns whether the value is greater than zero.
    #[must_use]
    pub const fn is_positive(self) -> bool {
        self.value > 0
    }

    /// Returns the smallest numeric derivation code capable of carrying the value.
    #[must_use]
    pub const fn code(self) -> DerivationCode {
        numeric_code(self.value)
    }

    /// Returns the value as fixed-width big-endian raw bytes selected by [`Self::code`].
    ///
    /// # Errors
    ///
    /// Returns a typed invariant error if shared code metadata cannot be represented as a byte
    /// width. This cannot occur for the pinned numeric code table.
    pub fn raw(self) -> Result<Vec<u8>, CesrError> {
        integer_to_bytes(self.value, numeric_width(self.code())?)
    }

    /// Encodes the number as canonical qualified Base64 (`qb64`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if a private numeric/code-table invariant is violated.
    pub fn qb64(self) -> Result<String, CesrError> {
        self.material()?.qb64()
    }

    /// Encodes the number as UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error if a private numeric/code-table invariant is violated.
    pub fn qb64_bytes(self) -> Result<Vec<u8>, CesrError> {
        self.material()?.qb64_bytes()
    }

    /// Encodes the number as canonical qualified binary (`qb2`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if a private numeric/code-table invariant is violated.
    pub fn qb2(self) -> Result<Vec<u8>, CesrError> {
        self.material()?.qb2()
    }

    fn material(self) -> Result<QualifiedMaterial, CesrError> {
        QualifiedMaterial::new(self.code(), &self.raw()?)
    }

    fn from_parsed_material(parsed: ParsedMaterial) -> Result<ParsedNumber, CesrError> {
        let (material, consumed) = parsed.into_parts();
        let code = material.code();
        if !code.belongs_to(CodeFamily::Numeric) {
            return Err(CesrError::InvalidNumericCode { code: code.as_str() });
        }
        let value = bytes_to_integer(material.raw())?;
        let canonical = numeric_code(value);
        if code != canonical {
            return Err(CesrError::NonCanonicalNumber {
                code: code.as_str(),
                canonical: canonical.as_str(),
            });
        }
        Ok(ParsedNumber {
            number: Self::new(value),
            consumed,
        })
    }
}

impl From<u128> for CesrNumber {
    fn from(value: u128) -> Self {
        Self::new(value)
    }
}

impl FromStr for CesrNumber {
    type Err = CesrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_hex(input)
    }
}

impl fmt::Display for CesrNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:x}", self.value)
    }
}

const fn numeric_code(value: u128) -> DerivationCode {
    if value <= u16::MAX as u128 {
        DerivationCode::SHORT_NUMBER
    } else if value <= u32::MAX as u128 {
        DerivationCode::LONG_NUMBER
    } else if value <= u64::MAX as u128 {
        DerivationCode::BIG_NUMBER
    } else {
        DerivationCode::HUGE_NUMBER
    }
}

fn numeric_width(code: DerivationCode) -> Result<u8, CesrError> {
    let width = code
        .size()
        .raw_size()
        .ok_or(CesrError::InvalidNumericCode { code: code.as_str() })?;
    u8::try_from(width).map_err(|_| CesrError::IntegerOverflow {
        context: "CESR number raw width",
    })
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
    fn reference_hex_inputs_are_exact_and_canonical() -> Result<(), CesrError> {
        assert_eq!(CesrNumber::ZERO, CesrNumber::from(0_u128));
        for (input, value, canonical) in [
            ("0", 0_u128, "0"),
            ("0000", 0, "0"),
            ("1", 1, "1"),
            ("f", 15, "f"),
            ("F", 15, "f"),
            ("15", 21, "15"),
        ] {
            let number = CesrNumber::from_hex(input)?;
            assert_eq!(number.value(), value);
            assert_eq!(number.hex(), canonical);
            assert_eq!(number.to_string(), canonical);
            assert_eq!(input.parse::<CesrNumber>()?, number);
        }
        Ok(())
    }

    #[test]
    fn code_selection_is_minimal_at_every_boundary() {
        for (value, code, raw_len) in [
            (0, DerivationCode::SHORT_NUMBER, 2),
            (u128::from(u16::MAX), DerivationCode::SHORT_NUMBER, 2),
            (u128::from(u16::MAX) + 1, DerivationCode::LONG_NUMBER, 4),
            (u128::from(u32::MAX), DerivationCode::LONG_NUMBER, 4),
            (u128::from(u32::MAX) + 1, DerivationCode::BIG_NUMBER, 8),
            (u128::from(u64::MAX), DerivationCode::BIG_NUMBER, 8),
            (u128::from(u64::MAX) + 1, DerivationCode::HUGE_NUMBER, 16),
            (u128::MAX, DerivationCode::HUGE_NUMBER, 16),
        ] {
            let number = CesrNumber::new(value);
            assert_eq!(number.code(), code);
            assert_eq!(number.raw().map(|raw| raw.len()), Ok(raw_len));
        }
    }

    #[test]
    fn all_encodings_round_trip_and_stream_parsers_report_consumption() -> Result<(), CesrError> {
        for value in [
            0,
            u128::from(u16::MAX) + 1,
            u128::from(u32::MAX) + 1,
            u128::from(u64::MAX) + 1,
            u128::MAX,
        ] {
            let number = CesrNumber::new(value);
            let qb64 = number.qb64()?;
            let qb2 = number.qb2()?;
            assert_eq!(CesrNumber::from_qb64(&qb64)?, number);
            assert_eq!(CesrNumber::from_qb64_bytes(&number.qb64_bytes()?)?, number);
            assert_eq!(CesrNumber::from_qb2(&qb2)?, number);

            let text_stream = format!("{qb64}ABCD");
            let parsed_text = CesrNumber::parse_qb64(&text_stream)?;
            assert_eq!(parsed_text.number(), number);
            assert_eq!(parsed_text.consumed(), qb64.len());

            let mut binary_stream = qb2.clone();
            binary_stream.extend_from_slice(&[0, 1]);
            let parsed_binary = CesrNumber::parse_qb2(&binary_stream)?;
            assert_eq!(parsed_binary.into_parts(), (number, qb2.len()));
        }
        Ok(())
    }

    #[test]
    fn malformed_hex_is_rejected_without_partial_parsing() {
        assert!(matches!(CesrNumber::from_hex(""), Err(CesrError::EmptyInput { .. })));
        for input in ["-1", "+1", " 1", "1 ", "0x10", "fzz", "gg"] {
            assert!(matches!(
                CesrNumber::from_hex(input),
                Err(CesrError::InvalidHexCharacter { .. })
            ));
        }
        assert!(matches!(
            CesrNumber::from_hex("000000000000000000000000000000000"),
            Err(CesrError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn malformed_encoded_inputs_retain_typed_material_errors() {
        assert!(matches!(CesrNumber::parse_qb64(""), Err(CesrError::EmptyInput { .. })));
        assert!(matches!(CesrNumber::from_qb64("MAA"), Err(CesrError::Truncated { .. })));
        assert!(matches!(
            CesrNumber::from_qb64("M!AA"),
            Err(CesrError::InvalidBase64Character { .. })
        ));
        assert!(matches!(
            CesrNumber::from_qb64("RAAA"),
            Err(CesrError::UnsupportedCode { .. })
        ));
        assert!(matches!(CesrNumber::parse_qb2(&[]), Err(CesrError::EmptyInput { .. })));
    }

    #[test]
    fn encoded_input_rejects_wrong_code_nonminimal_forms_and_suffixes() -> Result<(), CesrError> {
        let digest = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &[0_u8; 32])?;
        assert!(matches!(
            CesrNumber::from_qb64(&digest.qb64()?),
            Err(CesrError::InvalidNumericCode { .. })
        ));

        let wide_zero = QualifiedMaterial::new(DerivationCode::LONG_NUMBER, &[0_u8; 4])?;
        assert!(matches!(
            CesrNumber::from_qb64(&wide_zero.qb64()?),
            Err(CesrError::NonCanonicalNumber { .. })
        ));
        assert!(matches!(
            CesrNumber::from_qb2(&wide_zero.qb2()?),
            Err(CesrError::NonCanonicalNumber { .. })
        ));

        let number = CesrNumber::new(1);
        assert!(matches!(
            CesrNumber::from_qb64(&format!("{}A", number.qb64()?)),
            Err(CesrError::TrailingMaterial { .. })
        ));
        let mut qb2 = number.qb2()?;
        qb2.push(0);
        assert!(matches!(
            CesrNumber::from_qb2(&qb2),
            Err(CesrError::TrailingMaterial { .. })
        ));
        assert!(matches!(
            CesrNumber::from_qb64_bytes(&[0xff]),
            Err(CesrError::InvalidUtf8 { .. })
        ));
        Ok(())
    }
}
