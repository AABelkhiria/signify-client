//! Canonical CESR material for URL-safe Base64 text.
//!
//! The pinned TypeScript reference calls this material `Bexter`. The Rust API uses
//! [`Base64Text`] to expose the domain concept without reproducing the reference's class
//! hierarchy. Text is restricted to the unpadded URL-safe Base64 alphabet and encoded with one of
//! the six `BexDex` derivation codes.

use std::{fmt, str::FromStr};

use crate::{
    CesrError,
    base64::{decode_url_safe_bounded, encode_url_safe},
    bytes::utf8_text,
    code::{CodeFamily, DerivationCode},
    matter::{MAX_RAW_MATERIAL_BYTES, ParsedMaterial, QualifiedMaterial},
};

/// Largest Base64-text input accepted by [`Base64Text::new`].
///
/// This is the longest text whose decoded raw representation fits the generic qualified-material
/// allocation bound. The limit is below CESR's four-character soft-size maximum.
pub const MAX_BASE64_TEXT_CHARS: usize = (MAX_RAW_MATERIAL_BYTES / 3) * 4 + (MAX_RAW_MATERIAL_BYTES % 3);

/// Validated URL-safe Base64 text encoded as CESR qualified material.
///
/// Input text may contain only `A-Z`, `a-z`, `0-9`, `-`, and `_`; padding is never accepted.
/// Empty text is valid and encodes as `4AAA`. As in the pinned reference, a leading `A` is
/// ambiguous for certain lengths: for example, `ABBB` and `BBB` both canonicalize to `BBB` and
/// encode as `4AABABBB`.
///
/// ```
/// use signify_cesr::{CesrError, bexter::Base64Text};
///
/// # fn main() -> Result<(), CesrError> {
/// let text = Base64Text::new("-A-B")?;
/// assert_eq!(text.text()?, "-A-B");
/// assert_eq!(text.qb64()?, "4AAB-A-B");
/// assert_eq!(Base64Text::from_qb64(&text.qb64()?)?.text()?, "-A-B");
/// # Ok(())
/// # }
/// ```
pub struct Base64Text {
    material: QualifiedMaterial,
}

/// One Base64-text material value parsed from the front of a qb64 or qb2 stream.
#[derive(Debug)]
pub struct ParsedBase64Text {
    value: Base64Text,
    consumed: usize,
}

impl fmt::Debug for Base64Text {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Base64Text")
            .field("code", &self.code())
            .field("raw_length", &self.raw().len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for Base64Text {
    fn eq(&self, other: &Self) -> bool {
        self.code() == other.code() && self.variable_size() == other.variable_size() && self.raw() == other.raw()
    }
}

impl Eq for Base64Text {}

impl ParsedBase64Text {
    /// Returns the parsed Base64-text material.
    #[must_use]
    pub const fn value(&self) -> &Base64Text {
        &self.value
    }

    /// Returns the number of input bytes or characters consumed.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Separates the parsed value from its consumed input length.
    #[must_use]
    pub fn into_parts(self) -> (Base64Text, usize) {
        (self.value, self.consumed)
    }
}

impl Base64Text {
    /// Constructs canonical CESR material from URL-safe Base64 text.
    ///
    /// The smallest applicable `BexDex` form is selected automatically, including the lead-byte
    /// variant determined by the text length.
    ///
    /// # Errors
    ///
    /// Returns a typed error when `text` contains a byte outside the unpadded URL-safe Base64
    /// alphabet, exceeds [`MAX_BASE64_TEXT_CHARS`], or cannot satisfy a shared material invariant.
    pub fn new(text: &str) -> Result<Self, CesrError> {
        validate_text(text)?;
        let remainder = text.len() % 4;
        let wad = (4 - remainder) % 4;
        let lead = (3 - remainder) % 3;
        let padded_length = text.len().checked_add(wad).ok_or(CesrError::LengthOverflow {
            context: "Base64 text padding",
        })?;
        let decoded_length = padded_length
            .checked_div(4)
            .and_then(|length| length.checked_mul(3))
            .ok_or(CesrError::LengthOverflow {
                context: "Base64 text decoding",
            })?;
        let raw_length = decoded_length.checked_sub(lead).ok_or(CesrError::InvalidLength {
            context: "Base64 text lead bytes",
            length: decoded_length,
        })?;
        let mut padded = String::with_capacity(padded_length);
        padded.extend(std::iter::repeat_n('A', wad));
        padded.push_str(text);
        let decoded = decode_url_safe_bounded(&padded, decoded_length)?;
        let raw = decoded.get(lead..).ok_or(CesrError::Truncated {
            context: "decoded Base64 text",
            needed: decoded_length,
            available: decoded.len(),
        })?;
        if raw.len() != raw_length {
            return Err(CesrError::RawSizeMismatch {
                context: "decoded Base64 text",
                expected: raw_length,
                actual: raw.len(),
            });
        }
        Self::from_raw(DerivationCode::BASE64_TEXT_LEAD_0, raw)
    }

    /// Constructs Base64-text material from exact raw bytes and a `BexDex` code.
    ///
    /// The code is normalized to the raw length's lead-byte variant. A large input code preserves
    /// the large form; a small code upgrades automatically when its two-character size field is
    /// insufficient.
    ///
    /// # Errors
    ///
    /// Returns [`CesrError::InvalidBase64TextCode`] for another code family and otherwise forwards
    /// bounded material-construction errors.
    pub fn from_raw(code: DerivationCode, raw: &[u8]) -> Result<Self, CesrError> {
        validate_code(code)?;
        Ok(Self {
            material: QualifiedMaterial::new(code, raw)?,
        })
    }

    /// Parses one canonical qualified-Base64 value from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error or [`CesrError::InvalidBase64TextCode`] when the parsed code
    /// is not in `BexDex`.
    pub fn parse_qb64(input: &str) -> Result<ParsedBase64Text, CesrError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb64(input)?)
    }

    /// Parses exactly one canonical qualified-Base64 value.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64`] and rejects trailing characters.
    pub fn from_qb64(input: &str) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64(input)?;
        reject_trailing("Base64 text qualified Base64", input.len(), parsed.consumed)?;
        Ok(parsed.value)
    }

    /// Parses one UTF-8 qualified-Base64 value from the beginning of a byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed UTF-8 or Base64-text material error.
    pub fn parse_qb64_bytes(input: &[u8]) -> Result<ParsedBase64Text, CesrError> {
        Self::parse_qb64(utf8_text(input)?)
    }

    /// Parses exactly one UTF-8 qualified-Base64 value from bytes.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb64_bytes`] and rejects trailing bytes.
    pub fn from_qb64_bytes(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb64_bytes(input)?;
        reject_trailing("Base64 text qualified Base64 bytes", input.len(), parsed.consumed)?;
        Ok(parsed.value)
    }

    /// Parses one canonical qualified-binary (`qb2`) value from the beginning of `input`.
    ///
    /// # Errors
    ///
    /// Returns a typed material error or [`CesrError::InvalidBase64TextCode`] for another code
    /// family.
    pub fn parse_qb2(input: &[u8]) -> Result<ParsedBase64Text, CesrError> {
        Self::from_parsed_material(QualifiedMaterial::parse_qb2(input)?)
    }

    /// Parses exactly one canonical qualified-binary (`qb2`) value.
    ///
    /// # Errors
    ///
    /// Returns any error from [`Self::parse_qb2`] and rejects trailing bytes.
    pub fn from_qb2(input: &[u8]) -> Result<Self, CesrError> {
        let parsed = Self::parse_qb2(input)?;
        reject_trailing("Base64 text qualified binary", input.len(), parsed.consumed)?;
        Ok(parsed.value)
    }

    /// Returns the normalized Base64-text derivation code.
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        self.material.code()
    }

    /// Returns the unqualified raw bytes represented by the text.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.material.raw()
    }

    /// Returns the encoded size in three-byte triplets.
    ///
    /// Safe `Base64Text` construction always produces `Some`; the optional form mirrors the shared
    /// material engine without fabricating a fallback value if an internal invariant regresses.
    #[must_use]
    pub const fn variable_size(&self) -> Option<u32> {
        self.material.variable_size()
    }

    /// Returns the hard and soft derivation-code text.
    ///
    /// # Errors
    ///
    /// Returns a typed error only if a private material invariant is violated.
    pub fn both(&self) -> Result<String, CesrError> {
        self.material.both()
    }

    /// Returns the canonical URL-safe Base64 text without its CESR leader.
    ///
    /// The returned text may be shorter than the constructor input for the documented leading-`A`
    /// ambiguity.
    ///
    /// # Errors
    ///
    /// Returns a typed length error only if a private material invariant is violated.
    pub fn text(&self) -> Result<String, CesrError> {
        let lead = self.code().size().lead_size();
        let padded_length = lead.checked_add(self.raw().len()).ok_or(CesrError::LengthOverflow {
            context: "Base64 text encoding",
        })?;
        let mut padded = Vec::with_capacity(padded_length);
        padded.resize(lead, 0);
        padded.extend_from_slice(self.raw());
        let encoded = encode_url_safe(&padded);
        let skip = if lead == 0 {
            usize::from(encoded.as_bytes().first() == Some(&b'A'))
        } else {
            (lead + 1) % 4
        };
        encoded
            .get(skip..)
            .map(ToOwned::to_owned)
            .ok_or(CesrError::InvalidLength {
                context: "encoded Base64 text",
                length: encoded.len(),
            })
    }

    /// Encodes the value as canonical qualified Base64 (`qb64`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if a shared material invariant is violated.
    pub fn qb64(&self) -> Result<String, CesrError> {
        self.material.qb64()
    }

    /// Encodes the value as UTF-8 qualified-Base64 bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error if a shared material invariant is violated.
    pub fn qb64_bytes(&self) -> Result<Vec<u8>, CesrError> {
        self.material.qb64_bytes()
    }

    /// Encodes the value as canonical qualified binary (`qb2`).
    ///
    /// # Errors
    ///
    /// Returns a typed error if a shared material invariant is violated.
    pub fn qb2(&self) -> Result<Vec<u8>, CesrError> {
        self.material.qb2()
    }

    fn from_parsed_material(parsed: ParsedMaterial) -> Result<ParsedBase64Text, CesrError> {
        let (material, consumed) = parsed.into_parts();
        validate_code(material.code())?;
        Ok(ParsedBase64Text {
            value: Self { material },
            consumed,
        })
    }
}

impl FromStr for Base64Text {
    type Err = CesrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::new(input)
    }
}

impl TryFrom<&str> for Base64Text {
    type Error = CesrError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::new(input)
    }
}

impl fmt::Display for Base64Text {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.text() {
            Ok(text) => formatter.write_str(&text),
            Err(_) => Err(fmt::Error),
        }
    }
}

fn validate_text(text: &str) -> Result<(), CesrError> {
    if text.len() > MAX_BASE64_TEXT_CHARS {
        return Err(CesrError::InputTooLarge {
            context: "Base64 text",
            length: text.len(),
            maximum: MAX_BASE64_TEXT_CHARS,
        });
    }
    for (index, byte) in text.bytes().enumerate() {
        if !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_') {
            return Err(CesrError::InvalidBase64Character { index, byte });
        }
    }
    Ok(())
}

fn validate_code(code: DerivationCode) -> Result<(), CesrError> {
    if code.belongs_to(CodeFamily::Base64Text) {
        Ok(())
    } else {
        Err(CesrError::InvalidBase64TextCode { code: code.as_str() })
    }
}

fn reject_trailing(context: &'static str, input_length: usize, consumed: usize) -> Result<(), CesrError> {
    let trailing = input_length
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
    use std::{error::Error, str::FromStr};

    use super::{Base64Text, MAX_BASE64_TEXT_CHARS};
    use crate::{CesrError, code::DerivationCode, matter::QualifiedMaterial};

    #[test]
    fn reference_examples_encode_and_decode() -> Result<(), Box<dyn Error>> {
        let cases = [
            ("", "4A", "", "4AAA", ""),
            ("-", "6A", "3e", "6AABAAA-", "-"),
            ("-A", "5A", "0f80", "5AABAA-A", "-A"),
            ("-A-", "4A", "03e03e", "4AABA-A-", "-A-"),
            ("-A-B", "4A", "f80f81", "4AAB-A-B", "-A-B"),
            ("A", "6A", "00", "6AABAAAA", "A"),
            ("AA", "5A", "0000", "5AABAAAA", "AA"),
            ("AAA", "4A", "000000", "4AABAAAA", "AAA"),
            ("AAAA", "4A", "000000", "4AABAAAA", "AAA"),
            ("ABB", "4A", "000041", "4AABAABB", "ABB"),
            ("BBB", "4A", "001041", "4AABABBB", "BBB"),
            ("ABBB", "4A", "001041", "4AABABBB", "BBB"),
        ];
        for (input, code, raw_hex, qb64, canonical) in cases {
            let value = Base64Text::new(input)?;
            assert_eq!(value.code().as_str(), code);
            assert!(value.variable_size().is_some());
            assert_eq!(value.both()?, qb64.get(..4).ok_or("missing Bexter leader")?);
            assert_eq!(hex(value.raw())?, raw_hex);
            assert_eq!(value.qb64()?, qb64);
            assert_eq!(value.qb64_bytes()?, qb64.as_bytes());
            assert_eq!(value.text()?, canonical);
            assert_eq!(value.to_string(), canonical);
            assert_eq!(Base64Text::from_str(input)?, value);
            assert_eq!(Base64Text::try_from(input)?, value);
            let reparsed = Base64Text::from_qb64(qb64)?;
            assert_eq!(reparsed, value);
            assert_eq!(Base64Text::from_qb2(&value.qb2()?)?, value);
        }
        Ok(())
    }

    #[test]
    fn invalid_text_and_wrong_codes_are_typed() -> Result<(), Box<dyn Error>> {
        for input in ["@!", "+", "/", "=", "a b", "é"] {
            assert!(matches!(
                Base64Text::new(input),
                Err(CesrError::InvalidBase64Character { .. })
            ));
        }
        assert!(matches!(
            Base64Text::from_raw(DerivationCode::ED25519_SEED, &[0_u8; 32]),
            Err(CesrError::InvalidBase64TextCode { code: "A" })
        ));
        let digest = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &[0_u8; 32])?;
        assert!(matches!(
            Base64Text::from_qb64(&digest.qb64()?),
            Err(CesrError::InvalidBase64TextCode { code: "E" })
        ));
        Ok(())
    }

    #[test]
    fn stream_parsers_report_consumption_and_strict_forms_reject_suffixes() -> Result<(), Box<dyn Error>> {
        let value = Base64Text::new("-A-B")?;
        let qb64 = value.qb64()?;
        let stream = format!("{qb64}ABCD");
        let parsed = Base64Text::parse_qb64(&stream)?;
        assert_eq!(parsed.consumed(), qb64.len());
        assert_eq!(parsed.value(), &value);
        let (owned, consumed) = parsed.into_parts();
        assert_eq!(owned, value);
        assert_eq!(consumed, qb64.len());
        assert!(matches!(
            Base64Text::from_qb64(&stream),
            Err(CesrError::TrailingMaterial { length: 4, .. })
        ));

        let qb2 = value.qb2()?;
        let mut binary_stream = qb2.clone();
        binary_stream.extend_from_slice(&[0_u8; 3]);
        let parsed = Base64Text::parse_qb2(&binary_stream)?;
        assert_eq!(parsed.consumed(), qb2.len());
        assert_eq!(parsed.value(), &value);
        assert!(matches!(
            Base64Text::from_qb2(&binary_stream),
            Err(CesrError::TrailingMaterial { length: 3, .. })
        ));

        let parsed = Base64Text::parse_qb64_bytes(stream.as_bytes())?;
        assert_eq!(parsed.consumed(), qb64.len());
        assert!(matches!(
            Base64Text::from_qb64_bytes(stream.as_bytes()),
            Err(CesrError::TrailingMaterial { length: 4, .. })
        ));
        assert!(matches!(
            Base64Text::from_qb64_bytes(&[0xff]),
            Err(CesrError::InvalidUtf8 { .. })
        ));
        Ok(())
    }

    #[test]
    fn small_limit_upgrades_to_large_and_explicit_large_code_is_preserved() -> Result<(), Box<dyn Error>> {
        let largest_small = vec![0_u8; 12_285];
        let small = Base64Text::from_raw(DerivationCode::BASE64_TEXT_LEAD_0, &largest_small)?;
        assert_eq!(small.code(), DerivationCode::BASE64_TEXT_LEAD_0);
        assert_eq!(small.variable_size(), Some(4_095));

        let first_large = vec![0_u8; 12_286];
        let upgraded = Base64Text::from_raw(DerivationCode::BASE64_TEXT_LEAD_0, &first_large)?;
        assert_eq!(upgraded.code(), DerivationCode::BASE64_TEXT_BIG_LEAD_2);
        assert_eq!(upgraded.variable_size(), Some(4_096));

        let explicit = Base64Text::from_raw(DerivationCode::BASE64_TEXT_BIG_LEAD_0, b"abc")?;
        assert_eq!(explicit.code(), DerivationCode::BASE64_TEXT_BIG_LEAD_0);
        assert_eq!(Base64Text::from_qb64(&explicit.qb64()?)?, explicit);
        Ok(())
    }

    #[test]
    fn allocation_bound_matches_raw_bound() {
        let maximum_raw_from_text = (MAX_BASE64_TEXT_CHARS / 4) * 3 + (MAX_BASE64_TEXT_CHARS % 4);
        assert_eq!(maximum_raw_from_text, crate::matter::MAX_RAW_MATERIAL_BYTES);
    }

    #[test]
    fn oversized_text_is_rejected_before_decoding() {
        let oversized = "A".repeat(MAX_BASE64_TEXT_CHARS + 1);
        assert!(matches!(
            Base64Text::new(&oversized),
            Err(CesrError::InputTooLarge {
                maximum: MAX_BASE64_TEXT_CHARS,
                ..
            })
        ));
    }

    fn hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let high = DIGITS.get(usize::from(byte >> 4)).copied().ok_or(std::fmt::Error)?;
            let low = DIGITS.get(usize::from(byte & 0x0f)).copied().ok_or(std::fmt::Error)?;
            output.push(char::from(high));
            output.push(char::from(low));
        }
        Ok(output)
    }
}
