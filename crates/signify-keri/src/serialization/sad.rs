//! Self-addressing data (SAD) values and their deterministic JSON codec.
//!
//! KERI computes SAIDs, prefixes, and event sizes over exact serialized bytes, so this module owns
//! an ordered value model and an explicit encoder rather than delegating to a general-purpose JSON
//! library whose field order and escaping are incidental. [`Sad`] preserves insertion order, and
//! [`Sad::to_json_bytes`] reproduces the pinned reference's `JSON.stringify` output byte for byte
//! for every value this module accepts.
//!
//! The accepted value space is deliberately narrower than RFC 8259 so that byte parity is provable
//! rather than hoped for; see [`SadValue::Integer`] and the module's error variants. Rationale and
//! the full divergence list are recorded in `docs/adr/0008-deterministic-json-serialization.md`.

use core::fmt;
use std::error::Error;

/// Largest serialized SAD accepted by the parser, matching the protocol's own size ceiling.
///
/// A CESR version string encodes its size in six hexadecimal digits, so no conforming KERI or ACDC
/// message can exceed this bound.
pub const MAX_SERIALIZED_BYTES: usize = 0x00ff_ffff;

/// Maximum array/object nesting accepted by the parser.
pub const MAX_NESTING_DEPTH: usize = 64;

/// Largest integer both this module and the reference represent exactly.
///
/// JavaScript numbers are IEEE-754 doubles, so the pinned reference silently rounds integers of
/// greater magnitude. Rejecting them keeps every accepted value byte-identical across languages.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Smallest integer both this module and the reference represent exactly.
pub const MIN_SAFE_INTEGER: i64 = -MAX_SAFE_INTEGER;

/// One value inside self-addressing data.
///
/// This is intentionally not a general JSON value: floating-point and out-of-safe-range numbers
/// are unrepresentable because the reference cannot round-trip them without changing bytes, and a
/// changed byte changes a SAID.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SadValue {
    /// JSON `null`.
    Null,
    /// JSON `true` or `false`.
    Bool(bool),
    /// An exact integer within the safe range, serialized without a fraction or exponent.
    Integer(i64),
    /// A UTF-8 string.
    Text(String),
    /// An ordered array.
    Array(Vec<SadValue>),
    /// An ordered field map.
    Map(Sad),
}

impl SadValue {
    /// Builds a text value from anything string-like.
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Builds an exact integer value.
    ///
    /// # Errors
    ///
    /// Returns [`SadError::IntegerOutOfRange`] outside the reference-representable safe range.
    pub fn integer(value: i64) -> Result<Self, SadError> {
        if (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
            Ok(Self::Integer(value))
        } else {
            Err(SadError::IntegerOutOfRange { value })
        }
    }

    /// Returns the string contents when this value is text.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the entries when this value is a map.
    #[must_use]
    pub const fn as_map(&self) -> Option<&Sad> {
        match self {
            Self::Map(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the items when this value is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }
}

impl From<&str> for SadValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for SadValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<bool> for SadValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<Sad> for SadValue {
    fn from(value: Sad) -> Self {
        Self::Map(value)
    }
}

/// An ordered, duplicate-free map of field labels to values.
///
/// Insertion order is the serialization order. The pinned reference inherits JavaScript object
/// semantics, which hoist array-index-like keys ahead of the rest; that behavior is a JavaScript
/// artifact rather than protocol order, so it is deliberately not reproduced. See the ADR.
///
/// ```
/// use signify_keri::serialization::{Sad, SadValue};
///
/// # fn main() -> Result<(), signify_keri::serialization::SadError> {
/// let mut sad = Sad::new();
/// sad.insert("v", SadValue::text("KERI10JSON000000_"))?;
/// sad.insert("t", SadValue::text("icp"))?;
/// assert_eq!(sad.to_json_bytes()?, br#"{"v":"KERI10JSON000000_","t":"icp"}"#);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Sad {
    entries: Vec<(String, SadValue)>,
}

impl Sad {
    /// Creates an empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Appends one field, preserving insertion order.
    ///
    /// # Errors
    ///
    /// Returns [`SadError::DuplicateField`] when the label is already present. The reference keeps
    /// the last value at the first position; silently choosing either would change bytes, so Rust
    /// rejects the ambiguity.
    pub fn insert(&mut self, label: impl Into<String>, value: impl Into<SadValue>) -> Result<(), SadError> {
        let label = label.into();
        if self.contains(&label) {
            return Err(SadError::DuplicateField { label });
        }
        self.entries.push((label, value.into()));
        Ok(())
    }

    /// Returns whether a label is present.
    #[must_use]
    pub fn contains(&self, label: &str) -> bool {
        self.entries.iter().any(|(existing, _)| existing == label)
    }

    /// Borrows one field's value.
    #[must_use]
    pub fn get(&self, label: &str) -> Option<&SadValue> {
        self.entries
            .iter()
            .find(|(existing, _)| existing == label)
            .map(|(_, value)| value)
    }

    /// Borrows one field's value as text.
    #[must_use]
    pub fn get_text(&self, label: &str) -> Option<&str> {
        self.get(label).and_then(SadValue::as_text)
    }

    /// Returns the first field's label, which the protocol requires to be the version string.
    #[must_use]
    pub fn first_label(&self) -> Option<&str> {
        self.entries.first().map(|(label, _)| label.as_str())
    }

    /// Iterates fields in serialization order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &SadValue)> {
        self.entries.iter().map(|(label, value)| (label.as_str(), value))
    }

    /// Returns the number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the map has no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Replaces an existing field's value in place, keeping its position.
    ///
    /// Used to write a computed version string back into a SAD without disturbing field order.
    pub(crate) fn replace_existing(&mut self, label: &str, value: SadValue) -> Result<(), SadError> {
        let slot = self
            .entries
            .iter_mut()
            .find(|(existing, _)| existing == label)
            .map(|(_, existing)| existing)
            .ok_or_else(|| SadError::MissingField {
                label: label.to_owned(),
            })?;
        *slot = value;
        Ok(())
    }

    /// Serializes to canonical JSON bytes matching the pinned reference's `JSON.stringify`.
    ///
    /// # Errors
    ///
    /// Returns [`SadError::SerializedTooLarge`] when the encoding exceeds
    /// [`MAX_SERIALIZED_BYTES`].
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, SadError> {
        let mut out = Vec::new();
        encode_map(self, &mut out);
        if out.len() > MAX_SERIALIZED_BYTES {
            return Err(SadError::SerializedTooLarge {
                length: out.len(),
                maximum: MAX_SERIALIZED_BYTES,
            });
        }
        Ok(out)
    }

    /// Parses canonical or whitespace-padded JSON object bytes into an ordered map.
    ///
    /// # Errors
    ///
    /// Returns a typed [`SadError`] for oversized input, invalid UTF-8, malformed JSON,
    /// unsupported numbers, duplicate fields, excessive nesting, or trailing content.
    pub fn from_json_bytes(input: &[u8]) -> Result<Self, SadError> {
        if input.len() > MAX_SERIALIZED_BYTES {
            return Err(SadError::InputTooLarge {
                length: input.len(),
                maximum: MAX_SERIALIZED_BYTES,
            });
        }
        let mut parser = Parser { input, position: 0 };
        parser.skip_whitespace();
        let value = parser.parse_value(0)?;
        parser.skip_whitespace();
        if parser.position != input.len() {
            return Err(SadError::TrailingContent {
                offset: parser.position,
            });
        }
        match value {
            SadValue::Map(map) => Ok(map),
            _ => Err(SadError::NotAnObject),
        }
    }
}

fn encode_value(value: &SadValue, out: &mut Vec<u8>) {
    match value {
        SadValue::Null => out.extend_from_slice(b"null"),
        SadValue::Bool(true) => out.extend_from_slice(b"true"),
        SadValue::Bool(false) => out.extend_from_slice(b"false"),
        SadValue::Integer(number) => out.extend_from_slice(number.to_string().as_bytes()),
        SadValue::Text(text) => encode_text(text, out),
        SadValue::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                encode_value(item, out);
            }
            out.push(b']');
        }
        SadValue::Map(map) => encode_map(map, out),
    }
}

fn encode_map(map: &Sad, out: &mut Vec<u8>) {
    out.push(b'{');
    for (index, (label, value)) in map.entries.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        encode_text(label, out);
        out.push(b':');
        encode_value(value, out);
    }
    out.push(b'}');
}

/// Returns one lowercase hexadecimal digit for the low nibble of `value`.
const fn hex_digit(value: u32) -> u8 {
    match value & 0x0f {
        0 => b'0',
        1 => b'1',
        2 => b'2',
        3 => b'3',
        4 => b'4',
        5 => b'5',
        6 => b'6',
        7 => b'7',
        8 => b'8',
        9 => b'9',
        10 => b'a',
        11 => b'b',
        12 => b'c',
        13 => b'd',
        14 => b'e',
        _ => b'f',
    }
}

/// Writes one JSON string literal using exactly the reference's escape set.
///
/// `JSON.stringify` escapes only `"`, `\`, and the C0 control range, using the five short forms
/// where they exist and lowercase `\u00xx` otherwise. Everything else, including `/`, DEL, and all
/// non-ASCII scalar values, is emitted as raw UTF-8.
fn encode_text(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{09}' => out.extend_from_slice(b"\\t"),
            '\u{0a}' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\u{0d}' => out.extend_from_slice(b"\\r"),
            control if u32::from(control) < 0x20 => {
                let code = u32::from(control);
                out.extend_from_slice(b"\\u00");
                out.push(hex_digit(code >> 4_u32));
                out.push(hex_digit(code));
            }
            other => {
                let mut buffer = [0_u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position = self.position.saturating_add(1);
        Some(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position = self.position.saturating_add(1);
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), SadError> {
        if self.peek() == Some(expected) {
            self.position = self.position.saturating_add(1);
            Ok(())
        } else {
            Err(SadError::UnexpectedByte {
                offset: self.position,
                found: self.peek(),
            })
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<SadValue, SadError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(SadError::NestingTooDeep {
                maximum: MAX_NESTING_DEPTH,
            });
        }
        match self.peek() {
            Some(b'{') => self.parse_object(depth).map(SadValue::Map),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => self.parse_string().map(SadValue::Text),
            Some(b't') => self.parse_literal(b"true").map(|()| SadValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false").map(|()| SadValue::Bool(false)),
            Some(b'n') => self.parse_literal(b"null").map(|()| SadValue::Null),
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => self.parse_number(),
            found => Err(SadError::UnexpectedByte {
                offset: self.position,
                found,
            }),
        }
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), SadError> {
        let end = self.position.saturating_add(literal.len());
        if self.input.get(self.position..end) == Some(literal) {
            self.position = end;
            Ok(())
        } else {
            Err(SadError::UnexpectedByte {
                offset: self.position,
                found: self.peek(),
            })
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Sad, SadError> {
        self.expect(b'{')?;
        let mut map = Sad::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position = self.position.saturating_add(1);
            return Ok(map);
        }
        loop {
            self.skip_whitespace();
            let label = self.parse_string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.parse_value(depth.saturating_add(1))?;
            map.insert(label, value)?;
            self.skip_whitespace();
            match self.advance() {
                Some(b',') => {}
                Some(b'}') => return Ok(map),
                found => {
                    return Err(SadError::UnexpectedByte {
                        offset: self.position.saturating_sub(1),
                        found,
                    });
                }
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<SadValue, SadError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position = self.position.saturating_add(1);
            return Ok(SadValue::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.parse_value(depth.saturating_add(1))?);
            self.skip_whitespace();
            match self.advance() {
                Some(b',') => {}
                Some(b']') => return Ok(SadValue::Array(items)),
                found => {
                    return Err(SadError::UnexpectedByte {
                        offset: self.position.saturating_sub(1),
                        found,
                    });
                }
            }
        }
    }

    fn parse_number(&mut self) -> Result<SadValue, SadError> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position = self.position.saturating_add(1);
        }
        match self.peek() {
            Some(b'0') => self.position = self.position.saturating_add(1),
            Some(byte) if byte.is_ascii_digit() => {
                while matches!(self.peek(), Some(digit) if digit.is_ascii_digit()) {
                    self.position = self.position.saturating_add(1);
                }
            }
            found => {
                return Err(SadError::UnexpectedByte {
                    offset: self.position,
                    found,
                });
            }
        }
        // A fraction or exponent would force the reference through IEEE-754 renormalization, so
        // the whole token is rejected rather than silently re-spelled on output.
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(SadError::UnsupportedNumber { offset: start });
        }
        let text = self
            .input
            .get(start..self.position)
            .and_then(|slice| core::str::from_utf8(slice).ok())
            .ok_or(SadError::UnsupportedNumber { offset: start })?;
        let value = text
            .parse::<i64>()
            .map_err(|_| SadError::IntegerOutOfRangeAt { offset: start })?;
        if !(MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
            return Err(SadError::IntegerOutOfRangeAt { offset: start });
        }
        Ok(SadValue::Integer(value))
    }

    fn parse_string(&mut self) -> Result<String, SadError> {
        self.expect(b'"')?;
        let mut text = String::new();
        loop {
            let offset = self.position;
            let byte = self.advance().ok_or(SadError::UnexpectedEnd)?;
            match byte {
                b'"' => return Ok(text),
                b'\\' => {
                    let escape = self.advance().ok_or(SadError::UnexpectedEnd)?;
                    let character = match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{08}',
                        b'f' => '\u{0c}',
                        b'n' => '\u{0a}',
                        b'r' => '\u{0d}',
                        b't' => '\u{09}',
                        b'u' => self.parse_unicode_escape()?,
                        _ => {
                            return Err(SadError::InvalidEscape { offset });
                        }
                    };
                    text.push(character);
                }
                control if control < 0x20 => {
                    return Err(SadError::UnescapedControl { offset });
                }
                _ => {
                    // Re-read the character from the source so multi-byte UTF-8 stays intact.
                    let rest = self.input.get(offset..).ok_or(SadError::UnexpectedEnd)?;
                    let decoded = core::str::from_utf8(rest)
                        .ok()
                        .and_then(|text| text.chars().next())
                        .ok_or(SadError::InvalidUtf8 { offset })?;
                    self.position = offset.saturating_add(decoded.len_utf8());
                    text.push(decoded);
                }
            }
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, SadError> {
        let offset = self.position;
        let first = self.parse_hex4()?;
        if let Some(scalar) = char::from_u32(u32::from(first)) {
            return Ok(scalar);
        }
        // The only non-scalar values are surrogates; a high surrogate must be followed by an
        // escaped low surrogate, exactly as the reference's own parser requires.
        if !(0xd800..0xdc00).contains(&first) {
            return Err(SadError::LoneSurrogate { offset });
        }
        if self.advance() != Some(b'\\') || self.advance() != Some(b'u') {
            return Err(SadError::LoneSurrogate { offset });
        }
        let second = self.parse_hex4()?;
        if !(0xdc00..0xe000).contains(&second) {
            return Err(SadError::LoneSurrogate { offset });
        }
        let high = u32::from(first).saturating_sub(0xd800);
        let low = u32::from(second).saturating_sub(0xdc00);
        let combined = 0x1_0000_u32
            .saturating_add(high.saturating_mul(0x400))
            .saturating_add(low);
        char::from_u32(combined).ok_or(SadError::LoneSurrogate { offset })
    }

    fn parse_hex4(&mut self) -> Result<u16, SadError> {
        let offset = self.position;
        let end = self.position.saturating_add(4);
        let digits = self.input.get(self.position..end).ok_or(SadError::UnexpectedEnd)?;
        let mut value = 0_u16;
        for digit in digits {
            let nibble = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(SadError::InvalidEscape { offset }),
            };
            value = (value << 4_u16) | u16::from(nibble);
        }
        self.position = end;
        Ok(value)
    }
}

/// Stable self-addressing-data construction and JSON codec failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum SadError {
    /// Input exceeds the protocol's serialized-size ceiling.
    InputTooLarge {
        /// Supplied length in bytes.
        length: usize,
        /// Maximum accepted length in bytes.
        maximum: usize,
    },
    /// The encoded form exceeds the protocol's serialized-size ceiling.
    SerializedTooLarge {
        /// Encoded length in bytes.
        length: usize,
        /// Maximum accepted length in bytes.
        maximum: usize,
    },
    /// The top-level value is not a JSON object.
    NotAnObject,
    /// A field label appears more than once.
    DuplicateField {
        /// Repeated field label.
        label: String,
    },
    /// A required field is absent.
    MissingField {
        /// Missing field label.
        label: String,
    },
    /// Array or object nesting exceeds [`MAX_NESTING_DEPTH`].
    NestingTooDeep {
        /// Maximum accepted nesting depth.
        maximum: usize,
    },
    /// A number carries a fraction or exponent, which the reference renormalizes through IEEE-754.
    UnsupportedNumber {
        /// Byte offset where the number token begins.
        offset: usize,
    },
    /// A parsed integer lies outside the reference-representable safe range.
    IntegerOutOfRangeAt {
        /// Byte offset where the number token begins.
        offset: usize,
    },
    /// A constructed integer lies outside the reference-representable safe range.
    IntegerOutOfRange {
        /// Rejected value.
        value: i64,
    },
    /// An unexpected byte was found while parsing.
    UnexpectedByte {
        /// Byte offset of the unexpected input.
        offset: usize,
        /// The byte found, or `None` at end of input.
        found: Option<u8>,
    },
    /// Input ended in the middle of a value.
    UnexpectedEnd,
    /// A string contains an invalid escape sequence.
    InvalidEscape {
        /// Byte offset of the escape.
        offset: usize,
    },
    /// A string contains an unescaped C0 control character.
    UnescapedControl {
        /// Byte offset of the control character.
        offset: usize,
    },
    /// A `\u` escape names an unpaired surrogate code point.
    LoneSurrogate {
        /// Byte offset of the escape.
        offset: usize,
    },
    /// String content is not valid UTF-8.
    InvalidUtf8 {
        /// Byte offset of the invalid sequence.
        offset: usize,
    },
    /// Content follows the top-level value.
    TrailingContent {
        /// Byte offset of the trailing input.
        offset: usize,
    },
}

impl fmt::Display for SadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { length, maximum } => {
                write!(formatter, "serialized input length {length} exceeds maximum {maximum}")
            }
            Self::SerializedTooLarge { length, maximum } => {
                write!(formatter, "serialized output length {length} exceeds maximum {maximum}")
            }
            Self::NotAnObject => formatter.write_str("self-addressing data must be a JSON object"),
            Self::DuplicateField { label } => write!(formatter, "duplicate field label {label:?}"),
            Self::MissingField { label } => write!(formatter, "missing field label {label:?}"),
            Self::NestingTooDeep { maximum } => {
                write!(formatter, "JSON nesting exceeds maximum depth {maximum}")
            }
            Self::UnsupportedNumber { offset } => write!(
                formatter,
                "non-integer number at offset {offset} is not exactly representable across languages"
            ),
            Self::IntegerOutOfRangeAt { offset } => write!(
                formatter,
                "integer at offset {offset} is outside the exactly representable range"
            ),
            Self::IntegerOutOfRange { value } => write!(
                formatter,
                "integer {value} is outside the exactly representable range \
                 {MIN_SAFE_INTEGER}..={MAX_SAFE_INTEGER}"
            ),
            Self::UnexpectedByte { offset, found } => match found {
                Some(byte) => write!(formatter, "unexpected byte {byte:#04x} at offset {offset}"),
                None => write!(formatter, "unexpected end of input at offset {offset}"),
            },
            Self::UnexpectedEnd => formatter.write_str("unexpected end of input"),
            Self::InvalidEscape { offset } => write!(formatter, "invalid string escape at offset {offset}"),
            Self::UnescapedControl { offset } => {
                write!(formatter, "unescaped control character at offset {offset}")
            }
            Self::LoneSurrogate { offset } => write!(formatter, "unpaired surrogate escape at offset {offset}"),
            Self::InvalidUtf8 { offset } => write!(formatter, "invalid UTF-8 at offset {offset}"),
            Self::TrailingContent { offset } => write!(formatter, "trailing content at offset {offset}"),
        }
    }
}

impl Error for SadError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertion_order_is_the_serialization_order() -> Result<(), SadError> {
        let mut sad = Sad::new();
        // Deliberately array-index-like labels: the reference hoists these ahead of the rest.
        sad.insert("b", SadValue::Integer(1))?;
        sad.insert("1", SadValue::Integer(2))?;
        sad.insert("0", SadValue::Integer(3))?;
        assert_eq!(sad.to_json_bytes()?, br#"{"b":1,"1":2,"0":3}"#);
        assert_eq!(sad.first_label(), Some("b"));
        assert_eq!(sad.len(), 3);
        Ok(())
    }

    #[test]
    fn every_escape_matches_the_reference_table() -> Result<(), SadError> {
        let mut sad = Sad::new();
        sad.insert("a", SadValue::text("\"\\/\u{08}\u{09}\u{0a}\u{0c}\u{0d}"))?;
        assert_eq!(sad.to_json_bytes()?, br#"{"a":"\"\\/\b\t\n\f\r"}"#.to_vec());

        let mut controls = Sad::new();
        controls.insert("c", SadValue::text("\u{00}\u{01}\u{0b}\u{0e}\u{1f}"))?;
        assert_eq!(
            controls.to_json_bytes()?,
            br#"{"c":"\u0000\u0001\u000b\u000e\u001f"}"#.to_vec()
        );

        // DEL and every non-ASCII scalar stay raw, exactly as `JSON.stringify` emits them.
        let mut raw = Sad::new();
        raw.insert("r", SadValue::text("\u{7f}ö漢\u{1f600}"))?;
        assert_eq!(raw.to_json_bytes()?, "{\"r\":\"\u{7f}ö漢\u{1f600}\"}".as_bytes());
        Ok(())
    }

    #[test]
    fn round_trip_parses_every_supported_value_kind() -> Result<(), SadError> {
        let source = br#"{"n":null,"b":true,"f":false,"i":-17,"t":"x","a":[1,[2],{"k":"v"}],"m":{}}"#;
        let parsed = Sad::from_json_bytes(source)?;
        assert_eq!(parsed.get("n"), Some(&SadValue::Null));
        assert_eq!(parsed.get("b"), Some(&SadValue::Bool(true)));
        assert_eq!(parsed.get("i"), Some(&SadValue::Integer(-17)));
        assert_eq!(parsed.get_text("t"), Some("x"));
        assert_eq!(parsed.to_json_bytes()?, source.to_vec());
        Ok(())
    }

    #[test]
    fn escape_sequences_decode_including_surrogate_pairs() -> Result<(), SadError> {
        let parsed = Sad::from_json_bytes(br#"{"a":"A\/\u00f6\ud83d\ude00"}"#)?;
        assert_eq!(parsed.get_text("a"), Some("A/\u{f6}\u{1f600}"));
        // Re-encoding normalizes the reference-permitted `\/` and `\uXXXX` forms to raw UTF-8,
        // which is exactly what `JSON.stringify` does after `JSON.parse`.
        assert_eq!(parsed.to_json_bytes()?, "{\"a\":\"A/\u{f6}\u{1f600}\"}".as_bytes());
        Ok(())
    }

    #[test]
    fn malformed_documents_return_typed_errors() {
        assert!(matches!(Sad::from_json_bytes(b"[]"), Err(SadError::NotAnObject)));
        assert!(matches!(
            Sad::from_json_bytes(br#"{"a":1}{"#),
            Err(SadError::TrailingContent { .. })
        ));
        assert!(matches!(
            Sad::from_json_bytes(br#"{"a":1,"a":2}"#),
            Err(SadError::DuplicateField { .. })
        ));
        assert!(matches!(
            Sad::from_json_bytes(br#"{"a":1.5}"#),
            Err(SadError::UnsupportedNumber { .. })
        ));
        assert!(matches!(
            Sad::from_json_bytes(br#"{"a":1e2}"#),
            Err(SadError::UnsupportedNumber { .. })
        ));
        assert!(matches!(
            Sad::from_json_bytes(br#"{"a":9007199254740992}"#),
            Err(SadError::IntegerOutOfRangeAt { .. })
        ));
        assert!(matches!(
            Sad::from_json_bytes(br#"{"a":"\x"}"#),
            Err(SadError::InvalidEscape { .. })
        ));
        assert!(matches!(
            Sad::from_json_bytes(br#"{"a":"\ud800"}"#),
            Err(SadError::LoneSurrogate { .. })
        ));
        assert!(matches!(
            Sad::from_json_bytes(b"{\"a\":\"\n\"}"),
            Err(SadError::UnescapedControl { .. })
        ));
        assert!(matches!(
            Sad::from_json_bytes(br#"{"a":"#),
            Err(SadError::UnexpectedByte { found: None, .. })
        ));
        assert!(matches!(
            Sad::from_json_bytes(br#"{"a":"unterminated"#),
            Err(SadError::UnexpectedEnd)
        ));
        assert!(matches!(
            Sad::from_json_bytes(br#"{"a":01}"#),
            Err(SadError::UnexpectedByte { .. })
        ));
        assert!(matches!(
            Sad::from_json_bytes(b""),
            Err(SadError::UnexpectedByte { .. })
        ));
    }

    #[test]
    fn safe_integer_boundaries_are_exact() -> Result<(), SadError> {
        assert!(SadValue::integer(MAX_SAFE_INTEGER).is_ok());
        assert!(SadValue::integer(MIN_SAFE_INTEGER).is_ok());
        assert!(matches!(
            SadValue::integer(MAX_SAFE_INTEGER + 1),
            Err(SadError::IntegerOutOfRange { .. })
        ));
        let parsed = Sad::from_json_bytes(br#"{"a":9007199254740991,"b":-9007199254740991}"#)?;
        assert_eq!(parsed.get("a"), Some(&SadValue::Integer(MAX_SAFE_INTEGER)));
        assert_eq!(parsed.get("b"), Some(&SadValue::Integer(MIN_SAFE_INTEGER)));
        Ok(())
    }

    #[test]
    fn nesting_and_size_bounds_are_enforced() {
        let deep = format!("{{\"a\":{}{}}}", "[".repeat(70), "]".repeat(70));
        assert!(matches!(
            Sad::from_json_bytes(deep.as_bytes()),
            Err(SadError::NestingTooDeep { .. })
        ));
        let oversized = vec![b' '; MAX_SERIALIZED_BYTES + 1];
        assert!(matches!(
            Sad::from_json_bytes(&oversized),
            Err(SadError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn whitespace_is_accepted_but_not_reproduced() -> Result<(), SadError> {
        let parsed = Sad::from_json_bytes(b" { \"a\" : [ 1 , 2 ] } ")?;
        assert_eq!(parsed.to_json_bytes()?, br#"{"a":[1,2]}"#.to_vec());
        Ok(())
    }

    #[test]
    fn duplicate_insertion_is_rejected_and_replacement_keeps_position() -> Result<(), SadError> {
        let mut sad = Sad::new();
        sad.insert("v", SadValue::text("first"))?;
        sad.insert("t", SadValue::text("icp"))?;
        assert!(matches!(
            sad.insert("v", SadValue::text("again")),
            Err(SadError::DuplicateField { .. })
        ));
        sad.replace_existing("v", SadValue::text("second"))?;
        assert_eq!(sad.to_json_bytes()?, br#"{"v":"second","t":"icp"}"#.to_vec());
        assert!(matches!(
            sad.replace_existing("absent", SadValue::Null),
            Err(SadError::MissingField { .. })
        ));
        Ok(())
    }
}
