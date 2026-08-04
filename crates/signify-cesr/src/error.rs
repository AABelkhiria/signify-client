//! Typed failures shared by CESR foundation operations.

use std::{error::Error, fmt, str::Utf8Error};

/// Errors produced while validating or converting CESR foundation data.
///
/// Variants carry bounded structural context and never include the full input.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CesrError {
    /// An operation that requires material received no bytes or characters.
    EmptyInput {
        /// Stable name of the operation or input kind.
        context: &'static str,
    },
    /// An input length is structurally invalid for the requested operation.
    InvalidLength {
        /// Stable name of the operation or input kind.
        context: &'static str,
        /// Observed length.
        length: usize,
    },
    /// A stream ended before one complete CESR primitive was available.
    Truncated {
        /// Stable name of the primitive or field being parsed.
        context: &'static str,
        /// Total bytes or characters required for the primitive.
        needed: usize,
        /// Bytes or characters available in the input.
        available: usize,
    },
    /// A strict parser found material after one complete CESR primitive.
    TrailingMaterial {
        /// Stable name of the encoded representation.
        context: &'static str,
        /// Number of unconsumed bytes or characters.
        length: usize,
    },
    /// Raw material has a different length from that selected by its fixed derivation code.
    RawSizeMismatch {
        /// Stable name of the raw-material input.
        context: &'static str,
        /// Required raw size in bytes.
        expected: usize,
        /// Observed raw size in bytes.
        actual: usize,
    },
    /// An input exceeds the operation's explicit resource bound.
    InputTooLarge {
        /// Stable name of the operation or input kind.
        context: &'static str,
        /// Observed length.
        length: usize,
        /// Largest accepted length.
        maximum: usize,
    },
    /// URL-safe Base64 text contains a byte outside the permitted alphabet.
    InvalidBase64Character {
        /// Zero-based byte offset of the invalid character.
        index: usize,
        /// Invalid ASCII byte.
        byte: u8,
    },
    /// URL-safe Base64 padding is misplaced or has the wrong length.
    InvalidBase64Padding {
        /// Zero-based byte offset at which invalid padding was detected.
        index: usize,
    },
    /// URL-safe Base64 has non-zero unused bits and is not canonical.
    NonCanonicalBase64,
    /// CESR code alignment bits or lead bytes are not zero.
    NonZeroPadding {
        /// Whether the failure was in code-alignment bits or lead bytes.
        context: &'static str,
    },
    /// A variable derivation code carries an impossible or unsupported material size.
    InvalidVariableSize {
        /// Stable description of the rejected size relationship.
        context: &'static str,
        /// Decoded CESR size in three-byte triplets.
        size: u64,
    },
    /// A CESR derivation code contains a byte outside the permitted code alphabet.
    InvalidCodeCharacter {
        /// Zero-based byte offset of the invalid character.
        index: usize,
        /// Invalid byte.
        byte: u8,
    },
    /// A syntactically complete derivation code is absent from the supported table.
    UnsupportedCode {
        /// Complete rejected code, bounded by derivation-code parsing to at most four ASCII bytes.
        code: String,
    },
    /// An indexed-material index exceeds the field width selected by its code.
    IndexOutOfRange {
        /// Stable name of the index field.
        context: &'static str,
        /// Rejected index value.
        value: u32,
        /// Largest value accepted by the selected code.
        maximum: u32,
    },
    /// Current and prior-list indices violate the selected code's relationship.
    InvalidIndexRelation {
        /// Stable description of the violated relationship.
        context: &'static str,
    },
    /// A CESR counter value does not fit the soft field selected by its code.
    CounterOutOfRange {
        /// Rejected counter value.
        value: u64,
        /// Largest value accepted by the selected counter code.
        maximum: u64,
    },
    /// Dotted semantic-version text is not a supported three-component integer form.
    InvalidSemanticVersion {
        /// Zero-based component containing invalid text, when a component was reached.
        component: Option<usize>,
    },
    /// A semantic-version component exceeds the CESR single-digit range.
    SemanticVersionOutOfRange {
        /// Zero-based major, minor, or patch component.
        component: usize,
        /// Rejected component value.
        value: u64,
    },
    /// A table entry describes variable-length indexed material that is not implemented upstream.
    UnsupportedVariableLength {
        /// Stable name of the indexed material operation.
        context: &'static str,
    },
    /// Hexadecimal text used for an exact CESR number contains an invalid byte.
    InvalidHexCharacter {
        /// Zero-based byte offset of the invalid character.
        index: usize,
        /// Invalid input byte.
        byte: u8,
    },
    /// Qualified material uses a supported derivation code that is not numeric.
    InvalidNumericCode {
        /// Rejected, bounded derivation code.
        code: &'static str,
    },
    /// A numeric value is encoded with a wider CESR derivation code than necessary.
    NonCanonicalNumber {
        /// Derivation code found in the encoded material.
        code: &'static str,
        /// Smallest derivation code for the decoded value.
        canonical: &'static str,
    },
    /// An integer cannot be represented by the selected Rust integer type.
    IntegerOverflow {
        /// Stable name of the conversion being performed.
        context: &'static str,
    },
    /// An integer does not fit in the requested number of output digits or bytes.
    ValueDoesNotFit {
        /// Stable name of the conversion being performed.
        context: &'static str,
        /// Requested output length.
        length: usize,
    },
    /// Summing or deriving lengths overflowed `usize`.
    LengthOverflow {
        /// Stable name of the operation being performed.
        context: &'static str,
    },
    /// Bytes are not valid UTF-8 text.
    InvalidUtf8 {
        /// Standard-library validation error.
        source: Utf8Error,
    },
}

impl fmt::Display for CesrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput { context } => write!(formatter, "{context} must not be empty"),
            Self::InvalidLength { context, length } => {
                write!(formatter, "invalid {context} length: {length}")
            }
            Self::Truncated {
                context,
                needed,
                available,
            } => write!(
                formatter,
                "truncated {context}: need {needed}, only {available} available"
            ),
            Self::TrailingMaterial { context, length } => {
                write!(formatter, "{context} has {length} trailing bytes or characters")
            }
            Self::RawSizeMismatch {
                context,
                expected,
                actual,
            } => write!(
                formatter,
                "invalid {context} size: expected {expected} bytes, got {actual}"
            ),
            Self::InputTooLarge {
                context,
                length,
                maximum,
            } => write!(formatter, "{context} length {length} exceeds the maximum {maximum}"),
            Self::InvalidBase64Character { index, byte } => {
                write!(formatter, "invalid URL-safe Base64 byte 0x{byte:02x} at offset {index}")
            }
            Self::InvalidBase64Padding { index } => {
                write!(formatter, "invalid URL-safe Base64 padding at offset {index}")
            }
            Self::NonCanonicalBase64 => formatter.write_str("non-canonical URL-safe Base64 encoding"),
            Self::NonZeroPadding { context } => {
                write!(formatter, "non-zero CESR {context}")
            }
            Self::InvalidVariableSize { context, size } => {
                write!(formatter, "invalid variable material size {size}: {context}")
            }
            Self::InvalidCodeCharacter { index, byte } => {
                write!(formatter, "invalid CESR code byte 0x{byte:02x} at offset {index}")
            }
            Self::UnsupportedCode { code } => write!(formatter, "unsupported CESR code {code}"),
            Self::IndexOutOfRange {
                context,
                value,
                maximum,
            } => write!(formatter, "{context} {value} exceeds maximum {maximum}"),
            Self::InvalidIndexRelation { context } => formatter.write_str(context),
            Self::CounterOutOfRange { value, maximum } => {
                write!(formatter, "counter value {value} exceeds maximum {maximum}")
            }
            Self::InvalidSemanticVersion { component } => match component {
                Some(component) => write!(
                    formatter,
                    "invalid CESR semantic-version component at position {component}"
                ),
                None => formatter.write_str("invalid CESR semantic version"),
            },
            Self::SemanticVersionOutOfRange { component, value } => write!(
                formatter,
                "CESR semantic-version component {component} value {value} exceeds maximum 63"
            ),
            Self::UnsupportedVariableLength { context } => {
                write!(formatter, "variable-length {context} is unsupported")
            }
            Self::InvalidHexCharacter { index, byte } => {
                write!(formatter, "invalid hexadecimal byte 0x{byte:02x} at offset {index}")
            }
            Self::InvalidNumericCode { code } => {
                write!(formatter, "CESR derivation code {code} is not numeric")
            }
            Self::NonCanonicalNumber { code, canonical } => write!(
                formatter,
                "CESR number code {code} is non-canonical; expected {canonical}"
            ),
            Self::IntegerOverflow { context } => {
                write!(formatter, "integer overflow while decoding {context}")
            }
            Self::ValueDoesNotFit { context, length } => {
                write!(formatter, "value does not fit in {length} {context}")
            }
            Self::LengthOverflow { context } => {
                write!(formatter, "length overflow while constructing {context}")
            }
            Self::InvalidUtf8 { source } => write!(formatter, "invalid UTF-8: {source}"),
        }
    }
}

impl Error for CesrError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidUtf8 { source } => Some(source),
            _ => None,
        }
    }
}
