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
            Self::InvalidCodeCharacter { index, byte } => {
                write!(formatter, "invalid CESR code byte 0x{byte:02x} at offset {index}")
            }
            Self::UnsupportedCode { code } => write!(formatter, "unsupported CESR code {code}"),
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
