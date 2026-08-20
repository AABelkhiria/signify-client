//! Failures this crate can report while decoding a KERIA document.

use core::fmt;
use std::error::Error;

/// Stable KERIA record failures.
///
/// Decoding failures that JSON itself can describe — a missing field, a wrong type, an unknown
/// value of a closed code table, nesting beyond [`MAX_NESTING_DEPTH`](crate::api::MAX_NESTING_DEPTH)
/// — arrive as [`ApiError::Json`] with the `serde_json` error preserved as the source. The other
/// variants are cross-field conditions the schema states but JSON cannot.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApiError {
    /// A document exceeds the byte bound it was decoded under.
    DocumentTooLarge {
        /// Actual length in bytes.
        length: usize,
        /// Bound the document was decoded under.
        limit: usize,
    },
    /// An identifier record names no key-manager state.
    ///
    /// The schema requires exactly one of `salty`, `randy`, `group`, or `extern`.
    MissingKeyManagerState,
    /// An identifier record names more than one key-manager state.
    ///
    /// The schema's union admits exactly one; two would leave which algorithm holds the keys
    /// undecided. The reference's own excess-property check refuses this too, while its runtime
    /// accepts it and reads whichever field the caller happens to look at.
    AmbiguousKeyManagerState {
        /// The two state names found, in schema order.
        names: [&'static str; 2],
    },
    /// An identifier record was decoded as accepted but carries no key state.
    MissingKeyState,
    /// An identifier record was decoded as pending but carries key state.
    UnexpectedKeyState,
    /// An embedded message carries an event kind the field cannot hold.
    UnexpectedEventKind {
        /// Field label the message was embedded under.
        label: &'static str,
        /// Ilk the message actually carries.
        found: &'static str,
        /// Ilks the field accepts, in schema order.
        expected: &'static [&'static str],
    },
    /// A document is not valid JSON, does not match the record, or nests too deeply.
    Json {
        /// Underlying `serde_json` failure.
        source: Box<serde_json::Error>,
    },
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge { length, limit } => {
                write!(formatter, "document of {length} bytes exceeds the {limit}-byte limit")
            }
            Self::MissingKeyManagerState => formatter.write_str("an identifier record names no key-manager state"),
            Self::AmbiguousKeyManagerState { names } => {
                let [first, second] = names;
                write!(
                    formatter,
                    "an identifier record names both {first} and {second} key-manager state"
                )
            }
            Self::MissingKeyState => formatter.write_str("an accepted identifier record carries no key state"),
            Self::UnexpectedKeyState => formatter.write_str("a pending identifier record carries key state"),
            Self::UnexpectedEventKind { label, found, expected } => write!(
                formatter,
                "the {label} field carries a {found} message, which is not one of {expected:?}"
            ),
            Self::Json { .. } => formatter.write_str("a KERIA document could not be decoded"),
        }
    }
}

impl Error for ApiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_readable_text_and_preserve_their_source() -> Result<(), Box<dyn Error>> {
        let malformed = serde_json::from_str::<u8>("[")
            .err()
            .ok_or("`[` must not decode as a u8")?;
        let json = ApiError::Json {
            source: Box::new(malformed),
        };
        assert!(json.source().is_some());

        for error in [
            ApiError::DocumentTooLarge { length: 9, limit: 8 },
            ApiError::MissingKeyManagerState,
            ApiError::MissingKeyState,
            ApiError::UnexpectedKeyState,
            ApiError::AmbiguousKeyManagerState {
                names: ["salty", "randy"],
            },
            ApiError::UnexpectedEventKind {
                label: "icp",
                found: "ixn",
                expected: &["icp", "dip"],
            },
            json,
        ] {
            assert!(!error.to_string().is_empty());
        }
        Ok(())
    }

    #[test]
    fn non_json_errors_have_no_source() {
        assert!(ApiError::MissingKeyManagerState.source().is_none());
        assert!(ApiError::DocumentTooLarge { length: 9, limit: 8 }.source().is_none());
    }
}
