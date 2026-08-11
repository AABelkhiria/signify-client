//! Typed failures for cryptographic material and operations.

use std::{error::Error, fmt};

use signify_cesr::CesrError;

/// Errors produced while validating or operating on cryptographic material.
///
/// Variants distinguish semantic code failures from lower-level CESR parsing and encoding errors.
/// Error messages contain only bounded public derivation-code text and structural context.
#[derive(Debug)]
#[non_exhaustive]
pub enum CryptoError {
    /// A CESR parsing, sizing, or canonical-encoding operation failed.
    Cesr {
        /// Underlying CESR failure.
        source: Box<CesrError>,
    },
    /// Qualified material used a code outside the CESR digest family.
    InvalidDigestCode {
        /// Rejected, bounded derivation code.
        code: &'static str,
    },
    /// Qualified material selected a digest algorithm not implemented by the pinned reference.
    UnsupportedDigestAlgorithm {
        /// Rejected, bounded digest derivation code.
        code: &'static str,
    },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cesr { source } => write!(formatter, "CESR cryptographic material error: {source}"),
            Self::InvalidDigestCode { code } => {
                write!(formatter, "CESR derivation code {code} is not digest material")
            }
            Self::UnsupportedDigestAlgorithm { code } => {
                write!(formatter, "digest algorithm for CESR code {code} is unsupported")
            }
        }
    }
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cesr { source } => Some(source.as_ref()),
            Self::InvalidDigestCode { .. } | Self::UnsupportedDigestAlgorithm { .. } => None,
        }
    }
}

impl From<CesrError> for CryptoError {
    fn from(source: CesrError) -> Self {
        Self::Cesr {
            source: Box::new(source),
        }
    }
}
