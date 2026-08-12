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
    /// Qualified material used a code that cannot represent a verification key.
    InvalidVerificationCode {
        /// Rejected, bounded derivation code.
        code: &'static str,
    },
    /// Qualified material selected a verification algorithm absent from the pinned reference.
    UnsupportedVerificationAlgorithm {
        /// Rejected, bounded verification-key derivation code.
        code: &'static str,
    },
    /// Qualified material used a code that cannot represent an unindexed signature.
    InvalidSignatureCode {
        /// Rejected, bounded derivation code.
        code: &'static str,
    },
    /// An unindexed signature was associated with a verifier for a different algorithm.
    SignatureVerifierMismatch {
        /// Algorithm selected by the signature derivation code.
        signature_algorithm: &'static str,
        /// Algorithm selected by the verification key derivation code.
        verifier_algorithm: &'static str,
    },
    /// Public verification-key bytes are not a valid point for the selected algorithm.
    InvalidVerificationKey {
        /// Stable algorithm name without key material.
        algorithm: &'static str,
    },
    /// A detached signature has the wrong byte width for the selected algorithm.
    InvalidSignatureLength {
        /// Stable algorithm name.
        algorithm: &'static str,
        /// Required signature width.
        expected: usize,
        /// Supplied signature width.
        actual: usize,
    },
    /// A fixed-width detached signature is not a valid scalar encoding.
    InvalidSignatureEncoding {
        /// Stable algorithm name.
        algorithm: &'static str,
    },
    /// A structurally valid signature did not authenticate the complete serialization.
    VerificationFailed {
        /// Stable algorithm name.
        algorithm: &'static str,
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
            Self::InvalidVerificationCode { code } => {
                write!(
                    formatter,
                    "CESR derivation code {code} is not verification-key material"
                )
            }
            Self::UnsupportedVerificationAlgorithm { code } => {
                write!(formatter, "verification algorithm for CESR code {code} is unsupported")
            }
            Self::InvalidSignatureCode { code } => {
                write!(
                    formatter,
                    "CESR derivation code {code} is not unindexed-signature material"
                )
            }
            Self::SignatureVerifierMismatch {
                signature_algorithm,
                verifier_algorithm,
            } => write!(
                formatter,
                "{signature_algorithm} signature cannot be associated with {verifier_algorithm} verifier"
            ),
            Self::InvalidVerificationKey { algorithm } => {
                write!(formatter, "invalid {algorithm} public verification key")
            }
            Self::InvalidSignatureLength {
                algorithm,
                expected,
                actual,
            } => write!(
                formatter,
                "invalid {algorithm} signature length: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidSignatureEncoding { algorithm } => {
                write!(formatter, "invalid {algorithm} signature encoding")
            }
            Self::VerificationFailed { algorithm } => {
                write!(formatter, "{algorithm} signature verification failed")
            }
        }
    }
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cesr { source } => Some(source.as_ref()),
            Self::InvalidDigestCode { .. }
            | Self::UnsupportedDigestAlgorithm { .. }
            | Self::InvalidVerificationCode { .. }
            | Self::UnsupportedVerificationAlgorithm { .. }
            | Self::InvalidSignatureCode { .. }
            | Self::SignatureVerifierMismatch { .. }
            | Self::InvalidVerificationKey { .. }
            | Self::InvalidSignatureLength { .. }
            | Self::InvalidSignatureEncoding { .. }
            | Self::VerificationFailed { .. } => None,
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
