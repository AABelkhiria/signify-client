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
    /// Indexed material used a code that cannot represent an indexed signature.
    InvalidIndexedSignatureCode {
        /// Rejected, bounded indexed derivation code.
        code: &'static str,
    },
    /// Qualified material used a code that cannot represent a private signing seed.
    InvalidSigningCode {
        /// Rejected, bounded derivation code.
        code: &'static str,
    },
    /// Qualified material selected a private signing algorithm absent from the pinned reference.
    UnsupportedSigningAlgorithm {
        /// Rejected, bounded signing-seed derivation code.
        code: &'static str,
    },
    /// Qualified material used a code that cannot represent a key-derivation salt.
    InvalidSaltCode {
        /// Rejected, bounded derivation code.
        code: &'static str,
    },
    /// Qualified material used a code that cannot represent supported ciphertext.
    InvalidCiphertextCode {
        /// Rejected, bounded derivation code.
        code: &'static str,
    },
    /// Raw ciphertext inference received neither supported fixed width.
    InvalidCiphertextLength {
        /// Supplied raw ciphertext width.
        actual: usize,
    },
    /// A deterministic key-derivation path exceeds the documented byte ceiling.
    DerivationPathTooLong {
        /// Maximum accepted UTF-8 byte length.
        maximum: usize,
        /// Supplied UTF-8 byte length.
        actual: usize,
    },
    /// Memory required by the selected key-derivation profile could not be reserved.
    KeyDerivationMemoryUnavailable {
        /// Number of bytes required by the selected profile.
        required: usize,
        /// Underlying allocation failure.
        source: Box<dyn Error + Send + Sync>,
    },
    /// The established key-derivation primitive rejected the operation.
    KeyDerivationFailed {
        /// Stable primitive name without secret inputs.
        algorithm: &'static str,
        /// Underlying primitive failure.
        source: Box<dyn Error + Send + Sync>,
    },
    /// A signature was associated with a verifier for a different algorithm.
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
    /// The operating system could not provide cryptographically secure random bytes.
    EntropyUnavailable {
        /// Underlying operating-system randomness failure.
        source: Box<dyn Error + Send + Sync>,
    },
    /// An established cryptographic primitive rejected a signing operation.
    SigningFailed {
        /// Stable algorithm name.
        algorithm: &'static str,
        /// Underlying primitive failure.
        source: Box<dyn Error + Send + Sync>,
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
            Self::InvalidIndexedSignatureCode { code } => {
                write!(
                    formatter,
                    "CESR indexed derivation code {code} is not signature material"
                )
            }
            Self::InvalidSigningCode { code } => {
                write!(
                    formatter,
                    "CESR derivation code {code} is not private signing-seed material"
                )
            }
            Self::UnsupportedSigningAlgorithm { code } => {
                write!(formatter, "signing algorithm for CESR seed code {code} is unsupported")
            }
            Self::InvalidSaltCode { code } => {
                write!(
                    formatter,
                    "CESR derivation code {code} is not key-derivation salt material"
                )
            }
            Self::InvalidCiphertextCode { code } => {
                write!(formatter, "CESR derivation code {code} is not supported ciphertext")
            }
            Self::InvalidCiphertextLength { actual } => write!(
                formatter,
                "invalid raw ciphertext length: expected 72 or 92 bytes, got {actual}"
            ),
            Self::DerivationPathTooLong { maximum, actual } => write!(
                formatter,
                "key-derivation path is too long: maximum {maximum} UTF-8 bytes, got {actual}"
            ),
            Self::KeyDerivationMemoryUnavailable { required, .. } => write!(
                formatter,
                "key-derivation memory is unavailable for the required {required} bytes"
            ),
            Self::KeyDerivationFailed { algorithm, .. } => {
                write!(formatter, "{algorithm} key derivation failed")
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
            Self::EntropyUnavailable { .. } => {
                formatter.write_str("operating-system cryptographic randomness is unavailable")
            }
            Self::SigningFailed { algorithm, .. } => {
                write!(formatter, "{algorithm} signing failed")
            }
        }
    }
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cesr { source } => Some(source.as_ref()),
            Self::EntropyUnavailable { source }
            | Self::SigningFailed { source, .. }
            | Self::KeyDerivationMemoryUnavailable { source, .. }
            | Self::KeyDerivationFailed { source, .. } => Some(source.as_ref()),
            Self::InvalidDigestCode { .. }
            | Self::UnsupportedDigestAlgorithm { .. }
            | Self::InvalidVerificationCode { .. }
            | Self::UnsupportedVerificationAlgorithm { .. }
            | Self::InvalidSignatureCode { .. }
            | Self::InvalidIndexedSignatureCode { .. }
            | Self::InvalidSigningCode { .. }
            | Self::UnsupportedSigningAlgorithm { .. }
            | Self::InvalidSaltCode { .. }
            | Self::InvalidCiphertextCode { .. }
            | Self::InvalidCiphertextLength { .. }
            | Self::DerivationPathTooLong { .. }
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
