//! What a client lifecycle can fail at.
//!
//! The reference throws strings — `bran must be 21 characters`, `agent does not exist for
//! controller …`, `commitment to controller AID missing in agent inception event`, `client need to
//! call connect first`. Each becomes a variant here, except the last, which the type system makes
//! unreachable.

use core::fmt;
use std::error::Error;

use signify_cesr::CesrError;
use signify_crypto::CryptoError;
use signify_http::header::HeaderError;
use signify_http::request::RequestError;
use signify_http::response::ResponseError;
use signify_http::signature::authentication::AuthenticationError;
use signify_http::signature::transport::{ResponseAuthenticationError, SigningError};
use signify_http::transport::TransportError;
use signify_keri::controller::ControllerError;
use signify_keri::manager::ManagerError;
use signify_keri::serialization::SerializationError;

/// Largest response body detail kept in an error message, in bytes.
const MAX_DETAIL_BYTES: usize = 256;

/// Stable client-lifecycle failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// A passcode is not exactly [`PASSCODE_LENGTH`](crate::config::PASSCODE_LENGTH) characters.
    InvalidPasscodeLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// A passcode holds a character outside the URL-safe Base64 alphabet.
    PasscodeNotBase64 {
        /// Zero-based position of the first offending character.
        position: usize,
    },
    /// The agent resource does not exist; the reference's `agent does not exist for controller …`.
    AgentNotFound {
        /// The controller prefix the agent was looked up for.
        controller: String,
    },
    /// The agent's inception event does not anchor this controller.
    ///
    /// The reference's `commitment to controller AID missing in agent inception event`. An agent
    /// that fails this is either not ours or has been substituted, so nothing else is attempted.
    AgentNotDelegatedToController {
        /// The controller this client derived.
        expected: String,
        /// The controller the agent's inception anchors.
        actual: String,
    },
    /// The agent state response did not carry an agent, or did not carry a controller.
    IncompleteAgentState {
        /// Which half was missing.
        missing: &'static str,
    },
    /// A request returned a non-success status.
    ///
    /// The reference builds one message out of the method, path, status, status text, and body;
    /// here the parts stay separate and the body is bounded.
    Status {
        /// The status returned.
        status: u16,
        /// The bounded body, for diagnosis.
        detail: String,
    },
    /// A response could not be decoded as the document it should have been.
    Decode {
        /// Underlying failure.
        source: Box<ResponseError>,
    },
    /// Building a request failed.
    Request {
        /// Underlying failure.
        source: Box<RequestError>,
    },
    /// A header name or value was unusable.
    Header {
        /// Underlying failure.
        source: Box<HeaderError>,
    },
    /// The transport failed.
    Transport {
        /// Underlying failure.
        source: Box<TransportError>,
    },
    /// Signing a request failed.
    Signing {
        /// Underlying failure.
        source: Box<SigningError>,
    },
    /// Preparing the signing or verifying material failed.
    Authentication {
        /// Underlying failure.
        source: Box<AuthenticationError>,
    },
    /// A response did not authenticate.
    ResponseAuthentication {
        /// Underlying failure.
        source: Box<ResponseAuthenticationError>,
    },
    /// The controller could not be derived or advanced.
    Controller {
        /// Underlying failure.
        source: Box<ControllerError>,
    },
    /// The key manager could not be built.
    Manager {
        /// Underlying failure.
        source: Box<ManagerError>,
    },
    /// A serialized event could not be read or written.
    Serialization {
        /// Underlying failure.
        source: Box<SerializationError>,
    },
    /// A cryptographic value could not be encoded.
    Crypto {
        /// Underlying failure.
        source: Box<CryptoError>,
    },
    /// A qualified value could not be encoded.
    Cesr {
        /// Underlying failure.
        source: Box<CesrError>,
    },
    /// Operating-system randomness was unavailable.
    Randomness,
}

impl ClientError {
    /// Builds a status failure, bounding the body kept for diagnosis.
    #[must_use]
    pub(crate) fn status(status: u16, body: &[u8]) -> Self {
        let text = String::from_utf8_lossy(body);
        let detail = text
            .char_indices()
            .take_while(|(index, character)| index.saturating_add(character.len_utf8()) <= MAX_DETAIL_BYTES)
            .map(|(_, character)| character)
            .collect();
        Self::Status { status, detail }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPasscodeLength { expected, actual } => write!(
                formatter,
                "a passcode must be exactly {expected} characters, not {actual}"
            ),
            Self::PasscodeNotBase64 { position } => write!(
                formatter,
                "a passcode character at position {position} is outside the URL-safe Base64 alphabet"
            ),
            Self::AgentNotFound { controller } => {
                write!(formatter, "no agent exists for controller {controller}")
            }
            Self::AgentNotDelegatedToController { expected, actual } => write!(
                formatter,
                "the agent's inception anchors {actual}, not this controller {expected}"
            ),
            Self::IncompleteAgentState { missing } => {
                write!(formatter, "the agent state carried no {missing}")
            }
            Self::Status { status, detail } => write!(formatter, "the agent answered {status}: {detail}"),
            Self::Decode { source } => write!(formatter, "response decoding failed: {source}"),
            Self::Request { source } => write!(formatter, "request construction failed: {source}"),
            Self::Header { source } => write!(formatter, "header construction failed: {source}"),
            Self::Transport { source } => write!(formatter, "transport failed: {source}"),
            Self::Signing { source } => write!(formatter, "request signing failed: {source}"),
            Self::Authentication { source } => write!(formatter, "authentication setup failed: {source}"),
            Self::ResponseAuthentication { source } => {
                write!(formatter, "response authentication failed: {source}")
            }
            Self::Controller { source } => write!(formatter, "controller derivation failed: {source}"),
            Self::Manager { source } => write!(formatter, "key manager construction failed: {source}"),
            Self::Serialization { source } => write!(formatter, "serialization failed: {source}"),
            Self::Crypto { source } => write!(formatter, "cryptographic encoding failed: {source}"),
            Self::Cesr { source } => write!(formatter, "qualified encoding failed: {source}"),
            Self::Randomness => formatter.write_str("operating-system randomness is unavailable"),
        }
    }
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode { source } => Some(source),
            Self::Request { source } => Some(source),
            Self::Header { source } => Some(source),
            Self::Transport { source } => Some(source),
            Self::Signing { source } => Some(source),
            Self::Authentication { source } => Some(source),
            Self::ResponseAuthentication { source } => Some(source),
            Self::Controller { source } => Some(source),
            Self::Manager { source } => Some(source),
            Self::Serialization { source } => Some(source),
            Self::Crypto { source } => Some(source),
            Self::Cesr { source } => Some(source),
            Self::InvalidPasscodeLength { .. }
            | Self::PasscodeNotBase64 { .. }
            | Self::AgentNotFound { .. }
            | Self::AgentNotDelegatedToController { .. }
            | Self::IncompleteAgentState { .. }
            | Self::Status { .. }
            | Self::Randomness => None,
        }
    }
}

macro_rules! layered {
    ($source:ty, $variant:ident) => {
        impl From<$source> for ClientError {
            fn from(source: $source) -> Self {
                Self::$variant {
                    source: Box::new(source),
                }
            }
        }
    };
}

layered!(ResponseError, Decode);
layered!(RequestError, Request);
layered!(HeaderError, Header);
layered!(TransportError, Transport);
layered!(SigningError, Signing);
layered!(AuthenticationError, Authentication);
layered!(ResponseAuthenticationError, ResponseAuthentication);
layered!(ControllerError, Controller);
layered!(ManagerError, Manager);
layered!(SerializationError, Serialization);
layered!(CryptoError, Crypto);
layered!(CesrError, Cesr);

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a status failure's two fields, or an error naming the wrong variant.
    fn status_parts(error: &ClientError) -> Result<(u16, &str), String> {
        match error {
            ClientError::Status { status, detail } => Ok((*status, detail.as_str())),
            other => Err(format!("the wrong variant was built: {other}")),
        }
    }

    #[test]
    fn a_status_failure_bounds_the_body_it_keeps() -> Result<(), String> {
        let error = ClientError::status(500, &b"x".repeat(MAX_DETAIL_BYTES * 4));
        let (status, detail) = status_parts(&error)?;
        assert_eq!(status, 500);
        assert_eq!(detail.len(), MAX_DETAIL_BYTES);
        assert!(error.to_string().contains("500"));
        Ok(())
    }

    #[test]
    fn a_status_body_is_never_split_through_a_character() -> Result<(), String> {
        // Four-byte characters, so a naive byte truncation would produce invalid UTF-8.
        let body = "\u{1f510}".repeat(200);
        let error = ClientError::status(400, body.as_bytes());
        let (_, detail) = status_parts(&error)?;
        assert!(detail.len() <= MAX_DETAIL_BYTES);
        assert!(detail.chars().all(|character| character == '\u{1f510}'));
        Ok(())
    }

    #[test]
    fn every_failure_describes_itself() {
        let failures = [
            ClientError::InvalidPasscodeLength {
                expected: 21,
                actual: 5,
            },
            ClientError::PasscodeNotBase64 { position: 3 },
            ClientError::AgentNotFound {
                controller: "ECTRL".to_owned(),
            },
            ClientError::AgentNotDelegatedToController {
                expected: "ECTRL".to_owned(),
                actual: "EOTHER".to_owned(),
            },
            ClientError::IncompleteAgentState { missing: "agent" },
            ClientError::status(404, b"missing"),
            ClientError::Randomness,
        ];
        for failure in &failures {
            assert!(!failure.to_string().is_empty());
            assert!(failure.source().is_none());
        }
    }
}
