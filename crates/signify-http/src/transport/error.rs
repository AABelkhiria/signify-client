//! Failures a transport reports.
//!
//! A non-success HTTP status is **not** one of these: a response that arrived is a [`Response`],
//! whatever its status, and turning a status into a typed failure is [`crate::response`]'s
//! job. These are the ways a request fails to produce a response at all, plus the construction
//! failures that keep a malformed request from being sent.
//!
//! [`Response`]: crate::transport::Response

use core::fmt;
use std::error::Error;

use crate::header::HeaderError;

/// Longest transport-supplied message text kept in an error.
const MAX_MESSAGE_BYTES: usize = 256;

/// Stable transport failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum TransportError {
    /// A URL is empty, oversized, not absolute `http`/`https`, or holds a forbidden byte.
    InvalidUrl {
        /// Why the URL was refused.
        reason: &'static str,
    },
    /// A request body exceeds [`MAX_REQUEST_BODY_BYTES`](crate::transport::MAX_REQUEST_BODY_BYTES).
    RequestBodyTooLarge {
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// A response body exceeds the limit the request set.
    ///
    /// A transport must stop reading at the limit rather than buffering the whole body first, so
    /// `actual` is what was read before the transport gave up, not necessarily the full size.
    ResponseBodyTooLarge {
        /// The limit that was exceeded, in bytes.
        limit: usize,
        /// Bytes read before the transport stopped.
        actual: usize,
    },
    /// A response-body limit is above
    /// [`MAX_RESPONSE_BODY_LIMIT`](crate::transport::MAX_RESPONSE_BODY_LIMIT).
    ResponseLimitTooLarge {
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Requested limit in bytes.
        requested: usize,
    },
    /// A status code is outside the range HTTP defines.
    InvalidStatus {
        /// The code in question.
        status: u16,
    },
    /// The request did not complete within its deadline.
    Timeout {
        /// The deadline that elapsed, in milliseconds.
        milliseconds: u64,
    },
    /// The transport could not reach the server, or the connection failed mid-request.
    ///
    /// The message is bounded and comes from the transport implementation; it must never carry a
    /// request body, an authorization header, or any other secret.
    Connect {
        /// Bounded description of what failed.
        message: String,
    },
    /// The server's answer could not be read as an HTTP response.
    InvalidResponse {
        /// Bounded description of what was wrong.
        message: String,
    },
    /// A scripted transport ran out of scripted outcomes.
    ///
    /// Only [`ScriptedTransport`](crate::transport::ScriptedTransport) produces this: it means a
    /// test issued more requests than it scripted answers for.
    ScriptExhausted {
        /// How many requests the transport had already answered.
        answered: usize,
    },
    /// A header could not be built.
    Header {
        /// Underlying failure.
        source: Box<HeaderError>,
    },
    /// The request could not be signed, so it was never sent.
    ///
    /// Reported by the signing layer of the transport stack. It is deliberately **not** transient:
    /// a request that cannot be signed cannot be signed on a second attempt either, so the retry
    /// classifier never retries it. The message is bounded and carries no
    /// key, no signature, and no header value.
    Signing {
        /// Bounded description of what failed.
        message: String,
    },
}

impl TransportError {
    /// Builds a [`TransportError::Connect`] with a bounded message.
    #[must_use]
    pub fn connect(message: impl AsRef<str>) -> Self {
        Self::Connect {
            message: bounded(message.as_ref()),
        }
    }

    /// Builds a [`TransportError::InvalidResponse`] with a bounded message.
    #[must_use]
    pub fn invalid_response(message: impl AsRef<str>) -> Self {
        Self::InvalidResponse {
            message: bounded(message.as_ref()),
        }
    }

    /// Builds a [`TransportError::Signing`] with a bounded message.
    #[must_use]
    pub fn signing(message: impl AsRef<str>) -> Self {
        Self::Signing {
            message: bounded(message.as_ref()),
        }
    }
}

/// Copies at most [`MAX_MESSAGE_BYTES`] characters of transport text into an error.
fn bounded(text: &str) -> String {
    text.chars().take(MAX_MESSAGE_BYTES).collect()
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl { reason } => write!(formatter, "invalid request URL: {reason}"),
            Self::RequestBodyTooLarge { maximum, actual } => {
                write!(formatter, "a request body of {actual} bytes exceeds maximum {maximum}")
            }
            Self::ResponseBodyTooLarge { limit, actual } => write!(
                formatter,
                "a response body exceeded its {limit}-byte limit after {actual} bytes"
            ),
            Self::ResponseLimitTooLarge { maximum, requested } => write!(
                formatter,
                "a response-body limit of {requested} bytes exceeds maximum {maximum}"
            ),
            Self::InvalidStatus { status } => write!(formatter, "invalid HTTP status {status}"),
            Self::Timeout { milliseconds } => {
                write!(formatter, "the request did not complete within {milliseconds} ms")
            }
            Self::Connect { message } => write!(formatter, "transport failure: {message}"),
            Self::InvalidResponse { message } => write!(formatter, "malformed response: {message}"),
            Self::ScriptExhausted { answered } => write!(
                formatter,
                "the scripted transport has no answer left after {answered} requests"
            ),
            Self::Header { source } => write!(formatter, "header construction failed: {source}"),
            Self::Signing { message } => write!(formatter, "the request could not be signed: {message}"),
        }
    }
}

impl Error for TransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Header { source } => Some(source),
            _ => None,
        }
    }
}

impl From<HeaderError> for TransportError {
    fn from(source: HeaderError) -> Self {
        Self::Header {
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::displays_and_sources;

    #[test]
    fn every_variant_displays_and_sources_correctly() {
        let cases: Vec<(TransportError, &[&str], bool)> = vec![
            (TransportError::InvalidUrl { reason: "empty" }, &["empty"], false),
            (
                TransportError::RequestBodyTooLarge {
                    maximum: 1031,
                    actual: 2047,
                },
                &["1031", "2047"],
                false,
            ),
            (
                TransportError::ResponseBodyTooLarge {
                    limit: 1031,
                    actual: 2047,
                },
                &["1031", "2047"],
                false,
            ),
            (
                TransportError::ResponseLimitTooLarge {
                    maximum: 1031,
                    requested: 2047,
                },
                &["1031", "2047"],
                false,
            ),
            (TransportError::InvalidStatus { status: 42 }, &["42"], false),
            (TransportError::Timeout { milliseconds: 1031 }, &["1031"], false),
            (TransportError::connect("refused"), &["refused"], false),
            (TransportError::invalid_response("truncated"), &["truncated"], false),
            (TransportError::ScriptExhausted { answered: 1031 }, &["1031"], false),
            (
                TransportError::from(HeaderError::DuplicateHeader {
                    name: "range".to_owned(),
                }),
                &["range"],
                true,
            ),
            (
                TransportError::signing("no covered header"),
                &["no covered header"],
                false,
            ),
        ];
        for (error, fragments, has_source) in cases {
            displays_and_sources(&error, fragments, has_source);
        }
    }

    #[test]
    fn transport_messages_are_bounded() {
        let long = "x".repeat(MAX_MESSAGE_BYTES * 2);
        for error in [
            TransportError::connect(&long),
            TransportError::invalid_response(&long),
            TransportError::signing(&long),
        ] {
            let rendered = error.to_string();
            assert!(rendered.len() < long.len(), "{rendered}");
        }
    }
}
