//! Reading one response: what its status means, what its body may be read as, and where it sits
//! in a paged list.
//!
//! The pinned reference does this in three unrelated places. `SignifyClient.fetch` throws when
//! `res.ok` is false, interpolating the whole response body into a message string. Every endpoint
//! module then calls `await res.json()`, which parses the body regardless of what the server
//! declared it to be. And `parseRangeHeaders` in `core/httping.ts` — the last capability of that
//! file left unported after request authentication — reads `Content-Range` with four `parseInt`
//! calls that cannot fail, only produce a `NaN`.
//!
//! # What is decided differently here, and why
//!
//! A [`ContentRange`] is parsed strictly and its fields are `u64`. The reference's version accepts
//! `aids 0x10-0x20/0x30` as 16, 32, 48; turns a missing field into a `NaN` that flows on into
//! arithmetic; returns `{0, 0, 0}` for an absent header, which no caller can tell apart from a
//! server that really answered `aids 0-0/0`; and loses precision past 2^53, so a total of
//! `9007199254740995` comes back as `9007199254740996`. All of that is recorded in
//! `fixtures/http-request-response/v1.json` and none of it is reproduced.
//!
//! [`ResourceResponse::json`] refuses a declared media type that is not `application/json`, where
//! the reference decodes a `text/plain` error page as a domain record whenever it happens to be
//! valid JSON. An *absent* type is accepted, because nothing then contradicts the caller.
//!
//! A non-success status is a typed [`ResponseError::Status`] carrying a **bounded** excerpt of the
//! body and the path **without its query**, where the reference's message interpolates the body
//! whole and the query with it.

use core::fmt;
use core::str;
use std::error::Error;

use crate::header::Headers;
use crate::request::{RangeUnit, RequestError};
use crate::transport::{Method, Request, Response, StatusCode};

/// Largest number of body characters an error excerpt keeps.
///
/// Enough for a KERIA problem document's title, and far too little for a server to write an
/// unbounded amount of its own text into a caller's log.
pub const MAX_DETAIL_CHARS: usize = 256;

/// Largest number of digits accepted in one `Content-Range` position.
///
/// `u64::MAX` has twenty digits, so anything longer cannot be a value and is refused before it is
/// parsed rather than after.
pub const MAX_RANGE_DIGITS: usize = 20;

/// Where a paged response sits within the whole collection.
///
/// KERIA counts items rather than bytes and names the kind of item in the unit position, so a list
/// of identifiers answers `Content-Range: aids 0-1/2`. Both positions are inclusive.
///
/// # Cross-field consistency is deliberately not checked
///
/// RFC 9110 would require `start <= end < total`, but KERIA's unit is not `bytes` and no evidence
/// in this repository establishes that it follows that discipline; the reference checks nothing at
/// all. Confirming it against a live deployment belongs to the KERIA integration runs, so this
/// type reports the three numbers exactly as sent and leaves the judgement to a caller that knows
/// what it asked for.
///
/// ```
/// use signify_http::request::RangeUnit;
/// use signify_http::response::ContentRange;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let range = ContentRange::parse("aids 0-1/2", &RangeUnit::new("aids")?)?;
/// assert_eq!((range.start(), range.end(), range.total()), (0, 1, 2));
///
/// // The reference reads this as 16, 32, 48.
/// assert!(ContentRange::parse("aids 0x10-0x20/0x30", &RangeUnit::new("aids")?).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentRange {
    start: u64,
    end: u64,
    total: u64,
}

impl ContentRange {
    /// Parses one `Content-Range` value for an expected unit.
    ///
    /// The accepted shape is exactly `<unit> <start>-<end>/<total>`: one space, ASCII digits only,
    /// one `-`, one `/`, and nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseError::InvalidContentRange`] when the unit does not match, when the shape
    /// is wrong, when a position is not a digit run, or when a position does not fit a `u64`.
    pub fn parse(value: &str, unit: &RangeUnit) -> Result<Self, ResponseError> {
        let invalid = |reason: &'static str| ResponseError::InvalidContentRange {
            value: bounded(value, 64),
            reason,
        };
        let Some(rest) = value.strip_prefix(unit.as_str()) else {
            return Err(invalid("the value does not begin with the expected unit"));
        };
        let Some(rest) = rest.strip_prefix(' ') else {
            return Err(invalid("the unit must be followed by exactly one space"));
        };
        let Some((positions, total)) = rest.split_once('/') else {
            return Err(invalid("the value must hold one `/` before the total"));
        };
        let Some((start, end)) = positions.split_once('-') else {
            return Err(invalid("the positions must hold one `-`"));
        };
        Ok(Self {
            start: digits(start).ok_or_else(|| invalid("the first position is not a bounded digit run"))?,
            end: digits(end).ok_or_else(|| invalid("the last position is not a bounded digit run"))?,
            total: digits(total).ok_or_else(|| invalid("the total is not a bounded digit run"))?,
        })
    }

    /// Returns the first position, which is included.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the last position, which is included.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Returns how many items the whole collection holds.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.total
    }
}

/// Parses one bounded run of ASCII digits.
///
/// Leading zeros are accepted, because a server may pad; anything else — a sign, a `0x` prefix, an
/// exponent, a decimal point, whitespace, an empty run, or a value past `u64::MAX` — is not a
/// position. The reference's `parseInt` accepts every one of them.
fn digits(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > MAX_RANGE_DIGITS || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// What a response is an answer to.
///
/// Captured before a request is handed to a transport, which consumes it, so a failure can name
/// the call without the whole request being kept alive. **The query is deliberately dropped**: it
/// carries caller-supplied filter values that are not needed to handle a status, and the
/// reference's error message interpolates it.
///
/// ```
/// use signify_http::response::RequestOrigin;
/// use signify_http::transport::{Method, Request, RequestUrl};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let request = Request::builder(
///     Method::Get,
///     RequestUrl::new("http://localhost:3901/contacts?group=secret")?,
/// )
/// .build()?;
///
/// let origin = RequestOrigin::of(&request);
/// assert_eq!(origin.path(), "/contacts");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestOrigin {
    method: Method,
    path: String,
}

impl RequestOrigin {
    /// Captures the method and path of one request.
    #[must_use]
    pub fn of(request: &Request) -> Self {
        Self {
            method: request.method(),
            path: request.url().path().to_owned(),
        }
    }

    /// Returns the method.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Returns the path, without its query.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for RequestOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.method, self.path)
    }
}

/// A response whose status a caller has already accepted.
///
/// ```
/// use signify_http::header::{HeaderName, HeaderValue, Headers};
/// use signify_http::request::RangeUnit;
/// use signify_http::response::{RequestOrigin, ResourceResponse};
/// use signify_http::transport::{Method, Request, RequestUrl, Response, StatusCode};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let request =
///     Request::builder(Method::Get, RequestUrl::new("http://localhost:3901/identifiers")?).build()?;
/// let headers = Headers::from_pairs([
///     (HeaderName::new("Content-Type")?, HeaderValue::new("application/json")?),
///     (HeaderName::new("Content-Range")?, HeaderValue::new("aids 0-1/2")?),
/// ])?;
/// let response = Response::new(StatusCode::new(200)?, headers, br#"[{"name":"aid1"}]"#.to_vec())?;
///
/// let decoded = ResourceResponse::decode(&RequestOrigin::of(&request), response)?;
/// assert_eq!(decoded.json()?, br#"[{"name":"aid1"}]"#);
/// assert_eq!(
///     decoded.content_range(&RangeUnit::new("aids")?)?.map(|range| range.total()),
///     Some(2),
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ResourceResponse {
    status: StatusCode,
    headers: Headers,
    body: Vec<u8>,
}

impl ResourceResponse {
    /// Classifies one transport response against the request that produced it.
    ///
    /// A 2xx status is accepted, matching the reference's `res.ok`; anything else becomes a typed
    /// failure rather than a response.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseError::Status`] for any status outside 200 through 299, carrying the
    /// method, the path without its query, the status, and a bounded excerpt of the body.
    pub fn decode(origin: &RequestOrigin, response: Response) -> Result<Self, ResponseError> {
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body();
        if !status.is_success() {
            return Err(ResponseError::Status {
                method: origin.method,
                path: bounded(&origin.path, MAX_DETAIL_CHARS),
                status,
                detail: excerpt(&body),
            });
        }
        Ok(Self { status, headers, body })
    }

    /// Returns the status, which is always a success.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the headers.
    #[must_use]
    pub const fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns the body, which may be empty.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consumes the response and returns its body.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Returns the declared media type, when the response declares one.
    ///
    /// A server that declares nothing is not an error; a server that declares something
    /// unparseable is, and is reported here rather than when the body is read.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseError::InvalidContentType`] when the header is present but malformed.
    pub fn content_type(&self) -> Result<Option<crate::request::MediaType>, ResponseError> {
        let Some(value) = self.headers.get("content-type") else {
            return Ok(None);
        };
        crate::request::MediaType::new(value)
            .map(Some)
            .map_err(|source| ResponseError::InvalidContentType {
                value: bounded(value, 64),
                source: Box::new(source),
            })
    }

    /// Returns the body as a JSON document.
    ///
    /// The bytes are handed back for a caller to deserialize; this crate does not deserialize, so
    /// no serialization dependency reaches it and the domain records stay in `keria-types`.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseError::UnexpectedContentType`] when the response declares a media type
    /// that is not `application/json`, and [`ResponseError::InvalidContentType`] when it declares
    /// an unparseable one. An absent type is accepted, because nothing contradicts the caller —
    /// the reference accepts any type at all.
    pub fn json(&self) -> Result<&[u8], ResponseError> {
        self.require_content_type(&crate::request::MediaType::json())?;
        Ok(&self.body)
    }

    /// Returns the body as a CESR stream.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseError::UnexpectedContentType`] when the response declares a media type
    /// that is not `application/json+cesr`, [`ResponseError::InvalidContentType`] when it declares
    /// an unparseable one, and [`ResponseError::NotUtf8`] when the body is not UTF-8. A CESR
    /// stream is text by definition, so this returns `&str` where [`Self::json`] returns bytes.
    pub fn cesr(&self) -> Result<&str, ResponseError> {
        self.require_content_type(&crate::request::MediaType::json_cesr())?;
        self.text()
    }

    /// Returns the body as text, whatever it declares itself to be.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseError::NotUtf8`] when the body is not valid UTF-8.
    pub fn text(&self) -> Result<&str, ResponseError> {
        str::from_utf8(&self.body).map_err(|error| ResponseError::NotUtf8 {
            offset: error.valid_up_to(),
        })
    }

    /// Returns where this response sits in a paged collection.
    ///
    /// An absent `Content-Range` is `None`, where the reference returns `{0, 0, 0}` — a value no
    /// caller can tell apart from a server that really answered `aids 0-0/0`.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseError::InvalidContentRange`] when the header is present but is not
    /// `<unit> <start>-<end>/<total>` in ASCII digits.
    pub fn content_range(&self, unit: &RangeUnit) -> Result<Option<ContentRange>, ResponseError> {
        match self.headers.get("content-range") {
            Some(value) => ContentRange::parse(value, unit).map(Some),
            None => Ok(None),
        }
    }

    /// Refuses a declared media type that is not the expected one.
    fn require_content_type(&self, expected: &crate::request::MediaType) -> Result<(), ResponseError> {
        match self.content_type()? {
            Some(declared) if !declared.matches(expected) => Err(ResponseError::UnexpectedContentType {
                expected: expected.essence().to_owned(),
                actual: declared.essence().to_owned(),
            }),
            _ => Ok(()),
        }
    }
}

/// Copies at most `limit` characters of text into an error.
fn bounded(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// Copies at most [`MAX_DETAIL_CHARS`] characters of a body into an error.
///
/// A body that is not UTF-8 is described rather than transcribed, so a hostile server cannot put
/// arbitrary bytes into a caller's log through a replacement-character conversion.
fn excerpt(body: &[u8]) -> String {
    match str::from_utf8(body) {
        Ok(text) => bounded(text, MAX_DETAIL_CHARS),
        Err(_) => format!("<{} bytes, not UTF-8>", body.len()),
    }
}

/// Stable response-decoding failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum ResponseError {
    /// The server answered with a status outside 200 through 299.
    ///
    /// The detail is a bounded excerpt of the body, and the path never carries its query.
    Status {
        /// Method of the request this answers.
        method: Method,
        /// Path of the request this answers, without its query.
        path: String,
        /// The status the server sent.
        status: StatusCode,
        /// Bounded excerpt of the response body.
        detail: String,
    },
    /// The response declares a media type that cannot be parsed.
    InvalidContentType {
        /// Bounded copy of the declared value.
        value: String,
        /// Underlying failure.
        source: Box<RequestError>,
    },
    /// The response declares a media type the caller cannot read.
    UnexpectedContentType {
        /// The essence the caller asked for.
        expected: String,
        /// The essence the server declared.
        actual: String,
    },
    /// The body is not valid UTF-8.
    NotUtf8 {
        /// Byte offset where decoding stopped.
        offset: usize,
    },
    /// A `Content-Range` header is present but malformed.
    InvalidContentRange {
        /// Bounded copy of the rejected value.
        value: String,
        /// Why it was refused.
        reason: &'static str,
    },
}

impl fmt::Display for ResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status {
                method,
                path,
                status,
                detail,
            } => {
                if detail.is_empty() {
                    write!(formatter, "HTTP {method} {path} answered {status}")
                } else {
                    write!(formatter, "HTTP {method} {path} answered {status}: {detail}")
                }
            }
            Self::InvalidContentType { value, source } => {
                write!(formatter, "unparseable content type {value:?}: {source}")
            }
            Self::UnexpectedContentType { expected, actual } => {
                write!(
                    formatter,
                    "expected content type {expected:?} but the response declares {actual:?}"
                )
            }
            Self::NotUtf8 { offset } => {
                write!(formatter, "the response body is not UTF-8 from byte {offset}")
            }
            Self::InvalidContentRange { value, reason } => {
                write!(formatter, "invalid Content-Range {value:?}: {reason}")
            }
        }
    }
}

impl Error for ResponseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidContentType { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{HeaderName, HeaderValue};
    use crate::request::MediaType;
    use crate::transport::RequestUrl;
    use std::error::Error;

    fn origin() -> Result<RequestOrigin, Box<dyn Error>> {
        let request = Request::builder(
            Method::Get,
            RequestUrl::new("http://localhost:3901/identifiers/aid1?filter=secret")?,
        )
        .build()?;
        Ok(RequestOrigin::of(&request))
    }

    fn response(status: u16, content_type: Option<&str>, body: &[u8]) -> Result<Response, Box<dyn Error>> {
        let mut headers = Headers::new();
        if let Some(value) = content_type {
            headers.insert(HeaderName::new("Content-Type")?, HeaderValue::new(value)?)?;
        }
        Ok(Response::new(StatusCode::new(status)?, headers, body.to_vec())?)
    }

    #[test]
    fn content_ranges_parse_strictly() -> Result<(), Box<dyn Error>> {
        let aids = RangeUnit::new("aids")?;
        for (value, start, end, total) in [
            ("aids 0-1/2", 0_u64, 1_u64, 2_u64),
            ("aids 0-24/24", 0, 24, 24),
            ("aids 5-5/6", 5, 5, 6),
            ("aids 00-01/02", 0, 1, 2),
            // Beyond 2^53, where the reference silently returns a different number.
            (
                "aids 9007199254740993-9007199254740994/9007199254740995",
                9_007_199_254_740_993,
                9_007_199_254_740_994,
                9_007_199_254_740_995,
            ),
            ("aids 0-0/0", 0, 0, 0),
            // Ordering is deliberately not checked; a server's own claim is reported as sent.
            ("aids 1-0/2", 1, 0, 2),
        ] {
            let range = ContentRange::parse(value, &aids)?;
            assert_eq!(
                (range.start(), range.end(), range.total()),
                (start, end, total),
                "{value}"
            );
        }
        assert_eq!(
            ContentRange::parse("notes 20-40/100", &RangeUnit::new("notes")?)?.total(),
            100
        );
        Ok(())
    }

    #[test]
    fn malformed_content_ranges_are_refused() -> Result<(), Box<dyn Error>> {
        let aids = RangeUnit::new("aids")?;
        // Every one of these produces a number or a NaN in the reference.
        for value in [
            "",
            "bytes 0-1/2",
            "AIDS 0-1/2",
            "xaids 0-1/2",
            "aids 0-1",
            "aids /2",
            "aids 0-1/",
            "aids -1/2",
            "aids 0-1/*",
            "*/2",
            "aids 0-1/2 aids ",
            "aids  0-1/2",
            "  aids 0-1/2  ",
            "aids 0-1/2/3",
            "aids 1e3-2e3/3e3",
            "aids 0x10-0x20/0x30",
            "aids 1.5-2.5/3.5",
            "aids +1--2/+3",
            "aids -0-1/2",
            "aids 99999999999999999999-1/2",
            "aids0-1/2",
            "aids 18446744073709551616-1/2",
        ] {
            assert!(
                matches!(
                    ContentRange::parse(value, &aids),
                    Err(ResponseError::InvalidContentRange { .. })
                ),
                "{value:?} was accepted",
            );
        }
        // The exact `u64` boundary is accepted on both positions and the total.
        let maximum = format!("aids {0}-{0}/{0}", u64::MAX);
        assert_eq!(ContentRange::parse(&maximum, &aids)?.total(), u64::MAX);
        Ok(())
    }

    #[test]
    fn a_success_decodes_and_keeps_its_parts() -> Result<(), Box<dyn Error>> {
        let decoded = ResourceResponse::decode(&origin()?, response(200, Some("application/json"), b"{}")?)?;
        assert_eq!(decoded.status().as_u16(), 200);
        assert_eq!(decoded.body(), b"{}");
        assert_eq!(decoded.json()?, b"{}");
        assert_eq!(decoded.text()?, "{}");
        assert_eq!(decoded.headers().get("content-type"), Some("application/json"));
        assert_eq!(
            decoded.content_type()?.map(|kind| kind.essence().to_owned()),
            Some("application/json".to_owned())
        );
        assert_eq!(decoded.clone().into_body(), b"{}".to_vec());

        // 202 is the status KERIA answers a long-running operation with.
        let accepted = ResourceResponse::decode(&origin()?, response(202, Some("application/json"), b"{}")?)?;
        assert_eq!(accepted.status().as_u16(), 202);
        // 204 carries nothing at all.
        let empty = ResourceResponse::decode(&origin()?, response(204, None, b"")?)?;
        assert_eq!(empty.body(), b"");
        assert_eq!(empty.content_type()?, None);
        // An absent content type does not block a JSON read.
        assert_eq!(empty.json()?, b"");
        Ok(())
    }

    #[test]
    fn the_success_boundary_matches_the_reference() -> Result<(), Box<dyn Error>> {
        for status in [200_u16, 201, 202, 299] {
            assert!(
                ResourceResponse::decode(&origin()?, response(status, None, b"")?).is_ok(),
                "{status}"
            );
        }
        for status in [100_u16, 199, 300, 301, 400, 404, 409, 500, 599] {
            assert!(
                matches!(
                    ResourceResponse::decode(&origin()?, response(status, None, b"")?),
                    Err(ResponseError::Status { .. })
                ),
                "{status}",
            );
        }
        Ok(())
    }

    #[test]
    fn a_failure_names_the_call_without_its_query() -> Result<(), Box<dyn Error>> {
        let failure = ResourceResponse::decode(&origin()?, response(404, Some("text/plain"), b"not found")?);
        let Err(ResponseError::Status {
            method,
            path,
            status,
            detail,
        }) = failure
        else {
            return Err("a 404 was accepted".into());
        };
        assert_eq!(method, Method::Get);
        // The query held `filter=secret`; the reference's own message would have carried it.
        assert_eq!(path, "/identifiers/aid1");
        assert_eq!(status.as_u16(), 404);
        assert_eq!(detail, "not found");
        Ok(())
    }

    #[test]
    fn a_failure_detail_is_bounded_and_never_raw_bytes() -> Result<(), Box<dyn Error>> {
        let long = "x".repeat(MAX_DETAIL_CHARS * 4);
        let failure = ResourceResponse::decode(&origin()?, response(500, None, long.as_bytes())?);
        let Err(ResponseError::Status { detail, .. }) = failure else {
            return Err("a 500 was accepted".into());
        };
        assert_eq!(detail.chars().count(), MAX_DETAIL_CHARS);

        let failure = ResourceResponse::decode(&origin()?, response(500, None, &[0xff, 0xfe, 0x00])?);
        let Err(ResponseError::Status { detail, .. }) = failure else {
            return Err("a 500 was accepted".into());
        };
        assert_eq!(detail, "<3 bytes, not UTF-8>");

        // An empty body renders without a trailing separator.
        let failure = ResourceResponse::decode(&origin()?, response(409, None, b"")?);
        let Err(error) = failure else {
            return Err("a 409 was accepted".into());
        };
        assert!(!error.to_string().contains(':'), "{error}");
        Ok(())
    }

    #[test]
    fn a_declared_type_the_caller_cannot_read_is_refused() -> Result<(), Box<dyn Error>> {
        // The reference parses this body as JSON regardless of the declaration.
        let mislabelled = ResourceResponse::decode(&origin()?, response(200, Some("text/plain"), b"{}")?)?;
        assert!(matches!(
            mislabelled.json(),
            Err(ResponseError::UnexpectedContentType { .. })
        ));
        assert_eq!(mislabelled.text()?, "{}");

        let cesr = ResourceResponse::decode(
            &origin()?,
            response(200, Some("application/json+cesr"), b"{\"v\":\"ACDC\"}-FAB")?,
        )?;
        assert_eq!(cesr.cesr()?, "{\"v\":\"ACDC\"}-FAB");
        assert!(matches!(cesr.json(), Err(ResponseError::UnexpectedContentType { .. })));

        let json = ResourceResponse::decode(&origin()?, response(200, Some("application/json"), b"{}")?)?;
        assert!(matches!(json.cesr(), Err(ResponseError::UnexpectedContentType { .. })));

        // Case and parameters do not change the essence.
        let charset = ResourceResponse::decode(
            &origin()?,
            response(200, Some("APPLICATION/JSON; charset=utf-8"), b"{}")?,
        )?;
        assert_eq!(charset.json()?, b"{}");
        assert_eq!(
            charset.content_type()?.map(|kind| kind == MediaType::json()),
            Some(true)
        );
        Ok(())
    }

    #[test]
    fn an_unparseable_declaration_is_reported_where_it_matters() -> Result<(), Box<dyn Error>> {
        let broken = ResourceResponse::decode(&origin()?, response(200, Some("application"), b"{}")?)?;
        assert!(matches!(
            broken.content_type(),
            Err(ResponseError::InvalidContentType { .. })
        ));
        assert!(matches!(broken.json(), Err(ResponseError::InvalidContentType { .. })));
        // Text still reads: a garbled declaration does not make an otherwise fine body unusable.
        assert_eq!(broken.text()?, "{}");
        Ok(())
    }

    #[test]
    fn a_body_that_is_not_utf8_is_typed_rather_than_repaired() -> Result<(), Box<dyn Error>> {
        let decoded =
            ResourceResponse::decode(&origin()?, response(200, Some("application/json+cesr"), &[b'a', 0xff])?)?;
        assert!(matches!(decoded.text(), Err(ResponseError::NotUtf8 { offset: 1 })));
        assert!(matches!(decoded.cesr(), Err(ResponseError::NotUtf8 { offset: 1 })));
        // JSON is bytes, so it survives; deserializing it is the caller's, and will fail there.
        let json = ResourceResponse::decode(&origin()?, response(200, Some("application/json"), &[b'a', 0xff])?)?;
        assert_eq!(json.json()?, &[b'a', 0xff]);
        Ok(())
    }

    #[test]
    fn an_absent_content_range_is_not_a_zero_range() -> Result<(), Box<dyn Error>> {
        let aids = RangeUnit::new("aids")?;
        let none = ResourceResponse::decode(&origin()?, response(200, Some("application/json"), b"[]")?)?;
        assert_eq!(none.content_range(&aids)?, None);

        let mut headers = Headers::new();
        headers.insert(HeaderName::new("Content-Range")?, HeaderValue::new("aids 0-0/0")?)?;
        let zero = ResourceResponse::decode(
            &origin()?,
            Response::new(StatusCode::new(200)?, headers, b"[]".to_vec())?,
        )?;
        assert_eq!(zero.content_range(&aids)?.map(ContentRange::total), Some(0));

        let mut headers = Headers::new();
        headers.insert(HeaderName::new("Content-Range")?, HeaderValue::new("aids 0x1-2/3")?)?;
        let broken = ResourceResponse::decode(
            &origin()?,
            Response::new(StatusCode::new(200)?, headers, b"[]".to_vec())?,
        )?;
        assert!(matches!(
            broken.content_range(&aids),
            Err(ResponseError::InvalidContentRange { .. })
        ));
        Ok(())
    }

    #[test]
    fn an_origin_reads_its_request() -> Result<(), Box<dyn Error>> {
        let origin = origin()?;
        assert_eq!(origin.method(), Method::Get);
        assert_eq!(origin.path(), "/identifiers/aid1");
        assert_eq!(origin.to_string(), "GET /identifiers/aid1");
        assert_eq!(origin, origin.clone());
        Ok(())
    }

    #[test]
    fn errors_carry_readable_text_and_their_sources() -> Result<(), Box<dyn Error>> {
        let cases: Vec<(ResponseError, bool)> = vec![
            (
                ResponseError::Status {
                    method: Method::Put,
                    path: "/agent/EPRE".to_owned(),
                    status: StatusCode::new(500)?,
                    detail: "boom".to_owned(),
                },
                false,
            ),
            (
                ResponseError::InvalidContentType {
                    value: "application".to_owned(),
                    source: Box::new(RequestError::EmptyPath),
                },
                true,
            ),
            (
                ResponseError::UnexpectedContentType {
                    expected: "application/json".to_owned(),
                    actual: "text/html".to_owned(),
                },
                false,
            ),
            (ResponseError::NotUtf8 { offset: 3 }, false),
            (
                ResponseError::InvalidContentRange {
                    value: "aids".to_owned(),
                    reason: "no slash",
                },
                false,
            ),
        ];
        for (error, has_source) in cases {
            assert_ne!(error.to_string(), "");
            assert_eq!(error.source().is_some(), has_source, "{error}");
        }
        Ok(())
    }
}
