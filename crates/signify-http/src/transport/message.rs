//! The request and response values that cross the transport boundary.

use core::fmt;

use crate::header::{HeaderName, HeaderValue, Headers};
use crate::transport::error::TransportError;
use crate::transport::url::RequestUrl;

/// Largest accepted request body, in bytes.
///
/// The largest thing the pinned reference sends is a credential issuance with its attachments,
/// which is measured in kilobytes; four mebibytes leaves room without letting a caller mistake
/// this boundary for a file upload.
pub const MAX_REQUEST_BODY_BYTES: usize = 4 << 20;

/// Response-body limit a request carries unless it sets its own, in bytes.
pub const DEFAULT_RESPONSE_BODY_LIMIT: usize = 16 << 20;

/// Largest response-body limit a request may set, in bytes.
///
/// A limit exists so an unbounded or hostile response cannot exhaust memory, so a caller may not
/// raise it arbitrarily.
pub const MAX_RESPONSE_BODY_LIMIT: usize = 64 << 20;

/// An HTTP method.
///
/// These are exactly the four the pinned reference issues across every endpoint module. A method
/// it never sends is not modelled, so an endpoint cannot invent one by writing a string.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Method {
    /// `GET`, which carries no body.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
}

impl Method {
    /// Every method, in the order this table declares them.
    pub const ALL: &'static [Self] = &[Self::Get, Self::Post, Self::Put, Self::Delete];

    /// Returns the exact wire spelling, which is uppercase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An HTTP status code.
///
/// ```
/// use signify_http::transport::StatusCode;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert!(StatusCode::new(202)?.is_success());
/// assert!(StatusCode::new(404)?.is_client_error());
/// assert!(StatusCode::new(99).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StatusCode {
    code: u16,
}

impl StatusCode {
    /// Validates one status code.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidStatus`] outside the range 100 through 599 that HTTP
    /// defines.
    pub const fn new(code: u16) -> Result<Self, TransportError> {
        if code < 100 || code > 599 {
            return Err(TransportError::InvalidStatus { status: code });
        }
        Ok(Self { code })
    }

    /// Returns the numeric code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.code
    }

    /// Returns whether the code is in the 2xx range.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.code >= 200 && self.code <= 299
    }

    /// Returns whether the code is in the 3xx range.
    #[must_use]
    pub const fn is_redirection(self) -> bool {
        self.code >= 300 && self.code <= 399
    }

    /// Returns whether the code is in the 4xx range.
    #[must_use]
    pub const fn is_client_error(self) -> bool {
        self.code >= 400 && self.code <= 499
    }

    /// Returns whether the code is in the 5xx range.
    #[must_use]
    pub const fn is_server_error(self) -> bool {
        self.code >= 500 && self.code <= 599
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.code)
    }
}

/// Assembles a [`Request`].
///
/// Every setter is infallible; [`RequestBuilder::build`] validates the whole request at once, so
/// a duplicate header and an oversized body are reported the same way.
#[derive(Clone)]
pub struct RequestBuilder {
    method: Method,
    url: RequestUrl,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Option<Vec<u8>>,
    response_limit: usize,
}

impl fmt::Debug for RequestBuilder {
    /// Names the method, URL and body size; the body and headers can carry secrets.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBuilder")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("body_bytes", &self.body.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl RequestBuilder {
    /// Adds one header.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Adds every header of a collection, in its order.
    #[must_use]
    pub fn headers(mut self, headers: &Headers) -> Self {
        for (name, value) in headers {
            self.headers.push((name.clone(), value.clone()));
        }
        self
    }

    /// Sets the request body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Sets how many response bytes this request will accept.
    #[must_use]
    pub const fn response_limit(mut self, limit: usize) -> Self {
        self.response_limit = limit;
        self
    }

    /// Validates and assembles the request.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::RequestBodyTooLarge`] above [`MAX_REQUEST_BODY_BYTES`],
    /// [`TransportError::ResponseLimitTooLarge`] above [`MAX_RESPONSE_BODY_LIMIT`], and a layered
    /// [`TransportError::Header`] for a duplicate or oversized header.
    pub fn build(self) -> Result<Request, TransportError> {
        if let Some(body) = &self.body
            && body.len() > MAX_REQUEST_BODY_BYTES
        {
            return Err(TransportError::RequestBodyTooLarge {
                maximum: MAX_REQUEST_BODY_BYTES,
                actual: body.len(),
            });
        }
        if self.response_limit > MAX_RESPONSE_BODY_LIMIT {
            return Err(TransportError::ResponseLimitTooLarge {
                maximum: MAX_RESPONSE_BODY_LIMIT,
                requested: self.response_limit,
            });
        }
        let headers = Headers::from_pairs(self.headers)?;
        Ok(Request {
            method: self.method,
            url: self.url,
            headers,
            body: self.body,
            response_limit: self.response_limit,
        })
    }
}

/// One request to send.
///
/// ```
/// use signify_http::header::{HeaderName, HeaderValue};
/// use signify_http::transport::{Method, Request, RequestUrl};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let request = Request::builder(Method::Post, RequestUrl::new("https://keria.example/boot")?)
///     .header(HeaderName::new("Content-Type")?, HeaderValue::new("application/json")?)
///     .body(br#"{"icp":{}}"#.to_vec())
///     .build()?;
///
/// assert_eq!(request.method(), Method::Post);
/// assert_eq!(request.url().path(), "/boot");
/// assert_eq!(request.headers().get("content-type"), Some("application/json"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Request {
    method: Method,
    url: RequestUrl,
    headers: Headers,
    body: Option<Vec<u8>>,
    response_limit: usize,
}

impl fmt::Debug for Request {
    /// Names the method, URL and body size; the body and headers can carry secrets.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("body_bytes", &self.body.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl Request {
    /// Starts building a request.
    #[must_use]
    pub fn builder(method: Method, url: RequestUrl) -> RequestBuilder {
        RequestBuilder {
            method,
            url,
            headers: Vec::new(),
            body: None,
            response_limit: DEFAULT_RESPONSE_BODY_LIMIT,
        }
    }

    /// Returns the method.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Returns the URL.
    #[must_use]
    pub const fn url(&self) -> &RequestUrl {
        &self.url
    }

    /// Returns the headers, in the order they were added.
    #[must_use]
    pub const fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns the body, when the request carries one.
    ///
    /// An absent body and an empty body are different: the reference sends `null` rather than an
    /// empty string for a `GET`, and a transport must not turn one into the other.
    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    /// Returns how many response bytes this request accepts.
    #[must_use]
    pub const fn response_limit(&self) -> usize {
        self.response_limit
    }
}

/// One response that arrived.
///
/// A non-success status is still a response: reading meaning from the status is
/// [`crate::response`]'s job, not the transport's.
#[derive(Clone, Debug)]
pub struct Response {
    status: StatusCode,
    headers: Headers,
    body: Vec<u8>,
}

impl Response {
    /// Assembles a response.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ResponseBodyTooLarge`] when the body exceeds
    /// [`MAX_RESPONSE_BODY_LIMIT`], which no request may raise past.
    pub fn new(status: StatusCode, headers: Headers, body: impl Into<Vec<u8>>) -> Result<Self, TransportError> {
        let body = body.into();
        if body.len() > MAX_RESPONSE_BODY_LIMIT {
            return Err(TransportError::ResponseBodyTooLarge {
                limit: MAX_RESPONSE_BODY_LIMIT,
                actual: body.len(),
            });
        }
        Ok(Self { status, headers, body })
    }

    /// Returns the status.
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

    /// Checks this response against one request's limit.
    ///
    /// A transport that buffers a whole body before constructing the response must call this; one
    /// that streams should stop reading at the limit instead and never build the response at all.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ResponseBodyTooLarge`] when the body exceeds the limit.
    pub fn within_limit(self, limit: usize) -> Result<Self, TransportError> {
        if self.body.len() > limit {
            return Err(TransportError::ResponseBodyTooLarge {
                limit,
                actual: self.body.len(),
            });
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    fn url() -> Result<RequestUrl, Box<dyn Error>> {
        Ok(RequestUrl::new("https://keria.example/identifiers")?)
    }

    fn header(name: &str, value: &str) -> Result<(HeaderName, HeaderValue), Box<dyn Error>> {
        Ok((HeaderName::new(name)?, HeaderValue::new(value)?))
    }

    #[test]
    fn debug_hides_body_and_headers() -> Result<(), Box<dyn Error>> {
        let builder = Request::builder(Method::Put, RequestUrl::new("http://localhost/salt")?)
            .header(HeaderName::new("Signature")?, HeaderValue::new("hidden-header")?)
            .body(b"hidden-body".to_vec());

        for rendered in [format!("{builder:?}"), format!("{:?}", builder.clone().build()?)] {
            assert!(rendered.contains("body_bytes: Some(11)"), "{rendered}");
            assert!(!rendered.contains("hidden"), "{rendered}");
        }
        Ok(())
    }

    #[test]
    fn every_method_has_its_wire_spelling() {
        assert_eq!(Method::ALL.len(), 4);
        for (method, text) in [
            (Method::Get, "GET"),
            (Method::Post, "POST"),
            (Method::Put, "PUT"),
            (Method::Delete, "DELETE"),
        ] {
            assert_eq!(method.as_str(), text);
            assert_eq!(method.to_string(), text);
            assert!(Method::ALL.contains(&method));
        }
    }

    #[test]
    fn status_codes_are_ranged_and_classified() -> Result<(), Box<dyn Error>> {
        for code in [100_u16, 200, 299, 300, 400, 499, 500, 599] {
            let status = StatusCode::new(code)?;
            assert_eq!(status.as_u16(), code);
            assert_eq!(status.to_string(), code.to_string());
            assert_eq!(status.is_success(), (200..=299).contains(&code));
            assert_eq!(status.is_redirection(), (300..=399).contains(&code));
            assert_eq!(status.is_client_error(), (400..=499).contains(&code));
            assert_eq!(status.is_server_error(), (500..=599).contains(&code));
        }
        for code in [0_u16, 99, 600, u16::MAX] {
            assert!(matches!(
                StatusCode::new(code),
                Err(TransportError::InvalidStatus { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn a_request_keeps_what_it_was_given() -> Result<(), Box<dyn Error>> {
        let (name, value) = header("Signify-Resource", "EPRE")?;
        let request = Request::builder(Method::Post, url()?)
            .header(name, value)
            .body(b"payload".to_vec())
            .build()?;
        assert_eq!(request.method(), Method::Post);
        assert_eq!(request.url().as_str(), "https://keria.example/identifiers");
        assert_eq!(request.headers().get("signify-resource"), Some("EPRE"));
        assert_eq!(request.body(), Some(b"payload".as_slice()));
        assert_eq!(request.response_limit(), DEFAULT_RESPONSE_BODY_LIMIT);
        Ok(())
    }

    #[test]
    fn an_absent_body_differs_from_an_empty_one() -> Result<(), Box<dyn Error>> {
        let absent = Request::builder(Method::Get, url()?).build()?;
        let empty = Request::builder(Method::Get, url()?).body(Vec::new()).build()?;
        assert_eq!(absent.body(), None);
        assert_eq!(empty.body(), Some(b"".as_slice()));
        Ok(())
    }

    #[test]
    fn headers_are_carried_in_order_and_deduplicated() -> Result<(), Box<dyn Error>> {
        let (first, first_value) = header("Range", "aids=0-24")?;
        let (second, second_value) = header("Content-Type", "application/json")?;
        let mut collection = Headers::new();
        collection.insert(first.clone(), first_value.clone())?;
        collection.insert(second, second_value)?;

        let request = Request::builder(Method::Get, url()?).headers(&collection).build()?;
        let names: Vec<&str> = request.headers().iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["Range", "Content-Type"]);

        // A repeated name is refused at build, where the reference joins the values with a comma.
        let duplicate = Request::builder(Method::Get, url()?)
            .header(first.clone(), first_value.clone())
            .header(first, first_value)
            .build();
        assert!(matches!(duplicate, Err(TransportError::Header { .. })));
        Ok(())
    }

    #[test]
    fn the_body_and_limit_bounds_are_enforced() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            Request::builder(Method::Post, url()?)
                .body(vec![0_u8; MAX_REQUEST_BODY_BYTES + 1])
                .build(),
            Err(TransportError::RequestBodyTooLarge { .. })
        ));
        // The bound is inclusive.
        assert!(
            Request::builder(Method::Post, url()?)
                .body(vec![0_u8; MAX_REQUEST_BODY_BYTES])
                .build()
                .is_ok()
        );
        assert!(matches!(
            Request::builder(Method::Get, url()?)
                .response_limit(MAX_RESPONSE_BODY_LIMIT + 1)
                .build(),
            Err(TransportError::ResponseLimitTooLarge { .. })
        ));
        let bounded = Request::builder(Method::Get, url()?).response_limit(64).build()?;
        assert_eq!(bounded.response_limit(), 64);
        Ok(())
    }

    #[test]
    fn a_response_carries_its_status_headers_and_body() -> Result<(), Box<dyn Error>> {
        let (name, value) = header("Content-Range", "aids 0-1/2")?;
        let headers = Headers::from_pairs([(name, value)])?;
        let response = Response::new(StatusCode::new(206)?, headers, b"{}".to_vec())?;
        assert_eq!(response.status().as_u16(), 206);
        assert_eq!(response.headers().get("content-range"), Some("aids 0-1/2"));
        assert_eq!(response.body(), b"{}");
        assert_eq!(response.clone().into_body(), b"{}".to_vec());

        // A non-success status is still a response, not an error.
        let failure = Response::new(StatusCode::new(404)?, Headers::new(), Vec::new())?;
        assert!(failure.status().is_client_error());
        assert_eq!(failure.body(), b"");
        Ok(())
    }

    #[test]
    fn a_response_is_checked_against_a_request_limit() -> Result<(), Box<dyn Error>> {
        let response = Response::new(StatusCode::new(200)?, Headers::new(), b"0123456789".to_vec())?;
        assert!(response.clone().within_limit(10).is_ok());
        assert!(matches!(
            response.within_limit(9),
            Err(TransportError::ResponseBodyTooLarge { limit: 9, actual: 10 })
        ));
        Ok(())
    }
}
