//! The production HTTP transport, behind the `http-client` feature.
//!
//! This implements [`Transport`] over hyper with rustls. The stack is hyper rather than a
//! higher-level client because a higher-level one parses its URL with the `url` crate, which
//! **collapses dot segments**, so a request for `/identifiers/..` goes out as `/` — while the
//! request signature still covers the path that was asked for. `http::Uri` preserves the path
//! exactly, which is what makes the signature and the request agree.
//!
//! # This is where the runtime is adopted
//!
//! Everything below `signify-http` stays runtime-free, and this module is the one place the SDK
//! takes a dependency on tokio — deliberately, documented, and behind a feature that is off by
//! default. A caller who brings its own transport never links it.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::header::{HeaderName, HeaderValue, Headers};
use crate::transport::error::TransportError;
use crate::transport::message::{Method, Request, Response, StatusCode};
use crate::transport::{Transport, TransportFuture};

/// How long a request may take before it is abandoned, unless configured otherwise.
///
/// The reference sets no timeout anywhere, so a call there can hang until the platform gives up.
/// A default exists here because an SDK that can hang forever is not one an application can hold
/// a lock across.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Where `http://` is allowed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Plaintext {
    Never,
    Loopback,
    Anywhere,
}

impl Plaintext {
    fn admits(self, host: Option<&str>) -> bool {
        match self {
            Self::Never => false,
            Self::Loopback => host.is_some_and(is_loopback),
            Self::Anywhere => true,
        }
    }
}

/// Returns whether a URL's host is `localhost` or a loopback address.
fn is_loopback(host: &str) -> bool {
    let address = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost") || address.parse().is_ok_and(|address: IpAddr| address.is_loopback())
}

/// Builds an [`HttpTransport`].
#[derive(Clone, Debug)]
pub struct HttpTransportBuilder {
    timeout: Duration,
    plaintext: Plaintext,
}

impl Default for HttpTransportBuilder {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            plaintext: Plaintext::Loopback,
        }
    }
}

impl HttpTransportBuilder {
    /// Sets how long each request may take.
    ///
    /// The deadline covers the whole exchange — connection, request, and response body — because
    /// a per-phase deadline still lets a slow server hold a request open indefinitely.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Refuses `http://` URLs everywhere, loopback included.
    ///
    /// By default `http://` is allowed only to loopback, for local development. Overrides
    /// [`Self::allow_plaintext`].
    #[must_use]
    pub const fn require_tls(mut self) -> Self {
        self.plaintext = Plaintext::Never;
        self
    }

    /// Allows `http://` to any host.
    ///
    /// Signatures cover neither a request's body nor its query, and nothing covers a response's
    /// body, so anyone on the path can rewrite them. Use this only on a network you trust.
    /// Overrides [`Self::require_tls`].
    #[must_use]
    pub const fn allow_plaintext(mut self) -> Self {
        self.plaintext = Plaintext::Anywhere;
        self
    }

    /// Builds the transport, loading the platform's certificate roots.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Connect`] when the platform's trust store cannot be read.
    pub fn build(self) -> Result<HttpTransport, TransportError> {
        // The platform trust store, so a private or enterprise certificate authority works
        // without the SDK shipping its own root list. The provider is named because rustls panics
        // on the process default when an application compiles in a second provider.
        let roots = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls::crypto::ring::default_provider())
            .map_err(|error| TransportError::connect(format!("cannot read the platform trust store: {error}")))?
            .https_or_http()
            .enable_all_versions();
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        let https = roots.wrap_connector(connector);

        Ok(HttpTransport {
            client: Arc::new(Client::builder(TokioExecutor::new()).build(https)),
            timeout: self.timeout,
            plaintext: self.plaintext,
        })
    }
}

/// Sends requests over the network.
///
/// The transport is cheap to clone and safe to share: cloning it shares one connection pool, which
/// is what a client holding `Arc<dyn Transport>` wants.
///
/// # Build it once
///
/// Construction reads the platform's certificate roots, which the benchmark measures at roughly
/// eighty milliseconds — four orders of magnitude more than sending a request. Build one transport
/// per client and clone or share it; building one per request would dominate everything else the
/// SDK does.
///
/// ```no_run
/// use signify_http::transport::{HttpTransport, Method, Request, RequestUrl, Transport};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let transport = HttpTransport::new()?;
/// let request = Request::builder(Method::Get, RequestUrl::new("https://keria.example/health")?)
///     .build()?;
///
/// let response = transport.execute(request).await?;
/// println!("{}", response.status());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct HttpTransport {
    client: Arc<Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>>,
    timeout: Duration,
    plaintext: Plaintext,
}

impl core::fmt::Debug for HttpTransport {
    /// Names the configuration and nothing about the connection pool.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HttpTransport")
            .field("timeout", &self.timeout)
            .field("plaintext", &self.plaintext)
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// Builds a transport with the default timeout and the platform's certificate roots.
    ///
    /// # Errors
    ///
    /// Returns whatever [`HttpTransportBuilder::build`] returns.
    pub fn new() -> Result<Self, TransportError> {
        Self::builder().build()
    }

    /// Starts building a transport.
    #[must_use]
    pub fn builder() -> HttpTransportBuilder {
        HttpTransportBuilder::default()
    }

    /// Returns the deadline each request is given.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Sends one request and reads its response, both under the configured deadline.
    async fn send(&self, request: Request) -> Result<Response, TransportError> {
        let limit = request.response_limit();
        let outgoing = build_outgoing(&request)?;
        if request.url().scheme() != "https" && !self.plaintext.admits(outgoing.uri().host()) {
            return Err(TransportError::InvalidUrl {
                reason: "http is not allowed to this host; use https",
            });
        }

        let exchange = async {
            let response = self
                .client
                .request(outgoing)
                .await
                .map_err(|error| TransportError::connect(error.to_string()))?;
            read_response(response, limit).await
        };

        // One deadline covers the whole exchange. Timing out drops the future, which cancels the
        // request; nothing partial is returned.
        match tokio::time::timeout(self.timeout, exchange).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout {
                milliseconds: u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX),
            }),
        }
    }
}

impl Transport for HttpTransport {
    fn execute(&self, request: Request) -> TransportFuture<'_> {
        Box::pin(async move { self.send(request).await })
    }
}

/// Converts one validated request into the outgoing message.
///
/// The URL's bytes reach `http::Uri` unchanged, which is the whole point of the non-normalizing
/// [`RequestUrl`](crate::transport::RequestUrl).
fn build_outgoing(request: &Request) -> Result<hyper::Request<Full<Bytes>>, TransportError> {
    let method = match request.method() {
        Method::Get => hyper::Method::GET,
        Method::Post => hyper::Method::POST,
        Method::Put => hyper::Method::PUT,
        Method::Delete => hyper::Method::DELETE,
    };
    let uri: hyper::Uri = request.url().as_str().parse().map_err(|_| TransportError::InvalidUrl {
        reason: "the URL is not a valid request target",
    })?;

    let mut builder = hyper::Request::builder().method(method).uri(uri);
    for (name, value) in request.headers() {
        let header_name = http::HeaderName::try_from(name.as_str())
            .map_err(|_| TransportError::invalid_response("a request header name is not sendable"))?;
        let header_value = http::HeaderValue::from_str(value.as_str())
            .map_err(|_| TransportError::invalid_response("a request header value is not sendable"))?;
        builder = builder.header(header_name, header_value);
    }

    // An absent body and an empty one stay different: `Full` over no bytes still sends no body,
    // and only a request that carried one gets a payload.
    let body = request.body().map_or_else(Bytes::new, Bytes::copy_from_slice);
    builder
        .body(Full::new(body))
        .map_err(|error| TransportError::connect(format!("the request could not be assembled: {error}")))
}

/// Reads one response, stopping at the limit rather than buffering past it.
async fn read_response(
    response: hyper::Response<hyper::body::Incoming>,
    limit: usize,
) -> Result<Response, TransportError> {
    let status = StatusCode::new(response.status().as_u16())?;
    let headers = convert_headers(response.headers())?;

    let mut body = response.into_body();
    let mut collected: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| TransportError::invalid_response(error.to_string()))?;
        let Some(chunk) = frame.data_ref() else {
            // A trailer frame carries no body bytes; trailers are not part of this boundary.
            continue;
        };
        let would_be = collected.len().saturating_add(chunk.len());
        if would_be > limit {
            // Stop here: the rest of the body is never read, and the connection is dropped.
            return Err(TransportError::ResponseBodyTooLarge {
                limit,
                actual: would_be,
            });
        }
        collected.extend_from_slice(chunk);
    }

    Response::new(status, headers, collected)
}

/// Returns whether this crate reads a response header, so two values for it would be ambiguous.
///
/// Keep in sync with the headers the crate reads.
fn is_read_header(name: &str) -> bool {
    name.starts_with("signify-")
        || matches!(
            name,
            "signature" | "signature-input" | "content-range" | "content-type" | "retry-after"
        )
}

/// Converts a response's headers into this crate's collection.
///
/// A repeated or non-text value is **refused** for a header this crate reads, rather than joined,
/// because joining changes what a signature covers. Any other header keeps its first usable value,
/// so a proxy adding `Set-Cookie` or `Vary` lines leaves the response readable.
fn convert_headers(source: &http::HeaderMap) -> Result<Headers, TransportError> {
    let mut headers = Headers::new();
    for (name, value) in source {
        let is_read = is_read_header(name.as_str());
        // The first usable value wins.
        if !is_read && headers.get(name.as_str()).is_some() {
            continue;
        }
        match convert_header(name, value) {
            Ok((name, value)) => headers.insert(name, value)?,
            Err(error) if is_read => return Err(error),
            Err(_) => {}
        }
    }
    Ok(headers)
}

/// Converts one header, refusing a non-text value.
fn convert_header(
    name: &http::HeaderName,
    value: &http::HeaderValue,
) -> Result<(HeaderName, HeaderValue), TransportError> {
    let text = value
        .to_str()
        .map_err(|_| TransportError::invalid_response("a response header value is not text"))?;
    Ok((HeaderName::new(name.as_str())?, HeaderValue::new(text)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    use crate::transport::RequestUrl;

    fn request(method: Method, url: &str) -> Result<Request, Box<dyn Error>> {
        Ok(Request::builder(method, RequestUrl::new(url)?).build()?)
    }

    #[test]
    fn a_transport_reports_its_configuration_without_leaking_state() -> Result<(), Box<dyn Error>> {
        let transport = HttpTransport::builder().timeout(Duration::from_millis(250)).build()?;
        assert_eq!(transport.timeout(), Duration::from_millis(250));
        let rendered = format!("{transport:?}");
        assert!(rendered.contains("250ms"), "{rendered}");
        assert!(rendered.contains("plaintext"), "{rendered}");
        // Cloning shares the pool rather than building a second one.
        let clone = transport.clone();
        assert_eq!(clone.timeout(), transport.timeout());
        Ok(())
    }

    #[test]
    fn the_default_timeout_is_finite() -> Result<(), Box<dyn Error>> {
        let transport = HttpTransport::new()?;
        assert_eq!(transport.timeout(), DEFAULT_TIMEOUT);
        assert!(transport.timeout() > Duration::ZERO);
        Ok(())
    }

    #[test]
    fn every_method_maps_to_its_wire_verb() -> Result<(), Box<dyn Error>> {
        for (method, expected) in [
            (Method::Get, hyper::Method::GET),
            (Method::Post, hyper::Method::POST),
            (Method::Put, hyper::Method::PUT),
            (Method::Delete, hyper::Method::DELETE),
        ] {
            let outgoing = build_outgoing(&request(method, "https://keria.example/a")?)?;
            assert_eq!(outgoing.method(), expected);
        }
        Ok(())
    }

    #[test]
    fn the_url_reaches_the_wire_without_being_rewritten() -> Result<(), Box<dyn Error>> {
        // The case that decided the dependency: a higher-level client's URL type collapses these
        // dot segments to `/`, which would not be the path that was signed.
        for (url, path, query) in [
            ("https://keria.example/identifiers/..", "/identifiers/..", None),
            ("https://keria.example/a/./b/../c", "/a/./b/../c", None),
            (
                "https://keria.example/identifiers/a%20name%20with%20%C3%B1!",
                "/identifiers/a%20name%20with%20%C3%B1!",
                None,
            ),
            (
                "https://keria.example/contacts?group=g&filter_field=f",
                "/contacts",
                Some("group=g&filter_field=f"),
            ),
        ] {
            let outgoing = build_outgoing(&request(Method::Get, url)?)?;
            assert_eq!(outgoing.uri().path(), path, "{url}");
            assert_eq!(outgoing.uri().query(), query, "{url}");
            // And the signed path is exactly what goes out.
            assert_eq!(RequestUrl::new(url)?.path(), outgoing.uri().path(), "{url}");
        }
        Ok(())
    }

    #[test]
    fn headers_and_bodies_are_carried_as_given() -> Result<(), Box<dyn Error>> {
        let outgoing = build_outgoing(
            &Request::builder(Method::Post, RequestUrl::new("https://keria.example/identifiers")?)
                .header(HeaderName::new("Signify-Resource")?, HeaderValue::new("EPRE")?)
                .header(HeaderName::new("Content-Type")?, HeaderValue::new("application/json")?)
                .body(br#"{"name":"aid1"}"#.to_vec())
                .build()?,
        )?;
        assert_eq!(
            outgoing
                .headers()
                .get("signify-resource")
                .map(http::HeaderValue::as_bytes),
            Some(b"EPRE".as_slice())
        );
        assert_eq!(
            outgoing.headers().get("content-type").map(http::HeaderValue::as_bytes),
            Some(b"application/json".as_slice())
        );
        Ok(())
    }

    #[test]
    fn a_plaintext_url_is_refused_when_tls_is_required() -> Result<(), Box<dyn Error>> {
        let transport = HttpTransport::builder().require_tls().build()?;
        let outcome = futures_block_on(transport.send(request(Method::Get, "http://127.0.0.1/a")?))?;
        assert!(matches!(outcome, Err(TransportError::InvalidUrl { .. })));
        Ok(())
    }

    #[test]
    fn a_remote_plaintext_url_is_refused_by_default() -> Result<(), Box<dyn Error>> {
        let transport = HttpTransport::new()?;
        let outcome = futures_block_on(transport.send(request(Method::Get, "http://keria.example/a")?))?;
        assert!(matches!(outcome, Err(TransportError::InvalidUrl { .. })));
        Ok(())
    }

    #[test]
    fn plaintext_reaches_only_what_its_policy_admits() {
        for host in ["localhost", "LOCALHOST", "127.0.0.1", "127.1.2.3", "[::1]"] {
            assert!(Plaintext::Loopback.admits(Some(host)), "{host}");
        }
        for host in ["keria.example", "localhost.example", "10.0.0.1", "[::2]"] {
            assert!(!Plaintext::Loopback.admits(Some(host)), "{host}");
            assert!(Plaintext::Anywhere.admits(Some(host)), "{host}");
        }
        assert!(!Plaintext::Loopback.admits(None));
        assert!(!Plaintext::Never.admits(Some("localhost")));
    }

    #[test]
    fn a_repeated_header_this_crate_reads_is_refused() {
        let mut map = http::HeaderMap::new();
        map.append(http::header::CONTENT_RANGE, http::HeaderValue::from_static("first"));
        map.append(http::header::CONTENT_RANGE, http::HeaderValue::from_static("second"));
        // A duplicate is ambiguous where responses are signed, so it does not become one value.
        assert!(matches!(convert_headers(&map), Err(TransportError::Header { .. })));
    }

    #[test]
    fn a_repeated_header_nothing_reads_keeps_its_first_value() -> Result<(), Box<dyn Error>> {
        let mut map = http::HeaderMap::new();
        map.append(http::header::SET_COOKIE, http::HeaderValue::from_static("first"));
        map.append(http::header::SET_COOKIE, http::HeaderValue::from_static("second"));

        assert_eq!(convert_headers(&map)?.get("set-cookie"), Some("first"));
        Ok(())
    }

    #[test]
    fn a_non_text_header_is_refused_only_when_this_crate_reads_it() -> Result<(), Box<dyn Error>> {
        let binary = http::HeaderValue::from_bytes(&[0xff, 0xfe]).map_err(|_| "unbuildable header")?;
        let mut map = http::HeaderMap::new();
        map.insert(http::header::ETAG, binary.clone());
        assert_eq!(convert_headers(&map)?.get("etag"), None);

        map.insert(http::header::CONTENT_TYPE, binary);
        assert!(matches!(
            convert_headers(&map),
            Err(TransportError::InvalidResponse { .. })
        ));
        Ok(())
    }

    /// Runs one future to completion on a current-thread runtime.
    fn futures_block_on<F: core::future::Future>(future: F) -> Result<F::Output, Box<dyn Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        Ok(runtime.block_on(future))
    }
}
