//! Applying a signature to a request, and checking the one on a response.
//!
//! Roadmap 3.10 built the primitives: [`RequestSigner`] makes the two headers and
//! [`ResponseVerifier`] checks them, with `created` supplied as a parameter so both are
//! reproducible. This module is the composition `SignifyClient.fetch` performs around them — stamp
//! `Signify-Resource` and `Signify-Timestamp`, sign at the request's final form, send, then check
//! the response's resource header and its signature.
//!
//! # Where this sits in the stack
//!
//! ```text
//! RetryingTransport          ← Roadmap 5.4: bounds and waits
//!   └── SigningTransport     ← here: stamps and signs, once per attempt
//!         └── HttpTransport  ← Roadmap 5.2: reaches the network
//!
//! …then ResponseAuthenticator::authenticate on what comes back.
//! ```
//!
//! **The order of the first two is load-bearing.** [`SigningTransport`] signs the request it is
//! given, so placing it *inside* the retry loop re-derives the timestamp and the signature on every
//! attempt. Placing it outside would resend one timestamp and one signature minutes later — a
//! replay the agent may reject, and one no happy-path test would catch. Roadmap 5.4 recorded this
//! constraint when the retry loop was built; this is the module it constrains.
//!
//! # Response authentication is not a transport
//!
//! [`ResponseAuthenticator`] is a separate type a caller invokes *after* the retry loop returns,
//! which is exactly where the reference verifies. Doing it inside a decorator would make a forged
//! response a transport failure, and Roadmap 5.4 would then have to special-case it out of the
//! retry classifier — a signature that does not verify is not worth asking for again.
//!
//! # What the reference does not do
//!
//! **It never checks freshness.** `Authenticater.verify` reads `created` only to rebuild the
//! signature base, `Authenticater.sign` never supplies the `expires` the grammar would carry, and
//! verification reads no clock at all — all three machine-checked in
//! `fixtures/http-auth/v1.json`. A captured response therefore authenticates forever. [`Freshness`]
//! is applied by default here; [`Freshness::Ignore`] reproduces the reference.

use core::fmt;
use core::time::Duration;
use std::error::Error;
use std::sync::Arc;
use std::time::SystemTime;

use crate::header::{HeaderName, HeaderValue, Headers};
use crate::retry::Clock;
use crate::signature::authentication::{AuthenticationError, RequestSigner, ResponseVerifier};
use crate::signature::input::{
    RequestTarget, SIGNIFY_RESOURCE_HEADER_NAME, SIGNIFY_TIMESTAMP_HEADER_NAME, SignatureComponent, SignatureInput,
    default_components,
};
use crate::signature::timestamp::{SignifyTimestamp, TimestampError};
use crate::transport::{Request, Transport, TransportError, TransportFuture};

/// How long either side of now a signature's `created` may sit.
///
/// The reference has no such notion: nothing anywhere compares `created` to a clock, so a response
/// captured today authenticates indefinitely. A window is the smallest thing that closes that, and
/// it is a window rather than a maximum age because two machines' clocks disagree in both
/// directions.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Freshness {
    /// Accept any `created`, as the reference does.
    Ignore,
    /// Accept a `created` between `past` before now and `future` after it.
    Window {
        /// How far behind now a signature may be.
        past: Duration,
        /// How far ahead of now a signature may be, which is tolerance for clock skew.
        future: Duration,
    },
}

impl Default for Freshness {
    /// Five minutes behind, one minute ahead.
    ///
    /// Generous in both directions on purpose. KERIA's clock is not this client's, and the cost of
    /// a window that is too tight is a working deployment that starts refusing its own agent —
    /// a far worse failure than the replay window being five minutes rather than one.
    fn default() -> Self {
        Self::Window {
            past: Duration::from_mins(5),
            future: Duration::from_mins(1),
        }
    }
}

impl Freshness {
    /// Checks one `created` against a moment.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseAuthenticationError::Stale`] when the signature is older than the window
    /// allows and [`ResponseAuthenticationError::FromTheFuture`] when it is newer.
    pub fn check(self, created: u64, now: SystemTime) -> Result<(), ResponseAuthenticationError> {
        let Self::Window { past, future } = self else {
            return Ok(());
        };
        let now_seconds = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| ResponseAuthenticationError::UnusableClock)?
            .as_secs();

        if created.saturating_add(past.as_secs()) < now_seconds {
            return Err(ResponseAuthenticationError::Stale {
                created,
                now: now_seconds,
                allowed: past,
            });
        }
        if created > now_seconds.saturating_add(future.as_secs()) {
            return Err(ResponseAuthenticationError::FromTheFuture {
                created,
                now: now_seconds,
                allowed: future,
            });
        }
        Ok(())
    }
}

/// A [`Transport`] that stamps and signs each request before passing it on.
///
/// Every attempt gets its own timestamp and its own signature, taken from **one** clock reading —
/// where the reference reads the clock twice, once for the header and once for the `created`
/// parameter, so its two values can disagree.
///
/// ```
/// use std::sync::Arc;
/// use signify_crypto::signer::Signer;
/// use signify_crypto::verifier::KeyTransferability;
/// use signify_http::header::HeaderValue;
/// use signify_http::retry::TestClock;
/// use signify_http::signature::authentication::RequestSigner;
/// use signify_http::signature::transport::SigningTransport;
/// use signify_http::transport::{ScriptedTransport, Transport};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let signer = Signer::generate(KeyTransferability::NonTransferable)?;
/// let transport = SigningTransport::new(
///     Arc::new(ScriptedTransport::new()),
///     RequestSigner::new(signer),
///     HeaderValue::new("ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose")?,
/// )?
/// .with_clock(Arc::new(TestClock::new()));
///
/// assert_eq!(transport.covered_components().len(), 4);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct SigningTransport {
    inner: Arc<dyn Transport>,
    signer: RequestSigner,
    clock: Arc<dyn Clock>,
    resource: HeaderValue,
    components: Vec<SignatureComponent>,
}

impl SigningTransport {
    /// Wraps a transport with a signer and the resource it speaks for.
    ///
    /// `resource` is the `Signify-Resource` value — the controller prefix a KERIA agent knows this
    /// client by. What that prefix *is* stays the client's knowledge (Roadmap 6.4); this layer only
    /// stamps and covers it.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::Input`] if the default covered components ever stop being
    /// valid field names, which the unit tests assert they do not.
    pub fn new(
        inner: Arc<dyn Transport>,
        signer: RequestSigner,
        resource: HeaderValue,
    ) -> Result<Self, AuthenticationError> {
        Ok(Self {
            inner,
            signer,
            #[cfg(feature = "http-client")]
            clock: Arc::new(crate::retry::TokioClock),
            #[cfg(not(feature = "http-client"))]
            clock: Arc::new(crate::retry::TestClock::new()),
            resource,
            components: default_components()?,
        })
    }

    /// Sets the clock the timestamp and the `created` parameter are read from.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Sets which components a signature covers.
    ///
    /// The default is the reference's four — `@method`, `@path`, `signify-resource`, and
    /// `signify-timestamp` — which is what KERIA verifies. Naming anything else produces a
    /// signature a KERIA agent will not accept, so this exists for a peer that has agreed to
    /// something different, not as a tuning knob.
    #[must_use]
    pub fn with_covered_components(mut self, components: Vec<SignatureComponent>) -> Self {
        self.components = components;
        self
    }

    /// Returns the components a signature covers.
    #[must_use]
    pub fn covered_components(&self) -> &[SignatureComponent] {
        &self.components
    }

    /// Returns the resource value each request is stamped with.
    #[must_use]
    pub const fn resource(&self) -> &HeaderValue {
        &self.resource
    }

    /// Stamps and signs one request, returning the request that should actually be sent.
    ///
    /// Exposed because a caller may need the signed form without sending it — the reference's
    /// `createSignedRequest` builds exactly this and hands it back.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::Timestamp`] when the clock cannot be rendered,
    /// [`SigningError::Authentication`] when the signature cannot be produced — most often a
    /// covered header the request does not carry, or a stamped header colliding with one it
    /// already had, which is what signing the same request twice does — and
    /// [`SigningError::Request`] when the signed request cannot be reassembled.
    pub fn sign_request(&self, request: &Request) -> Result<Request, SigningError> {
        // One reading, used for the header and for the `created` parameter alike.
        let stamp = SignifyTimestamp::at(self.clock.wall_clock())?;

        let mut headers = request.headers().clone();
        headers.insert(HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME)?, self.resource.clone())?;
        headers.insert(
            HeaderName::new(SIGNIFY_TIMESTAMP_HEADER_NAME)?,
            stamp.to_header_value()?,
        )?;

        // The query is stripped before signing, as upstream: `RequestUrl::path` never carries one.
        let target = RequestTarget::new(request.method().as_str(), request.url().path())?;
        let input = self.signer.signature_input(self.components.clone(), stamp.created())?;
        self.signer.sign(&input, &target, &headers)?.apply(&mut headers)?;

        let mut builder = Request::builder(request.method(), request.url().clone())
            .headers(&headers)
            .response_limit(request.response_limit());
        if let Some(body) = request.body() {
            builder = builder.body(body.to_vec());
        }
        Ok(builder.build()?)
    }
}

impl Transport for SigningTransport {
    fn execute(&self, request: Request) -> TransportFuture<'_> {
        Box::pin(async move {
            // A signing failure is bounded and permanent: Roadmap 5.4's classifier never retries it.
            let signed = self
                .sign_request(&request)
                .map_err(|error| TransportError::signing(error.to_string()))?;
            self.inner.execute(signed).await
        })
    }
}

/// Checks that a response came from the expected agent, and that it said what it appears to say.
///
/// This runs *after* a retry loop, not inside one: the reference verifies at the same point, and a
/// signature that does not check is not worth asking for again.
#[derive(Debug)]
pub struct ResponseAuthenticator {
    verifier: ResponseVerifier,
    expected_resource: HeaderValue,
    freshness: Freshness,
    clock: Arc<dyn Clock>,
}

impl ResponseAuthenticator {
    /// Requires responses signed by `verifier` and stamped with `expected_resource`.
    #[must_use]
    pub fn new(verifier: ResponseVerifier, expected_resource: HeaderValue, clock: Arc<dyn Clock>) -> Self {
        Self {
            verifier,
            expected_resource,
            freshness: Freshness::default(),
            clock,
        }
    }

    /// Sets how old a signature may be.
    #[must_use]
    pub const fn with_freshness(mut self, freshness: Freshness) -> Self {
        self.freshness = freshness;
        self
    }

    /// Returns the freshness window in force.
    #[must_use]
    pub const fn freshness(&self) -> Freshness {
        self.freshness
    }

    /// Returns the resource a response must claim to speak for.
    #[must_use]
    pub const fn expected_resource(&self) -> &HeaderValue {
        &self.expected_resource
    }

    /// Authenticates one response.
    ///
    /// The checks run in the reference's own order — the resource header first, then the signature
    /// — with the freshness check added **after** verification, because `created` is only worth
    /// trusting once the signature covering it has checked out.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseAuthenticationError::MissingResource`] when the response carries no
    /// `Signify-Resource`, [`ResponseAuthenticationError::UnexpectedResource`] when it names a
    /// different one, [`ResponseAuthenticationError::Signature`] when verification fails, and
    /// [`ResponseAuthenticationError::Stale`] or
    /// [`ResponseAuthenticationError::FromTheFuture`] when the signature sits outside the window.
    pub fn authenticate(
        &self,
        target: &RequestTarget,
        headers: &Headers,
    ) -> Result<SignatureInput, ResponseAuthenticationError> {
        let claimed = headers
            .get(SIGNIFY_RESOURCE_HEADER_NAME)
            .ok_or(ResponseAuthenticationError::MissingResource)?;
        if claimed != self.expected_resource.as_str() {
            return Err(ResponseAuthenticationError::UnexpectedResource {
                expected: bounded(self.expected_resource.as_str()),
                actual: bounded(claimed),
            });
        }

        let input = self
            .verifier
            .verify(target, headers)
            .map_err(|source| ResponseAuthenticationError::Signature {
                source: Box::new(source),
            })?;

        self.freshness.check(input.created(), self.clock.wall_clock())?;
        Ok(input)
    }
}

/// Copies at most sixty-four characters of a rejected value into an error.
fn bounded(text: &str) -> String {
    text.chars().take(64).collect()
}

/// Stable failures of composing a signed request.
///
/// A local type rather than a new variant on Roadmap 3.10's `AuthenticationError`: the three ways
/// this composition fails belong to the composition, and adding them upstream would make
/// `signature::authentication` depend on `transport`, which nothing else in that module needs.
#[derive(Debug)]
#[non_exhaustive]
pub enum SigningError {
    /// The clock could not be rendered as a `Signify-Timestamp`.
    Timestamp {
        /// Underlying failure.
        source: TimestampError,
    },
    /// The signature could not be produced.
    ///
    /// Most often a covered header the request does not carry, or a stamped header colliding with
    /// one it already had — which is what signing the same request twice does.
    Authentication {
        /// Underlying failure.
        source: Box<AuthenticationError>,
    },
    /// The signed request could not be reassembled.
    Request {
        /// Underlying failure.
        source: Box<TransportError>,
    },
}

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timestamp { source } => write!(formatter, "the request could not be stamped: {source}"),
            Self::Authentication { source } => write!(formatter, "the request could not be signed: {source}"),
            Self::Request { source } => write!(formatter, "the signed request could not be built: {source}"),
        }
    }
}

impl Error for SigningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Timestamp { source } => Some(source),
            Self::Authentication { source } => Some(source),
            Self::Request { source } => Some(source),
        }
    }
}

impl From<TimestampError> for SigningError {
    fn from(source: TimestampError) -> Self {
        Self::Timestamp { source }
    }
}

impl From<AuthenticationError> for SigningError {
    fn from(source: AuthenticationError) -> Self {
        Self::Authentication {
            source: Box::new(source),
        }
    }
}

impl From<crate::header::HeaderError> for SigningError {
    fn from(source: crate::header::HeaderError) -> Self {
        Self::Authentication {
            source: Box::new(AuthenticationError::from(source)),
        }
    }
}

impl From<crate::signature::input::SignatureInputError> for SigningError {
    fn from(source: crate::signature::input::SignatureInputError) -> Self {
        Self::Authentication {
            source: Box::new(AuthenticationError::from(source)),
        }
    }
}

impl From<TransportError> for SigningError {
    fn from(source: TransportError) -> Self {
        Self::Request {
            source: Box::new(source),
        }
    }
}

/// Stable response-authentication failures.
///
/// The reference collapses every one of these into the single message
/// `response verification failed`, or into `message from a different remote agent`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ResponseAuthenticationError {
    /// The response carries no `Signify-Resource` header.
    ///
    /// The reference compares the header against the agent prefix with `===`, so an absent header
    /// compares against `null` and is indistinguishable from a genuine mismatch.
    MissingResource,
    /// The response names a different resource than the one expected.
    UnexpectedResource {
        /// Bounded copy of the expected value.
        expected: String,
        /// Bounded copy of what the response claimed.
        actual: String,
    },
    /// The signature did not authenticate the response.
    Signature {
        /// Underlying failure.
        source: Box<AuthenticationError>,
    },
    /// The signature is older than the freshness window allows.
    Stale {
        /// The `created` the signature carried, in seconds since the Unix epoch.
        created: u64,
        /// Now, in the same units.
        now: u64,
        /// How far behind now a signature may be.
        allowed: Duration,
    },
    /// The signature claims a moment further ahead than the window allows.
    FromTheFuture {
        /// The `created` the signature carried, in seconds since the Unix epoch.
        created: u64,
        /// Now, in the same units.
        now: u64,
        /// How far ahead of now a signature may be.
        allowed: Duration,
    },
    /// The clock reads before the Unix epoch, so freshness cannot be judged.
    UnusableClock,
}

impl fmt::Display for ResponseAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingResource => {
                write!(
                    formatter,
                    "the response carries no {SIGNIFY_RESOURCE_HEADER_NAME:?} header"
                )
            }
            Self::UnexpectedResource { expected, actual } => write!(
                formatter,
                "the response speaks for {actual:?} but {expected:?} was expected"
            ),
            Self::Signature { source } => write!(formatter, "the response signature failed: {source}"),
            Self::Stale { created, now, allowed } => write!(
                formatter,
                "the response signature was created at {created} and now is {now}, more than {allowed:?} ago"
            ),
            Self::FromTheFuture { created, now, allowed } => write!(
                formatter,
                "the response signature claims {created} but now is {now}, more than {allowed:?} ahead"
            ),
            Self::UnusableClock => formatter.write_str("the clock reads before the Unix epoch"),
        }
    }
}

impl Error for ResponseAuthenticationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Signature { source } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::TestClock;
    use crate::signature::input::SIGNATURE_INPUT_HEADER_NAME;
    use crate::transport::{Method, RequestUrl, Response, ScriptedTransport, StatusCode};
    use signify_crypto::signer::Signer;
    use signify_crypto::verifier::KeyTransferability;
    use std::error::Error;

    /// A minimal executor; every future on this path is ready on its first poll.
    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        use core::task::{Context, Poll, Waker};
        let mut future = Box::pin(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
        }
    }

    /// A clock pinned to 2023-11-14T22:13:20.123Z, the instant the fixture uses.
    fn pinned_clock() -> Arc<TestClock> {
        Arc::new(TestClock::with_wall_clock(
            SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
        ))
    }

    const RESOURCE: &str = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose";

    fn request(method: Method) -> Result<Request, Box<dyn Error>> {
        Ok(Request::builder(
            method,
            RequestUrl::new("http://localhost:3901/identifiers?group=secret")?,
        )
        .build()?)
    }

    fn signing_transport(clock: Arc<TestClock>) -> Result<(SigningTransport, Signer), Box<dyn Error>> {
        let signer = Signer::generate(KeyTransferability::NonTransferable)?;
        let copy = Signer::generate(KeyTransferability::NonTransferable)?;
        let transport = SigningTransport::new(
            Arc::new(ScriptedTransport::new().respond(Response::new(
                StatusCode::new(200)?,
                Headers::new(),
                Vec::new(),
            )?)),
            RequestSigner::new(signer),
            HeaderValue::new(RESOURCE)?,
        )?
        .with_clock(clock);
        Ok((transport, copy))
    }

    #[test]
    fn a_signed_request_carries_the_four_headers() -> Result<(), Box<dyn Error>> {
        let clock = pinned_clock();
        let (transport, _) = signing_transport(Arc::clone(&clock))?;
        let signed = transport.sign_request(&request(Method::Get)?)?;

        assert_eq!(signed.headers().get("signify-resource"), Some(RESOURCE));
        assert_eq!(
            signed.headers().get("signify-timestamp"),
            Some("2023-11-14T22:13:20.123000+00:00"),
        );
        assert!(signed.headers().contains("signature"));
        assert!(signed.headers().contains(SIGNATURE_INPUT_HEADER_NAME));
        // The request itself is otherwise untouched.
        assert_eq!(signed.method(), Method::Get);
        assert_eq!(signed.url().as_str(), "http://localhost:3901/identifiers?group=secret");
        assert_eq!(signed.body(), None);
        Ok(())
    }

    #[test]
    fn the_signature_covers_the_path_without_its_query() -> Result<(), Box<dyn Error>> {
        let clock = pinned_clock();
        let (transport, _) = signing_transport(Arc::clone(&clock))?;
        let with_query = transport.sign_request(&request(Method::Get)?)?;

        let plain = Request::builder(Method::Get, RequestUrl::new("http://localhost:3901/identifiers")?).build()?;
        let without_query = transport.sign_request(&plain)?;

        // The same base, so the same signature: the query is stripped before signing, as upstream.
        assert_eq!(
            with_query.headers().get("signature"),
            without_query.headers().get("signature"),
        );
        Ok(())
    }

    #[test]
    fn a_body_is_carried_but_not_covered() -> Result<(), Box<dyn Error>> {
        let clock = pinned_clock();
        let (transport, _) = signing_transport(Arc::clone(&clock))?;
        let url = RequestUrl::new("http://localhost:3901/identifiers")?;

        let first = Request::builder(Method::Post, url.clone())
            .body(br#"{"name":"aid1"}"#.to_vec())
            .build()?;
        let second = Request::builder(Method::Post, url)
            .body(br#"{"name":"other"}"#.to_vec())
            .build()?;

        let one = transport.sign_request(&first)?;
        let two = transport.sign_request(&second)?;
        assert_eq!(one.body(), Some(br#"{"name":"aid1"}"#.as_slice()));
        // Nothing signed covers what was sent, exactly as upstream: the bodies differ and the
        // signatures do not.
        assert_eq!(one.headers().get("signature"), two.headers().get("signature"));
        Ok(())
    }

    #[test]
    fn signing_the_same_request_twice_is_refused() -> Result<(), Box<dyn Error>> {
        let clock = pinned_clock();
        let (transport, _) = signing_transport(Arc::clone(&clock))?;
        let once = transport.sign_request(&request(Method::Get)?)?;
        // The reference appends, producing two comma-joined values; Roadmap 3.9's `Headers`
        // refuses the duplicate instead.
        assert!(matches!(
            transport.sign_request(&once),
            Err(SigningError::Authentication { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_signing_failure_is_a_permanent_transport_failure() -> Result<(), Box<dyn Error>> {
        let clock = pinned_clock();
        let (transport, _) = signing_transport(Arc::clone(&clock))?;
        // Covering a header the request will never carry makes the base unbuildable.
        let transport =
            transport.with_covered_components(vec![SignatureComponent::Header(HeaderName::new("x-absent")?)]);
        let outcome = block_on(transport.execute(request(Method::Get)?));
        assert!(matches!(outcome, Err(TransportError::Signing { .. })), "{outcome:?}");
        // And Roadmap 5.4 will not retry it.
        if let Err(error) = outcome {
            assert!(!crate::retry::is_transient_error(&error));
        }
        Ok(())
    }

    #[test]
    fn the_signed_request_is_what_reaches_the_inner_transport() -> Result<(), Box<dyn Error>> {
        let clock = pinned_clock();
        let scripted = Arc::new(ScriptedTransport::new().respond(Response::new(
            StatusCode::new(200)?,
            Headers::new(),
            Vec::new(),
        )?));
        let transport = SigningTransport::new(
            Arc::clone(&scripted) as Arc<dyn Transport>,
            RequestSigner::new(Signer::generate(KeyTransferability::NonTransferable)?),
            HeaderValue::new(RESOURCE)?,
        )?
        .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);

        let answer = block_on(transport.execute(request(Method::Get)?));
        assert!(answer.is_ok());
        let sent = scripted.recorded();
        assert_eq!(sent.len(), 1);
        let sent = sent.first().ok_or("no request was recorded")?;
        assert_eq!(sent.headers().get("signify-resource"), Some(RESOURCE));
        assert!(sent.headers().contains("signature"));
        Ok(())
    }

    #[test]
    fn a_response_the_agent_signed_authenticates() -> Result<(), Box<dyn Error>> {
        let clock = pinned_clock();
        let agent = Signer::generate(KeyTransferability::NonTransferable)?;
        let verifier = ResponseVerifier::new(agent.verifier().clone());
        let agent_signer = RequestSigner::new(agent);

        // The agent stamps and signs its own answer.
        let target = RequestTarget::new("GET", "/identifiers")?;
        let stamp = SignifyTimestamp::at(clock.wall_clock())?;
        let mut headers = Headers::new();
        headers.insert(
            HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME)?,
            HeaderValue::new(RESOURCE)?,
        )?;
        headers.insert(
            HeaderName::new(SIGNIFY_TIMESTAMP_HEADER_NAME)?,
            stamp.to_header_value()?,
        )?;
        let input = agent_signer.signature_input(default_components()?, stamp.created())?;
        agent_signer.sign(&input, &target, &headers)?.apply(&mut headers)?;

        let authenticator = ResponseAuthenticator::new(
            verifier,
            HeaderValue::new(RESOURCE)?,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let covered = authenticator.authenticate(&target, &headers)?;
        assert_eq!(covered.created(), stamp.created());
        assert_eq!(authenticator.expected_resource().as_str(), RESOURCE);
        assert_eq!(authenticator.freshness(), Freshness::default());

        // A different path is a different base.
        let elsewhere = RequestTarget::new("GET", "/contacts")?;
        assert!(matches!(
            authenticator.authenticate(&elsewhere, &headers),
            Err(ResponseAuthenticationError::Signature { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_response_from_another_agent_is_refused_before_its_signature_is_checked() -> Result<(), Box<dyn Error>> {
        let clock = pinned_clock();
        let authenticator = ResponseAuthenticator::new(
            ResponseVerifier::new(
                Signer::generate(KeyTransferability::NonTransferable)?
                    .verifier()
                    .clone(),
            ),
            HeaderValue::new(RESOURCE)?,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let target = RequestTarget::new("GET", "/identifiers")?;

        // No resource header at all: the reference compares against `null` and cannot tell.
        assert!(matches!(
            authenticator.authenticate(&target, &Headers::new()),
            Err(ResponseAuthenticationError::MissingResource)
        ));

        let mut headers = Headers::new();
        headers.insert(
            HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME)?,
            HeaderValue::new("EOTHERAGENTPREFIX")?,
        )?;
        assert!(matches!(
            authenticator.authenticate(&target, &headers),
            Err(ResponseAuthenticationError::UnexpectedResource { .. })
        ));
        Ok(())
    }

    #[test]
    fn freshness_bounds_a_signature_in_both_directions() {
        let window = Freshness::default();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        // Inside the window, at both edges.
        assert!(window.check(1_700_000_000, now).is_ok());
        assert!(window.check(1_700_000_000 - 300, now).is_ok());
        assert!(window.check(1_700_000_000 + 60, now).is_ok());

        // One second past either edge.
        assert!(matches!(
            window.check(1_700_000_000 - 301, now),
            Err(ResponseAuthenticationError::Stale { .. })
        ));
        assert!(matches!(
            window.check(1_700_000_000 + 61, now),
            Err(ResponseAuthenticationError::FromTheFuture { .. })
        ));

        // The reference's behaviour: a signature from any moment at all is accepted.
        assert!(Freshness::Ignore.check(0, now).is_ok());
        assert!(Freshness::Ignore.check(u64::MAX, now).is_ok());
        // And nothing overflows at the extremes.
        assert!(window.check(u64::MAX, now).is_err());
        assert!(window.check(0, now).is_err());
    }

    #[test]
    fn a_replayed_response_is_refused_where_the_reference_accepts_it() -> Result<(), Box<dyn Error>> {
        let signing_clock = pinned_clock();
        let agent = Signer::generate(KeyTransferability::NonTransferable)?;
        let key = agent.verifier().clone();
        let verifier = ResponseVerifier::new(key.clone());
        let agent_signer = RequestSigner::new(agent);

        let target = RequestTarget::new("GET", "/identifiers")?;
        let stamp = SignifyTimestamp::at(signing_clock.wall_clock())?;
        let mut headers = Headers::new();
        headers.insert(
            HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME)?,
            HeaderValue::new(RESOURCE)?,
        )?;
        headers.insert(
            HeaderName::new(SIGNIFY_TIMESTAMP_HEADER_NAME)?,
            stamp.to_header_value()?,
        )?;
        let input = agent_signer.signature_input(default_components()?, stamp.created())?;
        agent_signer.sign(&input, &target, &headers)?.apply(&mut headers)?;

        // An hour later the signature still verifies — it is the same bytes — but it is stale.
        let later = Arc::new(TestClock::with_wall_clock(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + 3_600),
        ));
        let authenticator = ResponseAuthenticator::new(
            verifier,
            HeaderValue::new(RESOURCE)?,
            Arc::clone(&later) as Arc<dyn Clock>,
        );
        assert!(matches!(
            authenticator.authenticate(&target, &headers),
            Err(ResponseAuthenticationError::Stale { .. })
        ));

        // With the reference's own policy it is accepted, forever.
        let permissive = ResponseAuthenticator::new(
            ResponseVerifier::new(key),
            HeaderValue::new(RESOURCE)?,
            Arc::clone(&later) as Arc<dyn Clock>,
        )
        .with_freshness(Freshness::Ignore);
        assert!(permissive.authenticate(&target, &headers).is_ok());
        Ok(())
    }

    #[test]
    fn errors_carry_readable_text_and_their_sources() {
        let cases: Vec<(ResponseAuthenticationError, bool)> = vec![
            (ResponseAuthenticationError::MissingResource, false),
            (
                ResponseAuthenticationError::UnexpectedResource {
                    expected: "E1".to_owned(),
                    actual: "E2".to_owned(),
                },
                false,
            ),
            (
                ResponseAuthenticationError::Signature {
                    source: Box::new(AuthenticationError::MissingSignature),
                },
                true,
            ),
            (
                ResponseAuthenticationError::Stale {
                    created: 1,
                    now: 2,
                    allowed: Duration::from_secs(1),
                },
                false,
            ),
            (
                ResponseAuthenticationError::FromTheFuture {
                    created: 2,
                    now: 1,
                    allowed: Duration::from_secs(1),
                },
                false,
            ),
            (ResponseAuthenticationError::UnusableClock, false),
        ];
        for (error, has_source) in cases {
            assert!(!error.to_string().is_empty());
            assert_eq!(error.source().is_some(), has_source, "{error}");
        }
    }
}
