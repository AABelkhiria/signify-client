#![no_main]

//! Fuzzes the authenticated-transport composition.
//!
//! Two things here come from outside the process, and both decide whether a caller trusts what it
//! received. A **response's headers** are entirely the peer's — the resource it claims, the
//! timestamp it stamps, and the two signature headers — and a **clock reading** decides whether a
//! signature is still fresh. Between them sits the signing side, which must never produce a
//! request that carries two of any header or a signature over a base it did not build.
//!
//! The target asserts that nothing panics, that every rejection is a typed error with a non-empty
//! description, and above all the two properties that make the layer worth having: **a response is
//! accepted only when its signature actually verifies against the expected key**, and **a signed
//! request always carries exactly the four headers the reference sends** — never a duplicate, and
//! never a signature over a path that differs from the one being sent.

use core::time::Duration;
use std::sync::Arc;
use std::time::SystemTime;

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use libfuzzer_sys::fuzz_target;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, TestClock, is_transient_error};
use signify_http::signature::authentication::{RequestSigner, ResponseVerifier};
use signify_http::signature::input::{
    RequestTarget, SIGNIFY_RESOURCE_HEADER_NAME, SIGNIFY_TIMESTAMP_HEADER_NAME, default_components,
};
use signify_http::signature::timestamp::{SignifyTimestamp, TimestampError};
use signify_http::signature::transport::{
    Freshness, ResponseAuthenticationError, ResponseAuthenticator, SigningTransport,
};
use signify_http::transport::{Method, Request, RequestUrl, ScriptedTransport, Transport, TransportError};

/// The controller prefix the fixture uses.
const RESOURCE: &str = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose";

/// Returns whether a rejection is one response authentication is allowed to produce.
fn is_expected(error: &ResponseAuthenticationError) -> bool {
    matches!(
        error,
        ResponseAuthenticationError::MissingResource
            | ResponseAuthenticationError::UnexpectedResource { .. }
            | ResponseAuthenticationError::Signature { .. }
            | ResponseAuthenticationError::Stale { .. }
            | ResponseAuthenticationError::FromTheFuture { .. }
            | ResponseAuthenticationError::UnusableClock
    )
}

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

fuzz_target!(|data: &[u8]| {
    let [selector, skew, path_len, rest @ ..] = data else {
        return;
    };
    let text = String::from_utf8_lossy(rest).into_owned();

    // ---------------------------------------------------------------
    // The timestamp: every moment either renders in the fixed shape or is refused.
    // ---------------------------------------------------------------
    let millis = rest
        .get(..8)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map_or(1_700_000_000_123, u64::from_le_bytes);
    match SignifyTimestamp::from_unix(Duration::from_millis(millis)) {
        Ok(stamp) => {
            let rendered = stamp.as_str();
            assert_eq!(rendered.len(), 32, "{rendered}");
            assert!(rendered.ends_with("000+00:00"), "{rendered}");
            assert!(rendered.is_ascii());
            // The header and the `created` parameter always come from one reading.
            assert_eq!(stamp.created(), millis / 1_000);
            // And the value can always become a header, which the signature depends on.
            assert!(stamp.to_header_value().is_ok(), "{rendered}");
        }
        Err(error) => {
            assert!(matches!(
                error,
                TimestampError::BeforeEpoch | TimestampError::OutOfRange { .. }
            ));
            assert!(!error.to_string().is_empty());
        }
    }

    // ---------------------------------------------------------------
    // The signing side: a signed request is well formed, whatever it was given.
    // ---------------------------------------------------------------
    let clock: Arc<dyn Clock> = Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
    ));
    let Ok(signer) = Signer::generate(KeyTransferability::Transferable) else {
        return;
    };
    let Ok(resource) = HeaderValue::new(RESOURCE) else {
        return;
    };
    let Ok(transport) = SigningTransport::new(
        Arc::new(ScriptedTransport::new()),
        RequestSigner::new(signer),
        resource,
        Arc::clone(&clock),
    ) else {
        return;
    };

    let split = usize::from(*path_len) % text.len().saturating_add(1);
    let candidate = format!("http://localhost:3901/{}", text.get(..split).unwrap_or_default());
    if let Ok(url) = RequestUrl::new(candidate) {
        let method = *Method::ALL
            .get(usize::from(*selector) % Method::ALL.len())
            .unwrap_or(&Method::Get);
        let mut builder = Request::builder(method, url.clone());
        if selector & 1 == 1 {
            builder = builder.body(rest.to_vec());
        }
        if let Ok(request) = builder.build() {
            match transport.sign_request(&request) {
                Ok(signed) => {
                    // Everything the request had, it still has.
                    assert_eq!(signed.method(), method);
                    assert_eq!(signed.url().as_str(), url.as_str());
                    assert_eq!(signed.body(), request.body());
                    // Exactly the four headers the reference adds, each exactly once — the
                    // `Headers` invariant makes a duplicate unrepresentable, so reaching here at
                    // all is the assertion.
                    assert_eq!(signed.headers().len(), request.headers().len() + 4);
                    for name in [
                        SIGNIFY_RESOURCE_HEADER_NAME,
                        SIGNIFY_TIMESTAMP_HEADER_NAME,
                        "Signature",
                        "Signature-Input",
                    ] {
                        assert!(signed.headers().contains(name), "{name} is absent");
                    }
                    assert_eq!(signed.headers().get(SIGNIFY_RESOURCE_HEADER_NAME), Some(RESOURCE));
                    // Signing it again is always refused, never silently appended.
                    assert!(transport.sign_request(&signed).is_err());
                }
                Err(error) => assert!(!error.to_string().is_empty(), "{error:?}"),
            }
        }
    }

    // An unsignable request is a permanent transport failure, never a retryable one.
    if let (Ok(url), Ok(absent)) = (
        RequestUrl::new("http://localhost:3901/identifiers"),
        HeaderName::new("x-never-present"),
    ) && let Ok(request) = Request::builder(Method::Get, url).build()
    {
        let broken = SigningTransport::new(
            Arc::new(ScriptedTransport::new()),
            RequestSigner::new(match Signer::generate(KeyTransferability::Transferable) {
                Ok(signer) => signer,
                Err(_) => return,
            }),
            match HeaderValue::new(RESOURCE) {
                Ok(value) => value,
                Err(_) => return,
            },
            Arc::clone(&clock),
        );
        if let Ok(broken) = broken {
            let broken = broken
                .with_covered_components(vec![signify_http::signature::input::SignatureComponent::Header(absent)]);
            match block_on(broken.execute(request)) {
                Ok(_) => panic!("an unsignable request was sent"),
                Err(error) => {
                    assert!(matches!(error, TransportError::Signing { .. }), "{error:?}");
                    assert!(!is_transient_error(&error), "a signing failure would be retried");
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // The peer's side: a response is trusted only when it really verifies.
    // ---------------------------------------------------------------
    let Ok(agent) = Signer::generate(KeyTransferability::NonTransferable) else {
        return;
    };
    let key = agent.verifier().clone();
    let permissive_key = key.clone();
    let agent_signer = RequestSigner::new(agent);
    let Ok(target) = RequestTarget::new("GET", "/identifiers") else {
        return;
    };
    let Ok(stamp) = SignifyTimestamp::at(clock.wall_clock()) else {
        return;
    };

    let mut headers = Headers::new();
    let (Ok(resource_name), Ok(timestamp_name)) = (
        HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME),
        HeaderName::new(SIGNIFY_TIMESTAMP_HEADER_NAME),
    ) else {
        return;
    };
    // The resource the peer *claims*, which the input controls.
    let claimed = if selector & 2 == 2 {
        HeaderValue::new(&text).ok()
    } else {
        HeaderValue::new(RESOURCE).ok()
    };
    let Some(claimed) = claimed else {
        return;
    };
    let claimed_text = claimed.as_str().to_owned();
    if headers.insert(resource_name, claimed).is_err() {
        return;
    }
    let Ok(stamp_value) = stamp.to_header_value() else {
        return;
    };
    if headers.insert(timestamp_name, stamp_value).is_err() {
        return;
    }

    // Sign it honestly, then let the input decide whether to corrupt what the signature covered.
    let Ok(components) = default_components() else {
        return;
    };
    let Ok(input) = agent_signer.signature_input(components, stamp.created()) else {
        return;
    };
    let Ok(applied) = agent_signer.sign(&input, &target, &headers) else {
        return;
    };
    if applied.apply(&mut headers).is_err() {
        return;
    }

    let skewed =
        SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123) + Duration::from_secs(u64::from(*skew) * 10);
    let later: Arc<dyn Clock> = Arc::new(TestClock::with_wall_clock(skewed));
    let Ok(expected) = HeaderValue::new(RESOURCE) else {
        return;
    };
    let authenticator = ResponseAuthenticator::new(ResponseVerifier::new(key), expected, later);

    match authenticator.authenticate(&target, &headers) {
        Ok(covered) => {
            // Accepted, so every condition really held: the resource matched, the signature
            // verified against the expected key, and the moment was inside the window.
            assert_eq!(claimed_text, RESOURCE);
            assert_eq!(covered.created(), stamp.created());
            let elapsed = u64::from(*skew) * 10;
            assert!(elapsed <= 300, "a signature {elapsed} s old was accepted");
        }
        Err(error) => {
            assert!(is_expected(&error), "{error:?}");
            assert!(!error.to_string().is_empty());
            // A mismatched resource is always reported as such, before any signature is touched.
            if claimed_text != RESOURCE {
                assert!(matches!(error, ResponseAuthenticationError::UnexpectedResource { .. }));
            }
        }
    }

    // With the reference's own policy the same response is accepted whenever it matches, however
    // old it is — which is the divergence this layer exists to close.
    let permissive = ResponseAuthenticator::new(
        ResponseVerifier::new(permissive_key),
        match HeaderValue::new(RESOURCE) {
            Ok(value) => value,
            Err(_) => return,
        },
        Arc::new(TestClock::with_wall_clock(skewed)),
    )
    .with_freshness(Freshness::Ignore);
    let outcome = permissive.authenticate(&target, &headers);
    if claimed_text == RESOURCE {
        assert!(outcome.is_ok(), "{outcome:?}");
    }
});
