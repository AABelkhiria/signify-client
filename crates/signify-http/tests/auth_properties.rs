//! Invariants of the authenticated-transport composition.
//!
//! The generators include the boundaries that matter: a moment on either side of a freshness
//! window's exact edge, a timestamp at the epoch and at the last year the format can hold, and a
//! request whose method and path vary independently of what a signature covers.

use core::time::Duration;
use std::sync::Arc;
use std::time::SystemTime;

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use proptest::prelude::*;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::authentication::{RequestSigner, ResponseVerifier};
use signify_http::signature::input::{
    RequestTarget, SIGNIFY_RESOURCE_HEADER_NAME, SIGNIFY_TIMESTAMP_HEADER_NAME, default_components,
};
use signify_http::signature::timestamp::{MAX_YEAR, SignifyTimestamp, TIMESTAMP_WIDTH, TimestampError};
use signify_http::signature::transport::{
    Freshness, ResponseAuthenticationError, ResponseAuthenticator, SigningTransport,
};
use signify_http::transport::{Method, Request, RequestUrl, ScriptedTransport, Transport, TransportError};

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn method_of(index: usize) -> Method {
    *Method::ALL.get(index % Method::ALL.len()).unwrap_or(&Method::Get)
}

const RESOURCE: &str = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose";

/// The last instant the four-digit year can hold, in milliseconds.
const LATEST_MILLIS: u64 = 253_402_300_799_000;

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

/// Builds a signing transport over a scripted answer at a fixed clock.
fn signing_transport(at_millis: u64) -> Result<(SigningTransport, Arc<TestClock>), TestCaseError> {
    let clock = Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(at_millis),
    ));
    let signer = Signer::generate(KeyTransferability::Transferable).map_err(fail)?;
    let transport = SigningTransport::new(
        Arc::new(ScriptedTransport::new()),
        RequestSigner::new(signer),
        HeaderValue::new(RESOURCE).map_err(fail)?,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .map_err(fail)?;
    Ok((transport, clock))
}

proptest! {
    /// A rendered timestamp is always the same fixed shape, whatever the moment.
    #[test]
    fn a_timestamp_is_always_the_same_width_and_shape(millis in 0_u64..LATEST_MILLIS) {
        let stamp = SignifyTimestamp::from_unix(Duration::from_millis(millis)).map_err(fail)?;
        let text = stamp.as_str();
        prop_assert_eq!(text.len(), TIMESTAMP_WIDTH);
        prop_assert!(text.ends_with("000+00:00"), "{}", text);
        prop_assert!(text.is_ascii());

        // The separators are exactly where the format puts them.
        prop_assert_eq!(text.as_bytes().get(4), Some(&b'-'));
        prop_assert_eq!(text.as_bytes().get(7), Some(&b'-'));
        prop_assert_eq!(text.as_bytes().get(10), Some(&b'T'));
        prop_assert_eq!(text.as_bytes().get(13), Some(&b':'));
        prop_assert_eq!(text.as_bytes().get(16), Some(&b':'));
        prop_assert_eq!(text.as_bytes().get(19), Some(&b'.'));

        // `created` is the whole second of the same reading, always.
        prop_assert_eq!(stamp.created(), millis / 1_000);
        // And the value is always usable as a header, which the signature depends on.
        let rendered = stamp.to_header_value().map_err(fail)?;
        prop_assert_eq!(rendered.as_str(), text);
    }

    /// A timestamp is rendered exactly when the format can hold it.
    #[test]
    fn a_timestamp_is_accepted_exactly_when_it_fits(seconds in 0_u64..400_000_000_000) {
        match SignifyTimestamp::from_unix(Duration::from_secs(seconds)) {
            Ok(stamp) => {
                prop_assert!(seconds <= LATEST_MILLIS / 1_000);
                let year: i64 = stamp.as_str().get(..4).unwrap_or("0").parse().unwrap_or(0);
                prop_assert!((1..=MAX_YEAR).contains(&year), "{year}");
            }
            Err(TimestampError::OutOfRange { .. }) => prop_assert!(seconds > LATEST_MILLIS / 1_000),
            Err(other) => return Err(fail(other)),
        }
    }

    /// A signed request keeps everything it had, and gains exactly four headers.
    #[test]
    fn signing_adds_four_headers_and_changes_nothing_else(
        index in 0_usize..8,
        path in "(/[A-Za-z0-9._~-]{0,12}){1,4}",
        query in proptest::option::of("[a-z]{1,6}=[a-z0-9]{1,8}"),
        with_body in any::<bool>(),
        millis in 0_u64..LATEST_MILLIS,
    ) {
        let (transport, _clock) = signing_transport(millis)?;
        let text = match &query {
            Some(query) => format!("http://localhost:3901{path}?{query}"),
            None => format!("http://localhost:3901{path}"),
        };
        let url = RequestUrl::new(text.clone()).map_err(fail)?;

        let mut builder = Request::builder(method_of(index), url);
        builder = builder.header(
            HeaderName::new("X-Extra").map_err(fail)?,
            HeaderValue::new("1").map_err(fail)?,
        );
        if with_body {
            builder = builder.body(b"{}".to_vec());
        }
        let original = builder.build().map_err(fail)?;
        let signed = transport.sign_request(&original).map_err(fail)?;

        // Method, URL, and body cross untouched.
        prop_assert_eq!(signed.method(), original.method());
        prop_assert_eq!(signed.url().as_str(), text.as_str());
        prop_assert_eq!(signed.body(), original.body());
        prop_assert_eq!(signed.headers().get("x-extra"), Some("1"));

        // Exactly the four the reference adds, and no more.
        prop_assert_eq!(signed.headers().len(), original.headers().len() + 4);
        for name in [
            SIGNIFY_RESOURCE_HEADER_NAME,
            SIGNIFY_TIMESTAMP_HEADER_NAME,
            "Signature",
            "Signature-Input",
        ] {
            prop_assert!(signed.headers().contains(name), "{name} is absent");
        }
        prop_assert_eq!(signed.headers().get(SIGNIFY_RESOURCE_HEADER_NAME), Some(RESOURCE));
    }

    /// The query never reaches the signature base, so it cannot change a signature.
    #[test]
    fn a_query_never_changes_a_signature(
        path in "(/[A-Za-z0-9._~-]{1,10}){1,3}",
        query in "[a-z]{1,6}=[a-z0-9]{1,10}",
        index in 0_usize..8,
    ) {
        let (transport, _clock) = signing_transport(1_700_000_000_123)?;
        let plain = RequestUrl::new(format!("http://localhost:3901{path}")).map_err(fail)?;
        let queried = RequestUrl::new(format!("http://localhost:3901{path}?{query}")).map_err(fail)?;

        let one = transport
            .sign_request(&Request::builder(method_of(index), plain).build().map_err(fail)?)
            .map_err(fail)?;
        let two = transport
            .sign_request(&Request::builder(method_of(index), queried).build().map_err(fail)?)
            .map_err(fail)?;

        prop_assert_eq!(one.headers().get("signature"), two.headers().get("signature"));
        prop_assert_eq!(
            one.headers().get("signature-input"),
            two.headers().get("signature-input"),
        );
    }

    /// A different method or path always produces a different signature.
    #[test]
    fn the_method_and_path_always_change_a_signature(
        left in 0_usize..4,
        right in 0_usize..4,
        first in "(/[a-z]{1,8}){1,3}",
        second in "(/[a-z]{1,8}){1,3}",
    ) {
        prop_assume!(left != right || first != second);
        let (transport, _clock) = signing_transport(1_700_000_000_123)?;

        let one = transport
            .sign_request(
                &Request::builder(
                    method_of(left),
                    RequestUrl::new(format!("http://localhost:3901{first}")).map_err(fail)?,
                )
                .build()
                .map_err(fail)?,
            )
            .map_err(fail)?;
        let two = transport
            .sign_request(
                &Request::builder(
                    method_of(right),
                    RequestUrl::new(format!("http://localhost:3901{second}")).map_err(fail)?,
                )
                .build()
                .map_err(fail)?,
            )
            .map_err(fail)?;

        // Both are covered components, so changing either changes the base and the signature.
        prop_assert_ne!(one.headers().get("signature"), two.headers().get("signature"));
    }

    /// Signing the same request twice is always refused, whatever it carried.
    #[test]
    fn a_request_is_never_signed_twice(index in 0_usize..8, millis in 0_u64..LATEST_MILLIS) {
        let (transport, _clock) = signing_transport(millis)?;
        let url = RequestUrl::new("http://localhost:3901/identifiers").map_err(fail)?;
        let once = transport
            .sign_request(&Request::builder(method_of(index), url).build().map_err(fail)?)
            .map_err(fail)?;
        // The reference appends a second value; here the duplicate name does not build.
        prop_assert!(transport.sign_request(&once).is_err());
    }

    /// A signing failure is always the permanent transport failure, never a transient one.
    #[test]
    fn a_signing_failure_is_never_retryable(name in "[a-z][a-z0-9-]{0,12}", index in 0_usize..8) {
        // Covering a header the request will never carry makes the base unbuildable.
        let (transport, _clock) = signing_transport(1_700_000_000_123)?;
        let absent = HeaderName::new(format!("x-{name}")).map_err(fail)?;
        let transport = transport.with_covered_components(vec![
            signify_http::signature::input::SignatureComponent::Header(absent),
        ]);
        let url = RequestUrl::new("http://localhost:3901/identifiers").map_err(fail)?;
        let request = Request::builder(method_of(index), url).build().map_err(fail)?;

        match block_on(transport.execute(request)) {
            Ok(_) => return Err(fail("an unsignable request was sent")),
            Err(error) => {
                prop_assert!(matches!(error, TransportError::Signing { .. }), "{error:?}");
                prop_assert!(!signify_http::retry::is_transient_error(&error));
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    /// A freshness window accepts exactly the moments inside it.
    #[test]
    fn freshness_accepts_exactly_its_window(
        created in 0_u64..4_000_000_000,
        now in 0_u64..4_000_000_000,
        past_secs in 0_u64..1_000,
        future_secs in 0_u64..1_000,
    ) {
        let window = Freshness::Window {
            past: Duration::from_secs(past_secs),
            future: Duration::from_secs(future_secs),
        };
        let moment = SystemTime::UNIX_EPOCH + Duration::from_secs(now);

        let inside = created.saturating_add(past_secs) >= now && created <= now.saturating_add(future_secs);
        match window.check(created, moment) {
            Ok(()) => prop_assert!(inside, "created={created} now={now}"),
            Err(ResponseAuthenticationError::Stale { .. }) => {
                prop_assert!(created.saturating_add(past_secs) < now);
            }
            Err(ResponseAuthenticationError::FromTheFuture { .. }) => {
                prop_assert!(created > now.saturating_add(future_secs));
            }
            Err(other) => return Err(fail(other)),
        }

        // The reference's own policy accepts every moment there is.
        prop_assert!(Freshness::Ignore.check(created, moment).is_ok());
    }

    /// A response the agent signed authenticates, and any change to what it covers breaks it.
    #[test]
    fn a_signed_response_authenticates_and_tampering_does_not(
        index in 0_usize..4,
        path in "(/[a-z]{1,8}){1,3}",
        tamper in 0_usize..4,
    ) {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = Arc::new(TestClock::with_wall_clock(at));
        let agent = Signer::generate(KeyTransferability::NonTransferable).map_err(fail)?;
        let key = agent.verifier().clone();
        let agent_signer = RequestSigner::new(agent);

        let method = method_of(index);
        let target = RequestTarget::new(method.as_str(), &path).map_err(fail)?;
        let stamp = SignifyTimestamp::at(clock.wall_clock()).map_err(fail)?;

        let mut headers = Headers::new();
        headers
            .insert(
                HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME).map_err(fail)?,
                HeaderValue::new(RESOURCE).map_err(fail)?,
            )
            .map_err(fail)?;
        headers
            .insert(
                HeaderName::new(SIGNIFY_TIMESTAMP_HEADER_NAME).map_err(fail)?,
                stamp.to_header_value().map_err(fail)?,
            )
            .map_err(fail)?;
        let input = agent_signer
            .signature_input(default_components().map_err(fail)?, stamp.created())
            .map_err(fail)?;
        agent_signer
            .sign(&input, &target, &headers)
            .map_err(fail)?
            .apply(&mut headers)
            .map_err(fail)?;

        let authenticator = ResponseAuthenticator::new(
            ResponseVerifier::new(key),
            HeaderValue::new(RESOURCE).map_err(fail)?,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        // Untouched, it authenticates and reports the very `created` it was signed with.
        let covered = authenticator.authenticate(&target, &headers).map_err(fail)?;
        prop_assert_eq!(covered.created(), stamp.created());

        // Each tampering breaks exactly one thing the signature covers.
        let broken = match tamper {
            0 => {
                let elsewhere = RequestTarget::new(method.as_str(), &format!("{path}/x")).map_err(fail)?;
                authenticator.authenticate(&elsewhere, &headers)
            }
            1 => {
                let other = method_of(index + 1);
                prop_assume!(other != method);
                let swapped = RequestTarget::new(other.as_str(), &path).map_err(fail)?;
                authenticator.authenticate(&swapped, &headers)
            }
            2 => {
                let mut changed = Headers::new();
                for (name, value) in &headers {
                    let value = if name.matches(SIGNIFY_TIMESTAMP_HEADER_NAME) {
                        HeaderValue::new("2020-01-01T00:00:00.000000+00:00").map_err(fail)?
                    } else {
                        value.clone()
                    };
                    changed.insert(name.clone(), value).map_err(fail)?;
                }
                authenticator.authenticate(&target, &changed)
            }
            _ => {
                let mut without = Headers::new();
                for (name, value) in &headers {
                    if !name.matches("Signature") {
                        without.insert(name.clone(), value.clone()).map_err(fail)?;
                    }
                }
                authenticator.authenticate(&target, &without)
            }
        };
        prop_assert!(
            matches!(broken, Err(ResponseAuthenticationError::Signature { .. })),
            "tampering {tamper} was accepted",
        );
    }

    /// A response that names another resource is refused before any signature is checked.
    #[test]
    fn an_unexpected_resource_is_refused_first(claimed in "[A-Za-z0-9_-]{1,44}") {
        let clock = Arc::new(TestClock::new());
        let authenticator = ResponseAuthenticator::new(
            ResponseVerifier::new(
                Signer::generate(KeyTransferability::NonTransferable)
                    .map_err(fail)?
                    .verifier()
                    .clone(),
            ),
            HeaderValue::new(RESOURCE).map_err(fail)?,
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        let target = RequestTarget::new("GET", "/identifiers").map_err(fail)?;

        let mut headers = Headers::new();
        headers
            .insert(
                HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME).map_err(fail)?,
                HeaderValue::new(&claimed).map_err(fail)?,
            )
            .map_err(fail)?;

        // No signature headers at all, yet the resource is what is reported: the check runs first,
        // exactly as the reference orders it.
        let outcome = authenticator.authenticate(&target, &headers);
        let reported_signature = matches!(outcome, Err(ResponseAuthenticationError::Signature { .. }));
        let reported_resource = matches!(outcome, Err(ResponseAuthenticationError::UnexpectedResource { .. }));
        if claimed == RESOURCE {
            prop_assert!(reported_signature, "the expected resource was reported as unexpected");
        } else {
            prop_assert!(reported_resource, "a foreign resource reached the signature check");
        }
    }
}
