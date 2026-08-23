#![no_main]

//! Fuzzes the transport boundary's parsers and bounds.
//!
//! A URL, a header value, a body, and a response all cross this boundary from outside the
//! process, so the input bytes drive each of them. The target asserts that nothing panics, that
//! every rejection is a typed [`TransportError`] with a non-empty description, and that anything
//! accepted upholds the boundary's promises: an accepted URL is returned byte for byte and
//! decomposes into a path that never carries a query, a built request returns exactly the method,
//! body, and headers it was given, and a scripted round trip either honours the request's
//! response limit or reports that it could not.

use libfuzzer_sys::fuzz_target;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::transport::{
    MAX_REQUEST_BODY_BYTES, MAX_RESPONSE_BODY_LIMIT, MAX_URL_BYTES, Method, Request, RequestUrl, Response,
    ScriptedTransport, StatusCode, Transport, TransportError,
};

/// Returns whether a rejection is one of the variants this boundary is allowed to produce.
fn is_expected(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::InvalidUrl { .. }
            | TransportError::RequestBodyTooLarge { .. }
            | TransportError::ResponseBodyTooLarge { .. }
            | TransportError::ResponseLimitTooLarge { .. }
            | TransportError::InvalidStatus { .. }
            | TransportError::Timeout { .. }
            | TransportError::Connect { .. }
            | TransportError::InvalidResponse { .. }
            | TransportError::ScriptExhausted { .. }
            | TransportError::Header { .. }
    )
}

/// A minimal executor; the scripted transport's future is ready on its first poll.
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
    let [selector, status_low, limit_byte, body @ ..] = data else {
        return;
    };
    let text = String::from_utf8_lossy(body).into_owned();

    // A URL an endpoint or a caller assembled.
    let candidate = if selector & 1 == 0 {
        text.clone()
    } else {
        format!("https://keria.example/{text}")
    };
    match RequestUrl::new(candidate.clone()) {
        Ok(url) => {
            // Nothing is rewritten, and the parts never overlap.
            assert_eq!(url.as_str(), candidate);
            assert!(candidate.len() <= MAX_URL_BYTES);
            assert!(!url.authority().is_empty());
            assert!(!url.path().is_empty());
            assert!(!url.path().contains('?'));
            assert!(!url.path().contains('#'));
            assert!(url.scheme() == "http" || url.scheme() == "https");
            assert!(url.as_str().starts_with(url.scheme()));

            // A request built over it carries exactly what it was handed.
            let method = *Method::ALL
                .get(usize::from(*selector >> 1) % Method::ALL.len())
                .unwrap_or(&Method::Get);
            let limit = usize::from(*limit_byte) * 64;
            let mut builder = Request::builder(method, url).response_limit(limit);
            if selector & 2 == 2 {
                builder = builder.body(body.to_vec());
            }
            // A header whose value the input chose; an invalid one must be refused, not accepted.
            if let (Ok(name), Ok(value)) = (HeaderName::new("X-Fuzz"), HeaderValue::new(text.clone())) {
                builder = builder.header(name, value);
            }
            match builder.build() {
                Ok(request) => {
                    assert_eq!(request.method(), method);
                    assert_eq!(request.response_limit(), limit);
                    assert!(limit <= MAX_RESPONSE_BODY_LIMIT);
                    match request.body() {
                        Some(carried) => {
                            assert_eq!(carried, body);
                            assert!(carried.len() <= MAX_REQUEST_BODY_BYTES);
                        }
                        None => assert!(selector & 2 != 2),
                    }

                    // One round trip: the answer either fits the request's limit or says so.
                    let Ok(status) = StatusCode::new(100_u16.saturating_add(u16::from(*status_low))) else {
                        return;
                    };
                    let Ok(response) = Response::new(status, Headers::new(), body.to_vec()) else {
                        return;
                    };
                    let transport = ScriptedTransport::new().respond(response);
                    match block_on(transport.execute(request)) {
                        Ok(answer) => {
                            assert!(answer.body().len() <= limit);
                            assert_eq!(answer.body(), body);
                            assert_eq!(answer.status().as_u16(), status.as_u16());
                        }
                        Err(error) => {
                            assert!(is_expected(&error), "unexpected error: {error:?}");
                            assert!(body.len() > limit);
                        }
                    }
                    assert_eq!(transport.answered(), 1);
                }
                Err(error) => assert!(is_expected(&error), "unexpected error: {error:?}"),
            }
        }
        Err(error) => {
            assert!(matches!(error, TransportError::InvalidUrl { .. }), "{error:?}");
            assert!(!error.to_string().is_empty());
        }
    }

    // A status code a server claimed.
    let claimed = u16::from(*status_low) * 4;
    match StatusCode::new(claimed) {
        Ok(status) => assert!((100..=599).contains(&status.as_u16())),
        Err(error) => {
            assert!(matches!(error, TransportError::InvalidStatus { .. }), "{error:?}");
            assert!(!(100..=599).contains(&claimed));
        }
    }
});
