//! Invariants of the transport boundary.

mod support;

use crate::support::{block_on, fail, method_of};
use proptest::prelude::*;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::transport::{
    DEFAULT_RESPONSE_BODY_LIMIT, MAX_REQUEST_BODY_BYTES, MAX_RESPONSE_BODY_LIMIT, MAX_URL_BYTES, Method, Request,
    RequestUrl, Response, ScriptedTransport, StatusCode, Transport, TransportError,
};

proptest! {
    /// An accepted URL is returned exactly as given, and its parts recompose into it.
    #[test]
    fn urls_are_preserved_and_decompose(
        authority in "[a-zA-Z0-9.-]{1,24}(:[0-9]{1,5})?",
        path in "(/[A-Za-z0-9._~%!$&'()*+,;=:@-]{0,16}){0,4}",
        query in proptest::option::of("[A-Za-z0-9._~%!$&'()*+,;=:@/?-]{0,32}"),
        secure in any::<bool>(),
    ) {
        let scheme = if secure { "https" } else { "http" };
        let text = match &query {
            Some(query) => format!("{scheme}://{authority}{path}?{query}"),
            None => format!("{scheme}://{authority}{path}"),
        };
        prop_assume!(text.len() <= MAX_URL_BYTES);

        let url = RequestUrl::new(text.clone()).map_err(fail)?;
        prop_assert_eq!(url.as_str(), text.as_str());
        prop_assert_eq!(url.scheme(), scheme);
        prop_assert_eq!(url.authority(), authority.as_str());
        prop_assert_eq!(url.query(), query.as_deref());
        // The path is what a signature covers: never the query, and never empty.
        prop_assert!(!url.path().is_empty());
        prop_assert!(!url.path().contains('?'));
        if path.is_empty() {
            prop_assert_eq!(url.path(), "/");
        } else {
            prop_assert_eq!(url.path(), path.as_str());
        }
        // Nothing is rewritten: the recorded parts rebuild the original text.
        let rebuilt = match url.query() {
            Some(query) => format!("{}://{}{}?{}", url.scheme(), url.authority(), if path.is_empty() { "" } else { url.path() }, query),
            None => format!("{}://{}{}", url.scheme(), url.authority(), if path.is_empty() { "" } else { url.path() }),
        };
        prop_assert_eq!(rebuilt, text);
    }

    /// A URL holding a byte outside visible ASCII is always refused, whatever else it is.
    #[test]
    fn urls_with_forbidden_bytes_are_refused(
        prefix in "[a-z]{0,8}",
        suffix in "[a-z]{0,8}",
        forbidden in prop::sample::select(vec![' ', '\t', '\n', '\r', '\u{0}', '#', 'ñ']),
    ) {
        let text = format!("https://keria.example/{prefix}{forbidden}{suffix}");
        prop_assert!(RequestUrl::new(text).is_err());
    }

    /// A request carries what it was given, takes the default limit unless one is set, and never
    /// confuses an absent body with an empty one.
    #[test]
    fn requests_carry_what_they_were_given(
        method_index in 0_usize..4,
        header_count in 0_usize..6,
        body in proptest::option::of(prop::collection::vec(any::<u8>(), 0..256)),
        limit in proptest::option::of(0_usize..MAX_RESPONSE_BODY_LIMIT),
    ) {
        let method = method_of(method_index);
        let url = RequestUrl::new("https://keria.example/identifiers").map_err(fail)?;
        let mut builder = Request::builder(method, url.clone());
        if let Some(limit) = limit {
            builder = builder.response_limit(limit);
        }
        let mut expected = Vec::new();
        for index in 0..header_count {
            let name = format!("X-Header-{index}");
            let value = format!("value-{index}");
            builder = builder.header(
                HeaderName::new(name.clone()).map_err(fail)?,
                HeaderValue::new(value.clone()).map_err(fail)?,
            );
            expected.push((name, value));
        }
        if let Some(body) = &body {
            builder = builder.body(body.clone());
        }
        let request = builder.build().map_err(fail)?;

        prop_assert_eq!(request.method(), method);
        prop_assert_eq!(request.url().as_str(), url.as_str());
        prop_assert_eq!(request.response_limit(), limit.unwrap_or(DEFAULT_RESPONSE_BODY_LIMIT));
        prop_assert_eq!(request.body().map(<[u8]>::to_vec), body);
        prop_assert_eq!(request.headers().len(), header_count);
        for (name, value) in &expected {
            prop_assert_eq!(request.headers().get(name), Some(value.as_str()));
        }
        // Insertion order is preserved, because a signature covers the order it saw.
        let names: Vec<&str> = request.headers().iter().map(|(name, _)| name.as_str()).collect();
        let wanted: Vec<&str> = expected.iter().map(|(name, _)| name.as_str()).collect();
        prop_assert_eq!(names, wanted);
    }

    /// A body at or under the bound is accepted and one past it is refused, on both sides.
    #[test]
    fn body_bounds_hold_exactly(over in 0_usize..64) {
        let url = RequestUrl::new("https://keria.example/a").map_err(fail)?;
        let accepted = Request::builder(Method::Post, url.clone())
            .body(vec![0_u8; MAX_REQUEST_BODY_BYTES.saturating_sub(over)])
            .build();
        prop_assert!(accepted.is_ok());

        let refused = Request::builder(Method::Post, url.clone())
            .body(vec![0_u8; MAX_REQUEST_BODY_BYTES.saturating_add(over).saturating_add(1)])
            .build();
        let is_too_large = matches!(refused, Err(TransportError::RequestBodyTooLarge { .. }));
        prop_assert!(is_too_large);

        let limit_refused = Request::builder(Method::Get, url)
            .response_limit(MAX_RESPONSE_BODY_LIMIT.saturating_add(over).saturating_add(1))
            .build();
        let limit_too_large = matches!(limit_refused, Err(TransportError::ResponseLimitTooLarge { .. }));
        prop_assert!(limit_too_large);
    }

    /// A status is accepted exactly inside the range HTTP defines, and lands in one class.
    #[test]
    fn statuses_are_ranged_and_classified(code in 0_u16..1_000) {
        match StatusCode::new(code) {
            Ok(status) => {
                prop_assert!((100..=599).contains(&code));
                prop_assert_eq!(status.as_u16(), code);
                prop_assert_eq!(classes_of(status), expected_classes(code));
            }
            Err(error) => {
                prop_assert!(!(100..=599).contains(&code));
                let is_invalid = matches!(error, TransportError::InvalidStatus { .. });
                prop_assert!(is_invalid);
            }
        }
    }

    /// A response is served when it fits the request's limit and refused when it does not, and
    /// the boundary is exact.
    #[test]
    fn the_response_limit_is_enforced_exactly(size in 0_usize..512, limit in 0_usize..512) {
        let transport = ScriptedTransport::new().respond(
            Response::new(
                StatusCode::new(200).map_err(fail)?,
                Headers::new(),
                vec![7_u8; size],
            )
            .map_err(fail)?,
        );
        let request = Request::builder(
            Method::Get,
            RequestUrl::new("https://keria.example/a").map_err(fail)?,
        )
        .response_limit(limit)
        .build()
        .map_err(fail)?;

        match block_on(transport.execute(request)) {
            Ok(response) => {
                prop_assert!(size <= limit);
                prop_assert_eq!(response.body().len(), size);
            }
            Err(error) => {
                prop_assert!(size > limit);
                let is_too_large = matches!(error, TransportError::ResponseBodyTooLarge { .. });
                prop_assert!(is_too_large);
            }
        }
    }

    /// The scripted transport answers in order, records every request it answered, and reports
    /// exhaustion rather than hanging.
    #[test]
    fn the_script_is_served_in_order(scripted in 0_usize..6, issued in 0_usize..8) {
        let transport = ScriptedTransport::new();
        for index in 0..scripted {
            transport.push_response(
                Response::new(
                    StatusCode::new(200).map_err(fail)?,
                    Headers::new(),
                    vec![u8::try_from(index % 256).unwrap_or_default()],
                )
                .map_err(fail)?,
            );
        }
        prop_assert_eq!(transport.remaining(), scripted);

        for index in 0..issued {
            let request = Request::builder(
                Method::Get,
                RequestUrl::new(format!("https://keria.example/{index}")).map_err(fail)?,
            )
            .build()
            .map_err(fail)?;
            match block_on(transport.execute(request)) {
                Ok(response) => {
                    prop_assert!(index < scripted);
                    let expected = u8::try_from(index % 256).unwrap_or_default();
                    prop_assert_eq!(response.body(), &[expected]);
                }
                Err(error) => {
                    prop_assert!(index >= scripted);
                    let is_exhausted = matches!(error, TransportError::ScriptExhausted { .. });
                    prop_assert!(is_exhausted);
                }
            }
        }

        prop_assert_eq!(transport.answered(), issued);
        prop_assert_eq!(transport.remaining(), scripted.saturating_sub(issued));
        let recorded = transport.recorded();
        prop_assert_eq!(recorded.len(), issued);
        for (index, request) in recorded.iter().enumerate() {
            let expected_path = format!("/{index}");
            prop_assert_eq!(request.url().path(), expected_path.as_str());
        }
    }

    /// Dropping a future without polling it consumes no answer and records no request.
    #[test]
    fn dropped_futures_do_nothing(dropped in 0_usize..5) {
        let transport = ScriptedTransport::new().respond(
            Response::new(StatusCode::new(200).map_err(fail)?, Headers::new(), b"kept".to_vec())
                .map_err(fail)?,
        );
        for index in 0..dropped {
            let request = Request::builder(
                Method::Get,
                RequestUrl::new(format!("https://keria.example/dropped-{index}")).map_err(fail)?,
            )
            .build()
            .map_err(fail)?;
            drop(transport.execute(request));
        }
        prop_assert_eq!(transport.answered(), 0);
        prop_assert_eq!(transport.remaining(), 1);

        let request = Request::builder(
            Method::Get,
            RequestUrl::new("https://keria.example/kept").map_err(fail)?,
        )
        .build()
        .map_err(fail)?;
        let response = block_on(transport.execute(request)).map_err(fail)?;
        prop_assert_eq!(response.body(), b"kept");
    }
}

/// `[success, redirection, client error, server error]`.
fn classes_of(status: StatusCode) -> [bool; 4] {
    [
        status.is_success(),
        status.is_redirection(),
        status.is_client_error(),
        status.is_server_error(),
    ]
}

/// The class HTTP assigns by hundreds; a 1xx code is in none of the four.
fn expected_classes(code: u16) -> [bool; 4] {
    match code / 100 {
        2 => [true, false, false, false],
        3 => [false, true, false, false],
        4 => [false, false, true, false],
        5 => [false, false, false, true],
        _ => [false; 4],
    }
}

#[test]
fn every_class_boundary_lands_in_its_class() -> Result<(), TransportError> {
    let cases = [
        (100, [false, false, false, false]),
        (199, [false, false, false, false]),
        (200, [true, false, false, false]),
        (299, [true, false, false, false]),
        (300, [false, true, false, false]),
        (399, [false, true, false, false]),
        (400, [false, false, true, false]),
        (499, [false, false, true, false]),
        (500, [false, false, false, true]),
        (599, [false, false, false, true]),
    ];
    for (code, expected) in cases {
        assert_eq!(classes_of(StatusCode::new(code)?), expected, "{code}");
    }
    Ok(())
}
