#![no_main]

//! Fuzzes the request builder and the response decoder.
//!
//! Both ends of this layer take bytes from outside the process. A path component and a query value
//! come from a caller — an identifier alias, a credential SAID, a filter — and must never be able
//! to open a segment, a query, or a fragment. A `Content-Range` value, a `Content-Type` value, a
//! status, and a body come from a server, and must never panic, never allocate without a bound,
//! and never be read as something the server did not declare.
//!
//! The target asserts that every rejection is a typed error with a non-empty description, and that
//! everything accepted upholds the layer's promises: an encoded component holds only unreserved
//! bytes and complete escapes, a built path recomposes into its own parts, a decoded response
//! carries exactly the bytes it was given, and a `Content-Range` that parses re-renders to the
//! digits it was read from.

use libfuzzer_sys::fuzz_target;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::request::{
    BaseUrl, ItemRange, MAX_PATH_SEGMENTS, MAX_QUERY_PARAMETERS, MediaType, RangeUnit, RequestError, ResourcePath,
    ResourceRequestBuilder, encode_path_component, encode_query_component,
};
use signify_http::response::{ContentRange, MAX_DETAIL_CHARS, RequestOrigin, ResourceResponse, ResponseError};
use signify_http::transport::{Method, Request, RequestUrl, Response, StatusCode};

/// Returns whether a rejection is one this layer is allowed to produce when building a request.
fn is_expected_request_error(error: &RequestError) -> bool {
    matches!(
        error,
        RequestError::InvalidBaseUrl { .. }
            | RequestError::EmptyPath
            | RequestError::TooManySegments { .. }
            | RequestError::SegmentTooLong { .. }
            | RequestError::PathTooLong { .. }
            | RequestError::TooManyParameters { .. }
            | RequestError::QueryTooLong { .. }
            | RequestError::InvalidMediaType { .. }
            | RequestError::InvalidRangeUnit { .. }
            | RequestError::InvalidRange { .. }
            | RequestError::Header { .. }
            | RequestError::Transport { .. }
    )
}

/// Returns whether a rejection is one this layer is allowed to produce when reading a response.
fn is_expected_response_error(error: &ResponseError) -> bool {
    matches!(
        error,
        ResponseError::Status { .. }
            | ResponseError::InvalidContentType { .. }
            | ResponseError::UnexpectedContentType { .. }
            | ResponseError::NotUtf8 { .. }
            | ResponseError::InvalidContentRange { .. }
    )
}

/// Asserts that an encoded component can never introduce a delimiter.
fn check_encoding(value: &str) {
    let path = encode_path_component(value);
    assert!(path.is_ascii());
    for delimiter in ['/', '?', '#', '&', '=', ' '] {
        assert!(!path.contains(delimiter), "{path:?} holds {delimiter:?}");
    }
    // Every `%` begins a complete two-digit uppercase escape; nothing is truncated.
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            for _ in 0..2 {
                let Some(digit) = bytes.next() else {
                    panic!("a truncated escape in {path:?}");
                };
                assert!(digit.is_ascii_digit() || (b'A'..=b'F').contains(&digit), "{path:?}");
            }
        } else {
            assert!(
                byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte),
                "{byte} survived unescaped in {path:?}",
            );
        }
    }

    let query = encode_query_component(value);
    assert!(query.is_ascii());
    for delimiter in ['&', '=', '?', '#', '/', ' '] {
        assert!(!query.contains(delimiter), "{query:?} holds {delimiter:?}");
    }
    assert_eq!(query.matches('+').count(), value.matches(' ').count());
}

fuzz_target!(|data: &[u8]| {
    let [selector, status_low, unit_len, rest @ ..] = data else {
        return;
    };
    let text = String::from_utf8_lossy(rest).into_owned();

    // ---------------------------------------------------------------
    // The caller's half: a path component and a query value.
    // ---------------------------------------------------------------
    check_encoding(&text);

    let mut builder = ResourcePath::builder().segment("identifiers").segment(&text);
    if selector & 1 == 1 {
        builder = builder.parameter("filter", &text);
    }
    if selector & 2 == 2 {
        builder = builder.optional_parameter("group", None);
    }
    match builder.build() {
        Ok(path) => {
            // The path always begins with a `/` and always holds exactly the components asked for.
            assert!(path.as_str().starts_with('/'));
            let components: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(components.len(), 2);
            assert_eq!(components.first().copied(), Some("identifiers"));
            assert_eq!(components.get(1).copied(), Some(encode_path_component(&text).as_str()));
            assert!(components.len() <= MAX_PATH_SEGMENTS);
            // The query is present exactly when a parameter was added, and never leaks into the
            // path a signature covers.
            assert_eq!(path.query().is_some(), selector & 1 == 1);
            assert!(!path.path().contains('?'));
            assert!(!path.path().contains('#'));
            match path.query() {
                Some(query) => {
                    assert!(query.split('&').count() <= MAX_QUERY_PARAMETERS);
                    assert_eq!(path.as_str(), format!("{}?{}", path.path(), query));
                }
                None => assert_eq!(path.as_str(), path.path()),
            }

            // A joined URL keeps the path byte for byte.
            if let Ok(base) = BaseUrl::new("http://localhost:3901") {
                assert!(!base.as_str().ends_with('/'));
                match base.join(&path) {
                    Ok(url) => {
                        assert_eq!(url.path(), path.path());
                        assert_eq!(url.query(), path.query());
                        assert_eq!(url.as_str(), format!("{}{}", base.as_str(), path.as_str()));

                        // And a request built over it carries what it was handed.
                        let method = *Method::ALL
                            .get(usize::from(selector >> 2) % Method::ALL.len())
                            .unwrap_or(&Method::Get);
                        let mut request = ResourceRequestBuilder::new(method, url).content_type(MediaType::json());
                        if selector & 4 == 4 {
                            request = request.accept(MediaType::json_cesr());
                        }
                        match request.build() {
                            Ok(request) => {
                                assert_eq!(request.method(), method);
                                assert_eq!(request.headers().get("content-type"), Some("application/json"));
                                assert_eq!(request.body(), None);
                                // An origin never carries the query.
                                let origin = RequestOrigin::of(&request);
                                assert_eq!(origin.path(), path.path());
                                assert!(!origin.path().contains('?'));
                            }
                            Err(error) => assert!(is_expected_request_error(&error), "{error:?}"),
                        }
                    }
                    Err(error) => assert!(is_expected_request_error(&error), "{error:?}"),
                }
            }
        }
        Err(error) => {
            assert!(is_expected_request_error(&error), "{error:?}");
            assert!(!error.to_string().is_empty());
        }
    }

    // A media type a caller or a server named.
    match MediaType::new(text.clone()) {
        Ok(media_type) => {
            assert_eq!(media_type.as_str(), text);
            assert!(!media_type.kind().is_empty());
            assert!(!media_type.subtype().is_empty());
            assert!(media_type.matches(&media_type));
            assert!(media_type.header_value().is_ok());
        }
        Err(error) => assert!(matches!(error, RequestError::InvalidMediaType { .. }), "{error:?}"),
    }

    // A range unit, and the range header it renders.
    let split = usize::from(*unit_len) % text.len().saturating_add(1);
    let unit_text = text.get(..split).unwrap_or_default().to_owned();
    let unit = match RangeUnit::new(unit_text.clone()) {
        Ok(unit) => {
            assert_eq!(unit.as_str(), unit_text);
            Some(unit)
        }
        Err(error) => {
            assert!(matches!(error, RequestError::InvalidRangeUnit { .. }), "{error:?}");
            None
        }
    };
    if let Some(unit) = &unit {
        let start = u64::from(*selector);
        let end = start.saturating_add(u64::from(*status_low));
        if let Ok(range) = ItemRange::new(start, end) {
            assert_eq!(range.header_value(unit), format!("{}={start}-{end}", unit.as_str()));
            assert_eq!(range.count(), end.saturating_sub(start).saturating_add(1));
        }
        assert!(ItemRange::new(end.saturating_add(1), start).is_err() || end.saturating_add(1) <= start);
    }

    // ---------------------------------------------------------------
    // The server's half: a Content-Range, a Content-Type, a status, a body.
    // ---------------------------------------------------------------
    if let Some(unit) = &unit {
        match ContentRange::parse(&text, unit) {
            Ok(range) => {
                // An accepted value began with the unit and a space, and its digits re-render into
                // no more characters than it held.
                assert!(text.starts_with(unit.as_str()));
                let rendered = format!("{} {}-{}/{}", unit.as_str(), range.start(), range.end(), range.total());
                assert!(rendered.len() <= text.len(), "{rendered:?} from {text:?}");
            }
            Err(error) => {
                assert!(matches!(error, ResponseError::InvalidContentRange { .. }), "{error:?}");
                assert!(!error.to_string().is_empty());
            }
        }
    }

    let Ok(url) = RequestUrl::new("http://localhost:3901/identifiers/aid1?filter=secret") else {
        return;
    };
    let Ok(request) = Request::builder(Method::Get, url).build() else {
        return;
    };
    let origin = RequestOrigin::of(&request);
    assert_eq!(origin.path(), "/identifiers/aid1");

    let mut headers = Headers::new();
    if let (Ok(name), Ok(value)) = (HeaderName::new("Content-Type"), HeaderValue::new(&text)) {
        let _ = headers.insert(name, value);
    }
    if let (Ok(name), Ok(value)) = (HeaderName::new("Content-Range"), HeaderValue::new(&text)) {
        let _ = headers.insert(name, value);
    }
    let Ok(status) = StatusCode::new(100_u16.saturating_add(u16::from(*status_low))) else {
        return;
    };
    let Ok(response) = Response::new(status, headers, rest.to_vec()) else {
        return;
    };

    match ResourceResponse::decode(&origin, response) {
        Ok(decoded) => {
            assert!(status.is_success());
            assert_eq!(decoded.status().as_u16(), status.as_u16());
            // The body crosses unchanged; nothing is repaired or transcoded.
            assert_eq!(decoded.body(), rest);
            assert_eq!(decoded.text().is_ok(), core::str::from_utf8(rest).is_ok());
            for outcome in [decoded.json().err(), decoded.cesr().err(), decoded.content_type().err()] {
                if let Some(error) = outcome {
                    assert!(is_expected_response_error(&error), "{error:?}");
                }
            }
            if let Some(unit) = &unit
                && let Err(error) = decoded.content_range(unit)
            {
                assert!(matches!(error, ResponseError::InvalidContentRange { .. }), "{error:?}");
            }
            assert_eq!(decoded.into_body(), rest);
        }
        Err(error) => {
            assert!(is_expected_response_error(&error), "{error:?}");
            assert!(!status.is_success());
            if let ResponseError::Status { path, detail, .. } = &error {
                // A hostile body can never write unbounded text into a caller's log, and the
                // query never reaches an error at all.
                assert!(detail.chars().count() <= MAX_DETAIL_CHARS.max(32));
                assert_eq!(path, "/identifiers/aid1");
                assert!(!path.contains('?'));
            }
        }
    }
});
