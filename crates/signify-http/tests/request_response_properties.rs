//! Invariants of the request builder and the response decoder.
//!
//! The generators deliberately include the near-misses that matter here: a path component holding
//! the delimiters it must never introduce, a `Content-Range` differing from a well-formed one by a
//! single character, and a body that is not UTF-8.

use proptest::prelude::*;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::request::{
    BaseUrl, ItemRange, MAX_PATH_SEGMENTS, MAX_QUERY_PARAMETERS, MediaType, RangeUnit, RequestError, ResourcePath,
    ResourceRequestBuilder, encode_path_component, encode_query_component,
};
use signify_http::response::{ContentRange, MAX_DETAIL_CHARS, RequestOrigin, ResourceResponse, ResponseError};
use signify_http::transport::{Method, Request, RequestUrl, Response, StatusCode};

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn method_of(index: usize) -> Method {
    *Method::ALL.get(index % Method::ALL.len()).unwrap_or(&Method::Get)
}

/// Builds one response for a request whose URL carries a query.
fn decode(status: u16, content_type: Option<&str>, body: Vec<u8>) -> Result<ResourceResponse, ResponseError> {
    let Ok(url) = RequestUrl::new("http://localhost:3901/identifiers/aid1?filter=secret") else {
        return Err(ResponseError::NotUtf8 { offset: 0 });
    };
    let Ok(request) = Request::builder(Method::Get, url).build() else {
        return Err(ResponseError::NotUtf8 { offset: 0 });
    };
    let mut headers = Headers::new();
    if let Some(value) = content_type
        && let (Ok(name), Ok(value)) = (HeaderName::new("Content-Type"), HeaderValue::new(value))
    {
        let _ = headers.insert(name, value);
    }
    let Ok(status) = StatusCode::new(status) else {
        return Err(ResponseError::NotUtf8 { offset: 0 });
    };
    let Ok(response) = Response::new(status, headers, body) else {
        return Err(ResponseError::NotUtf8 { offset: 0 });
    };
    ResourceResponse::decode(&RequestOrigin::of(&request), response)
}

proptest! {
    /// An encoded path component can never introduce a delimiter, whatever it holds.
    #[test]
    fn a_path_component_can_never_open_a_segment_or_a_query(value in ".{0,64}") {
        let encoded = encode_path_component(&value);
        for delimiter in ['/', '?', '#', '&', '=', ' ', '%'] {
            if delimiter == '%' {
                continue;
            }
            prop_assert!(!encoded.contains(delimiter), "{encoded:?} holds {delimiter:?}");
        }
        // Every byte is either unreserved or the start of a two-digit uppercase escape.
        prop_assert!(encoded.is_ascii());
        let mut bytes = encoded.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                for _ in 0..2 {
                    let digit = bytes.next().ok_or_else(|| TestCaseError::fail("a truncated escape"))?;
                    prop_assert!(digit.is_ascii_digit() || (b'A'..=b'F').contains(&digit), "{digit}");
                }
            } else {
                prop_assert!(
                    byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte),
                    "{byte} survived unescaped",
                );
            }
        }
        // Encoding is a function of the bytes, and encoding twice is not the same as encoding once
        // unless nothing needed escaping — which is exactly the reference's behaviour.
        prop_assert_eq!(encode_path_component(&value), encoded.clone());
        if encoded == value {
            prop_assert_eq!(encode_path_component(&encoded), encoded);
        }
    }

    /// An encoded query component can never introduce a separator either.
    #[test]
    fn a_query_component_can_never_open_a_parameter(value in ".{0,64}") {
        let encoded = encode_query_component(&value);
        for delimiter in ['&', '=', '?', '#', '/', ' '] {
            prop_assert!(!encoded.contains(delimiter), "{encoded:?} holds {delimiter:?}");
        }
        // A space is the one byte with a shorthand, and it is the only source of a `+`.
        prop_assert_eq!(encoded.matches('+').count(), value.matches(' ').count());
    }

    /// A path recomposes from its own parts, and its components survive exactly.
    #[test]
    fn a_path_round_trips_through_its_parts(
        segments in proptest::collection::vec(".{0,16}", 1..6),
        parameters in proptest::collection::vec((".{0,8}", ".{0,8}"), 0..5),
    ) {
        let mut builder = ResourcePath::builder();
        for segment in &segments {
            builder = builder.segment(segment);
        }
        for (name, value) in &parameters {
            builder = builder.parameter(name, value);
        }
        let path = builder.build().map_err(fail)?;

        // The path holds exactly one `/` per component, and the components are the encoded ones.
        // Splitting rather than trimming matters: an empty component is a real component, and
        // `/identifiers//x` has three of them.
        let components: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(components.len(), segments.len());
        for (component, segment) in components.iter().zip(&segments) {
            prop_assert_eq!(*component, encode_path_component(segment));
        }
        // A component is a dot segment only when the caller's own value was exactly that: `.` is
        // unreserved, so `encodeURIComponent` leaves it alone and so does this crate. What a
        // component can never do is *introduce* one, which is the reference's actual defect —
        // `operations().get("../identifiers")` becomes two components there and one here.
        for (component, segment) in components.iter().zip(&segments) {
            if *component == "." || *component == ".." {
                prop_assert_eq!(component, segment);
            }
        }

        match path.query() {
            None => {
                prop_assert!(parameters.is_empty());
                prop_assert_eq!(path.as_str(), path.path());
                prop_assert!(!path.as_str().contains('?'));
            }
            Some(query) => {
                prop_assert!(!parameters.is_empty());
                let pairs: Vec<&str> = query.split('&').collect();
                prop_assert_eq!(pairs.len(), parameters.len());
                for (pair, (name, value)) in pairs.iter().zip(&parameters) {
                    let (encoded_name, encoded_value) = pair
                        .split_once('=')
                        .ok_or_else(|| TestCaseError::fail("a parameter without a separator"))?;
                    prop_assert_eq!(encoded_name, encode_query_component(name));
                    prop_assert_eq!(encoded_value, encode_query_component(value));
                }
                prop_assert_eq!(path.as_str(), format!("{}?{}", path.path(), query));
            }
        }
        prop_assert_eq!(path.as_str(), path.to_string());
    }

    /// A joined URL carries the path's own parts, unrewritten.
    #[test]
    fn joining_preserves_the_path_and_query(
        authority in "[a-z0-9.-]{1,20}(:[0-9]{1,5})?",
        segments in proptest::collection::vec("[A-Za-z0-9 ñ/?#-]{0,12}", 1..5),
        parameters in proptest::collection::vec(("[a-z_]{1,8}", "[A-Za-z0-9 &=/-]{0,12}"), 0..4),
        secure in any::<bool>(),
        trailing in any::<bool>(),
    ) {
        let scheme = if secure { "https" } else { "http" };
        let slash = if trailing { "/" } else { "" };
        let base = BaseUrl::new(format!("{scheme}://{authority}{slash}")).map_err(fail)?;
        prop_assert!(!base.as_str().ends_with('/'));

        let mut builder = ResourcePath::builder();
        for segment in &segments {
            builder = builder.segment(segment);
        }
        for (name, value) in &parameters {
            builder = builder.parameter(name, value);
        }
        let path = builder.build().map_err(fail)?;

        let url = base.join(&path).map_err(fail)?;
        prop_assert_eq!(url.as_str(), format!("{}{}", base.as_str(), path.as_str()));
        prop_assert_eq!(url.path(), path.path());
        prop_assert_eq!(url.query(), path.query());
        prop_assert_eq!(url.scheme(), scheme);
        prop_assert_eq!(url.authority(), authority.as_str());
    }

    /// A path is bounded in every dimension, and the bounds are the published ones.
    #[test]
    fn a_path_is_always_bounded(
        segments in proptest::collection::vec("[a-z]{0,4}", 0..(MAX_PATH_SEGMENTS + 4)),
        parameters in proptest::collection::vec(("[a-z]{1,4}", "[a-z]{0,4}"), 0..(MAX_QUERY_PARAMETERS + 4)),
    ) {
        let mut builder = ResourcePath::builder();
        for segment in &segments {
            builder = builder.segment(segment);
        }
        for (name, value) in &parameters {
            builder = builder.parameter(name, value);
        }
        match builder.build() {
            Ok(path) => {
                prop_assert!(!segments.is_empty());
                prop_assert!(segments.len() <= MAX_PATH_SEGMENTS);
                prop_assert!(parameters.len() <= MAX_QUERY_PARAMETERS);
                prop_assert!(path.as_str().starts_with('/'));
            }
            Err(RequestError::EmptyPath) => prop_assert!(segments.is_empty()),
            Err(RequestError::TooManySegments { .. }) => prop_assert!(segments.len() > MAX_PATH_SEGMENTS),
            Err(RequestError::TooManyParameters { .. }) => {
                prop_assert!(parameters.len() > MAX_QUERY_PARAMETERS);
            }
            Err(other) => return Err(fail(other)),
        }
    }

    /// A media type is preserved as written, and compares by essence alone.
    #[test]
    fn media_types_round_trip_and_compare_by_essence(
        kind in "[a-zA-Z][a-zA-Z0-9!#$%&'*+.^_`|~-]{0,12}",
        subtype in "[a-zA-Z][a-zA-Z0-9!#$%&'*+.^_`|~-]{0,12}",
        parameter in proptest::option::of("[a-z]{1,6}=[a-z0-9]{1,6}"),
    ) {
        let text = match &parameter {
            Some(parameter) => format!("{kind}/{subtype};{parameter}"),
            None => format!("{kind}/{subtype}"),
        };
        let media_type = MediaType::new(text.clone()).map_err(fail)?;
        prop_assert_eq!(media_type.as_str(), text.as_str());
        prop_assert_eq!(media_type.to_string(), text.as_str());
        prop_assert_eq!(media_type.kind(), kind.as_str());
        prop_assert_eq!(media_type.subtype(), subtype.as_str());
        prop_assert_eq!(media_type.essence(), format!("{kind}/{subtype}"));

        // Re-parsing the rendered form yields the same value.
        let again = MediaType::new(media_type.as_str()).map_err(fail)?;
        prop_assert_eq!(&again, &media_type);

        // Comparison ignores case and parameters, and is reflexive and symmetric.
        let upper = MediaType::new(format!("{}/{}", kind.to_uppercase(), subtype.to_uppercase()))
            .map_err(fail)?;
        prop_assert!(media_type.matches(&media_type));
        prop_assert!(media_type.matches(&upper));
        prop_assert!(upper.matches(&media_type));
        let rendered = media_type.header_value().map_err(fail)?;
        prop_assert_eq!(rendered.as_str(), text.as_str());
    }

    /// A request carries the derived headers first, then the caller's, and its own body.
    #[test]
    fn a_request_carries_its_derived_headers_in_order(
        index in 0_usize..8,
        with_body in any::<bool>(),
        with_accept in any::<bool>(),
        with_range in any::<bool>(),
        start in 0_u64..1_000,
        span in 0_u64..1_000,
    ) {
        let base = BaseUrl::new("http://localhost:3901").map_err(fail)?;
        let url = base
            .join(&ResourcePath::builder().segment("identifiers").build().map_err(fail)?)
            .map_err(fail)?;

        let mut builder = ResourceRequestBuilder::new(method_of(index), url);
        let mut expected = Vec::new();
        if with_body {
            builder = builder.json_body(b"{}".to_vec());
            expected.push("Content-Type");
        }
        if with_accept {
            builder = builder.accept(MediaType::json_cesr());
            expected.push("Accept");
        }
        if with_range {
            let range = ItemRange::new(start, start.saturating_add(span)).map_err(fail)?;
            builder = builder.range(&RangeUnit::new("aids").map_err(fail)?, range);
            expected.push("Range");
        }
        let request = builder
            .header(
                HeaderName::new("X-Extra").map_err(fail)?,
                HeaderValue::new("1").map_err(fail)?,
            )
            .build()
            .map_err(fail)?;
        expected.push("X-Extra");

        let names: Vec<&str> = request.headers().iter().map(|(name, _)| name.as_str()).collect();
        prop_assert_eq!(names, expected);
        prop_assert_eq!(request.method(), method_of(index));
        prop_assert_eq!(request.body().is_some(), with_body);
        if with_range {
            let value = request.headers().get("range").unwrap_or_default();
            prop_assert_eq!(value, format!("aids={}-{}", start, start.saturating_add(span)));
        }
    }

    /// A range is accepted exactly when it is ordered, and renders its own header.
    #[test]
    fn ranges_are_ordered_and_render_themselves(start in any::<u64>(), end in any::<u64>()) {
        let unit = RangeUnit::new("aids").map_err(fail)?;
        match ItemRange::new(start, end) {
            Ok(range) => {
                prop_assert!(start <= end);
                prop_assert_eq!(range.start(), start);
                prop_assert_eq!(range.end(), end);
                prop_assert_eq!(range.header_value(&unit), format!("aids={start}-{end}"));
                // A rendered range parses back as a content range over the same numbers.
                let content = format!("aids {start}-{end}/{end}");
                let parsed = ContentRange::parse(&content, &unit).map_err(fail)?;
                prop_assert_eq!(parsed.start(), start);
                prop_assert_eq!(parsed.end(), end);
            }
            Err(RequestError::InvalidRange { .. }) => prop_assert!(end < start),
            Err(other) => return Err(fail(other)),
        }
    }

    /// A well-formed content range round trips; a near-miss is refused rather than guessed at.
    #[test]
    fn content_ranges_round_trip_and_near_misses_are_refused(
        start in any::<u64>(),
        end in any::<u64>(),
        total in any::<u64>(),
        corruption in 0_usize..8,
    ) {
        let unit = RangeUnit::new("aids").map_err(fail)?;
        let well_formed = format!("aids {start}-{end}/{total}");
        let parsed = ContentRange::parse(&well_formed, &unit).map_err(fail)?;
        prop_assert_eq!((parsed.start(), parsed.end(), parsed.total()), (start, end, total));

        // Each corruption is one character away from the value above; the reference reads a
        // number or a NaN from every one of them.
        let corrupted = match corruption {
            0 => format!("aids  {start}-{end}/{total}"),
            1 => format!("aids {start}-{end}/{total} "),
            2 => format!("aids {start}-{end}/+{total}"),
            3 => format!("aids 0x{start}-{end}/{total}"),
            4 => format!("aids {start}.0-{end}/{total}"),
            5 => format!("Aids {start}-{end}/{total}"),
            6 => format!("aids{start}-{end}/{total}"),
            _ => format!("aids {start}-{end}/{total}/0"),
        };
        prop_assert!(
            matches!(
                ContentRange::parse(&corrupted, &unit),
                Err(ResponseError::InvalidContentRange { .. })
            ),
            "{corrupted:?} was accepted",
        );
    }

    /// Any input at all either parses into a canonical range or is refused, never panicking.
    #[test]
    fn arbitrary_content_ranges_never_panic(value in ".{0,64}", unit in "[a-z]{1,8}") {
        let unit = RangeUnit::new(unit).map_err(fail)?;
        match ContentRange::parse(&value, &unit) {
            Ok(range) => {
                // An accepted value re-renders to itself unless a position carried leading zeros.
                let rendered = format!(
                    "{} {}-{}/{}",
                    unit.as_str(),
                    range.start(),
                    range.end(),
                    range.total(),
                );
                prop_assert_eq!(rendered.len() <= value.len(), true);
                prop_assert!(value.starts_with(unit.as_str()));
            }
            Err(ResponseError::InvalidContentRange { value: rejected, reason }) => {
                prop_assert!(!reason.is_empty());
                prop_assert!(rejected.chars().count() <= 64);
            }
            Err(other) => return Err(fail(other)),
        }
    }

    /// A response decodes exactly when its status is a success, and a failure is always bounded.
    #[test]
    fn decoding_follows_the_status_and_bounds_its_detail(
        status in 100_u16..600,
        body in proptest::collection::vec(any::<u8>(), 0..2_048),
    ) {
        match decode(status, Some("application/json"), body.clone()) {
            Ok(decoded) => {
                prop_assert!((200..=299).contains(&status));
                prop_assert_eq!(decoded.status().as_u16(), status);
                prop_assert_eq!(decoded.body(), body.as_slice());
                prop_assert_eq!(decoded.json().map_err(fail)?, body.as_slice());
                // Text succeeds exactly when the body is UTF-8.
                prop_assert_eq!(decoded.text().is_ok(), core::str::from_utf8(&body).is_ok());
            }
            Err(ResponseError::Status { path, detail, status: reported, .. }) => {
                prop_assert!(!(200..=299).contains(&status));
                prop_assert_eq!(reported.as_u16(), status);
                // The query never reaches an error, and the detail is always bounded.
                prop_assert_eq!(path.as_str(), "/identifiers/aid1");
                prop_assert!(!path.contains('?'));
                prop_assert!(detail.chars().count() <= MAX_DETAIL_CHARS.max("<2048 bytes, not UTF-8>".len()));
                if core::str::from_utf8(&body).is_err() {
                    prop_assert!(detail.starts_with('<') && detail.ends_with("not UTF-8>"));
                }
            }
            Err(other) => return Err(fail(other)),
        }
    }

    /// A declared media type decides what a body may be read as, whatever the bytes hold.
    #[test]
    fn a_declaration_decides_what_a_body_may_be_read_as(
        subtype in "(json|json\\+cesr|plain|html)",
        body in "[ -~]{0,64}",
    ) {
        let declared = format!("application/{subtype}");
        let decoded = decode(200, Some(&declared), body.clone().into_bytes()).map_err(fail)?;
        // The bytes are always reachable as text; only the typed readers are gated.
        prop_assert_eq!(decoded.text().map_err(fail)?, body.as_str());
        prop_assert_eq!(decoded.json().is_ok(), subtype == "json");
        prop_assert_eq!(decoded.cesr().is_ok(), subtype == "json+cesr");

        // An absent declaration contradicts nothing, so both readers accept it.
        let undeclared = decode(200, None, body.clone().into_bytes()).map_err(fail)?;
        prop_assert!(undeclared.json().is_ok());
        prop_assert!(undeclared.cesr().is_ok());
        prop_assert_eq!(undeclared.content_type().map_err(fail)?.is_none(), true);
    }

    /// An origin never carries a query, whatever the request's URL held.
    #[test]
    fn an_origin_never_carries_a_query(
        path in "(/[A-Za-z0-9._~-]{0,12}){1,4}",
        query in proptest::option::of("[A-Za-z0-9=&_-]{0,24}"),
        index in 0_usize..8,
    ) {
        let text = match &query {
            Some(query) => format!("http://localhost:3901{path}?{query}"),
            None => format!("http://localhost:3901{path}"),
        };
        let url = RequestUrl::new(text).map_err(fail)?;
        let request = Request::builder(method_of(index), url).build().map_err(fail)?;
        let origin = RequestOrigin::of(&request);
        prop_assert_eq!(origin.method(), method_of(index));
        prop_assert_eq!(origin.path(), path.as_str());
        prop_assert!(!origin.path().contains('?'));
        prop_assert_eq!(origin.to_string(), format!("{} {}", method_of(index), path));
    }
}
