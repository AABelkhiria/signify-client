//! Every URL the pinned TypeScript reference builds, and every response value it reads.
//!
//! The request half has no upstream function to compare against — `SignifyClient.fetch`
//! concatenates a base URL with a path string its endpoint modules assembled — so the evidence is
//! the reference's own output: `encodeURIComponent` and `URLSearchParams` applied component by
//! component, and sixteen real endpoint calls captured by replacing the global `fetch`.
//!
//! The response half does have one, `parseRangeHeaders`, and its results are compared directly:
//! every value the reference reads correctly, this crate reads identically, and every value it
//! reads *wrongly* is refused here with a typed error rather than reproduced.

use std::error::Error;

use serde::Deserialize;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::request::{
    BaseUrl, ItemRange, MediaType, RangeUnit, ResourcePath, ResourceRequestBuilder, encode_path_component,
    encode_query_component,
};
use signify_http::response::{ContentRange, RequestOrigin, ResourceResponse, ResponseError};
use signify_http::transport::{Method, Request, RequestUrl, Response, StatusCode};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/http-request-response/v1.json"
));

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    media_types: MediaTypes,
    path_segments: Vec<SegmentCase>,
    query_strings: Vec<QueryCase>,
    requests: Vec<RequestCase>,
    content_ranges: Vec<RangeCase>,
    payload_decoding: Vec<DecodeCase>,
    status_outcomes: Vec<StatusCase>,
    reference_quirks: Quirks,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    boot_url: String,
    controller_prefix: String,
    masked_headers: Vec<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct MediaTypes {
    request_content_type: String,
    accept_json: String,
    accept_json_cesr: String,
    range_units: Vec<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct SegmentCase {
    input: String,
    encoded: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct QueryCase {
    pairs: Vec<QueryPair>,
    serialized: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct QueryPair {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct RequestCase {
    name: String,
    note: String,
    request: RecordedRequest,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    url: String,
    method: String,
    headers: Vec<RecordedHeader>,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedHeader {
    name: String,
    value: Option<String>,
    masked: bool,
}

/// One `parseRangeHeaders` result.
///
/// The numeric fields are `serde_json::Value` because the reference produces `NaN`, which the
/// generator records as the string `"NaN"` — JSON cannot spell one, which is part of what the
/// entry demonstrates.
#[derive(Debug, Deserialize)]
struct RangeCase {
    header: Option<String>,
    unit: String,
    start: serde_json::Value,
    end: serde_json::Value,
    total: serde_json::Value,
    note: String,
}

impl RangeCase {
    /// Returns the three values when the reference parsed all of them as real numbers.
    fn exact(&self) -> Option<(u64, u64, u64)> {
        Some((self.start.as_u64()?, self.end.as_u64()?, self.total.as_u64()?))
    }
}

#[derive(Debug, Deserialize)]
struct DecodeCase {
    name: String,
    status: u16,
    ok: bool,
    status_text: String,
    declared_content_type: Option<String>,
    observed_content_type: Option<String>,
    body: String,
    note: String,
    json: Option<String>,
    json_error: Option<String>,
    text: String,
}

#[derive(Debug, Deserialize)]
struct StatusCase {
    status: u16,
    body: String,
    ok: bool,
    message: Option<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Quirks {
    dynamic_components_are_usually_not_encoded: EncodingQuirk,
    a_missing_content_range_is_zero: MissingRangeQuirk,
    malformed_content_range_yields_nan: NoteQuirk,
    content_range_loses_precision: PrecisionQuirk,
    response_json_ignores_the_content_type: ContentTypeQuirk,
    status_error_message_carries_the_body: StatusMessageQuirk,
    status_text_is_empty: MessageQuirk,
    content_type_is_declared_even_without_a_body: DeclaredTypeQuirk,
    a_bodyless_put_sends_the_word_null: NullBodyQuirk,
    recorded_header_order_is_the_platform_sort: HeaderOrderQuirk,
    empty_query_still_emits_a_delimiter: EmptyQueryQuirk,
}

#[derive(Debug, Deserialize)]
struct EncodingQuirk {
    encoded_paths: Vec<String>,
    encoded_interpolations: u32,
    raw_interpolations: u32,
    total_interpolations: u32,
    scanned_files: u32,
    counting_method: String,
    operation_get_url: String,
    contact_delete_url: String,
    notification_mark_url: String,
    key_states_url: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct MissingRangeQuirk {
    absent_header_result: AbsentRange,
    real_zero_range_is_indistinguishable: bool,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct AbsentRange {
    start: u64,
    end: u64,
    total: u64,
}

#[derive(Debug, Deserialize)]
struct NoteQuirk {
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct PrecisionQuirk {
    header: String,
    parsed: AbsentRange,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct ContentTypeQuirk {
    declared: String,
    parsed: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct StatusMessageQuirk {
    status: u16,
    message: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct MessageQuirk {
    message: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct DeclaredTypeQuirk {
    method: String,
    body: Option<String>,
    headers: Vec<String>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct NullBodyQuirk {
    put_body: String,
    delete_body: Option<String>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct HeaderOrderQuirk {
    names: Vec<String>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct EmptyQueryQuirk {
    url: String,
    note: String,
    rust_decision: String,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let fixture: Fixture = serde_json::from_str(FIXTURE)?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(fixture.generated_on, "2026-08-23");
    assert!(fixture.sources.contains(&"src/keri/core/httping.ts".to_owned()));
    assert_ne!(fixture.provenance.note, "");
    assert_eq!(fixture.provenance.bran, "0123456789abcdefghijk");
    assert_eq!(fixture.provenance.admin_url, "http://localhost:3901");
    assert_eq!(fixture.provenance.boot_url, "http://localhost:3903");
    assert!(fixture.provenance.controller_prefix.starts_with('E'));
    assert_eq!(fixture.provenance.masked_headers.len(), 3);
    Ok(fixture)
}

fn find<'cases>(cases: &'cases [RequestCase], name: &str) -> Result<&'cases RequestCase, Box<dyn Error>> {
    cases
        .iter()
        .find(|case| case.name == name)
        .ok_or_else(|| format!("fixture has no request named {name}").into())
}

// ---------------------------------------------------------------------------
// Request: URL composition
// ---------------------------------------------------------------------------

#[test]
fn every_path_component_encodes_as_the_reference_does() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.path_segments.len(), 23);
    for case in &fixture.path_segments {
        assert!(!case.note.is_empty(), "{}", case.input);
        assert_eq!(
            encode_path_component(&case.input),
            case.encoded,
            "component {:?} ({})",
            case.input,
            case.note,
        );
    }
    Ok(())
}

#[test]
fn every_query_component_encodes_as_the_reference_does() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.query_strings.len(), 13);
    for case in &fixture.query_strings {
        assert_ne!(case.note, "");
        if case.pairs.is_empty() {
            // The reference still appends a bare `?` at the call site; a path with no parameters
            // has no query here at all. That divergence is asserted separately below.
            assert_eq!(case.serialized, "");
            continue;
        }
        let mut builder = ResourcePath::builder().segment("resource");
        for pair in &case.pairs {
            builder = builder.parameter(&pair.name, &pair.value);
        }
        let path = builder.build()?;
        assert_eq!(path.query(), Some(case.serialized.as_str()), "query ({})", case.note);
        // The same bytes, component by component.
        for pair in &case.pairs {
            assert!(case.serialized.contains(&encode_query_component(&pair.name)));
            assert!(case.serialized.contains(&encode_query_component(&pair.value)));
        }
    }
    Ok(())
}

#[test]
fn every_recorded_request_url_is_rebuilt_or_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.requests.len(), 16);
    for case in &fixture.requests {
        assert!(
            case.error.is_none(),
            "{} failed in the reference: {:?}",
            case.name,
            case.error
        );
        assert!(!case.note.is_empty(), "{}", case.name);
        assert!(case.request.url.starts_with("http://localhost:3901"), "{}", case.name);
    }

    let base = BaseUrl::new("http://localhost:3901")?;
    let rebuilt: [(&str, ResourcePath); 10] = [
        (
            "identifiers_list_default",
            ResourcePath::builder().segment("identifiers").build()?,
        ),
        (
            "identifiers_list_explicit",
            ResourcePath::builder().segment("identifiers").build()?,
        ),
        (
            "notifications_list",
            ResourcePath::builder().segment("notifications").build()?,
        ),
        (
            "identifier_get_encoded",
            ResourcePath::builder()
                .segment("identifiers")
                .segment("a name with ñ!")
                .build()?,
        ),
        (
            "contacts_list_query",
            ResourcePath::builder()
                .segment("contacts")
                .parameter("group", "group")
                .parameter("filter_field", "field")
                .parameter("filter_value", "value")
                .build()?,
        ),
        (
            "operations_list_typed",
            ResourcePath::builder()
                .segment("operations")
                .parameter("type", "witness")
                .build()?,
        ),
        (
            "escrows_list_reply",
            ResourcePath::builder()
                .segment("escrows")
                .segment("rpy")
                .parameter("route", "/multisig/icp")
                .build()?,
        ),
        (
            "credential_get_json",
            ResourcePath::builder()
                .segment("credentials")
                .segment("ECRED")
                .build()?,
        ),
        (
            "credential_get_cesr",
            ResourcePath::builder()
                .segment("credentials")
                .segment("ECRED")
                .build()?,
        ),
        (
            "credential_state",
            ResourcePath::builder()
                .segment("registries")
                .segment("EREGISTRY")
                .segment("ECRED")
                .build()?,
        ),
    ];
    for (name, path) in rebuilt {
        let case = find(&fixture.requests, name)?;
        let url = base.join(&path)?;
        assert_eq!(url.as_str(), case.request.url, "{name}");
    }
    Ok(())
}

#[test]
fn the_reference_paths_this_crate_refuses_to_reproduce_are_encoded_instead() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let base = BaseUrl::new("http://localhost:3901")?;

    // `..` is left alone by `encodeURIComponent`, which is why the reference's own encoded path
    // carries it verbatim — but this component reaches the path through a raw interpolation, and
    // this crate encodes it either way, so the segment can never escape itself.
    let dotted = find(&fixture.requests, "identifier_get_dot_segments")?;
    assert_eq!(dotted.request.url, "http://localhost:3901/identifiers/..");
    let ours = base.join(&ResourcePath::builder().segment("identifiers").segment("..").build()?)?;
    assert_eq!(
        ours.as_str(),
        dotted.request.url,
        "encodeURIComponent leaves `..` alone"
    );

    let cases: [(&str, ResourcePath, &str); 4] = [
        (
            "operation_get_traversal",
            ResourcePath::builder()
                .segment("operations")
                .segment("../identifiers")
                .build()?,
            "http://localhost:3901/operations/..%2Fidentifiers",
        ),
        (
            "contact_delete_raw_slash",
            ResourcePath::builder().segment("contacts").segment("a/b").build()?,
            "http://localhost:3901/contacts/a%2Fb",
        ),
        (
            "notification_mark_raw_query",
            ResourcePath::builder()
                .segment("notifications")
                .segment("a?b=c")
                .build()?,
            "http://localhost:3901/notifications/a%3Fb%3Dc",
        ),
        (
            "key_states_raw_query_value",
            ResourcePath::builder()
                .segment("states")
                .parameter("pre", "a&b=c")
                .build()?,
            "http://localhost:3901/states?pre=a%26b%3Dc",
        ),
    ];
    for (name, path, expected) in cases {
        let case = find(&fixture.requests, name)?;
        let ours = base.join(&path)?;
        assert_eq!(ours.as_str(), expected, "{name}");
        assert_ne!(
            ours.as_str(),
            case.request.url,
            "{name}: the reference's raw interpolation must not be reproduced",
        );
    }

    // The path a signature would cover changes with it, which is why this matters.
    let reference_signed_path = "/operations/../identifiers";
    let ours = base.join(
        &ResourcePath::builder()
            .segment("operations")
            .segment("../identifiers")
            .build()?,
    )?;
    assert_ne!(ours.path(), reference_signed_path);
    // The encoded path still holds the characters `..`, but never as a component of its own: a
    // component can no longer be a dot segment, which is what a server or a proxy would resolve.
    let components: Vec<&str> = ours.path().split('/').skip(1).collect();
    assert_eq!(components, ["operations", "..%2Fidentifiers"]);
    assert!(
        !components
            .iter()
            .any(|component| *component == ".." || *component == ".")
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Request: headers and bodies
// ---------------------------------------------------------------------------

#[test]
fn the_range_headers_match_the_reference_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.media_types.range_units, ["aids", "notes"]);
    assert_ne!(fixture.media_types.note, "");

    let cases: [(&str, &str, ItemRange); 3] = [
        ("identifiers_list_default", "aids", ItemRange::DEFAULT),
        ("identifiers_list_explicit", "aids", ItemRange::new(20, 40)?),
        ("notifications_list", "notes", ItemRange::new(20, 40)?),
    ];
    for (name, unit, range) in cases {
        let case = find(&fixture.requests, name)?;
        let recorded = case
            .request
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("range"))
            .and_then(|header| header.value.as_deref())
            .ok_or("the recorded request carries no Range header")?;
        assert_eq!(range.header_value(&RangeUnit::new(unit)?), recorded, "{name}");
    }
    Ok(())
}

#[test]
fn the_media_types_match_the_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(MediaType::json().as_str(), fixture.media_types.request_content_type);
    assert_eq!(MediaType::json().as_str(), fixture.media_types.accept_json);
    assert_eq!(MediaType::json_cesr().as_str(), fixture.media_types.accept_json_cesr);

    for (name, expected) in [
        ("credential_get_json", MediaType::json()),
        ("credential_get_cesr", MediaType::json_cesr()),
    ] {
        let case = find(&fixture.requests, name)?;
        let accept = case
            .request
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("accept"))
            .and_then(|header| header.value.as_deref())
            .ok_or("the recorded request carries no Accept header")?;
        assert_eq!(expected.as_str(), accept, "{name}");
        // And the content type the reference declares on every request.
        let declared = case
            .request
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .and_then(|header| header.value.as_deref())
            .ok_or("the recorded request carries no Content-Type header")?;
        assert_eq!(MediaType::json().as_str(), declared, "{name}");
    }
    Ok(())
}

#[test]
fn a_rebuilt_request_carries_the_recorded_values() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let base = BaseUrl::new("http://localhost:3901")?;
    let case = find(&fixture.requests, "credential_get_cesr")?;
    assert_eq!(case.request.method, "GET");
    assert_eq!(case.request.body, None);

    let request = ResourceRequestBuilder::new(
        Method::Get,
        base.join(
            &ResourcePath::builder()
                .segment("credentials")
                .segment("ECRED")
                .build()?,
        )?,
    )
    .content_type(MediaType::json())
    .accept(MediaType::json_cesr())
    .build()?;

    assert_eq!(request.url().as_str(), case.request.url);
    assert_eq!(request.method().as_str(), case.request.method);
    assert_eq!(request.body(), None);
    for header in &case.request.headers {
        if header.masked {
            // A clock read, or a signature over one; keri-http-auth owns those bytes and
            // `SigningTransport` applies them to a finished request.
            assert!(header.value.is_none(), "{} was recorded with a value", header.name);
            continue;
        }
        if header.name.eq_ignore_ascii_case("signify-resource") {
            // The controller prefix an authenticated request announces; `SigningTransport` applies
            // it, and it is the same prefix the fixture's provenance records.
            assert_eq!(
                header.value.as_deref(),
                Some(fixture.provenance.controller_prefix.as_str())
            );
            continue;
        }
        assert_eq!(
            request.headers().get(&header.name),
            header.value.as_deref(),
            "header {}",
            header.name,
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Response: Content-Range
// ---------------------------------------------------------------------------

#[test]
fn every_content_range_agrees_or_is_refused_on_purpose() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.content_ranges.len(), 31);

    let mut agreed = Vec::new();
    let mut disagreed = Vec::new();
    let mut refused = Vec::new();
    for case in &fixture.content_ranges {
        assert_ne!(case.note, "");
        let label = case.header.clone().unwrap_or_else(|| "<absent>".to_owned());
        let Ok(unit) = RangeUnit::new(case.unit.clone()) else {
            // The reference accepts an empty unit and a unit with a trailing space; neither is a
            // token, so neither can even be named here.
            assert!(case.unit.is_empty() || case.unit.ends_with(' '), "{:?}", case.unit);
            refused.push(label);
            continue;
        };
        let Some(header) = case.header.as_deref() else {
            // An absent header: the reference answers {0,0,0}, this crate answers `None`.
            assert_eq!(case.exact(), Some((0, 0, 0)));
            refused.push(label);
            continue;
        };
        match ContentRange::parse(header, &unit) {
            Ok(range) => {
                let ours = (range.start(), range.end(), range.total());
                match case.exact() {
                    Some(theirs) if theirs == ours => agreed.push(label),
                    // The reference's answer is a double, so it can differ from the bytes sent.
                    Some(_) => disagreed.push(label),
                    None => {
                        return Err(format!("{header:?} parsed where the reference produced a NaN").into());
                    }
                }
            }
            Err(ResponseError::InvalidContentRange { .. }) => refused.push(label),
            Err(other) => return Err(format!("{header:?} produced the wrong error: {other}").into()),
        }
    }

    assert_eq!(
        agreed,
        [
            "aids 0-1/2",
            "notes 20-40/100",
            "aids 0-24/24",
            "aids 5-5/6",
            // Ordering is not checked on either side, so a descending range agrees too.
            "aids 1-0/2",
            "aids 00-01/02",
        ],
        "the values both sides read the same way",
    );
    // Exactly one recorded value is read *correctly* here and *incorrectly* there.
    assert_eq!(
        disagreed,
        ["aids 9007199254740993-9007199254740994/9007199254740995"],
        "the values where the reference loses precision",
    );
    assert_eq!(
        refused.len(),
        fixture.content_ranges.len() - agreed.len() - disagreed.len(),
    );
    // Everything refused here is a value the reference read as a number or a NaN.
    assert_eq!(refused.len(), 24);
    Ok(())
}

#[test]
fn the_content_range_defects_are_pinned_and_not_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let aids = RangeUnit::new("aids")?;

    // An absent header is not a zero range.
    let missing = &fixture.reference_quirks.a_missing_content_range_is_zero;
    assert_eq!(
        (
            missing.absent_header_result.start,
            missing.absent_header_result.end,
            missing.absent_header_result.total,
        ),
        (0, 0, 0),
    );
    assert!(missing.real_zero_range_is_indistinguishable);
    assert_ne!(missing.rust_decision, "");
    let zero = ContentRange::parse("aids 0-0/0", &aids)?;
    assert_eq!((zero.start(), zero.end(), zero.total()), (0, 0, 0));

    // A malformed value is a typed error, not a NaN.
    assert_ne!(fixture.reference_quirks.malformed_content_range_yields_nan.note, "");
    assert_ne!(
        fixture
            .reference_quirks
            .malformed_content_range_yields_nan
            .rust_decision,
        ""
    );

    // Precision: the reference's own answer differs from the bytes the server sent.
    let precision = &fixture.reference_quirks.content_range_loses_precision;
    let parsed = ContentRange::parse(&precision.header, &aids)?;
    assert_eq!(parsed.total(), 9_007_199_254_740_995);
    assert_eq!(precision.parsed.total, 9_007_199_254_740_996);
    assert_ne!(parsed.total(), precision.parsed.total, "{}", precision.note);
    assert_eq!(parsed.start(), 9_007_199_254_740_993);
    assert_eq!(precision.parsed.start, 9_007_199_254_740_992);
    Ok(())
}

// ---------------------------------------------------------------------------
// Response: status and body
// ---------------------------------------------------------------------------

fn decode(status: u16, content_type: Option<&str>, body: &str) -> Result<DecodeOutcome, Box<dyn Error>> {
    let request = Request::builder(
        Method::Get,
        RequestUrl::new("http://localhost:3901/identifiers/aid1?filter=secret")?,
    )
    .build()?;
    let mut headers = Headers::new();
    if let Some(value) = content_type {
        headers.insert(HeaderName::new("Content-Type")?, HeaderValue::new(value)?)?;
    }
    let response = Response::new(StatusCode::new(status)?, headers, body.as_bytes().to_vec())?;
    Ok(match ResourceResponse::decode(&RequestOrigin::of(&request), response) {
        Ok(decoded) => DecodeOutcome::Accepted(Box::new(decoded)),
        Err(error) => DecodeOutcome::Refused(error),
    })
}

enum DecodeOutcome {
    Accepted(Box<ResourceResponse>),
    Refused(ResponseError),
}

#[test]
fn the_success_boundary_is_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.status_outcomes.len(), 8);
    for case in &fixture.status_outcomes {
        assert_ne!(case.note, "");
        let outcome = decode(case.status, Some("application/json"), &case.body)?;
        match (&outcome, case.ok) {
            (DecodeOutcome::Accepted(decoded), true) => {
                assert_eq!(decoded.status().as_u16(), case.status);
                assert_eq!(decoded.body(), case.body.as_bytes());
                // The reference accepted the status too, and only then failed on the missing
                // agent signature, which is `ResponseAuthenticator`'s.
                assert_eq!(case.message.as_deref(), Some("message from a different remote agent"));
            }
            (DecodeOutcome::Refused(ResponseError::Status { status, detail, .. }), false) => {
                assert_eq!(status.as_u16(), case.status);
                assert_eq!(detail, &case.body);
                // The reference threw a message naming the same status and body.
                let message = case.message.as_deref().ok_or("a refused status recorded no message")?;
                assert!(message.starts_with("HTTP GET /identifiers/aid1 - "), "{message}");
                assert!(message.contains(&case.status.to_string()), "{message}");
                assert!(message.ends_with(&case.body), "{message}");
            }
            _ => return Err(format!("status {} disagreed with the reference", case.status).into()),
        }
    }
    Ok(())
}

#[test]
fn a_status_failure_redacts_what_the_reference_interpolates() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    let quirk = &fixture.reference_quirks.status_error_message_carries_the_body;
    assert_eq!(quirk.status, 400);
    // The reference's message carries the path *with* its query; the request here has one.
    assert_eq!(quirk.message, "HTTP GET /identifiers/aid1 - 400  - bad request");
    let DecodeOutcome::Refused(ResponseError::Status { path, detail, .. }) =
        decode(400, Some("application/json"), "bad request")?
    else {
        return Err("a 400 was accepted".into());
    };
    assert_eq!(path, "/identifiers/aid1");
    assert!(!path.contains("filter=secret"), "the query must not reach an error");
    assert_eq!(detail, "bad request");

    // The reason phrase the reference interpolates is always empty, and is not modelled at all.
    let empty_reason = &fixture.reference_quirks.status_text_is_empty;
    assert!(empty_reason.message.contains(" - 500  - "), "{}", empty_reason.message);
    assert_ne!(empty_reason.rust_decision, "");
    Ok(())
}

#[test]
fn every_recorded_body_reads_the_same_way_or_is_refused_on_purpose() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.payload_decoding.len(), 12);

    for case in &fixture.payload_decoding {
        assert!(!case.note.is_empty(), "{}", case.name);
        assert_eq!(
            case.status_text, "",
            "{}: the platform never sets a reason phrase",
            case.name
        );
        assert_eq!(case.ok, (200..=299).contains(&case.status), "{}", case.name);
        // The reference either parsed the body or reported why it could not; never both.
        assert_eq!(case.json.is_some(), case.json_error.is_none(), "{}", case.name);

        let outcome = decode(case.status, case.declared_content_type.as_deref(), &case.body)?;
        let DecodeOutcome::Accepted(decoded) = outcome else {
            assert!(!case.ok, "{}: a success was refused", case.name);
            continue;
        };
        assert!(case.ok, "{}: a failure was accepted", case.name);

        // Text is the body, whatever it declares itself to be — exactly as `res.text()` returns.
        assert_eq!(decoded.text()?, case.text, "{}", case.name);

        let declared = case.observed_content_type.as_deref().unwrap_or("");
        let json = decoded.json();
        if case.declared_content_type.is_none()
            || declared.starts_with("application/json;")
            || declared == "application/json"
            || declared.eq_ignore_ascii_case("APPLICATION/JSON")
        {
            // The declaration agrees, so the bytes come back and the reference parsed them too
            // whenever they were a document.
            assert_eq!(json?, case.body.as_bytes(), "{}", case.name);
            if case.body.is_empty() {
                assert!(
                    case.json_error.is_some(),
                    "{}: an empty body is not a document",
                    case.name
                );
            }
        } else {
            // A declaration this caller cannot read: the reference decoded it anyway whenever it
            // happened to be valid JSON.
            assert!(
                matches!(json, Err(ResponseError::UnexpectedContentType { .. })),
                "{}: a mismatched declaration was accepted",
                case.name,
            );
        }

        if declared == "application/json+cesr" {
            assert_eq!(decoded.cesr()?, case.text, "{}", case.name);
            // And the reference could not read it as JSON either, though it tried.
            assert!(case.json_error.is_some(), "{}", case.name);
        }
    }
    Ok(())
}

#[test]
fn the_body_decoding_defects_are_pinned_and_not_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirk = &fixture.reference_quirks.response_json_ignores_the_content_type;
    assert_eq!(quirk.declared, "text/plain");
    assert_eq!(quirk.parsed, r#"{"name":"aid1"}"#);
    assert_ne!(quirk.rust_decision, "");

    let DecodeOutcome::Accepted(decoded) = decode(200, Some("text/plain"), r#"{"name":"aid1"}"#)? else {
        return Err("a 200 was refused".into());
    };
    assert!(
        matches!(decoded.json(), Err(ResponseError::UnexpectedContentType { .. })),
        "{}",
        quirk.note,
    );
    // The bytes are still reachable, so a caller that knows better is not blocked.
    assert_eq!(decoded.text()?, quirk.parsed);
    Ok(())
}

// ---------------------------------------------------------------------------
// The remaining recorded divergences
// ---------------------------------------------------------------------------

#[test]
fn the_request_defects_are_pinned_and_not_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let base = BaseUrl::new("http://localhost:3901")?;

    // Only two paths encode; the URLs the other forty produce are recorded above.
    let encoding = &fixture.reference_quirks.dynamic_components_are_usually_not_encoded;
    // Two of the reference's forty-three dynamic path and query values are encoded. The count is
    // read from the pinned source by the generator, not hand-written; its method is recorded too.
    assert_eq!(encoding.encoded_paths.len(), 1);
    assert_eq!(encoding.encoded_interpolations, 2);
    assert_eq!(encoding.raw_interpolations, 41);
    assert_eq!(encoding.total_interpolations, 43);
    assert_eq!(encoding.scanned_files, 12);
    assert_ne!(encoding.counting_method, "");
    assert_eq!(
        encoding.operation_get_url,
        "http://localhost:3901/operations/../identifiers"
    );
    assert_eq!(encoding.contact_delete_url, "http://localhost:3901/contacts/a/b");
    assert_eq!(
        encoding.notification_mark_url,
        "http://localhost:3901/notifications/a?b=c"
    );
    assert_eq!(encoding.key_states_url, "http://localhost:3901/states?pre=a&b=c");
    assert!(!encoding.note.is_empty() && !encoding.rust_decision.is_empty());

    // A content type without a body stays expressible, because the reference sends one.
    let declared = &fixture.reference_quirks.content_type_is_declared_even_without_a_body;
    assert_eq!(declared.method, "GET");
    assert_eq!(declared.body, None);
    assert!(declared.headers.iter().any(|name| name == "content-type"));
    let request = ResourceRequestBuilder::new(
        Method::Get,
        base.join(&ResourcePath::builder().segment("identifiers").build()?)?,
    )
    .content_type(MediaType::json())
    .build()?;
    assert_eq!(request.headers().get("content-type"), Some("application/json"));
    assert_eq!(request.body(), None);

    // A body-less PUT sends the word `null` upstream; here an absent body stays absent.
    let null_body = &fixture.reference_quirks.a_bodyless_put_sends_the_word_null;
    assert_eq!(null_body.put_body, "null");
    assert_eq!(null_body.delete_body, None);
    let put = ResourceRequestBuilder::new(
        Method::Put,
        base.join(
            &ResourcePath::builder()
                .segment("notifications")
                .segment("ESAID")
                .build()?,
        )?,
    )
    .content_type(MediaType::json())
    .build()?;
    assert_eq!(put.body(), None, "{}", null_body.note);
    // Sending the document is still possible, but only by asking for it.
    let explicit = ResourceRequestBuilder::new(
        Method::Put,
        base.join(
            &ResourcePath::builder()
                .segment("notifications")
                .segment("ESAID")
                .build()?,
        )?,
    )
    .json_body(b"null".to_vec())
    .build()?;
    assert_eq!(explicit.body(), Some(b"null".as_slice()));

    // An empty query has no delimiter.
    let empty_query = &fixture.reference_quirks.empty_query_still_emits_a_delimiter;
    assert_eq!(empty_query.url, "http://localhost:3901/contacts?");
    let ours = base.join(&ResourcePath::builder().segment("contacts").build()?)?;
    assert_eq!(ours.as_str(), "http://localhost:3901/contacts");
    assert_ne!(ours.as_str(), empty_query.url, "{}", empty_query.note);
    // The signed path is the same either way, which is why the delimiter is safe to drop.
    assert_eq!(ours.path(), "/contacts");

    // The recorded header order is the platform's sort, not a choice this crate must match.
    let order = &fixture.reference_quirks.recorded_header_order_is_the_platform_sort;
    let mut sorted = order.names.clone();
    sorted.sort();
    assert_eq!(order.names, sorted, "{}", order.note);
    assert_ne!(order.rust_decision, "");
    Ok(())
}

#[test]
fn every_recorded_divergence_names_what_this_crate_does_instead() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = &fixture.reference_quirks;
    let decisions: [(&str, &str, &str); 11] = [
        (
            "dynamic_components_are_usually_not_encoded",
            &quirks.dynamic_components_are_usually_not_encoded.note,
            &quirks.dynamic_components_are_usually_not_encoded.rust_decision,
        ),
        (
            "a_missing_content_range_is_zero",
            &quirks.a_missing_content_range_is_zero.note,
            &quirks.a_missing_content_range_is_zero.rust_decision,
        ),
        (
            "malformed_content_range_yields_nan",
            &quirks.malformed_content_range_yields_nan.note,
            &quirks.malformed_content_range_yields_nan.rust_decision,
        ),
        (
            "content_range_loses_precision",
            &quirks.content_range_loses_precision.note,
            &quirks.content_range_loses_precision.rust_decision,
        ),
        (
            "response_json_ignores_the_content_type",
            &quirks.response_json_ignores_the_content_type.note,
            &quirks.response_json_ignores_the_content_type.rust_decision,
        ),
        (
            "status_error_message_carries_the_body",
            &quirks.status_error_message_carries_the_body.note,
            &quirks.status_error_message_carries_the_body.rust_decision,
        ),
        (
            "status_text_is_empty",
            &quirks.status_text_is_empty.note,
            &quirks.status_text_is_empty.rust_decision,
        ),
        (
            "content_type_is_declared_even_without_a_body",
            &quirks.content_type_is_declared_even_without_a_body.note,
            &quirks.content_type_is_declared_even_without_a_body.rust_decision,
        ),
        (
            "a_bodyless_put_sends_the_word_null",
            &quirks.a_bodyless_put_sends_the_word_null.note,
            &quirks.a_bodyless_put_sends_the_word_null.rust_decision,
        ),
        (
            "recorded_header_order_is_the_platform_sort",
            &quirks.recorded_header_order_is_the_platform_sort.note,
            &quirks.recorded_header_order_is_the_platform_sort.rust_decision,
        ),
        (
            "empty_query_still_emits_a_delimiter",
            &quirks.empty_query_still_emits_a_delimiter.note,
            &quirks.empty_query_still_emits_a_delimiter.rust_decision,
        ),
    ];
    for (name, note, decision) in decisions {
        assert!(!note.is_empty(), "{name} records no observation");
        assert!(!decision.is_empty(), "{name} records no decision");
    }
    Ok(())
}
