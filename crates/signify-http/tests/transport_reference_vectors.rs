//! Every request the pinned TypeScript reference sends, expressed through the transport boundary.
//!
//! There is no upstream transport to compare against byte for byte — the reference calls the
//! global `fetch` directly — so the evidence is that this crate's `Request` can carry each
//! recorded call without loss: the same method, the same URL bytes, the same header names in the
//! same order, and the same body or the same absence of one.

use std::error::Error;

use serde::Deserialize;
use signify_http::header::{HeaderName, HeaderValue};
use signify_http::transport::{
    Method, Request, RequestUrl, Response, ScriptedTransport, StatusCode, Transport, TransportError,
};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/http-transport/v1.json"));

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    requests: Vec<RequestCase>,
    responses: Vec<ResponseCase>,
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
struct RequestCase {
    name: String,
    note: String,
    request: RecordedRequest,
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
    /// Absent on the response shapes, which record no clock-dependent value.
    #[serde(default)]
    masked: bool,
}

#[derive(Debug, Deserialize)]
struct ResponseCase {
    name: String,
    status: u16,
    headers: Vec<RecordedHeader>,
    body: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Quirks {
    get_sends_a_null_body: NullBodyQuirk,
    headers_are_joined_on_duplicates: NoteQuirk,
    boot_uses_a_second_base_url: BaseUrlQuirk,
    delegation_approval_is_unauthenticated: ApprovalQuirk,
    no_timeout_anywhere: NoteQuirk,
}

#[derive(Debug, Deserialize)]
struct NullBodyQuirk {
    body: Option<String>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct NoteQuirk {
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct BaseUrlQuirk {
    boot_url: String,
    admin_url: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct ApprovalQuirk {
    headers: Vec<String>,
    carries_signature: bool,
    note: String,
    rust_decision: String,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

/// Maps a recorded method name onto the typed method.
fn method_of(text: &str) -> Result<Method, Box<dyn Error>> {
    Method::ALL
        .iter()
        .copied()
        .find(|method| method.as_str() == text)
        .ok_or_else(|| format!("the reference sent an unmodelled method {text:?}").into())
}

/// Rebuilds one recorded request through the transport boundary.
///
/// A masked header keeps its name and takes a placeholder value, because the fixture records what
/// the reference sent and only its clock-dependent values are withheld.
fn rebuild(recorded: &RecordedRequest) -> Result<Request, Box<dyn Error>> {
    let mut builder = Request::builder(method_of(&recorded.method)?, RequestUrl::new(recorded.url.clone())?);
    for header in &recorded.headers {
        let value = header.value.clone().unwrap_or_else(|| "masked".to_owned());
        builder = builder.header(HeaderName::new(header.name.clone())?, HeaderValue::new(value)?);
    }
    if let Some(body) = &recorded.body {
        builder = builder.body(body.clone().into_bytes());
    }
    Ok(builder.build()?)
}

#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert_ne!(fixture.generated_on, "");
    assert!(fixture.sources.iter().any(|source| source.ends_with("clienting.ts")));
    assert_ne!(fixture.provenance.note, "");
    assert_eq!(fixture.provenance.bran.len(), 21);
    assert!(fixture.provenance.controller_prefix.starts_with('E'));
    assert_eq!(fixture.provenance.masked_headers.len(), 3);
    assert_eq!(fixture.requests.len(), 8);
    assert_eq!(fixture.responses.len(), 5);
    Ok(())
}

#[test]
fn every_recorded_request_is_expressible() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for case in &fixture.requests {
        assert!(!case.note.is_empty(), "{}", case.name);
        let recorded = &case.request;
        let request = rebuild(recorded).map_err(|error| format!("{}: {error}", case.name))?;

        // The method, the URL's exact bytes, and the body survive the round trip.
        assert_eq!(request.method().as_str(), recorded.method, "{}", case.name);
        assert_eq!(request.url().as_str(), recorded.url, "{}", case.name);
        assert_eq!(
            request.body().map(<[u8]>::to_vec),
            recorded.body.as_ref().map(|body| body.clone().into_bytes()),
            "{}",
            case.name
        );

        // Header names arrive in the order the reference set them.
        let names: Vec<&str> = request.headers().iter().map(|(name, _)| name.as_str()).collect();
        let expected: Vec<&str> = recorded.headers.iter().map(|header| header.name.as_str()).collect();
        assert_eq!(names, expected, "{}", case.name);

        // Every unmasked value is carried verbatim, and a masked one is exactly the three
        // clock-dependent headers whose bytes keri-http-auth already verified.
        for header in &recorded.headers {
            match &header.value {
                Some(value) => {
                    assert!(
                        !header.masked,
                        "{}: {} is masked but has a value",
                        case.name, header.name
                    );
                    assert_eq!(
                        request.headers().get(&header.name),
                        Some(value.as_str()),
                        "{}",
                        case.name
                    );
                }
                None => assert!(
                    header.masked,
                    "{}: {} has no value but is not masked",
                    case.name, header.name
                ),
            }
        }
    }
    Ok(())
}

#[test]
fn the_recorded_urls_decompose_as_the_reference_built_them() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let case = |name: &str| -> Result<RequestUrl, Box<dyn Error>> {
        let recorded = fixture
            .requests
            .iter()
            .find(|case| case.name == name)
            .ok_or_else(|| format!("no case named {name:?}"))?;
        Ok(RequestUrl::new(recorded.request.url.clone())?)
    };

    // The boot interface is a different origin from the admin one.
    let boot = case("boot")?;
    assert_eq!(boot.authority(), "localhost:3903");
    assert_eq!(boot.path(), "/boot");
    assert_eq!(boot.query(), None);

    // A query string is separated from the path, which is what a signature covers.
    let query = case("contacts_list_with_query")?;
    assert_eq!(query.path(), "/contacts");
    assert_eq!(query.query(), Some("group=group&filter_field=field&filter_value=value"));

    // Percent-encoded UTF-8 in a path is preserved exactly, never re-encoded or decoded.
    let encoded = case("identifier_update")?;
    assert_eq!(encoded.path(), "/identifiers/a%20name%20with%20%C3%B1!");
    assert_eq!(encoded.authority(), "localhost:3901");

    // The delegation approval's `?type=ixn` likewise splits cleanly.
    let approval = case("approve_delegation")?;
    assert_eq!(approval.query(), Some("type=ixn"));
    assert!(approval.path().starts_with("/agent/"));
    Ok(())
}

#[test]
fn every_recorded_response_shape_is_carryable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for case in &fixture.responses {
        assert!(!case.note.is_empty(), "{}", case.name);
        let mut headers = signify_http::header::Headers::new();
        for header in &case.headers {
            let value = header.value.clone().unwrap_or_default();
            headers.insert(HeaderName::new(header.name.clone())?, HeaderValue::new(value)?)?;
        }
        let response = Response::new(StatusCode::new(case.status)?, headers, case.body.clone().into_bytes())?;
        assert_eq!(response.status().as_u16(), case.status, "{}", case.name);
        assert_eq!(response.body(), case.body.as_bytes(), "{}", case.name);
        for header in &case.headers {
            if let Some(value) = &header.value {
                assert_eq!(
                    response.headers().get(&header.name),
                    Some(value.as_str()),
                    "{}",
                    case.name
                );
            }
        }
        // A non-success status is a response, not a failure.
        if case.name == "not_found" {
            assert!(response.status().is_client_error());
        }
    }
    Ok(())
}

#[test]
fn a_recorded_exchange_replays_through_the_scripted_transport() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let ranged = fixture
        .responses
        .iter()
        .find(|case| case.name == "ranged_list")
        .ok_or("the fixture records no ranged list response")?;
    let listing = fixture
        .requests
        .iter()
        .find(|case| case.name == "identifiers_list")
        .ok_or("the fixture records no listing request")?;

    let mut headers = signify_http::header::Headers::new();
    for header in &ranged.headers {
        headers.insert(
            HeaderName::new(header.name.clone())?,
            HeaderValue::new(header.value.clone().unwrap_or_default())?,
        )?;
    }
    let transport = ScriptedTransport::new().respond(Response::new(
        StatusCode::new(ranged.status)?,
        headers,
        ranged.body.clone().into_bytes(),
    )?);

    let response = block_on(transport.execute(rebuild(&listing.request)?))?;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-range"), Some("aids 0-1/2"));

    // What the transport recorded is exactly what the reference sent.
    let sent = transport.last_request().ok_or("the transport recorded nothing")?;
    assert_eq!(sent.url().as_str(), listing.request.url);
    assert_eq!(sent.method(), Method::Get);
    assert_eq!(sent.body(), None);
    assert_eq!(sent.headers().get("range"), Some("aids=0-24"));
    Ok(())
}

#[test]
fn the_reference_quirks_hold_and_the_divergences_are_deliberate() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = &fixture.reference_quirks;

    // A GET carries no body at all, which is a different value from an empty one here.
    assert_eq!(quirks.get_sends_a_null_body.body, None);
    assert_ne!(quirks.get_sends_a_null_body.note, "");
    assert_ne!(quirks.get_sends_a_null_body.rust_decision, "");
    let url = RequestUrl::new("https://keria.example/identifiers")?;
    let absent = Request::builder(Method::Get, url.clone()).build()?;
    let empty = Request::builder(Method::Get, url).body(Vec::new()).build()?;
    assert_eq!(absent.body(), None);
    assert_eq!(empty.body(), Some(b"".as_slice()));

    // A duplicate header name is refused rather than joined with a comma.
    assert_ne!(quirks.headers_are_joined_on_duplicates.note, "");
    let duplicate = Request::builder(Method::Get, RequestUrl::new("https://keria.example/a")?)
        .header(HeaderName::new("Range")?, HeaderValue::new("aids=0-24")?)
        .header(HeaderName::new("range")?, HeaderValue::new("aids=25-49")?)
        .build();
    assert!(matches!(duplicate, Err(TransportError::Header { .. })));

    // Two base URLs, both carried whole.
    assert_ne!(
        quirks.boot_uses_a_second_base_url.boot_url,
        quirks.boot_uses_a_second_base_url.admin_url
    );
    assert!(
        quirks
            .boot_uses_a_second_base_url
            .boot_url
            .starts_with(&fixture.provenance.boot_url)
    );
    assert!(
        quirks
            .boot_uses_a_second_base_url
            .admin_url
            .starts_with(&fixture.provenance.admin_url)
    );
    assert_ne!(quirks.boot_uses_a_second_base_url.note, "");
    assert_ne!(quirks.boot_uses_a_second_base_url.rust_decision, "");

    // The delegation approval really does go out unsigned.
    assert!(!quirks.delegation_approval_is_unauthenticated.carries_signature);
    assert_eq!(quirks.delegation_approval_is_unauthenticated.headers, ["content-type"]);
    assert_ne!(quirks.delegation_approval_is_unauthenticated.note, "");
    assert_ne!(quirks.delegation_approval_is_unauthenticated.rust_decision, "");

    // No timeout anywhere upstream; here it is a typed outcome a transport can report.
    assert_ne!(quirks.no_timeout_anywhere.note, "");
    assert_ne!(quirks.no_timeout_anywhere.rust_decision, "");
    let transport = ScriptedTransport::new().fail(TransportError::Timeout { milliseconds: 30_000 });
    let outcome = block_on(
        transport.execute(Request::builder(Method::Get, RequestUrl::new("https://keria.example/slow")?).build()?),
    );
    assert!(matches!(outcome, Err(TransportError::Timeout { .. })));
    Ok(())
}

/// A minimal executor: every future in this crate is ready on its first poll.
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
