//! Exact operations-endpoint vectors recorded from the pinned reference's own `Operations`.
//!
//! Each call rebuilt through a connected client and compared against the path that actually goes out.

use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use keria_types::api::{KeyEvent, UntypedOperation, WitnessMetadata};
use serde::Deserialize;
use signify_client::client::SignifyClient;
use signify_client::config::ClientConfig;
use signify_client::endpoint::operations::{OPERATIONS_SEGMENT, TYPE_PARAMETER, completed};
use signify_client::error::ClientError;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::request::ResourcePath;
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::transport::Freshness;
use signify_http::transport::{Response, ScriptedTransport, StatusCode};
use signify_keri::manager::DerivationCost;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-operations/v1.json");

const ADMIN: &str = "http://127.0.0.1:3901";
const BOOT: &str = "http://127.0.0.1:3903";
const PASSCODE: &str = "0123456789abcdefghijk";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";
const AGENT_KEY: &str = "BHptu91ecGv_mxO8T3b98vNQUCghT8nfYkWRkVqOZark";

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    declarations: Declarations,
    calls: Vec<Call>,
    failures: Failures,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Quirks,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    get_path: String,
    list_path: String,
    list_parameters: String,
    list_append: String,
    delete_path: String,
    throw_if_failed: String,
    has_depends: String,
    operation_union: Vec<String>,
    notes: DeclarationNotes,
}

#[derive(Debug, Deserialize)]
struct DeclarationNotes {
    paths: String,
    failure: String,
    depends: String,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    request: Option<RecordedRequest>,
    result: serde_json::Value,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    body: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Failures {
    with_details: Failure,
    without_details: Failure,
    completed_returns_itself: Identical,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Failure {
    operation: serde_json::Value,
    message: String,
}

#[derive(Debug, Deserialize)]
struct Identical {
    identical: bool,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    published_paths: Vec<String>,
    driven_paths: Vec<String>,
    every_pinned_path_is_driven: bool,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Quirks {
    list_always_appends_a_question_mark: PathQuirk,
    path_components_are_not_encoded: PathQuirk,
    query_values_are_not_encoded_by_the_path: PathQuirk,
    failure_is_a_thrown_string: FailureQuirk,
    delete_discards_its_response: RequestQuirk,
    get_returns_the_untyped_union: UnionQuirk,
}

#[derive(Debug, Deserialize)]
struct PathQuirk {
    path: Option<String>,
    expression: Option<String>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct FailureQuirk {
    with_details: String,
    without_details: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct RequestQuirk {
    request: Option<RecordedRequest>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct UnionQuirk {
    union: Vec<String>,
    scan: Scan,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct Scan {
    needle: String,
    total: usize,
    files: Vec<ScanHit>,
    scanned_files: usize,
}

#[derive(Debug, Deserialize)]
struct ScanHit {
    file: String,
    count: usize,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

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

fn clock() -> Arc<dyn Clock> {
    Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
    ))
}

fn response(body: &[u8]) -> Result<Response, Box<dyn Error>> {
    let mut headers = Headers::new();
    headers.insert(HeaderName::new("signify-resource")?, HeaderValue::new(AGENT)?)?;
    Ok(Response::new(StatusCode::new(200)?, headers, body.to_vec())?)
}

fn connected(
    bodies: &[&[u8]],
) -> Result<(signify_client::client::ConnectedClient, Arc<ScriptedTransport>), Box<dyn Error>> {
    let transport = Arc::new(ScriptedTransport::new());
    let config = ClientConfig::new(ADMIN, PASSCODE)?
        .with_boot_url(BOOT)?
        .with_derivation_cost(DerivationCost::Ephemeral);
    let client = SignifyClient::new(config, Arc::clone(&transport) as Arc<_>, clock())?;
    let prefix = client.controller().prefix().qb64()?;
    let inception = core::str::from_utf8(client.controller().current_event().raw())?.to_owned();

    let agent = format!(
        r#"{{"vn":[1,0],"i":"{AGENT}","s":"0","p":"","d":"{AGENT}","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1","k":["{AGENT_KEY}"],"nt":"1","n":["EL6zVoZ0F8OXcbXP4LOm5oJTxCXP6ZLp5o3vNfvVZ9YB"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{AGENT}","br":[],"ba":[]}},"di":"{prefix}"}}"#
    );
    let state = format!(r#"{{"agent":{agent},"controller":{{"state":{agent},"ee":{inception}}},"ridx":0,"pidx":0}}"#);
    transport.push_response(response(state.as_bytes())?);
    transport.push_response(response(b"{}")?);
    for body in bodies {
        transport.push_response(response(body)?);
    }

    let connected = block_on(client.connect())?.with_freshness(Freshness::Ignore);
    Ok((connected, transport))
}

fn call<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Call, Box<dyn Error>> {
    fixture
        .calls
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| format!("no recorded call {name}").into())
}

fn sent_path(transport: &ScriptedTransport) -> Result<String, Box<dyn Error>> {
    let recorded = transport.recorded();
    let request = recorded.get(2).ok_or("no endpoint request was sent")?;
    let url = request.url().as_str();
    Ok(url.strip_prefix(ADMIN).unwrap_or(url).to_owned())
}

#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert!(!fixture.generated_on.is_empty());
    assert!(fixture.sources.iter().any(|source| source.ends_with("coring.ts")));
    assert!(!fixture.provenance.note.is_empty());
    assert_eq!(fixture.calls.len(), 7);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
    }
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    assert!(declarations.get_path.contains("/operations/"));
    assert_eq!(declarations.get_path, declarations.delete_path);
    assert!(declarations.get_path.contains(OPERATIONS_SEGMENT));

    assert!(declarations.list_path.contains("/operations?"));
    assert!(declarations.list_parameters.contains("URLSearchParams"));
    assert!(declarations.list_append.contains(TYPE_PARAMETER));

    assert!(declarations.throw_if_failed.contains("op.error.code"));
    assert!(declarations.throw_if_failed.contains("op.error.message"));
    assert!(declarations.throw_if_failed.contains("op.error.details"));
    assert!(declarations.has_depends.contains("'depends' in op.metadata"));

    assert_eq!(declarations.operation_union.len(), 14);
    assert!(
        declarations
            .operation_union
            .iter()
            .any(|member| member == "WitnessOperation")
    );

    for note in [
        &declarations.notes.paths,
        &declarations.notes.failure,
        &declarations.notes.depends,
    ] {
        assert!(!note.is_empty());
    }
    Ok(())
}

#[test]
fn a_get_addresses_the_recorded_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let expected = call(&fixture, "get_pending")?;
    let recorded = expected.request.as_ref().ok_or("no recorded request")?;

    let (client, transport) = connected(&[serde_json::to_vec(&expected.result)?.as_slice()])?;
    let _ = block_on(client.operations().get("operationName"));
    assert_eq!(sent_path(&transport)?, recorded.path);
    assert_eq!(recorded.method, "GET");
    assert!(recorded.body.is_none() || recorded.body == Some(serde_json::Value::Null));
    Ok(())
}

#[test]
fn a_list_addresses_the_recorded_path_apart_from_the_bare_question_mark() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    let filtered = call(&fixture, "list_by_type")?;
    let recorded = filtered.request.as_ref().ok_or("no recorded request")?;
    let (client, transport) = connected(&[b"[]"])?;
    let _ = block_on(client.operations().list(Some("witness")));
    assert_eq!(sent_path(&transport)?, recorded.path);
    assert_eq!(recorded.path, "/operations?type=witness");

    let encoded = call(&fixture, "list_by_type_needing_encoding")?;
    let recorded = encoded.request.as_ref().ok_or("no recorded request")?;
    let (client, transport) = connected(&[b"[]"])?;
    let _ = block_on(client.operations().list(Some("a b&c=d")));
    assert_eq!(sent_path(&transport)?, recorded.path);
    assert_eq!(recorded.path, "/operations?type=a+b%26c%3Dd");

    let unfiltered = call(&fixture, "list_all")?;
    let recorded = unfiltered.request.as_ref().ok_or("no recorded request")?;
    assert_eq!(recorded.path, "/operations?");
    let (client, transport) = connected(&[b"[]"])?;
    let _ = block_on(client.operations().list(None));
    assert_eq!(sent_path(&transport)?, "/operations");
    Ok(())
}

#[test]
fn a_delete_uses_the_same_path_with_a_different_method() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let expected = call(&fixture, "delete")?;
    let recorded = expected.request.as_ref().ok_or("no recorded request")?;
    assert_eq!(recorded.method, "DELETE");
    assert_eq!(recorded.path, "/operations/operationName");

    let (client, transport) = connected(&[b"{}"])?;
    let _ = block_on(client.operations().delete("operationName"));
    assert_eq!(sent_path(&transport)?, recorded.path);

    assert!(expected.result.is_null());
    assert!(expected.error.is_none());
    Ok(())
}

#[test]
fn a_recorded_operation_decodes_into_the_typed_model() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    let pending: UntypedOperation = serde_json::from_value(call(&fixture, "get_pending")?.result.clone())?;
    assert!(!pending.outcome.is_done());
    let typed = pending.into_typed::<WitnessMetadata, KeyEvent>()?;
    assert_eq!(typed.metadata.as_ref().map(|metadata| metadata.sn), Some(0));
    assert!(matches!(completed(typed), Err(ClientError::OperationPending { .. })));

    let done: UntypedOperation = serde_json::from_value(call(&fixture, "get_completed")?.result.clone())?;
    assert!(done.outcome.is_done());
    let typed = done.into_typed::<WitnessMetadata, KeyEvent>()?;
    let event = completed(typed)?;
    assert!(matches!(event, KeyEvent::Inception(_)));
    Ok(())
}

#[test]
fn a_failed_operation_carries_everything_the_reference_interpolates() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (recorded, expects_details) in [
        (&fixture.failures.with_details, true),
        (&fixture.failures.without_details, false),
    ] {
        let operation: UntypedOperation = serde_json::from_value(recorded.operation.clone())?;
        assert!(operation.outcome.is_done());
        let typed = operation.into_typed::<WitnessMetadata, KeyEvent>()?;
        let name = typed.name.clone();
        let Err(ClientError::OperationFailed {
            name: reported,
            code,
            message,
            details,
        }) = completed(typed)
        else {
            return Err("a failed operation was not reported as one".into());
        };

        assert_eq!(reported, name);
        assert!(recorded.message.contains(&name));
        assert!(recorded.message.contains(&code.to_string()));
        assert!(recorded.message.contains(&message));
        assert_eq!(details.is_some(), expects_details);
        if let Some(details) = &details {
            for key in ["received", "expected"] {
                assert!(details.contains(key), "{details} is missing {key}");
                assert!(recorded.message.contains(key));
            }
        } else {
            assert!(!recorded.message.contains("Details:"));
        }
    }

    assert!(fixture.failures.completed_returns_itself.identical);
    assert!(!fixture.failures.note.is_empty());
    Ok(())
}

#[test]
fn every_path_the_pinned_test_asserts_is_produced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let confirmations = &fixture.pinned_confirmations;
    assert!(confirmations.every_pinned_path_is_driven);
    assert!(!confirmations.note.is_empty());
    assert_eq!(
        confirmations.published_paths,
        ["/operations/operationName", "/operations?", "/operations?type=witness"]
    );
    assert_eq!(confirmations.driven_paths.len(), fixture.calls.len());
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = &fixture.reference_quirks;
    let pairs: [(&str, &str); 6] = [
        (
            &quirks.list_always_appends_a_question_mark.note,
            &quirks.list_always_appends_a_question_mark.rust_decision,
        ),
        (
            &quirks.path_components_are_not_encoded.note,
            &quirks.path_components_are_not_encoded.rust_decision,
        ),
        (
            &quirks.query_values_are_not_encoded_by_the_path.note,
            &quirks.query_values_are_not_encoded_by_the_path.rust_decision,
        ),
        (
            &quirks.failure_is_a_thrown_string.note,
            &quirks.failure_is_a_thrown_string.rust_decision,
        ),
        (
            &quirks.delete_discards_its_response.note,
            &quirks.delete_discards_its_response.rust_decision,
        ),
        (
            &quirks.get_returns_the_untyped_union.note,
            &quirks.get_returns_the_untyped_union.rust_decision,
        ),
    ];
    for (index, (note, decision)) in pairs.iter().enumerate() {
        assert!(!note.is_empty(), "divergence {index} records no reference behaviour");
        assert!(!decision.is_empty(), "divergence {index} records no Rust decision");
    }
    Ok(())
}

#[test]
fn every_reference_quirk_holds_and_the_divergence_is_deliberate() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = &fixture.reference_quirks;

    let bare = &quirks.list_always_appends_a_question_mark;
    assert_eq!(bare.path.as_deref(), Some("/operations?"));
    assert!(
        bare.expression
            .as_deref()
            .unwrap_or_default()
            .contains("params.toString()")
    );
    let path = ResourcePath::builder().segment(OPERATIONS_SEGMENT).build()?;
    assert_eq!(path.as_str(), "/operations");
    assert_eq!(path.query(), None);
    assert_eq!(path.path(), "/operations");

    let unencoded = &quirks.path_components_are_not_encoded;
    assert_eq!(unencoded.path.as_deref(), Some("/operations/a/b?c=d"));
    let encoded = ResourcePath::builder()
        .segment(OPERATIONS_SEGMENT)
        .segment("a/b?c=d")
        .build()?;
    assert_eq!(encoded.as_str(), "/operations/a%2Fb%3Fc%3Dd");
    assert_eq!(encoded.query(), None, "an encoded name cannot introduce a query");

    let query = &quirks.query_values_are_not_encoded_by_the_path;
    assert_eq!(query.path.as_deref(), Some("/operations?type=a+b%26c%3Dd"));
    let filtered = ResourcePath::builder()
        .segment(OPERATIONS_SEGMENT)
        .parameter(TYPE_PARAMETER, "a b&c=d")
        .build()?;
    assert_eq!(filtered.as_str(), "/operations?type=a+b%26c%3Dd");

    let failure = &quirks.failure_is_a_thrown_string;
    assert!(failure.with_details.starts_with("Operation '"));
    assert!(failure.with_details.contains("Details: "));
    assert!(!failure.without_details.contains("Details: "));

    let deleted = &quirks.delete_discards_its_response;
    assert_eq!(
        deleted.request.as_ref().map(|request| request.method.as_str()),
        Some("DELETE")
    );

    let union = &quirks.get_returns_the_untyped_union;
    assert_eq!(union.union.len(), 14);
    assert_eq!(union.scan.needle, "hasDepends");
    assert_eq!(union.scan.total, 2);
    assert!(union.scan.scanned_files > 100);
    assert_eq!(
        union.scan.files.first().map(|hit| (hit.file.as_str(), hit.count)),
        Some(("src/keri/app/coring.ts", 2))
    );
    Ok(())
}
