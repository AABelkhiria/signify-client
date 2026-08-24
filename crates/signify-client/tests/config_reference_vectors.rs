//! Exact configuration-endpoint vectors recorded from the pinned reference's own `Config`.
//!
//! `Config` takes a whole `SignifyClient`, so the generator drives the real client with
//! `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would — the
//! arrangement Roadmap 6.4's fixture established and 6.7's reused.
//!
//! The address carries no caller input, so every one of the five recorded answers produces the
//! same request. What the vectors are really about is the *response*: the reference casts it and
//! this port decodes it, and one of the five recorded answers is a shape only one of the two
//! refuses.

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::config::CONFIG_SEGMENT;
use signify_client::error::ClientError;
use signify_crypto::signer::Signer;
use signify_crypto::verifier::KeyTransferability;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::authentication::RequestSigner;
use signify_http::signature::input::{RequestTarget, default_components};
use signify_http::signature::timestamp::SignifyTimestamp;
use signify_http::transport::{Method, Request, Response, StatusCode, Transport, TransportError, TransportFuture};
use signify_keri::manager::DerivationCost;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-config/v1.json");

const ADMIN: &str = "http://127.0.0.1:3901";
const BOOT: &str = "http://127.0.0.1:3903";
const PASSCODE: &str = "0123456789abcdefghijk";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";

/// The agent seed Roadmap 6.4's fixture pinned.
const AGENT_SEED: [u8; 32] = [
    187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192, 61, 145, 222, 110, 59, 160, 152, 2, 72, 122, 87,
    143, 109, 39, 98, 153, 192, 148,
];

const FIXED_MILLIS: u64 = 1_700_000_000_123;

// ---------------------------------------------------------------------------
// Fixture model.
// ---------------------------------------------------------------------------

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
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    boot_url: String,
    fixed_clock_ms: u64,
    agent_prefix: String,
    controller_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    config_path: String,
    config_method: String,
    config_fetch: String,
    config_return: String,
    config_members: Vec<String>,
    agent_config_schema: String,
    agent_config_uses: Scan,
    config_accessor_uses: Scan,
    notes: Value,
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

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    answer: Value,
    request: Option<RecordedRequest>,
    result: Value,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    published_paths: Vec<String>,
    driven_paths: Vec<String>,
    every_pinned_path_is_driven: bool,
    note: String,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

fn call<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Call, Box<dyn Error>> {
    fixture
        .calls
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| format!("no recorded call {name}").into())
}

// ---------------------------------------------------------------------------
// A KERIA agent, answering exactly as the generator's mocked `fetch` did.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct AgentTransport {
    answers: Mutex<Vec<Vec<u8>>>,
    recorded: Mutex<Vec<Request>>,
}

impl AgentTransport {
    fn new(answers: &[&[u8]]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().rev().map(|body| body.to_vec()).collect()),
            recorded: Mutex::new(Vec::new()),
        })
    }

    fn requests(&self) -> Vec<Request> {
        self.recorded.lock().map_or_else(|_| Vec::new(), |guard| guard.clone())
    }

    fn answer(&self, request: &Request) -> Result<Response, TransportError> {
        let body = self
            .answers
            .lock()
            .map_err(|_| TransportError::signing("the scripted answers are poisoned"))?
            .pop()
            .unwrap_or_else(|| b"{}".to_vec());
        signed_response(request.method(), request.url().path(), body)
            .map_err(|error| TransportError::signing(error.to_string()))
    }
}

impl Transport for AgentTransport {
    fn execute(&self, request: Request) -> TransportFuture<'_> {
        let answer = {
            if let Ok(mut guard) = self.recorded.lock() {
                guard.push(request.clone());
            }
            self.answer(&request)
        };
        let future: Pin<Box<dyn Future<Output = Result<Response, TransportError>> + Send + '_>> =
            Box::pin(async move { answer });
        future
    }
}

fn agent_signer() -> Result<Signer, Box<dyn Error>> {
    Ok(Signer::from_seed(&AGENT_SEED, KeyTransferability::NonTransferable)?)
}

fn signed_response(method: Method, path: &str, body: Vec<u8>) -> Result<Response, Box<dyn Error>> {
    let stamp = SignifyTimestamp::from_unix(Duration::from_millis(FIXED_MILLIS))?;
    let mut headers = Headers::new();
    headers.insert(HeaderName::new("signify-resource")?, HeaderValue::new(AGENT)?)?;
    headers.insert(HeaderName::new("signify-timestamp")?, stamp.to_header_value()?)?;
    let signer = RequestSigner::new(agent_signer()?);
    let input = signer.signature_input(default_components()?, stamp.created())?;
    let target = RequestTarget::new(method.as_str(), path)?;
    signer.sign(&input, &target, &headers)?.apply(&mut headers)?;
    Ok(Response::new(StatusCode::new(202)?, headers, body)?)
}

fn clock() -> Arc<dyn Clock> {
    Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(FIXED_MILLIS),
    ))
}

fn block_on<F: Future>(future: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
}

fn agent_verification_key() -> String {
    agent_signer()
        .and_then(|signer| Ok(signer.verifier().qb64()?))
        .unwrap_or_default()
}

fn agent_state(controller: &str, inception: &str) -> String {
    let agent = format!(
        r#"{{"vn":[1,0],"i":"{AGENT}","s":"0","p":"","d":"{AGENT}","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1","k":["{key}"],"nt":"1","n":["EL6zVoZ0F8OXcbXP4LOm5oJTxCXP6ZLp5o3vNfvVZ9YB"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{AGENT}","br":[],"ba":[]}},"di":"{controller}"}}"#,
        key = agent_verification_key()
    );
    format!(r#"{{"agent":{agent},"controller":{{"state":{agent},"ee":{inception}}},"ridx":0,"pidx":0}}"#)
}

fn connected(bodies: &[&[u8]]) -> Result<(ConnectedClient, Arc<AgentTransport>), Box<dyn Error>> {
    let configuration = || {
        ClientConfig::new(ADMIN, PASSCODE)
            .and_then(|config| config.with_boot_url(BOOT))
            .map(|config| config.with_derivation_cost(DerivationCost::Ephemeral))
    };
    let probe = SignifyClient::new(
        configuration()?,
        AgentTransport::new(&[]) as Arc<dyn Transport>,
        clock(),
    )?;
    let prefix = probe.controller().prefix().qb64()?;
    let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();

    let state = agent_state(&prefix, &inception);
    let mut answers: Vec<&[u8]> = vec![state.as_bytes(), b"{}"];
    answers.extend_from_slice(bodies);
    let transport = AgentTransport::new(&answers);

    let client = SignifyClient::new(configuration()?, Arc::clone(&transport) as Arc<dyn Transport>, clock())?;
    Ok((block_on(client.connect())?, transport))
}

/// Returns the path, method, and body of the first endpoint request after connecting.
fn sent(transport: &AgentTransport) -> Result<(String, String, Option<String>), Box<dyn Error>> {
    let recorded = transport.requests();
    // Two requests are the lifecycle's: the state read and the delegation approval.
    let request = recorded.get(2).ok_or("no endpoint request was sent")?;
    let url = request.url().as_str();
    let path = url.strip_prefix(ADMIN).unwrap_or(url).to_owned();
    let body = request
        .body()
        .map(|bytes| String::from_utf8(bytes.to_vec()))
        .transpose()?;
    Ok((path, request.method().as_str().to_owned(), body))
}

// ---------------------------------------------------------------------------
// Manifest and provenance.
// ---------------------------------------------------------------------------

#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert!(!fixture.generated_on.is_empty());
    assert!(fixture.sources.iter().any(|source| source.ends_with("coring.ts")));
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert!(!fixture.provenance.controller_prefix.is_empty());
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 5);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        // The reference refuses none of the five — including the one whose shape is wrong.
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
    }
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // A template literal with nothing interpolated: the only such address in the port.
    assert_eq!(declarations.config_path, "path = `/config`");
    assert!(declarations.config_path.contains(CONFIG_SEGMENT));
    assert!(!declarations.config_path.contains("${"));
    assert_eq!(declarations.config_method, "method = 'GET'");
    assert!(declarations.config_fetch.contains("null"));

    // The cast this port replaces with a decode.
    assert_eq!(declarations.config_return, "await res.json()");

    // The whole class is three members, one of which is the constructor.
    assert_eq!(declarations.config_members, ["client", "<constructor>", "get"]);

    // The response type: one optional field, and nothing else in the schema.
    assert_eq!(declarations.agent_config_schema, "AgentConfig: { iurls?: string[]; };");
    assert_eq!(declarations.agent_config_uses.needle, "AgentConfig");
    assert_eq!(declarations.agent_config_uses.scanned_files, 117);
    assert!(
        declarations
            .agent_config_uses
            .files
            .iter()
            .any(|hit| hit.file.ends_with("keria-api-schema.ts") && hit.count == 1)
    );
    assert!(declarations.config_accessor_uses.total >= 1);
    assert!(declarations.notes.is_object());
    Ok(())
}

#[test]
fn the_one_pinned_path_is_produced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(fixture.pinned_confirmations.every_pinned_path_is_driven);
    assert_eq!(fixture.pinned_confirmations.published_paths, ["/config"]);
    assert_eq!(fixture.pinned_confirmations.driven_paths, ["/config"]);
    assert!(!fixture.pinned_confirmations.note.is_empty());
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 4);
    for (name, quirk) in quirks {
        let entry = quirk.as_object().ok_or("a divergence is not an object")?;
        for label in ["note", "rust_decision"] {
            assert!(
                entry
                    .get(label)
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.is_empty()),
                "divergence {name} records no {label}"
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The call.
// ---------------------------------------------------------------------------

#[test]
fn a_configuration_read_addresses_the_recorded_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "config_with_introductions")?;
    let request = recorded.request.as_ref().ok_or("no recorded request")?;
    let answer = serde_json::to_vec(&recorded.answer)?;

    let (client, transport) = connected(&[&answer])?;
    let config = block_on(client.agent_config().get())?;

    let (path, method, body) = sent(&transport)?;
    assert_eq!(path, request.path);
    assert_eq!(path, "/config");
    assert_eq!(method, request.method);
    assert_eq!(method, "GET");
    // The reference passes `null` as its data and `fetch` sends no body for a GET either way.
    assert_eq!(body, None);
    assert_eq!(request.body, None);

    // The answer decodes into what the reference returns unchecked.
    assert_eq!(
        config.introduction_urls.as_ref().map(Vec::len),
        recorded.result.get("iurls").and_then(Value::as_array).map(Vec::len)
    );
    Ok(())
}

#[test]
fn every_recorded_answer_produces_the_same_request() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The address carries no caller input, so nothing an agent says can change what was asked.
    for entry in &fixture.calls {
        let request = entry.request.as_ref().ok_or("no recorded request")?;
        assert_eq!(request.path, "/config", "call {} addressed something else", entry.name);
        assert_eq!(request.method, "GET");
        assert_eq!(request.body, None);
    }
    Ok(())
}

#[test]
fn an_absent_list_and_an_empty_one_stay_distinguishable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    let absent = call(&fixture, "config_absent_field")?;
    assert_eq!(absent.result, serde_json::json!({}));
    let (client, _) = connected(&[&serde_json::to_vec(&absent.answer)?])?;
    let config = block_on(client.agent_config().get())?;
    assert_eq!(config.introduction_urls, None);

    let empty = call(&fixture, "config_empty_list")?;
    assert_eq!(empty.result, serde_json::json!({ "iurls": [] }));
    let (client, _) = connected(&[&serde_json::to_vec(&empty.answer)?])?;
    let config = block_on(client.agent_config().get())?;
    assert_eq!(config.introduction_urls, Some(Vec::new()));
    Ok(())
}

#[test]
fn an_undeclared_field_is_ignored_where_the_reference_keeps_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "config_unknown_fields")?;
    // The reference hands the caller everything the agent sent, `curls` and `unknown` included.
    assert!(recorded.result.get("curls").is_some());
    assert!(recorded.result.get("unknown").is_some());

    let (client, _) = connected(&[&serde_json::to_vec(&recorded.answer)?])?;
    let config = block_on(client.agent_config().get())?;
    assert_eq!(config.introduction_urls, Some(Vec::new()));
    // Nothing undeclared survives, which is Roadmap 4.1's rule for a schema with no index
    // signature.
    assert_eq!(serde_json::to_string(&config)?, r#"{"iurls":[]}"#);
    Ok(())
}

#[test]
fn an_answer_of_the_wrong_shape_is_refused_where_the_reference_casts_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "config_wrong_shape")?;
    // The reference returned it unchanged, typed as an `AgentConfig` at compile time only.
    assert_eq!(recorded.error, None);
    assert_eq!(recorded.result.get("iurls").and_then(Value::as_str), Some("not-a-list"));

    let (client, transport) = connected(&[&serde_json::to_vec(&recorded.answer)?])?;
    let outcome = block_on(client.agent_config().get());
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "a wrong-shaped configuration was not refused: {outcome:?}"
    );
    // The request still went out, so this is a refusal of the answer rather than of the call.
    assert_eq!(sent(&transport)?.0, "/config");
    Ok(())
}
