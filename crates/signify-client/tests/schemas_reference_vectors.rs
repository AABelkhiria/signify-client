//! Exact schema-endpoint vectors recorded from the pinned reference's own `Schemas`.
//!
//! A scan of every pinned `.ts` file finds this family in four of them, and **no unit test
//! exercises either call**: `clienting.test.ts` asserts only that `client.schemas()` is a
//! `Schemas`. The real usage is `test-integration/credentials.test.ts`, which reads both vLEI
//! schemas by SAID and lists them against a live KERIA. So the vectors here are the reference
//! driven directly, with the two SAIDs that integration test uses — the paths a real deployment
//! sees.

use std::collections::BTreeMap;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::schemas::SCHEMA_SEGMENT;
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
use signify_keri::said::Said;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-schemas/v1.json");

const ADMIN: &str = "http://127.0.0.1:3901";
const BOOT: &str = "http://127.0.0.1:3903";
const PASSCODE: &str = "0123456789abcdefghijk";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";

/// The two vLEI schema SAIDs `test-integration/credentials.test.ts` reads.
const QVI: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const LEGAL_ENTITY: &str = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY";

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
    qvi_schema_said: String,
    le_schema_said: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    get_path: String,
    get_method: String,
    list_path: String,
    list_method: String,
    get_return: String,
    class_members: Vec<String>,
    schema_type: String,
    files_naming_schemas: Vec<String>,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
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
    files_naming_schemas: Vec<String>,
    assertions: BTreeMap<String, Vec<String>>,
    qvi_schema_said: String,
    le_schema_said: String,
    driven_paths: Vec<String>,
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

fn request_of<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a RecordedRequest, Box<dyn Error>> {
    call(fixture, name)?
        .request
        .as_ref()
        .ok_or_else(|| format!("call {name} recorded no request").into())
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
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("credentialing.ts"))
    );
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert!(!fixture.provenance.controller_prefix.is_empty());
    assert_eq!(fixture.provenance.qvi_schema_said, QVI);
    assert_eq!(fixture.provenance.le_schema_said, LEGAL_ENTITY);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 6);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        // The reference refuses none of them, the wrong-shaped answer included.
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
        // Neither call sends a body, whichever it is.
        let request = entry.request.as_ref().ok_or("a recorded call made no request")?;
        assert_eq!(request.body, None, "call {} sent a body", entry.name);
    }
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // The segment is singular in both paths, where the class and accessor are plural.
    assert_eq!(declarations.get_path, "path = `/schema/${said}`");
    assert_eq!(declarations.list_path, "path = `/schema`");
    assert!(declarations.get_path.contains(SCHEMA_SEGMENT));
    assert!(!declarations.get_path.contains("/schemas/"));
    assert!(!declarations.get_path.contains("encodeURIComponent"));
    assert_eq!(declarations.get_method, "method = 'GET'");
    assert_eq!(declarations.list_method, "method = 'GET'");

    // The cast this port replaces with a decode, and the whole four-member class.
    assert_eq!(declarations.get_return, "await res.json()");
    assert_eq!(declarations.class_members, ["client", "<constructor>", "get", "list"]);

    // The response type: ten required fields, one of them an open map.
    for field in [
        "$id",
        "$schema",
        "credentialType",
        "properties",
        "additionalProperties",
        "required",
    ] {
        assert!(declarations.schema_type.contains(field), "the schema lacks {field}");
    }
    assert!(declarations.schema_type.contains("[key: string]: unknown"));
    assert!(declarations.notes.is_object());
    Ok(())
}

#[test]
fn the_pinned_tree_exercises_this_family_only_in_integration() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;
    // Four files name it: two source, one unit test, one integration test.
    assert_eq!(
        pinned.files_naming_schemas,
        [
            "src/keri/app/clienting.ts",
            "src/keri/app/credentialing.ts",
            "test-integration/credentials.test.ts",
            "test/app/clienting.test.ts",
        ]
    );
    assert_eq!(pinned.files_naming_schemas, fixture.declarations.files_naming_schemas);
    // The unit test asserts the accessor's type and nothing else.
    let unit = pinned
        .assertions
        .get("test/app/clienting.test.ts")
        .ok_or("no recorded unit-test assertions")?;
    assert_eq!(unit.len(), 1);
    assert!(unit.iter().any(|line| line.contains("instanceof Schemas")));

    // The integration test is where both calls are actually made, and what it checks is that a
    // schema comes back under the SAID it was asked for.
    let integration = pinned
        .assertions
        .get("test-integration/credentials.test.ts")
        .ok_or("no recorded integration assertions")?;
    assert_eq!(integration.len(), 6);
    assert!(integration.iter().any(|line| line.contains("schemas().list()")));
    assert!(integration.iter().any(|line| line.contains("$id, QVI_SCHEMA_SAID")));
    assert!(integration.iter().any(|line| line.contains("holderSchemas.length, 2")));
    assert!(!pinned.note.is_empty());

    // Both SAIDs the integration test uses are valid qualified digests, which is what lets this
    // port take a `Said` rather than a string without narrowing the reference's reach.
    assert!(Said::from_qb64(&pinned.qvi_schema_said).is_ok());
    assert!(Said::from_qb64(&pinned.le_schema_said).is_ok());

    // Only two distinct addresses exist in the whole family, however many calls are made.
    assert_eq!(
        pinned.driven_paths,
        [
            "/schema",
            "/schema/E/../schema?x=1#y",
            &format!("/schema/{QVI}"),
            &format!("/schema/{LEGAL_ENTITY}"),
        ]
        .map(ToString::to_string)
    );
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 5);
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
// The calls.
// ---------------------------------------------------------------------------

#[test]
fn both_recorded_reads_address_the_recorded_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, said) in [("get_qvi", QVI), ("get_legal_entity", LEGAL_ENTITY)] {
        let recorded = request_of(&fixture, name)?;
        let answer = serde_json::to_vec(&call(&fixture, name)?.result)?;

        let (client, transport) = connected(&[&answer])?;
        let schema = block_on(client.schemas().get(&Said::from_qb64(said)?))?;
        let (path, method, body) = sent(&transport)?;
        assert_eq!(path, recorded.path);
        assert_eq!(path, format!("/schema/{said}"));
        assert_eq!(method, recorded.method);
        assert_eq!(method, "GET");
        assert_eq!(body, None);

        // The agent's answer decodes into what the reference returns unchecked.
        assert_eq!(schema.id, said);
        assert!(!schema.credential_type.is_empty());
    }
    Ok(())
}

#[test]
fn a_listing_addresses_the_constant_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list")?;
    let answer = serde_json::to_vec(&call(&fixture, "list")?.result)?;

    let (client, transport) = connected(&[&answer])?;
    let schemas = block_on(client.schemas().list())?;
    let (path, method, body) = sent(&transport)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, "/schema");
    assert_eq!(method, "GET");
    assert_eq!(body, None);
    // The integration test asserts a count of two; this is that same pair.
    assert_eq!(schemas.len(), 2);
    assert_eq!(schemas.first().map(|schema| schema.id.as_str()), Some(QVI));
    assert_eq!(schemas.get(1).map(|schema| schema.id.as_str()), Some(LEGAL_ENTITY));

    // An empty listing addresses the very same path — there is no input to change it.
    let empty = request_of(&fixture, "list_empty")?;
    assert_eq!(empty.path, recorded.path);
    let answer = serde_json::to_vec(&call(&fixture, "list_empty")?.result)?;
    let (client, _) = connected(&[&answer])?;
    assert!(block_on(client.schemas().list())?.is_empty());
    Ok(())
}

#[test]
fn a_said_that_would_escape_the_path_is_unrepresentable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "get_said_needing_encoding")?;
    // The reference sent `/schema/E/../schema?x=1#y`: three extra segments, a query, and a
    // fragment, from one argument.
    assert_eq!(recorded.path, "/schema/E/../schema?x=1#y");
    assert!(Said::from_qb64("E/../schema?x=1#y").is_err());
    Ok(())
}

#[test]
fn a_wrong_shaped_answer_is_refused_where_the_reference_casts_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "get_wrong_shape")?;
    // The reference returned an object with only `$id`, typed `Schema` at compile time only.
    assert_eq!(recorded.error, None);
    assert_eq!(recorded.result.get("$id").and_then(Value::as_str), Some(QVI));
    assert_eq!(recorded.result.as_object().map(serde_json::Map::len), Some(1));

    let answer = serde_json::to_vec(&recorded.result)?;
    let (client, transport) = connected(&[&answer])?;
    let outcome = block_on(client.schemas().get(&Said::from_qb64(QVI)?));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "a schema missing nine required fields was not refused: {outcome:?}"
    );
    // The request still went out, so this refuses the answer rather than the call.
    assert_eq!(sent(&transport)?.0, format!("/schema/{QVI}"));
    Ok(())
}

#[test]
fn nothing_checks_the_schema_came_back_under_the_said_asked_for() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference's own integration test makes this check at the call site, and `Schemas.get`
    // does not — so an agent answering with a different schema is not challenged here either.
    let answer = serde_json::to_vec(&call(&fixture, "get_legal_entity")?.result)?;
    let (client, _) = connected(&[&answer])?;
    let schema = block_on(client.schemas().get(&Said::from_qb64(QVI)?))?;
    assert_eq!(schema.id, LEGAL_ENTITY);
    assert_ne!(schema.id, QVI);
    // Which is exactly why the fixture records the integration assertion as the check that
    // matters, and why the method's own documentation tells a caller to make it.
    assert!(
        fixture
            .pinned_confirmations
            .assertions
            .values()
            .flatten()
            .any(|line| line.contains("$id, QVI_SCHEMA_SAID"))
    );
    Ok(())
}
