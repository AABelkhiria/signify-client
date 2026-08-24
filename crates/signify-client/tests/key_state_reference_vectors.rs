//! Exact key-event and key-state vectors recorded from the pinned reference's own classes.
//!
//! `KeyEvents` and `KeyStates` each take a whole `SignifyClient`, so the generator drives the real
//! client with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent
//! would — the arrangement Roadmap 6.4's fixture established. This test rebuilds each call through
//! a connected client and compares the path, the method, and the body that actually go out.

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::key_events::{EVENTS_SEGMENT, PREFIX_PARAMETER};
use signify_client::endpoint::key_states::{KeyStateQuery, QUERIES_SEGMENT, QuerySequence, STATES_SEGMENT};
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
use signify_keri::prefix::IdentifierPrefix;
use signify_types::api::{OperationOutcome, Seal};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-key-state/v1.json");

const ADMIN: &str = "http://127.0.0.1:3901";
const BOOT: &str = "http://127.0.0.1:3903";
const PASSCODE: &str = "0123456789abcdefghijk";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";
const PREFIX_ONE: &str = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";
const PREFIX_TWO: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const ANCHOR_SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

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
    prefix_one: String,
    prefix_two: String,
    anchor_said: String,
    fixed_clock_ms: u64,
    agent_prefix: String,
    controller_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    events_path: String,
    states_path: String,
    states_list_path: String,
    queries_path: String,
    query_body: String,
    query_signature: Vec<String>,
    query_sn_doc: String,
    query_anchor_doc: String,
    query_metadata_sn: String,
    query_metadata_anchor: String,
    anchor_schema: String,
    seal_schema: String,
    key_event_record: String,
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
    published_paths: Vec<String>,
    driven_paths: Vec<String>,
    every_pinned_path_is_driven: bool,
    pinned_query_body: String,
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

fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
    Ok(IdentifierPrefix::from_qb64(text)?)
}

/// Runs one call and compares its request with the recorded one.
fn assert_matches_recorded(
    fixture: &Fixture,
    name: &str,
    answer: &[u8],
    run: impl FnOnce(&ConnectedClient),
) -> Result<(), Box<dyn Error>> {
    let recorded = request_of(fixture, name)?;
    let (client, transport) = connected(&[answer])?;
    run(&client);
    let (path, method, body) = sent(&transport)?;
    assert_eq!(path, recorded.path, "path mismatch for {name}");
    assert_eq!(method, recorded.method, "method mismatch for {name}");
    assert_eq!(body.as_deref(), recorded.body.as_deref(), "body mismatch for {name}");
    Ok(())
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
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("keria-api-schema.ts"))
    );
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.prefix_one, PREFIX_ONE);
    assert_eq!(fixture.provenance.prefix_two, PREFIX_TWO);
    assert_eq!(fixture.provenance.anchor_said, ANCHOR_SAID);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert!(!fixture.provenance.controller_prefix.is_empty());
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));
    assert_eq!(fixture.calls.len(), 11);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        // The reference refuses none of these — not an empty listing, not a prefix carrying
        // query delimiters, not a two-digit sequence number. Everything it validates, it
        // validates on the far side of the wire.
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
        assert!(entry.request.is_some(), "call {} made no request", entry.name);
    }
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // The three read paths, none of which encodes its prefix.
    assert!(declarations.events_path.contains("/events?pre=${pre}"));
    assert!(declarations.states_path.contains("/states?pre=${pre}"));
    assert!(declarations.states_list_path.contains("join('&')"));
    for raw in [
        &declarations.events_path,
        &declarations.states_path,
        &declarations.states_list_path,
    ] {
        assert!(!raw.contains("encodeURIComponent"), "{raw} unexpectedly encodes");
    }
    assert!(declarations.events_path.contains(EVENTS_SEGMENT));
    assert!(declarations.states_path.contains(STATES_SEGMENT));
    assert!(declarations.queries_path.contains(QUERIES_SEGMENT));
    assert!(declarations.events_path.contains(PREFIX_PARAMETER));

    // The body literal names only `pre`; the other two are added conditionally.
    assert!(declarations.query_body.contains("pre: pre"));
    assert!(!declarations.query_body.contains("sn:"));

    // The sequence number's three spellings, and the anchor's.
    assert_eq!(
        declarations.query_signature,
        ["pre: string", "sn?: string", "anchor?: any"]
    );
    assert!(declarations.query_sn_doc.contains("{number}"));
    assert!(declarations.query_anchor_doc.contains("{any}"));
    assert!(declarations.query_metadata_sn.contains("number"));
    assert!(declarations.query_metadata_anchor.contains("Anchor"));
    // The two shapes that share the name `anchor`: the schema's begins `pre`, a seal's begins `s`.
    assert!(declarations.anchor_schema.starts_with("pre:"));
    assert!(declarations.seal_schema.starts_with("s:"));
    assert!(declarations.key_event_record.contains("KeyEvent"));
    assert!(declarations.notes.is_object());
    Ok(())
}

#[test]
fn every_path_the_pinned_test_asserts_is_produced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(fixture.pinned_confirmations.every_pinned_path_is_driven);
    assert!(!fixture.pinned_confirmations.note.is_empty());
    for path in [
        format!("/events?pre={PREFIX_ONE}"),
        format!("/states?pre={PREFIX_ONE}"),
        format!("/states?pre={PREFIX_ONE}&pre={PREFIX_TWO}"),
        "/queries".to_owned(),
    ] {
        assert!(
            fixture.pinned_confirmations.published_paths.contains(&path),
            "{path} is not published by the pinned test"
        );
        assert!(
            fixture.pinned_confirmations.driven_paths.contains(&path),
            "{path} was not driven"
        );
    }
    // The body the pinned test inspects field by field.
    assert!(fixture.pinned_confirmations.pinned_query_body.contains(r#""sn":"1""#));
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 7);
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
// Reads.
// ---------------------------------------------------------------------------

#[test]
fn a_key_event_read_addresses_the_recorded_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let answer = serde_json::to_vec(&call(&fixture, "events_get")?.result)?;
    let expected = prefix(PREFIX_ONE)?;

    let recorded = request_of(&fixture, "events_get")?;
    let (client, transport) = connected(&[&answer])?;
    let events = block_on(client.key_events().get(&expected))?;
    let (path, method, body) = sent(&transport)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, "GET");
    assert_eq!(body, None, "a key-event read sends no body");

    // The agent's answer decodes into the typed record Roadmap 4.1 built.
    assert_eq!(events.len(), 1);
    let record = events.first().ok_or("no record decoded")?;
    assert!(!record.atc.is_empty());
    Ok(())
}

#[test]
fn a_key_state_read_addresses_the_recorded_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let answer = serde_json::to_vec(&call(&fixture, "states_get")?.result)?;
    let expected = prefix(PREFIX_ONE)?;

    let recorded = request_of(&fixture, "states_get")?;
    let (client, transport) = connected(&[&answer])?;
    let states = block_on(client.key_states().get(&expected))?;
    let (path, method, body) = sent(&transport)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, "GET");
    assert_eq!(body, None);
    assert_eq!(states.len(), 1);
    assert_eq!(states.first().map(|state| state.identifier.as_str()), Some(PREFIX_ONE));
    Ok(())
}

#[test]
fn a_listing_repeats_the_parameter_in_the_recorded_order() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let answer = serde_json::to_vec(&call(&fixture, "states_list")?.result)?;
    let recorded = request_of(&fixture, "states_list")?;

    let (client, transport) = connected(&[&answer])?;
    let states = block_on(client.key_states().list(&[prefix(PREFIX_ONE)?, prefix(PREFIX_TWO)?]))?;
    let (path, method, _) = sent(&transport)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, format!("/states?pre={PREFIX_ONE}&pre={PREFIX_TWO}"));
    assert_eq!(method, "GET");
    assert_eq!(states.len(), 2);

    // A one-prefix listing is exactly a read, which the reference's own paths confirm.
    let single = request_of(&fixture, "states_list_one")?;
    assert_eq!(single.path, request_of(&fixture, "states_get")?.path);
    Ok(())
}

#[test]
fn an_empty_listing_is_refused_rather_than_addressing_a_bare_question_mark() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference sends `/states?` and asks for nothing at all.
    assert_eq!(request_of(&fixture, "states_list_empty")?.path, "/states?");

    let (client, transport) = connected(&[b"[]"])?;
    let outcome = block_on(client.key_states().list(&[]));
    assert!(matches!(outcome, Err(ClientError::EmptyKeyStateListing)));
    // Nothing was sent: only the two lifecycle requests were made.
    assert_eq!(transport.requests().len(), 2);
    Ok(())
}

// ---------------------------------------------------------------------------
// Queries.
// ---------------------------------------------------------------------------

#[test]
fn a_query_with_a_sequence_number_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let answer = serde_json::to_vec(&call(&fixture, "query_sequence_only")?.result)?;
    assert_matches_recorded(&fixture, "query_sequence_only", &answer, |client| {
        let Ok(pre) = prefix(PREFIX_ONE) else { return };
        let _ = block_on(
            client
                .key_states()
                .query(&KeyStateQuery::at(pre, QuerySequence::Decimal(1))),
        );
    })
}

#[test]
fn a_query_with_neither_argument_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let answer = serde_json::to_vec(&call(&fixture, "query_prefix_only")?.result)?;
    assert_matches_recorded(&fixture, "query_prefix_only", &answer, |client| {
        let Ok(pre) = prefix(PREFIX_ONE) else { return };
        let _ = block_on(client.key_states().query(&KeyStateQuery::latest(pre)));
    })
}

#[test]
fn a_query_anchored_on_a_seal_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let answer = serde_json::to_vec(&call(&fixture, "query_seal_anchor")?.result)?;
    // This is the shape every integration caller passes, and the only one a live KERIA has seen.
    assert_matches_recorded(&fixture, "query_seal_anchor", &answer, |client| {
        let Ok(pre) = prefix(PREFIX_ONE) else { return };
        let anchor = Seal {
            identifier: Some(PREFIX_TWO.to_owned()),
            sequence_number: "0".to_owned(),
            digest: PREFIX_TWO.to_owned(),
        };
        let _ = block_on(client.key_states().query(&KeyStateQuery::anchoring(pre, anchor)));
    })
}

#[test]
fn the_pinned_query_carries_an_anchor_this_port_cannot_express() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "query_pinned")?;
    let body: Value = serde_json::from_str(recorded.body.as_deref().unwrap_or("null"))?;

    // The pinned unit test passes a bare SAID string where every integration caller passes a seal.
    // It is recorded verbatim and is unrepresentable here: `anchor` is a `Seal`.
    assert_eq!(body.get("anchor").and_then(Value::as_str), Some(ANCHOR_SAID));
    assert!(body.get("anchor").and_then(Value::as_object).is_none());

    // The rest of that same body — the prefix and the sequence number — reproduces exactly.
    let answer = serde_json::to_vec(&call(&fixture, "query_pinned")?.result)?;
    let (client, transport) = connected(&[&answer])?;
    let _ = block_on(
        client
            .key_states()
            .query(&KeyStateQuery::at(prefix(PREFIX_ONE)?, QuerySequence::Decimal(1))),
    );
    let (path, method, sent_body) = sent(&transport)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, "POST");
    assert_eq!(
        sent_body.as_deref(),
        Some(r#"{"pre":"EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX","sn":"1"}"#)
    );
    Ok(())
}

#[test]
fn a_query_answer_decodes_into_the_typed_operation() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let answer = serde_json::to_vec(&call(&fixture, "query_prefix_only")?.result)?;
    let (client, _) = connected(&[&answer])?;
    let operation = block_on(client.key_states().query(&KeyStateQuery::latest(prefix(PREFIX_ONE)?)))?;

    // Roadmap 4.1 replaced the three-way `QueryOperation` union with one generic type, so the
    // pending state is a variant rather than a `done: false` a caller has to remember to check.
    assert_eq!(operation.name, format!("query.{PREFIX_ONE}"));
    assert!(matches!(operation.outcome, OperationOutcome::Pending));
    let metadata = operation.metadata.ok_or("the recorded operation carried no metadata")?;
    assert_eq!(metadata.pre, PREFIX_ONE);
    assert_eq!(metadata.sn, 1);
    Ok(())
}

#[test]
fn a_two_digit_sequence_number_is_where_the_bases_part_company() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "query_two_digit_sequence")?;
    // The reference passes its string through untouched, so its own body says nothing about base.
    assert!(
        recorded
            .body
            .as_deref()
            .is_some_and(|body| body.contains(r#""sn":"10""#))
    );

    // The decimal rendering reproduces it; the hexadecimal one does not, and that is the whole
    // point of making the caller choose.
    let decimal = KeyStateQuery::at(prefix(PREFIX_ONE)?, QuerySequence::Decimal(10)).body()?;
    let hexadecimal = KeyStateQuery::at(prefix(PREFIX_ONE)?, QuerySequence::Hexadecimal(10)).body()?;
    assert_eq!(String::from_utf8(decimal)?, recorded.body.clone().unwrap_or_default());
    assert!(String::from_utf8(hexadecimal)?.contains(r#""sn":"a""#));

    // Below ten every recorded call is identical either way, which is why the reference's own
    // evidence cannot settle it.
    for value in 0..10 {
        assert_eq!(
            QuerySequence::Decimal(value).to_text(),
            QuerySequence::Hexadecimal(value).to_text()
        );
    }
    Ok(())
}

#[test]
fn a_prefix_carrying_query_delimiters_is_not_a_prefix() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference produced `/events?pre=E&pre=EOTHER#x`: a second parameter and a fragment.
    let recorded = request_of(&fixture, "events_get_prefix_needing_encoding")?;
    assert_eq!(recorded.path, "/events?pre=E&pre=EOTHER#x");
    assert!(IdentifierPrefix::from_qb64("E&pre=EOTHER#x").is_err());
    Ok(())
}
