//! Exact exchange-endpoint vectors recorded from the pinned reference's own `Exchanges`.
//!
//! `Exchanges` takes a whole `SignifyClient`, so the generator drives the real client with
//! `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would, and the
//! identifier is the reference's own `mockGetAID` — which is why the sender here is the literal the
//! pinned `contacting.test.ts` asserts.
//!
//! The **clock is pinned**, because `send` passes no timestamp and `exchange(...)` then reads the
//! system clock. Without that, nothing this class sends is reproducible at all.
//!
//! Twelve calls are recorded. What they prove has three parts: the two addresses and the request
//! body reproduce byte for byte, signatures included; the four inputs this port refuses are each
//! shown to be refused; and the two behaviours the reference's own integration tests depend on —
//! the dead loop in `send`, and the alias that need not be the signer — are reproduced only when a
//! caller says so explicitly.

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::challenges::{CHALLENGE_RESPONSE_ROUTE, CHALLENGE_TOPIC, CHALLENGE_WORDS_LABEL};
use signify_client::endpoint::exchanges::{ExchangeDraft, MULTISIG_TOPIC, REGISTRY_TOPIC};
use signify_client::error::ClientError;
use signify_crypto::cipher::Encrypter;
use signify_crypto::salt::{Salt, SecurityTier};
use signify_crypto::signer::Signer;
use signify_crypto::verifier::KeyTransferability;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::authentication::RequestSigner;
use signify_http::signature::input::{RequestTarget, default_components};
use signify_http::signature::timestamp::SignifyTimestamp;
use signify_http::transport::{Method, Request, Response, StatusCode, Transport, TransportError, TransportFuture};
use signify_keri::event::Timestamp;
use signify_keri::manager::DerivationCost;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-exchanges/v1.json");

const ADMIN: &str = "http://127.0.0.1:3901";
const BOOT: &str = "http://127.0.0.1:3903";
const PASSCODE: &str = "0123456789abcdefghijk";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";
const ALIAS: &str = "aid1";
const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const RECIPIENT: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SECOND_RECIPIENT: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const STAMP: &str = "2023-11-14T22:13:20.123000+00:00";

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
    mock_shortfall: MockShortfall,
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
    identifier_prefix: String,
    recipient: String,
    second_recipient: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    create_signature: Vec<String>,
    create_keeper: String,
    create_exchange_call: String,
    create_sign: String,
    create_return: String,
    send_signature: Vec<String>,
    send_body: String,
    send_loop: String,
    send_throw: String,
    send_return_type: String,
    send_from_events_signature: Vec<String>,
    send_from_events_path: String,
    send_from_events_data: String,
    send_from_events_method: String,
    send_from_events_return_type: String,
    get_path: String,
    get_signature: Vec<String>,
    get_return_type: String,
    get_return: String,
    exchanges_members: Vec<String>,
    respond_body: String,
    respond_return_type: String,
    submit_grant_return_type: String,
    route_constants: Value,
    exn_schema: String,
    exchange_resource_schema: String,
    exchanges_accessor_uses: Scan,
    send_uses: Scan,
    send_from_events_uses: Scan,
    pinned_words: Vec<String>,
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
struct MockShortfall {
    identifier_record: Value,
    identifier_record_fields: Vec<String>,
    identifier_record_missing: Vec<String>,
    added_inception_stamp: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    requests: Vec<RecordedRequest>,
    result: Value,
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    exchanging_test: ExchangingAssertions,
    contacting_test: ContactingAssertions,
    every_pinned_assertion_is_driven: bool,
    note: String,
}

#[derive(Debug, Deserialize)]
struct ExchangingAssertions {
    send_from_events_path: String,
    send_from_events_method: String,
    get_path: String,
    get_method: String,
}

#[derive(Debug, Deserialize)]
struct ContactingAssertions {
    path: String,
    method: String,
    tpc: String,
    exn_route: String,
    exn_sender: String,
    exn_words: Vec<String>,
    first_signature_length: usize,
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

/// The last request one recorded call produced: the submission, after any identifier read.
fn submission<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a RecordedRequest, Box<dyn Error>> {
    call(fixture, name)?
        .requests
        .last()
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
    Ok(Response::new(StatusCode::new(200)?, headers, body)?)
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

/// One endpoint request as it left the transport: path, method, and body.
type SentRequest = (String, String, Option<String>);

/// Returns the path, method, and body of the endpoint request at `index`.
fn sent(transport: &AgentTransport, index: usize) -> Result<SentRequest, Box<dyn Error>> {
    let recorded = transport.requests();
    // Two requests are the lifecycle's: the state read and the delegation approval.
    let request = recorded.get(2 + index).ok_or("no endpoint request was sent")?;
    let url = request.url().as_str();
    let path = url.strip_prefix(ADMIN).unwrap_or(url).to_owned();
    let body = request
        .body()
        .map(|bytes| String::from_utf8(bytes.to_vec()))
        .transpose()?;
    Ok((path, request.method().as_str().to_owned(), body))
}

/// The sealing key this client's controller salt derives, so a recorded record can be re-sealed.
fn sealing_key() -> Result<Encrypter, Box<dyn Error>> {
    let salt = Salt::from_qb64(&format!("0AA{PASSCODE}"), SecurityTier::Low)?;
    let signer = salt.derive_signer("", KeyTransferability::NonTransferable)?;
    Ok(Encrypter::from_verification_key(signer.verifier())?)
}

/// The identifier record every lookup answers with, re-sealed under this client's own key.
///
/// The fixture records what the reference's sealed salt *opens to* rather than the blob itself,
/// because only the reference's controller can open that blob. Roadmap 6.11 established the shape.
fn identifier_record(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut record = fixture.mock_shortfall.identifier_record.clone();
    let opens_to = record
        .get("salty")
        .and_then(|salty| salty.get("sxlt_opens_to"))
        .and_then(Value::as_str)
        .ok_or("the recorded identifier carries no sealed salt")?
        .to_owned();
    let sealed = sealing_key()?
        .encrypt_salt(&Salt::from_qb64(&opens_to, SecurityTier::Low)?)?
        .qb64()?;
    let salty = record
        .get_mut("salty")
        .and_then(Value::as_object_mut)
        .ok_or("the recorded identifier has no key-manager block")?;
    salty.remove("sxlt_opens_to");
    salty.insert("sxlt".to_owned(), Value::String(sealed));
    Ok(serde_json::to_vec(&record)?)
}

fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
    Ok(IdentifierPrefix::from_qb64(text)?)
}

fn stamp() -> Result<Timestamp, Box<dyn Error>> {
    Ok(STAMP.parse()?)
}

/// The word list the pinned test responds with, taken from the fixture rather than transcribed.
fn words(fixture: &Fixture) -> Vec<String> {
    fixture.declarations.pinned_words.clone()
}

fn words_payload(fixture: &Fixture) -> Result<Sad, Box<dyn Error>> {
    let mut payload = Sad::new();
    payload.insert(
        CHALLENGE_WORDS_LABEL,
        SadValue::Array(words(fixture).into_iter().map(SadValue::Text).collect()),
    )?;
    Ok(payload)
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
    assert!(fixture.sources.iter().any(|source| source.ends_with("exchanging.ts")));
    assert!(fixture.sources.iter().any(|source| source.ends_with("contacting.ts")));
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert_eq!(fixture.provenance.identifier_prefix, SENDER);
    assert_eq!(fixture.provenance.recipient, RECIPIENT);
    assert_eq!(fixture.provenance.second_recipient, SECOND_RECIPIENT);
    assert!(!fixture.provenance.controller_prefix.is_empty());
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 12);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
    }
    // The reference refuses exactly one of the twelve, and only because its loop cannot run.
    let refused: Vec<&str> = fixture
        .calls
        .iter()
        .filter(|entry| entry.error.is_some())
        .map(|entry| entry.name.as_str())
        .collect();
    assert_eq!(refused, ["send_empty_recipients"]);
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // Four methods, and this item ports all four.
    assert_eq!(
        declarations.exchanges_members,
        [
            "client",
            "<constructor>",
            "createExchangeMessage",
            "send",
            "sendFromEvents",
            "get"
        ]
    );

    // The composition `create_message` performs: look the keeper up, build, sign.
    assert!(declarations.create_keeper.contains("this.client.manager"));
    assert!(declarations.create_exchange_call.starts_with("exchange("));
    assert!(declarations.create_sign.contains("keeper.sign"));
    assert!(declarations.create_return.contains("sigs"));
    // Seven parameters, the last two of which `send` never passes.
    assert_eq!(declarations.create_signature.len(), 7);
    assert!(declarations.create_signature.iter().any(|p| p.starts_with("datetime?")));
    assert!(declarations.create_signature.iter().any(|p| p.starts_with("dig?")));

    // The submission: one path, one method, one body of five fields.
    assert_eq!(
        declarations.send_from_events_path,
        "path = `/identifiers/${name}/exchanges`"
    );
    assert_eq!(declarations.send_from_events_method, "method = 'POST'");
    for field in ["tpc:", "exn:", "sigs:", "atc:", "rec:"] {
        assert!(
            declarations.send_from_events_data.contains(field),
            "the body no longer writes {field}"
        );
    }

    // The read: one segment interpolated raw.
    assert_eq!(declarations.get_path, "path = `/exchanges/${said}`");
    assert_eq!(declarations.get_signature, ["said: string"]);
    assert_eq!(declarations.get_return, "await res.json()");

    // `respond` still delegates, which is what made Roadmap 7.4's deferral legitimate.
    assert!(declarations.respond_body.contains("exchanges.send("));
    assert!(declarations.respond_body.contains("'/challenge/response'"));
    assert!(declarations.respond_body.contains("'challenge'"));

    assert!(declarations.notes.is_object());
    assert!(declarations.exchanges_accessor_uses.total >= 1);
    assert_eq!(declarations.exchanges_accessor_uses.scanned_files, 117);
    Ok(())
}

#[test]
fn the_route_table_is_recorded_and_left_to_roadmap_8_1() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let routes = fixture
        .declarations
        .route_constants
        .as_object()
        .ok_or("the route constants are not an object")?;
    // Thirteen exported route constants: eight multisig and five IPEX.
    assert_eq!(routes.len(), 13);
    assert_eq!(
        routes.get("MULTISIG_ICP_ROUTE").and_then(Value::as_str),
        Some("/multisig/icp")
    );
    assert_eq!(
        routes.get("IPEX_GRANT_ROUTE").and_then(Value::as_str),
        Some("/ipex/grant")
    );
    // None of them is a challenge route: that constant is Roadmap 7.4's, and stayed there.
    assert!(
        !routes
            .values()
            .any(|route| route.as_str() == Some(CHALLENGE_RESPONSE_ROUTE))
    );

    // The two topics this port publishes are the ones the reference's integration tests use, and
    // they are *not* route constants — a topic is not a route.
    assert!(!routes.values().any(|route| route.as_str() == Some(MULTISIG_TOPIC)));
    assert!(!routes.values().any(|route| route.as_str() == Some(REGISTRY_TOPIC)));
    Ok(())
}

#[test]
fn the_declared_shapes_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // `send` takes seven arguments, two of which are the alias and the identifier that need not
    // agree, and one of which is the recipient *list* the message can only have one of.
    assert_eq!(declarations.send_signature.len(), 7);
    assert!(declarations.send_signature.iter().any(|p| p.starts_with("name:")));
    assert!(declarations.send_signature.iter().any(|p| p.starts_with("sender:")));
    assert!(declarations.send_signature.iter().any(|p| p.starts_with("recipients:")));

    // The loop that returns on its first pass.
    assert!(
        declarations
            .send_loop
            .starts_with("for (const recipient of recipients)")
    );
    assert!(declarations.send_loop.contains("return await this.sendFromEvents"));

    // `sendFromEvents` takes the message, its signatures, and its attachment as three separate
    // arguments, which is what lets them disagree; here they are one `SignedExchange`.
    assert_eq!(declarations.send_from_events_signature.len(), 6);
    for parameter in ["exn: Serder", "sigs: string[]", "atc: string"] {
        assert!(
            declarations
                .send_from_events_signature
                .iter()
                .any(|declared| declared == parameter),
            "the signature no longer declares {parameter}"
        );
    }

    // Both reads declare a cast, and `respond` declares the same answer `sendFromEvents` does.
    assert_eq!(declarations.get_return_type, "Promise<ExchangeResourceV1>");
    assert_eq!(declarations.respond_return_type, "Promise<Exn>");

    // The two schema shapes behind those casts.
    assert!(declarations.exn_schema.starts_with("Exn:"));
    assert!(declarations.exchange_resource_schema.contains("exn:"));
    assert!(declarations.exchange_resource_schema.contains("pathed:"));
    Ok(())
}

#[test]
fn the_recorded_scans_name_the_files_they_counted() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // Every scan reports what it looked for, over the whole pinned tree.
    for scan in [
        &declarations.exchanges_accessor_uses,
        &declarations.send_uses,
        &declarations.send_from_events_uses,
    ] {
        assert!(!scan.needle.is_empty());
        assert_eq!(scan.scanned_files, 117);
        assert_eq!(
            scan.files.iter().map(|hit| hit.count).sum::<usize>(),
            scan.total,
            "the per-file counts for {} do not add up",
            scan.needle
        );
        assert!(scan.files.iter().all(|hit| {
            std::path::Path::new(&hit.file)
                .extension()
                .is_some_and(|kind| kind == "ts")
        }));
    }

    // `send` is called from one production file — `contacting.ts`'s `respond` — and otherwise only
    // from integration tests. That is why `respond` is the only in-tree caller this item can
    // reproduce, and why the two-recipient shape is evidence from `multisig.test.ts` rather than
    // from a unit case.
    assert_eq!(declarations.send_uses.needle, ".send(");
    let production: Vec<&str> = declarations
        .send_uses
        .files
        .iter()
        .filter(|hit| hit.file.starts_with("src/"))
        .map(|hit| hit.file.as_str())
        .collect();
    assert_eq!(production, ["src/keri/app/contacting.ts"]);
    assert!(
        declarations
            .send_uses
            .files
            .iter()
            .any(|hit| hit.file.ends_with("multisig.test.ts") && hit.count > 1)
    );

    // `sendFromEvents` is named in its own declaration, in `send`, and in the one unit case.
    assert!(declarations.send_from_events_uses.total >= 3);
    Ok(())
}

#[test]
fn every_pinned_assertion_is_driven() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let confirmations = &fixture.pinned_confirmations;
    assert!(confirmations.every_pinned_assertion_is_driven);
    assert_eq!(
        confirmations.exchanging_test.send_from_events_path,
        "/identifiers/aid1/exchanges"
    );
    assert_eq!(confirmations.exchanging_test.send_from_events_method, "POST");
    assert_eq!(confirmations.exchanging_test.get_path, format!("/exchanges/{SAID}"));
    assert_eq!(confirmations.exchanging_test.get_method, "GET");
    assert_eq!(confirmations.contacting_test.path, "/identifiers/aid1/exchanges");
    assert_eq!(confirmations.contacting_test.method, "POST");
    assert_eq!(confirmations.contacting_test.tpc, CHALLENGE_TOPIC);
    assert_eq!(confirmations.contacting_test.exn_route, CHALLENGE_RESPONSE_ROUTE);
    assert_eq!(confirmations.contacting_test.exn_sender, SENDER);
    assert_eq!(
        confirmations.contacting_test.exn_words,
        fixture.declarations.pinned_words
    );
    assert_eq!(confirmations.contacting_test.first_signature_length, 88);
    assert!(!confirmations.note.is_empty());
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

#[test]
fn the_mock_shortfall_is_recorded_rather_than_papered_over() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let shortfall = &fixture.mock_shortfall;
    // The reference's own mock omits a field its own generated schema declares required.
    assert_eq!(shortfall.identifier_record_missing, ["icp_dt"]);
    assert_eq!(shortfall.added_inception_stamp, "2023-08-21T22:30:46.473545+00:00");
    assert!(shortfall.identifier_record_fields.contains(&"salty".to_owned()));
    assert!(!shortfall.note.is_empty());
    // And the record it produces is one this port accepts.
    let record: signify_types::api::Hab = serde_json::from_slice(&identifier_record(&fixture)?)?;
    assert!(matches!(record, signify_types::api::Hab::Accepted(_)));
    Ok(())
}

// ---------------------------------------------------------------------------
// The requests.
// ---------------------------------------------------------------------------

#[test]
fn a_challenge_response_reproduces_the_pinned_body_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = submission(&fixture, "respond_pinned")?;
    let record = identifier_record(&fixture)?;

    let (client, transport) = connected(&[&record, b"{}"])?;
    let sent_response = block_on(
        client
            .challenges()
            .respond(ALIAS, &prefix(RECIPIENT)?, &words(&fixture), stamp()?),
    )?;
    let _ = sent_response.response_body();

    // The alias is read first — which is what makes the signer and the resource the same
    // identifier — and then the message is submitted.
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/aid1");
    let (path, method, body) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    // Byte for byte, signature included.
    assert_eq!(body.as_deref(), recorded.body.as_deref());
    Ok(())
}

#[test]
fn the_pinned_response_body_carries_what_the_pinned_test_asserts() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = submission(&fixture, "respond_pinned")?;
    let body: Value = serde_json::from_str(recorded.body.as_deref().ok_or("no recorded body")?)?;

    assert_eq!(body.get("tpc").and_then(Value::as_str), Some(CHALLENGE_TOPIC));
    let exn = body.get("exn").ok_or("no exn in the body")?;
    assert_eq!(exn.get("r").and_then(Value::as_str), Some(CHALLENGE_RESPONSE_ROUTE));
    assert_eq!(exn.get("i").and_then(Value::as_str), Some(SENDER));
    assert_eq!(exn.get("rp").and_then(Value::as_str), Some(RECIPIENT));
    // The word list reaches the attribute block, in order.
    let sent_words: Vec<String> = exn
        .get("a")
        .and_then(|attributes| attributes.get(CHALLENGE_WORDS_LABEL))
        .and_then(Value::as_array)
        .ok_or("no words in the attribute block")?
        .iter()
        .filter_map(|word| word.as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(sent_words, fixture.declarations.pinned_words);
    // One indexed signature of the length the pinned test asserts.
    let signatures = body.get("sigs").and_then(Value::as_array).ok_or("no signatures")?;
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures.first().and_then(Value::as_str).map(str::len), Some(88));
    // A challenge response embeds nothing, so its attachment stream is empty.
    assert_eq!(body.get("atc").and_then(Value::as_str), Some(""));
    assert_eq!(
        body.get("rec").and_then(Value::as_array).map(Vec::len),
        Some(1),
        "a challenge answer has exactly one reader"
    );
    Ok(())
}

#[test]
fn a_single_recipient_submission_reproduces_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = submission(&fixture, "send_single_recipient")?;
    let record = identifier_record(&fixture)?;

    let mut payload = Sad::new();
    payload.insert("gid", SadValue::text(SENDER))?;
    let draft = ExchangeDraft::new("/multisig/icp", prefix(RECIPIENT)?, stamp()?).payload(payload);

    let (client, transport) = connected(&[&record, b"{}"])?;
    let _ = block_on(
        client
            .exchanges()
            .send(ALIAS, MULTISIG_TOPIC, &draft, &[prefix(RECIPIENT)?]),
    )?;

    let (path, method, body) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, "/identifiers/aid1/exchanges");
    assert_eq!(method, "POST");
    assert_eq!(body.as_deref(), recorded.body.as_deref());
    Ok(())
}

#[test]
fn the_dead_loop_is_reproduced_only_when_a_caller_says_so() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = submission(&fixture, "send_two_recipients")?;
    let record = identifier_record(&fixture)?;

    // Upstream, passing two recipients addresses the message to the first and delivers to both —
    // the loop returns on its first pass. Here the addressee and the list are separate, so
    // reproducing those bytes means naming the first recipient as the addressee explicitly.
    let mut payload = Sad::new();
    payload.insert("gid", SadValue::text(SENDER))?;
    let draft = ExchangeDraft::new("/multisig/icp", prefix(RECIPIENT)?, stamp()?).payload(payload);

    let (client, transport) = connected(&[&record, b"{}"])?;
    let _ = block_on(client.exchanges().send(
        ALIAS,
        MULTISIG_TOPIC,
        &draft,
        &[prefix(RECIPIENT)?, prefix(SECOND_RECIPIENT)?],
    ))?;

    let (path, _, body) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    assert_eq!(body.as_deref(), recorded.body.as_deref());

    // And this is what those bytes say: addressed to one, delivered to two.
    let sent_body: Value = serde_json::from_str(body.as_deref().ok_or("no body")?)?;
    let exn = sent_body.get("exn").ok_or("no exn")?;
    assert_eq!(exn.get("rp").and_then(Value::as_str), Some(RECIPIENT));
    assert_eq!(
        exn.get("a").and_then(|a| a.get("i")).and_then(Value::as_str),
        Some(RECIPIENT)
    );
    let delivered: Vec<&str> = sent_body
        .get("rec")
        .and_then(Value::as_array)
        .ok_or("no recipients")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(delivered, [RECIPIENT, SECOND_RECIPIENT]);
    Ok(())
}

#[test]
fn addressing_the_second_recipient_is_a_different_message() -> Result<(), Box<dyn Error>> {
    // The thing the reference cannot express: a message actually addressed to the member it is
    // being delivered to. Upstream every member but the first receives the first member's message.
    let fixture = fixture()?;
    let record = identifier_record(&fixture)?;
    let recorded = submission(&fixture, "send_two_recipients")?;

    let mut payload = Sad::new();
    payload.insert("gid", SadValue::text(SENDER))?;
    let draft = ExchangeDraft::new("/multisig/icp", prefix(SECOND_RECIPIENT)?, stamp()?).payload(payload);

    let (client, transport) = connected(&[&record, b"{}"])?;
    let _ = block_on(client.exchanges().send(
        ALIAS,
        MULTISIG_TOPIC,
        &draft,
        &[prefix(RECIPIENT)?, prefix(SECOND_RECIPIENT)?],
    ))?;

    let (_, _, body) = sent(&transport, 1)?;
    let sent_body: Value = serde_json::from_str(body.as_deref().ok_or("no body")?)?;
    assert_eq!(
        sent_body
            .get("exn")
            .and_then(|exn| exn.get("rp"))
            .and_then(Value::as_str),
        Some(SECOND_RECIPIENT)
    );
    // A different addressee is a different message, so a different SAID and a different signature.
    assert_ne!(body.as_deref(), recorded.body.as_deref());
    Ok(())
}

#[test]
fn an_alias_that_is_not_the_signer_is_unrepresentable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = submission(&fixture, "send_alias_disagrees_with_sender")?;
    // Upstream posted under one alias a message signed by, and naming, a different identifier.
    assert_eq!(recorded.path, "/identifiers/some-other-alias/exchanges");
    let body: Value = serde_json::from_str(recorded.body.as_deref().ok_or("no recorded body")?)?;
    assert_eq!(
        body.get("exn").and_then(|exn| exn.get("i")).and_then(Value::as_str),
        Some(SENDER),
        "the recorded message names the identifier that signed it, not the alias it was posted under"
    );

    // Here the alias decides both, so the two can never disagree: posting under another alias
    // means looking that identifier up, and the agent's answer is what signs.
    let record = identifier_record(&fixture)?;
    let mut payload = Sad::new();
    payload.insert("gid", SadValue::text(SENDER))?;
    let draft = ExchangeDraft::new("/multisig/icp", prefix(RECIPIENT)?, stamp()?).payload(payload);

    let (client, transport) = connected(&[&record, b"{}"])?;
    let _ = block_on(
        client
            .exchanges()
            .send("some-other-alias", MULTISIG_TOPIC, &draft, &[prefix(RECIPIENT)?]),
    )?;
    // The lookup addresses the alias that was named…
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/some-other-alias");
    // …and the message names whatever identifier that lookup returned. There is no second
    // argument that could have said anything else.
    let (path, _, body) = sent(&transport, 1)?;
    assert_eq!(path, "/identifiers/some-other-alias/exchanges");
    let sent_body: Value = serde_json::from_str(body.as_deref().ok_or("no body")?)?;
    assert_eq!(
        sent_body
            .get("exn")
            .and_then(|exn| exn.get("i"))
            .and_then(Value::as_str),
        Some(SENDER)
    );
    Ok(())
}

#[test]
fn a_read_addresses_the_pinned_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = submission(&fixture, "get_pinned_said")?;
    let resource = serde_json::to_vec(&call(&fixture, "get_pinned_said")?.result)?;

    let (client, transport) = connected(&[&resource])?;
    let read = block_on(client.exchanges().get(&SAID.parse::<Said>()?))?;

    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, format!("/exchanges/{SAID}"));
    assert_eq!(method, "GET");
    assert_eq!(body, None);
    // The answer is decoded rather than cast.
    assert_eq!(read.exn.digest, SAID);
    assert!(read.pathed.is_empty());
    Ok(())
}

#[test]
fn a_said_that_escapes_its_segment_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = submission(&fixture, "get_escaping_said")?;
    // The reference sent it: three extra segments and a query, on a path Roadmap 3.10 signs.
    assert_eq!(recorded.path, "/exchanges/../identifiers/aid1?x=1");
    assert!(
        "../identifiers/aid1?x=1".parse::<Said>().is_err(),
        "the recorded input was accepted as a SAID"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The inputs this port refuses.
// ---------------------------------------------------------------------------

#[test]
fn the_pinned_unit_calls_three_empty_values_are_each_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = submission(&fixture, "send_from_events_pinned")?;
    let body: Value = serde_json::from_str(recorded.body.as_deref().ok_or("no recorded body")?)?;

    // What the reference sent, unchallenged: no topic, one empty signature, nobody to deliver to.
    assert_eq!(body.get("tpc").and_then(Value::as_str), Some(""));
    assert_eq!(
        body.get("sigs").and_then(Value::as_array).map(Vec::len),
        Some(1),
        "the recorded call sent one signature"
    );
    assert_eq!(
        body.get("sigs")
            .and_then(Value::as_array)
            .and_then(|sigs| sigs.first())
            .and_then(Value::as_str),
        Some("")
    );
    assert_eq!(body.get("rec").and_then(Value::as_array).map(Vec::len), Some(0));

    // Each is refused here. The signatures are not even an argument: they come from the keeper.
    let record = identifier_record(&fixture)?;
    let draft = ExchangeDraft::new("/multisig/icp", prefix(RECIPIENT)?, stamp()?);

    let (client, _) = connected(&[&record, b"{}"])?;
    assert!(matches!(
        block_on(client.exchanges().send(ALIAS, "", &draft, &[prefix(RECIPIENT)?])),
        Err(ClientError::EmptyExchangeTopic)
    ));
    assert!(matches!(
        block_on(client.exchanges().send(ALIAS, MULTISIG_TOPIC, &draft, &[])),
        Err(ClientError::NoExchangeRecipients)
    ));
    Ok(())
}

#[test]
fn a_refusal_costs_no_request_at_all() -> Result<(), Box<dyn Error>> {
    // Both checks run before the identifier is looked up, so a caller mistake never reaches the
    // agent — where upstream `sendFromEvents` posts the malformed body and `send` throws only
    // after building nothing.
    let fixture = fixture()?;
    let record = identifier_record(&fixture)?;
    let draft = ExchangeDraft::new("/multisig/icp", prefix(RECIPIENT)?, stamp()?);

    let (client, transport) = connected(&[&record, b"{}"])?;
    let before = transport.requests().len();
    assert!(block_on(client.exchanges().send(ALIAS, "", &draft, &[])).is_err());
    assert_eq!(
        transport.requests().len(),
        before,
        "a refused submission still sent something"
    );
    Ok(())
}

#[test]
fn the_reference_refuses_only_the_empty_recipient_list_and_only_by_accident() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let refused = call(&fixture, "send_empty_recipients")?;
    assert_eq!(refused.error.as_deref(), Some("recipients list was empty"));
    assert!(refused.requests.is_empty(), "the refused call still sent a request");

    // …and `sendFromEvents`, which takes the same list, accepts it.
    let accepted = call(&fixture, "send_from_events_pinned")?;
    assert_eq!(accepted.error, None);
    assert_eq!(accepted.requests.len(), 1);

    // The `throw` is after the loop, so it is reachable only when the loop body never runs.
    assert!(fixture.declarations.send_throw.contains("recipients list was empty"));
    assert!(
        fixture
            .declarations
            .send_body
            .find("for (const recipient")
            .zip(fixture.declarations.send_body.find("throw new Error"))
            .is_some_and(|(loop_at, throw_at)| loop_at < throw_at),
        "the throw is no longer after the loop"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The answer.
// ---------------------------------------------------------------------------

#[test]
fn the_answer_has_two_declared_types_and_neither_is_imposed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The same shape of POST, to the same agent, declared two incompatible ways.
    assert_eq!(fixture.declarations.send_from_events_return_type, "Promise<Exn>");
    assert_eq!(fixture.declarations.send_return_type, "Promise<Exn>");
    assert_eq!(
        fixture.declarations.submit_grant_return_type,
        "Promise<ExchangeOperation>"
    );

    let record = identifier_record(&fixture)?;
    let mut payload = Sad::new();
    payload.insert("gid", SadValue::text(SENDER))?;
    let draft = ExchangeDraft::new("/multisig/icp", prefix(RECIPIENT)?, stamp()?).payload(payload);

    // Answered as `Ipex.submit*` declares: an operation decodes, an exchange does not.
    let operation = serde_json::to_vec(&call(&fixture, "send_single_recipient")?.result)?;
    let (client, _) = connected(&[&record, &operation])?;
    let sent_operation = block_on(
        client
            .exchanges()
            .send(ALIAS, MULTISIG_TOPIC, &draft, &[prefix(RECIPIENT)?]),
    )?;
    assert!(sent_operation.operation().is_ok());
    assert!(sent_operation.exchange().is_err());

    // Answered as `sendFromEvents` declares: the other way round.
    let exchange = serde_json::to_vec(&call(&fixture, "send_answered_with_an_exchange")?.result)?;
    let record = identifier_record(&fixture)?;
    let (client, _) = connected(&[&record, &exchange])?;
    let sent_exchange = block_on(
        client
            .exchanges()
            .send(ALIAS, MULTISIG_TOPIC, &draft, &[prefix(RECIPIENT)?]),
    )?;
    assert!(sent_exchange.exchange().is_ok());
    assert!(sent_exchange.operation().is_err());

    // Both requests were identical: the answer cannot change what was asked.
    assert_eq!(
        submission(&fixture, "send_single_recipient")?.body,
        submission(&fixture, "send_answered_with_an_exchange")?.body
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The message itself.
// ---------------------------------------------------------------------------

#[test]
fn a_created_message_reproduces_the_recorded_bytes_and_signature() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "create_challenge_response")?;
    let expected = recorded.result.as_object().ok_or("no recorded message")?;
    let record = identifier_record(&fixture)?;

    let draft =
        ExchangeDraft::new(CHALLENGE_RESPONSE_ROUTE, prefix(RECIPIENT)?, stamp()?).payload(words_payload(&fixture)?);

    let (client, transport) = connected(&[&record])?;
    let message = block_on(client.exchanges().create_message(ALIAS, &draft))?;

    // The raw bytes, exactly.
    assert_eq!(
        core::str::from_utf8(message.message().raw())?,
        expected.get("raw").and_then(Value::as_str).ok_or("no recorded raw")?
    );
    // The signatures, exactly.
    let expected_signatures: Vec<&str> = expected
        .get("sigs")
        .and_then(Value::as_array)
        .ok_or("no recorded signatures")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(message.signatures().qb64()?, expected_signatures);
    // And the attachment stream, which a message with no embeds leaves empty.
    assert_eq!(
        core::str::from_utf8(message.attachments())?,
        expected.get("atc").and_then(Value::as_str).unwrap_or("<missing>")
    );

    // Building a message sends exactly one request — the alias lookup — and posts nothing.
    assert_eq!(transport.requests().len(), 3);
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/aid1");
    Ok(())
}

#[test]
fn a_created_message_carries_an_explicit_prior_and_timestamp() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "create_with_explicit_datetime_and_prior")?;
    let expected = recorded.result.as_object().ok_or("no recorded message")?;
    let record = identifier_record(&fixture)?;

    let mut payload = Sad::new();
    payload.insert("gid", SadValue::text(SENDER))?;
    let draft = ExchangeDraft::new(
        "/multisig/vcp",
        prefix(RECIPIENT)?,
        "2023-08-30T17:22:54.183000+00:00".parse::<Timestamp>()?,
    )
    .payload(payload)
    .prior(SAID.parse::<Said>()?);

    let (client, _) = connected(&[&record])?;
    let message = block_on(client.exchanges().create_message(ALIAS, &draft))?;

    assert_eq!(
        core::str::from_utf8(message.message().raw())?,
        expected.get("raw").and_then(Value::as_str).ok_or("no recorded raw")?
    );
    // These are the two arguments `send` never passes upstream, so their only reachable use is
    // through `createExchangeMessage` directly.
    let exn = expected.get("exn").ok_or("no recorded message")?;
    assert_eq!(exn.get("p").and_then(Value::as_str), Some(SAID));
    assert_eq!(
        exn.get("dt").and_then(Value::as_str),
        Some("2023-08-30T17:22:54.183000+00:00")
    );
    Ok(())
}

#[test]
fn a_message_with_an_embed_carries_a_transposed_attachment() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "create_multisig_icp_with_embed")?;
    let expected = recorded.result.as_object().ok_or("no recorded message")?;
    // Roadmap 3.8 already proved the transposition byte-exact; what matters here is that the
    // wrapper carries it through to the submission body's `atc` rather than dropping it.
    let attachment = expected.get("atc").and_then(Value::as_str).ok_or("no attachment")?;
    assert!(!attachment.is_empty(), "the recorded embed produced no attachment");
    assert!(attachment.starts_with("-L"), "the attachment is not a pathed group");
    let exn = expected.get("exn").ok_or("no message")?;
    assert!(
        exn.get("e").and_then(|embeds| embeds.get("icp")).is_some(),
        "the embed is missing from the message"
    );
    Ok(())
}
