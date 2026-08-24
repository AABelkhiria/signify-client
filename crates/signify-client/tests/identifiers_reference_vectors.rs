//! Exact identifier-endpoint vectors recorded from the pinned reference's own `Identifier`.
//!
//! `Identifier` takes an `IdentifierDeps` — one `fetch` method, a `pidx`, and a manager — so the
//! generator hands the real class a recorder, exactly as the pinned `aiding.test.ts` does, and
//! every request it makes is captured with its path, method, headers, and the **exact body bytes**
//! `SignifyClient.fetch` would send. This test rebuilds each one through a connected client and
//! compares what actually goes out.
//!
//! Because a salty keeper's sealed salt draws a fresh ephemeral key per call, each side's
//! ciphertext is masked as `<SXLT>` and compared by what it opens to. Everything else is compared
//! byte for byte, including every signature — the key material derives at the reference's own
//! production Argon2 profile, so this file is deliberately slow.

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::identifiers::{
    END_ROLES_SEGMENT, EVENTS_SEGMENT, IDENTIFIER_RANGE_UNIT, IdentifierUpdate, LOCATION_SCHEMES_SEGMENT,
    LocationSchemeRequest, MEMBERS_SEGMENT,
};
use signify_client::error::ClientError;
use signify_crypto::cipher::{Ciphertext, Decrypter};
use signify_crypto::salt::{Salt, SecurityTier};
use signify_crypto::signer::Signer;
use signify_crypto::verifier::KeyTransferability;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::request::ItemRange;
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::authentication::RequestSigner;
use signify_http::signature::input::{RequestTarget, default_components};
use signify_http::signature::timestamp::SignifyTimestamp;
use signify_http::transport::{Method, Request, Response, StatusCode, Transport, TransportError, TransportFuture};
use signify_keri::event::Timestamp;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest};
use signify_keri::manager::DerivationCost;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::serialization::Sad;
use signify_types::api::{AcceptedHab, Role};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-identifiers/v1.json");

const ADMIN: &str = "http://127.0.0.1:3901";
const BOOT: &str = "http://127.0.0.1:3903";
const PASSCODE: &str = "0123456789abcdefghijk";
const MULTISIG_PASSCODE: &str = "0123456789lmnopqrstuv";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";
const DELEGATOR: &str = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C";
const STAMP: &str = "2021-06-27T21:26:21.233257+00:00";

/// The agent seed Roadmap 6.4's fixture pinned, so its response signatures are reproducible.
const AGENT_SEED: [u8; 32] = [
    187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192, 61, 145, 222, 110, 59, 160, 152, 2, 72, 122, 87,
    143, 109, 39, 98, 153, 192, 148,
];

/// The instant the generator pinned: 2023-11-14T22:13:20.123Z.
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
    group_creation: GroupCreation,
    randy_shape: RandyShape,
    randy_reload_shape: RandyReloadShape,
    signed_request: SignedRequest,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    multisig_bran: String,
    member_two_bran: String,
    admin_url: String,
    boot_url: String,
    stamp: String,
    delegator: String,
    witnesses: Vec<String>,
    fixed_clock_ms: u64,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    list_range_header: String,
    list_defaults: Vec<String>,
    list_result: String,
    get_path: String,
    update_path: String,
    create_body: String,
    create_pidx_increment: String,
    interact_path: String,
    rotate_body: String,
    end_role_path: String,
    loc_scheme_path: String,
    members_path: String,
    event_result_members: Vec<String>,
    signed_request_resource: String,
    signed_request_signer: String,
    salty_parameters: String,
    randy_parameters: String,
    group_parameters: String,
    reloaded_randy_transferability: String,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    request: Option<RecordedRequest>,
    requests: usize,
    pidx_after: u32,
    result: Value,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    headers: Vec<RecordedHeader>,
    body: Option<String>,
    #[serde(default)]
    sxlt_opens_to: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedHeader {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct GroupCreation {
    members: GroupMembers,
    note: String,
}

#[derive(Debug, Deserialize)]
struct GroupMembers {
    member1: Value,
    member2: Value,
    member3: Value,
}

#[derive(Debug, Deserialize)]
struct RandyShape {
    path: String,
    method: String,
    randy_fields: Vec<String>,
    prxs_count: usize,
    nxts_count: usize,
    sig_count: usize,
    note: String,
}

#[derive(Debug, Deserialize)]
struct RandyReloadShape {
    randy_fields: Vec<String>,
    randy_transferable: bool,
    prefix_code: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct SignedRequest {
    controller_prefix: String,
    agent_prefix: String,
    identifier: Value,
    identifier_signing_key: String,
    lookup_path: String,
    post: SignedForm,
    get: SignedForm,
    fixed_clock_ms: u64,
    note: String,
}

#[derive(Debug, Deserialize)]
struct SignedForm {
    url: String,
    method: String,
    headers: Vec<RecordedHeader>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    published_paths: Vec<String>,
    driven_paths: Vec<String>,
    every_pinned_path_is_driven: bool,
    create_signed_request_is_published: bool,
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

/// A transport that answers each scripted body in turn, signing as the pinned agent would.
///
/// The generator's mocked `fetch` signed every answer so the reference's own `SignifyClient.fetch`
/// would accept it; this does the same, which is what lets a two-request flow — read the record,
/// then submit — run all the way through.
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

    /// Returns the requests this transport answered, in order.
    fn requests(&self) -> Vec<Request> {
        self.recorded.lock().map_or_else(|_| Vec::new(), |guard| guard.clone())
    }

    /// Builds the signed answer to one request.
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

/// Derives the pinned agent's signer.
fn agent_signer() -> Result<Signer, Box<dyn Error>> {
    Ok(Signer::from_seed(&AGENT_SEED, KeyTransferability::NonTransferable)?)
}

/// Signs one response the way the generator's agent did: the same four covered components.
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

/// A minimal executor; every future on this path is ready on its first poll.
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

/// The agent-state document `connect` reads, naming the pinned agent and this controller.
fn agent_state(controller: &str, inception: &str) -> String {
    let agent = format!(
        r#"{{"vn":[1,0],"i":"{AGENT}","s":"0","p":"","d":"{AGENT}","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1","k":["{key}"],"nt":"1","n":["EL6zVoZ0F8OXcbXP4LOm5oJTxCXP6ZLp5o3vNfvVZ9YB"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{AGENT}","br":[],"ba":[]}},"di":"{controller}"}}"#,
        key = agent_verification_key()
    );
    format!(r#"{{"agent":{agent},"controller":{{"state":{agent},"ee":{inception}}},"ridx":0,"pidx":0}}"#)
}

/// The pinned agent's verification key, qualified.
fn agent_verification_key() -> String {
    agent_signer()
        .and_then(|signer| Ok(signer.verifier().qb64()?))
        .unwrap_or_default()
}

/// Connects a client whose transport answers `bodies` after the two the lifecycle consumes.
fn connected(bodies: &[&[u8]]) -> Result<(ConnectedClient, Arc<AgentTransport>), Box<dyn Error>> {
    let config = ClientConfig::new(ADMIN, PASSCODE)?
        .with_boot_url(BOOT)?
        // The controller's own Argon2 cost does not reach any byte compared here: a keeper's
        // sealing key comes from the passcode salt directly, and an identifier's keys derive at
        // the production profile the request asks for.
        .with_derivation_cost(DerivationCost::Ephemeral);
    let probe = SignifyClient::new(
        ClientConfig::new(ADMIN, PASSCODE)?
            .with_boot_url(BOOT)?
            .with_derivation_cost(DerivationCost::Ephemeral),
        AgentTransport::new(&[]) as Arc<dyn Transport>,
        clock(),
    )?;
    let prefix = probe.controller().prefix().qb64()?;
    let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();

    let mut answers: Vec<&[u8]> = Vec::new();
    let state = agent_state(&prefix, &inception);
    answers.push(state.as_bytes());
    answers.push(b"{}");
    answers.extend_from_slice(bodies);
    let transport = AgentTransport::new(&answers);

    let client = SignifyClient::new(config, Arc::clone(&transport) as Arc<dyn Transport>, clock())?;
    let connected = block_on(client.connect())?;
    Ok((connected, transport))
}

/// Returns the path, method, and body of the request the client sent after connecting.
fn sent(transport: &AgentTransport, index: usize) -> Result<(String, String, Option<String>), Box<dyn Error>> {
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

/// Replaces every sealed salt in a rendered body with the generator's mask, returning what each
/// one opened to.
fn mask_sealed(body: &str, passcode: &str) -> Result<(String, Vec<String>), Box<dyn Error>> {
    let decrypter = Decrypter::from_signer(
        &Salt::from_qb64(&format!("0AA{passcode}"), SecurityTier::Low)?
            .derive_signer("", KeyTransferability::NonTransferable)?,
    );
    let mut masked = String::with_capacity(body.len());
    let mut opened = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(r#""sxlt":""#) {
        let (head, tail) = rest.split_at(start.saturating_add(r#""sxlt":""#.len()));
        masked.push_str(head);
        let end = tail.find('"').ok_or("an unterminated sealed salt")?;
        let (sealed, remainder) = tail.split_at(end);
        opened.push(
            decrypter
                .decrypt_salt(&Ciphertext::from_qb64(sealed)?, SecurityTier::Low)?
                .expose_qb64()?
                .to_string(),
        );
        masked.push_str("<SXLT>");
        rest = remainder;
    }
    masked.push_str(rest);
    Ok((masked, opened))
}

/// Compares one sent body with its recorded one, masking sealed salts on both sides.
fn assert_body(sent: Option<&str>, recorded: &RecordedRequest, passcode: &str) -> Result<(), Box<dyn Error>> {
    let expected = recorded.body.as_deref().ok_or("the recorded request carried no body")?;
    let actual = sent.ok_or("the sent request carried no body")?;
    let (masked, opened) = mask_sealed(actual, passcode)?;
    assert_eq!(masked, expected);
    assert_eq!(opened, recorded.sxlt_opens_to);
    Ok(())
}

/// The identifier record the generator built for `aid1`, as JSON bytes.
fn record_document(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
    reseal(&fixture.signed_request.identifier, PASSCODE)
}

/// Turns a fixture record's `sxlt_opens_to` back into a sealed salt this client can open.
fn reseal(record: &Value, passcode: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    use signify_crypto::cipher::Encrypter;
    let mut document = record.clone();
    let signer = Salt::from_qb64(&format!("0AA{passcode}"), SecurityTier::Low)?
        .derive_signer("", KeyTransferability::NonTransferable)?;
    let encrypter = Encrypter::from_verification_key(signer.verifier())?;
    reseal_in_place(&mut document, &encrypter)?;
    Ok(serde_json::to_vec(&document)?)
}

/// Rewrites every `sxlt_opens_to` in a document into a fresh `sxlt`.
fn reseal_in_place(document: &mut Value, encrypter: &signify_crypto::cipher::Encrypter) -> Result<(), Box<dyn Error>> {
    match document {
        Value::Object(fields) => {
            if let Some(Value::String(opens_to)) = fields.get("sxlt_opens_to").cloned() {
                let sealed = encrypter
                    .encrypt_salt(&Salt::from_qb64(&opens_to, SecurityTier::Low)?)?
                    .qb64()?;
                fields.remove("sxlt_opens_to");
                fields.insert("sxlt".to_owned(), Value::String(sealed));
            }
            for value in fields.values_mut() {
                reseal_in_place(value, encrypter)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                reseal_in_place(item, encrypter)?;
            }
        }
        _ => {}
    }
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
    assert!(fixture.sources.iter().any(|source| source.ends_with("aiding.ts")));
    assert!(fixture.sources.iter().any(|source| source.ends_with("clienting.ts")));
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.multisig_bran, MULTISIG_PASSCODE);
    assert_eq!(fixture.provenance.member_two_bran, "abcdefghijk0123456789");
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.stamp, STAMP);
    assert_eq!(fixture.provenance.delegator, DELEGATOR);
    assert_eq!(fixture.provenance.witnesses.len(), 3);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));
    assert_eq!(fixture.calls.len(), 24);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
    }
    assert!(!fixture.group_creation.note.is_empty());
    assert!(!fixture.randy_shape.note.is_empty());
    assert!(!fixture.randy_reload_shape.note.is_empty());
    assert!(!fixture.signed_request.note.is_empty());
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // The one header this family sends, and its two defaults.
    assert!(declarations.list_range_header.contains(IDENTIFIER_RANGE_UNIT));
    assert!(declarations.list_range_header.contains("Range"));
    assert_eq!(declarations.list_defaults, ["start: number = 0", "end: number = 24"]);
    assert_eq!(ItemRange::DEFAULT.start(), 0);
    assert_eq!(ItemRange::DEFAULT.end(), 24);
    assert!(declarations.list_result.contains("parseRangeHeaders"));

    // Two paths encode their name; five do not.
    assert!(declarations.get_path.contains("encodeURIComponent"));
    assert!(declarations.update_path.contains("encodeURIComponent"));
    for raw in [
        &declarations.interact_path,
        &declarations.end_role_path,
        &declarations.loc_scheme_path,
        &declarations.members_path,
    ] {
        assert!(!raw.contains("encodeURIComponent"), "{raw} unexpectedly encodes");
        assert!(raw.contains("'/identifiers/' + name"));
    }
    assert!(declarations.interact_path.contains(EVENTS_SEGMENT));
    assert!(declarations.end_role_path.contains(END_ROLES_SEGMENT));
    assert!(declarations.loc_scheme_path.contains(LOCATION_SCHEMES_SEGMENT));
    assert!(declarations.members_path.contains(MEMBERS_SEGMENT));

    // The body literals whose field order and optionality this port reproduces.
    for label in ["name:", "icp:", "sigs:", "proxy:", "smids:", "rmids:"] {
        assert!(declarations.create_body.contains(label), "create body lacks {label}");
    }
    assert!(!declarations.rotate_body.contains("proxy:"));
    assert!(declarations.rotate_body.contains("rot:"));
    assert!(declarations.create_pidx_increment.contains("pidx + 1"));

    // The keeper parameter literals, whose order the algorithm block follows.
    assert!(
        declarations
            .salty_parameters
            .contains("sxlt: this.sxlt, pidx: this.pidx, kidx: this.kidx, stem: this.stem, tier: this.tier")
    );
    assert!(
        declarations
            .randy_parameters
            .contains("nxts: this.nxts, prxs: this.prxs, transferable: this.transferable")
    );
    assert!(declarations.group_parameters.contains("mhab: this.mhab"));
    assert!(declarations.reloaded_randy_transferability.contains("aid['prefix']"));

    // `EventResult` and the signing entry point this item also owns.
    assert!(declarations.event_result_members.iter().any(|member| member == "op"));
    assert!(declarations.signed_request_resource.contains("Signify-Resource"));
    assert!(declarations.signed_request_signer.contains("keeper.signers[0]"));
    assert!(declarations.notes.is_object());
    Ok(())
}

#[test]
fn every_path_the_pinned_test_asserts_is_produced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(fixture.pinned_confirmations.every_pinned_path_is_driven);
    assert!(fixture.pinned_confirmations.create_signed_request_is_published);
    assert!(!fixture.pinned_confirmations.note.is_empty());
    for path in [
        "/identifiers",
        "/identifiers/aid1",
        "/identifiers/aid1/events",
        "/identifiers/aid1/endroles",
        "/identifiers/aid1/locschemes",
        "/identifiers/aid1/members",
    ] {
        assert!(
            fixture.pinned_confirmations.published_paths.contains(&path.to_owned()),
            "{path} is not published by the pinned test"
        );
        assert!(
            fixture.pinned_confirmations.driven_paths.contains(&path.to_owned()),
            "{path} was not driven"
        );
    }
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 13);
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
fn a_listing_sends_the_recorded_range_and_reads_the_window_back() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    for (name, window) in [
        ("list_default", ItemRange::DEFAULT),
        ("list_explicit_range", ItemRange::new(2, 5)?),
    ] {
        let recorded = request_of(&fixture, name)?;
        let (client, transport) = connected(&[b"[]"])?;
        let _ = block_on(client.identifiers().list(window));
        let (path, method, body) = sent(&transport, 0)?;
        assert_eq!(path, recorded.path);
        assert_eq!(method, recorded.method);
        assert_eq!(body, None, "a listing sends no body, as upstream");

        // The `Range` header is the only one this family adds, and it matches byte for byte.
        let expected = recorded
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("range"))
            .ok_or("no recorded range header")?;
        let requests = transport.requests();
        let request = requests.get(2).ok_or("no endpoint request")?;
        assert_eq!(request.headers().get("range"), Some(expected.value.as_str()));
    }
    Ok(())
}

#[test]
fn an_absent_content_range_is_told_apart_from_an_empty_one() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "list_without_content_range")?;
    // The reference reports {0, 0, 0} for an answer carrying no header at all.
    assert_eq!(recorded.result.get("total"), Some(&Value::from(0)));
    assert_eq!(
        recorded.result.get("aids").and_then(Value::as_array).map(Vec::len),
        Some(2)
    );

    let (client, transport) = connected(&[b"[]"])?;
    let listing = block_on(client.identifiers().list(ItemRange::DEFAULT))?;
    assert!(listing.window.is_none(), "an unreported window is not a zero one");
    assert!(listing.identifiers.is_empty());
    assert_eq!(
        sent(&transport, 0)?.0,
        recorded.request.as_ref().map_or("", |r| &r.path)
    );
    Ok(())
}

#[test]
fn a_get_addresses_the_recorded_path_and_encodes_its_name() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let document = record_document(&fixture)?;

    let plain = request_of(&fixture, "get")?;
    let (client, transport) = connected(&[&document])?;
    let record = block_on(client.identifiers().get("aid1"))?;
    assert_eq!(sent(&transport, 0)?.0, plain.path);
    assert_eq!(
        Some(record.common.prefix.as_str()),
        call(&fixture, "get")?.result.get("prefix").and_then(Value::as_str)
    );

    // The pinned unit test's own awkward name, which the reference encodes and so does this.
    let encoded = request_of(&fixture, "get_name_needing_encoding")?;
    let (client, transport) = connected(&[&document])?;
    let _ = block_on(client.identifiers().get("a name with ñ!"));
    assert_eq!(sent(&transport, 0)?.0, encoded.path);
    assert_eq!(encoded.path, "/identifiers/a%20name%20with%20%C3%B1!");
    Ok(())
}

#[test]
fn a_pending_group_is_refused_by_get_and_returned_by_get_any() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let refused = call(&fixture, "get_pending_refused")?;
    assert_eq!(refused.error.as_deref(), Some("No key state for identifier group1"));

    // The same record with its key state removed, which is what the generator sent.
    let mut document: Value = serde_json::from_slice(&record_document(&fixture)?)?;
    if let Some(fields) = document.as_object_mut() {
        fields.remove("state");
        fields.insert("name".to_owned(), Value::String("group1".to_owned()));
    }
    let body = serde_json::to_vec(&document)?;

    let (client, transport) = connected(&[&body])?;
    let outcome = block_on(client.identifiers().get("group1"));
    assert!(matches!(
        outcome,
        Err(ClientError::IdentifierNotAccepted { ref name }) if name == "group1"
    ));
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/group1");

    let (client, _) = connected(&[&body])?;
    let pending = block_on(client.identifiers().get_any("group1"))?;
    assert!(pending.key_state().is_none());
    assert_eq!(pending.common().name, "group1");
    Ok(())
}

#[test]
fn an_update_sends_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "update")?;
    let (client, transport) = connected(&[&record_document(&fixture)?])?;
    let _ = block_on(client.identifiers().update("aid1", &IdentifierUpdate::rename("aid2")));
    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_eq!(body.as_deref(), Some(r#"{"name":"aid2"}"#));
    assert_eq!(body.as_deref(), recorded.body.as_deref());
    Ok(())
}

#[test]
fn a_member_listing_addresses_the_recorded_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "members")?;
    let (client, transport) = connected(&[br#"{"signing":[],"rotation":[]}"#])?;
    let members = block_on(client.identifiers().members("aid1"))?;
    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_eq!(body, None);
    assert!(members.signing.is_empty() && members.rotation.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Writes.
// ---------------------------------------------------------------------------

/// The creation request the reference's `create('aid1', {bran})` amounts to.
fn salty_request(passcode: &str, keys: usize) -> CreateIdentifierRequest {
    CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some(passcode.to_owned()),
        tier: SecurityTier::Low,
        current_count: keys,
        next_count: keys,
        cost: DerivationCost::Production,
    })
}

#[test]
fn a_default_creation_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "create_salty")?;
    let (client, transport) = connected(&[b"{}"])?;
    let submission = block_on(client.identifiers().create("aid1", &salty_request(PASSCODE, 1)))?;

    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_body(body.as_deref(), recorded, PASSCODE)?;
    // The artifact returned is the same event the body carries, and the pinned unit test
    // publishes exactly that identifier.
    let identifier = submission.artifact().event.identifier().qb64()?;
    assert_eq!(identifier, "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK");
    assert!(recorded.body.as_deref().is_some_and(|text| text.contains(&identifier)));
    assert_eq!(submission.artifact().signatures.len(), 1);
    Ok(())
}

#[test]
fn a_non_transferable_creation_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "create_non_transferable")?;
    let mut request = salty_request(PASSCODE, 1);
    request.transferability = KeyTransferability::NonTransferable;
    if let CreateAlgorithm::Salty { next_count, .. } = &mut request.algorithm {
        *next_count = 0;
    }

    let (client, transport) = connected(&[b"{}"])?;
    let _ = block_on(client.identifiers().create("aid1", &request))?;
    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);

    // This body differs from the reference's in exactly one field, and only here: `create` reuses
    // one variable for the prefix code and the stored digest code, so a non-transferable record
    // names the basic prefix code `B` where the digest algorithm belongs. Roadmap 4.6 recorded the
    // divergence; this is where it reaches the wire.
    let expected = recorded.body.as_deref().ok_or("the recorded request carried no body")?;
    assert!(expected.contains(r#""dcode":"B""#));
    assert_eq!(expected.matches(r#""dcode""#).count(), 1);
    let (masked, opened) = mask_sealed(body.as_deref().ok_or("no body was sent")?, PASSCODE)?;
    assert!(masked.contains(r#""dcode":"E""#));
    assert_eq!(masked, expected.replace(r#""dcode":"B""#, r#""dcode":"E""#));
    assert_eq!(opened, recorded.sxlt_opens_to);
    assert_eq!(
        fixture
            .reference_quirks
            .get("non_transferable_stores_the_prefix_code_as_its_digest_code")
            .and_then(|entry| entry.get("stored_dcode"))
            .and_then(Value::as_str),
        Some("B")
    );
    Ok(())
}

#[test]
fn a_multisig_creation_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "create_multisig")?;
    let mut request = salty_request(MULTISIG_PASSCODE, 3);
    request.signing_threshold = Some(signify_keri::threshold::SigningThreshold::numeric(2));
    request.next_threshold = Some(signify_keri::threshold::SigningThreshold::numeric(2));

    let (client, transport) = connected(&[b"{}"])?;
    let _ = block_on(client.identifiers().create("aid2", &request))?;
    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    // The identifier derives from its own passcode, but its salt is sealed to the *client's*
    // controller key — which is what the generator's mock client used too.
    assert_body(body.as_deref(), recorded, PASSCODE)?;
    assert_eq!(recorded.sxlt_opens_to, [format!("0AA{MULTISIG_PASSCODE}")]);
    Ok(())
}

#[test]
fn a_witnessed_creation_writes_the_proxy_the_others_omit() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "create_witnessed_with_proxy")?;
    let mut request = salty_request(PASSCODE, 1);
    request.witnesses = fixture
        .provenance
        .witnesses
        .iter()
        .map(|witness| IdentifierPrefix::from_qb64(witness))
        .collect::<Result<Vec<_>, _>>()?;
    request.witness_threshold = 2;
    request.proxy = Some("EPROXY".to_owned());

    let (client, transport) = connected(&[b"{}"])?;
    let _ = block_on(client.identifiers().create("aid3", &request))?;
    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_body(body.as_deref(), recorded, PASSCODE)?;
    // Seven fields would be a group; this is five, because `proxy` is the only optional one set.
    assert!(
        recorded
            .body
            .as_deref()
            .is_some_and(|text| text.contains(r#""proxy":"EPROXY""#))
    );
    assert!(recorded.body.as_deref().is_some_and(|text| !text.contains("smids")));
    Ok(())
}

#[test]
fn a_delegated_creation_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "create_delegated_with_data")?;
    let mut request = salty_request(PASSCODE, 1);
    request.delegator = Some(IdentifierPrefix::from_qb64(DELEGATOR)?);
    let mut anchor = Sad::new();
    anchor.insert("i", DELEGATOR.to_owned())?;
    anchor.insert("s", "0".to_owned())?;
    anchor.insert("d", DELEGATOR.to_owned())?;
    request.anchor = Some(anchor);

    let (client, transport) = connected(&[b"{}"])?;
    let _ = block_on(client.identifiers().create("aid4", &request))?;
    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_body(body.as_deref(), recorded, PASSCODE)?;
    Ok(())
}

#[test]
fn a_group_creation_writes_both_member_lists_and_the_member_record() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "create_group")?;

    let member1: AcceptedHab = serde_json::from_slice(&reseal(&fixture.group_creation.members.member1, PASSCODE)?)?;
    let member2: AcceptedHab = serde_json::from_slice(&reseal(
        &fixture.group_creation.members.member2,
        &fixture.provenance.member_two_bran,
    )?)?;
    let member3: AcceptedHab =
        serde_json::from_slice(&reseal(&fixture.group_creation.members.member3, MULTISIG_PASSCODE)?)?;

    let states = vec![(*member1.state).clone(), (*member2.state).clone()];
    let next_states = vec![(*member2.state).clone(), (*member3.state).clone()];
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::Group {
        member: Box::new(member1),
        states,
        next_states,
    });
    request.signing_threshold = Some(signify_keri::threshold::SigningThreshold::numeric(1));
    request.next_threshold = Some(signify_keri::threshold::SigningThreshold::numeric(1));

    let (client, transport) = connected(&[b"{}"])?;
    let _ = block_on(client.identifiers().create("group1", &request))?;
    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_body(body.as_deref(), recorded, PASSCODE)?;
    assert!(
        recorded
            .body
            .as_deref()
            .is_some_and(|text| text.contains(r#""smids":[""#))
    );
    assert!(
        recorded
            .body
            .as_deref()
            .is_some_and(|text| text.contains(r#""rmids":[""#))
    );
    Ok(())
}

#[test]
fn an_interaction_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "interact")?;
    let document = record_document(&fixture)?;

    let (client, transport) = connected(&[&document, b"{}"])?;
    let prefix = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
    let mut seal = Sad::new();
    seal.insert("i", prefix.to_owned())?;
    seal.insert("s", signify_keri::serialization::SadValue::integer(0)?)?;
    seal.insert("d", prefix.to_owned())?;
    let _ = block_on(client.identifiers().interact("aid1", vec![seal]))?;

    // Two requests: the record read, then the submission — exactly as many as the reference made.
    assert_eq!(call(&fixture, "interact")?.requests, 2);
    assert_eq!(transport.requests().len(), 2 + call(&fixture, "interact")?.requests);
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/aid1");
    let (path, method, body) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_body(body.as_deref(), recorded, PASSCODE)?;
    Ok(())
}

#[test]
fn an_alias_can_never_leave_its_own_path_segment() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "interact_name_needing_encoding")?;
    // The reference sends `/identifiers/a/b/events`: a slash in an alias silently addresses a
    // different resource, and Roadmap 3.10 signs `@path`, so it changes what is signed too.
    assert_eq!(recorded.path, "/identifiers/a/b/events");

    let (client, transport) = connected(&[&record_document(&fixture)?, b"{}"])?;
    let _ = block_on(client.identifiers().interact("a/b", Vec::new()));
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/a%2Fb");
    Ok(())
}

#[test]
fn a_rotation_always_writes_both_member_lists() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "rotate")?;
    let (client, transport) = connected(&[&record_document(&fixture)?, b"{}"])?;
    let _ = block_on(client.identifiers().rotate("aid1", &RotateIdentifierRequest::default()))?;

    let (path, method, body) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_body(body.as_deref(), recorded, PASSCODE)?;
    // Empty here and absent from a creation: the reference defaults them before mapping.
    assert!(
        recorded
            .body
            .as_deref()
            .is_some_and(|text| text.contains(r#""smids":[],"rmids":[]"#))
    );
    Ok(())
}

#[test]
fn an_end_role_reply_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let document = record_document(&fixture)?;
    let stamp = Timestamp::parse(STAMP)?;

    for (name, endpoint) in [
        ("add_end_role", Some(IdentifierPrefix::from_qb64(DELEGATOR)?)),
        ("add_end_role_without_endpoint", None),
    ] {
        let recorded = request_of(&fixture, name)?;
        let (client, transport) = connected(&[&document, b"{}"])?;
        let _ = block_on(
            client
                .identifiers()
                .add_end_role("aid1", &Role::Agent, endpoint.as_ref(), stamp.clone()),
        )?;
        let (path, method, body) = sent(&transport, 1)?;
        assert_eq!(path, recorded.path);
        assert_eq!(method, recorded.method);
        assert_body(body.as_deref(), recorded, PASSCODE)?;
    }
    Ok(())
}

#[test]
fn a_location_scheme_reply_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let document = record_document(&fixture)?;
    let stamp = Timestamp::parse(STAMP)?;

    let explicit = LocationSchemeRequest {
        url: "https://test.com".to_owned(),
        scheme: Some("https".to_owned()),
        endpoint: Some(IdentifierPrefix::from_qb64(
            "EHgwVwQT15OJvilVvW57HE4w0-GPs_Stj2OFoAHZSysY",
        )?),
        stamp: stamp.clone(),
    };
    let defaulted = LocationSchemeRequest {
        url: "http://test.com".to_owned(),
        scheme: None,
        endpoint: None,
        stamp,
    };

    for (name, request) in [
        ("add_location_scheme", &explicit),
        ("add_location_scheme_defaults", &defaulted),
    ] {
        let recorded = request_of(&fixture, name)?;
        let (client, transport) = connected(&[&document, b"{}"])?;
        let _ = block_on(client.identifiers().add_location_scheme("aid1", request))?;
        let (path, method, body) = sent(&transport, 1)?;
        assert_eq!(path, recorded.path);
        assert_eq!(method, recorded.method);
        assert_body(body.as_deref(), recorded, PASSCODE)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The prefix index, the randy shape, and the signed external request.
// ---------------------------------------------------------------------------

#[test]
fn the_prefix_index_advances_with_every_creation() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference's own walk: the first body carries index 0, the second index 1.
    let quirk = fixture
        .reference_quirks
        .get("pidx_advances_on_the_client")
        .and_then(|entry| entry.get("walk"))
        .ok_or("no recorded prefix-index walk")?;
    assert_eq!(quirk.get("first_body_pidx"), Some(&Value::from(0)));
    assert_eq!(quirk.get("second_body_pidx"), Some(&Value::from(1)));
    assert_eq!(quirk.get("after_second"), Some(&Value::from(2)));
    assert_eq!(call(&fixture, "create_salty")?.pidx_after, 1);

    let (client, transport) = connected(&[b"{}", b"{}"])?;
    assert_eq!(client.prefix_index(), 0);
    let _ = block_on(client.identifiers().create("aid1", &salty_request(PASSCODE, 1)))?;
    assert_eq!(client.prefix_index(), 1);
    let _ = block_on(client.identifiers().create("aid2", &salty_request(PASSCODE, 1)))?;
    assert_eq!(client.prefix_index(), 2);

    let first = sent(&transport, 0)?.2.unwrap_or_default();
    let second = sent(&transport, 1)?.2.unwrap_or_default();
    assert!(first.contains(r#""pidx":0"#));
    assert!(second.contains(r#""pidx":1"#));
    Ok(())
}

#[test]
fn a_randy_creation_has_the_recorded_shape() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // Random keys cannot be pinned, so the shape is what is compared.
    assert_eq!(fixture.randy_shape.path, "/identifiers");
    assert_eq!(fixture.randy_shape.method, "POST");
    assert_eq!(fixture.randy_shape.randy_fields, ["nxts", "prxs", "transferable"]);

    let (client, transport) = connected(&[b"{}"])?;
    let request = CreateIdentifierRequest::new(CreateAlgorithm::Randy {
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Ephemeral,
    });
    let submission = block_on(client.identifiers().create("aid1", &request))?;
    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, fixture.randy_shape.path);
    assert_eq!(method, fixture.randy_shape.method);

    let rendered = body.unwrap_or_default();
    let document: Value = serde_json::from_str(&rendered)?;
    let randy = document
        .get("randy")
        .and_then(Value::as_object)
        .ok_or("the body carries no randy block")?;
    let mut sorted = fixture.randy_shape.randy_fields.clone();
    sorted.sort();
    // A `serde_json::Map` sorts its keys, so the *order* is asserted on the rendered text.
    assert_eq!(randy.keys().cloned().collect::<Vec<_>>(), sorted);
    assert!(rendered.contains(r#""randy":{"nxts":["#));
    assert_eq!(
        randy.get("prxs").and_then(Value::as_array).map(Vec::len),
        Some(fixture.randy_shape.prxs_count)
    );
    assert_eq!(
        randy.get("nxts").and_then(Value::as_array).map(Vec::len),
        Some(fixture.randy_shape.nxts_count)
    );
    assert_eq!(
        document.get("sigs").and_then(Value::as_array).map(Vec::len),
        Some(fixture.randy_shape.sig_count)
    );
    assert_eq!(submission.artifact().signatures.len(), fixture.randy_shape.sig_count);

    // The field the schema does not declare, written back exactly as the reference writes it.
    assert_eq!(randy.get("transferable"), Some(&Value::Bool(true)));
    assert_eq!(
        fixture.randy_reload_shape.randy_fields,
        ["nxts", "prxs", "transferable"]
    );
    assert!(fixture.randy_reload_shape.randy_transferable);
    assert_eq!(fixture.randy_reload_shape.prefix_code, "E");
    Ok(())
}

#[test]
fn an_external_request_is_signed_with_the_identifiers_own_key() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let signed = &fixture.signed_request;
    assert_eq!(signed.agent_prefix, AGENT);

    let (client, transport) = connected(&[&record_document(&fixture)?])?;
    // The recorded controller prefix is the generator's, derived at the production Argon2 profile
    // Roadmap 6.4's fixture already proves; this client derives its controller cheaply, which
    // reaches nothing compared here — `createSignedRequest` never uses the controller's key.
    assert!(!signed.controller_prefix.is_empty());

    let url = signify_http::transport::RequestUrl::new(&signed.post.url)?;
    let request = Request::builder(Method::Post, url)
        .body(br#"{"hello":"world"}"#.to_vec())
        .build()?;
    let external = block_on(client.sign_external_request("aid1", request))?;

    // The lookup goes to the agent; the signed request itself is never sent from here.
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/aid1");
    assert_eq!(signed.lookup_path, format!("{ADMIN}{}", sent(&transport, 0)?.0));
    assert_eq!(external.url().as_str(), signed.post.url);
    assert_eq!(external.method().as_str(), signed.post.method);

    // Every header the reference produced, byte for byte — including the signature, because the
    // clock is pinned on both sides.
    for header in &signed.post.headers {
        if header.name == "content-type" {
            // The browser `Request` adds a `text/plain` content type for a string body. It is not
            // a covered component and nothing sends it here.
            continue;
        }
        assert_eq!(
            external.headers().get(&header.name),
            Some(header.value.as_str()),
            "header {} does not match",
            header.name
        );
    }
    // The resource stamped is the *identifier's* prefix, not the controller's.
    assert_ne!(signed.controller_prefix, signed.identifier_signing_key);
    assert_eq!(
        external.headers().get("signify-resource"),
        fixture.signed_request.identifier.get("prefix").and_then(Value::as_str)
    );
    assert!(
        signed
            .post
            .headers
            .iter()
            .any(|header| header.name == "signature-input" && header.value.contains(&signed.identifier_signing_key))
    );
    Ok(())
}

#[test]
fn an_external_request_without_a_body_matches_the_recorded_get() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let signed = &fixture.signed_request;
    let (client, _) = connected(&[&record_document(&fixture)?])?;

    let url = signify_http::transport::RequestUrl::new(&signed.get.url)?;
    let request = Request::builder(Method::Get, url).build()?;
    let external = block_on(client.sign_external_request("aid1", request))?;
    for header in &signed.get.headers {
        assert_eq!(
            external.headers().get(&header.name),
            Some(header.value.as_str()),
            "header {} does not match",
            header.name
        );
    }
    assert!(!signed.get.note.is_empty());
    assert_eq!(signed.fixed_clock_ms, FIXED_MILLIS);
    Ok(())
}
