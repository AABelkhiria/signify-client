//! Exact IPEX-submission vectors recorded from the pinned reference's own `Ipex`.
//!
//! The pinned `test/app/credentialing.test.ts` calls all five submitters across its three IPEX
//! cases and asserts each one's full URL, which is the whole of what it checks about them — no body
//! is asserted anywhere. So the generator builds each message through the reference's own Roadmap
//! 6.3 builder and then submits it through the reference's own submitter, recording the request
//! that leaves; every recorded `exn` is one `fixtures/acdc-ipex/v1.json` has already proven
//! byte-exact, and this file proves the body assembled around it.
//!
//! The sender's keys derive at the reference's production Argon2 cost, so this file is deliberately
//! slow. Everything else is deterministic: every message's timestamp is supplied.

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::Value;
use signify_acdc::credential::{Credential, CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use signify_acdc::ipex::{Disclosure, IpexEnvelope, IpexMessage, IpexRoute, admit, agree, apply, grant, offer};
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::ipex::IPEX_SEGMENT;
use signify_client::error::ClientError;
use signify_crypto::salt::{Salt, SecurityTier};
use signify_crypto::signer::Signer;
use signify_crypto::verifier::KeyTransferability;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::request::ResourcePath;
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::authentication::RequestSigner;
use signify_http::signature::input::{RequestTarget, default_components};
use signify_http::signature::timestamp::SignifyTimestamp;
use signify_http::transport::{Method, Request, Response, StatusCode, Transport, TransportError, TransportFuture};
use signify_keri::event::Timestamp;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::manager::{DerivationCost, IdentifierKeeper, KeeperFactory};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-ipex/v1.json");

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
    embedded_artifacts: EmbeddedArtifacts,
    messages: std::collections::BTreeMap<String, MessageRecord>,
    calls: Vec<Call>,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    boot_url: String,
    stamp: String,
    agent_prefix: String,
    sender_alias: String,
    sender: String,
    recipient: String,
    second_recipient: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    class_members: Vec<String>,
    submit_apply: Submitter,
    submit_offer: Submitter,
    submit_agree: Submitter,
    submit_grant: Submitter,
    submit_admit: Submitter,
    usage_scan: Value,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct Submitter {
    parameters: Vec<String>,
    body: String,
    path: String,
    returns: String,
}

#[derive(Debug, Deserialize)]
struct EmbeddedArtifacts {
    acdc_raw: String,
    iss_raw: String,
    anc_raw: String,
    anchor_attachment: String,
    schema: String,
    lei: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct MessageRecord {
    raw: String,
    said: String,
    route: String,
    addressed_to: String,
    attachment: String,
    signatures: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    request: Option<RecordedRequest>,
    requests: usize,
    #[serde(default)]
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
    unit_test_file: String,
    unit_test_files_naming_ipex: Vec<String>,
    published_submission_urls: Vec<String>,
    published_routes: Vec<String>,
    accessor_assertion: bool,
    accessor_assertions_that_do_exist: Vec<String>,
    submitter_call_sites: Value,
    driven_paths: Vec<String>,
    distinct_submission_urls: Vec<String>,
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

/// Returns the path, method, and body of the endpoint request at `index`.
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

// ---------------------------------------------------------------------------
// Rebuilding the five messages the generator submitted.
// ---------------------------------------------------------------------------

/// The sender's keeper, at the reference's production cost so its signatures are the recorded ones.
fn keeper(passcode: &str) -> Result<Box<dyn IdentifierKeeper>, Box<dyn Error>> {
    let salt = Salt::from_qb64(&format!("0AA{}", &passcode[..21]), SecurityTier::Low)?;
    let factory = KeeperFactory::new(salt);
    let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some(passcode.to_owned()),
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Production,
    });
    Ok(factory.create(request.keeper_request(0)?)?)
}

fn envelope(fixture: &Fixture, message: &str) -> Result<IpexEnvelope, Box<dyn Error>> {
    Ok(IpexEnvelope::new(
        IdentifierPrefix::from_qb64(&fixture.provenance.sender)?,
        IdentifierPrefix::from_qb64(&fixture.provenance.recipient)?,
        message,
        fixture.provenance.stamp.parse::<Timestamp>()?,
    )?)
}

fn credential(fixture: &Fixture) -> Result<Credential, Box<dyn Error>> {
    let sad = Sad::from_json_bytes(fixture.embedded_artifacts.acdc_raw.as_bytes())?;
    let attributes = sad
        .get("a")
        .and_then(SadValue::as_map)
        .ok_or("the recorded credential has no attribute block")?;
    Ok(CredentialBuilder::new(
        IdentifierPrefix::from_qb64(sad.get_text("i").ok_or("no issuer")?)?,
        RegistryIdentifier::from_qb64(sad.get_text("ri").ok_or("no registry")?)?,
        Said::from_qb64(sad.get_text("s").ok_or("no schema")?)?,
        CredentialAttributes::new(attributes.get_text("dt").ok_or("no timestamp")?.parse::<Timestamp>()?)
            .issuee(&IdentifierPrefix::from_qb64(
                attributes.get_text("i").ok_or("no issuee")?,
            )?)?
            .timestamp()?
            .text("LEI", attributes.get_text("LEI").ok_or("no LEI")?)?,
    )
    .build()?)
}

fn disclosure(fixture: &Fixture) -> Result<Disclosure, Box<dyn Error>> {
    use signify_acdc::issuance::IssuanceEvent;
    use signify_keri::attachment::{AttachmentFraming, SealSourceCouple};

    let credential = credential(fixture)?;
    let issuance = IssuanceEvent::for_credential(&credential)?;
    let anchor = SerializedEvent::parse(fixture.embedded_artifacts.anc_raw.as_bytes())?;
    let anchor_said = Said::from_qb64(anchor.said().ok_or("the anchor carries no identifier")?)?;
    let anchor_sequence = anchor
        .sequence_number()?
        .ok_or("the anchor carries no sequence number")?
        .value();
    let couple = SealSourceCouple::new(anchor_sequence.into(), anchor_said);

    Ok(Disclosure::new(
        credential.serialized().clone(),
        issuance.credential_attachment()?,
        issuance.serialized().clone(),
        couple.attachment(AttachmentFraming::Pipelined)?,
        anchor,
        fixture.embedded_artifacts.anchor_attachment.clone().into_bytes(),
    ))
}

/// The five messages, in conversation order, each chaining on the one before it.
fn conversation(fixture: &Fixture) -> Result<Vec<(&'static str, IpexMessage)>, Box<dyn Error>> {
    let keeper = keeper(&fixture.provenance.bran)?;
    let keeper = keeper.as_ref();

    let mut attributes = Sad::new();
    attributes.insert("LEI", fixture.embedded_artifacts.lei.as_str())?;
    let applied = apply(
        keeper,
        &envelope(fixture, "Applying")?,
        Said::from_qb64(&fixture.embedded_artifacts.schema)?,
        attributes,
    )?;

    let credential = credential(fixture)?;
    let offered = offer(
        keeper,
        &envelope(fixture, "How about this")?,
        &credential,
        Some(applied.said()),
    )?;
    let agreed = agree(keeper, &envelope(fixture, "OK!")?, offered.said())?;

    let granted = grant(
        keeper,
        &envelope(fixture, "")?,
        &disclosure(fixture)?,
        Some(agreed.said()),
    )?;
    let admitted = admit(keeper, &envelope(fixture, "")?, granted.said())?;

    Ok(vec![
        ("apply", applied),
        ("offer", offered),
        ("agree", agreed),
        ("grant", granted),
        ("admit", admitted),
    ])
}

fn recipients(fixture: &Fixture) -> Result<Vec<IdentifierPrefix>, Box<dyn Error>> {
    Ok(vec![IdentifierPrefix::from_qb64(&fixture.provenance.recipient)?])
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
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert_eq!(fixture.provenance.sender_alias, "multisig");
    assert!(!fixture.provenance.sender.is_empty());
    assert!(!fixture.provenance.recipient.is_empty());
    assert!(!fixture.provenance.second_recipient.is_empty());
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));
    assert!(!fixture.embedded_artifacts.note.is_empty());
    // The three artifacts a grant embeds, each rebuilt below and each appearing in its body.
    let grant_body = request_of(&fixture, "grant")?.body.clone().unwrap_or_default();
    for artifact in [
        &fixture.embedded_artifacts.acdc_raw,
        &fixture.embedded_artifacts.iss_raw,
        &fixture.embedded_artifacts.anc_raw,
    ] {
        let embedded = artifact.trim_start_matches('{').trim_end_matches('}');
        assert!(
            grant_body.contains(embedded),
            "an embedded artifact is missing from the recorded grant body"
        );
    }

    assert_eq!(fixture.calls.len(), 11);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
        assert_eq!(entry.requests, 1, "call {} sent more than one request", entry.name);
    }
    // Five messages, one per route.
    assert_eq!(fixture.messages.len(), 5);
    for route in IpexRoute::ALL {
        let name = route.as_str().trim_start_matches("/ipex/");
        let record = fixture
            .messages
            .get(name)
            .ok_or_else(|| format!("no recorded message {name}"))?;
        assert_eq!(record.route, route.as_str());
        assert_eq!(record.addressed_to, fixture.provenance.recipient);
    }
    Ok(())
}

#[test]
fn the_pinned_unit_test_publishes_all_five_submission_urls() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;
    assert_eq!(pinned.unit_test_file, "test/app/credentialing.test.ts");
    assert!(!pinned.note.is_empty());
    assert!(pinned.submitter_call_sites.is_object());

    // Eight assertions across three cases, over five distinct addresses.
    assert_eq!(pinned.published_submission_urls.len(), 8);
    assert_eq!(pinned.distinct_submission_urls.len(), 5);
    for route in IpexRoute::ALL {
        let segment = route.as_str().trim_start_matches("/ipex/");
        assert!(
            pinned
                .distinct_submission_urls
                .iter()
                .any(|url| url.ends_with(&format!("/identifiers/multisig/ipex/{segment}"))),
            "the pinned test publishes no submission URL for {route}"
        );
        assert!(pinned.published_routes.iter().any(|value| value == route.as_str()));
    }
    // Every address the reference sent is one this port also produces.
    for path in &pinned.driven_paths {
        assert!(path.starts_with("/identifiers/"), "an unexpected address: {path}");
    }

    // The accessor is the one endpoint accessor `clienting.test.ts` does *not* type-assert.
    assert!(!pinned.accessor_assertion);
    assert!(!pinned.accessor_assertions_that_do_exist.is_empty());
    assert_eq!(pinned.unit_test_files_naming_ipex, ["test/app/credentialing.test.ts"]);
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    for member in [
        "submitApply",
        "submitOffer",
        "submitAgree",
        "submitGrant",
        "submitAdmit",
    ] {
        assert!(
            declarations.class_members.iter().any(|name| name == member),
            "the class no longer declares {member}"
        );
    }

    // Two submitters take no `atc` at all; the other three do.
    let without: [&Submitter; 2] = [&declarations.submit_apply, &declarations.submit_agree];
    let with: [&Submitter; 3] = [
        &declarations.submit_offer,
        &declarations.submit_grant,
        &declarations.submit_admit,
    ];
    for submitter in without {
        assert!(
            !submitter
                .parameters
                .iter()
                .any(|parameter| parameter.starts_with("atc")),
            "a submitter unexpectedly declares an attachment"
        );
        assert!(
            !submitter.body.contains("atc"),
            "a body unexpectedly writes an attachment"
        );
    }
    for submitter in with {
        assert!(
            submitter
                .parameters
                .iter()
                .any(|parameter| parameter.starts_with("atc")),
            "a submitter no longer declares an attachment"
        );
        assert!(submitter.body.contains("atc"));
    }

    // Every submitter writes the same three other fields, addresses `/ipex/`, and casts its answer.
    for submitter in [without.as_slice(), with.as_slice()].concat() {
        for label in ["exn:", "sigs", "rec:"] {
            assert!(submitter.body.contains(label), "a body lacks {label}");
        }
        assert!(submitter.path.contains("/ipex/"));
        assert!(submitter.path.contains("${name}"));
        assert!(!submitter.path.contains("encodeURIComponent"));
        assert!(submitter.returns.contains("response.json()"));
    }
    assert!(declarations.notes.is_object());
    assert!(declarations.usage_scan.is_object());
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 6);
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
// The five submissions.
// ---------------------------------------------------------------------------

#[test]
fn every_message_rebuilds_byte_for_byte_before_it_is_submitted() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, message) in conversation(&fixture)? {
        let recorded = fixture
            .messages
            .get(name)
            .ok_or_else(|| format!("no recorded message {name}"))?;
        assert_eq!(core::str::from_utf8(message.raw())?, recorded.raw, "{name} differs");
        assert_eq!(message.said().qb64()?, recorded.said);
        assert_eq!(message.route().as_str(), recorded.route);
        assert_eq!(message.signatures().qb64()?, recorded.signatures);
        assert_eq!(core::str::from_utf8(message.attachments())?, recorded.attachment);
    }
    Ok(())
}

#[test]
fn all_five_submissions_reproduce_the_recorded_requests() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recipients = recipients(&fixture)?;
    let answer = serde_json::to_vec(&call(&fixture, "grant")?.result)?;
    let answers: Vec<&[u8]> = core::iter::repeat_n(answer.as_slice(), 5).collect();
    let (client, transport) = connected(&answers)?;

    for (index, (name, message)) in conversation(&fixture)?.into_iter().enumerate() {
        let recorded = request_of(&fixture, name)?;
        let submitted = block_on(client.ipex().submit("multisig", &message, &recipients))?;
        assert_eq!(submitted.route(), message.route());

        let (path, method, body) = sent(&transport, index)?;
        assert_eq!(path, recorded.path, "{name} addressed a different resource");
        assert_eq!(path, format!("/identifiers/multisig/ipex/{name}"));
        assert_eq!(method, recorded.method);
        assert_eq!(method, "POST");
        assert_eq!(
            body.as_deref(),
            recorded.body.as_deref(),
            "{name} sent a different body"
        );

        // The two routes with no `atc` write three fields; the other three write four.
        let document: Value = serde_json::from_str(&body.unwrap_or_default())?;
        let fields = document.as_object().ok_or("a body is not an object")?;
        let expected = if matches!(name, "apply" | "agree") { 3 } else { 4 };
        assert_eq!(fields.len(), expected, "{name} wrote {} fields", fields.len());
        assert_eq!(fields.contains_key("atc"), expected == 4);
    }
    Ok(())
}

#[test]
fn two_routes_discard_an_attachment_that_is_always_empty() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference's own `apply` and `agree` return an attachment their submitters never send.
    for name in ["apply", "agree"] {
        let record = fixture
            .messages
            .get(name)
            .ok_or_else(|| format!("no recorded message {name}"))?;
        assert_eq!(record.attachment, "", "{name} recorded a non-empty attachment");
        assert!(
            !request_of(&fixture, name)?
                .body
                .clone()
                .unwrap_or_default()
                .contains("atc")
        );
    }
    // The one route that really carries material is the grant.
    let grant = fixture.messages.get("grant").ok_or("no recorded grant")?;
    assert!(grant.attachment.starts_with("-LAg"));
    assert!(
        request_of(&fixture, "grant")?
            .body
            .clone()
            .unwrap_or_default()
            .contains("atc")
    );
    // An offer and an admit send an `atc` that is the empty string.
    for name in ["offer", "admit"] {
        let record = fixture
            .messages
            .get(name)
            .ok_or_else(|| format!("no recorded message {name}"))?;
        assert_eq!(record.attachment, "");
        assert!(
            request_of(&fixture, name)?
                .body
                .clone()
                .unwrap_or_default()
                .contains(r#""atc":"""#)
        );
    }
    Ok(())
}

#[test]
fn a_route_can_never_disagree_with_the_resource_it_is_posted_to() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference posted a grant to `/ipex/apply` and an apply to `/ipex/grant`.
    let grant_to_apply = request_of(&fixture, "grant_through_the_apply_submitter")?;
    assert_eq!(grant_to_apply.path, "/identifiers/multisig/ipex/apply");
    assert!(
        grant_to_apply
            .body
            .clone()
            .unwrap_or_default()
            .contains(r#""r":"/ipex/grant""#)
    );
    let apply_to_grant = request_of(&fixture, "apply_through_the_grant_submitter")?;
    assert_eq!(apply_to_grant.path, "/identifiers/multisig/ipex/grant");
    assert!(
        apply_to_grant
            .body
            .clone()
            .unwrap_or_default()
            .contains(r#""r":"/ipex/apply""#)
    );

    // Here the address is read from the message, so both are unrepresentable.
    let recipients = recipients(&fixture)?;
    let (client, transport) = connected(&[b"{}", b"{}"])?;
    let messages = conversation(&fixture)?;
    for (name, message) in &messages {
        if !matches!(*name, "apply" | "grant") {
            continue;
        }
        let index = usize::from(*name == "grant");
        let _ = block_on(client.ipex().submit("multisig", message, &recipients))?;
        let (path, _, body) = sent(&transport, index)?;
        let route = message.route().as_str();
        assert!(
            path.ends_with(route.trim_start_matches('/').trim_start_matches("ipex/")),
            "{path} does not address {route}"
        );
        assert!(body.unwrap_or_default().contains(&format!(r#""r":"{route}""#)));
    }
    Ok(())
}

#[test]
fn an_empty_recipient_list_is_refused_before_anything_is_sent() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference sends `"rec":[]`, asking the agent to deliver to nobody.
    let recorded = request_of(&fixture, "grant_no_recipients")?;
    assert!(recorded.body.clone().unwrap_or_default().contains(r#""rec":[]"#));

    let (client, transport) = connected(&[])?;
    let messages = conversation(&fixture)?;
    let grant = messages
        .iter()
        .find(|(name, _)| *name == "grant")
        .map(|(_, message)| message)
        .ok_or("no grant was built")?;
    let outcome = block_on(client.ipex().submit("multisig", grant, &[]));
    assert!(
        matches!(outcome, Err(ClientError::NoIpexRecipients { .. })),
        "an empty recipient list was accepted: {outcome:?}"
    );
    // Only the two lifecycle requests went out.
    assert_eq!(transport.requests().len(), 2);
    Ok(())
}

#[test]
fn a_recipient_list_is_carried_as_given_and_is_not_checked_against_the_message() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let two = request_of(&fixture, "grant_two_recipients")?;
    assert!(
        two.body
            .clone()
            .unwrap_or_default()
            .contains(&fixture.provenance.second_recipient)
    );
    // Upstream a grant addressed to one identifier can be delivered to another, unchecked.
    let elsewhere = request_of(&fixture, "grant_recipient_is_not_the_addressee")?;
    let body = elsewhere.body.clone().unwrap_or_default();
    assert!(body.contains(&format!(r#""rec":["{}"]"#, fixture.provenance.second_recipient)));
    assert!(body.contains(&format!(r#""rp":"{}""#, fixture.provenance.recipient)));

    // This port reproduces both, because the pinned tree proves nothing either way about fanning
    // out and the method documents that it does not check.
    let messages = conversation(&fixture)?;
    let grant = messages
        .iter()
        .find(|(name, _)| *name == "grant")
        .map(|(_, message)| message)
        .ok_or("no grant was built")?;
    let (client, transport) = connected(&[b"{}", b"{}"])?;

    let both = vec![
        IdentifierPrefix::from_qb64(&fixture.provenance.recipient)?,
        IdentifierPrefix::from_qb64(&fixture.provenance.second_recipient)?,
    ];
    let _ = block_on(client.ipex().submit("multisig", grant, &both))?;
    assert_eq!(sent(&transport, 0)?.2.as_deref(), two.body.as_deref());

    let elsewhere_only = vec![IdentifierPrefix::from_qb64(&fixture.provenance.second_recipient)?];
    let _ = block_on(client.ipex().submit("multisig", grant, &elsewhere_only))?;
    assert_eq!(sent(&transport, 1)?.2.as_deref(), elsewhere.body.as_deref());
    Ok(())
}

#[test]
fn an_alias_can_never_leave_its_own_path_segment() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference sends `/identifiers/a/b/ipex/apply`: the alias becomes two segments.
    assert_eq!(
        request_of(&fixture, "apply_alias_needing_encoding")?.path,
        "/identifiers/a/b/ipex/apply"
    );

    let recipients = recipients(&fixture)?;
    let messages = conversation(&fixture)?;
    let applied = messages
        .iter()
        .find(|(name, _)| *name == "apply")
        .map(|(_, message)| message)
        .ok_or("no apply was built")?;
    let (client, transport) = connected(&[b"{}"])?;
    let _ = block_on(client.ipex().submit("a/b", applied, &recipients))?;
    let (path, _, _) = sent(&transport, 0)?;
    assert_eq!(path, "/identifiers/a%2Fb/ipex/apply");
    assert_eq!(path.split('/').count(), 5);

    // And the encoded form is what a real alias produces unchanged.
    let plain = ResourcePath::builder()
        .segment("identifiers")
        .segment("multisig")
        .segment(IPEX_SEGMENT)
        .segment("apply")
        .build()?;
    assert_eq!(plain.as_str(), "/identifiers/multisig/ipex/apply");
    Ok(())
}

#[test]
fn the_answer_is_decoded_rather_than_cast() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let answer = serde_json::to_vec(&call(&fixture, "grant")?.result)?;
    let recipients = recipients(&fixture)?;
    let messages = conversation(&fixture)?;
    let grant = messages
        .iter()
        .find(|(name, _)| *name == "grant")
        .map(|(_, message)| message)
        .ok_or("no grant was built")?;

    let (client, _) = connected(&[&answer])?;
    let submitted = block_on(client.ipex().submit("multisig", grant, &recipients))?;
    let operation = submitted.operation()?;
    assert!(operation.name.starts_with("exchange."));
    let metadata = operation.metadata.ok_or("the operation carried no metadata")?;
    assert!(!metadata.said.is_empty());
    // The body is owned, so it can be read as often as a caller likes.
    assert!(submitted.operation().is_ok());
    assert!(!submitted.response_body().is_empty());

    // A wrong-shaped answer is a typed failure, where the reference casts whatever arrives.
    let (other, _) = connected(&[br#"{"not":"an operation"}"#])?;
    let submitted = block_on(other.ipex().submit("multisig", grant, &recipients))?;
    assert!(
        matches!(submitted.operation(), Err(ClientError::Api { .. })),
        "a wrong-shaped answer was accepted as an operation"
    );
    Ok(())
}
