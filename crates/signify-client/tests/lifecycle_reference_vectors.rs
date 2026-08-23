//! Exact client-lifecycle vectors recorded from the pinned reference's own `SignifyClient`.
//!
//! The generator replaces `globalThis.fetch` with a recorder that answers as a KERIA agent would,
//! pins the clock, and walks the real client through boot, state, connect, two signed requests,
//! both passcode calls, and one non-success status. Every request it made is recorded with its
//! method, URL, headers, and body — and this test rebuilds each one.
//!
//! Because the clock is pinned and the agent's key is fixed, the signed requests compare **with
//! their signatures**, as Roadmap 5.5's did.

use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use signify_client::client::{ClientRequest, SignifyClient};
use signify_client::config::{ClientConfig, Passcode};
use signify_client::error::ClientError;
use signify_http::header::Headers;
use signify_http::request::ResourcePath;
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::transport::Freshness;
use signify_http::transport::{Method, Response, ScriptedTransport, StatusCode};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-lifecycle/v1.json");

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    declarations: Declarations,
    lifecycle: Vec<Step>,
    connected: Connected,
    pinned_confirmations: PinnedConfirmations,
    random_shapes: RandomShapes,
    reference_quirks: Quirks,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    passcode: String,
    passcode_note: String,
    admin_url: String,
    boot_url: String,
    agent_prefix: String,
    agent_verification_key: String,
    agent_seed_note: String,
    fixed_clock_ms: u64,
    fixed_clock_iso: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    default_boot_url: String,
    passcode_length_check: String,
    boot_body: String,
    state_path: String,
    connect_anchor_check: String,
    connect_delegation_check: String,
    approve_delegation_url: String,
    fetch_error_message: String,
    random_passcode: String,
    random_nonce: String,
    ready: String,
    notes: DeclarationNotes,
}

#[derive(Debug, Deserialize)]
struct DeclarationNotes {
    boot: String,
    connect: String,
    fetch: String,
}

#[derive(Debug, Deserialize)]
struct Step {
    name: String,
    note: String,
    error: Option<String>,
    requests: Vec<RecordedRequest>,
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
    value: String,
}

#[derive(Debug, Deserialize)]
struct Connected {
    controller_prefix: String,
    controller_sequence_number: String,
    controller_kind: String,
    controller_event_raw: String,
    agent_prefix: String,
    agent_anchor: String,
    agent_verification_key: String,
    pidx: u32,
    note: String,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    controller_prefix: String,
    controller_prefix_is_published: bool,
    inception_raw: String,
    boot_body: String,
    boot_body_is_published: bool,
    passcode_error: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct RandomShapes {
    passcode_length: usize,
    passcode_lengths_all_equal: bool,
    passcode_alphabet: String,
    passcode_distinct: usize,
    passcode_note: String,
    nonce_length: usize,
    nonce_lengths_all_equal: bool,
    nonce_code: String,
    nonce_codes_all_equal: bool,
    nonce_distinct: usize,
    nonce_note: String,
    samples: usize,
}

#[derive(Debug, Deserialize)]
struct Quirks {
    boot_hardcodes_pidx_one: PidxQuirk,
    approve_delegation_is_unauthenticated: RequestQuirk,
    passcode_save_and_delete_are_unauthenticated: RequestsQuirk,
    state_reports_404_as_a_message: ExpressionQuirk,
    connect_assigns_ridx_without_rederiving: ExpressionQuirk,
    ready_is_libsodium_initialization: ReadyQuirk,
    fetch_requires_connect_at_run_time: ExpressionQuirk,
}

#[derive(Debug, Deserialize)]
struct PidxQuirk {
    expression: String,
    recorded_pidx: i64,
    client_pidx: i64,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct RequestQuirk {
    url: String,
    request: Option<RecordedRequest>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct RequestsQuirk {
    requests: Vec<Option<RecordedRequest>>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct ExpressionQuirk {
    expression: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct ReadyQuirk {
    source: String,
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

/// A minimal executor; every future on this path is ready on its first poll, which is what
/// Roadmap 5.1's ADR `0019` guarantees for the scripted transport. The crate is runtime-neutral,
/// so its tests are too.
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

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

/// The clock every signed request reads, pinned to the instant the generator pinned.
fn pinned_clock(fixture: &Fixture) -> Arc<dyn Clock> {
    Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(fixture.provenance.fixed_clock_ms),
    ))
}

fn config(fixture: &Fixture) -> Result<ClientConfig, Box<dyn Error>> {
    Ok(
        ClientConfig::new(&fixture.provenance.admin_url, &fixture.provenance.passcode)?
            .with_boot_url(&fixture.provenance.boot_url)?,
    )
}

/// The agent-resource body the generator's mock returned.
///
/// Assembled as text rather than through a JSON value, because the controller's establishment
/// event must keep its version string first — Roadmap 3.2 refuses a message whose `v` is not the
/// opening field, and a JSON map would sort the keys.
fn agent_state_body(fixture: &Fixture) -> Vec<u8> {
    let agent = format!(
        r#"{{"vn":[1,0],"i":"{prefix}","s":"0","p":"","d":"{prefix}","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1","k":["{key}"],"nt":"1","n":["EL6zVoZ0F8OXcbXP4LOm5oJTxCXP6ZLp5o3vNfvVZ9YB"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{prefix}","br":[],"ba":[]}},"di":"{controller}"}}"#,
        prefix = fixture.provenance.agent_prefix,
        key = fixture.provenance.agent_verification_key,
        controller = fixture.connected.controller_prefix,
    );
    let document = format!(
        r#"{{"agent":{agent},"controller":{{"state":{agent},"ee":{inception}}},"ridx":0,"pidx":0}}"#,
        agent = agent,
        inception = fixture.pinned_confirmations.inception_raw,
    );
    document.into_bytes()
}

/// Finds one recorded request by the step that produced it.
fn recorded<'a>(fixture: &'a Fixture, step: &str) -> Result<&'a RecordedRequest, Box<dyn Error>> {
    fixture
        .lifecycle
        .iter()
        .find(|entry| entry.name == step)
        .and_then(|entry| entry.requests.first())
        .ok_or_else(|| format!("no recorded request for {step}").into())
}

/// Answers with a signed empty document, as the generator's agent did.
fn signed_response(fixture: &Fixture, body: Vec<u8>) -> Result<Response, Box<dyn Error>> {
    // The signature headers are the ones the generator's agent produced; this test compares
    // requests, and authenticates responses in the dedicated case below.
    let mut headers = Headers::new();
    headers.insert(
        signify_http::header::HeaderName::new("signify-resource")?,
        signify_http::header::HeaderValue::new(&fixture.provenance.agent_prefix)?,
    )?;
    Ok(Response::new(StatusCode::new(202)?, headers, body)?)
}

#[test]
fn every_recorded_step_and_scan_hit_carries_its_context() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // Every lifecycle step says what it exercises, so a reader of the fixture alone can follow it.
    for step in &fixture.lifecycle {
        assert!(!step.note.is_empty(), "step {} records no note", step.name);
    }
    // The reference's own passcode refusal, recorded verbatim beside this port's typed one.
    assert_eq!(
        fixture.pinned_confirmations.passcode_error,
        "bran must be 21 characters"
    );
    assert!(!fixture.pinned_confirmations.note.is_empty());
    assert!(matches!(
        Passcode::new("short"),
        Err(ClientError::InvalidPasscodeLength { .. })
    ));
    // The boot-body expression the `pidx` divergence is read from.
    assert!(
        fixture
            .reference_quirks
            .boot_hardcodes_pidx_one
            .expression
            .contains("pidx: 1")
    );
    // Every scan hit counts at least one occurrence.
    for hit in &fixture.reference_quirks.ready_is_libsodium_initialization.scan.files {
        assert!(hit.count >= 1, "{} recorded no occurrence", hit.file);
    }
    Ok(())
}

#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert!(!fixture.generated_on.is_empty());
    assert!(fixture.sources.iter().any(|source| source.ends_with("clienting.ts")));
    assert!(fixture.sources.iter().any(|source| source.ends_with("ready.ts")));
    assert!(fixture.provenance.passcode_note.contains("PUBLIC TEST MATERIAL"));
    assert!(fixture.provenance.agent_seed_note.contains("PUBLIC TEST MATERIAL"));
    assert!(!fixture.provenance.note.is_empty());
    assert!(!fixture.provenance.fixed_clock_iso.is_empty());
    assert_eq!(fixture.lifecycle.len(), 8);
    assert!(!fixture.connected.note.is_empty());
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // The default boot URL and the passcode length are both constants this port hard-codes.
    assert!(
        declarations
            .default_boot_url
            .contains(signify_client::config::DEFAULT_BOOT_URL)
    );
    assert!(declarations.passcode_length_check.contains("bran.length < 21"));

    // The boot body's five fields, in the order this port writes them.
    for (earlier, later) in [
        ("icp:", "sig:"),
        ("sig:", "stem:"),
        ("stem:", "pidx:"),
        ("pidx:", "tier:"),
    ] {
        let (Some(first), Some(second)) = (declarations.boot_body.find(earlier), declarations.boot_body.find(later))
        else {
            return Err(format!("{earlier:?} and {later:?} are no longer both in the boot body").into());
        };
        assert!(first < second, "{earlier:?} must precede {later:?}");
    }
    assert!(declarations.boot_body.contains("pidx: 1"));

    // The lifecycle's own checks.
    assert!(declarations.state_path.contains("/agent/"));
    assert!(declarations.connect_anchor_check.contains("agent.anchor"));
    assert!(declarations.connect_delegation_check.contains("serder.sad.s == 0"));
    assert!(declarations.approve_delegation_url.contains("?type=ixn"));
    assert!(declarations.fetch_error_message.contains("res.status"));

    // Both random helpers, and `ready`.
    assert!(declarations.random_passcode.contains("randombytes_buf(16)"));
    assert!(declarations.random_passcode.contains("substring(2, 23)"));
    assert!(declarations.random_nonce.contains("crypto_sign_SEEDBYTES"));
    assert!(declarations.ready.contains("_sodium.ready"));

    for note in [
        &declarations.notes.boot,
        &declarations.notes.connect,
        &declarations.notes.fetch,
    ] {
        assert!(!note.is_empty());
    }
    Ok(())
}

#[test]
fn the_boot_request_matches_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let transport = Arc::new(ScriptedTransport::new().respond(signed_response(&fixture, b"{}".to_vec())?));
    let client = SignifyClient::new(config(&fixture)?, transport.clone(), pinned_clock(&fixture))?;

    // The controller derives to the prefix the pinned test publishes.
    assert!(fixture.pinned_confirmations.controller_prefix_is_published);
    assert_eq!(
        client.controller().prefix().qb64()?,
        fixture.pinned_confirmations.controller_prefix
    );
    assert_eq!(
        core::str::from_utf8(client.controller().current_event().raw())?,
        fixture.pinned_confirmations.inception_raw
    );

    // And the body it posts is the exact literal the pinned test asserts.
    assert!(fixture.pinned_confirmations.boot_body_is_published);
    assert_eq!(
        core::str::from_utf8(&client.boot_body()?)?,
        fixture.pinned_confirmations.boot_body
    );

    block_on(client.boot())?;
    let sent = transport.recorded();
    let expected = recorded(&fixture, "boot")?;
    let actual = sent.first().ok_or("boot sent nothing")?;
    assert_eq!(actual.url().as_str(), expected.url);
    assert_eq!(actual.method().as_str(), expected.method);
    assert_eq!(
        actual.body().map(|body| core::str::from_utf8(body)).transpose()?,
        expected.body.as_deref()
    );
    Ok(())
}

#[test]
fn the_state_request_matches_and_its_body_is_typed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let transport = Arc::new(ScriptedTransport::new().respond(signed_response(&fixture, agent_state_body(&fixture))?));
    let client = SignifyClient::new(config(&fixture)?, transport.clone(), pinned_clock(&fixture))?;

    let state = block_on(client.state())?;
    let sent = transport.recorded();
    let expected = recorded(&fixture, "state")?;
    let actual = sent.first().ok_or("state sent nothing")?;
    assert_eq!(actual.url().as_str(), expected.url);
    assert_eq!(actual.method().as_str(), expected.method);
    assert!(actual.body().is_none(), "a state read carries no body");

    // Both halves are typed, where the reference's are `any`.
    assert_eq!(state.agent().identifier, fixture.provenance.agent_prefix);
    assert_eq!(
        state.controller_event().said(),
        Some(fixture.pinned_confirmations.controller_prefix.as_str())
    );
    assert_eq!(state.rotation_index(), 0);
    assert_eq!(state.prefix_index(), fixture.connected.pidx);
    Ok(())
}

#[test]
fn connecting_validates_the_agent_and_approves_the_delegation() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let transport = Arc::new(
        ScriptedTransport::new()
            .respond(signed_response(&fixture, agent_state_body(&fixture))?)
            .respond(signed_response(&fixture, b"{}".to_vec())?),
    );
    let client = SignifyClient::new(config(&fixture)?, transport.clone(), pinned_clock(&fixture))?;
    let connected = block_on(client.connect())?;

    // The controller has advanced to the interaction event approving the delegation.
    assert_eq!(
        connected.controller().current_sequence_number().to_string(),
        fixture.connected.controller_sequence_number
    );
    assert_eq!(
        connected.controller().current_event().sad().get_text("t"),
        Some(fixture.connected.controller_kind.as_str())
    );
    assert_eq!(
        core::str::from_utf8(connected.controller().current_event().raw())?,
        fixture.connected.controller_event_raw
    );
    assert_eq!(connected.agent().prefix().qb64()?, fixture.connected.agent_prefix);
    assert_eq!(connected.agent().anchor().qb64()?, fixture.connected.agent_anchor);
    assert_eq!(
        connected.agent().verifier().qb64()?,
        fixture.connected.agent_verification_key
    );

    // Two requests: the state read, then the unsigned approval.
    let sent = transport.recorded();
    assert_eq!(sent.len(), 2);
    let approval = sent.get(1).ok_or("no approval request")?;
    let expected = fixture
        .lifecycle
        .iter()
        .find(|step| step.name == "connect")
        .and_then(|step| step.requests.get(1))
        .ok_or("no recorded approval")?;
    assert_eq!(approval.url().as_str(), expected.url);
    assert_eq!(approval.method().as_str(), expected.method);
    assert_eq!(
        approval.body().map(|body| core::str::from_utf8(body)).transpose()?,
        expected.body.as_deref()
    );
    Ok(())
}

#[test]
fn a_signed_request_matches_byte_for_byte_including_its_signature() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let transport = Arc::new(
        ScriptedTransport::new()
            .respond(signed_response(&fixture, agent_state_body(&fixture))?)
            .respond(signed_response(&fixture, b"{}".to_vec())?)
            .respond(signed_response(&fixture, b"[]".to_vec())?),
    );
    let client = SignifyClient::new(config(&fixture)?, transport.clone(), pinned_clock(&fixture))?;
    let connected = block_on(client.connect())?.with_freshness(Freshness::Ignore);

    // The response the scripted transport returns is not signed, so authenticating it fails —
    // which is itself the check that authentication runs at all.
    let path = ResourcePath::builder().segment("contacts").build()?;
    let outcome = block_on(connected.fetch(ClientRequest::new(Method::Get, path)));
    assert!(
        matches!(outcome, Err(ClientError::ResponseAuthentication { .. })),
        "an unsigned response was accepted"
    );

    // The request that went out is still the one the reference sent, signature included.
    let sent = transport.recorded();
    let actual = sent.get(2).ok_or("no signed request")?;
    let expected = recorded(&fixture, "fetch_get")?;
    assert_eq!(actual.url().as_str(), expected.url);
    assert_eq!(actual.method().as_str(), expected.method);
    for header in &expected.headers {
        let name = header.name.to_ascii_lowercase();
        if name == "content-type" {
            continue;
        }
        assert_eq!(
            actual.headers().get(&name),
            Some(header.value.as_str()),
            "header {name} differs"
        );
    }
    Ok(())
}

#[test]
fn both_passcode_calls_match_and_are_unsigned() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let transport = Arc::new(
        ScriptedTransport::new()
            .respond(signed_response(&fixture, agent_state_body(&fixture))?)
            .respond(signed_response(&fixture, b"{}".to_vec())?)
            .respond(signed_response(&fixture, b"{}".to_vec())?)
            .respond(signed_response(&fixture, b"{}".to_vec())?),
    );
    let client = SignifyClient::new(config(&fixture)?, transport.clone(), pinned_clock(&fixture))?;
    let connected = block_on(client.connect())?;

    block_on(connected.save_old_passcode(&Passcode::new("1234567890123456789ab")?))?;
    block_on(connected.delete_passcode())?;

    let sent = transport.recorded();
    for (index, step) in [(2_usize, "save_old_passcode"), (3, "delete_passcode")] {
        let actual = sent.get(index).ok_or("a passcode request is missing")?;
        let expected = recorded(&fixture, step)?;
        assert_eq!(actual.url().as_str(), expected.url, "{step}");
        assert_eq!(actual.method().as_str(), expected.method, "{step}");
        // Unsigned: no signature header goes out, exactly as upstream.
        assert!(actual.headers().get("signature").is_none(), "{step} was signed");
        assert!(
            actual.headers().get("signature-input").is_none(),
            "{step} carried a signature input"
        );
    }
    Ok(())
}

#[test]
fn a_non_success_status_is_typed_rather_than_a_message() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let mut failing = Headers::new();
    failing.insert(
        signify_http::header::HeaderName::new("content-type")?,
        signify_http::header::HeaderValue::new("text/plain")?,
    )?;
    let transport = Arc::new(
        ScriptedTransport::new()
            .respond(signed_response(&fixture, agent_state_body(&fixture))?)
            .respond(signed_response(&fixture, b"{}".to_vec())?)
            .respond(Response::new(StatusCode::new(400)?, failing, b"Error info".to_vec())?),
    );
    let client = SignifyClient::new(config(&fixture)?, transport, pinned_clock(&fixture))?;
    let connected = block_on(client.connect())?;

    let path = ResourcePath::builder().segment("somepath").build()?;
    let outcome = block_on(connected.fetch(ClientRequest::new(Method::Get, path)));
    let Err(ClientError::Status { status, detail }) = outcome else {
        return Err("a 400 was not reported as a status failure".into());
    };
    assert_eq!(status, 400);
    assert_eq!(detail, "Error info");

    // The reference builds one string out of method, path, status, status text, and body; the
    // recorded message shows all five, and the parts stay separate here.
    let recorded_error = fixture
        .lifecycle
        .iter()
        .find(|step| step.name == "fetch_error")
        .and_then(|step| step.error.as_deref())
        .ok_or("no recorded error")?;
    assert!(recorded_error.contains("400"));
    assert!(recorded_error.contains("Error info"));
    assert!(recorded_error.contains("/somepath"));
    Ok(())
}

#[test]
fn the_random_helpers_match_the_recorded_shapes() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let shapes = &fixture.random_shapes;
    assert!(shapes.passcode_lengths_all_equal);
    assert!(shapes.nonce_lengths_all_equal);
    assert!(shapes.nonce_codes_all_equal);
    assert_eq!(shapes.passcode_distinct, shapes.samples);
    assert_eq!(shapes.nonce_distinct, shapes.samples);
    assert!(!shapes.passcode_note.is_empty());
    assert!(!shapes.nonce_note.is_empty());

    // The recorded alphabet is URL-safe Base64, which is what this port validates against.
    assert!(
        shapes
            .passcode_alphabet
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
    );

    for _ in 0..8 {
        let passcode = signify_client::random::random_passcode()?;
        assert_eq!(passcode.expose().chars().count(), shapes.passcode_length);
        let nonce = signify_client::random::random_nonce()?;
        assert_eq!(nonce.len(), shapes.nonce_length);
        assert!(nonce.starts_with(&shapes.nonce_code));
    }
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = &fixture.reference_quirks;
    let pairs: [(&str, &str); 7] = [
        (
            &quirks.boot_hardcodes_pidx_one.note,
            &quirks.boot_hardcodes_pidx_one.rust_decision,
        ),
        (
            &quirks.approve_delegation_is_unauthenticated.note,
            &quirks.approve_delegation_is_unauthenticated.rust_decision,
        ),
        (
            &quirks.passcode_save_and_delete_are_unauthenticated.note,
            &quirks.passcode_save_and_delete_are_unauthenticated.rust_decision,
        ),
        (
            &quirks.state_reports_404_as_a_message.note,
            &quirks.state_reports_404_as_a_message.rust_decision,
        ),
        (
            &quirks.connect_assigns_ridx_without_rederiving.note,
            &quirks.connect_assigns_ridx_without_rederiving.rust_decision,
        ),
        (
            &quirks.ready_is_libsodium_initialization.note,
            &quirks.ready_is_libsodium_initialization.rust_decision,
        ),
        (
            &quirks.fetch_requires_connect_at_run_time.note,
            &quirks.fetch_requires_connect_at_run_time.rust_decision,
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

    // 1. The boot body's `pidx` is 1 while the client's own field is 0; here it is a constant.
    let pidx = &quirks.boot_hardcodes_pidx_one;
    assert_eq!(pidx.recorded_pidx, 1);
    assert_eq!(pidx.client_pidx, 0);
    assert_eq!(signify_client::client::BOOT_PREFIX_INDEX, pidx.recorded_pidx);

    // 2. The delegation approval carries no signature; reproduced.
    let approval = &quirks.approve_delegation_is_unauthenticated;
    assert!(approval.url.contains("?type=ixn"));
    let request = approval.request.as_ref().ok_or("no approval recorded")?;
    assert_eq!(request.method, "PUT");
    assert!(
        !request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("signature")),
        "the approval was signed"
    );

    // 3. Both passcode calls are likewise unsigned.
    for recorded in &quirks.passcode_save_and_delete_are_unauthenticated.requests {
        let request = recorded.as_ref().ok_or("a passcode request was not recorded")?;
        assert!(request.url.contains("/salt/"));
        assert!(
            !request
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("signature")),
            "a passcode request was signed"
        );
    }

    // 4. A 404 is a message upstream and a typed variant here.
    assert!(quirks.state_reports_404_as_a_message.expression.contains("404"));

    // 5. `ridx` is assigned after construction upstream; here the controller is rebuilt with it.
    assert!(
        quirks
            .connect_assigns_ridx_without_rederiving
            .expression
            .contains("ridx")
    );

    // 6. `ready` is libsodium initialization, recorded `N/A` against the file's own text.
    let ready = &quirks.ready_is_libsodium_initialization;
    assert!(ready.source.contains("_sodium.ready"));
    assert!(ready.source.lines().count() <= 6, "ready.ts is four lines");
    assert!(ready.scan.scanned_files > 100);
    // The module is imported from exactly one place — the export surface — and nothing in the
    // protocol tree touches it.
    assert_eq!(ready.scan.needle, "ready.ts");
    assert_eq!(ready.scan.total, 1);
    assert_eq!(
        ready.scan.files.first().map(|hit| hit.file.as_str()),
        Some("src/exports.ts")
    );

    // 7. The run-time connect check is a compile-time one here: `SignifyClient` has no `fetch`.
    assert!(
        quirks
            .fetch_requires_connect_at_run_time
            .expression
            .contains("connect first")
    );
    Ok(())
}
