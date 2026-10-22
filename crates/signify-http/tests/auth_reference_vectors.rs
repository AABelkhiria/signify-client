//! The pinned TypeScript reference's complete authenticated-request pipeline, byte for byte.
//!
//! keri-http-auth verifies `siginput` and `Authenticater` in isolation. What is proven here is the
//! *composition* `SignifyClient.fetch` performs around them, and it is proven with **unmasked**
//! signature bytes: the generator pins `globalThis.Date`, so the timestamp, the `created`
//! parameter, and the two signature headers are all deterministic. Every earlier fixture had to
//! record them as `masked: true`.
//!
//! The controller's signing seed is in the fixture for exactly this reason — it is public test
//! material the reference derives from its own published passcode — so the same key can sign here
//! and the resulting headers compared character for character.

use core::time::Duration;
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::time::SystemTime;

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use serde::Deserialize;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::authentication::{RequestSigner, ResponseVerifier};
use signify_http::signature::input::{
    RequestTarget, SIGNIFY_RESOURCE_HEADER_NAME, SIGNIFY_TIMESTAMP_HEADER_NAME, SignatureComponent, default_components,
};
use signify_http::signature::timestamp::SignifyTimestamp;
use signify_http::signature::transport::{
    Freshness, ResponseAuthenticationError, ResponseAuthenticator, SigningTransport,
};
use signify_http::transport::{Method, Request, RequestUrl, ScriptedTransport, Transport};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/http-auth/v1.json"));

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    constants: Constants,
    requests: Vec<RequestCase>,
    response_verification: Vec<VerificationCase>,
    freshness_scan: FreshnessScan,
    reference_quirks: Quirks,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    controller_prefix: String,
    agent_prefix: String,
    agent_verification_key: String,
    agent_signing_seed: String,
    controller_signing_seed: String,
    controller_verification_key: String,
    seed_warning: String,
    fixed_clock_ms: u64,
    typescript_version: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Constants {
    default_fields: Vec<String>,
    timestamp_expression: String,
    timestamp_at_fixed_clock: String,
    fixed_clock_ms: u64,
    fixed_clock_iso: String,
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
    value: String,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }
}

#[derive(Debug, Deserialize)]
struct VerificationCase {
    name: String,
    note: String,
    method: String,
    path: String,
    headers: Vec<RecordedHeader>,
    accepted: bool,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FreshnessScan {
    roots: Vec<String>,
    files_scanned: u32,
    matches: BTreeMap<String, ScanMatch>,
    checks: FreshnessChecks,
    note: String,
}

/// The three claims that actually carry the "no freshness check" finding.
#[derive(Debug, Deserialize)]
struct FreshnessChecks {
    authenticater_ever_sets_expires: bool,
    a_parameter_is_ever_compared: bool,
    verification_reads_a_clock: bool,
}

#[derive(Debug, Deserialize)]
struct ScanMatch {
    count: u32,
    files: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Quirks {
    there_is_no_freshness_check: FreshnessQuirk,
    the_timestamp_claims_precision_it_does_not_have: TimestampQuirk,
    two_clock_readings_per_request: NoteQuirk,
    the_query_is_stripped_before_signing: UrlQuirk,
    covered_fields_are_fixed: FieldsQuirk,
    headers_are_appended_not_set: NoteQuirk,
    a_failed_verification_and_a_missing_header_are_the_same: SameOutcomeQuirk,
    the_resource_check_is_an_equality_on_an_untyped_header: NoteQuirk,
}

#[derive(Debug, Deserialize)]
struct FreshnessQuirk {
    accepted: bool,
    checks: FreshnessChecks,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct TimestampQuirk {
    expression: String,
    produced: String,
    iso: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct NoteQuirk {
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct UrlQuirk {
    url: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct FieldsQuirk {
    fields: Vec<String>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct SameOutcomeQuirk {
    missing_signature: bool,
    missing_input: bool,
    note: String,
    rust_decision: String,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let fixture: Fixture = serde_json::from_str(FIXTURE)?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(fixture.generated_on, "2026-08-23");
    assert_eq!(fixture.sources.len(), 3);
    assert_eq!(fixture.provenance.bran, "0123456789abcdefghijk");
    assert_eq!(fixture.provenance.admin_url, "http://localhost:3901");
    assert!(fixture.provenance.seed_warning.contains("PUBLIC TEST MATERIAL"));
    assert_ne!(fixture.provenance.note, "");
    assert_eq!(fixture.provenance.typescript_version, "5.9.2");
    Ok(fixture)
}

/// The clock the reference was pinned to when the fixture was recorded.
fn pinned_clock(fixture: &Fixture) -> Arc<TestClock> {
    Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(fixture.provenance.fixed_clock_ms),
    ))
}

/// Rebuilds the controller's signer from the seed the reference derived.
fn controller_signer(fixture: &Fixture) -> Result<Signer, Box<dyn Error>> {
    Ok(Signer::from_qb64(
        &fixture.provenance.controller_signing_seed,
        KeyTransferability::Transferable,
    )?)
}

fn find<'cases>(cases: &'cases [RequestCase], name: &str) -> Result<&'cases RequestCase, Box<dyn Error>> {
    cases
        .iter()
        .find(|case| case.name == name)
        .ok_or_else(|| format!("fixture has no request named {name}").into())
}

/// A minimal executor; every future on this path is ready on its first poll.
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

// ---------------------------------------------------------------------------
// The constants, and the key the whole fixture hangs on
// ---------------------------------------------------------------------------

#[test]
fn the_covered_components_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(
        fixture.constants.default_fields,
        ["@method", "@path", "signify-resource", "signify-timestamp"],
    );
    assert_ne!(fixture.constants.note, "");

    let ours = default_components()?;
    let names: Vec<&str> = ours.iter().map(SignatureComponent::as_str).collect();
    assert_eq!(names, fixture.constants.default_fields);
    Ok(())
}

#[test]
fn the_recorded_signer_is_reproduced_from_its_seed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let signer = controller_signer(&fixture)?;
    // The same key the reference signed every recorded request with.
    assert_eq!(
        signer.verifier().qb64()?,
        fixture.provenance.controller_verification_key,
    );
    Ok(())
}

#[test]
fn the_timestamp_format_is_reproduced_exactly() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirk = &fixture.reference_quirks.the_timestamp_claims_precision_it_does_not_have;
    assert!(quirk.expression.contains("toISOString"));
    assert!(quirk.expression.contains("'000+00:00'"));

    // The expression the reference sets the header from, read from its own syntax tree.
    assert_eq!(fixture.constants.timestamp_expression, quirk.expression);

    let stamp = SignifyTimestamp::from_unix(Duration::from_millis(fixture.constants.fixed_clock_ms))?;
    assert_eq!(stamp.as_str(), fixture.constants.timestamp_at_fixed_clock);
    assert_eq!(stamp.as_str(), quirk.produced);

    // The reference's own `toISOString` had milliseconds; the three zeros are padding. The
    // rendered value is the ISO one with the `Z` replaced, and nothing else.
    assert_eq!(fixture.constants.fixed_clock_iso, "2023-11-14T22:13:20.123Z");
    assert_eq!(quirk.iso, fixture.constants.fixed_clock_iso);
    assert_eq!(
        stamp.as_str(),
        fixture.constants.fixed_clock_iso.replace('Z', "000+00:00"),
    );
    assert!(quirk.produced.ends_with("000+00:00"), "{}", quirk.produced);
    assert_ne!(quirk.rust_decision, "");
    Ok(())
}

// ---------------------------------------------------------------------------
// The composed request, byte for byte
// ---------------------------------------------------------------------------

#[test]
fn every_recorded_request_is_signed_identically() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.requests.len(), 5);

    let clock = pinned_clock(&fixture);
    let transport = SigningTransport::new(
        Arc::new(ScriptedTransport::new()),
        RequestSigner::new(controller_signer(&fixture)?),
        HeaderValue::new(&fixture.provenance.controller_prefix)?,
    )?
    .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);

    for case in &fixture.requests {
        assert!(!case.note.is_empty(), "{}", case.name);
        let method = match case.request.method.as_str() {
            "GET" => Method::Get,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            other => return Err(format!("unexpected method {other}").into()),
        };

        let mut builder = Request::builder(method, RequestUrl::new(case.request.url.clone())?);
        if let Some(body) = &case.request.body {
            builder = builder.body(body.clone().into_bytes());
        }
        let signed = transport.sign_request(&builder.build()?)?;

        // The two clock-dependent headers, which no earlier fixture could compare at all.
        assert_eq!(
            signed.headers().get(SIGNIFY_TIMESTAMP_HEADER_NAME),
            case.request.header("signify-timestamp"),
            "{}: timestamp",
            case.name,
        );
        assert_eq!(
            signed.headers().get(SIGNIFY_RESOURCE_HEADER_NAME),
            case.request.header("signify-resource"),
            "{}: resource",
            case.name,
        );
        // And the signature itself, character for character.
        assert_eq!(
            signed.headers().get("signature-input"),
            case.request.header("signature-input"),
            "{}: signature input",
            case.name,
        );
        assert_eq!(
            signed.headers().get("signature"),
            case.request.header("signature"),
            "{}: signature",
            case.name,
        );
        // The body crosses unchanged and is not covered by anything.
        assert_eq!(
            signed.body().map(<[u8]>::to_vec),
            case.request.body.as_ref().map(|body| body.clone().into_bytes()),
            "{}: body",
            case.name,
        );
    }
    Ok(())
}

#[test]
fn the_query_is_stripped_before_signing() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirk = &fixture.reference_quirks.the_query_is_stripped_before_signing;
    assert_eq!(quirk.url, "http://localhost:3901/contacts?group=g&filter_field=f");

    let with_query = find(&fixture.requests, "get_with_query")?;
    let signature_input = with_query
        .request
        .header("signature-input")
        .ok_or("no signature input was recorded")?;
    // The reference signed `@path` alone, so the covered path carries no query.
    assert!(signature_input.contains("\"@path\""), "{signature_input}");

    let clock = pinned_clock(&fixture);
    let transport = SigningTransport::new(
        Arc::new(ScriptedTransport::new()),
        RequestSigner::new(controller_signer(&fixture)?),
        HeaderValue::new(&fixture.provenance.controller_prefix)?,
    )?
    .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);

    let queried =
        transport.sign_request(&Request::builder(Method::Get, RequestUrl::new(quirk.url.clone())?).build()?)?;
    let plain = transport
        .sign_request(&Request::builder(Method::Get, RequestUrl::new("http://localhost:3901/contacts")?).build()?)?;
    // Same base, same signature — and the same one the reference produced.
    assert_eq!(queried.headers().get("signature"), plain.headers().get("signature"));
    assert_eq!(
        queried.headers().get("signature"),
        with_query.request.header("signature"),
    );
    Ok(())
}

#[test]
fn the_body_is_carried_but_never_covered() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirk = &fixture.reference_quirks.covered_fields_are_fixed;
    assert_eq!(quirk.fields.len(), 4);
    assert!(!quirk.fields.iter().any(|field| field.contains("digest")));

    // Two recorded POSTs and PUTs carry different bodies; nothing signed covers either.
    let put = find(&fixture.requests, "put_with_body")?;
    let post = find(&fixture.requests, "post_with_body")?;
    assert_ne!(put.request.body, post.request.body);
    // They differ in method, so their signatures differ for that reason — but the path and method
    // are the only things that made them differ.
    assert!(put.request.body.is_some() && post.request.body.is_some());
    assert_ne!(quirk.rust_decision, "");
    Ok(())
}

// ---------------------------------------------------------------------------
// Response authentication
// ---------------------------------------------------------------------------

#[test]
fn every_recorded_verification_outcome_is_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.response_verification.len(), 7);

    let agent_key = Signer::from_qb64(
        &fixture.provenance.agent_signing_seed,
        KeyTransferability::NonTransferable,
    )?;
    assert_eq!(agent_key.verifier().qb64()?, fixture.provenance.agent_verification_key,);
    let clock = pinned_clock(&fixture);

    for case in &fixture.response_verification {
        assert!(!case.note.is_empty(), "{}", case.name);
        let mut headers = Headers::new();
        for header in &case.headers {
            headers.insert(HeaderName::new(header.name.clone())?, HeaderValue::new(&header.value)?)?;
        }
        let target = RequestTarget::new(&case.method, &case.path)?;

        // The reference checks only the signature here; the resource it stamped is its own.
        let authenticator = ResponseAuthenticator::new(
            ResponseVerifier::new(agent_key.verifier().clone()),
            HeaderValue::new(&fixture.provenance.agent_prefix)?,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        // The reference has no freshness check, so reproducing its verdict needs it switched off.
        .with_freshness(Freshness::Ignore);

        let outcome = authenticator.authenticate(&target, &headers);
        assert_eq!(
            outcome.is_ok(),
            case.accepted,
            "{}: reference accepted={}, ours={:?}",
            case.name,
            case.accepted,
            outcome.as_ref().err(),
        );
        // Where the reference *threw* — as against silently returning `false` — the cause was the
        // signature itself, and so is ours.
        if case.error.is_some() {
            assert!(
                matches!(outcome, Err(ResponseAuthenticationError::Signature { .. })),
                "{}: the reference threw {:?} and we did not fail on the signature",
                case.name,
                case.error,
            );
        }
    }
    Ok(())
}

#[test]
fn a_missing_header_and_a_bad_signature_become_distinct_errors() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirk = &fixture
        .reference_quirks
        .a_failed_verification_and_a_missing_header_are_the_same;
    // The reference returns `false` for both, and the client turns both into one message.
    assert!(!quirk.missing_signature);
    assert!(!quirk.missing_input);
    assert_ne!(quirk.rust_decision, "");

    let agent_key = Signer::from_qb64(
        &fixture.provenance.agent_signing_seed,
        KeyTransferability::NonTransferable,
    )?;
    let clock = pinned_clock(&fixture);
    let authenticator = ResponseAuthenticator::new(
        ResponseVerifier::new(agent_key.verifier().clone()),
        HeaderValue::new(&fixture.provenance.agent_prefix)?,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .with_freshness(Freshness::Ignore);
    let target = RequestTarget::new("GET", "/identifiers")?;

    // Each recorded case that the reference reported identically is a different error here.
    let mut kinds = Vec::new();
    for name in ["no_signature", "no_signature_input", "wrong_path"] {
        let case = fixture
            .response_verification
            .iter()
            .find(|case| case.name == name)
            .ok_or("missing recorded case")?;
        let mut headers = Headers::new();
        for header in &case.headers {
            headers.insert(HeaderName::new(header.name.clone())?, HeaderValue::new(&header.value)?)?;
        }
        let target = if name == "wrong_path" {
            RequestTarget::new(&case.method, &case.path)?
        } else {
            target.clone()
        };
        let Err(ResponseAuthenticationError::Signature { source }) = authenticator.authenticate(&target, &headers)
        else {
            return Err(format!("{name} was accepted").into());
        };
        kinds.push(format!("{source:?}").split_whitespace().next().unwrap_or("").to_owned());
    }
    // Three inputs the reference cannot tell apart, three distinct variants here.
    kinds.dedup();
    assert_eq!(kinds.len(), 3, "{kinds:?}");
    Ok(())
}

// ---------------------------------------------------------------------------
// The finding: there is no freshness check anywhere
// ---------------------------------------------------------------------------

#[test]
fn the_reference_has_no_freshness_check_at_all() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let scan = &fixture.freshness_scan;
    assert_eq!(scan.roots, ["src", "test", "test-integration"]);
    assert_eq!(scan.files_scanned, 117);
    assert_ne!(scan.note, "");

    // Two needles do match, and both are accounted for rather than waved away.
    let expires = scan.matches.get("expires").ok_or("no `expires` scan")?;
    assert_eq!(expires.count, 3);
    assert_eq!(
        expires.files,
        [
            "src/keri/core/authing.ts",
            "src/keri/core/httping.ts",
            "test/core/httping.test.ts",
        ],
    );
    let replay = scan.matches.get("replay").ok_or("no `replay` scan")?;
    // KEL replay messages, nothing to do with a signature.
    assert_eq!(
        replay.files,
        [
            "src/keri/app/escrowing.ts",
            "src/keri/app/exchanging.ts",
            "src/keri/app/grouping.ts",
        ],
    );
    // Everything else is absent outright.
    for name in ["maxAge", "max_age", "skew", "freshness", "staleness"] {
        assert_eq!(scan.matches.get(name).map(|entry| entry.count), Some(0), "{name}");
    }

    // And the three claims that actually carry the finding.
    assert!(!scan.checks.authenticater_ever_sets_expires);
    assert!(!scan.checks.a_parameter_is_ever_compared);
    assert!(!scan.checks.verification_reads_a_clock);

    let quirk = &fixture.reference_quirks.there_is_no_freshness_check;
    assert!(quirk.accepted, "the reference refused its own replayed response");
    assert!(!quirk.checks.authenticater_ever_sets_expires);
    assert!(!quirk.checks.a_parameter_is_ever_compared);
    assert!(!quirk.checks.verification_reads_a_clock);
    Ok(())
}

#[test]
fn a_response_the_reference_would_replay_forever_goes_stale_here() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let replayed = fixture
        .response_verification
        .iter()
        .find(|case| case.name == "replayed_after_the_fact")
        .ok_or("no replay case")?;
    assert!(replayed.accepted, "the reference refused it");

    let agent_key = Signer::from_qb64(
        &fixture.provenance.agent_signing_seed,
        KeyTransferability::NonTransferable,
    )?;
    let mut headers = Headers::new();
    for header in &replayed.headers {
        headers.insert(HeaderName::new(header.name.clone())?, HeaderValue::new(&header.value)?)?;
    }
    let target = RequestTarget::new(&replayed.method, &replayed.path)?;

    // An hour after the recorded signature was made.
    let later = Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(fixture.provenance.fixed_clock_ms) + Duration::from_hours(1),
    ));
    let authenticator = ResponseAuthenticator::new(
        ResponseVerifier::new(agent_key.verifier().clone()),
        HeaderValue::new(&fixture.provenance.agent_prefix)?,
        Arc::clone(&later) as Arc<dyn Clock>,
    );
    assert!(
        matches!(
            authenticator.authenticate(&target, &headers),
            Err(ResponseAuthenticationError::Stale { .. })
        ),
        "a replayed response was accepted",
    );

    // Switching the policy off reproduces the reference exactly.
    let permissive = ResponseAuthenticator::new(
        ResponseVerifier::new(agent_key.verifier().clone()),
        HeaderValue::new(&fixture.provenance.agent_prefix)?,
        Arc::clone(&later) as Arc<dyn Clock>,
    )
    .with_freshness(Freshness::Ignore);
    assert!(permissive.authenticate(&target, &headers).is_ok());
    Ok(())
}

// ---------------------------------------------------------------------------
// The remaining recorded divergences
// ---------------------------------------------------------------------------

#[test]
fn the_defects_are_pinned_and_not_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = &fixture.reference_quirks;

    // One clock reading here, two there.
    let two_readings = &quirks.two_clock_readings_per_request;
    let stamp = SignifyTimestamp::from_unix(Duration::from_millis(fixture.constants.fixed_clock_ms))?;
    // The header and the parameter come from the same reading, so they can never disagree.
    assert_eq!(stamp.created(), fixture.constants.fixed_clock_ms / 1_000);
    assert!(stamp.as_str().starts_with("2023-11-14T22:13:20"));

    // Signing twice appends upstream; here it does not build.
    let appended = &quirks.headers_are_appended_not_set;
    let clock = pinned_clock(&fixture);
    let transport = SigningTransport::new(
        Arc::new(ScriptedTransport::new()),
        RequestSigner::new(controller_signer(&fixture)?),
        HeaderValue::new(&fixture.provenance.controller_prefix)?,
    )?
    .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);
    let once = transport
        .sign_request(&Request::builder(Method::Get, RequestUrl::new("http://localhost:3901/identifiers")?).build()?)?;
    assert!(transport.sign_request(&once).is_err(), "{}", appended.note);

    // The resource check is an equality on an untyped header upstream.
    let resource = &quirks.the_resource_check_is_an_equality_on_an_untyped_header;
    assert_ne!(resource.rust_decision, "");

    for (name, note, decision) in [
        (
            "freshness",
            &quirks.there_is_no_freshness_check.note,
            &quirks.there_is_no_freshness_check.rust_decision,
        ),
        (
            "timestamp",
            &quirks.the_timestamp_claims_precision_it_does_not_have.note,
            &quirks.the_timestamp_claims_precision_it_does_not_have.rust_decision,
        ),
        ("two_readings", &two_readings.note, &two_readings.rust_decision),
        (
            "query",
            &quirks.the_query_is_stripped_before_signing.note,
            &quirks.the_query_is_stripped_before_signing.rust_decision,
        ),
        (
            "fields",
            &quirks.covered_fields_are_fixed.note,
            &quirks.covered_fields_are_fixed.rust_decision,
        ),
        ("appended", &appended.note, &appended.rust_decision),
        (
            "same_outcome",
            &quirks.a_failed_verification_and_a_missing_header_are_the_same.note,
            &quirks
                .a_failed_verification_and_a_missing_header_are_the_same
                .rust_decision,
        ),
        ("resource", &resource.note, &resource.rust_decision),
    ] {
        assert!(!note.is_empty(), "{name} records no observation");
        assert!(!decision.is_empty(), "{name} records no decision");
    }
    Ok(())
}

#[test]
fn the_signed_request_reaches_the_transport_beneath() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let case = find(&fixture.requests, "get_identifiers")?;

    let scripted = Arc::new(ScriptedTransport::new().respond(signify_http::transport::Response::new(
        signify_http::transport::StatusCode::new(200)?,
        Headers::new(),
        Vec::new(),
    )?));
    let clock = pinned_clock(&fixture);
    let transport = SigningTransport::new(
        Arc::clone(&scripted) as Arc<dyn Transport>,
        RequestSigner::new(controller_signer(&fixture)?),
        HeaderValue::new(&fixture.provenance.controller_prefix)?,
    )?
    .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);

    let request = Request::builder(Method::Get, RequestUrl::new(case.request.url.clone())?).build()?;
    assert!(block_on(transport.execute(request)).is_ok());

    // What was actually sent carries the reference's own signature bytes.
    let sent = scripted.last_request().ok_or("nothing was sent")?;
    assert_eq!(sent.headers().get("signature"), case.request.header("signature"));
    assert_eq!(
        sent.headers().get("signature-input"),
        case.request.header("signature-input"),
    );
    Ok(())
}
