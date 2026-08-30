//! Exact challenge-endpoint vectors recorded from the pinned reference's own `Challenges`.
//!
//! Three of the class's four methods are Roadmap 7.4's. The fourth, `respond`, is a wrapper over
//! `Exchanges.send` and belongs to Roadmap 7.7 — and that is not asserted here but *read out of the
//! reference*: the fixture's `deferred_capability` block holds `respond`'s whole body and the three
//! `Exchanges` methods it reaches, so the deferral is checkable rather than claimed.

mod support;

use core::time::Duration;
use std::error::Error;
use std::sync::Arc;
use std::time::SystemTime;

use crate::support::{ADMIN, AGENT, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on};
use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::challenges::{
    CHALLENGE_RESPONSE_ROUTE, CHALLENGE_TOPIC, CHALLENGES_SEGMENT, CHALLENGES_VERIFY_SEGMENT, ChallengeStrength,
    STRENGTH_PARAMETER,
};
use signify_client::error::ClientError;
use signify_http::retry::{Clock, TestClock};
use signify_http::transport::Transport;
use signify_keri::manager::DerivationCost;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_types::api::OperationOutcome;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-challenges/v1.json");

/// The identifier the pinned unit test challenges.
const SOURCE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
/// The exchange SAID the pinned unit test marks as accepted.
const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

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
    deferred_capability: DeferralRecord,
    calls: Vec<Call>,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    fixed_clock_ms: u64,
    agent_prefix: String,
    source_prefix: String,
    exchange_said: String,
    words: Vec<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    generate_parameters: Vec<String>,
    generate_path: String,
    generate_method: String,
    verify_parameters: Vec<String>,
    verify_path: String,
    verify_method: String,
    verify_body: String,
    responded_parameters: Vec<String>,
    responded_path: String,
    responded_method: String,
    responded_body: String,
    responded_return: String,
    verify_return: String,
    class_members: Vec<String>,
    challenge_type: String,
}

#[derive(Debug, Deserialize)]
struct DeferralRecord {
    capability: String,
    deferred_to: String,
    body: String,
    reaches: Vec<String>,
    send_from_events_path: String,
    send_from_events_body: String,
    topic: String,
    route: String,
    note: String,
    rust_decision: String,
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
    unit_test_assertions: Vec<String>,
    unit_test_paths: Vec<String>,
    unit_test_words: Vec<String>,
    unit_test_said: String,
    integration_usage: Vec<String>,
    call_sites: Scan,
    driven_paths: Vec<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Scan {
    total: usize,
    scanned_files: usize,
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

fn answer_of(fixture: &Fixture, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(serde_json::to_vec(&call(fixture, name)?.result)?)
}

/// A connected client and its scripted agent.
type Harness = (ConnectedClient, Arc<AgentTransport>);

fn connected(bodies: &[&[u8]]) -> Result<Harness, Box<dyn Error>> {
    let configuration = || {
        ClientConfig::new(ADMIN, PASSCODE)
            .and_then(|config| config.with_boot_url(BOOT))
            .map(|config| config.with_derivation_cost(DerivationCost::Ephemeral))
    };
    let clock: Arc<dyn Clock> = Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(FIXED_MILLIS),
    ));
    let probe = SignifyClient::new(
        configuration()?,
        AgentTransport::new(&[]) as Arc<dyn Transport>,
        Arc::clone(&clock),
    )?;
    let prefix = probe.controller().prefix().qb64()?;
    let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();

    let state = agent_state(&prefix, &inception);
    let mut answers: Vec<&[u8]> = vec![state.as_bytes(), b"{}"];
    answers.extend_from_slice(bodies);
    let transport = AgentTransport::new(&answers);

    let client = SignifyClient::new(
        configuration()?,
        Arc::clone(&transport) as Arc<dyn Transport>,
        Arc::clone(&clock),
    )?;
    Ok((block_on(client.connect())?, transport))
}

/// Returns the path, method, and body of the first endpoint request after connecting.
fn sent(transport: &AgentTransport) -> Result<(String, String, Option<String>), Box<dyn Error>> {
    let recorded = transport.requests();
    let request = recorded.get(2).ok_or("no endpoint request was sent")?;
    let path = request.resource();
    let body = request.body_text();
    Ok((path, request.method().to_owned(), body))
}

fn source() -> Result<IdentifierPrefix, Box<dyn Error>> {
    Ok(IdentifierPrefix::from_qb64(SOURCE)?)
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
    assert!(fixture.sources.iter().any(|source| source.ends_with("contacting.ts")));
    // The exchange module is a source here *because* of what was deferred from it.
    assert!(fixture.sources.iter().any(|source| source.ends_with("exchanging.ts")));
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert_eq!(fixture.provenance.source_prefix, SOURCE);
    assert_eq!(fixture.provenance.exchange_said, SAID);
    // Twelve words, which is what 128 bits of BIP39 entropy produces.
    assert_eq!(fixture.provenance.words.len(), 12);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 13);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        // The reference refuses none of them — not `NaN`, not an empty word list.
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
        assert!(entry.request.is_some(), "call {} made no request", entry.name);
    }
    Ok(())
}

#[test]
fn the_deferred_capability_is_read_from_the_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let deferred = &fixture.deferred_capability;

    assert_eq!(deferred.capability, "Challenges.respond");
    assert!(deferred.deferred_to.contains("7.7"));
    assert!(!deferred.note.is_empty());
    assert!(!deferred.rust_decision.is_empty());

    // `respond` delegates: it reads the habitat and calls `Exchanges.send`, and reaches nothing else.
    assert!(deferred.body.contains("exchanges.send("));
    assert!(deferred.body.contains("identifiers().get(name)"));
    assert_eq!(
        deferred.reaches,
        [
            "Exchanges.send",
            "Exchanges.createExchangeMessage",
            "Exchanges.sendFromEvents"
        ]
    );
    // The submission it needs is the generic exchange one, which is Roadmap 7.7's whole write half.
    assert_eq!(
        deferred.send_from_events_path,
        "path = `/identifiers/${name}/exchanges`"
    );
    assert!(deferred.send_from_events_body.contains("tpc: topic"));
    assert!(deferred.send_from_events_body.contains("exn: exn.sad"));

    // The two constants this module keeps, because they are facts about challenges rather than
    // about exchanges.
    assert_eq!(deferred.topic, CHALLENGE_TOPIC);
    assert_eq!(deferred.route, CHALLENGE_RESPONSE_ROUTE);
    assert!(deferred.body.contains(CHALLENGE_RESPONSE_ROUTE));
    assert!(deferred.body.contains(CHALLENGE_TOPIC));
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // Four methods, of which three are this item's.
    assert_eq!(
        declarations.class_members,
        ["client", "<constructor>", "generate", "respond", "verify", "responded"]
    );

    // The strength is stringified straight into the query, with a default that reaches the wire.
    assert_eq!(declarations.generate_parameters, ["strength: number = 128"]);
    assert_eq!(
        declarations.generate_path,
        "path = `/challenges?strength=${strength.toString()}`"
    );
    assert!(!declarations.generate_path.contains("URLSearchParams"));
    assert_eq!(declarations.generate_method, "method = 'GET'");
    assert!(declarations.generate_path.contains(CHALLENGES_SEGMENT));
    assert!(declarations.generate_path.contains(STRENGTH_PARAMETER));

    // Both verification calls share one address and differ only in method and body.
    assert_eq!(declarations.verify_path, "path = `/challenges_verify/${source}`");
    assert_eq!(declarations.responded_path, declarations.verify_path);
    assert!(declarations.verify_path.contains(CHALLENGES_VERIFY_SEGMENT));
    assert_eq!(declarations.verify_method, "method = 'POST'");
    assert_eq!(declarations.responded_method, "method = 'PUT'");
    assert_eq!(declarations.verify_body, "data = { words: words, }");
    assert_eq!(declarations.responded_body, "data = { said: said, }");
    assert_eq!(declarations.verify_parameters, ["source: string", "words: string[]"]);
    assert_eq!(declarations.responded_parameters, ["source: string", "said: string"]);

    // `responded` is the only method that does not read its answer.
    assert_eq!(declarations.verify_return, "await res.json()");
    assert_eq!(declarations.responded_return, "return res;");
    assert!(!declarations.responded_return.contains("json"));

    // The answer type, whose three optional fields are what `responded` eventually fills in.
    assert!(declarations.challenge_type.contains("words: string[]"));
    assert!(declarations.challenge_type.contains("authenticated?: boolean"));
    Ok(())
}

#[test]
fn every_assertion_the_pinned_unit_test_makes_is_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;

    assert_eq!(pinned.unit_test_assertions.len(), 4);
    assert!(
        pinned
            .unit_test_assertions
            .iter()
            .any(|line| line.contains("strength=128"))
    );
    assert!(
        pinned
            .unit_test_assertions
            .iter()
            .any(|line| line.contains("challenges_verify"))
    );
    assert!(
        pinned
            .unit_test_assertions
            .iter()
            .any(|line| line.contains("lastBody.words, words"))
    );
    assert!(
        pinned
            .unit_test_assertions
            .iter()
            .any(|line| line.contains("lastBody.said"))
    );

    // Two addresses, both driven.
    assert_eq!(pinned.unit_test_paths.len(), 2);
    for path in &pinned.unit_test_paths {
        assert!(
            pinned.driven_paths.iter().any(|driven| driven == path),
            "the pinned test asserts {path}, which nothing here drove"
        );
    }
    assert_eq!(pinned.unit_test_words.len(), 12);
    assert_eq!(pinned.unit_test_said, SAID);

    // The integration suites add the second strength, the operation, and the empty challenge list
    // that `responded` exists to fill.
    assert_eq!(pinned.integration_usage.len(), 5);
    assert!(
        pinned
            .integration_usage
            .iter()
            .any(|line| line.contains("generate(256)"))
    );
    assert!(
        pinned
            .integration_usage
            .iter()
            .any(|line| line.contains("bobContact.challenges.length, 0"))
    );
    assert!(pinned.call_sites.total >= 10);
    assert!(pinned.call_sites.scanned_files > 100);
    assert!(!pinned.note.is_empty());
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 8);
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
// `generate`.
// ---------------------------------------------------------------------------

#[test]
fn both_recorded_strengths_reproduce_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, strength, words) in [
        ("generate_128", ChallengeStrength::BITS_128, 12_usize),
        ("generate_256", ChallengeStrength::BITS_256, 24),
    ] {
        let recorded = request_of(&fixture, name)?;
        assert_eq!(recorded.path, format!("/challenges?strength={}", strength.bits()));
        assert_eq!(recorded.method, "GET");
        assert_eq!(recorded.body, None);

        let answer = answer_of(&fixture, name)?;
        let (client, transport) = connected(&[&answer])?;
        let challenge = block_on(client.challenges().generate(strength))?;
        let (path, method, body) = sent(&transport)?;

        assert_eq!(path, recorded.path, "{name} addressed a different resource");
        assert_eq!(method, recorded.method);
        assert_eq!(body, None);
        // The agent's own answer carries exactly the word count BIP39 gives that strength.
        assert_eq!(challenge.words.len(), words);
        assert_eq!(
            usize::try_from(strength.word_count()).unwrap_or_default(),
            challenge.words.len()
        );
        // A fresh challenge has been answered by nobody.
        assert_eq!(challenge.authenticated, None);
    }
    Ok(())
}

#[test]
fn the_default_strength_produces_the_same_request_as_naming_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // `generate()` writes the `= 128` default into the query, so it is an observable request.
    let defaulted = request_of(&fixture, "generate_default")?;
    let named = request_of(&fixture, "generate_128")?;
    assert_eq!(defaulted.path, named.path);
    assert_eq!(defaulted.path, "/challenges?strength=128");
    assert_eq!(ChallengeStrength::default(), ChallengeStrength::BITS_128);
    Ok(())
}

#[test]
fn a_strength_no_generator_could_satisfy_is_unrepresentable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference stringifies all three straight into the query.
    for (name, path) in [
        ("generate_fractional", "/challenges?strength=1.5"),
        ("generate_not_a_number", "/challenges?strength=NaN"),
        ("generate_negative", "/challenges?strength=-1"),
    ] {
        assert_eq!(request_of(&fixture, name)?.path, path, "{name} sent something else");
    }
    // None of them is an entropy size, and this type takes only entropy sizes.
    for bits in [0_u32, 1, 127, 129, 255, 257] {
        assert!(
            matches!(
                ChallengeStrength::new(bits),
                Err(ClientError::InvalidChallengeStrength { bits: reported }) if reported == bits
            ),
            "{bits} was accepted"
        );
    }
    // A fraction and a negative are not even expressible as the argument's type.
    assert_eq!(ChallengeStrength::DECLARED, [128, 160, 192, 224, 256]);
    Ok(())
}

// ---------------------------------------------------------------------------
// `verify` and `responded`.
// ---------------------------------------------------------------------------

#[test]
fn the_pinned_verification_reproduces_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "verify")?;
    assert_eq!(recorded.path, format!("/challenges_verify/{SOURCE}"));
    assert_eq!(recorded.method, "POST");

    let words = fixture.provenance.words.clone();
    let answer = answer_of(&fixture, "verify")?;
    let (client, transport) = connected(&[&answer])?;
    let operation = block_on(client.challenges().verify(&source()?, &words))?;
    let (path, method, body) = sent(&transport)?;

    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_eq!(body, recorded.body, "the verification body differs");
    // It is an operation, not a verdict: the agent has to go and look.
    assert!(matches!(operation.outcome, OperationOutcome::Pending));
    assert_eq!(operation.metadata.map(|metadata| metadata.words), Some(words));
    Ok(())
}

#[test]
fn the_pinned_acceptance_reproduces_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "responded")?;
    assert_eq!(recorded.path, format!("/challenges_verify/{SOURCE}"));
    assert_eq!(recorded.method, "PUT");
    assert_eq!(recorded.body.as_deref(), Some(&format!(r#"{{"said":"{SAID}"}}"#)[..]));

    let (client, transport) = connected(&[b"{}"])?;
    block_on(client.challenges().responded(&source()?, &Said::from_qb64(SAID)?))?;
    let (path, method, body) = sent(&transport)?;

    assert_eq!(path, recorded.path);
    assert_eq!(method, "PUT");
    assert_eq!(body, recorded.body);
    // And the two verification calls really do address the identical resource.
    assert_eq!(path, request_of(&fixture, "verify")?.path);
    Ok(())
}

#[test]
fn responded_returns_nothing_where_the_reference_returns_a_transport_type() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "responded")?;
    // The reference hands back the platform `Response` without reading it.
    assert_eq!(
        recorded.result.get("kind").and_then(Value::as_str),
        Some("Response"),
        "the reference no longer returns a raw response"
    );
    assert_eq!(
        recorded.result.get("body_already_read").and_then(Value::as_bool),
        Some(false),
        "the reference now reads the body"
    );

    // Here the method returns the unit type, so no transport type crosses the SDK boundary.
    let (client, _) = connected(&[b"{}"])?;
    let returned: () = block_on(client.challenges().responded(&source()?, &Said::from_qb64(SAID)?))?;
    assert_eq!(returned, ());
    Ok(())
}

#[test]
fn an_empty_word_list_is_refused_where_the_reference_sends_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "verify_empty_words")?;
    // Upstream asks the agent to confirm that an identifier signed nothing.
    assert_eq!(recorded.body.as_deref(), Some(r#"{"words":[]}"#));
    assert_eq!(recorded.path, format!("/challenges_verify/{SOURCE}"));

    let (client, transport) = connected(&[b"{}"])?;
    let outcome = block_on(client.challenges().verify(&source()?, &[]));
    assert!(
        matches!(outcome, Err(ClientError::EmptyChallengeWords)),
        "an empty word list was not refused: {outcome:?}"
    );
    // Refused before anything was sent, which is what makes it a caller error rather than a request.
    assert!(sent(&transport).is_err(), "an empty verification reached the agent");
    Ok(())
}

#[test]
fn a_source_that_would_escape_the_path_is_unrepresentable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "verify_source_needing_encoding")?;
    // One argument becoming two segments and a query, and a different `@path` to sign.
    assert_eq!(recorded.path, "/challenges_verify/a/b?c=d");
    assert!(IdentifierPrefix::from_qb64("a/b?c=d").is_err());
    Ok(())
}

#[test]
fn the_said_reaches_the_body_and_changes_no_address() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let hostile = request_of(&fixture, "responded_said_needing_encoding")?;
    // Unlike the source, it cannot move the request: it is written into the JSON body.
    assert_eq!(hostile.path, format!("/challenges_verify/{SOURCE}"));
    assert_eq!(hostile.body.as_deref(), Some(r#"{"said":"E/../x?y=1"}"#));
    // It is still typed, because a SAID that names no message records an acceptance of nothing.
    assert!(Said::from_qb64("E/../x?y=1").is_err());
    assert!(Said::from_qb64(SAID).is_ok());
    Ok(())
}

#[test]
fn a_wrong_shaped_answer_is_refused_where_the_reference_casts_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    let generated = call(&fixture, "generate_wrong_shape")?;
    assert_eq!(generated.error, None);
    assert_eq!(generated.result.get("unexpected").and_then(Value::as_bool), Some(true));
    let answer = serde_json::to_vec(&generated.result)?;
    let (client, transport) = connected(&[&answer])?;
    let outcome = block_on(client.challenges().generate(ChallengeStrength::BITS_128));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "an answer carrying no words was not refused: {outcome:?}"
    );
    // The request still went out, so this refuses the answer rather than the call.
    assert_eq!(sent(&transport)?.0, "/challenges?strength=128");

    let verified = call(&fixture, "verify_wrong_shape")?;
    assert_eq!(verified.error, None);
    let answer = serde_json::to_vec(&verified.result)?;
    let words = fixture.provenance.words.clone();
    let (client, _) = connected(&[&answer])?;
    let outcome = block_on(client.challenges().verify(&source()?, &words));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "an answer that is not an operation was not refused: {outcome:?}"
    );
    Ok(())
}
