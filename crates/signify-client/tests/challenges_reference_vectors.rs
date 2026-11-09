//! Exact challenge-endpoint vectors recorded from the pinned reference's own `Challenges`.
//!
//! Three methods' exact addresses and bodies; `respond`'s deferral read out of the reference rather than claimed.

mod support;

use std::error::Error;

use crate::support::{ADMIN, AGENT, FIXED_MILLIS, Harness, PASSCODE, SentRequest, block_on, connected, sent};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keria_types::api::OperationOutcome;
use serde::Deserialize;
use serde_json::Value;
use signify_client::endpoint::challenges::{
    CHALLENGE_RESPONSE_ROUTE, CHALLENGE_TOPIC, CHALLENGES_SEGMENT, CHALLENGES_VERIFY_SEGMENT, ChallengeStrength,
    STRENGTH_PARAMETER,
};
use signify_client::error::ClientError;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

const SOURCE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

// --- Fixture model ---
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

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    support::fixture("client-challenges")
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

fn source() -> Result<IdentifierPrefix, Box<dyn Error>> {
    Ok(IdentifierPrefix::from_qb64(SOURCE)?)
}

// --- Manifest and provenance ---
#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert_ne!(fixture.generated_on, "");
    assert!(fixture.sources.iter().any(|source| source.ends_with("contacting.ts")));
    assert!(fixture.sources.iter().any(|source| source.ends_with("exchanging.ts")));
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert_eq!(fixture.provenance.source_prefix, SOURCE);
    assert_eq!(fixture.provenance.exchange_said, SAID);
    assert_eq!(fixture.provenance.words.len(), 12);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 13);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
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
    assert!(deferred.deferred_to.contains("exchange endpoint"));
    assert_ne!(deferred.note, "");
    assert_ne!(deferred.rust_decision, "");

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
    assert_eq!(
        deferred.send_from_events_path,
        "path = `/identifiers/${name}/exchanges`"
    );
    assert!(deferred.send_from_events_body.contains("tpc: topic"));
    assert!(deferred.send_from_events_body.contains("exn: exn.sad"));

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

    assert_eq!(
        declarations.class_members,
        ["client", "<constructor>", "generate", "respond", "verify", "responded"]
    );

    assert_eq!(declarations.generate_parameters, ["strength: number = 128"]);
    assert_eq!(
        declarations.generate_path,
        "path = `/challenges?strength=${strength.toString()}`"
    );
    assert!(!declarations.generate_path.contains("URLSearchParams"));
    assert_eq!(declarations.generate_method, "method = 'GET'");
    assert!(declarations.generate_path.contains(CHALLENGES_SEGMENT));
    assert!(declarations.generate_path.contains(STRENGTH_PARAMETER));

    assert_eq!(declarations.verify_path, "path = `/challenges_verify/${source}`");
    assert_eq!(declarations.responded_path, declarations.verify_path);
    assert!(declarations.verify_path.contains(CHALLENGES_VERIFY_SEGMENT));
    assert_eq!(declarations.verify_method, "method = 'POST'");
    assert_eq!(declarations.responded_method, "method = 'PUT'");
    assert_eq!(declarations.verify_body, "data = { words: words, }");
    assert_eq!(declarations.responded_body, "data = { said: said, }");
    assert_eq!(declarations.verify_parameters, ["source: string", "words: string[]"]);
    assert_eq!(declarations.responded_parameters, ["source: string", "said: string"]);

    assert_eq!(declarations.verify_return, "await res.json()");
    assert_eq!(declarations.responded_return, "return res;");
    assert!(!declarations.responded_return.contains("json"));

    assert!(declarations.challenge_type.contains("words: string[]"));
    assert!(declarations.challenge_type.contains("authenticated?: boolean"));
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

// --- `generate` ---
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
        let Harness { client, transport, .. } = connected(&[&answer])?;
        let challenge = block_on(client.challenges().generate(strength))?;
        let SentRequest { path, method, body, .. } = sent(&transport, 0)?;

        assert_eq!(path, recorded.path, "{name} addressed a different resource");
        assert_eq!(method, recorded.method);
        assert_eq!(body, None);
        assert_eq!(challenge.words.len(), words);
        assert_eq!(
            usize::try_from(strength.word_count()).unwrap_or_default(),
            challenge.words.len()
        );
        assert_eq!(challenge.authenticated, None);
    }
    Ok(())
}

#[test]
fn the_default_strength_produces_the_same_request_as_naming_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
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
    for (name, path) in [
        ("generate_fractional", "/challenges?strength=1.5"),
        ("generate_not_a_number", "/challenges?strength=NaN"),
        ("generate_negative", "/challenges?strength=-1"),
    ] {
        assert_eq!(request_of(&fixture, name)?.path, path, "{name} sent something else");
    }
    for bits in [0_u32, 1, 127, 129, 255, 257] {
        assert!(
            matches!(
                ChallengeStrength::new(bits),
                Err(ClientError::InvalidChallengeStrength { bits: reported }) if reported == bits
            ),
            "{bits} was accepted"
        );
    }
    assert_eq!(ChallengeStrength::DECLARED, [128, 160, 192, 224, 256]);
    Ok(())
}

// --- `verify` and `responded` ---
#[test]
fn the_pinned_verification_reproduces_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "verify")?;
    assert_eq!(recorded.path, format!("/challenges_verify/{SOURCE}"));
    assert_eq!(recorded.method, "POST");

    let words = fixture.provenance.words.clone();
    let answer = answer_of(&fixture, "verify")?;
    let Harness { client, transport, .. } = connected(&[&answer])?;
    let operation = block_on(client.challenges().verify(&source()?, &words))?;
    let SentRequest { path, method, body, .. } = sent(&transport, 0)?;

    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_eq!(body, recorded.body, "the verification body differs");
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

    let Harness { client, transport, .. } = connected(&[b"{}"])?;
    block_on(client.challenges().responded(&source()?, &Said::from_qb64(SAID)?))?;
    let SentRequest { path, method, body, .. } = sent(&transport, 0)?;

    assert_eq!(path, recorded.path);
    assert_eq!(method, "PUT");
    assert_eq!(body, recorded.body);
    assert_eq!(path, request_of(&fixture, "verify")?.path);
    Ok(())
}

#[test]
fn an_empty_word_list_is_refused_where_the_reference_sends_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "verify_empty_words")?;
    assert_eq!(recorded.body.as_deref(), Some(r#"{"words":[]}"#));
    assert_eq!(recorded.path, format!("/challenges_verify/{SOURCE}"));

    let Harness { client, transport, .. } = connected(&[b"{}"])?;
    let outcome = block_on(client.challenges().verify(&source()?, &[]));
    assert!(
        matches!(outcome, Err(ClientError::EmptyChallengeWords)),
        "an empty word list was not refused: {outcome:?}"
    );
    assert!(sent(&transport, 0).is_err(), "an empty verification reached the agent");
    Ok(())
}

#[test]
fn the_said_reaches_the_body_and_changes_no_address() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let hostile = request_of(&fixture, "responded_said_needing_encoding")?;
    assert_eq!(hostile.path, format!("/challenges_verify/{SOURCE}"));
    assert_eq!(hostile.body.as_deref(), Some(r#"{"said":"E/../x?y=1"}"#));
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
    let Harness { client, transport, .. } = connected(&[&answer])?;
    let outcome = block_on(client.challenges().generate(ChallengeStrength::BITS_128));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "an answer carrying no words was not refused: {outcome:?}"
    );
    assert_eq!(sent(&transport, 0)?.path, "/challenges?strength=128");

    let verified = call(&fixture, "verify_wrong_shape")?;
    assert_eq!(verified.error, None);
    let answer = serde_json::to_vec(&verified.result)?;
    let words = fixture.provenance.words.clone();
    let Harness { client, .. } = connected(&[&answer])?;
    let outcome = block_on(client.challenges().verify(&source()?, &words));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "an answer that is not an operation was not refused: {outcome:?}"
    );
    Ok(())
}
