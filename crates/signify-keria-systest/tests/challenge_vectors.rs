//! Hermetic assertions over the recorded challenge round.
//!
//! Word counts at both strengths, the signed response, the verification, and the contact ledger left behind.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use signify_keri::prefix::IdentifierPrefix;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    words_at_128: usize,
    words_at_256: usize,
    alice_prefix: String,
    bob_prefix: String,
    challenges_before: Option<usize>,
    response_exn: String,
    response_said: String,
    response_operation_born_done: bool,
    verified_said: String,
    challenge_after_words: usize,
    challenge_after_authenticated: Option<bool>,
    challenge_after_said: Option<String>,
    alice_operations_remaining: usize,
    bob_operations_remaining: usize,
    alice_transcript: Vec<Observation>,
    bob_transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct Observation {
    method: String,
    resource: String,
    status: u16,
}

fn captured() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/observations/challenge.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

#[test]
fn the_recording_is_the_whole_scenario() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "challenge");
    assert!(!captured.preset.is_empty());
    assert!(!captured.alice_transcript.is_empty());
    assert!(!captured.bob_transcript.is_empty());

    assert_eq!(captured.words_at_128, 12);
    assert_eq!(captured.words_at_256, 24);

    IdentifierPrefix::from_qb64(&captured.alice_prefix)?;
    IdentifierPrefix::from_qb64(&captured.bob_prefix)?;
    assert_ne!(captured.alice_prefix, captured.bob_prefix);

    assert_eq!(captured.challenges_before, Some(0));
    assert!(captured.response_operation_born_done);
    assert_eq!(captured.alice_operations_remaining, 0);
    assert_eq!(captured.bob_operations_remaining, 0);
    Ok(())
}

#[test]
fn the_verified_message_is_the_one_bob_sent() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    assert_eq!(captured.response_said, captured.verified_said);

    let exn: Value = serde_json::from_str(&captured.response_exn)?;
    assert_eq!(exn.get("r").and_then(Value::as_str), Some("/challenge/response"));
    assert_eq!(exn.get("i").and_then(Value::as_str), Some(captured.bob_prefix.as_str()));
    assert_eq!(
        exn.get("d").and_then(Value::as_str),
        Some(captured.verified_said.as_str())
    );
    let words = exn
        .get("a")
        .and_then(|payload| payload.get("words"))
        .and_then(Value::as_array)
        .ok_or("the response carries no word list")?;
    assert_eq!(words.len(), 12);

    assert!(
        captured
            .bob_transcript
            .iter()
            .any(|observation| observation.method == "POST"
                && observation.resource == "/identifiers/bob/exchanges"
                && (200..300).contains(&observation.status)),
        "the response was never submitted as an exchange"
    );
    Ok(())
}

#[test]
fn the_contact_records_the_authenticated_challenge() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    assert_eq!(captured.challenge_after_words, 12);
    assert_eq!(captured.challenge_after_authenticated, Some(true));
    assert_eq!(
        captured.challenge_after_said.as_deref(),
        Some(captured.verified_said.as_str())
    );

    let verify_resource = format!("/challenges_verify/{}", captured.bob_prefix);
    for method in ["POST", "PUT"] {
        assert!(
            captured
                .alice_transcript
                .iter()
                .any(|observation| observation.method == method
                    && observation.resource == verify_resource
                    && (200..300).contains(&observation.status)),
            "no successful {method} of {verify_resource} is recorded"
        );
    }
    Ok(())
}
