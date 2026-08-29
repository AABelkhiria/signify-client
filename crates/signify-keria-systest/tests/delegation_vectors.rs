//! Hermetic assertions over the recorded single-signature delegation.
//!
//! Wave 9 drove `test-integration/delegation.test.ts` against a live deployment: a delegated
//! inception that stays **pending** until the delegator anchors a seal of it, the approving
//! interaction, the key-state query that lets the delegate's agent see the anchor, and the
//! upstream case's odd tail — the delegate's agent OOBI truncated at `/agent/` still resolving.
//! This file re-checks the recording from the events' own bytes.
//!
//! Not ignored: it reads a checked-in recording and never touches a network.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use signify_keri::prefix::{IdentifierPrefix, PrefixVerification};
use signify_keri::said::{Said, SaidVerification};
use signify_keri::serialization::Sad;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    delegator_prefix: String,
    delegate_prefix: String,
    delegate_event: String,
    delegate_said: String,
    pending_before_approval: bool,
    approval_event: String,
    approval_said: String,
    query_sequence_sent: String,
    accepted_prefix: String,
    truncated_oobi: String,
    contact_resolved: String,
    delegator_operations_remaining: usize,
    delegate_operations_remaining: usize,
    delegator_transcript: Vec<Observation>,
    delegate_transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct Observation {
    method: String,
    resource: String,
    request_body: Option<String>,
    status: u16,
}

fn captured() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/observations/delegation.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

/// Reads one text field out of a JSON document, by label.
fn text_field(document: &Value, label: &str) -> Result<String, Box<dyn Error>> {
    document
        .get(label)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("the document carries no text field {label}").into())
}

#[test]
fn the_recording_is_the_whole_scenario() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "delegation");
    assert!(!captured.preset.is_empty());
    assert!(!captured.delegator_transcript.is_empty());
    assert!(!captured.delegate_transcript.is_empty());

    IdentifierPrefix::from_qb64(&captured.delegator_prefix)?;
    IdentifierPrefix::from_qb64(&captured.delegate_prefix)?;
    assert_ne!(captured.delegator_prefix, captured.delegate_prefix);
    assert_eq!(captured.accepted_prefix, captured.delegate_prefix);

    // The upstream postcondition, on both clients — which needs the dependency walk: a delegation
    // approval spawns a `witness.…` operation inside its own `metadata.depends`.
    assert_eq!(captured.delegator_operations_remaining, 0);
    assert_eq!(captured.delegate_operations_remaining, 0);
    Ok(())
}

#[test]
fn the_delegated_inception_names_its_delegator_and_pends() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The row's point: the operation was pending before the approval — a delegated identifier
    // does not exist until its delegator anchors it.
    assert!(captured.pending_before_approval);

    // The dip itself: it names the delegator in `di`, and its identifier is its own digest.
    let event: Value = serde_json::from_str(&captured.delegate_event)?;
    assert_eq!(text_field(&event, "t")?, "dip");
    assert_eq!(text_field(&event, "di")?, captured.delegator_prefix);
    assert_eq!(text_field(&event, "i")?, captured.delegate_prefix);
    assert_eq!(text_field(&event, "d")?, captured.delegate_said);
    assert_eq!(captured.delegate_said, captured.delegate_prefix);

    // The prefix re-derives from the derived bytes, strictly.
    let sad = Sad::from_json_bytes(captured.delegate_event.as_bytes())?;
    IdentifierPrefix::from_qb64(&captured.delegate_prefix)?.verify(&sad, PrefixVerification::Strict)?;
    Ok(())
}

#[test]
fn the_approval_anchors_exactly_the_inception_seal() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The approving interaction: the delegator's log at sequence one, anchoring one seal whose
    // three fields all name the delegate's inception.
    let event: Value = serde_json::from_str(&captured.approval_event)?;
    assert_eq!(text_field(&event, "t")?, "ixn");
    assert_eq!(text_field(&event, "i")?, captured.delegator_prefix);
    assert_eq!(text_field(&event, "s")?, "1");
    let anchors = event
        .get("a")
        .and_then(Value::as_array)
        .ok_or("the approval carries no anchor list")?;
    let seal = match anchors.as_slice() {
        [seal] => seal,
        other => return Err(format!("expected exactly one anchored seal, found {}", other.len()).into()),
    };
    assert_eq!(text_field(seal, "i")?, captured.delegate_prefix);
    assert_eq!(text_field(seal, "s")?, "0");
    assert_eq!(text_field(seal, "d")?, captured.delegate_prefix);

    // Its SAID verifies strictly over the derived bytes, and the exact bytes were accepted at
    // the delegation address — which Roadmap 8.5 proved is the whole difference from an
    // ordinary interaction.
    let sad = Sad::from_json_bytes(captured.approval_event.as_bytes())?;
    Said::from_qb64(&captured.approval_said)?.verify(&sad, "d", SaidVerification::strict())?;
    assert!(
        captured.delegator_transcript.iter().any(|observation| {
            observation.method == "POST"
                && observation.resource == "/identifiers/delegator/delegation"
                && (200..300).contains(&observation.status)
                && observation
                    .request_body
                    .as_deref()
                    .is_some_and(|body| body.contains(&captured.approval_event))
        }),
        "the exact approval bytes were never accepted at the delegation address"
    );
    Ok(())
}

#[test]
fn the_delegate_saw_the_anchor_through_the_key_state_query() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The query that makes the delegate's agent fetch the approving interaction: sequence one,
    // hexadecimal, proven sent from the delegate's transcript.
    assert_eq!(captured.query_sequence_sent, "1");
    assert!(
        captured.delegate_transcript.iter().any(|observation| {
            observation.method == "POST"
                && observation.resource == "/queries"
                && observation.request_body.as_deref().is_some_and(|body| {
                    body.contains(&format!("\"pre\":\"{}\"", captured.delegator_prefix))
                        && body.contains("\"sn\":\"1\"")
                })
        }),
        "the delegator key-state query was never sent"
    );
    Ok(())
}

#[test]
fn the_truncated_oobi_still_resolves_the_delegate() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The upstream case's tail: the agent OOBI cut at `/agent/` — so it ends at the bare prefix —
    // still resolves, and answers the delegate's prefix.
    assert!(
        captured
            .truncated_oobi
            .ends_with(&format!("/oobi/{}", captured.delegate_prefix)),
        "the truncated OOBI does not end at the delegate's prefix: {}",
        captured.truncated_oobi
    );
    assert!(!captured.truncated_oobi.contains("/agent/"));
    assert_eq!(captured.contact_resolved, captured.delegate_prefix);
    Ok(())
}
