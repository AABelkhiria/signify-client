//! Hermetic assertions over the recorded randy identifier lifecycle.
//!
//! Wave 6 drove `test-integration/randy.test.ts` against a live deployment: a fresh-entropy
//! identifier incepted, an interaction anchored, and a rotation revealed. Nothing about a randy
//! identifier can be pinned — every run's keys are new — so what this file re-checks is the
//! structure the upstream case asserts, and above all the **key commitment**: BLAKE3-256 over the
//! rotation's revealed signing key must equal the digest the inception committed to, recomputed
//! here from the recorded events rather than trusted.
//!
//! Not ignored: it reads a checked-in recording and never touches a network.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use signify_crypto::digest::{Digest, DigestAlgorithm};
use signify_keri::prefix::{IdentifierPrefix, PrefixVerification};
use signify_keri::said::{Said, SaidVerification};
use signify_keri::serialization::Sad;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    prefix: String,
    inception: EventCapture,
    port_anchor: String,
    interaction: EventCapture,
    rotation: EventCapture,
    commitment: KeyCommitment,
    log_lengths: Vec<usize>,
    operations_remaining: usize,
    transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct EventCapture {
    derived_event: String,
    derived_said: String,
    agent_event: String,
}

#[derive(Debug, Deserialize)]
struct KeyCommitment {
    inception_diger: String,
    rotation_verfer: String,
    recomputed: String,
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
        .join("fixtures/keria-integration/observations/randy_lifecycle.json");
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

/// Reads the sole element of one text array, by label.
fn sole_text(document: &Value, label: &str) -> Result<String, Box<dyn Error>> {
    let values = document
        .get(label)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("the document carries no array {label}"))?;
    match values.as_slice() {
        [Value::String(text)] => Ok(text.clone()),
        other => Err(format!("{label} holds {} entries where one text was expected", other.len()).into()),
    }
}

#[test]
fn the_recording_is_the_whole_scenario() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "randy_lifecycle");
    assert!(!captured.preset.is_empty());
    assert!(!captured.transcript.is_empty(), "the recording kept no transcript");

    // The upstream case's structural spine: the log grows from two to three, and every operation
    // was waited out and deleted.
    assert_eq!(captured.log_lengths, [2, 3]);
    assert_eq!(captured.operations_remaining, 0);
    Ok(())
}

#[test]
fn the_inception_has_the_upstream_shape_and_derives_its_prefix() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    let event: Value = serde_json::from_str(&captured.inception.derived_event)?;
    assert_eq!(text_field(&event, "kt")?, "1");
    assert_eq!(text_field(&event, "nt")?, "1");
    assert_eq!(text_field(&event, "i")?, captured.prefix);
    sole_text(&event, "k")?;
    sole_text(&event, "n")?;

    // The prefix re-derives from the derived bytes, strictly.
    let sad = Sad::from_json_bytes(captured.inception.derived_event.as_bytes())?;
    IdentifierPrefix::from_qb64(&captured.prefix)?.verify(&sad, PrefixVerification::Strict)?;

    // And the agent echoed the same event.
    let echoed: Value = serde_json::from_str(&captured.inception.agent_event)?;
    assert_eq!(text_field(&echoed, "d")?, captured.inception.derived_said);
    Ok(())
}

#[test]
fn the_interaction_anchors_the_inception_seal() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    let event: Value = serde_json::from_str(&captured.interaction.derived_event)?;
    assert_eq!(text_field(&event, "s")?, "1");

    // The anchor is one seal of the inception — upstream's bare-string `[icp.pre]` is
    // unrepresentable (wave 3 records the divergence); the seal is the value that can exist.
    let anchors = event
        .get("a")
        .and_then(Value::as_array)
        .ok_or("the interaction carries no anchor list")?;
    let seal = match anchors.as_slice() {
        [seal] => seal,
        other => return Err(format!("expected exactly one anchored seal, found {}", other.len()).into()),
    };
    assert_eq!(text_field(seal, "i")?, captured.prefix);
    assert_eq!(text_field(seal, "s")?, "0");
    assert_eq!(text_field(seal, "d")?, captured.inception.derived_said);
    let recorded_anchor: Value = serde_json::from_str(&captured.port_anchor)?;
    assert_eq!(seal, &recorded_anchor);

    // The event's SAID verifies strictly, and the agent echoed the same document.
    let sad = Sad::from_json_bytes(captured.interaction.derived_event.as_bytes())?;
    Said::from_qb64(&captured.interaction.derived_said)?.verify(&sad, "d", SaidVerification::strict())?;
    let echoed: Value = serde_json::from_str(&captured.interaction.agent_event)?;
    assert_eq!(text_field(&echoed, "d")?, captured.interaction.derived_said);
    Ok(())
}

#[test]
fn the_rotation_reveals_exactly_the_committed_key() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    let inception: Value = serde_json::from_str(&captured.inception.derived_event)?;
    let rotation: Value = serde_json::from_str(&captured.rotation.derived_event)?;
    assert_eq!(text_field(&rotation, "s")?, "2");

    // The keys moved: the rotation neither kept the signing key nor repeated the commitment.
    let inception_verfer = sole_text(&inception, "k")?;
    let inception_diger = sole_text(&inception, "n")?;
    let rotation_verfer = sole_text(&rotation, "k")?;
    assert_ne!(rotation_verfer, inception_verfer);
    assert_ne!(sole_text(&rotation, "n")?, inception_diger);

    // The commitment, recomputed from the recorded events rather than read from the flags the
    // scenario wrote: the revealed key's BLAKE3-256 digest is the digest the inception committed.
    let recomputed = Digest::derive(DigestAlgorithm::Blake3_256, rotation_verfer.as_bytes()).qb64()?;
    assert_eq!(recomputed, inception_diger);
    assert_eq!(captured.commitment.inception_diger, inception_diger);
    assert_eq!(captured.commitment.rotation_verfer, rotation_verfer);
    assert_eq!(captured.commitment.recomputed, recomputed);

    // And the rotation's own SAID verifies over the derived bytes.
    let sad = Sad::from_json_bytes(captured.rotation.derived_event.as_bytes())?;
    Said::from_qb64(&captured.rotation.derived_said)?.verify(&sad, "d", SaidVerification::strict())?;
    Ok(())
}

#[test]
fn the_agent_accepted_the_ports_exact_bytes() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // Byte-level, from the transcript: each derived event appears verbatim inside a successful
    // POST body, so what the agent accepted is what the port serialized.
    let embedded = |resource: &str, needle: &str| -> bool {
        captured.transcript.iter().any(|observation| {
            observation.method == "POST"
                && observation.resource == resource
                && (200..300).contains(&observation.status)
                && observation
                    .request_body
                    .as_deref()
                    .is_some_and(|body| body.contains(needle))
        })
    };
    assert!(
        embedded("/identifiers", &captured.inception.derived_event),
        "the exact inception bytes were never accepted by the agent"
    );
    for (name, capture) in [("interaction", &captured.interaction), ("rotation", &captured.rotation)] {
        assert!(
            embedded("/identifiers/aid1/events", &capture.derived_event),
            "the exact {name} bytes were never accepted by the agent"
        );
    }
    Ok(())
}
