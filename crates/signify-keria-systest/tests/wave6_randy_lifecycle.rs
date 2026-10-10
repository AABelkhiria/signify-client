//! Wave 6 — the randy identifier lifecycle: fresh-entropy keys against a live agent.
//!
//! Incepts, anchors, and rotates a fresh-entropy identifier so the key commitment can be recomputed.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave6_randy_lifecycle -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_protocol::serialization::{Sad, SadValue};
use serde::Serialize;
use serde_json::Value;
use signify_client::client::ConnectedClient;
use signify_http::request::ItemRange;
use signify_keria_systest::{Environment, connect, progress, record, recorder, wait_and_delete};
use signify_keys::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest};

#[derive(Debug, Serialize)]
struct EventCapture {
    derived_event: String,
    derived_said: String,
    agent_event: String,
}

#[derive(Debug, Serialize)]
struct KeyCommitment {
    inception_diger: String,
    rotation_verfer: String,
    recomputed: String,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    prefix: String,
    inception: EventCapture,
    port_anchor: String,
    interaction: EventCapture,
    rotation: EventCapture,
    commitment: KeyCommitment,
    log_lengths: Vec<usize>,
    operations_remaining: usize,
    transcript: Vec<signify_keria_systest::Observation>,
}

fn text_field(document: &Value, label: &str) -> Result<String, Box<dyn Error>> {
    document
        .get(label)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("the document carries no text field {label}").into())
}

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

fn check(mismatches: &mut Vec<String>, what: &str, observed: &str, expected: &str) {
    if observed != expected {
        mismatches.push(format!("{what}: observed {observed}, expected {expected}"));
    }
}

async fn create_randy(
    client: &ConnectedClient,
    mismatches: &mut Vec<String>,
) -> Result<(EventCapture, String, String, String), Box<dyn Error>> {
    progress("aid1: creating (randy)");
    let created = client
        .identifiers()
        .create("aid1", &CreateIdentifierRequest::new(CreateAlgorithm::randy()))
        .await?;
    let response = wait_and_delete(client, &created.operation()?.name).await?;
    let prefix_text = created.artifact().event.identifier().qb64()?;
    let inception = EventCapture {
        derived_event: String::from_utf8(created.artifact().event.raw().to_vec())?,
        derived_said: created.artifact().event.said().qb64()?,
        agent_event: serde_json::to_string(&response)?,
    };
    let document: Value = serde_json::from_str(&inception.derived_event)?;
    check(mismatches, "inception kt", &text_field(&document, "kt")?, "1");
    check(mismatches, "inception nt", &text_field(&document, "nt")?, "1");
    let verfer = sole_text(&document, "k")?;
    let diger = sole_text(&document, "n")?;
    Ok((inception, prefix_text, verfer, diger))
}

async fn rotate_randy(
    client: &ConnectedClient,
    inception_verfer: &str,
    inception_diger: &str,
    mismatches: &mut Vec<String>,
) -> Result<(EventCapture, KeyCommitment), Box<dyn Error>> {
    progress("aid1: rotating");
    let rotated = client
        .identifiers()
        .rotate("aid1", &RotateIdentifierRequest::default())
        .await?;
    let response = wait_and_delete(client, &rotated.operation()?.name).await?;
    let rotation = EventCapture {
        derived_event: String::from_utf8(rotated.artifact().event.raw().to_vec())?,
        derived_said: rotated.artifact().event.said().qb64()?,
        agent_event: serde_json::to_string(&response)?,
    };
    let document: Value = serde_json::from_str(&rotation.derived_event)?;
    check(mismatches, "rotation sequence", &text_field(&document, "s")?, "2");
    let rotation_verfer = sole_text(&document, "k")?;
    if rotation_verfer == inception_verfer {
        mismatches.push("the rotation kept the inception's signing key".to_owned());
    }
    if sole_text(&document, "n")? == inception_diger {
        mismatches.push("the rotation kept the inception's next-key digest".to_owned());
    }
    let recomputed = Digest::derive(DigestAlgorithm::Blake3_256, rotation_verfer.as_bytes()).qb64()?;
    check(mismatches, "key commitment", &recomputed, inception_diger);
    Ok((
        rotation,
        KeyCommitment {
            inception_diger: inception_diger.to_owned(),
            rotation_verfer,
            recomputed,
        },
    ))
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn the_randy_lifecycle_rotates_to_the_committed_key() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let transcript = recorder("randy_lifecycle")?;
    progress("connecting the client");
    let client = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &transcript,
    )
    .await?;
    let mut mismatches = Vec::new();

    let (inception, prefix_text, inception_verfer, inception_diger) = create_randy(&client, &mut mismatches).await?;
    let prefix = keri_protocol::prefix::IdentifierPrefix::from_qb64(&prefix_text)?;

    let listing = client.identifiers().list(ItemRange::DEFAULT).await?;
    if listing.identifiers.len() != 1 {
        mismatches.push(format!(
            "expected one identifier listed, found {}",
            listing.identifiers.len()
        ));
    }
    if let Some(hab) = listing.identifiers.first() {
        check(&mut mismatches, "listed name", &hab.common().name, "aid1");
        check(&mut mismatches, "listed prefix", &hab.common().prefix, &prefix_text);
    }

    progress("aid1: interacting");
    let mut seal = Sad::new();
    seal.insert("i", SadValue::text(&prefix_text))?;
    seal.insert("s", SadValue::text("0"))?;
    seal.insert("d", SadValue::text(&inception.derived_said))?;
    let port_anchor = String::from_utf8(seal.to_json_bytes()?)?;
    let interacted = client.identifiers().interact("aid1", vec![seal]).await?;
    let interaction_response = wait_and_delete(&client, &interacted.operation()?.name).await?;
    let interaction = EventCapture {
        derived_event: String::from_utf8(interacted.artifact().event.raw().to_vec())?,
        derived_said: interacted.artifact().event.said().qb64()?,
        agent_event: serde_json::to_string(&interaction_response)?,
    };
    check(
        &mut mismatches,
        "interaction sequence",
        &text_field(&serde_json::from_str(&interaction.derived_event)?, "s")?,
        "1",
    );

    let mut log_lengths = Vec::new();
    log_lengths.push(client.key_events().get(&prefix).await?.len());

    let (rotation, commitment) = rotate_randy(&client, &inception_verfer, &inception_diger, &mut mismatches).await?;

    log_lengths.push(client.key_events().get(&prefix).await?.len());
    let operations_remaining = client.operations().list(None).await?.len();

    let captured = Captured {
        scenario: "randy_lifecycle",
        preset: environment.preset.to_string(),
        prefix: prefix_text,
        inception,
        port_anchor,
        interaction,
        rotation,
        commitment,
        log_lengths: log_lengths.clone(),
        operations_remaining,
        transcript: transcript.observations(),
    };

    if record("observations/randy_lifecycle.json", &captured)? {
        progress("recorded observations/randy_lifecycle.json");
    } else {
        progress("not a recording run, nothing written");
    }

    assert!(
        mismatches.is_empty(),
        "the run diverged from the upstream scenario: {mismatches:#?}"
    );
    assert_eq!(
        log_lengths,
        [2, 3],
        "the key event log did not grow as the upstream case asserts"
    );
    assert_eq!(captured.operations_remaining, 0, "operations were left behind");
    Ok(())
}
