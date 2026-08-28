//! Wave 6 — the randy identifier lifecycle: fresh-entropy keys against a live agent.
//!
//! `test-integration/randy.test.ts` is the §7 row for the *other* key algorithm: keys generated
//! from operating-system entropy and held sealed to the passcode, rather than derived from a
//! salt. Nothing about a randy identifier can be pinned — every run's keys are new — so the
//! upstream case is structural, and its strongest assertion is the **key commitment**: the
//! rotation's new signing key, hashed with BLAKE3-256, must equal the digest the inception
//! committed to. That check ties three artifacts together — the inception the port built, the
//! rotation the port built one wait later, and the agent's acceptance of both — and it is
//! recomputed here from the recorded events rather than trusted.
//!
//! The interaction anchors a seal of the inception where upstream anchors the bare string
//! `[icp.pre]`, exactly as wave 3 did and for the same reason: a bare string is not a `Sad`
//! (Roadmap 4.6), so the anchor divergence is documented once and reproduced identically.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave6_randy_lifecycle -- --ignored --test-threads=1 --nocapture
//! ```

// After the docs: a false `#![cfg]` strips everything below it, docs included, and an
// undocumented empty crate trips `missing_docs`.
#![cfg(feature = "live")]

use std::error::Error;

use serde::Serialize;
use serde_json::Value;
use signify_client::client::ConnectedClient;
use signify_crypto::digest::{Digest, DigestAlgorithm};
use signify_http::request::ItemRange;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest};
use signify_keri::serialization::{Sad, SadValue};
use signify_keria_systest::{Environment, connect, progress, record, recorder};

/// One event: the port's exact bytes, its SAID, and the agent's echo.
#[derive(Debug, Serialize)]
struct EventCapture {
    derived_event: String,
    derived_said: String,
    agent_event: String,
}

/// The key-commitment check, with every input recorded so it can be recomputed.
#[derive(Debug, Serialize)]
struct KeyCommitment {
    /// The digest the inception committed to, its `n[0]`.
    inception_diger: String,
    /// The signing key the rotation revealed, its `k[0]`.
    rotation_verfer: String,
    /// BLAKE3-256 over the revealed key's qb64, computed by the port at run time.
    recomputed: String,
}

/// Everything the run observed, written as the fixture.
#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    /// The randy identifier's prefix.
    prefix: String,
    inception: EventCapture,
    /// The seal this run anchored where upstream anchors the bare string `[icp.pre]`.
    port_anchor: String,
    interaction: EventCapture,
    rotation: EventCapture,
    commitment: KeyCommitment,
    /// The key event log's length after the interaction and after the rotation.
    log_lengths: Vec<usize>,
    /// Operations left listed after the run; upstream asserts zero.
    operations_remaining: usize,
    transcript: Vec<signify_keria_systest::Observation>,
}

/// Waits one submission's operation out, deletes it, and returns the agent's echoed event.
async fn wait_and_delete(client: &ConnectedClient, name: &str) -> Result<Value, Box<dyn Error>> {
    let operation = client.operations().get(name).await?;
    let completed = client.poller().wait(operation).await?;
    let (name, _metadata, response) = completed.into_parts();
    client.operations().delete(&name).await?;
    Ok(response)
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

/// Compares one observed value with what the scenario expects.
fn check(mismatches: &mut Vec<String>, what: &str, observed: &str, expected: &str) {
    if observed != expected {
        mismatches.push(format!("{what}: observed {observed}, expected {expected}"));
    }
}

/// Creates the randy identifier and captures both sides plus its key and commitment.
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

/// Rotates the identifier and checks the reveal against the inception's commitment.
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
    // The commitment: the revealed key's BLAKE3-256 digest is the digest the inception committed.
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

    // A randy identifier at the reference's defaults: one key, one next key, fresh entropy.
    let (inception, prefix_text, inception_verfer, inception_diger) = create_randy(&client, &mut mismatches).await?;
    let prefix = signify_keri::prefix::IdentifierPrefix::from_qb64(&prefix_text)?;

    // The listing knows it, under its alias, at its prefix.
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

    // Interact, anchoring a seal of the inception — upstream anchors the bare string `[icp.pre]`,
    // which Vec<Sad> cannot spell; wave 3 records that divergence and this reproduces it.
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

    // Rotate, and check the reveal against the commitment.
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

    // Record before asserting, so a diverging run still leaves the evidence of how it diverged.
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
