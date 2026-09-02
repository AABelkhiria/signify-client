//! Hermetic assertions over the recorded single-signature rotation and interaction.
//!
//! The local/remote key-state divergence, closed by a refresh spelled in hexadecimal.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use signify_keri::said::{Said, SaidVerification};
use signify_keri::serialization::Sad;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    prefix: String,
    contact_resolved: String,
    local_before: StateBrief,
    remote_before_sequence: String,
    derived_event: String,
    derived_said: String,
    agent_event: String,
    local_after: StateBrief,
    remote_stale_sequence: String,
    query_sequence_sent: String,
    refreshed: StateBrief,
    owner_operations_remaining: usize,
    observer_operations_remaining: usize,
    observer_transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct StateBrief {
    sequence: String,
    signing_key: String,
    next_digest: String,
}

#[derive(Debug, Deserialize)]
struct Observation {
    method: String,
    resource: String,
    request_body: Option<String>,
}

fn captured(name: &str) -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join(format!("fixtures/keria-integration/observations/{name}.json"));
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

fn shared(captured: &Captured, kind: &str) -> Result<(), Box<dyn Error>> {
    assert!(!captured.preset.is_empty());

    assert_eq!(captured.contact_resolved, captured.prefix);

    assert_eq!(captured.local_before.sequence, captured.remote_before_sequence);
    let before = u64::from_str_radix(&captured.local_before.sequence, 16)?;
    let after = u64::from_str_radix(&captured.local_after.sequence, 16)?;
    assert_eq!(after, before + 1, "{kind}: the local sequence did not increment");
    assert_eq!(captured.remote_stale_sequence, captured.local_before.sequence);
    assert_eq!(captured.refreshed.sequence, captured.local_after.sequence);

    assert_eq!(captured.query_sequence_sent, format!("{after:x}"));
    assert!(
        captured.observer_transcript.iter().any(|observation| {
            observation.method == "POST"
                && observation.resource == "/queries"
                && observation
                    .request_body
                    .as_deref()
                    .is_some_and(|body| body.contains(&format!("\"sn\":\"{}\"", captured.query_sequence_sent)))
        }),
        "{kind}: the refresh query's sequence text was never sent"
    );

    let sad = Sad::from_json_bytes(captured.derived_event.as_bytes())?;
    Said::from_qb64(&captured.derived_said)?.verify(&sad, "d", SaidVerification::strict())?;
    let echoed: Value = serde_json::from_str(&captured.agent_event)?;
    assert_eq!(
        echoed.get("d").and_then(Value::as_str),
        Some(captured.derived_said.as_str()),
        "{kind}: the agent echoed a different event"
    );

    assert_eq!(captured.owner_operations_remaining, 0);
    assert_eq!(captured.observer_operations_remaining, 0);
    Ok(())
}

#[test]
fn the_rotation_twin_moves_the_keys_and_the_refresh_carries_them() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured("singlesig_rot")? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "singlesig_rot");
    shared(&captured, "rot")?;

    assert_ne!(captured.local_after.signing_key, captured.local_before.signing_key);
    assert_ne!(captured.local_after.next_digest, captured.local_before.next_digest);
    assert_eq!(captured.refreshed.signing_key, captured.local_after.signing_key);
    assert_eq!(captured.refreshed.next_digest, captured.local_after.next_digest);

    let event: Value = serde_json::from_str(&captured.derived_event)?;
    assert_eq!(event.get("t").and_then(Value::as_str), Some("rot"));
    Ok(())
}

#[test]
fn the_interaction_twin_keeps_the_keys_and_anchors_the_empty_object() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured("singlesig_ixn")? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "singlesig_ixn");
    shared(&captured, "ixn")?;

    assert_eq!(captured.local_after.signing_key, captured.local_before.signing_key);
    assert_eq!(captured.local_after.next_digest, captured.local_before.next_digest);
    assert_eq!(captured.refreshed.signing_key, captured.local_after.signing_key);

    let event: Value = serde_json::from_str(&captured.derived_event)?;
    assert_eq!(event.get("t").and_then(Value::as_str), Some("ixn"));
    let anchors = event
        .get("a")
        .and_then(Value::as_array)
        .ok_or("the interaction carries no anchor list")?;
    match anchors.as_slice() {
        [Value::Object(map)] if map.is_empty() => {}
        other => return Err(format!("expected exactly [{{}}] anchored, found {other:?}").into()),
    }
    Ok(())
}
