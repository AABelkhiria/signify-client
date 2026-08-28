//! Hermetic assertions over the recorded single-signature rotation and interaction.
//!
//! Wave 8 drove the twin scenarios `singlesig-rot.test.ts` and `singlesig-ixn.test.ts` against a
//! live deployment. Each advances a witnessed identifier's log by one event and observes the same
//! divergence: the owner's key state moves at once, the observer's stays one sequence behind
//! until it refreshes with `keyStates().query` at the new sequence — spelled in **hexadecimal**,
//! wave 1's answer. This file re-checks both recordings from their own bytes.
//!
//! Not ignored: it reads checked-in recordings and never touches a network.

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

/// The claims both twins share, checked from one recording.
fn shared(captured: &Captured, kind: &str) -> Result<(), Box<dyn Error>> {
    assert!(!captured.preset.is_empty());

    // The contact resolution answered the identifier's own prefix.
    assert_eq!(captured.contact_resolved, captured.prefix);

    // Sequences: local and remote agree before; the event increments the local one; the remote
    // stays where it was until the refresh catches it up.
    assert_eq!(captured.local_before.sequence, captured.remote_before_sequence);
    let before = u64::from_str_radix(&captured.local_before.sequence, 16)?;
    let after = u64::from_str_radix(&captured.local_after.sequence, 16)?;
    assert_eq!(after, before + 1, "{kind}: the local sequence did not increment");
    assert_eq!(captured.remote_stale_sequence, captured.local_before.sequence);
    assert_eq!(captured.refreshed.sequence, captured.local_after.sequence);

    // The refresh was asked in hexadecimal — wave 1's answer — and the exact text reached the
    // wire, proven from the observer's transcript rather than the flag.
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

    // The event verifies over its derived bytes, and the agent echoed the same document.
    let sad = Sad::from_json_bytes(captured.derived_event.as_bytes())?;
    Said::from_qb64(&captured.derived_said)?.verify(&sad, "d", SaidVerification::strict())?;
    let echoed: Value = serde_json::from_str(&captured.agent_event)?;
    assert_eq!(
        echoed.get("d").and_then(Value::as_str),
        Some(captured.derived_said.as_str()),
        "{kind}: the agent echoed a different event"
    );

    // The upstream postcondition, on both clients.
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

    // The rotation moved both key fields, and the refreshed remote state carries exactly the new
    // ones — which is the point of the refresh.
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

    // An interaction changes no keys.
    assert_eq!(captured.local_after.signing_key, captured.local_before.signing_key);
    assert_eq!(captured.local_after.next_digest, captured.local_before.next_digest);
    assert_eq!(captured.refreshed.signing_key, captured.local_after.signing_key);

    // And its anchor is upstream's own `{}` — representable as a `Sad`, so unlike the bare-string
    // anchors of the salty and randy waves this one reproduces upstream exactly: `"a": [{}]`.
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
