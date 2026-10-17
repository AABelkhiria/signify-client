//! Hermetic assertions over the recorded passcode rotation (wave 17).
//!
//! Two rotations and a reconnection after each, re-verified from the recording's own bytes.
//!
//! Not ignored: it reads checked-in recordings and never touches a network. Until a deployment
//! that checks the rotation's signature correctly has been recorded, the observation does not exist
//! and every assertion here is skipped; the local deployment cannot record it, because its agent
//! endpoint inverts the rotation's signature check.

use std::error::Error;
use std::fs;
use std::path::Path;

use keri_protocol::serialization::SerializedEvent;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    controller_prefix: String,
    connected_sequence_number: String,
    first: Rotation,
    after_first: Reconnection,
    second: Rotation,
    after_second: Reconnection,
    transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct Rotation {
    status: u16,
    sequence_number: String,
    said: String,
    prior: String,
    said_before: String,
    same_session_read: bool,
}

#[derive(Debug, Deserialize)]
struct Reconnection {
    sequence_number: String,
    said: String,
    identifier_read: bool,
    keeper_opened: bool,
}

#[derive(Debug, Deserialize)]
struct Observation {
    method: String,
    resource: String,
    request_headers: Vec<(String, String)>,
    request_body: Option<String>,
    status: u16,
    response_body: Option<String>,
}

fn read() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/observations/passcode_rotation.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

/// The rotation events the recording's `PUT /agent/{prefix}` requests carried, in order, as the
/// exact bytes sent — a JSON value would re-sort the labels a SAID commits to.
fn sent_rotations(captured: &Captured) -> Result<Vec<SerializedEvent>, Box<dyn Error>> {
    let path = format!("/agent/{}", captured.controller_prefix);
    let mut rotations = Vec::new();
    for observation in &captured.transcript {
        if observation.method != "PUT" || observation.resource != path {
            continue;
        }
        let body = observation
            .request_body
            .as_deref()
            .ok_or("a rotation carried no body")?;
        let start = body.find(r#""rot":"#).ok_or("a rotation request carried no rot")? + r#""rot":"#.len();
        let rest = body.get(start..).ok_or("the rotation body is truncated")?;
        let end = rest.find(r#","sigs":"#).ok_or("a rotation request carried no sigs")?;
        let raw = rest.get(..end).ok_or("the rotation body is truncated")?;
        rotations.push(SerializedEvent::parse(raw.as_bytes())?);
    }
    Ok(rotations)
}

#[test]
fn both_rotations_were_accepted_and_follow_the_log() -> Result<(), Box<dyn Error>> {
    let Some(captured) = read()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "passcode_rotation");
    assert_eq!(captured.connected_sequence_number, "1");

    for rotation in [&captured.first, &captured.second] {
        assert!(
            (200..300).contains(&rotation.status),
            "a rotation answered {}",
            rotation.status
        );
        assert_eq!(rotation.prior, rotation.said_before);
        assert!(rotation.same_session_read);
    }
    assert_eq!(captured.first.sequence_number, "2");
    assert_eq!(captured.second.sequence_number, "3");
    assert_eq!(captured.second.prior, captured.first.said);

    // The events on the wire say the same, and each one's SAID is its own.
    let sent = sent_rotations(&captured)?;
    assert_eq!(sent.len(), 2, "the recording holds {} rotation requests", sent.len());
    for (event, rotation) in sent.iter().zip([&captured.first, &captured.second]) {
        assert_eq!(event.sad().get_text("t"), Some("rot"));
        assert_eq!(event.sad().get_text("s"), Some(rotation.sequence_number.as_str()));
        assert_eq!(event.sad().get_text("p"), Some(rotation.prior.as_str()));
        assert_eq!(event.said(), Some(rotation.said.as_str()));
    }
    Ok(())
}

#[test]
fn every_rotation_request_was_signed() -> Result<(), Box<dyn Error>> {
    let Some(captured) = read()? else {
        return Ok(());
    };
    let path = format!("/agent/{}", captured.controller_prefix);
    let signed: Vec<bool> = captured
        .transcript
        .iter()
        .filter(|observation| observation.method == "PUT" && observation.resource == path)
        .map(|observation| {
            observation
                .request_headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("signature-input"))
        })
        .collect();
    assert_eq!(signed, [true, true]);
    Ok(())
}

#[test]
fn each_new_passcode_reconnects_where_the_rotation_left_the_log() -> Result<(), Box<dyn Error>> {
    let Some(captured) = read()? else {
        return Ok(());
    };
    assert_eq!(captured.after_first.sequence_number, "2");
    assert_eq!(captured.after_first.said, captured.first.said);
    assert_eq!(captured.after_second.sequence_number, "3");
    assert_eq!(captured.after_second.said, captured.second.said);
    for reconnection in [&captured.after_first, &captured.after_second] {
        assert!(reconnection.identifier_read && reconnection.keeper_opened);
    }

    // A reconnection reads its state unsigned; the agent reports the rotation as the latest
    // establishment event and no rotation index.
    let path = format!("/agent/{}", captured.controller_prefix);
    let states: Vec<&str> = captured
        .transcript
        .iter()
        .filter(|observation| observation.method == "GET" && observation.resource == path && observation.status == 200)
        .filter_map(|observation| observation.response_body.as_deref())
        .collect();
    let rotated = states
        .iter()
        .filter(|body| body.contains(r#""t": "rot""#) || body.contains(r#""t":"rot""#))
        .count();
    assert!(rotated >= 2, "{rotated} state reads reported a rotation");
    assert!(states.iter().all(|body| !body.contains(r#""ridx""#)));
    Ok(())
}
