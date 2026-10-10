//! Hermetic assertions over the recorded endpoint smoke coverage.
//!
//! No agent role before the grant, the exact triple after, and the OOBI a self-controlled mailbox derives.

use std::error::Error;
use std::fs;
use std::path::Path;

use keri_protocol::prefix::IdentifierPrefix;
use serde::Deserialize;

const MAILBOX_URL: &str = "https://mymailbox.com";

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    cid: String,
    agent_prefix: String,
    agent_roles_before: usize,
    agent_roles: Vec<RecordedRole>,
    mailbox_roles: Vec<RecordedRole>,
    mailbox_oobi: String,
    operations_remaining: usize,
    transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct RecordedRole {
    cid: String,
    role: String,
    eid: String,
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
        .join("fixtures/keria-integration/observations/endpoint_smoke.json");
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
    assert_eq!(captured.scenario, "endpoint_smoke");
    assert_ne!(captured.preset, "");
    assert!(!captured.transcript.is_empty(), "the recording kept no transcript");
    assert_eq!(captured.operations_remaining, 0);

    IdentifierPrefix::from_qb64(&captured.cid)?;
    IdentifierPrefix::from_qb64(&captured.agent_prefix)?;
    assert_ne!(captured.cid, captured.agent_prefix);
    Ok(())
}

#[test]
fn the_agent_role_goes_from_none_to_exactly_one() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    assert_eq!(captured.agent_roles_before, 0);

    let role = match captured.agent_roles.as_slice() {
        [role] => role,
        other => return Err(format!("expected one agent authorisation, found {}", other.len()).into()),
    };
    assert_eq!(role.cid, captured.cid);
    assert_eq!(role.role, "agent");
    assert_eq!(role.eid, captured.agent_prefix);
    Ok(())
}

#[test]
fn the_mailbox_role_names_the_identifier_itself() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    let role = match captured.mailbox_roles.as_slice() {
        [role] => role,
        other => return Err(format!("expected one mailbox authorisation, found {}", other.len()).into()),
    };
    assert_eq!(role.cid, captured.cid);
    assert_eq!(role.role, "mailbox");
    assert_eq!(role.eid, captured.cid);
    Ok(())
}

#[test]
fn the_mailbox_oobi_joins_the_location_to_the_role() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    assert_eq!(
        captured.mailbox_oobi,
        format!("{MAILBOX_URL}/oobi/{}/mailbox/{}", captured.cid, captured.cid)
    );
    Ok(())
}

#[test]
fn the_reads_went_through_the_end_roles_resource() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    for role in ["agent", "mailbox"] {
        let resource = format!("/endroles/{}/{role}", captured.cid);
        assert!(
            captured.transcript.iter().any(|observation| observation.method == "GET"
                && observation.resource == resource
                && (200..300).contains(&observation.status)),
            "no successful read of {resource} is recorded"
        );
    }
    Ok(())
}
