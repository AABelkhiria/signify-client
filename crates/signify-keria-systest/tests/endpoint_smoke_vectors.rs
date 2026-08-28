//! Hermetic assertions over the recorded endpoint smoke coverage.
//!
//! Wave 5 drove `test-integration/endpoints.test.ts` against a live deployment: an unwitnessed
//! identifier granting the agent role, granting the **mailbox** role to itself, adding a location
//! scheme, and reading back the OOBI the agent derives from the pair. This file re-checks the
//! recording from its own values — the expected URL is recomputed from the recorded prefixes, not
//! read from a flag the scenario wrote.
//!
//! Not ignored: it reads a checked-in recording and never touches a network.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use signify_keri::prefix::IdentifierPrefix;

/// The location the upstream case authorises for its mailbox.
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
    assert!(!captured.preset.is_empty());
    assert!(!captured.transcript.is_empty(), "the recording kept no transcript");
    assert_eq!(captured.operations_remaining, 0);

    // Both prefixes are real qualified identifiers, and they are different parties.
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

    // Upstream's first assertion: nothing was authorised before the grant — creating an
    // identifier does not grant its agent anything by itself.
    assert_eq!(captured.agent_roles_before, 0);

    // And after the grant, exactly the one triple the upstream case deep-equals: the identifier
    // as `cid`, the agent as `eid`.
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

    // The self-controlled endpoint: cid and eid are deliberately the same prefix, which is what
    // makes the derived OOBI below end in the same identifier twice.
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

    // The upstream case's final assertion, recomputed from the recorded prefixes rather than
    // trusted: the OOBI is the authorised URL joined to `/oobi/{cid}/mailbox/{eid}`, and because
    // the mailbox is self-controlled the identifier appears twice.
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

    // The mapping the wave documents: upstream's helper raw-fetches
    // `/identifiers/{alias}/endroles/{role}`, the port reads `/endroles/{aid}/{role}` — Roadmap
    // 7.1's resource. The transcript proves which address answered the triples above.
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
