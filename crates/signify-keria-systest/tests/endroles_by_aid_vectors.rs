//! Hermetic assertions over the recorded end-roles-by-AID reads.
//!
//! A group's end-role round, then a third party's five reads naming exactly both members' agents.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use signify_keri::prefix::IdentifierPrefix;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    member1_prefix: String,
    member2_prefix: String,
    group_prefix: String,
    agent_eids: Vec<String>,
    all_roles: Vec<RecordedRole>,
    agent_roles: Vec<RecordedRole>,
    mailbox_roles_len: usize,
    unknown_prefix: String,
    unknown_roles_len: usize,
    alice_prefix: String,
    alice_roles: Vec<RecordedRole>,
    member1_operations_remaining: usize,
    member2_operations_remaining: usize,
    alice_operations_remaining: usize,
    alice_transcript: Vec<Observation>,
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
        .join("fixtures/keria-integration/observations/endroles_by_aid.json");
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
    assert_eq!(captured.scenario, "endroles_by_aid");
    assert!(!captured.preset.is_empty());
    assert!(!captured.alice_transcript.is_empty());

    let prefixes = [
        &captured.member1_prefix,
        &captured.member2_prefix,
        &captured.group_prefix,
        &captured.alice_prefix,
    ];
    for prefix in prefixes {
        IdentifierPrefix::from_qb64(prefix)?;
    }
    for (index, left) in prefixes.iter().enumerate() {
        for right in prefixes.iter().skip(index + 1) {
            assert_ne!(left, right);
        }
    }
    assert_eq!(captured.agent_eids.len(), 2);

    assert_eq!(captured.member1_operations_remaining, 0);
    assert_eq!(captured.member2_operations_remaining, 0);
    assert_eq!(captured.alice_operations_remaining, 0);
    Ok(())
}

#[test]
fn the_groups_end_roles_name_both_agents_and_nothing_else() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    for listing in [&captured.all_roles, &captured.agent_roles] {
        assert!(!listing.is_empty());
        for role in &**listing {
            assert_eq!(role.cid, captured.group_prefix);
            assert_eq!(role.role, "agent");
        }
        let mut eids: Vec<&str> = listing.iter().map(|role| role.eid.as_str()).collect();
        eids.sort_unstable();
        let mut expected: Vec<&str> = captured.agent_eids.iter().map(String::as_str).collect();
        expected.sort_unstable();
        assert_eq!(eids, expected);
    }
    Ok(())
}

#[test]
fn a_role_nobody_granted_and_an_identifier_nobody_owns_answer_empty() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    assert_eq!(captured.mailbox_roles_len, 0);
    IdentifierPrefix::from_qb64(&captured.unknown_prefix)?;
    assert_eq!(captured.unknown_roles_len, 0);
    Ok(())
}

#[test]
fn alices_own_identifier_answers_exactly_her_agent() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    let role = match captured.alice_roles.as_slice() {
        [role] => role,
        other => return Err(format!("expected one authorisation, found {}", other.len()).into()),
    };
    assert_eq!(role.cid, captured.alice_prefix);
    assert_eq!(role.role, "agent");
    IdentifierPrefix::from_qb64(&role.eid)?;
    Ok(())
}

#[test]
fn every_read_went_through_the_end_roles_resource() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    let expected = [
        format!("/endroles/{}", captured.group_prefix),
        format!("/endroles/{}/agent", captured.group_prefix),
        format!("/endroles/{}/mailbox", captured.group_prefix),
        format!("/endroles/{}", captured.unknown_prefix),
        format!("/endroles/{}", captured.alice_prefix),
    ];
    for resource in &expected {
        assert!(
            captured
                .alice_transcript
                .iter()
                .any(|observation| observation.method == "GET"
                    && &observation.resource == resource
                    && (200..300).contains(&observation.status)),
            "no successful read of {resource} is recorded"
        );
    }
    Ok(())
}
