//! Hermetic assertions over the recorded multisig join.
//!
//! A third member committed then seated, rebuilding the rotation he was shown and comparing SAIDs first.

use std::error::Error;
use std::fs;
use std::path::Path;

use keri_protocol::prefix::IdentifierPrefix;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    member_prefixes: Vec<String>,
    group_prefix: String,
    after_first_rotation_keys: Vec<String>,
    after_first_rotation_digests: Vec<String>,
    shown_rotation_said: String,
    rebuilt_rotation_said: String,
    joined_keys: Vec<String>,
    joined_digests: Vec<String>,
    operations_remaining: Vec<usize>,
    member3_transcript: Vec<Observation>,
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
        .join("fixtures/keria-integration/observations/multisig_join.json");
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
    assert_eq!(captured.scenario, "multisig_join");
    assert_ne!(captured.preset, "");
    assert!(!captured.member3_transcript.is_empty());
    assert_eq!(captured.member_prefixes.len(), 3);
    for prefix in &captured.member_prefixes {
        IdentifierPrefix::from_qb64(prefix)?;
    }
    IdentifierPrefix::from_qb64(&captured.group_prefix)?;
    assert_eq!(captured.operations_remaining, [0, 0, 0]);
    Ok(())
}

#[test]
fn the_first_rotation_commits_the_incoming_member_before_admitting_him() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    assert_eq!(captured.after_first_rotation_keys.len(), 2);
    assert_eq!(captured.after_first_rotation_digests.len(), 3);
    Ok(())
}

#[test]
fn the_join_rebuilt_exactly_the_shown_rotation() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    assert_eq!(captured.shown_rotation_said, captured.rebuilt_rotation_said);

    assert_eq!(captured.joined_keys.len(), 3);
    assert_eq!(captured.joined_digests.len(), 3);

    assert!(
        captured.member3_transcript.iter().any(|observation| {
            observation.method == "POST"
                && observation.resource == "/identifiers/multisigGroup/multisig/join"
                && (200..300).contains(&observation.status)
        }),
        "the join was never submitted"
    );
    Ok(())
}
