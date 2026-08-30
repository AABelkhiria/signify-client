//! Hermetic assertions over the recorded multisig join.
//!
//! Wave 14 drove the spine of `test-integration/multisig-join.test.ts` against a live
//! deployment: a 1-of-1 group, a rotation that commits a third member into rotation authority,
//! and a second rotation that brings him into the signing set — which he joins by **rebuilding**
//! the shown rotation from the proposal's member lists and his own queried key states, comparing
//! the SAID he built with the SAID he was shown, and only then submitting his signature through
//! `groups().join`. Upstream's member3 signs the shown bytes unexamined, which Roadmap 8.4
//! recorded; the recording proves the checked path reaches the same wire outcome.
//!
//! Not ignored: it reads a checked-in recording and never touches a network.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use signify_keri::prefix::IdentifierPrefix;

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
    assert!(!captured.preset.is_empty());
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

    // KERI's own two-step admission: the incoming member first appears among the *next* digests
    // — two signers, three commitments — and only the following rotation seats him.
    assert_eq!(captured.after_first_rotation_keys.len(), 2);
    assert_eq!(captured.after_first_rotation_digests.len(), 3);
    Ok(())
}

#[test]
fn the_join_rebuilt_exactly_the_shown_rotation() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The port's whole difference from upstream's join: the rotation is rebuilt from the
    // proposal's member lists and the joiner's own queried states, and the SAIDs must agree —
    // where upstream's member3 signs the shown bytes unexamined (Roadmap 8.4's finding).
    assert_eq!(captured.shown_rotation_said, captured.rebuilt_rotation_said);

    // And after the join the group seats all three, with three fresh commitments.
    assert_eq!(captured.joined_keys.len(), 3);
    assert_eq!(captured.joined_digests.len(), 3);

    // The join travelled through Roadmap 8.2's endpoint, proven from member3's transcript.
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
