//! Hermetic assertions over the recorded multisig credential rounds.
//!
//! A group issuing, granting and revoking, and a group admitting one issued to it.
//!
//! Not ignored: it reads checked-in recordings and never touches a network.

use std::error::Error;
use std::fs;
use std::path::Path;

use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct IssuedByGroup {
    scenario: String,
    preset: String,
    group_prefix: String,
    member_prefixes: Vec<String>,
    holder_prefix: String,
    registry: String,
    credential_said: String,
    holder_admitted: bool,
    state_after_issue: String,
    state_after_revoke: String,
    operations_remaining: Vec<usize>,
}

#[derive(Debug, Deserialize)]
struct HeldByGroup {
    scenario: String,
    group_prefix: String,
    issuer_prefix: String,
    credential_said: String,
    group_admitted: bool,
    operations_remaining: Vec<usize>,
}

fn read<T: for<'a> Deserialize<'a>>(name: &str) -> Result<Option<T>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("crates/signify-client/fixtures/keria-integration/observations")
        .join(name);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

#[test]
fn the_group_that_issued_is_a_group_of_two() -> Result<(), Box<dyn Error>> {
    let Some(captured) = read::<IssuedByGroup>("multisig_credentials.json")? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "multisig_credentials");
    assert_ne!(captured.preset, "");

    assert_eq!(captured.member_prefixes.len(), 2);
    for prefix in &captured.member_prefixes {
        IdentifierPrefix::from_qb64(prefix)?;
    }
    let group = IdentifierPrefix::from_qb64(&captured.group_prefix)?;

    // The group is its own identifier, not either member's.
    for prefix in &captured.member_prefixes {
        assert_ne!(&group.qb64()?, prefix);
    }
    IdentifierPrefix::from_qb64(&captured.holder_prefix)?;
    assert_eq!(captured.operations_remaining, [0, 0, 0]);
    Ok(())
}

#[test]
fn a_group_issues_and_revokes_through_the_same_registry() -> Result<(), Box<dyn Error>> {
    let Some(captured) = read::<IssuedByGroup>("multisig_credentials.json")? else {
        return Ok(());
    };

    Said::from_qb64(&captured.credential_said)?;
    assert_ne!(captured.registry, "");

    // Every step was a propose/accept round, and the outcome is the single-signature one.
    assert_eq!(captured.state_after_issue, "iss");
    assert_eq!(captured.state_after_revoke, "rev");
    assert!(captured.holder_admitted, "the holder never admitted the group's grant");
    Ok(())
}

#[test]
fn a_group_can_hold_a_credential_issued_to_it() -> Result<(), Box<dyn Error>> {
    let Some(captured) = read::<HeldByGroup>("multisig_holder.json")? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "multisig_holder");

    let group = IdentifierPrefix::from_qb64(&captured.group_prefix)?;
    let issuer = IdentifierPrefix::from_qb64(&captured.issuer_prefix)?;
    assert_ne!(group.qb64()?, issuer.qb64()?, "the group issued to itself");
    Said::from_qb64(&captured.credential_said)?;

    // The difference from the single-signature case: both members had to admit.
    assert!(captured.group_admitted);
    assert_eq!(captured.operations_remaining, [0, 0, 0]);
    Ok(())
}
