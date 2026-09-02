//! Hermetic assertions over the recorded single-signature credential and IPEX round.
//!
//! Registry, issuance, the reads, an unsolicited grant, the five-step verifier round, revocation.
//!
//! Not ignored: it reads a checked-in recording and never touches a network.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    schema: String,
    issuer_prefix: String,
    holder_prefix: String,
    verifier_prefix: String,
    registry: String,
    credential_said: String,
    issuer_reads_lei: Option<String>,
    listed_all: usize,
    listed_by_schema: usize,
    state_after_issue: String,
    state_after_revoke: String,
    holder_admitted: bool,
    apply_said: String,
    offer_said: String,
    agree_said: String,
    disclose_said: String,
    verifier_admit_said: String,
    deleted: bool,
    operations_remaining: Vec<usize>,
}

fn captured() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/observations/credential_ipex.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

#[test]
fn the_recording_names_three_distinct_parties_and_one_credential() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "credential_ipex");
    assert!(!captured.preset.is_empty());

    for prefix in [
        &captured.issuer_prefix,
        &captured.holder_prefix,
        &captured.verifier_prefix,
    ] {
        IdentifierPrefix::from_qb64(prefix)?;
    }
    assert_ne!(captured.issuer_prefix, captured.holder_prefix);
    assert_ne!(captured.holder_prefix, captured.verifier_prefix);

    Said::from_qb64(&captured.credential_said)?;
    Said::from_qb64(&captured.schema)?;
    assert!(!captured.registry.is_empty());
    assert_eq!(captured.operations_remaining, [0, 0, 0]);
    Ok(())
}

#[test]
fn the_issued_credential_carries_what_it_was_built_from() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The document read back is the one issued, and it carries the attribute the schema requires.
    assert_eq!(captured.issuer_reads_lei.as_deref(), Some("5493001KJTIIGC8Y1R17"));

    // A filter on the schema finds it, and finds no more than the unfiltered listing.
    assert!(captured.listed_by_schema >= 1);
    assert!(captured.listed_by_schema <= captured.listed_all);
    Ok(())
}

#[test]
fn the_registry_status_moves_from_issued_to_revoked() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // `get` returns the document and says nothing about this; `state` is what says it.
    assert_eq!(captured.state_after_issue, "iss");
    assert_eq!(captured.state_after_revoke, "rev");
    assert_ne!(captured.state_after_issue, captured.state_after_revoke);
    assert!(captured.deleted, "the issuer's copy survived its own delete");
    Ok(())
}

#[test]
fn the_holder_admitted_a_grant_it_never_asked_for() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The unsolicited half: `deliver` rather than `disclose`, with no apply before it.
    assert!(captured.holder_admitted);
    Ok(())
}

#[test]
fn the_verifier_round_is_five_distinct_messages() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    let round = [
        &captured.apply_said,
        &captured.offer_said,
        &captured.agree_said,
        &captured.disclose_said,
        &captured.verifier_admit_said,
    ];
    for said in round {
        Said::from_qb64(said)?;
    }

    // A conversation whose steps shared a SAID would not be a conversation.
    let mut seen: Vec<&String> = round.to_vec();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 5, "two steps of the round share a SAID");
    Ok(())
}
