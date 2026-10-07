//! Hermetic assertions over the recorded multisig inceptions.
//!
//! Two groups, witnessed and witnessless, including the listing upstream comments out against `keria#189`.

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
    rounds: Vec<GroupRound>,
    member1_operations_remaining: usize,
    member2_operations_remaining: usize,
    member1_transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct GroupRound {
    group_name: String,
    witnessed: bool,
    witness_threshold: u32,
    proposer_prefix: String,
    acceptor_prefix: String,
    signing_aids: Vec<String>,
    rotation_aids: Vec<String>,
    members_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Observation {
    method: String,
    resource: String,
    request_body: Option<String>,
    status: u16,
}

fn captured() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/observations/multisig_inception.json");
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
    assert_eq!(captured.scenario, "multisig_inception");
    assert_ne!(captured.preset, "");
    assert!(!captured.member1_transcript.is_empty());

    let [witnessed, witnessless] = captured.rounds.as_slice() else {
        return Err("the recording does not hold exactly two rounds".into());
    };
    assert_eq!(witnessed.group_name, "multisig");
    assert!(witnessed.witnessed);
    assert_eq!(witnessed.witness_threshold, 2);
    assert_eq!(witnessless.group_name, "multisig2");
    assert!(!witnessless.witnessed);
    assert_eq!(witnessless.witness_threshold, 0);

    IdentifierPrefix::from_qb64(&captured.member1_prefix)?;
    IdentifierPrefix::from_qb64(&captured.member2_prefix)?;
    IdentifierPrefix::from_qb64(&witnessed.proposer_prefix)?;
    IdentifierPrefix::from_qb64(&witnessless.proposer_prefix)?;
    assert_ne!(witnessed.proposer_prefix, witnessless.proposer_prefix);
    assert_eq!(captured.member1_operations_remaining, 0);
    assert_eq!(captured.member2_operations_remaining, 0);
    Ok(())
}

#[test]
fn both_rounds_agree_on_the_group_and_its_members() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    for round in &captured.rounds {
        assert_eq!(
            round.proposer_prefix, round.acceptor_prefix,
            "{}: the members disagree",
            round.group_name
        );

        assert_eq!(
            round.signing_aids,
            [captured.member1_prefix.clone(), captured.member2_prefix.clone()],
            "{}: signing members",
            round.group_name
        );
        assert_eq!(
            round.rotation_aids, round.signing_aids,
            "{}: rotation members",
            round.group_name
        );
    }
    Ok(())
}

#[test]
fn the_witnessless_members_listing_works_despite_upstreams_guard() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    let witnessless = captured
        .rounds
        .iter()
        .find(|round| !round.witnessed)
        .ok_or("no witnessless round recorded")?;
    assert_eq!(
        witnessless.members_error, None,
        "the witnessless members listing failed, so upstream's keria#189 guard is live again"
    );
    assert_ne!(witnessless.signing_aids, [] as [String; 0]);
    Ok(())
}

#[test]
fn both_proposals_travelled_on_the_inception_route() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    let creations = captured
        .member1_transcript
        .iter()
        .filter(|observation| {
            observation.method == "POST"
                && observation.resource == "/identifiers"
                && (200..300).contains(&observation.status)
                && observation
                    .request_body
                    .as_deref()
                    .is_some_and(|body| body.contains("\"group\""))
        })
        .count();
    assert_eq!(creations, 2, "expected two group creations");
    let proposals = captured
        .member1_transcript
        .iter()
        .filter(|observation| {
            observation.method == "POST"
                && observation.resource == "/identifiers/member1/exchanges"
                && (200..300).contains(&observation.status)
                && observation
                    .request_body
                    .as_deref()
                    .is_some_and(|body| body.contains("/multisig/icp"))
        })
        .count();
    assert_eq!(proposals, 2, "expected two inception proposals");
    Ok(())
}
