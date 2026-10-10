//! Wave 13 — multisig inception: two groups, witnessed and witnessless.
//!
//! Incepts two groups by two members: witnessed at threshold two, and witnessless at zero.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave13_multisig_inception -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::threshold::SigningThreshold;
use serde::Serialize;
use signify_client::client::ConnectedClient;
use signify_client::multisig::GroupInceptionRequest;
use signify_keria_systest::singlesig::create_identifier;
use signify_keria_systest::{
    Environment, agent_oobi, await_notification, connect, progress, record, recorder, resolve_oobi, wait_and_delete,
    witness_prefixes,
};

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    member1_prefix: String,
    member2_prefix: String,
    rounds: Vec<GroupRound>,
    member1_operations_remaining: usize,
    member2_operations_remaining: usize,
    member1_transcript: Vec<signify_keria_systest::Observation>,
}

async fn group_round(
    member1: &ConnectedClient,
    member2: &ConnectedClient,
    participants: &[IdentifierPrefix],
    group_name: &str,
    witnesses: &[IdentifierPrefix],
    witness_threshold: u32,
) -> Result<GroupRound, Box<dyn Error>> {
    progress(&format!(
        "{group_name}: proposing at witness threshold {witness_threshold}"
    ));
    let proposed = member1
        .multisig()
        .propose_inception(&GroupInceptionRequest {
            group_name,
            local_member: "member1",
            participants,
            signing_threshold: Some(SigningThreshold::numeric(2)),
            next_threshold: Some(SigningThreshold::numeric(2)),
            witnesses,
            witness_threshold,
            delegator: None,
            timestamp: signify_keria_systest::now()?,
        })
        .await?;
    wait_and_delete(member1, &proposed.proposal().operation()?.name).await?;

    let said = await_notification(member2, "/multisig/icp").await?;
    progress(&format!("{group_name}: accepting"));
    let accepted = member2
        .multisig()
        .accept_inception(group_name, "member2", &said, signify_keria_systest::now()?)
        .await?;
    wait_and_delete(member2, &accepted.proposal().operation()?.name).await?;
    wait_and_delete(member1, &proposed.creation().operation()?.name).await?;
    wait_and_delete(member2, &accepted.creation().operation()?.name).await?;

    let stored1 = member1.identifiers().get(group_name).await?;
    let stored2 = member2.identifiers().get(group_name).await?;

    let (signing_aids, rotation_aids, members_error) = match member1.identifiers().members(group_name).await {
        Ok(listing) => (
            listing.signing.iter().map(|record| record.aid.clone()).collect(),
            listing.rotation.iter().map(|record| record.aid.clone()).collect(),
            None,
        ),
        Err(error) => (Vec::new(), Vec::new(), Some(error.to_string())),
    };

    Ok(GroupRound {
        group_name: group_name.to_owned(),
        witnessed: !witnesses.is_empty(),
        witness_threshold,
        proposer_prefix: stored1.common.prefix.clone(),
        acceptor_prefix: stored2.common.prefix.clone(),
        signing_aids,
        rotation_aids,
        members_error,
    })
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn two_groups_incept_witnessed_and_witnessless() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let member1_transcript = recorder("multisig_member1")?;
    progress("connecting member1's client");
    let member1 = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &member1_transcript,
    )
    .await?;
    let member2_transcript = recorder("multisig_member2")?;
    progress("connecting member2's client");
    let member2 = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &member2_transcript,
    )
    .await?;

    let aid1 = create_identifier(&member1, "member1", &witness_prefixes(&environment)?).await?;
    let aid2 = create_identifier(&member2, "member2", &witness_prefixes(&environment)?).await?;
    resolve_oobi(&member1, &agent_oobi(&member2, "member2").await?, "member2").await?;
    resolve_oobi(&member2, &agent_oobi(&member1, "member1").await?, "member1").await?;
    let participants = [aid1.clone(), aid2.clone()];

    let witnesses: Vec<IdentifierPrefix> = environment
        .witness_prefixes
        .iter()
        .map(|prefix| IdentifierPrefix::from_qb64(prefix))
        .collect::<Result<_, _>>()?;
    let witnessed_round = group_round(&member1, &member2, &participants, "multisig", &witnesses, 2).await?;

    let witnessless_round = group_round(&member1, &member2, &participants, "multisig2", &[], 0).await?;

    let captured = Captured {
        scenario: "multisig_inception",
        preset: environment.preset.to_string(),
        member1_prefix: aid1.qb64()?,
        member2_prefix: aid2.qb64()?,
        rounds: vec![witnessed_round, witnessless_round],
        member1_operations_remaining: member1.operations().list(None).await?.len(),
        member2_operations_remaining: member2.operations().list(None).await?.len(),
        member1_transcript: member1_transcript.observations(),
    };
    if record("observations/multisig_inception.json", &captured)? {
        progress("recorded observations/multisig_inception.json");
    } else {
        progress("not a recording run, nothing written");
    }

    for round in &captured.rounds {
        assert_eq!(
            round.proposer_prefix, round.acceptor_prefix,
            "{}: the two members derived different groups",
            round.group_name
        );
    }
    let first = captured.rounds.first().ok_or("no witnessed round recorded")?;
    assert_eq!(first.signing_aids, [aid1.qb64()?, aid2.qb64()?]);
    assert_eq!(first.rotation_aids, [aid1.qb64()?, aid2.qb64()?]);
    assert_eq!(
        captured.member1_operations_remaining, 0,
        "member1 left operations behind"
    );
    assert_eq!(
        captured.member2_operations_remaining, 0,
        "member2 left operations behind"
    );
    Ok(())
}
