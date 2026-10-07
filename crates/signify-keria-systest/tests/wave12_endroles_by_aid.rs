//! Wave 12 — end roles by AID: a third party reading a group's authorisations.
//!
//! Incepts a two-member group, runs the end-role round, and has a third party read it back.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave12_endroles_by_aid -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keria_types::api::Role;
use serde::Serialize;
use signify_client::client::ConnectedClient;
use signify_client::multisig::GroupInceptionRequest;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::threshold::SigningThreshold;
use signify_keria_systest::group::authorise_agents;
use signify_keria_systest::singlesig::create_identifier;
use signify_keria_systest::{
    Environment, agent_oobi, await_notification, connect, progress, record, recorder, resolve_oobi, wait_and_delete,
    witness_prefixes,
};

const GROUP_NAME: &str = "endroles-byaid-group";

#[derive(Debug, Serialize)]
struct RecordedRole {
    cid: String,
    role: String,
    eid: String,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
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
    alice_transcript: Vec<signify_keria_systest::Observation>,
}

async fn three_clients(
    environment: &Environment,
    transcripts: &[std::sync::Arc<signify_keria_systest::Recorder>; 3],
) -> Result<(ConnectedClient, ConnectedClient, ConnectedClient), Box<dyn Error>> {
    progress("connecting the three clients");
    let member1 = connect(
        environment,
        signify_client::random::random_passcode()?.expose(),
        &transcripts[0],
    )
    .await?;
    let member2 = connect(
        environment,
        signify_client::random::random_passcode()?.expose(),
        &transcripts[1],
    )
    .await?;
    let alice = connect(
        environment,
        signify_client::random::random_passcode()?.expose(),
        &transcripts[2],
    )
    .await?;
    Ok((member1, member2, alice))
}

async fn roles(
    client: &ConnectedClient,
    identifier: &IdentifierPrefix,
    role: Option<&Role>,
) -> Result<Vec<RecordedRole>, Box<dyn Error>> {
    Ok(client
        .oobis()
        .end_roles(identifier, role)
        .await?
        .into_iter()
        .map(|entry| RecordedRole {
            cid: entry.cid,
            role: entry.role.as_str().to_owned(),
            eid: entry.eid,
        })
        .collect())
}

async fn incept_group(
    member1: &ConnectedClient,
    member2: &ConnectedClient,
    aid1: &IdentifierPrefix,
    aid2: &IdentifierPrefix,
    environment: &Environment,
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let witnesses: Vec<IdentifierPrefix> = environment
        .witness_prefixes
        .iter()
        .map(|prefix| IdentifierPrefix::from_qb64(prefix))
        .collect::<Result<_, _>>()?;
    let participants = [aid1.clone(), aid2.clone()];
    progress("member1: proposing the group inception");
    let proposed = member1
        .multisig()
        .propose_inception(&GroupInceptionRequest {
            group_name: GROUP_NAME,
            local_member: "member1",
            participants: &participants,
            signing_threshold: Some(SigningThreshold::numeric(2)),
            next_threshold: Some(SigningThreshold::numeric(2)),
            witnesses: &witnesses,
            witness_threshold: 3,
            delegator: None,
            timestamp: signify_keria_systest::now()?,
        })
        .await?;
    wait_and_delete(member1, &proposed.proposal().operation()?.name).await?;

    let said = await_notification(member2, "/multisig/icp").await?;
    progress("member2: accepting the group inception");
    let accepted = member2
        .multisig()
        .accept_inception(GROUP_NAME, "member2", &said, signify_keria_systest::now()?)
        .await?;
    wait_and_delete(member2, &accepted.proposal().operation()?.name).await?;

    progress("waiting out both group creations");
    wait_and_delete(member1, &proposed.creation().operation()?.name).await?;
    wait_and_delete(member2, &accepted.creation().operation()?.name).await?;
    if proposed.group() != accepted.group() {
        return Err("the two members derived different groups".into());
    }
    Ok(proposed.group().clone())
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn a_third_party_reads_a_groups_end_roles() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let transcripts = [recorder("member1")?, recorder("member2")?, recorder("alice")?];
    let (member1, member2, alice) = Box::pin(three_clients(&environment, &transcripts)).await?;

    let aid1 = create_identifier(&member1, "member1", &witness_prefixes(&environment)?).await?;
    let aid2 = create_identifier(&member2, "member2", &witness_prefixes(&environment)?).await?;
    let alice_prefix = create_identifier(&alice, "alice", &witness_prefixes(&environment)?).await?;
    resolve_oobi(&member1, &agent_oobi(&member2, "member2").await?, "member2").await?;
    resolve_oobi(&member2, &agent_oobi(&member1, "member1").await?, "member1").await?;

    let group = incept_group(&member1, &member2, &aid1, &aid2, &environment).await?;
    progress(&format!("group incepted as {}", group.qb64()?));

    // The end-role round, through the library: one reply per member's agent, and every member
    // accepting each proposal.
    let agent_eids = [member1.agent().prefix().clone(), member2.agent().prefix().clone()];
    authorise_agents(&[(&member1, "member1"), (&member2, "member2")], GROUP_NAME).await?;

    let group_oobi = agent_oobi(&member1, GROUP_NAME).await?;
    let truncated = group_oobi
        .split("/agent/")
        .next()
        .map(ToOwned::to_owned)
        .ok_or("the group OOBI has no /agent/ segment")?;
    resolve_oobi(&alice, &truncated, GROUP_NAME).await?;

    let all_roles = roles(&alice, &group, None).await?;
    let agent_roles = roles(&alice, &group, Some(&Role::Agent)).await?;
    let mailbox_roles_len = roles(&alice, &group, Some(&Role::Mailbox)).await?.len();
    let unknown_prefix = Digest::derive(DigestAlgorithm::Blake3_256, b"wave12 unknown aid").qb64()?;
    let unknown_roles_len = roles(&alice, &IdentifierPrefix::from_qb64(&unknown_prefix)?, None)
        .await?
        .len();
    let alice_roles = roles(&alice, &alice_prefix, None).await?;

    let captured = Captured {
        scenario: "endroles_by_aid",
        preset: environment.preset.to_string(),
        member1_prefix: aid1.qb64()?,
        member2_prefix: aid2.qb64()?,
        group_prefix: group.qb64()?,
        agent_eids: agent_eids
            .iter()
            .map(IdentifierPrefix::qb64)
            .collect::<Result<_, _>>()?,
        all_roles,
        agent_roles,
        mailbox_roles_len,
        unknown_prefix,
        unknown_roles_len,
        alice_prefix: alice_prefix.qb64()?,
        alice_roles,
        member1_operations_remaining: member1.operations().list(None).await?.len(),
        member2_operations_remaining: member2.operations().list(None).await?.len(),
        alice_operations_remaining: alice.operations().list(None).await?.len(),
        alice_transcript: transcripts[2].observations(),
    };
    if record("observations/endroles_by_aid.json", &captured)? {
        progress("recorded observations/endroles_by_aid.json");
    } else {
        progress("not a recording run, nothing written");
    }

    assert!(!captured.all_roles.is_empty(), "the group has no end roles");
    assert_eq!(captured.mailbox_roles_len, 0);
    assert_eq!(captured.unknown_roles_len, 0);
    assert_eq!(captured.alice_roles.len(), 1);
    assert_eq!(
        captured.member1_operations_remaining, 0,
        "member1 left operations behind"
    );
    assert_eq!(
        captured.member2_operations_remaining, 0,
        "member2 left operations behind"
    );
    assert_eq!(captured.alice_operations_remaining, 0, "alice left operations behind");
    Ok(())
}
