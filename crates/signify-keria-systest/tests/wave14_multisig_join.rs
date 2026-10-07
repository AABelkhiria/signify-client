//! Wave 14 — multisig join: a third member enters a group by rotation.
//!
//! A third member joins by rebuilding the rotation he was shown and comparing SAIDs before signing.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave14_multisig_join -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keria_types::api::{KeyState, Role};
use serde::Serialize;
use serde_json::Value;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::exchanges::{ClassifiedExchange, MultisigRoute};
use signify_client::endpoint::groups::GroupJoin;
use signify_client::endpoint::key_states::{KeyStateQuery, QuerySequence};
use signify_client::multisig::{GroupInceptionRequest, GroupRotationRequest};
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest, rotate_identifier};
use signify_keri::manager::KeeperRequest;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::threshold::SigningThreshold;
use signify_keria_systest::group::authorise_agents;
use signify_keria_systest::{
    Environment, agent_oobi, await_notification, connect, progress, record, recorder, resolve_oobi, wait_and_delete,
};

const GROUP_NAME: &str = "multisigGroup";

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
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
    member3_transcript: Vec<signify_keria_systest::Observation>,
}

async fn plain_identifier(client: &ConnectedClient, alias: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
    progress(&format!("{alias}: creating without witnesses"));
    let created = client
        .identifiers()
        .create(alias, &CreateIdentifierRequest::new(CreateAlgorithm::salty(None)))
        .await?;
    wait_and_delete(client, &created.operation()?.name).await?;
    let prefix = created.artifact().event.identifier().clone();

    let agent = client.agent().prefix().clone();
    let authorised = client
        .identifiers()
        .add_end_role(alias, &Role::Agent, Some(&agent), signify_keria_systest::now()?)
        .await?;
    wait_and_delete(client, &authorised.operation()?.name).await?;
    Ok(prefix)
}

async fn query_state(
    client: &ConnectedClient,
    prefix: &IdentifierPrefix,
    sequence: u64,
) -> Result<KeyState, Box<dyn Error>> {
    let query = KeyStateQuery::at(prefix.clone(), QuerySequence::Hexadecimal(sequence));
    let queried = client.key_states().query(&query).await?;
    let completed = client.poller().wait(queried).await?;
    let name = completed.name().to_owned();
    let state = completed.into_response();
    client.operations().delete(&name).await?;
    Ok(state)
}

async fn rotate_own(client: &ConnectedClient, alias: &str) -> Result<(), Box<dyn Error>> {
    progress(&format!("{alias}: rotating own keys"));
    let rotated = client
        .identifiers()
        .rotate(alias, &RotateIdentifierRequest::default())
        .await?;
    wait_and_delete(client, &rotated.operation()?.name).await?;
    Ok(())
}

async fn incept_group(
    member1: &ConnectedClient,
    member2: &ConnectedClient,
    aid1: &IdentifierPrefix,
    aid2: &IdentifierPrefix,
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let participants = [aid1.clone(), aid2.clone()];
    progress("member1: proposing the 1-of-1 group");
    let proposed = member1
        .multisig()
        .propose_inception(&GroupInceptionRequest {
            group_name: GROUP_NAME,
            local_member: "member1",
            participants: &participants,
            signing_threshold: Some(SigningThreshold::numeric(1)),
            next_threshold: Some(SigningThreshold::numeric(1)),
            witnesses: &[],
            witness_threshold: 0,
            delegator: None,
            timestamp: signify_keria_systest::now()?,
        })
        .await?;
    wait_and_delete(member1, &proposed.proposal().operation()?.name).await?;
    let said = await_notification(member2, "/multisig/icp").await?;
    progress("member2: accepting the group");
    let accepted = member2
        .multisig()
        .accept_inception(GROUP_NAME, "member2", &said, signify_keria_systest::now()?)
        .await?;
    wait_and_delete(member2, &accepted.proposal().operation()?.name).await?;
    wait_and_delete(member1, &proposed.creation().operation()?.name).await?;
    wait_and_delete(member2, &accepted.creation().operation()?.name).await?;

    // The end-role round, through the library.
    authorise_agents(&[(member1, "member1"), (member2, "member2")], GROUP_NAME).await?;
    Ok(proposed.group().clone())
}

async fn propose_group_rotation(
    member1: &ConnectedClient,
    signing: &[KeyState],
    rotation: &[KeyState],
) -> Result<(), Box<dyn Error>> {
    let proposed = member1
        .multisig()
        .propose_rotation(&GroupRotationRequest {
            group_name: GROUP_NAME,
            local_member: "member1",
            signing_states: signing,
            rotation_states: rotation,
            next_threshold: None,
            witness_threshold: None,
            witness_cuts: &[],
            witness_adds: &[],
            anchor: None,
            timestamp: signify_keria_systest::now()?,
        })
        .await?;
    wait_and_delete(member1, &proposed.announcement().operation()?.name).await?;
    wait_and_delete(member1, &proposed.submission().operation()?.name).await?;
    Ok(())
}

async fn rebuild_and_join(
    member3: &ConnectedClient,
    shown: &Said,
    group_prior: &KeyState,
    own_alias: &str,
    states_by_prefix: &[(IdentifierPrefix, KeyState)],
) -> Result<(String, String), Box<dyn Error>> {
    let listing = member3.groups().requests(shown).await?;
    let resource = listing.first().ok_or("the group request listing is empty")?;
    let classified = ClassifiedExchange::try_from(resource)?;
    let proposal = classified
        .as_multisig()
        .filter(|proposal| proposal.route == MultisigRoute::Rotation)
        .ok_or("the shown message is not a rotation proposal")?;
    let shown_said = serde_json::to_value(&proposal.proposed.message)?
        .get("rot")
        .and_then(|rot| rot.get("d"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or("the rotation embed carries no d")?;

    let signing_members = proposal
        .attributes
        .signing_members
        .clone()
        .ok_or("the proposal names no signing members")?;
    let rotation_members = proposal
        .attributes
        .rotation_members
        .clone()
        .unwrap_or_else(|| signing_members.clone());
    let pick = |members: &[IdentifierPrefix]| -> Result<Vec<KeyState>, Box<dyn Error>> {
        members
            .iter()
            .map(|member| {
                states_by_prefix
                    .iter()
                    .find(|(prefix, _)| prefix == member)
                    .map(|(_, state)| state.clone())
                    .ok_or_else(|| format!("no key state held for member {member:?}").into())
            })
            .collect()
    };
    let signing_states = pick(&signing_members)?;
    let rotation_states = pick(&rotation_members)?;

    let prior_commitments: Vec<KeyState> = signing_states
        .iter()
        .zip(&group_prior.next_key_digests)
        .map(|(state, digest)| {
            let mut shell = state.clone();
            shell.next_key_digests = vec![digest.clone()];
            shell
        })
        .collect();
    let own = member3.identifiers().get(own_alias).await?;
    let mut keeper = member3.keepers().create(KeeperRequest::Group {
        member: Box::new(own),
        states: &signing_states,
        next_states: &prior_commitments,
    })?;
    let request = RotateIdentifierRequest {
        states: signing_states.clone(),
        next_states: rotation_states.clone(),
        ..RotateIdentifierRequest::default()
    };
    let artifact = rotate_identifier(keeper.as_mut(), group_prior, &request)?;
    let rebuilt_said = artifact.event.said().qb64()?;
    if rebuilt_said != shown_said {
        return Err(format!("the rebuilt rotation {rebuilt_said} is not the shown {shown_said}").into());
    }

    progress("member3: joining the group with the rebuilt rotation");
    let join = GroupJoin::new(
        &artifact,
        &proposal.attributes.group,
        &signing_members,
        &rotation_members,
    );
    let operation = member3.groups().join(GROUP_NAME, &join).await?;
    wait_and_delete(member3, &operation.name).await?;
    Ok((shown_said, rebuilt_said))
}

async fn introduce_member3(
    member1: &ConnectedClient,
    member2: &ConnectedClient,
    member3: &ConnectedClient,
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let aid3 = plain_identifier(member3, "member3").await?;
    let oobi3 = agent_oobi(member3, "member3").await?;
    resolve_oobi(member1, &oobi3, "member3").await?;
    resolve_oobi(member2, &oobi3, "member3").await?;
    resolve_oobi(member3, &agent_oobi(member1, "member1").await?, "member1").await?;
    resolve_oobi(member3, &agent_oobi(member2, "member2").await?, "member2").await?;
    let group_oobi = agent_oobi(member1, GROUP_NAME).await?;
    let truncated = group_oobi
        .split("/agent/")
        .next()
        .map(ToOwned::to_owned)
        .ok_or("the group OOBI has no /agent/ segment")?;
    resolve_oobi(member3, &truncated, GROUP_NAME).await?;
    Ok(aid3)
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
    let member3 = connect(
        environment,
        signify_client::random::random_passcode()?.expose(),
        &transcripts[2],
    )
    .await?;
    Ok((member1, member2, member3))
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn a_third_member_joins_a_group_by_rotation() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let transcripts = [
        recorder("join_member1")?,
        recorder("join_member2")?,
        recorder("join_member3")?,
    ];
    let (member1, member2, member3) = Box::pin(three_clients(&environment, &transcripts)).await?;

    let aid1 = plain_identifier(&member1, "member1").await?;
    let aid2 = plain_identifier(&member2, "member2").await?;
    resolve_oobi(&member1, &agent_oobi(&member2, "member2").await?, "member2").await?;
    resolve_oobi(&member2, &agent_oobi(&member1, "member1").await?, "member1").await?;
    let group = incept_group(&member1, &member2, &aid1, &aid2).await?;
    progress(&format!("group incepted as {}", group.qb64()?));

    let aid3 = Box::pin(introduce_member3(&member1, &member2, &member3)).await?;

    rotate_own(&member1, "member1").await?;
    rotate_own(&member2, "member2").await?;
    let state2_on_1 = query_state(&member1, &aid2, 1).await?;
    let state3_on_1 = query_state(&member1, &aid3, 0).await?;
    let own1 = member1.identifiers().get("member1").await?;
    progress("member1: rotating the group to commit to member3");
    let signing = [(*own1.state).clone(), state2_on_1.clone()];
    let rotation = [(*own1.state).clone(), state2_on_1.clone(), state3_on_1.clone()];
    propose_group_rotation(&member1, &signing, &rotation).await?;
    await_notification(&member2, "/multisig/rot").await?;
    let after_first = member1.identifiers().get(GROUP_NAME).await?;

    rotate_own(&member1, "member1").await?;
    rotate_own(&member2, "member2").await?;
    rotate_own(&member3, "member3").await?;
    let group_prior = query_state(&member3, &group, 1).await?;
    let state1_on_3 = query_state(&member3, &aid1, 2).await?;
    let state2_on_3 = query_state(&member3, &aid2, 2).await?;
    let own3 = member3.identifiers().get("member3").await?;
    let state1_on_1 = member1.identifiers().get("member1").await?;
    let state2_queried_on_1 = query_state(&member1, &aid2, 2).await?;
    let state3_queried_on_1 = query_state(&member1, &aid3, 1).await?;

    progress("member1: rotating the group to bring member3 into the signing set");
    let all_states = [
        (*state1_on_1.state).clone(),
        state2_queried_on_1.clone(),
        state3_queried_on_1.clone(),
    ];
    propose_group_rotation(&member1, &all_states, &all_states).await?;

    let shown = await_notification(&member3, "/multisig/rot").await?;
    await_notification(&member2, "/multisig/rot").await?;
    let held = [
        (aid1.clone(), state1_on_3),
        (aid2.clone(), state2_on_3),
        (aid3.clone(), (*own3.state).clone()),
    ];
    let (shown_said, rebuilt_said) =
        Box::pin(rebuild_and_join(&member3, &shown, &group_prior, "member3", &held)).await?;
    let joined = member3.identifiers().get(GROUP_NAME).await?;

    let captured = Captured {
        scenario: "multisig_join",
        preset: environment.preset.to_string(),
        member_prefixes: vec![aid1.qb64()?, aid2.qb64()?, aid3.qb64()?],
        group_prefix: group.qb64()?,
        after_first_rotation_keys: after_first.state.signing_keys.clone(),
        after_first_rotation_digests: after_first.state.next_key_digests.clone(),
        shown_rotation_said: shown_said,
        rebuilt_rotation_said: rebuilt_said,
        joined_keys: joined.state.signing_keys.clone(),
        joined_digests: joined.state.next_key_digests.clone(),
        operations_remaining: vec![
            member1.operations().list(None).await?.len(),
            member2.operations().list(None).await?.len(),
            member3.operations().list(None).await?.len(),
        ],
        member3_transcript: transcripts[2].observations(),
    };
    if record("observations/multisig_join.json", &captured)? {
        progress("recorded observations/multisig_join.json");
    } else {
        progress("not a recording run, nothing written");
    }

    assert_eq!(
        captured.after_first_rotation_keys.len(),
        2,
        "the first rotation should keep two signers"
    );
    assert_eq!(
        captured.after_first_rotation_digests.len(),
        3,
        "member3's digest should join n"
    );
    assert_eq!(captured.shown_rotation_said, captured.rebuilt_rotation_said);
    assert_eq!(captured.joined_keys.len(), 3, "member3 should be in the signing set");
    assert_eq!(captured.joined_digests.len(), 3);
    assert_eq!(captured.operations_remaining, [0, 0, 0], "operations were left behind");
    Ok(())
}
