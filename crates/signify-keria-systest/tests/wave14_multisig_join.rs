//! Wave 14 — multisig join: a third member enters a group by rotation.
//!
//! The spine of `test-integration/multisig-join.test.ts`, the **Multisig inception/join** row's
//! second half: two members run a 1-of-1 group; a third member appears; a first group rotation
//! adds him to **rotation authority** (his digest joins `n` while `k` stays two); everyone
//! rotates their own keys again; and a second group rotation brings him into the **signing set**
//! — which he joins not by holding the group but by being shown the proposal.
//!
//! The join is where this port deliberately differs from the reference in *how* while agreeing in
//! *what*: upstream's member3 signs the shown bytes unexamined, which Roadmap 8.4 recorded as the
//! joining member never reading the rotation it joins. Here member3 **rebuilds** the rotation
//! from the proposal's member lists and his own queried key states — composing the group keeper
//! from `KeeperRequest::Group` and driving `rotate_identifier` over the group's prior state —
//! and compares the SAID he built with the SAID he was shown before `groups().join` submits his
//! signature. Same wire outcome, checked instead of trusted.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave14_multisig_join -- --ignored --test-threads=1 --nocapture
//! ```

// After the docs: a false `#![cfg]` strips everything below it, docs included, and an
// undocumented empty crate trips `missing_docs`.
#![cfg(feature = "live")]

use std::error::Error;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use signify_cesr::sequence::SequenceNumber;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::exchanges::{ClassifiedExchange, ExchangeDraft, MultisigRoute};
use signify_client::endpoint::groups::GroupJoin;
use signify_client::endpoint::key_states::{KeyStateQuery, QuerySequence};
use signify_client::endpoint::oobis::OobiResolution;
use signify_client::multisig::{GroupInceptionRequest, GroupRotationRequest};
use signify_http::request::ItemRange;
use signify_http::transport::RequestUrl;
use signify_keri::attachment::{SignatureSeal, SignedMessageBuilder};
use signify_keri::event::exchange::ExchangeEmbed;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest, rotate_identifier};
use signify_keri::manager::{KeeperRequest, ManagedSignatures};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::threshold::SigningThreshold;
use signify_keria_systest::{Environment, connect, progress, record, recorder};
use signify_types::api::{KeyState, Role};

/// The group alias, as the upstream case names it.
const GROUP_NAME: &str = "multisigGroup";

/// Everything the run observed, written as the fixture.
#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    member_prefixes: Vec<String>,
    group_prefix: String,
    /// The group's signing keys and next digests after the first rotation: two keys, three digests.
    after_first_rotation_keys: Vec<String>,
    after_first_rotation_digests: Vec<String>,
    /// The SAID the second rotation's proposal showed, and the SAID member3 rebuilt.
    shown_rotation_said: String,
    rebuilt_rotation_said: String,
    /// The group's state as member3 reads it after joining: three keys, three digests.
    joined_keys: Vec<String>,
    joined_digests: Vec<String>,
    operations_remaining: Vec<usize>,
    member3_transcript: Vec<signify_keria_systest::Observation>,
}

/// Waits one operation out and deletes it and any dependency.
async fn wait_and_delete(client: &ConnectedClient, name: &str) -> Result<Value, Box<dyn Error>> {
    let operation = client.operations().get(name).await?;
    let completed = client.poller().wait(operation).await?;
    let (name, metadata, response) = completed.into_parts();
    client.operations().delete(&name).await?;
    if let Some(depends) = metadata
        .as_ref()
        .and_then(|metadata| metadata.get("depends"))
        .and_then(|depends| depends.get("name"))
        .and_then(Value::as_str)
    {
        client.operations().delete(depends).await?;
    }
    Ok(response)
}

/// Creates one unwitnessed identifier with the agent end role, as `multisig-join` creates its
/// members (`createAID(client, name, [])`).
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

/// Resolves one OOBI URL under `alias` and waits the resolution out.
async fn resolve_url(client: &ConnectedClient, url: &str, alias: &str) -> Result<(), Box<dyn Error>> {
    let resolution = OobiResolution {
        url: RequestUrl::new(url.to_owned())?,
        alias: Some(alias.to_owned()),
    };
    let submitted = client.oobis().resolve(&resolution).await?;
    let completed = client.poller().wait(submitted).await?;
    let name = completed.name().to_owned();
    client.operations().delete(&name).await?;
    Ok(())
}

/// Returns the first agent OOBI `alias` publishes.
async fn agent_oobi(client: &ConnectedClient, alias: &str) -> Result<String, Box<dyn Error>> {
    client
        .oobis()
        .get(alias, &Role::Agent)
        .await?
        .oobis
        .first()
        .cloned()
        .ok_or_else(|| format!("{alias} publishes no OOBI").into())
}

/// Polls until an unread notification carries `route`, marking every match; returns the last SAID.
async fn await_notification(client: &ConnectedClient, route: &str) -> Result<Said, Box<dyn Error>> {
    progress(&format!("waiting for a notification on {route}"));
    for _ in 0..60 {
        let listing = client.notifications().list(ItemRange::DEFAULT).await?;
        let matching: Vec<_> = listing
            .unread()
            .filter(|notification| notification.attributes.route.as_deref() == Some(route))
            .cloned()
            .collect();
        if let Some(last) = matching.last() {
            let said = last
                .attributes
                .digest
                .clone()
                .ok_or("the notification names no message")?;
            for notification in &matching {
                client.notifications().mark(&notification.id).await?;
            }
            return Ok(Said::from_qb64(&said)?);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!("no notification on {route} arrived in time").into())
}

/// Queries one identifier's key state at a sequence and returns the state it resolved to.
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

/// Rotates one member's own identifier and waits it out.
async fn rotate_own(client: &ConnectedClient, alias: &str) -> Result<(), Box<dyn Error>> {
    progress(&format!("{alias}: rotating own keys"));
    let rotated = client
        .identifiers()
        .rotate(alias, &RotateIdentifierRequest::default())
        .await?;
    wait_and_delete(client, &rotated.operation()?.name).await?;
    Ok(())
}

/// One member's group end-role authorisation with its `/multisig/rpy` relay — wave 12's round.
async fn add_group_end_role(
    client: &ConnectedClient,
    member_alias: &str,
    eid: &IdentifierPrefix,
    peers: &[IdentifierPrefix],
    stamp: signify_keri::event::Timestamp,
) -> Result<String, Box<dyn Error>> {
    let authorised = client
        .identifiers()
        .add_end_role(GROUP_NAME, &Role::Agent, Some(eid), stamp)
        .await?;
    let operation_name = authorised.operation()?.name;

    let group_record = client.identifiers().get(GROUP_NAME).await?;
    let establishment = &group_record.state.latest_establishment_event;
    let reply = authorised.artifact();
    let ManagedSignatures::Indexed(signatures) = &reply.signatures else {
        return Err("the group reply is not signed with indexed signatures".into());
    };
    let attachment = SignedMessageBuilder::new(reply.reply.serialized())
        .controller_signatures(signatures.clone())
        .seal(SignatureSeal::Event {
            identifier: IdentifierPrefix::from_qb64(&group_record.common.prefix)?,
            sequence_number: SequenceNumber::from_hex(&establishment.sequence_number)?,
            said: Said::from_qb64(&establishment.digest)?,
        })
        .build()?
        .attachments()
        .to_vec();
    let embed = ExchangeEmbed::new("rpy", reply.reply.serialized())?.with_attachment(attachment)?;

    let addressee = peers.first().ok_or("the end-role round has no peers")?.clone();
    let mut payload = signify_keri::serialization::Sad::new();
    payload.insert("gid", group_record.common.prefix.clone())?;
    let draft = ExchangeDraft::new("/multisig/rpy", addressee, signify_keria_systest::now()?)
        .payload(payload)
        .embeds(vec![embed]);
    let sent = client.exchanges().send(member_alias, GROUP_NAME, &draft, peers).await?;
    wait_and_delete(client, &sent.operation()?.name).await?;
    Ok(operation_name)
}

/// Incepts the 1-of-1 two-member group and gives it its agent end roles.
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

    // The group's agent end roles, so it publishes the OOBI member3 will resolve.
    let stamp = signify_keria_systest::now()?;
    let eids = [member1.agent().prefix().clone(), member2.agent().prefix().clone()];
    let mut names = Vec::new();
    progress("member1: authorising both agents for the group");
    for eid in &eids {
        names.push((
            add_group_end_role(member1, "member1", eid, core::slice::from_ref(aid2), stamp.clone()).await?,
            true,
        ));
    }
    await_notification(member2, "/multisig/rpy").await?;
    progress("member2: authorising both agents for the group");
    for eid in &eids {
        names.push((
            add_group_end_role(member2, "member2", eid, core::slice::from_ref(aid1), stamp.clone()).await?,
            false,
        ));
    }
    for (name, on_member1) in &names {
        if *on_member1 {
            wait_and_delete(member1, name).await?;
        } else {
            wait_and_delete(member2, name).await?;
        }
    }
    Ok(proposed.group().clone())
}

/// Member1 proposes one group rotation over the given states and waits his own halves out.
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

/// Member3 rebuilds the shown rotation from its member lists and joins the group with it.
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
    // The rotation's own SAID — not `proposal.proposed.digest`, which is the embeds *block*'s.
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

    // The rebuild: the group keeper composed from the member's own record and the key states, and
    // the rotation derived over the group's prior state — then compared with what was shown.
    //
    // The keeper's `next_states` supply what a *rotation* signature indexes into: the digests the
    // **prior** group event committed (`keeper_for` reads them from the stored record's state,
    // which a joining member does not have). Handing it the new rotation states instead makes the
    // member's current key `MemberNotPrecommitted` — it is committed by the prior event, not the
    // proposed one — so each prior commitment is carried in a state shell of its own.
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

/// Creates member3 and cross-resolves every OOBI the join needs, including the group's
/// `/agent/`-truncated one.
async fn introduce_member3(
    member1: &ConnectedClient,
    member2: &ConnectedClient,
    member3: &ConnectedClient,
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let aid3 = plain_identifier(member3, "member3").await?;
    let oobi3 = agent_oobi(member3, "member3").await?;
    resolve_url(member1, &oobi3, "member3").await?;
    resolve_url(member2, &oobi3, "member3").await?;
    resolve_url(member3, &agent_oobi(member1, "member1").await?, "member1").await?;
    resolve_url(member3, &agent_oobi(member2, "member2").await?, "member2").await?;
    let group_oobi = agent_oobi(member1, GROUP_NAME).await?;
    let truncated = group_oobi
        .split("/agent/")
        .next()
        .map(ToOwned::to_owned)
        .ok_or("the group OOBI has no /agent/ segment")?;
    resolve_url(member3, &truncated, GROUP_NAME).await?;
    Ok(aid3)
}

/// Connects the three member clients, in transcript order.
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

    // The two-member group, and member3 introduced to everyone.
    let aid1 = plain_identifier(&member1, "member1").await?;
    let aid2 = plain_identifier(&member2, "member2").await?;
    resolve_url(&member1, &agent_oobi(&member2, "member2").await?, "member2").await?;
    resolve_url(&member2, &agent_oobi(&member1, "member1").await?, "member1").await?;
    let group = incept_group(&member1, &member2, &aid1, &aid2).await?;
    progress(&format!("group incepted as {}", group.qb64()?));

    let aid3 = Box::pin(introduce_member3(&member1, &member2, &member3)).await?;

    // First rotation: members 1 and 2 rotate their own keys; member3's digest joins `n`.
    rotate_own(&member1, "member1").await?;
    rotate_own(&member2, "member2").await?;
    let state2_on_1 = query_state(&member1, &aid2, 1).await?;
    let state3_on_1 = query_state(&member1, &aid3, 0).await?;
    let own1 = member1.identifiers().get("member1").await?;
    progress("member1: rotating the group to commit to member3");
    let signing = [(*own1.state).clone(), state2_on_1.clone()];
    let rotation = [(*own1.state).clone(), state2_on_1.clone(), state3_on_1.clone()];
    propose_group_rotation(&member1, &signing, &rotation).await?;
    // Only member2 hears of this rotation. The port's announcement reaches the **signing** peers,
    // and member3 holds only rotation authority here — upstream tells him by hand, because its
    // `send` takes a free-form recipient list (Roadmap 7.7's finding about that list, seen from
    // the other side). He needs nothing from this message: the second rotation's signing set
    // includes him, and that announcement is the one his join reads.
    await_notification(&member2, "/multisig/rot").await?;
    let after_first = member1.identifiers().get(GROUP_NAME).await?;

    // Second rotation: everyone rotates again; member3 queries the states he will rebuild from —
    // including the group's own prior state, fetched before the proposal exists.
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

    // Member3 reads the proposal, rebuilds the rotation, compares, and joins.
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
