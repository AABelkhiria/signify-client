//! Wave 13 — multisig inception: two groups, witnessed and witnessless.
//!
//! Incepts two groups by two members: witnessed at threshold two, and witnessless at zero.

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::oobis::OobiResolution;
use signify_client::multisig::GroupInceptionRequest;
use signify_http::request::ItemRange;
use signify_http::transport::RequestUrl;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::threshold::SigningThreshold;
use signify_keria_systest::{Environment, connect, progress, record, recorder};
use signify_types::api::Role;

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

async fn witnessed_identifier(
    client: &ConnectedClient,
    alias: &str,
    environment: &Environment,
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::salty(None));
    request.witnesses = environment
        .witness_prefixes
        .iter()
        .map(|prefix| IdentifierPrefix::from_qb64(prefix))
        .collect::<Result<Vec<_>, _>>()?;
    request.witness_threshold = u32::try_from(environment.witness_prefixes.len())?;
    progress(&format!("{alias}: creating with the witness triple"));
    let created = client.identifiers().create(alias, &request).await?;
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

async fn resolve_url(client: &ConnectedClient, url: &str, alias: &str) -> Result<(), Box<dyn Error>> {
    progress(&format!("resolving {alias}'s OOBI"));
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

    let aid1 = witnessed_identifier(&member1, "member1", &environment).await?;
    let aid2 = witnessed_identifier(&member2, "member2", &environment).await?;
    resolve_url(&member1, &agent_oobi(&member2, "member2").await?, "member2").await?;
    resolve_url(&member2, &agent_oobi(&member1, "member1").await?, "member1").await?;
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
