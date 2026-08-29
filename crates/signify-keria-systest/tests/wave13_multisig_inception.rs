//! Wave 13 — multisig inception: two groups, witnessed and witnessless.
//!
//! `test-integration/multisig-inception.test.ts` is the first half of the **Multisig
//! inception/join** row: two members incept a group **witnessed at threshold two of the demo
//! triple**, assert that both derived the same prefix and that the members listing names both of
//! them in order for signing and rotation alike — and then incept a second group with **no
//! witnesses at all** (`toad: 0, wits: []`), whose members assertions upstream comments out
//! against `keria#189`. What that issue actually does to a live KERIA 1.0.1 is recorded here
//! rather than assumed: the listing call's outcome for the witnessless group is captured either
//! way it goes.
//!
//! The rounds run through the port's `propose_inception`/`accept_inception`, exactly as wave 12's
//! setup did — the difference is that here the groups *are* the observation, at two witness
//! configurations wave 12 did not touch.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave13_multisig_inception -- --ignored --test-threads=1 --nocapture
//! ```

// After the docs: a false `#![cfg]` strips everything below it, docs included, and an
// undocumented empty crate trips `missing_docs`.
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

/// One group's round: what both members derived and what the agent lists.
#[derive(Debug, Serialize)]
struct GroupRound {
    group_name: String,
    /// Whether the group named the witness triple, and at what threshold.
    witnessed: bool,
    witness_threshold: u32,
    /// The prefix each member's client derived; upstream asserts them equal.
    proposer_prefix: String,
    acceptor_prefix: String,
    /// The signing and rotation member AIDs the proposer's `members()` listing answered, in
    /// order — or the error it answered instead, for the witnessless group `keria#189` is about.
    signing_aids: Vec<String>,
    rotation_aids: Vec<String>,
    members_error: Option<String>,
}

/// Everything the run observed, written as the fixture.
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

/// Creates one identifier witnessed by the whole triple, with the agent end role.
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

/// Resolves one OOBI URL under `alias` and waits the resolution out.
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

/// Polls until an unread notification carries `route`, marking every match read; returns the last
/// one's named message.
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

/// Runs one two-member inception round and reads the members listing back.
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

    // Upstream reads both records back and asserts the prefixes equal; here both derivations were
    // already compared inside the round, and the records confirm what the agents stored.
    let stored1 = member1.identifiers().get(group_name).await?;
    let stored2 = member2.identifiers().get(group_name).await?;

    // The members listing — commented out upstream for the witnessless group against `keria#189`,
    // so its outcome is recorded here whichever way it goes rather than asserted blindly.
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

    // The witnessed group: the whole triple at threshold two — the one witness configuration no
    // earlier wave has driven.
    let witnesses: Vec<IdentifierPrefix> = environment
        .witness_prefixes
        .iter()
        .map(|prefix| IdentifierPrefix::from_qb64(prefix))
        .collect::<Result<_, _>>()?;
    let witnessed_round = group_round(&member1, &member2, &participants, "multisig", &witnesses, 2).await?;

    // The witnessless group: `toad: 0, wits: []`, whose members listing upstream dare not assert.
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
