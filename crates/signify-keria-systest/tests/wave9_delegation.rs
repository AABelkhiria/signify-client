//! Wave 9 — single-signature delegation: an inception that exists only once it is anchored.
//!
//! Creates a delegated identifier, proves it pending, then anchors its seal at the delegation address.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave9_delegation -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use serde::Serialize;
use serde_json::Value;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::delegations::InceptionSeal;
use signify_client::endpoint::key_states::{KeyStateQuery, QuerySequence};
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keria_systest::{Environment, connect, progress, record, recorder, resolve_oobi, wait_and_delete};
use signify_types::api::Role;

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    delegator_prefix: String,
    delegate_prefix: String,
    delegate_event: String,
    delegate_said: String,
    pending_before_approval: bool,
    approval_event: String,
    approval_said: String,
    anchored_seal: String,
    query_sequence_sent: String,
    accepted_prefix: String,
    truncated_oobi: String,
    contact_resolved: String,
    delegator_operations_remaining: usize,
    delegate_operations_remaining: usize,
    delegator_transcript: Vec<signify_keria_systest::Observation>,
    delegate_transcript: Vec<signify_keria_systest::Observation>,
}

async fn witnessed_delegator(
    client: &ConnectedClient,
    environment: &Environment,
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::salty(None));
    request.witnesses = environment
        .witness_prefixes
        .iter()
        .map(|prefix| IdentifierPrefix::from_qb64(prefix))
        .collect::<Result<Vec<_>, _>>()?;
    request.witness_threshold = u32::try_from(environment.witness_prefixes.len())?;
    progress("delegator: creating with the witness triple");
    let created = client.identifiers().create("delegator", &request).await?;
    wait_and_delete(client, &created.operation()?.name).await?;
    let prefix = created.artifact().event.identifier().clone();

    progress("delegator: authorising the agent end role");
    let agent = client.agent().prefix().clone();
    let authorised = client
        .identifiers()
        .add_end_role("delegator", &Role::Agent, Some(&agent), signify_keria_systest::now()?)
        .await?;
    wait_and_delete(client, &authorised.operation()?.name).await?;
    Ok(prefix)
}

async fn introduced_delegator(
    delegator_client: &ConnectedClient,
    delegate_client: &ConnectedClient,
    environment: &Environment,
    mismatches: &mut Vec<String>,
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let delegator_prefix = witnessed_delegator(delegator_client, environment).await?;
    let published = delegator_client.oobis().get("delegator", &Role::Agent).await?;
    let delegator_oobi = published
        .oobis
        .first()
        .cloned()
        .ok_or("the delegator publishes no OOBI")?;
    let learned = resolve_oobi(delegate_client, &delegator_oobi, "delegator").await?;
    if learned != delegator_prefix.qb64()? {
        mismatches.push("the delegate learned a different delegator prefix".to_owned());
    }
    Ok(delegator_prefix)
}

async fn refresh_delegator_state(
    delegate_client: &ConnectedClient,
    delegator_prefix: &IdentifierPrefix,
) -> Result<String, Box<dyn Error>> {
    progress("delegate: querying the delegator's key state at sequence one");
    let query_sequence = QuerySequence::Hexadecimal(1);
    let query = KeyStateQuery::at(delegator_prefix.clone(), query_sequence);
    let queried = delegate_client.key_states().query(&query).await?;
    let completed = delegate_client.poller().wait(queried).await?;
    let name = completed.name().to_owned();
    delegate_client.operations().delete(&name).await?;
    Ok(query_sequence.to_text())
}

async fn truncated_contact_tail(
    delegate_client: &ConnectedClient,
    delegator_client: &ConnectedClient,
) -> Result<(String, String), Box<dyn Error>> {
    progress("delegate: authorising the agent end role");
    let agent = delegate_client.agent().prefix().clone();
    let authorised = delegate_client
        .identifiers()
        .add_end_role("delegate", &Role::Agent, Some(&agent), signify_keria_systest::now()?)
        .await?;
    wait_and_delete(delegate_client, &authorised.operation()?.name).await?;
    let published = delegate_client.oobis().get("delegate", &Role::Agent).await?;
    let delegate_oobi = published
        .oobis
        .first()
        .cloned()
        .ok_or("the delegate publishes no OOBI")?;
    let truncated_oobi = delegate_oobi
        .split("/agent/")
        .next()
        .map(ToOwned::to_owned)
        .ok_or("the agent OOBI has no /agent/ segment")?;
    let contact_resolved = resolve_oobi(delegator_client, &truncated_oobi, "delegate").await?;
    Ok((truncated_oobi, contact_resolved))
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn a_delegated_inception_pends_until_its_seal_is_anchored() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let delegator_transcript = recorder("delegator")?;
    progress("connecting the delegator client");
    let delegator_client = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &delegator_transcript,
    )
    .await?;
    let delegate_transcript = recorder("delegate")?;
    progress("connecting the delegate client");
    let delegate_client = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &delegate_transcript,
    )
    .await?;
    let mut mismatches = Vec::new();

    let delegator_prefix =
        introduced_delegator(&delegator_client, &delegate_client, &environment, &mut mismatches).await?;

    progress("delegate: creating the delegated identifier");
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::salty(None));
    request.delegator = Some(delegator_prefix.clone());
    let created = delegate_client.identifiers().create("delegate", &request).await?;
    let delegate_prefix = created.artifact().event.identifier().clone();
    let pending_name = created.operation()?.name;
    let pending_before_approval = !delegate_client.operations().get(&pending_name).await?.outcome.is_done();

    progress("delegator: approving the delegation");
    let seal = InceptionSeal::new(delegate_prefix.clone(), Said::from_qb64(&delegate_prefix.qb64()?)?);
    let approved = delegator_client
        .delegations()
        .approve_inception("delegator", &seal)
        .await?;
    wait_and_delete(&delegator_client, &approved.operation()?.name).await?;
    let approval_event = String::from_utf8(approved.artifact().event.raw().to_vec())?;
    let approval_said = approved.artifact().event.said().qb64()?;
    let anchored_seal = serde_json::from_str::<Value>(&approval_event)?
        .get("a")
        .and_then(Value::as_array)
        .and_then(|anchors| anchors.first().cloned())
        .map(|seal| seal.to_string())
        .unwrap_or_default();

    let query_sequence_sent = refresh_delegator_state(&delegate_client, &delegator_prefix).await?;

    progress("delegate: waiting out the pending inception");
    wait_and_delete(&delegate_client, &pending_name).await?;
    let accepted = delegate_client.identifiers().get("delegate").await?;
    if accepted.common.prefix != delegate_prefix.qb64()? {
        mismatches.push("the accepted record names a different prefix".to_owned());
    }

    let (truncated_oobi, contact_resolved) =
        Box::pin(truncated_contact_tail(&delegate_client, &delegator_client)).await?;
    if contact_resolved != delegate_prefix.qb64()? {
        mismatches.push("the truncated OOBI resolved a different prefix".to_owned());
    }

    let captured = Captured {
        scenario: "delegation",
        preset: environment.preset.to_string(),
        delegator_prefix: delegator_prefix.qb64()?,
        delegate_prefix: delegate_prefix.qb64()?,
        delegate_event: String::from_utf8(created.artifact().event.raw().to_vec())?,
        delegate_said: created.artifact().event.said().qb64()?,
        pending_before_approval,
        approval_event,
        approval_said,
        anchored_seal,
        query_sequence_sent,
        accepted_prefix: accepted.common.prefix.clone(),
        truncated_oobi,
        contact_resolved,
        delegator_operations_remaining: delegator_client.operations().list(None).await?.len(),
        delegate_operations_remaining: delegate_client.operations().list(None).await?.len(),
        delegator_transcript: delegator_transcript.observations(),
        delegate_transcript: delegate_transcript.observations(),
    };
    if record("observations/delegation.json", &captured)? {
        progress("recorded observations/delegation.json");
    } else {
        progress("not a recording run, nothing written");
    }

    assert!(mismatches.is_empty(), "the run diverged: {mismatches:#?}");
    assert!(
        captured.pending_before_approval,
        "the inception completed without approval"
    );
    assert_eq!(
        captured.delegator_operations_remaining, 0,
        "delegator operations left behind"
    );
    assert_eq!(
        captured.delegate_operations_remaining, 0,
        "delegate operations left behind"
    );
    Ok(())
}
