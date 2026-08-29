//! Wave 9 — single-signature delegation: an inception that exists only once it is anchored.
//!
//! `test-integration/delegation.test.ts` is the §7 row for Roadmap 8.5's endpoint driven whole: a
//! delegate creates an identifier naming a delegator, and that inception's operation stays
//! **pending** — the identifier does not exist yet — until the delegator anchors a seal of it in
//! its own log and the delegate's agent sees that anchor. The seeing is itself a step: the
//! delegate's client queries the delegator's key state at sequence one, which is what makes its
//! agent fetch the approving interaction from the witnesses.
//!
//! Two of Roadmap 8.5's refusals are exercised live. The delegate's prefix is read from the
//! creation's own artifact, not parsed out of an operation name (`op.name.split('.')[1]`
//! upstream); and the seal is [`InceptionSeal`], whose three fields cannot disagree, not a
//! hand-assembled object. The tail reproduces the upstream case's odd contact resolution: the
//! delegate's agent OOBI **truncated at `/agent/`** still resolves, and answers the delegate's
//! prefix.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave9_delegation -- --ignored --test-threads=1 --nocapture
//! ```

// After the docs: a false `#![cfg]` strips everything below it, docs included, and an
// undocumented empty crate trips `missing_docs`.
#![cfg(feature = "live")]

use std::error::Error;

use serde::Serialize;
use serde_json::Value;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::delegations::InceptionSeal;
use signify_client::endpoint::key_states::{KeyStateQuery, QuerySequence};
use signify_client::endpoint::oobis::OobiResolution;
use signify_http::transport::RequestUrl;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keria_systest::{Environment, connect, progress, record, recorder};
use signify_types::api::Role;

/// Everything the run observed, written as the fixture.
#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    /// The witnessed delegator.
    delegator_prefix: String,
    /// The delegated identifier.
    delegate_prefix: String,
    /// The delegated inception exactly as the delegate's client serialized it.
    delegate_event: String,
    delegate_said: String,
    /// Whether the creation's operation was still pending before the approval — the row's point.
    pending_before_approval: bool,
    /// The approving interaction as the delegator's client serialized it.
    approval_event: String,
    approval_said: String,
    /// The seal that interaction anchors, read back from the event.
    anchored_seal: String,
    /// The sequence text the delegate's key-state query sent; hexadecimal.
    query_sequence_sent: String,
    /// The delegate record's prefix after the operation completed.
    accepted_prefix: String,
    /// The truncated OOBI URL the delegator resolved the delegate through.
    truncated_oobi: String,
    /// The prefix that resolution answered with.
    contact_resolved: String,
    delegator_operations_remaining: usize,
    delegate_operations_remaining: usize,
    delegator_transcript: Vec<signify_keria_systest::Observation>,
    delegate_transcript: Vec<signify_keria_systest::Observation>,
}

/// Waits one operation out and deletes it **and its dependency**, as the upstream helper does.
///
/// A delegation approval spawns a second operation — `witness.{said}`, the receipting of the
/// anchoring interaction — embedded in the first one's `metadata.depends`. Upstream's
/// `deleteOperations` walks that chain; a helper that deleted only the top operation leaves the
/// dependency listed, which is how this wave's first run failed its own postcondition.
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

/// Creates the witnessed delegator with its agent end role, as the upstream case does.
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

/// Resolves one OOBI URL on `client` under `alias` and returns the prefix it answered.
async fn resolve_url(client: &ConnectedClient, url: &str, alias: &str) -> Result<String, Box<dyn Error>> {
    progress(&format!("resolving {alias}'s OOBI"));
    let resolution = OobiResolution {
        url: RequestUrl::new(url.to_owned())?,
        alias: Some(alias.to_owned()),
    };
    let resolved = client.oobis().resolve(&resolution).await?;
    let completed = client.poller().wait(resolved).await?;
    let name = completed.name().to_owned();
    let state = completed.into_response();
    client.operations().delete(&name).await?;
    Ok(state.identifier)
}

/// Creates the witnessed delegator and introduces it to the delegate through its agent OOBI.
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
    let learned = resolve_url(delegate_client, &delegator_oobi, "delegator").await?;
    if learned != delegator_prefix.qb64()? {
        mismatches.push("the delegate learned a different delegator prefix".to_owned());
    }
    Ok(delegator_prefix)
}

/// Queries the delegator's key state at sequence one on the delegate's client, which is what
/// makes its agent fetch the approving interaction; returns the sequence text sent.
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

/// The tail of the upstream case: the delegate authorises its agent, and the delegator resolves
/// the delegate's agent OOBI **truncated at `/agent/`** — upstream's own odd URL — as a contact.
/// Returns the truncated URL and the prefix it resolved to.
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
    let contact_resolved = resolve_url(delegator_client, &truncated_oobi, "delegate").await?;
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

    // The delegator, witnessed by the whole triple, and known to the delegate through its OOBI.
    let delegator_prefix =
        introduced_delegator(&delegator_client, &delegate_client, &environment, &mut mismatches).await?;

    // The delegate creates an identifier naming the delegator. The prefix comes from the
    // artifact, not from an operation's name; and the operation stays pending.
    progress("delegate: creating the delegated identifier");
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::salty(None));
    request.delegator = Some(delegator_prefix.clone());
    let created = delegate_client.identifiers().create("delegate", &request).await?;
    let delegate_prefix = created.artifact().event.identifier().clone();
    let pending_name = created.operation()?.name;
    let pending_before_approval = !delegate_client.operations().get(&pending_name).await?.outcome.is_done();

    // The delegator anchors the seal — built from the delegate's prefix and inception digest,
    // which for a self-addressing delegated inception are the same value.
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

    // The delegate's agent learns of the anchor by querying the delegator's key state at
    // sequence one — hexadecimal, wave 1's answer — and only then does the creation complete.
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
