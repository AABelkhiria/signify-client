//! Wave 10 — the delegated lifecycle: two inceptions, a rotation, and both refresh modes.
//!
//! Two delegated inceptions and a delegated rotation, seen through both refresh modes.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave10_delegated_lifecycle -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::{Role, Seal};
use serde::Serialize;
use serde_json::Value;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::key_states::{KeyStateQuery, QuerySequence};
use signify_client::endpoint::oobis::OobiResolution;
use signify_http::transport::RequestUrl;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest};
use signify_keria_systest::{Environment, connect, progress, record, recorder, wait_and_delete};

#[derive(Debug, Serialize)]
struct DelegatedStep {
    prefix: String,
    derived_event: String,
    derived_said: String,
    operation_name: String,
    pending_before_approval: bool,
    approval_event: String,
    refreshed_by: &'static str,
    witnessed: bool,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    delegator_prefix: String,
    steps: Vec<DelegatedStep>,
    anchor_query_idempotent: Option<bool>,
    completed_kind: Option<String>,
    completed_sequence: Option<String>,
    delegator_operations_remaining: usize,
    delegate_operations_remaining: usize,
    delegator_transcript: Vec<signify_keria_systest::Observation>,
    delegate_transcript: Vec<signify_keria_systest::Observation>,
}

async fn introduced_delegator(
    delegator_client: &ConnectedClient,
    delegate_client: &ConnectedClient,
    environment: &Environment,
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::salty(None));
    request.witnesses = environment
        .witness_prefixes
        .iter()
        .map(|prefix| IdentifierPrefix::from_qb64(prefix))
        .collect::<Result<Vec<_>, _>>()?;
    request.witness_threshold = u32::try_from(environment.witness_prefixes.len())?;
    progress("name1: creating the witnessed delegator");
    let created = delegator_client.identifiers().create("name1", &request).await?;
    wait_and_delete(delegator_client, &created.operation()?.name).await?;
    let prefix = created.artifact().event.identifier().clone();

    let agent = delegator_client.agent().prefix().clone();
    let authorised = delegator_client
        .identifiers()
        .add_end_role("name1", &Role::Agent, Some(&agent), signify_keria_systest::now()?)
        .await?;
    wait_and_delete(delegator_client, &authorised.operation()?.name).await?;

    let published = delegator_client.oobis().get("name1", &Role::Agent).await?;
    let url = published
        .oobis
        .first()
        .cloned()
        .ok_or("the delegator publishes no OOBI")?;
    progress("resolving the delegator's OOBI on the delegate");
    let resolution = OobiResolution {
        url: RequestUrl::new(url)?,
        alias: Some("contact1".to_owned()),
    };
    let resolved = delegate_client.oobis().resolve(&resolution).await?;
    let completed = delegate_client.poller().wait(resolved).await?;
    let name = completed.name().to_owned();
    delegate_client.operations().delete(&name).await?;
    Ok(prefix)
}

async fn approve_via_interact(
    delegator_client: &ConnectedClient,
    identifier: &str,
    sequence: &str,
    digest: &str,
) -> Result<String, Box<dyn Error>> {
    progress("name1: anchoring the delegation seal with a plain interaction");
    let mut seal = Sad::new();
    seal.insert("i", SadValue::text(identifier))?;
    seal.insert("s", SadValue::text(sequence))?;
    seal.insert("d", SadValue::text(digest))?;
    let interacted = delegator_client.identifiers().interact("name1", vec![seal]).await?;
    wait_and_delete(delegator_client, &interacted.operation()?.name).await?;
    Ok(String::from_utf8(interacted.artifact().event.raw().to_vec())?)
}

async fn refresh_by_sequence(
    delegate_client: &ConnectedClient,
    delegator: &IdentifierPrefix,
    sequence: u64,
) -> Result<(), Box<dyn Error>> {
    progress("delegate: refreshing the delegator's key state by sequence");
    let query = KeyStateQuery::at(delegator.clone(), QuerySequence::Hexadecimal(sequence));
    let queried = delegate_client.key_states().query(&query).await?;
    let completed = delegate_client.poller().wait(queried).await?;
    let name = completed.name().to_owned();
    delegate_client.operations().delete(&name).await?;
    Ok(())
}

async fn refresh_by_anchor(
    delegate_client: &ConnectedClient,
    delegator: &IdentifierPrefix,
    seal: Seal,
) -> Result<(), Box<dyn Error>> {
    progress("delegate: refreshing the delegator's key state by anchor");
    let query = KeyStateQuery::anchoring(delegator.clone(), seal);
    let queried = delegate_client.key_states().query(&query).await?;
    let completed = delegate_client.poller().wait(queried).await?;
    let name = completed.name().to_owned();
    delegate_client.operations().delete(&name).await?;
    Ok(())
}

async fn delegated_inception(
    delegate_client: &ConnectedClient,
    alias: &str,
    delegator: &IdentifierPrefix,
    environment: &Environment,
    witnessed: bool,
) -> Result<(String, String, String, String, bool), Box<dyn Error>> {
    progress(&format!("{alias}: creating the delegated identifier"));
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::salty(None));
    request.delegator = Some(delegator.clone());
    if witnessed {
        request.witnesses = environment
            .witness_prefixes
            .iter()
            .map(|prefix| IdentifierPrefix::from_qb64(prefix))
            .collect::<Result<Vec<_>, _>>()?;
        request.witness_threshold = u32::try_from(environment.witness_prefixes.len())?;
    }
    let created = delegate_client.identifiers().create(alias, &request).await?;
    let prefix = created.artifact().event.identifier().qb64()?;
    let derived_event = String::from_utf8(created.artifact().event.raw().to_vec())?;
    let derived_said = created.artifact().event.said().qb64()?;
    let operation_name = created.operation()?.name;
    let pending = !delegate_client
        .operations()
        .get(&operation_name)
        .await?
        .outcome
        .is_done();
    Ok((prefix, derived_event, derived_said, operation_name, pending))
}

async fn two_clients(
    environment: &Environment,
    scenario: &str,
) -> Result<
    (
        ConnectedClient,
        ConnectedClient,
        std::sync::Arc<signify_keria_systest::Recorder>,
        std::sync::Arc<signify_keria_systest::Recorder>,
    ),
    Box<dyn Error>,
> {
    let delegator_transcript = recorder(scenario)?;
    progress("connecting the delegator client");
    let delegator_client = connect(
        environment,
        signify_client::random::random_passcode()?.expose(),
        &delegator_transcript,
    )
    .await?;
    let delegate_transcript = recorder("delegate")?;
    progress("connecting the delegate client");
    let delegate_client = connect(
        environment,
        signify_client::random::random_passcode()?.expose(),
        &delegate_transcript,
    )
    .await?;
    Ok((
        delegator_client,
        delegate_client,
        delegator_transcript,
        delegate_transcript,
    ))
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn delegated_inceptions_complete_under_both_refresh_modes() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let (delegator_client, delegate_client, delegator_transcript, delegate_transcript) =
        Box::pin(two_clients(&environment, "singlesig_dip")).await?;
    let delegator = Box::pin(introduced_delegator(&delegator_client, &delegate_client, &environment)).await?;
    let mut steps = Vec::new();

    let (prefix, derived_event, derived_said, operation_name, pending) =
        delegated_inception(&delegate_client, "delegate1", &delegator, &environment, false).await?;
    let approval = approve_via_interact(&delegator_client, &prefix, "0", &prefix).await?;
    refresh_by_sequence(&delegate_client, &delegator, 1).await?;
    let echoed = wait_and_delete(&delegate_client, &operation_name).await?;
    assert_eq!(echoed.get("i").and_then(Value::as_str), Some(prefix.as_str()));
    steps.push(DelegatedStep {
        prefix,
        derived_event,
        derived_said,
        operation_name,
        pending_before_approval: pending,
        approval_event: approval,
        refreshed_by: "sequence",
        witnessed: false,
    });

    let (prefix, derived_event, derived_said, operation_name, pending) =
        delegated_inception(&delegate_client, "delegate2", &delegator, &environment, true).await?;
    let approval = approve_via_interact(&delegator_client, &prefix, "0", &prefix).await?;
    let seal = Seal {
        sequence_number: "0".to_owned(),
        digest: prefix.clone(),
        identifier: Some(prefix.clone()),
    };
    refresh_by_anchor(&delegate_client, &delegator, seal.clone()).await?;
    let echoed = wait_and_delete(&delegate_client, &operation_name).await?;
    assert_eq!(echoed.get("i").and_then(Value::as_str), Some(prefix.as_str()));
    steps.push(DelegatedStep {
        prefix,
        derived_event,
        derived_said,
        operation_name,
        pending_before_approval: pending,
        approval_event: approval,
        refreshed_by: "anchor",
        witnessed: true,
    });

    refresh_by_anchor(&delegate_client, &delegator, seal).await?;
    let anchor_query_idempotent = Some(true);

    let captured = Captured {
        scenario: "singlesig_dip",
        preset: environment.preset.to_string(),
        delegator_prefix: delegator.qb64()?,
        steps,
        anchor_query_idempotent,
        completed_kind: None,
        completed_sequence: None,
        delegator_operations_remaining: delegator_client.operations().list(None).await?.len(),
        delegate_operations_remaining: delegate_client.operations().list(None).await?.len(),
        delegator_transcript: delegator_transcript.observations(),
        delegate_transcript: delegate_transcript.observations(),
    };
    if record("observations/singlesig_dip.json", &captured)? {
        progress("recorded observations/singlesig_dip.json");
    } else {
        progress("not a recording run, nothing written");
    }
    assert!(captured.steps.iter().all(|step| step.pending_before_approval));
    assert_eq!(captured.delegator_operations_remaining, 0);
    assert_eq!(captured.delegate_operations_remaining, 0);
    Ok(())
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn a_delegated_rotation_pends_until_its_seal_is_anchored() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let (delegator_client, delegate_client, delegator_transcript, delegate_transcript) =
        Box::pin(two_clients(&environment, "singlesig_drt")).await?;
    let delegator = Box::pin(introduced_delegator(&delegator_client, &delegate_client, &environment)).await?;
    let mut steps = Vec::new();

    let (prefix, derived_event, derived_said, operation_name, pending) =
        delegated_inception(&delegate_client, "delegate1", &delegator, &environment, false).await?;
    let approval = approve_via_interact(&delegator_client, &prefix, "0", &prefix).await?;
    refresh_by_sequence(&delegate_client, &delegator, 1).await?;
    wait_and_delete(&delegate_client, &operation_name).await?;
    steps.push(DelegatedStep {
        prefix: prefix.clone(),
        derived_event,
        derived_said,
        operation_name,
        pending_before_approval: pending,
        approval_event: approval,
        refreshed_by: "sequence",
        witnessed: false,
    });

    progress("delegate1: rotating the delegated identifier");
    let rotated = delegate_client
        .identifiers()
        .rotate("delegate1", &RotateIdentifierRequest::default())
        .await?;
    let rotation_said = rotated.artifact().event.said().qb64()?;
    let rotation_event = String::from_utf8(rotated.artifact().event.raw().to_vec())?;
    let rotation_operation = rotated.operation()?.name;
    let rotation_pending = !delegate_client
        .operations()
        .get(&rotation_operation)
        .await?
        .outcome
        .is_done();
    let approval = approve_via_interact(&delegator_client, &prefix, "1", &rotation_said).await?;
    refresh_by_sequence(&delegate_client, &delegator, 2).await?;
    let echoed = wait_and_delete(&delegate_client, &rotation_operation).await?;
    steps.push(DelegatedStep {
        prefix,
        derived_event: rotation_event,
        derived_said: rotation_said,
        operation_name: rotation_operation,
        pending_before_approval: rotation_pending,
        approval_event: approval,
        refreshed_by: "sequence",
        witnessed: false,
    });

    let captured = Captured {
        scenario: "singlesig_drt",
        preset: environment.preset.to_string(),
        delegator_prefix: delegator.qb64()?,
        steps,
        anchor_query_idempotent: None,
        completed_kind: echoed.get("t").and_then(Value::as_str).map(ToOwned::to_owned),
        completed_sequence: echoed.get("s").and_then(Value::as_str).map(ToOwned::to_owned),
        delegator_operations_remaining: delegator_client.operations().list(None).await?.len(),
        delegate_operations_remaining: delegate_client.operations().list(None).await?.len(),
        delegator_transcript: delegator_transcript.observations(),
        delegate_transcript: delegate_transcript.observations(),
    };
    if record("observations/singlesig_drt.json", &captured)? {
        progress("recorded observations/singlesig_drt.json");
    } else {
        progress("not a recording run, nothing written");
    }
    assert!(captured.steps.iter().all(|step| step.pending_before_approval));
    assert_eq!(captured.completed_kind.as_deref(), Some("drt"));
    assert_eq!(captured.completed_sequence.as_deref(), Some("1"));
    assert_eq!(captured.delegator_operations_remaining, 0);
    assert_eq!(captured.delegate_operations_remaining, 0);
    Ok(())
}
