//! Wave 8 — single-signature rotation and interaction: the local/remote key-state divergence.
//!
//! `test-integration/singlesig-rot.test.ts` and `singlesig-ixn.test.ts` are twins, and together
//! they are two §7 rows. Each has one client advance a witnessed identifier's log by one event —
//! a rotation in one file, an interaction in the other — and then observes the same thing from
//! two sides: the owner's key state has moved, while a second client that resolved the identifier
//! as a contact still holds the *old* state, one sequence behind, until it refreshes with
//! `keyStates().query` at the new sequence number.
//!
//! That query is the call whose base wave 1 settled: the upstream twins forward the key state's
//! own `s` — hexadecimal text — verbatim, so they are the one recorded call site that is correct
//! above sequence nine, and [`QuerySequence::Hexadecimal`] is how this port spells the same
//! request. The interaction also shows the anchor contrast to waves 3 and 6: upstream passes
//! `{}`, an empty object, which **is** representable as a `Sad` — so this wave's interaction
//! reproduces upstream's anchor exactly where the salty and randy waves could not.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave8_singlesig_events -- --ignored --test-threads=1 --nocapture
//! ```

// After the docs: a false `#![cfg]` strips everything below it, docs included, and an
// undocumented empty crate trips `missing_docs`.
#![cfg(feature = "live")]

use std::error::Error;

use serde::Serialize;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::key_states::{KeyStateQuery, QuerySequence};
use signify_client::endpoint::oobis::OobiResolution;
use signify_http::transport::RequestUrl;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::serialization::Sad;
use signify_keria_systest::{Environment, Recorder, connect, progress, record, recorder};
use signify_types::api::Role;

/// The slice of a key state the twins assert about.
#[derive(Debug, Serialize)]
struct StateBrief {
    sequence: String,
    signing_key: String,
    next_digest: String,
}

/// Everything one twin's run observed, written as its fixture.
#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    /// The witnessed identifier under test.
    prefix: String,
    /// The prefix the second client's contact resolution answered with; upstream asserts equality.
    contact_resolved: String,
    /// Local and remote sequences before the event; upstream asserts they match.
    local_before: StateBrief,
    remote_before_sequence: String,
    /// The event that advanced the log, as the port serialized it and as the agent echoed it.
    derived_event: String,
    derived_said: String,
    agent_event: String,
    /// The owner's state after the event.
    local_after: StateBrief,
    /// The second client's stale state after the event — one sequence behind.
    remote_stale_sequence: String,
    /// The exact sequence text the refresh query sent; hexadecimal, wave 1's answer.
    query_sequence_sent: String,
    /// The state the refresh query resolved to.
    refreshed: StateBrief,
    /// Operations left listed on each client after the run; upstream asserts zero.
    owner_operations_remaining: usize,
    observer_operations_remaining: usize,
    owner_transcript: Vec<signify_keria_systest::Observation>,
    observer_transcript: Vec<signify_keria_systest::Observation>,
}

/// Waits one submission's untyped operation out, deletes it, and returns the agent's echo.
async fn wait_and_delete(client: &ConnectedClient, name: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let operation = client.operations().get(name).await?;
    let completed = client.poller().wait(operation).await?;
    let (name, _metadata, response) = completed.into_parts();
    client.operations().delete(&name).await?;
    Ok(response)
}

/// Creates a witnessed identifier with the agent end role — the upstream helper's defaults.
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

    progress(&format!("{alias}: authorising the agent end role"));
    let agent = client.agent().prefix().clone();
    let authorised = client
        .identifiers()
        .add_end_role(alias, &Role::Agent, Some(&agent), signify_keria_systest::now()?)
        .await?;
    wait_and_delete(client, &authorised.operation()?.name).await?;
    Ok(prefix)
}

/// Resolves `alias`'s agent OOBI on `observer` and returns the prefix the resolution answered.
async fn resolve_contact(
    owner: &ConnectedClient,
    alias: &str,
    observer: &ConnectedClient,
) -> Result<String, Box<dyn Error>> {
    let published = owner.oobis().get(alias, &Role::Agent).await?;
    let url = published
        .oobis
        .first()
        .ok_or_else(|| format!("{alias} published no OOBI"))?;
    progress(&format!("resolving {alias} as contact1"));
    let resolution = OobiResolution {
        url: RequestUrl::new(url.clone())?,
        alias: Some("contact1".to_owned()),
    };
    let resolved = observer.oobis().resolve(&resolution).await?;
    let completed = observer.poller().wait(resolved).await?;
    let name = completed.name().to_owned();
    let state = completed.into_response();
    observer.operations().delete(&name).await?;
    Ok(state.identifier)
}

/// Reads the sole key state one client holds for `prefix`, as a brief.
async fn state_brief(client: &ConnectedClient, prefix: &IdentifierPrefix) -> Result<StateBrief, Box<dyn Error>> {
    let states = client.key_states().get(prefix).await?;
    let state = match states.as_slice() {
        [state] => state,
        other => return Err(format!("expected one key state, found {}", other.len()).into()),
    };
    Ok(StateBrief {
        sequence: state.sequence_number.clone(),
        signing_key: state.signing_keys.first().cloned().unwrap_or_default(),
        next_digest: state.next_key_digests.first().cloned().unwrap_or_default(),
    })
}

/// Which twin is running.
#[derive(Clone, Copy)]
enum Advance {
    Rotate,
    Interact,
}

/// Runs one twin end to end and returns its capture and its mismatches.
async fn run_twin(advance: Advance) -> Result<(Captured, Vec<String>), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let scenario = match advance {
        Advance::Rotate => "singlesig_rot",
        Advance::Interact => "singlesig_ixn",
    };
    let owner_transcript: std::sync::Arc<Recorder> = recorder(scenario)?;
    progress("connecting the owner client");
    let owner = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &owner_transcript,
    )
    .await?;
    let observer_transcript = recorder("observer")?;
    progress("connecting the observer client");
    let observer = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &observer_transcript,
    )
    .await?;

    let prefix = witnessed_identifier(&owner, "name1", &environment).await?;
    let contact_resolved = resolve_contact(&owner, "name1", &observer).await?;

    let mut mismatches = Vec::new();
    let local_before = state_brief(&owner, &prefix).await?;
    let remote_before = state_brief(&observer, &prefix).await?;
    if local_before.sequence != remote_before.sequence {
        mismatches.push(format!(
            "sequences disagree before the event: local {}, remote {}",
            local_before.sequence, remote_before.sequence
        ));
    }

    // Advance the log by one event. The interaction's `{}` anchor is upstream's own, and unlike
    // the bare-string anchors of waves 3 and 6 it is representable, so it is reproduced exactly.
    let submitted = match advance {
        Advance::Rotate => {
            progress("name1: rotating");
            owner
                .identifiers()
                .rotate("name1", &RotateIdentifierRequest::default())
                .await?
        }
        Advance::Interact => {
            progress("name1: interacting with the empty anchor");
            owner.identifiers().interact("name1", vec![Sad::new()]).await?
        }
    };
    let echoed = wait_and_delete(&owner, &submitted.operation()?.name).await?;
    let derived_event = String::from_utf8(submitted.artifact().event.raw().to_vec())?;
    let derived_said = submitted.artifact().event.said().qb64()?;
    let agent_event = serde_json::to_string(&echoed)?;

    let local_after = state_brief(&owner, &prefix).await?;
    let remote_stale = state_brief(&observer, &prefix).await?;

    // Refresh the observer at the owner's new sequence — the key state's own `s` is hexadecimal
    // text, and wave 1 proved the agent reads the query in that base.
    let sequence_value = u64::from_str_radix(&local_after.sequence, 16)?;
    let query_sequence = QuerySequence::Hexadecimal(sequence_value);
    let query_sequence_sent = query_sequence.to_text();
    progress("observer: refreshing the remote key state");
    let query = KeyStateQuery::at(prefix.clone(), query_sequence);
    let queried = observer.key_states().query(&query).await?;
    let completed = observer.poller().wait(queried).await?;
    let name = completed.name().to_owned();
    let refreshed_state = completed.into_response();
    observer.operations().delete(&name).await?;
    let refreshed = StateBrief {
        sequence: refreshed_state.sequence_number.clone(),
        signing_key: refreshed_state.signing_keys.first().cloned().unwrap_or_default(),
        next_digest: refreshed_state.next_key_digests.first().cloned().unwrap_or_default(),
    };

    let captured = Captured {
        scenario,
        preset: environment.preset.to_string(),
        prefix: prefix.qb64()?,
        contact_resolved,
        local_before,
        remote_before_sequence: remote_before.sequence,
        derived_event,
        derived_said,
        agent_event,
        local_after,
        remote_stale_sequence: remote_stale.sequence,
        query_sequence_sent,
        refreshed,
        owner_operations_remaining: owner.operations().list(None).await?.len(),
        observer_operations_remaining: observer.operations().list(None).await?.len(),
        owner_transcript: owner_transcript.observations(),
        observer_transcript: observer_transcript.observations(),
    };
    Ok((captured, mismatches))
}

/// The assertions both twins share, checked after recording.
fn shared_assertions(captured: &Captured, mismatches: &mut Vec<String>) {
    if captured.contact_resolved != captured.prefix {
        mismatches.push("the contact resolution answered a different prefix".to_owned());
    }
    let before = u64::from_str_radix(&captured.local_before.sequence, 16).unwrap_or(u64::MAX);
    let after = u64::from_str_radix(&captured.local_after.sequence, 16).unwrap_or(0);
    if after != before + 1 {
        mismatches.push(format!(
            "the local sequence did not increment: {} then {}",
            captured.local_before.sequence, captured.local_after.sequence
        ));
    }
    if captured.remote_stale_sequence != captured.local_before.sequence {
        mismatches.push(format!(
            "the remote state is not one behind: stale {}, was {}",
            captured.remote_stale_sequence, captured.local_before.sequence
        ));
    }
    if captured.refreshed.sequence != captured.local_after.sequence {
        mismatches.push(format!(
            "the refresh did not catch up: {} against {}",
            captured.refreshed.sequence, captured.local_after.sequence
        ));
    }
    if captured.owner_operations_remaining != 0 || captured.observer_operations_remaining != 0 {
        mismatches.push("operations were left behind".to_owned());
    }
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn a_rotation_is_seen_remotely_only_after_a_refresh() -> Result<(), Box<dyn Error>> {
    let (captured, mut mismatches) = Box::pin(run_twin(Advance::Rotate)).await?;
    shared_assertions(&captured, &mut mismatches);

    // The rotation's own claims: the keys moved locally, and the refreshed remote state carries
    // exactly the new key and commitment.
    if captured.local_after.signing_key == captured.local_before.signing_key {
        mismatches.push("the rotation kept the signing key".to_owned());
    }
    if captured.local_after.next_digest == captured.local_before.next_digest {
        mismatches.push("the rotation kept the next-key digest".to_owned());
    }
    if captured.refreshed.signing_key != captured.local_after.signing_key
        || captured.refreshed.next_digest != captured.local_after.next_digest
    {
        mismatches.push("the refreshed remote state does not match the local one".to_owned());
    }

    if record("observations/singlesig_rot.json", &captured)? {
        progress("recorded observations/singlesig_rot.json");
    } else {
        progress("not a recording run, nothing written");
    }
    assert!(mismatches.is_empty(), "the run diverged: {mismatches:#?}");
    Ok(())
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn an_interaction_is_seen_remotely_only_after_a_refresh() -> Result<(), Box<dyn Error>> {
    let (captured, mut mismatches) = Box::pin(run_twin(Advance::Interact)).await?;
    shared_assertions(&captured, &mut mismatches);

    // An interaction changes no keys: the local state keeps both, and so does the refresh.
    if captured.local_after.signing_key != captured.local_before.signing_key {
        mismatches.push("the interaction changed the signing key".to_owned());
    }
    if captured.refreshed.signing_key != captured.local_after.signing_key {
        mismatches.push("the refreshed remote state does not match the local one".to_owned());
    }

    if record("observations/singlesig_ixn.json", &captured)? {
        progress("recorded observations/singlesig_ixn.json");
    } else {
        progress("not a recording run, nothing written");
    }
    assert!(mismatches.is_empty(), "the run diverged: {mismatches:#?}");
    Ok(())
}
