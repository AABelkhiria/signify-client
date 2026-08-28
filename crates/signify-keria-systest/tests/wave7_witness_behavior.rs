//! Wave 7 — witness behavior: incept witnessed, rotate, cut the witness, add it back.
//!
//! `test-integration/witness.test.ts` is the only upstream scenario that exercises a witness
//! receipt end to end *through change*: an identifier incepts with one witness at threshold one,
//! rotates while keeping it, rotates it **out** with a cut, and rotates it back **in** with an
//! add — four establishment events, each of which the agent completes only once the witness set
//! it names has receipted it. The observation after every step is the key state's witness list,
//! read back from the agent.
//!
//! The witness is Wan, `BBilc4…`, whose controller OOBI the client resolves first exactly as the
//! upstream case does — from the URL **as KERIA reaches it**, because the agent is the one who
//! fetches it (the preset records this distinction; the reference's own file never says so).
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave7_witness_behavior -- --ignored --test-threads=1 --nocapture
//! ```

// After the docs: a false `#![cfg]` strips everything below it, docs included, and an
// undocumented empty crate trips `missing_docs`.
#![cfg(feature = "live")]

use std::error::Error;

use serde::Serialize;
use serde_json::Value;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::oobis::OobiResolution;
use signify_http::transport::RequestUrl;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest};
use signify_keri::prefix::IdentifierPrefix;
use signify_keria_systest::preset::WITNESS_PREFIXES;
use signify_keria_systest::{Environment, connect, progress, record, recorder};

/// One establishment event and the witness state the agent reported after it.
#[derive(Debug, Serialize)]
struct Step {
    /// What this step did: `incept`, `rotate`, `cut`, or `add`.
    action: &'static str,
    /// The event exactly as the port serialized and signed it.
    derived_event: String,
    derived_said: String,
    /// The agent's echo from the completed operation.
    agent_event: String,
    /// The key state's witness list after the operation completed.
    witnesses_after: Vec<String>,
    /// The key state's witness threshold after the operation completed.
    threshold_after: String,
    /// The key state's sequence number after the operation completed.
    sequence_after: String,
}

/// Everything the run observed, written as the fixture.
#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    /// The witness whose membership changes; Wan of the demo triple.
    witness: String,
    /// The identifier under test.
    prefix: String,
    steps: Vec<Step>,
    /// Operations left listed after the run; upstream waits every one out.
    operations_remaining: usize,
    transcript: Vec<signify_keria_systest::Observation>,
}

/// Waits one submission's operation out, deletes it, and returns the agent's echoed event.
async fn wait_and_delete(client: &ConnectedClient, name: &str) -> Result<Value, Box<dyn Error>> {
    let operation = client.operations().get(name).await?;
    let completed = client.poller().wait(operation).await?;
    let (name, _metadata, response) = completed.into_parts();
    client.operations().delete(&name).await?;
    Ok(response)
}

/// Reads the key state's witness list, threshold, and sequence back for `alias`.
async fn state_triple(client: &ConnectedClient, alias: &str) -> Result<(Vec<String>, String, String), Box<dyn Error>> {
    let stored = client.identifiers().get(alias).await?;
    Ok((
        stored.state.witnesses.clone(),
        stored.state.witness_threshold.clone(),
        stored.state.sequence_number.clone(),
    ))
}

/// Rotates `alias` with the given cuts and adds, capturing the event and the state after it.
async fn rotate_step(
    client: &ConnectedClient,
    alias: &str,
    action: &'static str,
    cuts: Vec<IdentifierPrefix>,
    adds: Vec<IdentifierPrefix>,
) -> Result<Step, Box<dyn Error>> {
    progress(&format!("{alias}: {action}"));
    let request = RotateIdentifierRequest {
        witness_cuts: cuts,
        witness_adds: adds,
        ..RotateIdentifierRequest::default()
    };
    let rotated = client.identifiers().rotate(alias, &request).await?;
    let response = wait_and_delete(client, &rotated.operation()?.name).await?;
    let (witnesses_after, threshold_after, sequence_after) = state_triple(client, alias).await?;
    Ok(Step {
        action,
        derived_event: String::from_utf8(rotated.artifact().event.raw().to_vec())?,
        derived_said: rotated.artifact().event.said().qb64()?,
        agent_event: serde_json::to_string(&response)?,
        witnesses_after,
        threshold_after,
        sequence_after,
    })
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn a_witness_is_kept_cut_and_added_back() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let witness = WITNESS_PREFIXES
        .first()
        .map(|prefix| (*prefix).to_owned())
        .ok_or("the preset names no witnesses")?;
    let witness_prefix = IdentifierPrefix::from_qb64(&witness)?;

    let transcript = recorder("witness_behavior")?;
    progress("connecting the client");
    let client = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &transcript,
    )
    .await?;

    // Resolve the witness's controller OOBI, as the upstream case does before anything else. The
    // URL is the witness's address as KERIA reaches it, because the agent does the fetching.
    let witness_url = environment
        .witness_urls
        .first()
        .ok_or("the environment names no witness URLs")?;
    progress("resolving the witness controller OOBI");
    let resolution = OobiResolution {
        url: RequestUrl::new(format!("{witness_url}/oobi/{witness}"))?,
        alias: Some("wit".to_owned()),
    };
    let resolved = client.oobis().resolve(&resolution).await?;
    let completed = client.poller().wait(resolved).await?;
    let resolved_name = completed.name().to_owned();
    client.operations().delete(&resolved_name).await?;

    // Incept with that one witness at threshold one, and wait for its receipt.
    progress("aid1: creating with one witness at threshold one");
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::salty(None));
    request.witnesses = vec![witness_prefix.clone()];
    request.witness_threshold = 1;
    let created = client.identifiers().create("aid1", &request).await?;
    let response = wait_and_delete(&client, &created.operation()?.name).await?;
    let prefix = created.artifact().event.identifier().qb64()?;
    let (witnesses_after, threshold_after, sequence_after) = state_triple(&client, "aid1").await?;
    let mut steps = vec![Step {
        action: "incept",
        derived_event: String::from_utf8(created.artifact().event.raw().to_vec())?,
        derived_said: created.artifact().event.said().qb64()?,
        agent_event: serde_json::to_string(&response)?,
        witnesses_after,
        threshold_after,
        sequence_after,
    }];

    // Rotate keeping the witness, rotate it out, rotate it back in.
    steps.push(rotate_step(&client, "aid1", "rotate", Vec::new(), Vec::new()).await?);
    steps.push(rotate_step(&client, "aid1", "cut", vec![witness_prefix.clone()], Vec::new()).await?);
    steps.push(rotate_step(&client, "aid1", "add", Vec::new(), vec![witness_prefix.clone()]).await?);

    // The upstream case's assertions, checked before recording so a divergence is loud — but the
    // recording happens either way, so a diverging run still leaves its evidence.
    let witness_sets: Vec<&[String]> = steps.iter().map(|step| step.witnesses_after.as_slice()).collect();
    let expected: Vec<Vec<String>> = vec![
        vec![witness.clone()],
        vec![witness.clone()],
        Vec::new(),
        vec![witness.clone()],
    ];
    let observed: Vec<Vec<String>> = witness_sets.iter().map(|set| set.to_vec()).collect();

    let operations_remaining = client.operations().list(None).await?.len();
    let captured = Captured {
        scenario: "witness_behavior",
        preset: environment.preset.to_string(),
        witness,
        prefix,
        steps,
        operations_remaining,
        transcript: transcript.observations(),
    };
    if record("observations/witness_behavior.json", &captured)? {
        progress("recorded observations/witness_behavior.json");
    } else {
        progress("not a recording run, nothing written");
    }

    assert_eq!(
        observed, expected,
        "the witness sets did not evolve as the upstream case asserts"
    );
    assert_eq!(captured.operations_remaining, 0, "operations were left behind");
    Ok(())
}
