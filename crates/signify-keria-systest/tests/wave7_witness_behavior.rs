//! Wave 7 — witness behavior: incept witnessed, rotate, cut the witness, add it back.
//!
//! Incepts witnessed, rotates, cuts the witness, and adds it back: four receipted establishments.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave7_witness_behavior -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use serde::Serialize;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::oobis::OobiResolution;
use signify_http::transport::RequestUrl;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest};
use signify_keri::prefix::IdentifierPrefix;
use signify_keria_systest::preset::WITNESS_PREFIXES;
use signify_keria_systest::{Environment, connect, progress, record, recorder, wait_and_delete};

#[derive(Debug, Serialize)]
struct Step {
    action: &'static str,
    derived_event: String,
    derived_said: String,
    agent_event: String,
    witnesses_after: Vec<String>,
    threshold_after: String,
    sequence_after: String,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    witness: String,
    prefix: String,
    steps: Vec<Step>,
    operations_remaining: usize,
    transcript: Vec<signify_keria_systest::Observation>,
}

async fn state_triple(client: &ConnectedClient, alias: &str) -> Result<(Vec<String>, String, String), Box<dyn Error>> {
    let stored = client.identifiers().get(alias).await?;
    Ok((
        stored.state.witnesses.clone(),
        stored.state.witness_threshold.clone(),
        stored.state.sequence_number.clone(),
    ))
}

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

    steps.push(rotate_step(&client, "aid1", "rotate", Vec::new(), Vec::new()).await?);
    steps.push(rotate_step(&client, "aid1", "cut", vec![witness_prefix.clone()], Vec::new()).await?);
    steps.push(rotate_step(&client, "aid1", "add", Vec::new(), vec![witness_prefix.clone()]).await?);

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
