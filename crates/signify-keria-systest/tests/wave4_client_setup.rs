//! Wave 4 — client setup, single and multiple: the scenario-table row's remaining halves.
//!
//! Drives both setup files: a pinned passcode, a witnessed identifier's OOBIs, and two clients meeting.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave4_client_setup -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;
use std::sync::Arc;

use keri_protocol::prefix::IdentifierPrefix;
use keria_types::api::Role;
use serde::Serialize;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::oobis::OobiResolution;
use signify_http::retry::TokioClock;
use signify_http::transport::{HttpTransport, RequestUrl, Transport};
use signify_keria_systest::{Environment, Recorder, progress, record, wait_and_delete};
use signify_keys::identifier::{CreateAlgorithm, CreateIdentifierRequest};

const PINNED_PASSCODE_UPSTREAM: &str = "0ADF2TpptgqcDE5IQUF1HeTp";
const PINNED_PASSCODE: &str = "0ADF2TpptgqcDE5IQUF1H";
const PINNED_CONTROLLER_PREFIX: &str = "EB3UGWwIMq7ppzcQ697ImQIuXlBG5jzh-baSx-YG3-tY";

#[derive(Debug, Serialize)]
struct PinnedClient {
    passcode_upstream: &'static str,
    passcode_used: &'static str,
    derived_controller_prefix: String,
    pinned_controller_prefix: &'static str,
    agent_prefix: String,
    identifier_prefix: String,
    identifier_created: bool,
    agent_oobi: String,
    witness_oobis: Vec<String>,
    introduction_urls: Option<Vec<String>>,
    operations_remaining: usize,
}

#[derive(Debug, Serialize)]
struct CrossResolution {
    a_prefix: String,
    b_prefix: String,
    a_resolved_b: String,
    b_resolved_a: String,
    a_operations_remaining: usize,
    b_operations_remaining: usize,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    pinned: PinnedClient,
    cross: CrossResolution,
    pinned_transcript: Vec<signify_keria_systest::Observation>,
    a_transcript: Vec<signify_keria_systest::Observation>,
    b_transcript: Vec<signify_keria_systest::Observation>,
}

async fn connect_or_boot(
    environment: &Environment,
    passcode: &str,
    recorder: &Arc<Recorder>,
) -> Result<ConnectedClient, Box<dyn Error>> {
    let build = || -> Result<SignifyClient, Box<dyn Error>> {
        let config = ClientConfig::new(&environment.admin_url, passcode)?.with_boot_url(&environment.boot_url)?;
        let transport = Arc::clone(recorder) as Arc<dyn Transport>;
        Ok(SignifyClient::new(config, transport, Arc::new(TokioClock))?)
    };
    if let Ok(connected) = build()?.connect().await {
        return Ok(connected);
    }
    let client = build()?;
    client.boot().await?;
    Ok(client.connect().await?)
}

fn recorder(scenario: &str) -> Result<Arc<Recorder>, Box<dyn Error>> {
    Ok(Recorder::new(scenario, Arc::new(HttpTransport::new()?)))
}

async fn witnessed_identifier(
    client: &ConnectedClient,
    alias: &str,
    environment: &Environment,
) -> Result<(String, bool), Box<dyn Error>> {
    let (prefix, created) = match client.identifiers().get(alias).await {
        Ok(existing) => {
            progress(&format!("{alias}: found from an earlier run"));
            (existing.common.prefix.clone(), false)
        }
        Err(signify_client::error::ClientError::Status { status: 404, .. }) => {
            let mut request = CreateIdentifierRequest::new(CreateAlgorithm::salty(None));
            request.witnesses = environment
                .witness_prefixes
                .iter()
                .map(|prefix| IdentifierPrefix::from_qb64(prefix))
                .collect::<Result<Vec<_>, _>>()?;
            request.witness_threshold = u32::try_from(environment.witness_prefixes.len())?;

            progress(&format!("{alias}: creating with the witness triple"));
            let submitted = client.identifiers().create(alias, &request).await?;
            wait_and_delete(client, &submitted.operation()?.name).await?;
            (submitted.artifact().event.identifier().qb64()?, true)
        }
        Err(error) => return Err(error.into()),
    };

    let needs_role = created || client.oobis().get(alias, &Role::Agent).await?.oobis.is_empty();
    if needs_role {
        progress(&format!("{alias}: authorising the agent end role"));
        let agent = client.agent().prefix().clone();
        let authorised = client
            .identifiers()
            .add_end_role(alias, &Role::Agent, Some(&agent), signify_keria_systest::now()?)
            .await?;
        wait_and_delete(client, &authorised.operation()?.name).await?;
    }
    Ok((prefix, created))
}

async fn resolve_contact(
    from: &ConnectedClient,
    alias: &str,
    to: &ConnectedClient,
    contact_alias: &str,
) -> Result<String, Box<dyn Error>> {
    let published = from.oobis().get(alias, &Role::Agent).await?;
    let url = published
        .oobis
        .first()
        .ok_or_else(|| format!("{alias} published no OOBI, so it cannot be resolved"))?;
    progress(&format!("resolving {alias}'s agent OOBI as {contact_alias}"));
    let resolution = OobiResolution {
        url: RequestUrl::new(url.clone())?,
        alias: Some(contact_alias.to_owned()),
    };
    let resolved = to.oobis().resolve(&resolution).await?;
    let completed = to.poller().wait(resolved).await?;
    let name = completed.name().to_owned();
    let resolved = completed.into_response();
    to.operations().delete(&name).await?;
    let state = resolved.into_key_state().ok_or("the OOBI introduced no controller")?;
    Ok(state.identifier)
}

async fn pinned_half(
    environment: &Environment,
) -> Result<(PinnedClient, Vec<signify_keria_systest::Observation>), Box<dyn Error>> {
    let transcript = recorder("client_setup_pinned")?;
    progress("connecting the pinned client");
    let client = connect_or_boot(environment, PINNED_PASSCODE, &transcript).await?;

    let derived_controller_prefix = client.controller().prefix().qb64()?;
    let agent_prefix = client.agent().prefix().qb64()?;

    let (identifier_prefix, identifier_created) = witnessed_identifier(&client, "name1", environment).await?;

    let agent = client.oobis().get("name1", &Role::Agent).await?;
    let agent_oobi = agent.oobis.first().cloned().ok_or("name1 publishes no agent OOBI")?;
    let witnesses = client.oobis().get("name1", &Role::Witness).await?;

    let configuration = client.agent_config().get().await?;
    let operations_remaining = client.operations().list(None).await?.len();

    Ok((
        PinnedClient {
            passcode_upstream: PINNED_PASSCODE_UPSTREAM,
            passcode_used: PINNED_PASSCODE,
            derived_controller_prefix,
            pinned_controller_prefix: PINNED_CONTROLLER_PREFIX,
            agent_prefix,
            identifier_prefix,
            identifier_created,
            agent_oobi,
            witness_oobis: witnesses.oobis,
            introduction_urls: configuration.introduction_urls,
            operations_remaining,
        },
        transcript.observations(),
    ))
}

async fn cross_half(
    environment: &Environment,
) -> Result<
    (
        CrossResolution,
        Vec<signify_keria_systest::Observation>,
        Vec<signify_keria_systest::Observation>,
    ),
    Box<dyn Error>,
> {
    let a_transcript = recorder("client_setup_a")?;
    progress("connecting client A");
    let a = connect_or_boot(
        environment,
        signify_client::random::random_passcode()?.expose(),
        &a_transcript,
    )
    .await?;
    let b_transcript = recorder("client_setup_b")?;
    progress("connecting client B");
    let b = connect_or_boot(
        environment,
        signify_client::random::random_passcode()?.expose(),
        &b_transcript,
    )
    .await?;

    let (a_prefix, _) = witnessed_identifier(&a, "name1", environment).await?;
    let (b_prefix, _) = witnessed_identifier(&b, "name2", environment).await?;

    let b_resolved_a = resolve_contact(&a, "name1", &b, "contact1").await?;
    let a_resolved_b = resolve_contact(&b, "name2", &a, "contact2").await?;

    let a_operations_remaining = a.operations().list(None).await?.len();
    let b_operations_remaining = b.operations().list(None).await?.len();

    Ok((
        CrossResolution {
            a_prefix,
            b_prefix,
            a_resolved_b,
            b_resolved_a,
            a_operations_remaining,
            b_operations_remaining,
        },
        a_transcript.observations(),
        b_transcript.observations(),
    ))
}

fn check(mismatches: &mut Vec<String>, what: &str, observed: &str, expected: &str) {
    if observed != expected {
        mismatches.push(format!("{what}: observed {observed}, pinned {expected}"));
    }
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn client_setup_reproduces_the_pinned_controller_and_cross_resolves() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let mut mismatches = Vec::new();

    let (pinned, pinned_transcript) = Box::pin(pinned_half(&environment)).await?;
    check(
        &mut mismatches,
        "controller prefix",
        &pinned.derived_controller_prefix,
        PINNED_CONTROLLER_PREFIX,
    );
    if pinned.witness_oobis.len() != environment.witness_prefixes.len() {
        mismatches.push(format!(
            "witness OOBIs: observed {}, expected {}",
            pinned.witness_oobis.len(),
            environment.witness_prefixes.len()
        ));
    }
    for (oobi, prefix) in pinned.witness_oobis.iter().zip(&environment.witness_prefixes) {
        if !oobi.ends_with(&format!("/witness/{prefix}")) {
            mismatches.push(format!(
                "witness OOBI {oobi} does not name the expected witness {prefix}"
            ));
        }
    }
    let expected_agent_suffix = format!("/oobi/{}/agent/{}", pinned.identifier_prefix, pinned.agent_prefix);
    if !pinned.agent_oobi.ends_with(&expected_agent_suffix) {
        mismatches.push(format!(
            "agent OOBI {} does not end with {expected_agent_suffix}",
            pinned.agent_oobi
        ));
    }

    let (cross, a_transcript, b_transcript) = Box::pin(cross_half(&environment)).await?;
    check(
        &mut mismatches,
        "A's resolution of B",
        &cross.a_resolved_b,
        &cross.b_prefix,
    );
    check(
        &mut mismatches,
        "B's resolution of A",
        &cross.b_resolved_a,
        &cross.a_prefix,
    );

    let captured = Captured {
        scenario: "client_setup",
        preset: environment.preset.to_string(),
        pinned,
        cross,
        pinned_transcript,
        a_transcript,
        b_transcript,
    };

    if record("observations/client_setup.json", &captured)? {
        progress("recorded observations/client_setup.json");
    } else {
        progress("not a recording run, nothing written");
    }

    assert!(
        mismatches.is_empty(),
        "the run diverged from the pinned scenario: {mismatches:#?}"
    );
    assert_eq!(
        captured.pinned.operations_remaining, 0,
        "the pinned client left operations behind"
    );
    assert_eq!(
        captured.cross.a_operations_remaining, 0,
        "client A left operations behind"
    );
    assert_eq!(
        captured.cross.b_operations_remaining, 0,
        "client B left operations behind"
    );
    Ok(())
}
