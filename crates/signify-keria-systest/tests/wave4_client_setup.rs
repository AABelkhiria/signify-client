//! Wave 4 — client setup, single and multiple: the §7 row's remaining halves.
//!
//! Two upstream files share the **Client setup** row. `test-setup-single-client.test.ts` boots a
//! client from a *pinned* passcode and asserts the pinned controller prefix — the one place a live
//! run can confirm the port's controller derivation against a real agent's acceptance — then
//! creates a witnessed identifier and asserts the exact agent and witness OOBI URLs and the
//! agent's introduction configuration. `test-setup-clients.test.ts` boots two clients with random
//! passcodes and cross-resolves their agent OOBIs as contacts, asserting each resolution answers
//! with the other's prefix.
//!
//! Two upstream behaviours are made explicit rather than reproduced silently. The pinned passcode
//! upstream passes is **24 characters**, and the reference slices the first 21 without saying so;
//! the port's `Passcode` refuses a wrong length outright, so this scenario performs the truncation
//! itself and records both spellings. And `getOrCreateClient` *connects first and boots only when
//! that fails*, which is what lets a pinned client survive re-runs against a used deployment; the
//! same order is used here.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave4_client_setup -- --ignored --test-threads=1 --nocapture
//! ```

// After the docs: a false `#![cfg]` strips everything below it, docs included, and an
// undocumented empty crate trips `missing_docs`.
#![cfg(feature = "live")]

use std::error::Error;
use std::sync::Arc;

use serde::Serialize;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::oobis::OobiResolution;
use signify_http::retry::TokioClock;
use signify_http::transport::{HttpTransport, RequestUrl, Transport};
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::prefix::IdentifierPrefix;
use signify_keria_systest::{Environment, Recorder, progress, record};
use signify_types::api::Role;

/// The passcode exactly as `test-setup-single-client.test.ts` writes it: 24 characters, of which
/// the reference silently uses the first 21. A published test constant, not a secret.
const PINNED_PASSCODE_UPSTREAM: &str = "0ADF2TpptgqcDE5IQUF1HeTp";
/// The 21 characters the reference actually derives from, passed explicitly because the port
/// refuses to truncate a passcode silently.
const PINNED_PASSCODE: &str = "0ADF2TpptgqcDE5IQUF1H";
/// The controller prefix upstream pins for that passcode.
const PINNED_CONTROLLER_PREFIX: &str = "EB3UGWwIMq7ppzcQ697ImQIuXlBG5jzh-baSx-YG3-tY";

/// The single-client half: pinned controller, witnessed identifier, OOBI shapes, configuration.
#[derive(Debug, Serialize)]
struct PinnedClient {
    /// The passcode as upstream spells it, for provenance.
    passcode_upstream: &'static str,
    /// The 21 characters this run actually used.
    passcode_used: &'static str,
    /// The controller prefix the port derived from it.
    derived_controller_prefix: String,
    /// The prefix upstream pins.
    pinned_controller_prefix: &'static str,
    /// The agent's prefix, which the agent OOBI embeds.
    agent_prefix: String,
    /// The witnessed identifier's prefix.
    identifier_prefix: String,
    /// Whether this run created it, or found it from an earlier run of the same pinned client.
    identifier_created: bool,
    /// The agent OOBI the identifier publishes.
    agent_oobi: String,
    /// The witness OOBIs it publishes, in answer order.
    witness_oobis: Vec<String>,
    /// The agent's introduction OOBIs from `GET /config`, absent kept apart from empty.
    introduction_urls: Option<Vec<String>>,
    /// Operations left listed after the run; upstream asserts zero.
    operations_remaining: usize,
}

/// The two-client half: each resolves the other's agent OOBI and reads back a prefix.
#[derive(Debug, Serialize)]
struct CrossResolution {
    /// Client A's identifier prefix.
    a_prefix: String,
    /// Client B's identifier prefix.
    b_prefix: String,
    /// The prefix A's resolution of B's OOBI answered with; upstream asserts it equals B's.
    a_resolved_b: String,
    /// The prefix B's resolution of A's OOBI answered with.
    b_resolved_a: String,
    /// Operations left listed on A after the run.
    a_operations_remaining: usize,
    /// Operations left listed on B after the run.
    b_operations_remaining: usize,
}

/// Everything the run observed, written as the fixture.
#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    pinned: PinnedClient,
    cross: CrossResolution,
    /// The pinned client's transcript.
    pinned_transcript: Vec<signify_keria_systest::Observation>,
    /// Client A's transcript.
    a_transcript: Vec<signify_keria_systest::Observation>,
    /// Client B's transcript.
    b_transcript: Vec<signify_keria_systest::Observation>,
}

/// Builds a recording client and connects it, booting only when connecting fails — the
/// reference's `getOrCreateClient` order, which is what lets a pinned client survive re-runs.
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

/// Builds a recorder over the production transport.
fn recorder(scenario: &str) -> Result<Arc<Recorder>, Box<dyn Error>> {
    Ok(Recorder::new(scenario, Arc::new(HttpTransport::new()?)))
}

/// Waits one submission's operation out and deletes it, as the upstream helper does.
async fn wait_and_delete(client: &ConnectedClient, name: &str) -> Result<(), Box<dyn Error>> {
    let operation = client.operations().get(name).await?;
    let completed = client.poller().wait(operation).await?;
    client.operations().delete(completed.name()).await?;
    Ok(())
}

/// Gets or creates one identifier witnessed by the environment's whole triple, with the agent
/// end role — the reference's `getOrCreateIdentifier` with its `resolveEnvironment` defaults,
/// including its `hasEndRole` check: an identifier found from an earlier run may exist *without*
/// the role, when that run failed between the two steps.
async fn witnessed_identifier(
    client: &ConnectedClient,
    alias: &str,
    environment: &Environment,
) -> Result<(String, bool), Box<dyn Error>> {
    // Only an actual not-found means "create it". Any other failure — a record that does not
    // decode, above all — must surface, not be papered over by a doomed second creation; this is
    // exactly how wave 4 found `windexes` spelt as numbers.
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

    // The upstream helper checks `hasEndRole` rather than assuming; the cheapest equivalent
    // observation is whether an agent OOBI is published, since an identifier without the role
    // publishes none.
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

/// Resolves `alias`'s agent OOBI from `from` on `to`, returning the prefix the resolution
/// answered with — the reference's `getOrCreateContact` read of `response.i`.
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
    let state = completed.into_response();
    to.operations().delete(&name).await?;
    Ok(state.identifier)
}

/// The single-client half, against the pinned passcode.
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

/// The two-client half, with random passcodes.
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

    // Upstream's naming: client2 resolves name1 as contact1, client1 resolves name2 as contact2.
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

/// Compares one observed value with what the pinned scenario expects.
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

    // Record before asserting, so a diverging run still leaves the evidence of how it diverged.
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
