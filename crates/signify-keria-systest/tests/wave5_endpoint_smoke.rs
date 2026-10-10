//! Wave 5 — endpoint smoke coverage: end roles and a self-controlled mailbox.
//!
//! Grants the agent role, grants a mailbox to itself, and reads back the OOBI the agent derives.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave5_endpoint_smoke -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keri_protocol::prefix::IdentifierPrefix;
use keria_types::api::Role;
use serde::Serialize;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::identifiers::LocationSchemeRequest;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keria_systest::{Environment, connect, progress, record, recorder, wait_and_delete};

const MAILBOX_URL: &str = "https://mymailbox.com";

#[derive(Debug, Serialize)]
struct RecordedRole {
    cid: String,
    role: String,
    eid: String,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    cid: String,
    agent_prefix: String,
    agent_roles_before: usize,
    agent_roles: Vec<RecordedRole>,
    mailbox_roles: Vec<RecordedRole>,
    mailbox_oobi: String,
    operations_remaining: usize,
    transcript: Vec<signify_keria_systest::Observation>,
}

async fn roles(
    client: &ConnectedClient,
    identifier: &IdentifierPrefix,
    role: &Role,
) -> Result<Vec<RecordedRole>, Box<dyn Error>> {
    Ok(client
        .oobis()
        .end_roles(identifier, Some(role))
        .await?
        .into_iter()
        .map(|entry| RecordedRole {
            cid: entry.cid,
            role: entry.role.as_str().to_owned(),
            eid: entry.eid,
        })
        .collect())
}

fn check(mismatches: &mut Vec<String>, what: &str, observed: &str, expected: &str) {
    if observed != expected {
        mismatches.push(format!("{what}: observed {observed}, pinned {expected}"));
    }
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn end_roles_and_a_self_controlled_mailbox_authorise() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let transcript = recorder("endpoint_smoke")?;
    progress("connecting the client");
    let client = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &transcript,
    )
    .await?;
    let mut mismatches = Vec::new();

    progress("aid1: creating");
    let created = client
        .identifiers()
        .create("aid1", &CreateIdentifierRequest::new(CreateAlgorithm::salty(None)))
        .await?;
    wait_and_delete(&client, &created.operation()?.name).await?;
    let cid_prefix = created.artifact().event.identifier().clone();
    let cid = cid_prefix.qb64()?;
    let agent_prefix = client.agent().prefix().qb64()?;

    let agent_roles_before = roles(&client, &cid_prefix, &Role::Agent).await?.len();

    progress("aid1: authorising the agent role");
    let agent = client.agent().prefix().clone();
    let granted = client
        .identifiers()
        .add_end_role("aid1", &Role::Agent, Some(&agent), signify_keria_systest::now()?)
        .await?;
    wait_and_delete(&client, &granted.operation()?.name).await?;
    let agent_roles = roles(&client, &cid_prefix, &Role::Agent).await?;

    progress("aid1: authorising itself as its mailbox");
    let self_granted = client
        .identifiers()
        .add_end_role("aid1", &Role::Mailbox, Some(&cid_prefix), signify_keria_systest::now()?)
        .await?;
    wait_and_delete(&client, &self_granted.operation()?.name).await?;
    let mailbox_roles = roles(&client, &cid_prefix, &Role::Mailbox).await?;

    progress("aid1: adding the mailbox location scheme");
    let location = LocationSchemeRequest {
        url: MAILBOX_URL.to_owned(),
        scheme: Some("https".to_owned()),
        endpoint: None,
        stamp: signify_keria_systest::now()?,
    };
    let located = client.identifiers().add_location_scheme("aid1", &location).await?;
    wait_and_delete(&client, &located.operation()?.name).await?;
    let published = client.oobis().get("aid1", &Role::Mailbox).await?;
    let mailbox_oobi = published
        .oobis
        .first()
        .cloned()
        .ok_or("aid1 publishes no mailbox OOBI")?;

    check(
        &mut mismatches,
        "mailbox OOBI",
        &mailbox_oobi,
        &format!("{MAILBOX_URL}/oobi/{cid}/mailbox/{cid}"),
    );
    if agent_roles_before != 0 {
        mismatches.push(format!(
            "agent roles before the grant: {agent_roles_before}, expected 0"
        ));
    }
    if agent_roles.len() != 1 || mailbox_roles.len() != 1 {
        mismatches.push(format!(
            "expected one authorisation per role, found {} agent and {} mailbox",
            agent_roles.len(),
            mailbox_roles.len()
        ));
    }

    let operations_remaining = client.operations().list(None).await?.len();
    let captured = Captured {
        scenario: "endpoint_smoke",
        preset: environment.preset.to_string(),
        cid,
        agent_prefix,
        agent_roles_before,
        agent_roles,
        mailbox_roles,
        mailbox_oobi,
        operations_remaining,
        transcript: transcript.observations(),
    };

    if record("observations/endpoint_smoke.json", &captured)? {
        progress("recorded observations/endpoint_smoke.json");
    } else {
        progress("not a recording run, nothing written");
    }

    assert!(
        mismatches.is_empty(),
        "the run diverged from the pinned scenario: {mismatches:#?}"
    );
    assert_eq!(captured.operations_remaining, 0, "operations were left behind");
    Ok(())
}
