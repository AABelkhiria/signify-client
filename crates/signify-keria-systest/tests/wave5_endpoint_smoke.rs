//! Wave 5 — endpoint smoke coverage: end roles and a self-controlled mailbox.
//!
//! `test-integration/endpoints.test.ts` is the §7 row that exercises endpoint *authorisation* end
//! to end: an unwitnessed identifier grants the agent role, then grants the **mailbox** role to
//! itself — the one place the suite authorises an endpoint the client controls rather than the
//! agent — adds a location scheme for it, and reads back the OOBI the agent derives from the two:
//! `https://mymailbox.com/oobi/{cid}/mailbox/{cid}`, the URL joined to the role granted.
//!
//! One mapping is deliberate. The upstream case reads roles back through a test helper that
//! raw-fetches `/identifiers/{alias}/endroles/{role}` — the reference SDK itself exposes no such
//! read — while this port reads `/endroles/{aid}/{role}`, Roadmap 7.1's `Oobis::end_roles`, which
//! is the same authorisations addressed by AID. The assertions are about the triples that come
//! back, and those must agree wherever they are read from.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave5_endpoint_smoke -- --ignored --test-threads=1 --nocapture
//! ```

// After the docs: a false `#![cfg]` strips everything below it, docs included, and an
// undocumented empty crate trips `missing_docs`.
#![cfg(feature = "live")]

use std::error::Error;

use serde::Serialize;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::identifiers::LocationSchemeRequest;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::prefix::IdentifierPrefix;
use signify_keria_systest::{Environment, connect, progress, record, recorder};
use signify_types::api::Role;

/// The location the upstream case authorises for its mailbox.
const MAILBOX_URL: &str = "https://mymailbox.com";

/// One end-role triple as the agent answered it, flattened for the fixture.
#[derive(Debug, Serialize)]
struct RecordedRole {
    cid: String,
    role: String,
    eid: String,
}

/// Everything the run observed, written as the fixture.
#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    /// The identifier granting the roles; upstream's `cid`.
    cid: String,
    /// The agent's prefix, the first grant's `eid`.
    agent_prefix: String,
    /// How many agent-role authorisations existed before anything was granted.
    agent_roles_before: usize,
    /// The agent-role authorisations after the grant.
    agent_roles: Vec<RecordedRole>,
    /// The mailbox-role authorisations after the self-grant.
    mailbox_roles: Vec<RecordedRole>,
    /// The OOBI the agent derives from the mailbox role plus the location scheme.
    mailbox_oobi: String,
    /// Operations left listed after the run; upstream waits and deletes every one.
    operations_remaining: usize,
    transcript: Vec<signify_keria_systest::Observation>,
}

/// Waits one submission's operation out and deletes it, as the upstream helper does.
async fn wait_and_delete(client: &ConnectedClient, name: &str) -> Result<(), Box<dyn Error>> {
    let operation = client.operations().get(name).await?;
    let completed = client.poller().wait(operation).await?;
    client.operations().delete(completed.name()).await?;
    Ok(())
}

/// Reads one role's authorisations back as flat triples.
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

/// Compares one observed value with what the pinned scenario expects.
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

    // An unwitnessed identifier, as the upstream case creates it — and no end role yet, because
    // granting the agent role is the observation under test.
    progress("aid1: creating");
    let created = client
        .identifiers()
        .create("aid1", &CreateIdentifierRequest::new(CreateAlgorithm::salty(None)))
        .await?;
    wait_and_delete(&client, &created.operation()?.name).await?;
    let cid_prefix = created.artifact().event.identifier().clone();
    let cid = cid_prefix.qb64()?;
    let agent_prefix = client.agent().prefix().qb64()?;

    // Upstream's first assertion: no agent-role authorisation exists yet.
    let agent_roles_before = roles(&client, &cid_prefix, &Role::Agent).await?.len();

    // Grant the agent role, and read back exactly one triple naming the agent.
    progress("aid1: authorising the agent role");
    let agent = client.agent().prefix().clone();
    let granted = client
        .identifiers()
        .add_end_role("aid1", &Role::Agent, Some(&agent), signify_keria_systest::now()?)
        .await?;
    wait_and_delete(&client, &granted.operation()?.name).await?;
    let agent_roles = roles(&client, &cid_prefix, &Role::Agent).await?;

    // Grant the mailbox role to the identifier itself — upstream's "endpoint we control", where
    // cid and eid are deliberately the same prefix.
    progress("aid1: authorising itself as its mailbox");
    let self_granted = client
        .identifiers()
        .add_end_role("aid1", &Role::Mailbox, Some(&cid_prefix), signify_keria_systest::now()?)
        .await?;
    wait_and_delete(&client, &self_granted.operation()?.name).await?;
    let mailbox_roles = roles(&client, &cid_prefix, &Role::Mailbox).await?;

    // Add the location scheme, and read back the OOBI the agent joins from the two.
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

    // Record before asserting, so a diverging run still leaves the evidence of how it diverged.
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
