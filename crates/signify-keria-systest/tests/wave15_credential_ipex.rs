//! Wave 15 — the credential lifecycle and the IPEX conversation, single-signature.
//!
//! Registry, issuance, the reads, an unsolicited grant, the verifier's apply/offer/agree/disclose
//! round, revocation, and deletion — the whole of `test-integration/credentials.test.ts`'s subject
//! driven through this port's helpers against a live deployment.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_KERIA_SCHEMA_URL=http://localhost:3001 SIGNIFY_RECORD=1 \
//!     cargo test -p signify-keria-systest --features live \
//!     --test wave15_credential_ipex -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadValue};
use serde::Serialize;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::credentials::CredentialFilter;
use signify_client::presentation::disclosure_of;
use signify_keria_systest::singlesig::{
    admit_credential, agree_to_offer, apply_for_credential, await_ipex_step, build_credential, create_identifier,
    create_registry, credential_state, delete_credential, disclose_credential, get_credential, grant_credential,
    issue_credential, list_credentials, offer_credential, revoke_credential,
};
use signify_keria_systest::{
    Environment, agent_oobi, connect, progress, record, recorder, resolve_oobi, resolve_schema,
};
use signify_keys::acdc::ipex::IpexRoute;

/// The Qualified vLEI Issuer schema, which the vLEI server and the Veridian credential server both
/// serve under the same SAID — the schemas are byte-identical, so the SAID is too.
const QVI_SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/// The LEI the upstream case issues against.
const LEI: &str = "5493001KJTIIGC8Y1R17";

/// Everything the run observed, written as the fixture.
#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    schema: String,
    issuer_prefix: String,
    holder_prefix: String,
    verifier_prefix: String,
    registry: String,
    credential_said: String,
    /// The credential as the issuer reads it back, and the LEI it carries.
    issuer_reads_lei: Option<String>,
    /// How many the issuer lists unfiltered, and how many under a schema filter.
    listed_all: usize,
    listed_by_schema: usize,
    /// The registry status before and after the revocation: `iss` then `rev`.
    state_after_issue: String,
    state_after_revoke: String,
    /// Whether the holder holds the credential after admitting the unsolicited grant.
    holder_admitted: bool,
    /// The five IPEX messages of the verifier's round, by SAID.
    apply_said: String,
    offer_said: String,
    agree_said: String,
    disclose_said: String,
    verifier_admit_said: String,
    /// Whether the issuer's copy was deleted at the end.
    deleted: bool,
    operations_remaining: Vec<usize>,
    issuer_transcript: Vec<signify_keria_systest::Observation>,
    holder_transcript: Vec<signify_keria_systest::Observation>,
    verifier_transcript: Vec<signify_keria_systest::Observation>,
}

/// Introduces `from`'s identifier to `to`, the way a stranger would learn it.
async fn introduce(from: &ConnectedClient, alias: &str, to: &ConnectedClient) -> Result<(), Box<dyn Error>> {
    let url = agent_oobi(from, alias).await?;
    resolve_oobi(to, &url, alias).await?;
    Ok(())
}

/// Counts the operations a client has left, which upstream requires to be none.
async fn operations_remaining(client: &ConnectedClient) -> Result<usize, Box<dyn Error>> {
    Ok(client.operations().list(None).await?.len())
}

#[tokio::test]
#[ignore = "requires a live KERIA and a schema server; see the crate documentation"]
async fn a_credential_is_issued_granted_presented_and_revoked() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let schema = Said::from_qb64(QVI_SCHEMA)?;

    let (issuer, issuer_recorder) = party(&environment, "issuer").await?;
    let (holder, holder_recorder) = party(&environment, "holder").await?;
    let (verifier, verifier_recorder) = party(&environment, "verifier").await?;

    // Unwitnessed throughout: nothing this scenario asserts is about receipting, and witnesses
    // make every establishment slower.
    let issuer_prefix = create_identifier(&issuer, "issuer", &[]).await?;
    let holder_prefix = create_identifier(&holder, "holder", &[]).await?;
    let verifier_prefix = create_identifier(&verifier, "verifier", &[]).await?;

    introduce(&issuer, "issuer", &holder).await?;
    introduce(&holder, "holder", &issuer).await?;
    introduce(&holder, "holder", &verifier).await?;
    introduce(&verifier, "verifier", &holder).await?;

    // Every party must know the schema before it will validate a credential against it.
    for client in [&issuer, &holder, &verifier] {
        resolve_schema(client, &environment, &schema).await?;
    }

    let registry = create_registry(&issuer, "issuer", "vLEI-test-registry").await?;
    let credential = build_credential(&issuer_prefix, &registry, &schema, &holder_prefix, &[("LEI", LEI)])?;
    // The holder offers this same ACDC further down; it is what the issuance puts in its store.
    let acdc = credential.clone();
    let credential_said = issue_credential(&issuer, "issuer", credential).await?;

    // The reads: the document, and the two listings.
    let record_read = get_credential(&issuer, &credential_said).await?;
    let issuer_reads_lei = record_read
        .sad
        .attributes
        .as_ref()
        .and_then(|attributes| attributes.additional.get("LEI"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);

    let listed_all = list_credentials(&issuer, &CredentialFilter::new()).await?.len();
    let mut clause = Sad::new();
    clause.insert("-s", SadValue::Text(schema.qb64()?))?;
    let listed_by_schema = list_credentials(&issuer, &CredentialFilter::new().with_filter(clause))
        .await?
        .len();

    let state_after_issue = credential_state(&issuer, &registry, &credential_said)
        .await?
        .status()
        .to_owned();

    // The unsolicited grant: the issuer sends without having been asked, the holder admits.
    grant_credential(&issuer, "issuer", &holder_prefix, &record_read, "here it is").await?;
    let grant = await_ipex_step(&holder, IpexRoute::Grant).await?;
    admit_credential(&holder, "holder", &grant, "thank you").await?;
    let holder_admitted = !list_credentials(&holder, &CredentialFilter::new()).await?.is_empty();

    let round = verifier_round(&holder, &verifier, &holder_prefix, &schema, &acdc, &credential_said).await?;

    // The end of the lifecycle: revoke, re-read the status, delete.
    revoke_credential(&issuer, "issuer", &registry, &credential_said).await?;
    let state_after_revoke = credential_state(&issuer, &registry, &credential_said)
        .await?
        .status()
        .to_owned();

    delete_credential(&issuer, &credential_said).await?;
    let deleted = get_credential(&issuer, &credential_said).await.is_err();

    let captured = Captured {
        scenario: "credential_ipex",
        preset: environment.preset.to_string(),
        schema: schema.qb64()?,
        issuer_prefix: issuer_prefix.qb64()?,
        holder_prefix: holder_prefix.qb64()?,
        verifier_prefix: verifier_prefix.qb64()?,
        registry: registry.qb64()?,
        credential_said: credential_said.qb64()?,
        issuer_reads_lei,
        listed_all,
        listed_by_schema,
        state_after_issue,
        state_after_revoke,
        holder_admitted,
        apply_said: round.apply.qb64()?,
        offer_said: round.offer.qb64()?,
        agree_said: round.agree.qb64()?,
        disclose_said: round.disclose.qb64()?,
        verifier_admit_said: round.admit.qb64()?,
        deleted,
        operations_remaining: vec![
            operations_remaining(&issuer).await?,
            operations_remaining(&holder).await?,
            operations_remaining(&verifier).await?,
        ],
        issuer_transcript: issuer_recorder.observations(),
        holder_transcript: holder_recorder.observations(),
        verifier_transcript: verifier_recorder.observations(),
    };

    assert_eq!(captured.state_after_issue, "iss");
    assert_eq!(captured.state_after_revoke, "rev");
    assert!(captured.holder_admitted);
    record("observations/credential_ipex.json", &captured)?;
    Ok(())
}

/// Connects one party with its own recorder and a fresh passcode.
async fn party(
    environment: &Environment,
    name: &str,
) -> Result<(ConnectedClient, std::sync::Arc<signify_keria_systest::Recorder>), Box<dyn Error>> {
    let recorded = recorder(&format!("credential_ipex_{name}"))?;
    let client = connect(
        environment,
        signify_client::random::random_passcode()?.expose(),
        &recorded,
    )
    .await?;
    Ok((client, recorded))
}

/// The five messages of a disclosure conversation, by SAID.
struct Round {
    apply: Said,
    offer: Said,
    agree: Said,
    disclose: Said,
    admit: Said,
}

/// Drives apply, offer, agree, disclose, and admit between a holder and a verifier.
async fn verifier_round(
    holder: &ConnectedClient,
    verifier: &ConnectedClient,
    holder_prefix: &keri_protocol::prefix::IdentifierPrefix,
    schema: &Said,
    acdc: &keri_acdc::credential::Credential,
    credential_said: &Said,
) -> Result<Round, Box<dyn Error>> {
    progress("the verifier's disclosure round begins");
    let apply = apply_for_credential(verifier, "verifier", holder_prefix, schema, Sad::new(), "may I see it").await?;

    let applied = await_ipex_step(holder, IpexRoute::Apply).await?;
    let held = get_credential(holder, credential_said).await?;
    let offer = offer_credential(holder, "holder", &applied, acdc, "here").await?;

    let offered = await_ipex_step(verifier, IpexRoute::Offer).await?;
    let agree = agree_to_offer(verifier, "verifier", &offered, "yes please").await?;

    let agreed = await_ipex_step(holder, IpexRoute::Agree).await?;
    let disclosure = disclosure_of(&held)?;
    let disclose = disclose_credential(holder, "holder", &agreed, &disclosure, "disclosed").await?;

    let disclosed = await_ipex_step(verifier, IpexRoute::Grant).await?;
    let admit = admit_credential(verifier, "verifier", &disclosed, "received").await?;
    Ok(Round {
        apply,
        offer,
        agree,
        disclose,
        admit,
    })
}
