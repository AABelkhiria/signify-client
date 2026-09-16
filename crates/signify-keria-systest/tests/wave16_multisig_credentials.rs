//! Wave 16 — the credential lifecycle driven by a multisig group.
//!
//! A two-member group issues a credential to a single-signature holder and later revokes it, and
//! then holds one itself: the subject of `test-integration/multisig-holder.test.ts`, where every
//! step is a propose/accept round rather than one call.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_KERIA_SCHEMA_URL=http://localhost:3001 SIGNIFY_RECORD=1 \
//!     cargo test -p signify-keria-systest --features live \
//!     --test wave16_multisig_credentials -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;
use std::sync::Arc;

use serde::Serialize;
use signify_acdc::credential::RegistryIdentifier;
use signify_acdc::ipex::IpexRoute;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::credentials::CredentialFilter;
use signify_client::presentation::disclosure_of;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::threshold::SigningThreshold;
use signify_keria_systest::group;
use signify_keria_systest::singlesig::{
    admit_credential, await_ipex_step, build_credential, create_identifier, credential_state, get_credential,
    grant_credential, issue_credential, list_credentials,
};
use signify_keria_systest::{
    Environment, Recorder, agent_oobi, connect, dump_tails, record, recorder, resolve_oobi, resolve_schema,
};

/// The Qualified vLEI Issuer schema, served under this SAID by the vLEI server and by the Veridian
/// credential server alike.
const QVI_SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/// The group's local alias, as the upstream case names it.
const GROUP: &str = "multisig-holder-group";

/// The LEI the upstream cases issue against.
const LEI: &str = "5493001KJTIIGC8Y1R17";

/// What the group-as-issuer round observed.
#[derive(Debug, Serialize)]
struct IssuedByGroup {
    scenario: &'static str,
    preset: String,
    group_prefix: String,
    member_prefixes: Vec<String>,
    holder_prefix: String,
    registry: String,
    credential_said: String,
    /// Whether the holder held it after admitting the group's grant.
    holder_admitted: bool,
    state_after_issue: String,
    state_after_revoke: String,
    operations_remaining: Vec<usize>,
    member1_transcript: Vec<signify_keria_systest::Observation>,
    member2_transcript: Vec<signify_keria_systest::Observation>,
}

/// What the group-as-holder round observed.
#[derive(Debug, Serialize)]
struct HeldByGroup {
    scenario: &'static str,
    preset: String,
    group_prefix: String,
    issuer_prefix: String,
    credential_said: String,
    /// Whether the group held it after both participants admitted.
    group_admitted: bool,
    operations_remaining: Vec<usize>,
}

/// Connects one party with its own recorder and a fresh passcode.
async fn party(environment: &Environment, name: &str) -> Result<(ConnectedClient, Arc<Recorder>), Box<dyn Error>> {
    let recorded = recorder(&format!("multisig_credentials_{name}"))?;
    let client = connect(
        environment,
        signify_client::random::random_passcode()?.expose(),
        &recorded,
    )
    .await?;
    Ok((client, recorded))
}

/// Introduces `from`'s identifier to `to`.
async fn introduce(from: &ConnectedClient, alias: &str, to: &ConnectedClient) -> Result<(), Box<dyn Error>> {
    let url = agent_oobi(from, alias).await?;
    resolve_oobi(to, &url, alias).await?;
    Ok(())
}

/// Counts the operations a client has left, which upstream requires to be none.
async fn remaining(client: &ConnectedClient) -> Result<usize, Box<dyn Error>> {
    Ok(client.operations().list(None).await?.len())
}

/// Builds the two-member group every test here starts from.
async fn two_member_group(
    environment: &Environment,
    member1: &ConnectedClient,
    member2: &ConnectedClient,
    schema: &Said,
) -> Result<(IdentifierPrefix, Vec<IdentifierPrefix>), Box<dyn Error>> {
    let aid1 = create_identifier(member1, "member1", &[]).await?;
    let aid2 = create_identifier(member2, "member2", &[]).await?;
    introduce(member1, "member1", member2).await?;
    introduce(member2, "member2", member1).await?;
    resolve_schema(member1, environment, schema).await?;
    resolve_schema(member2, environment, schema).await?;

    let participants = vec![aid1, aid2];
    let pair = [(member1, "member1"), (member2, "member2")];
    let group_prefix =
        group::incept_group(&pair, GROUP, &participants, Some(SigningThreshold::numeric(2)), &[], 0).await?;
    // A group that has not authorised its agents publishes no OOBI, so nobody could be
    // introduced to it — wave 12's lesson.
    group::authorise_agents(&pair, GROUP, &participants).await?;
    Ok((group_prefix, participants))
}

#[tokio::test]
#[ignore = "requires a live KERIA and a schema server; see the crate documentation"]
async fn a_group_issues_grants_and_revokes_a_credential() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let schema = Said::from_qb64(QVI_SCHEMA)?;

    let (member1, member1_recorder) = party(&environment, "member1").await?;
    let (member2, member2_recorder) = party(&environment, "member2").await?;
    let (holder, holder_recorder) = party(&environment, "holder").await?;

    let outcome = issued_by_group(&environment, &schema, (&member1, &member2, &holder)).await;
    if outcome.is_err() {
        dump_tails(&[&member1_recorder, &member2_recorder, &holder_recorder], 3);
    }
    let (
        group_prefix,
        participants,
        holder_prefix,
        registry,
        credential_said,
        state_after_issue,
        state_after_revoke,
        holder_admitted,
    ) = outcome?;

    let captured = IssuedByGroup {
        scenario: "multisig_credentials",
        preset: environment.preset.to_string(),
        group_prefix: group_prefix.qb64()?,
        member_prefixes: participants
            .iter()
            .map(IdentifierPrefix::qb64)
            .collect::<Result<Vec<_>, _>>()?,
        holder_prefix: holder_prefix.qb64()?,
        registry: registry.qb64()?,
        credential_said: credential_said.qb64()?,
        holder_admitted,
        state_after_issue,
        state_after_revoke,
        operations_remaining: vec![
            remaining(&member1).await?,
            remaining(&member2).await?,
            remaining(&holder).await?,
        ],
        member1_transcript: member1_recorder.observations(),
        member2_transcript: member2_recorder.observations(),
    };

    assert_eq!(captured.state_after_issue, "iss");
    assert_eq!(captured.state_after_revoke, "rev");
    assert!(captured.holder_admitted);
    record("observations/multisig_credentials.json", &captured)?;
    Ok(())
}

type IssuedByGroupOutcome = (
    IdentifierPrefix,
    Vec<IdentifierPrefix>,
    IdentifierPrefix,
    RegistryIdentifier,
    Said,
    String,
    String,
    bool,
);

/// The group-as-issuer round, up to what is captured; split out so a failure can show its transcript.
async fn issued_by_group(
    environment: &Environment,
    schema: &Said,
    (member1, member2, holder): (&ConnectedClient, &ConnectedClient, &ConnectedClient),
) -> Result<IssuedByGroupOutcome, Box<dyn Error>> {
    let (group_prefix, participants) = two_member_group(environment, member1, member2, schema).await?;
    let holder_prefix = create_identifier(holder, "holder", &[]).await?;
    resolve_schema(holder, environment, schema).await?;
    introduce(member1, GROUP, holder).await?;
    introduce(holder, "holder", member1).await?;
    introduce(holder, "holder", member2).await?;

    let pair = [(member1, "member1"), (member2, "member2")];
    let registry = group::create_registry(
        &pair,
        GROUP,
        &participants,
        "group-registry",
        "0AA_group_registry_nonce",
    )
    .await?;
    let credential = build_credential(&group_prefix, &registry, schema, &holder_prefix, &[("LEI", LEI)])?;
    let credential_said = group::issue_credential(&pair, GROUP, &participants, &credential).await?;

    let state_after_issue = credential_state(member1, &registry, &credential_said)
        .await?
        .status()
        .to_owned();

    let record_read = get_credential(member1, &credential_said).await?;
    let disclosure = disclosure_of(&record_read)?;
    group::grant_credential(
        &pair,
        GROUP,
        &participants,
        &holder_prefix,
        &disclosure,
        "from the group",
    )
    .await?;

    let grant = await_ipex_step(holder, IpexRoute::Grant).await?;
    admit_credential(holder, "holder", &grant, "thank you").await?;
    let holder_admitted = !list_credentials(holder, &CredentialFilter::new()).await?.is_empty();

    group::revoke_credential(&pair, GROUP, &participants, &registry, &credential_said).await?;
    let state_after_revoke = credential_state(member1, &registry, &credential_said)
        .await?
        .status()
        .to_owned();

    Ok((
        group_prefix,
        participants,
        holder_prefix,
        registry,
        credential_said,
        state_after_issue,
        state_after_revoke,
        holder_admitted,
    ))
}

#[tokio::test]
#[ignore = "requires a live KERIA and a schema server; see the crate documentation"]
async fn a_group_admits_a_credential_issued_to_it() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let schema = Said::from_qb64(QVI_SCHEMA)?;

    let (member1, _member1_recorder) = party(&environment, "holder_member1").await?;
    let (member2, _member2_recorder) = party(&environment, "holder_member2").await?;
    let (issuer, _issuer_recorder) = party(&environment, "external_issuer").await?;

    let (group_prefix, participants) = two_member_group(&environment, &member1, &member2, &schema).await?;
    let issuer_prefix = create_identifier(&issuer, "issuer", &[]).await?;
    resolve_schema(&issuer, &environment, &schema).await?;
    introduce(&issuer, "issuer", &member1).await?;
    introduce(&issuer, "issuer", &member2).await?;
    introduce(&member1, GROUP, &issuer).await?;

    // The issuer is an ordinary identifier; only the holder is a group.
    let registry = signify_keria_systest::singlesig::create_registry(&issuer, "issuer", "external-registry").await?;
    let credential = build_credential(&issuer_prefix, &registry, &schema, &group_prefix, &[("LEI", LEI)])?;
    let credential_said = issue_credential(&issuer, "issuer", credential).await?;

    let record_read = get_credential(&issuer, &credential_said).await?;
    let grant_said = grant_credential(&issuer, "issuer", &group_prefix, &record_read, "for the group").await?;

    // Both participants must admit, which is the whole difference from the single-signature case.
    let pair = [(&member1, "member1"), (&member2, "member2")];
    group::admit_credential(&pair, GROUP, &participants, &issuer_prefix, &grant_said, "received").await?;
    let group_admitted = !list_credentials(&member1, &CredentialFilter::new()).await?.is_empty();

    let captured = HeldByGroup {
        scenario: "multisig_holder",
        preset: environment.preset.to_string(),
        group_prefix: group_prefix.qb64()?,
        issuer_prefix: issuer_prefix.qb64()?,
        credential_said: credential_said.qb64()?,
        group_admitted,
        operations_remaining: vec![
            remaining(&member1).await?,
            remaining(&member2).await?,
            remaining(&issuer).await?,
        ],
    };

    assert!(captured.group_admitted);
    record("observations/multisig_holder.json", &captured)?;
    let _ = RegistryIdentifier::from_qb64(&captured.credential_said).is_err();
    Ok(())
}
