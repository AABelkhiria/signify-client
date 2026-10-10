//! The credential lifecycle driven by one identifier.
//!
//! One function per operation a scenario performs, each a thin composition over the client API.
//! Nothing here decides what a correct KERI artifact looks like; `ARCHITECTURE.md` §11 reserves
//! that for the crates under test.

use std::error::Error;

use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::Sad;
use keria_types::api::{Credential as CredentialRecord, CredentialState, Role};
use signify_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use signify_acdc::ipex::{Disclosure, IpexRoute};
use signify_acdc::revocation::RevocationEventBuilder;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::credentials::CredentialFilter;
use signify_client::endpoint::registries::CreateRegistryRequest;
use signify_client::presentation::{DisclosureRequest, ReceivedStep, disclosure_of};
use signify_http::request::ItemRange;
use signify_keys::identifier::{CreateAlgorithm, CreateIdentifierRequest};

use crate::operation::wait_and_delete;

/// Creates a single-signature identifier and authorises the agent to speak for it.
///
/// Pass an empty `witnesses` for an unwitnessed identifier. The end role is added immediately
/// after inception: added later, a live KERIA refuses the reply with
/// `400 "unable to verify end role reply message"`.
///
/// # Errors
///
/// Returns whatever creating the identifier, waiting on either operation, or authorising the role
/// returns.
pub async fn create_identifier(
    client: &ConnectedClient,
    alias: &str,
    witnesses: &[IdentifierPrefix],
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::salty(None));
    request.witnesses = witnesses.to_vec();
    request.witness_threshold = u32::try_from(witnesses.len())?;

    crate::progress(&format!("{alias}: creating with {} witnesses", witnesses.len()));
    let created = client.identifiers().create(alias, &request).await?;
    wait_and_delete(client, &created.operation()?.name).await?;
    let prefix = created.artifact().event.identifier().clone();

    let agent = client.agent().prefix().clone();
    let authorised = client
        .identifiers()
        .add_end_role(alias, &Role::Agent, Some(&agent), crate::now()?)
        .await?;
    wait_and_delete(client, &authorised.operation()?.name).await?;
    crate::progress(&format!("{alias}: incepted as {prefix}"));
    Ok(prefix)
}

/// Records a contact under `prefix`, carrying `info`.
///
/// # Errors
///
/// Returns whatever the contacts endpoint returns.
pub async fn add_contact(
    client: &ConnectedClient,
    prefix: &IdentifierPrefix,
    info: &Sad,
) -> Result<keria_types::api::Contact, Box<dyn Error>> {
    Ok(client.contacts().add(prefix, info).await?)
}

/// Creates a credential registry under `alias` and returns its identifier.
///
/// # Errors
///
/// Returns whatever creating the registry or waiting on its operation returns, and an error when
/// the inception's SAID is not a registry identifier.
pub async fn create_registry(
    client: &ConnectedClient,
    alias: &str,
    name: &str,
) -> Result<RegistryIdentifier, Box<dyn Error>> {
    crate::progress(&format!("{alias}: creating registry {name}"));
    let request = CreateRegistryRequest::new(alias, name);
    let created = client.registries().create(&request).await?;
    wait_and_delete(client, &created.operation()?.name).await?;
    Ok(RegistryIdentifier::from_qb64(&created.inception.said().qb64()?)?)
}

/// Builds a credential issued by `issuer` into `registry` against `schema`.
///
/// Attributes are supplied as label/value text pairs, which is every shape the demo schemas need.
///
/// # Errors
///
/// Returns whatever building the attributes or deriving the credential returns.
pub fn build_credential(
    issuer: &IdentifierPrefix,
    registry: &RegistryIdentifier,
    schema: &Said,
    holder: &IdentifierPrefix,
    attributes: &[(&str, &str)],
) -> Result<signify_acdc::credential::Credential, Box<dyn Error>> {
    let mut block = CredentialAttributes::new(crate::now()?).issuee(holder)?;
    for (label, value) in attributes {
        block = block.text(*label, *value)?;
    }
    Ok(CredentialBuilder::new(issuer.clone(), registry.clone(), *schema, block.timestamp()?).build()?)
}

/// Issues `credential` under `alias` and returns its SAID.
///
/// # Errors
///
/// Returns whatever the issuance or its operation returns.
pub async fn issue_credential(
    client: &ConnectedClient,
    alias: &str,
    credential: signify_acdc::credential::Credential,
) -> Result<Said, Box<dyn Error>> {
    let said = credential.said();
    crate::progress(&format!("{alias}: issuing {said}"));
    let issued = client.credentials().issue(alias, credential).await?;
    wait_and_delete(client, &issued.operation()?.name).await?;
    Ok(said)
}

/// Lists the credentials matching `filter`.
///
/// # Errors
///
/// Returns whatever the credentials endpoint returns.
pub async fn list_credentials(
    client: &ConnectedClient,
    filter: &CredentialFilter,
) -> Result<Vec<CredentialRecord>, Box<dyn Error>> {
    Ok(client.credentials().list(filter).await?)
}

/// Reads one credential by SAID.
///
/// This is the ACDC document; it says nothing about whether the credential is still in force.
/// Use [`credential_state`] for that.
///
/// # Errors
///
/// Returns whatever the credentials endpoint returns.
pub async fn get_credential(client: &ConnectedClient, said: &Said) -> Result<CredentialRecord, Box<dyn Error>> {
    Ok(client.credentials().get(said).await?)
}

/// Reads one credential's registry status: issued or revoked.
///
/// The counterpart to [`get_credential`] — this is what says whether the credential is in force,
/// and it carries the digest a revocation must supersede.
///
/// # Errors
///
/// Returns whatever the credentials endpoint returns.
pub async fn credential_state(
    client: &ConnectedClient,
    registry: &RegistryIdentifier,
    said: &Said,
) -> Result<CredentialState, Box<dyn Error>> {
    Ok(client.credentials().state(registry, said).await?)
}

/// Returns the digest of the TEL event that set a credential's current status.
///
/// This is the value a revocation supersedes.
#[must_use]
pub fn state_digest(state: &CredentialState) -> String {
    match state {
        CredentialState::Unbacked(unbacked) => unbacked.digest.clone(),
        CredentialState::Backed(backed) => backed.digest.clone(),
    }
}

/// Grants a credential to `recipient` without having been asked — an unsolicited grant.
///
/// The counterpart to [`disclose_credential`], which answers an agree.
///
/// # Errors
///
/// Returns whatever deriving the disclosure or submitting the grant returns.
pub async fn grant_credential(
    client: &ConnectedClient,
    alias: &str,
    recipient: &IdentifierPrefix,
    credential: &CredentialRecord,
    message: &str,
) -> Result<Said, Box<dyn Error>> {
    let disclosure = disclosure_of(credential)?;
    crate::progress(&format!("{alias}: granting to {recipient}"));
    let submitted = client
        .presentation()
        .deliver(alias, recipient, &disclosure, message, &crate::now()?)
        .await?;
    submitted_said(client, &submitted).await
}

/// Answers an agree with the credential it asked for.
///
/// # Errors
///
/// Returns whatever submitting the grant returns.
pub async fn disclose_credential(
    client: &ConnectedClient,
    alias: &str,
    agree: &ReceivedStep,
    disclosure: &Disclosure,
    message: &str,
) -> Result<Said, Box<dyn Error>> {
    let submitted = client
        .presentation()
        .disclose(alias, agree, disclosure, message, &crate::now()?)
        .await?;
    submitted_said(client, &submitted).await
}

/// Acknowledges a grant, which is what puts the credential in the holder's store.
///
/// # Errors
///
/// Returns whatever submitting the admit returns.
pub async fn admit_credential(
    client: &ConnectedClient,
    alias: &str,
    grant: &ReceivedStep,
    message: &str,
) -> Result<Said, Box<dyn Error>> {
    crate::progress(&format!("{alias}: admitting"));
    let submitted = client
        .presentation()
        .admit(alias, grant, message, &crate::now()?)
        .await?;
    submitted_said(client, &submitted).await
}

/// Asks `holder` for a credential satisfying `schema` — the verifier's opening move.
///
/// # Errors
///
/// Returns whatever submitting the apply returns.
pub async fn apply_for_credential(
    client: &ConnectedClient,
    alias: &str,
    holder: &IdentifierPrefix,
    schema: &Said,
    attributes: Sad,
    message: &str,
) -> Result<Said, Box<dyn Error>> {
    crate::progress(&format!("{alias}: applying to {holder}"));
    let request = DisclosureRequest {
        holder: holder.clone(),
        schema: *schema,
        attributes,
        message: message.to_owned(),
        timestamp: crate::now()?,
    };
    let submitted = client.presentation().request(alias, &request).await?;
    submitted_said(client, &submitted).await
}

/// Answers an apply with the credential that satisfies it.
///
/// # Errors
///
/// Returns whatever submitting the offer returns.
pub async fn offer_credential(
    client: &ConnectedClient,
    alias: &str,
    apply: &ReceivedStep,
    credential: &signify_acdc::credential::Credential,
    message: &str,
) -> Result<Said, Box<dyn Error>> {
    let submitted = client
        .presentation()
        .offer(alias, apply, credential, message, &crate::now()?)
        .await?;
    submitted_said(client, &submitted).await
}

/// Accepts an offer, asking for the credential to be disclosed.
///
/// # Errors
///
/// Returns whatever submitting the agree returns.
pub async fn agree_to_offer(
    client: &ConnectedClient,
    alias: &str,
    offer: &ReceivedStep,
    message: &str,
) -> Result<Said, Box<dyn Error>> {
    let submitted = client
        .presentation()
        .agree(alias, offer, message, &crate::now()?)
        .await?;
    submitted_said(client, &submitted).await
}

/// Revokes a credential, superseding whatever TEL event currently describes it.
///
/// The superseded digest is read from the registry rather than assumed, which is what lets this
/// work on a credential whose log has already moved.
///
/// # Errors
///
/// Returns whatever reading the state, building the revocation, or the revocation returns.
pub async fn revoke_credential(
    client: &ConnectedClient,
    alias: &str,
    registry: &RegistryIdentifier,
    said: &Said,
) -> Result<(), Box<dyn Error>> {
    let state = credential_state(client, registry, said).await?;
    let prior = Said::from_qb64(&state_digest(&state))?;
    crate::progress(&format!("{alias}: revoking {said}"));
    let revocation = RevocationEventBuilder::new(*said, registry.clone(), prior, crate::now()?).build()?;
    let revoked = client.credentials().revoke(alias, revocation).await?;
    wait_and_delete(client, &revoked.operation()?.name).await?;
    Ok(())
}

/// Deletes a credential from this client's store.
///
/// # Errors
///
/// Returns whatever the credentials endpoint returns.
pub async fn delete_credential(client: &ConnectedClient, said: &Said) -> Result<(), Box<dyn Error>> {
    Ok(client.credentials().delete(said).await?)
}

/// Waits for an IPEX step on `route` to arrive and reads it.
///
/// # Errors
///
/// Returns an error when nothing arrives in time, and whatever reading the step returns.
pub async fn await_ipex_step(client: &ConnectedClient, route: IpexRoute) -> Result<ReceivedStep, Box<dyn Error>> {
    crate::progress(&format!("waiting for an IPEX {}", route.as_str()));
    for _ in 0..60 {
        let waiting = client.presentation().waiting(route, ItemRange::DEFAULT).await?;
        if let Some(notification) = waiting.first() {
            let step = client.presentation().read(notification).await?;
            client.presentation().close(&step).await?;
            return Ok(step);
        }
        signify_http::retry::Clock::sleep(&signify_http::retry::TokioClock, core::time::Duration::from_millis(500))
            .await;
    }
    Err(format!("no IPEX {} arrived in time", route.as_str()).into())
}

/// Waits an IPEX submission out and returns the message's SAID.
///
/// Both submission paths answer with an operation, which wave 2 established against a deployment.
async fn submitted_said(
    client: &ConnectedClient,
    submitted: &signify_client::endpoint::ipex::SubmittedIpexMessage,
) -> Result<Said, Box<dyn Error>> {
    let operation = submitted.operation()?;
    let said = operation.metadata.as_ref().map(|metadata| metadata.said.clone());
    wait_and_delete(client, &operation.name).await?;
    said.map_or_else(
        || Err::<Said, Box<dyn Error>>("the submission's operation names no message".into()),
        |said| Ok(Said::from_qb64(&said)?),
    )
}
