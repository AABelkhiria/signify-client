//! The credential lifecycle driven by a multisig group, one propose/accept round per step.
//!
//! Every group operation has the same spine: one member proposes, its peers wait for the
//! notification the proposal raises, and each accepts it. These functions take the members as
//! `(client, local alias)` pairs and run that round, so a scenario reads as one call per step.
//!
//! The reads — list, get, state, delete — are not group operations at all: any member's client can
//! perform them, so they stay in [`crate::singlesig`].

use std::error::Error;

use signify_acdc::credential::{Credential, RegistryIdentifier};
use signify_acdc::ipex::Disclosure;
use signify_acdc::revocation::RevocationEventBuilder;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::exchanges::MultisigRoute;
use signify_client::endpoint::registries::RegistryBacking;
use signify_client::multisig::{
    GroupAdmittanceRequest, GroupDisclosureRequest, GroupEndRoleRequest, GroupInceptionRequest, GroupIssuanceRequest,
    GroupRegistryRequest, GroupRevocationRequest,
};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::threshold::SigningThreshold;

use crate::operation::{await_notification, await_proposals, wait_and_delete};
use crate::singlesig::{credential_state, state_digest};

/// One member of a group: its client, and the local alias of its own identifier.
pub type Member<'a> = (&'a ConnectedClient, &'a str);

/// Incepts a group that every member derives independently.
///
/// The first member proposes; the rest accept. Returns the group identifier, which every member
/// must agree on — two that disagree have not joined the same group.
///
/// # Errors
///
/// Returns an error when `members` is empty, when two members derive different group identifiers,
/// and whatever proposing or accepting returns.
pub async fn incept_group(
    members: &[Member<'_>],
    group_name: &str,
    participants: &[IdentifierPrefix],
    signing_threshold: Option<SigningThreshold>,
    witnesses: &[IdentifierPrefix],
    witness_threshold: u32,
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let (leader, leader_alias) = *members.first().ok_or("a group needs at least one member")?;

    crate::progress(&format!("{group_name}: proposing inception"));
    let proposed = leader
        .multisig()
        .propose_inception(&GroupInceptionRequest {
            group_name,
            local_member: leader_alias,
            participants,
            signing_threshold: signing_threshold.clone(),
            next_threshold: signing_threshold,
            witnesses,
            witness_threshold,
            delegator: None,
            timestamp: crate::now()?,
        })
        .await?;
    wait_and_delete(leader, &proposed.proposal().operation()?.name).await?;
    let group = proposed.group().clone();

    for (client, alias) in members.iter().skip(1) {
        let said = await_notification(client, MultisigRoute::Inception.as_str()).await?;
        crate::progress(&format!("{group_name}: {alias} accepting inception"));
        let accepted = client
            .multisig()
            .accept_inception(group_name, alias, &said, crate::now()?)
            .await?;
        wait_and_delete(client, &accepted.proposal().operation()?.name).await?;
        if accepted.group() != &group {
            return Err(format!("{alias} derived a different group than the leader").into());
        }
    }

    wait_and_delete(leader, &proposed.creation().operation()?.name).await?;
    crate::progress(&format!("{group_name}: incepted as {group}"));
    Ok(group)
}

/// Creates a registry owned by the group.
///
/// The nonce is an argument rather than drawn per member: the registry identifier derives from it,
/// so members handed different nonces would create different registries and neither call fails.
///
/// # Errors
///
/// Returns an error when `members` is empty, and whatever proposing or accepting returns.
pub async fn create_registry(
    members: &[Member<'_>],
    group_name: &str,
    participants: &[IdentifierPrefix],
    registry: &str,
    nonce: &str,
) -> Result<RegistryIdentifier, Box<dyn Error>> {
    let (leader, leader_alias) = *members.first().ok_or("a group needs at least one member")?;

    crate::progress(&format!("{group_name}: proposing registry {registry}"));
    let proposed = leader
        .multisig()
        .propose_registry(&GroupRegistryRequest {
            group_name,
            local_member: leader_alias,
            members: participants,
            registry,
            nonce,
            backing: RegistryBacking::None,
            timestamp: crate::now()?,
        })
        .await?;
    wait_and_delete(leader, &proposed.announcement().operation()?.name).await?;

    for (client, alias) in members.iter().skip(1) {
        let said = await_notification(client, MultisigRoute::RegistryInception.as_str()).await?;
        crate::progress(&format!("{group_name}: {alias} accepting registry"));
        let accepted = client
            .multisig()
            .accept_registry(group_name, alias, registry, &said, crate::now()?)
            .await?;
        wait_and_delete(client, &accepted.announcement().operation()?.name).await?;
    }

    wait_and_delete(leader, &proposed.submission().operation()?.name).await?;
    let listed = leader.registries().list(group_name).await?;
    let found = listed
        .iter()
        .find(|entry| entry.name == registry)
        .ok_or_else(|| format!("the group has no registry named {registry}"))?;
    Ok(RegistryIdentifier::from_qb64(&found.regk)?)
}

/// Issues a credential from the group's registry.
///
/// Every member is handed the same [`Credential`]: its SAID covers every field, so members that
/// built their own from separate arguments would issue different credentials.
///
/// # Errors
///
/// Returns an error when `members` is empty, and whatever proposing or accepting returns.
pub async fn issue_credential(
    members: &[Member<'_>],
    group_name: &str,
    participants: &[IdentifierPrefix],
    credential: &Credential,
) -> Result<Said, Box<dyn Error>> {
    let (leader, leader_alias) = *members.first().ok_or("a group needs at least one member")?;
    let said = credential.said();

    crate::progress(&format!("{group_name}: proposing issuance of {said}"));
    let proposed = leader
        .multisig()
        .propose_issuance(&GroupIssuanceRequest {
            group_name,
            local_member: leader_alias,
            members: participants,
            credential: credential.clone(),
            timestamp: crate::now()?,
        })
        .await?;
    wait_and_delete(leader, &proposed.announcement().operation()?.name).await?;

    for (client, alias) in members.iter().skip(1) {
        let proposal = await_notification(client, MultisigRoute::Issuance.as_str()).await?;
        crate::progress(&format!("{group_name}: {alias} accepting issuance"));
        let accepted = client
            .multisig()
            .accept_issuance(group_name, alias, credential.clone(), &proposal, crate::now()?)
            .await?;
        wait_and_delete(client, &accepted.announcement().operation()?.name).await?;
    }

    wait_and_delete(leader, &proposed.submission().operation()?.name).await?;
    Ok(said)
}

/// Revokes a credential the group issued, superseding whatever event currently describes it.
///
/// # Errors
///
/// Returns an error when `members` is empty, and whatever reading the state, proposing, or
/// accepting returns.
pub async fn revoke_credential(
    members: &[Member<'_>],
    group_name: &str,
    participants: &[IdentifierPrefix],
    registry: &RegistryIdentifier,
    said: &Said,
) -> Result<(), Box<dyn Error>> {
    let (leader, leader_alias) = *members.first().ok_or("a group needs at least one member")?;

    let state = credential_state(leader, registry, said).await?;
    let prior = Said::from_qb64(&state_digest(&state))?;
    let revocation = RevocationEventBuilder::new(*said, registry.clone(), prior, crate::now()?).build()?;

    crate::progress(&format!("{group_name}: proposing revocation of {said}"));
    let proposed = leader
        .multisig()
        .propose_revocation(&GroupRevocationRequest {
            group_name,
            local_member: leader_alias,
            members: participants,
            revocation: revocation.clone(),
            timestamp: crate::now()?,
        })
        .await?;
    wait_and_delete(leader, &proposed.announcement().operation()?.name).await?;

    for (client, alias) in members.iter().skip(1) {
        let proposal = await_notification(client, MultisigRoute::Revocation.as_str()).await?;
        crate::progress(&format!("{group_name}: {alias} accepting revocation"));
        let accepted = client
            .multisig()
            .accept_revocation(group_name, alias, revocation.clone(), &proposal, crate::now()?)
            .await?;
        wait_and_delete(client, &accepted.announcement().operation()?.name).await?;
    }

    wait_and_delete(leader, &proposed.submission().operation()?.name).await?;
    Ok(())
}

/// Grants a credential from the group to `recipient`.
///
/// # Errors
///
/// Returns an error when `members` is empty, and whatever proposing or accepting returns.
pub async fn grant_credential(
    members: &[Member<'_>],
    group_name: &str,
    participants: &[IdentifierPrefix],
    recipient: &IdentifierPrefix,
    disclosure: &Disclosure,
    message: &str,
) -> Result<(), Box<dyn Error>> {
    let (leader, leader_alias) = *members.first().ok_or("a group needs at least one member")?;

    crate::progress(&format!("{group_name}: proposing a grant to {recipient}"));
    let proposed = leader
        .multisig()
        .propose_disclosure(&GroupDisclosureRequest {
            group_name,
            local_member: leader_alias,
            members: participants,
            recipient: recipient.clone(),
            disclosure: disclosure.clone(),
            message: message.to_owned(),
            timestamp: crate::now()?,
        })
        .await?;
    wait_and_delete(leader, &proposed.announcement().operation()?.name).await?;

    for (client, alias) in members.iter().skip(1) {
        let proposal = await_notification(client, MultisigRoute::Exchange.as_str()).await?;
        crate::progress(&format!("{group_name}: {alias} accepting the grant"));
        let accepted = client
            .multisig()
            .accept_disclosure(group_name, alias, &proposal, disclosure)
            .await?;
        wait_and_delete(client, &accepted.announcement().operation()?.name).await?;
    }
    Ok(())
}

/// Admits a grant addressed to the group, which is what puts the credential in its store.
///
/// # Errors
///
/// Returns an error when `members` is empty, and whatever proposing or accepting returns.
pub async fn admit_credential(
    members: &[Member<'_>],
    group_name: &str,
    participants: &[IdentifierPrefix],
    discloser: &IdentifierPrefix,
    grant: &Said,
    message: &str,
) -> Result<(), Box<dyn Error>> {
    let (leader, leader_alias) = *members.first().ok_or("a group needs at least one member")?;

    crate::progress(&format!("{group_name}: proposing an admit of {grant}"));
    let proposed = leader
        .multisig()
        .propose_admittance(&GroupAdmittanceRequest {
            group_name,
            local_member: leader_alias,
            members: participants,
            discloser: discloser.clone(),
            grant: *grant,
            message: message.to_owned(),
            timestamp: crate::now()?,
        })
        .await?;
    wait_and_delete(leader, &proposed.announcement().operation()?.name).await?;

    for (client, alias) in members.iter().skip(1) {
        let proposal = await_notification(client, MultisigRoute::Exchange.as_str()).await?;
        crate::progress(&format!("{group_name}: {alias} accepting the admit"));
        let accepted = client
            .multisig()
            .accept_admittance(group_name, alias, &proposal)
            .await?;
        wait_and_delete(client, &accepted.announcement().operation()?.name).await?;
    }
    Ok(())
}

/// Authorises every member's agent for the group, so the group publishes an OOBI.
///
/// The leader proposes one end-role reply per member's agent, and every other
/// member accepts each proposal, reading the stamp, role, and endpoint out of it. Until this
/// completes, nothing addressed to the group reaches any member's agent but the leader's.
///
/// Each acceptance is announced to every other member, but the agent raises one notification per
/// reply however many members relay it, so a joining member waits for exactly as many proposals
/// as the leader sent. The leader is left with one unread `/multisig/rpy` notification per reply
/// per joining member, which nothing here reads: a scenario that later waits on that route with
/// the leader must expect them.
///
/// # Errors
///
/// Returns whatever the proposal, the notifications, the acceptances, or the operations return.
pub async fn authorise_agents(members: &[Member<'_>], group_name: &str) -> Result<(), Box<dyn Error>> {
    let (leader, leader_alias) = *members.first().ok_or("a group needs at least one member")?;
    crate::progress(&format!(
        "{group_name}: {leader_alias} authorising every member's agent"
    ));
    let proposed = leader
        .multisig()
        .propose_agent_end_roles(&GroupEndRoleRequest {
            group_name,
            local_member: leader_alias,
            timestamp: crate::now()?,
        })
        .await?;
    let mut operations: Vec<(usize, String)> = proposed
        .iter()
        .map(|reply| Ok((0, reply.submission().operation()?.name)))
        .collect::<Result<_, Box<dyn Error>>>()?;
    for reply in &proposed {
        wait_and_delete(leader, &reply.announcement().operation()?.name).await?;
    }

    for (index, (client, alias)) in members.iter().enumerate().skip(1) {
        let proposals = await_proposals(client, MultisigRoute::Reply.as_str(), proposed.len()).await?;
        for proposal in &proposals {
            crate::progress(&format!("{group_name}: {alias} accepting an agent authorisation"));
            let accepted = client.multisig().accept_end_role(group_name, alias, proposal).await?;
            operations.push((index, accepted.submission().operation()?.name));
            wait_and_delete(client, &accepted.announcement().operation()?.name).await?;
        }
    }

    // The end-role operations complete only once the group's threshold is met, so they are waited
    // out after every member has signed. The agent names an operation for the role and endpoint it
    // authorizes, so two members sharing one agent yield one operation twice; it is waited once.
    operations.dedup();
    for (index, name) in &operations {
        let (client, _) = members.get(*index).ok_or("an operation names no member")?;
        wait_and_delete(client, name).await?;
    }
    Ok(())
}
