//! Revoking a credential through the issuer's keeper: the `rev` event and its signed anchor.
//!
//! The event is keri-acdc's. This module adds the reference's `Credentials.revoke` composition:
//! anchor the event in the issuer's log, signed by its keeper.

use crate::identifier::artifact::IdentifierArtifact;
use crate::manager::keeper::IdentifierKeeper;
use keria_types::api::KeyState;

pub use keri_acdc::revocation::{DEFAULT_REVOCATION_SEQUENCE_NUMBER, RevocationEvent, RevocationEventBuilder};

use crate::acdc::error::AnchorError;
use crate::acdc::transaction::anchor;

/// Everything revoking one credential produces before anything is sent.
#[derive(Debug)]
pub struct RevocationArtifacts {
    /// The transaction event recording the revocation.
    pub revocation: RevocationEvent,
    /// The issuer's interaction event sealing that transaction event, with its signatures.
    pub anchor: IdentifierArtifact,
}

/// Revokes a credential: anchors `revocation` in the issuer's key event log and signs it.
///
/// This is the reference's `Credentials.revoke` short of the request. Unlike issuance it produces
/// no attachments, because nothing upstream carries a revocation in a disclosure.
///
/// # Errors
///
/// Returns the failures listed on [`anchor`].
pub fn revoke_credential(
    keeper: &dyn IdentifierKeeper,
    state: &KeyState,
    revocation: RevocationEvent,
) -> Result<RevocationArtifacts, AnchorError> {
    let anchor = anchor(keeper, state, &revocation.seal())?;
    Ok(RevocationArtifacts { revocation, anchor })
}
