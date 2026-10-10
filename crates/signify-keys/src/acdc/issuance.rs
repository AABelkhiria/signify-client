//! Issuing a credential through the issuer's keeper: the `iss` event, its signed anchor, and the
//! attachments a disclosure carries.
//!
//! The event and the attachments are keri-acdc's. This module adds the reference's
//! `Credentials.issue` composition: anchor the event in the issuer's log, signed by its keeper.

use crate::identifier::artifact::IdentifierArtifact;
use crate::manager::keeper::IdentifierKeeper;
use keri_acdc::ipex::Disclosure;
use keri_protocol::attachment::{AttachmentFraming, SealSourceCouple};
use keria_types::api::KeyState;

pub use keri_acdc::issuance::{ISSUANCE_SEQUENCE_NUMBER, IssuanceEvent};

use crate::acdc::error::{AnchorError, IpexError, TransactionError};
use crate::acdc::transaction::{anchor, signed_anchor};
use keri_acdc::credential::Credential;

/// Everything issuing one credential produces before anything is sent.
#[derive(Debug)]
pub struct IssuanceArtifacts {
    /// The credential itself.
    pub credential: Credential,
    /// The transaction event recording its issuance.
    pub issuance: IssuanceEvent,
    /// The issuer's interaction event sealing that transaction event, with its signatures.
    pub anchor: IdentifierArtifact,
}

impl IssuanceArtifacts {
    /// Encodes the CESR attachment that authenticates the **issuance event**: a pipelined
    /// seal-source couple naming the anchoring key event.
    ///
    /// # Errors
    ///
    /// Returns layered [`TransactionError::Attachment`] and [`TransactionError::Said`] failures
    /// for material that cannot be encoded.
    pub fn issuance_attachment(&self) -> Result<Vec<u8>, TransactionError> {
        let couple = SealSourceCouple::new(self.anchor.event.sequence_number().into(), self.anchor.event.said());
        Ok(couple.attachment(AttachmentFraming::Pipelined)?)
    }

    /// Encodes the CESR attachment that authenticates the credential.
    ///
    /// # Errors
    ///
    /// Returns the failures listed on [`IssuanceEvent::credential_attachment`].
    pub fn credential_attachment(&self) -> Result<Vec<u8>, TransactionError> {
        self.issuance.credential_attachment()
    }

    /// Reads these artifacts into keri-acdc's form, with the anchor's signatures beside its event.
    ///
    /// Returns `None` when the anchor carries no indexed signatures.
    #[must_use]
    pub fn protocol_artifacts(&self) -> Option<keri_acdc::issuance::IssuanceArtifacts> {
        Some(keri_acdc::issuance::IssuanceArtifacts {
            credential: self.credential.clone(),
            issuance: self.issuance.clone(),
            anchor: signed_anchor(&self.anchor)?,
        })
    }

    /// Assembles the disclosure an IPEX grant carries, every attachment derived from these
    /// artifacts.
    ///
    /// # Errors
    ///
    /// Returns [`IpexError::UnsignedAnchor`] when the anchor carries no indexed signatures, and
    /// the failures listed on [`Disclosure::from_issuance`].
    pub fn disclosure(&self) -> Result<Disclosure, IpexError> {
        let artifacts = self.protocol_artifacts().ok_or(IpexError::UnsignedAnchor)?;
        Disclosure::from_issuance(&artifacts)
    }
}

/// Issues `credential`: builds its transaction event and the signed key event anchoring it.
///
/// This is the reference's `Credentials.issue` short of the request. The anchor lands at the
/// issuer's next sequence number over the state's digest.
///
/// # Errors
///
/// Returns the failures listed on [`anchor`] and [`IssuanceEvent::for_credential`].
pub fn issue_credential(
    keeper: &dyn IdentifierKeeper,
    state: &KeyState,
    credential: Credential,
) -> Result<IssuanceArtifacts, AnchorError> {
    let issuance = IssuanceEvent::for_credential(&credential)?;
    let anchor = anchor(keeper, state, &issuance.seal())?;
    Ok(IssuanceArtifacts {
        credential,
        issuance,
        anchor,
    })
}
