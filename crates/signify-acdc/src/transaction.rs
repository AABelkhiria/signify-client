//! Anchoring a transaction event in the issuer's key event log: the key state read as KERIA
//! reports it, the interaction event built over it, and the keeper's signatures on that event.
//!
//! The seal, the state and the unsigned event are keri-acdc's. What is added here is reading a
//! [`KeyState`] into an [`AnchorState`] and signing the event through an [`IdentifierKeeper`],
//! which is what the reference's `Credentials.issue` and `Credentials.revoke` both do.

pub use keri_acdc::transaction::{
    AnchorState, PRIOR_LABEL, SignedAnchor, TIMESTAMP_LABEL, TransactionSeal, UNSIZED_VERSION_STRING,
};
use keri_protocol::event::KeyEvent;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keria_types::api::KeyState;
use signify_keys::identifier::IdentifierError;
use signify_keys::identifier::artifact::IdentifierArtifact;
use signify_keys::manager::keeper::IdentifierKeeper;
use signify_keys::manager::{ManagedSignatures, SignatureForm, SigningPurpose};

use crate::error::AnchorError;

/// Reads what anchoring needs from a key state as KERIA reports it.
///
/// # Errors
///
/// Returns layered [`AnchorError::Identifier`] failures when the state's identifier, digest or
/// sequence number cannot be read.
pub fn anchor_state(state: &KeyState) -> Result<AnchorState, AnchorError> {
    let identifier = IdentifierPrefix::from_qb64(&state.identifier).map_err(IdentifierError::from)?;
    let digest = Said::from_qb64(&state.digest).map_err(IdentifierError::from)?;
    let sequence_number =
        u128::from_str_radix(&state.sequence_number, 16).map_err(|_| IdentifierError::ValueOutOfRange {
            context: "sequence number",
        })?;
    Ok(AnchorState::new(identifier, sequence_number, digest).with_configuration(&state.configuration))
}

/// Returns whether this key state forbids anchoring in an interaction event.
#[must_use]
pub fn is_establishment_only(state: &KeyState) -> bool {
    keri_acdc::transaction::is_establishment_only(&state.configuration)
}

/// Builds the interaction event anchoring `seal` over `state`, unsigned.
///
/// # Errors
///
/// Returns [`AnchorError::Transaction`] for keri-acdc's refusals, an establishment-only issuer
/// and a log that cannot advance among them, and [`AnchorError::Identifier`] for a key state that
/// cannot be read.
pub fn anchor_event(state: &KeyState, seal: &TransactionSeal) -> Result<KeyEvent, AnchorError> {
    Ok(keri_acdc::transaction::anchor_event(&anchor_state(state)?, seal)?)
}

/// Builds and signs the interaction event anchoring `seal` in the issuer's key event log.
///
/// The event is the one [`anchor_event`] builds, byte for byte; the signatures are the keeper's
/// current keys over it, indexed by position.
///
/// # Errors
///
/// Returns the failures listed on [`anchor_event`], and [`AnchorError::Identifier`] when the keeper
/// cannot sign.
pub fn anchor(
    keeper: &dyn IdentifierKeeper,
    state: &KeyState,
    seal: &TransactionSeal,
) -> Result<IdentifierArtifact, AnchorError> {
    let event = anchor_event(state, seal)?;
    let signatures = keeper
        .sign(event.raw(), &SignatureForm::IndexedByPosition, SigningPurpose::Current)
        .map_err(IdentifierError::from)?;
    Ok(IdentifierArtifact { event, signatures })
}

/// Reads a keeper-signed anchor into the form keri-acdc's disclosure takes.
///
/// Returns `None` when the artifact carries no indexed signatures, which a disclosure refuses.
#[must_use]
pub fn signed_anchor(artifact: &IdentifierArtifact) -> Option<SignedAnchor> {
    match &artifact.signatures {
        ManagedSignatures::Indexed(signatures) if !signatures.is_empty() => {
            Some(SignedAnchor::new(artifact.event.clone(), signatures.clone()))
        }
        ManagedSignatures::Indexed(_) | ManagedSignatures::Unindexed(_) => None,
    }
}
