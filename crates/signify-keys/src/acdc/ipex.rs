//! IPEX messages signed by the sender's keeper.
//!
//! The five messages, the envelope, the routes and the disclosure are keri-acdc's. This module
//! adds the reference's `createExchangeMessage` tail: one keeper signature over the serialized
//! message, indexed by position, which [`IpexMessage`] carries beside the message.

use crate::manager::keeper::IdentifierKeeper;
use crate::manager::{ManagedSignatures, SignatureForm, SigningPurpose};
use keri_protocol::event::exchange::ExchangeMessage;
use keri_protocol::said::Said;
use keri_protocol::serialization::Sad;

pub use keri_acdc::ipex::{
    ANCHOR_EMBED, ATTRIBUTES_LABEL, CREDENTIAL_EMBED, Disclosure, ISSUANCE_EMBED, IpexEnvelope, IpexRoute,
    MAX_MESSAGE_BYTES, MESSAGE_LABEL, SCHEMA_LABEL, SignedIpexMessage,
};

use crate::acdc::error::IpexSigningError;
use keri_acdc::credential::Credential;

/// One IPEX message signed by its sender's keeper: the message and the signatures over it.
#[derive(Debug)]
pub struct IpexMessage {
    message: keri_acdc::ipex::IpexMessage,
    signatures: ManagedSignatures,
}

impl IpexMessage {
    /// Returns which step of the conversation this is.
    #[must_use]
    pub const fn route(&self) -> IpexRoute {
        self.message.route()
    }

    /// Borrows the message as keri-acdc built it.
    #[must_use]
    pub const fn message(&self) -> &keri_acdc::ipex::IpexMessage {
        &self.message
    }

    /// Borrows the underlying exchange message.
    #[must_use]
    pub const fn exchange(&self) -> &ExchangeMessage {
        self.message.exchange()
    }

    /// Returns the exact serialized message bytes the signatures cover.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.message.raw()
    }

    /// Returns this message's own identifier, which the next step names as its prior.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.message.said()
    }

    /// Returns the transposed attachment stream carrying the embedded messages' material.
    #[must_use]
    pub fn attachments(&self) -> &[u8] {
        self.message.attachments()
    }

    /// Returns the sender's signatures over the message bytes.
    #[must_use]
    pub const fn signatures(&self) -> &ManagedSignatures {
        &self.signatures
    }

    /// Splits this message into its exchange and its signatures.
    #[must_use]
    pub fn into_parts(self) -> (ExchangeMessage, ManagedSignatures) {
        (self.message.into_exchange(), self.signatures)
    }
}

/// Builds and signs an apply: a request for a credential satisfying `schema`.
///
/// # Errors
///
/// Returns the failures listed on [`keri_acdc::ipex::apply`], and [`IpexSigningError::Manager`]
/// when the keeper cannot sign.
pub fn apply(
    keeper: &dyn IdentifierKeeper,
    envelope: &IpexEnvelope,
    schema: Said,
    attributes: Sad,
) -> Result<IpexMessage, IpexSigningError> {
    sign(keeper, keri_acdc::ipex::apply(envelope, schema, attributes)?)
}

/// Builds and signs an offer: the credential itself, embedded without attachments.
///
/// # Errors
///
/// Returns the failures listed on [`keri_acdc::ipex::offer`], and [`IpexSigningError::Manager`]
/// when the keeper cannot sign.
pub fn offer(
    keeper: &dyn IdentifierKeeper,
    envelope: &IpexEnvelope,
    credential: &Credential,
    apply: Option<Said>,
) -> Result<IpexMessage, IpexSigningError> {
    sign(keeper, keri_acdc::ipex::offer(envelope, credential, apply)?)
}

/// Builds and signs an agree: acceptance of `offer`.
///
/// # Errors
///
/// Returns the failures listed on [`keri_acdc::ipex::agree`], and [`IpexSigningError::Manager`]
/// when the keeper cannot sign.
pub fn agree(
    keeper: &dyn IdentifierKeeper,
    envelope: &IpexEnvelope,
    offer: Said,
) -> Result<IpexMessage, IpexSigningError> {
    sign(keeper, keri_acdc::ipex::agree(envelope, offer)?)
}

/// Builds and signs a grant: the credential with its provenance.
///
/// # Errors
///
/// Returns the failures listed on [`keri_acdc::ipex::grant`], and [`IpexSigningError::Manager`]
/// when the keeper cannot sign.
pub fn grant(
    keeper: &dyn IdentifierKeeper,
    envelope: &IpexEnvelope,
    disclosure: &Disclosure,
    agree: Option<Said>,
) -> Result<IpexMessage, IpexSigningError> {
    sign(keeper, keri_acdc::ipex::grant(envelope, disclosure, agree)?)
}

/// Builds and signs an admit: acknowledgement of `grant`.
///
/// # Errors
///
/// Returns the failures listed on [`keri_acdc::ipex::admit`], and [`IpexSigningError::Manager`]
/// when the keeper cannot sign.
pub fn admit(
    keeper: &dyn IdentifierKeeper,
    envelope: &IpexEnvelope,
    grant: Said,
) -> Result<IpexMessage, IpexSigningError> {
    sign(keeper, keri_acdc::ipex::admit(envelope, grant)?)
}

/// The reference's `keeper.sign` over a built message: the sender's current keys, indexed by
/// position.
fn sign(keeper: &dyn IdentifierKeeper, message: keri_acdc::ipex::IpexMessage) -> Result<IpexMessage, IpexSigningError> {
    let signatures = keeper.sign(
        message.raw(),
        &SignatureForm::IndexedByPosition,
        SigningPurpose::Current,
    )?;
    Ok(IpexMessage { message, signatures })
}
