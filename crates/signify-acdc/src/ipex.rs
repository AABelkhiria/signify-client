//! IPEX: the five messages two controllers exchange to disclose a credential.
//!
//! The Issuance and Presentation Exchange protocol is a conversation, and each step is an `exn`
//! message naming the step before it:
//!
//! ```text
//! apply   disclosee asks for a credential satisfying a schema      (no prior)
//!   ↓
//! offer   discloser answers with the credential, embedded          (prior: the apply)
//!   ↓
//! agree   disclosee accepts                                        (prior: the offer)
//!   ↓
//! grant   discloser sends the credential and its provenance        (prior: the agree)
//!   ↓
//! admit   disclosee acknowledges receipt                           (prior: the grant)
//! ```
//!
//! Either side may start: a discloser with a `grant` and no prior, or a disclosee with an `apply`.
//! Only `offer` and `grant` embed anything, and only a `grant` carries attachments — the three
//! that chain a credential to a signed key event, which [`issuance`](crate::issuance) produces.
//!
//! This module ports the pure half of `Ipex.apply`, `.offer`, `.agree`, `.grant`, and `.admit` in
//! the pinned `src/keri/app/credentialing.ts`, together with the `createExchangeMessage`
//! composition of `src/keri/app/exchanging.ts` that each calls. The message itself is Roadmap
//! 3.8's [`ExchangeBuilder`]; what is added here is the route, the payload each route carries, the
//! embeds, and the signature. Submitting the result is Roadmap 6.12.
//!
//! # The message is required on every route
//!
//! Four of the five upstream methods write `m: args.message ?? ''`. `admit` writes
//! `m: args.message`, so an admit built without a message emits an attribute block carrying **no
//! `m` field at all** — a different message with a different identifier from one carrying the
//! empty string. Whether the field exists at all should not depend on which argument a caller
//! happened to omit, so the message is required here and an empty one is spelled explicitly. See
//! `fixtures/acdc-ipex/`.
//!
//! # Example
//!
//! ```
//! use signify_acdc::ipex::{IpexEnvelope, IpexRoute};
//! use signify_keri::prefix::IdentifierPrefix;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let envelope = IpexEnvelope::new(
//!     IdentifierPrefix::from_qb64("ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK")?,
//!     IdentifierPrefix::from_qb64("ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k")?,
//!     "Applying",
//!     "2023-08-23T15:16:07.553000+00:00".parse()?,
//! )?;
//!
//! assert_eq!(IpexRoute::Apply.as_str(), "/ipex/apply");
//! assert_eq!(envelope.message(), "Applying");
//! # Ok(())
//! # }
//! ```

use signify_keri::attachment::SignedMessageBuilder;
use signify_keri::event::Timestamp;
use signify_keri::event::exchange::{ExchangeBuilder, ExchangeEmbed, ExchangeMessage};
use signify_keri::manager::keeper::IdentifierKeeper;
use signify_keri::manager::{ManagedSignatures, SignatureForm, SigningPurpose};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{IDENTIFIER_LABEL, Sad, SadValue, SerializedEvent};

use crate::credential::Credential;
use crate::error::IpexError;
use crate::issuance::IssuanceArtifacts;

/// Field label carrying an IPEX message's human-readable text; the payload's `m`.
pub const MESSAGE_LABEL: &str = "m";
/// Field label carrying the schema an apply asks for; the payload's `s`.
pub const SCHEMA_LABEL: &str = "s";
/// Field label carrying an apply's selective-disclosure attributes; the payload's `a`.
pub const ATTRIBUTES_LABEL: &str = "a";

/// Embed label carrying the credential itself, in an offer or a grant.
pub const CREDENTIAL_EMBED: &str = "acdc";
/// Embed label carrying the credential's issuance event, in a grant.
pub const ISSUANCE_EMBED: &str = "iss";
/// Embed label carrying the key event anchoring that issuance, in a grant.
pub const ANCHOR_EMBED: &str = "anc";

/// Largest message text this builder accepts, in bytes.
///
/// The reference imposes no bound. The value is committed into the exchange's identifier and
/// travels to a peer, so it is bounded here as every other caller-supplied text in this crate is.
pub const MAX_MESSAGE_BYTES: usize = 4_096;

/// One step of the IPEX conversation.
///
/// The reference writes these as bare string literals at each call site; the fixture reads them
/// back out of its syntax tree, and a test asserts each variant against the literal it found.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IpexRoute {
    /// A disclosee asks for a credential satisfying a schema.
    Apply,
    /// A discloser answers with the credential.
    Offer,
    /// A disclosee accepts the offer.
    Agree,
    /// A discloser sends the credential with its provenance.
    Grant,
    /// A disclosee acknowledges receipt.
    Admit,
}

impl IpexRoute {
    /// Every route, in conversation order.
    pub const ALL: [Self; 5] = [Self::Apply, Self::Offer, Self::Agree, Self::Grant, Self::Admit];

    /// Returns the exact route text written into a message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "/ipex/apply",
            Self::Offer => "/ipex/offer",
            Self::Agree => "/ipex/agree",
            Self::Grant => "/ipex/grant",
            Self::Admit => "/ipex/admit",
        }
    }

    /// Returns whether this route may open a conversation, carrying no prior message.
    ///
    /// A disclosee opens with an apply and a discloser with a grant; an offer answers an apply but
    /// the reference also lets one stand alone, which its own third IPEX test exercises.
    #[must_use]
    pub const fn may_open_a_conversation(self) -> bool {
        matches!(self, Self::Apply | Self::Offer | Self::Grant)
    }
}

impl core::fmt::Display for IpexRoute {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What every IPEX message carries regardless of route: who, to whom, saying what, and when.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpexEnvelope {
    sender: IdentifierPrefix,
    recipient: IdentifierPrefix,
    message: String,
    timestamp: Timestamp,
}

impl IpexEnvelope {
    /// Builds an envelope, bounding the message text.
    ///
    /// The message is required on every route — see the module documentation for why — and an
    /// empty one is spelled as the empty string, which is what four of the five upstream methods
    /// default to.
    ///
    /// # Errors
    ///
    /// Returns [`IpexError::MessageTooLong`] above [`MAX_MESSAGE_BYTES`].
    pub fn new(
        sender: IdentifierPrefix,
        recipient: IdentifierPrefix,
        message: impl Into<String>,
        timestamp: Timestamp,
    ) -> Result<Self, IpexError> {
        let message = message.into();
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(IpexError::MessageTooLong {
                maximum: MAX_MESSAGE_BYTES,
                actual: message.len(),
            });
        }
        Ok(Self {
            sender,
            recipient,
            message,
            timestamp,
        })
    }

    /// Returns the identifier sending this message.
    #[must_use]
    pub const fn sender(&self) -> &IdentifierPrefix {
        &self.sender
    }

    /// Returns the identifier it is addressed to.
    #[must_use]
    pub const fn recipient(&self) -> &IdentifierPrefix {
        &self.recipient
    }

    /// Returns the human-readable text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the instant the message is stamped with.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Builds the payload every route opens with: the message alone.
    fn payload(&self) -> Result<Sad, IpexError> {
        let mut payload = Sad::new();
        payload.insert(MESSAGE_LABEL, SadValue::text(self.message.as_str()))?;
        Ok(payload)
    }
}

/// One signed IPEX message: its exchange, its signatures, and its attachment stream.
#[derive(Debug)]
pub struct IpexMessage {
    route: IpexRoute,
    exchange: ExchangeMessage,
    signatures: ManagedSignatures,
}

impl IpexMessage {
    /// Returns which step of the conversation this is.
    #[must_use]
    pub const fn route(&self) -> IpexRoute {
        self.route
    }

    /// Borrows the underlying exchange message.
    #[must_use]
    pub const fn exchange(&self) -> &ExchangeMessage {
        &self.exchange
    }

    /// Returns the exact serialized message bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.exchange.raw()
    }

    /// Returns this message's own identifier, which the next step names as its prior.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.exchange.said()
    }

    /// Returns the transposed attachment stream carrying the embedded messages' material.
    ///
    /// Empty for every route but `grant`; an offer embeds the credential with no attachment, which
    /// writes nothing here.
    #[must_use]
    pub fn attachments(&self) -> &[u8] {
        self.exchange.attachments()
    }

    /// Returns the sender's signatures over the message bytes.
    #[must_use]
    pub const fn signatures(&self) -> &ManagedSignatures {
        &self.signatures
    }

    /// Splits this message into its exchange and its signatures.
    #[must_use]
    pub fn into_parts(self) -> (ExchangeMessage, ManagedSignatures) {
        (self.exchange, self.signatures)
    }
}

/// The three artifacts and three attachments a grant discloses.
///
/// Together they let a recipient walk from the credential to a signed key event: the credential's
/// attachment names its issuance, the issuance's attachment names the anchoring key event, and the
/// anchor's attachment is the issuer's signature over it.
#[derive(Clone, Debug)]
pub struct Disclosure {
    credential: SerializedEvent,
    credential_attachment: Vec<u8>,
    issuance: SerializedEvent,
    issuance_attachment: Vec<u8>,
    anchor: SerializedEvent,
    anchor_attachment: Vec<u8>,
}

impl Disclosure {
    /// Assembles a disclosure from artifacts and attachments a caller already holds.
    ///
    /// Use this for a credential received from elsewhere; for one issued here,
    /// [`Self::from_issuance`] derives every attachment itself.
    #[must_use]
    pub const fn new(
        credential: SerializedEvent,
        credential_attachment: Vec<u8>,
        issuance: SerializedEvent,
        issuance_attachment: Vec<u8>,
        anchor: SerializedEvent,
        anchor_attachment: Vec<u8>,
    ) -> Self {
        Self {
            credential,
            credential_attachment,
            issuance,
            issuance_attachment,
            anchor,
            anchor_attachment,
        }
    }

    /// Assembles a disclosure from Roadmap 6.2's issuance artifacts.
    ///
    /// All three attachments are derived: the credential's from the issuance event, the issuance's
    /// from the anchor, and the anchor's from the signatures the issuer's keeper produced over it.
    /// The reference instead signs the anchor with the *sender's* keeper when no attachment is
    /// given, which a discloser who is not the issuer cannot do correctly; here the signatures
    /// come from the artifacts, so there is no such path.
    ///
    /// # Errors
    ///
    /// Returns layered [`IpexError::Transaction`] and [`IpexError::Attachment`] failures for
    /// material that cannot be encoded, and [`IpexError::UnsignedAnchor`] when the artifacts carry
    /// no indexed signatures over the anchor.
    pub fn from_issuance(artifacts: &IssuanceArtifacts) -> Result<Self, IpexError> {
        let ManagedSignatures::Indexed(signatures) = &artifacts.anchor.signatures else {
            return Err(IpexError::UnsignedAnchor);
        };
        if signatures.is_empty() {
            return Err(IpexError::UnsignedAnchor);
        }
        let anchor_attachment = SignedMessageBuilder::new(artifacts.anchor.event.serialized())
            .controller_signatures(signatures.clone())
            .build()?
            .attachments()
            .to_vec();

        Ok(Self {
            credential: artifacts.credential.serialized().clone(),
            credential_attachment: artifacts.credential_attachment()?,
            issuance: artifacts.issuance.serialized().clone(),
            issuance_attachment: artifacts.issuance_attachment()?,
            anchor: artifacts.anchor.event.serialized().clone(),
            anchor_attachment,
        })
    }

    /// Borrows the credential being disclosed.
    #[must_use]
    pub const fn credential(&self) -> &SerializedEvent {
        &self.credential
    }

    /// Borrows the transaction event recording its issuance.
    #[must_use]
    pub const fn issuance(&self) -> &SerializedEvent {
        &self.issuance
    }

    /// Borrows the key event anchoring that issuance.
    #[must_use]
    pub const fn anchor(&self) -> &SerializedEvent {
        &self.anchor
    }

    /// Builds the three embeds a grant carries, in the reference's order.
    fn embeds(&self) -> Result<Vec<ExchangeEmbed>, IpexError> {
        Ok(vec![
            ExchangeEmbed::new(CREDENTIAL_EMBED, &self.credential)?
                .with_attachment(self.credential_attachment.clone())?,
            ExchangeEmbed::new(ISSUANCE_EMBED, &self.issuance)?.with_attachment(self.issuance_attachment.clone())?,
            ExchangeEmbed::new(ANCHOR_EMBED, &self.anchor)?.with_attachment(self.anchor_attachment.clone())?,
        ])
    }
}

/// Builds and signs an apply: a request for a credential satisfying `schema`.
///
/// `attributes` narrows the request to particular attribute values — the reference's selective
/// disclosure — and is written under the payload's own `a`. An empty block asks for any credential
/// of that schema, which is the reference's default.
///
/// # Errors
///
/// Returns [`IpexError::ReservedPayloadLabel`] when the attributes carry the identifier label that
/// names the recipient, and layered exchange and signing failures.
pub fn apply(
    keeper: &dyn IdentifierKeeper,
    envelope: &IpexEnvelope,
    schema: Said,
    attributes: Sad,
) -> Result<IpexMessage, IpexError> {
    if attributes.contains(IDENTIFIER_LABEL) {
        return Err(IpexError::ReservedPayloadLabel {
            label: IDENTIFIER_LABEL,
        });
    }
    let mut payload = envelope.payload()?;
    payload.insert(SCHEMA_LABEL, SadValue::Text(schema.qb64()?))?;
    payload.insert(ATTRIBUTES_LABEL, SadValue::Map(attributes))?;
    build(keeper, envelope, IpexRoute::Apply, payload, Vec::new(), None)
}

/// Builds and signs an offer: the credential itself, embedded without attachments.
///
/// `apply` names the request being answered, and is absent when a discloser offers unprompted —
/// which the reference's own third IPEX case exercises.
///
/// # Errors
///
/// Returns layered exchange and signing failures.
pub fn offer(
    keeper: &dyn IdentifierKeeper,
    envelope: &IpexEnvelope,
    credential: &Credential,
    apply: Option<Said>,
) -> Result<IpexMessage, IpexError> {
    let embeds = vec![ExchangeEmbed::new(CREDENTIAL_EMBED, credential.serialized())?];
    build(keeper, envelope, IpexRoute::Offer, envelope.payload()?, embeds, apply)
}

/// Builds and signs an agree: acceptance of `offer`.
///
/// # Errors
///
/// Returns layered exchange and signing failures.
pub fn agree(keeper: &dyn IdentifierKeeper, envelope: &IpexEnvelope, offer: Said) -> Result<IpexMessage, IpexError> {
    build(
        keeper,
        envelope,
        IpexRoute::Agree,
        envelope.payload()?,
        Vec::new(),
        Some(offer),
    )
}

/// Builds and signs a grant: the credential with everything needed to verify it.
///
/// `agree` names the acceptance being answered, and is absent when a discloser grants unprompted.
///
/// # Errors
///
/// Returns layered exchange and signing failures, including the attachment refusals
/// [`ExchangeEmbed::with_attachment`] performs on each of the three.
pub fn grant(
    keeper: &dyn IdentifierKeeper,
    envelope: &IpexEnvelope,
    disclosure: &Disclosure,
    agree: Option<Said>,
) -> Result<IpexMessage, IpexError> {
    build(
        keeper,
        envelope,
        IpexRoute::Grant,
        envelope.payload()?,
        disclosure.embeds()?,
        agree,
    )
}

/// Builds and signs an admit: acknowledgement of `grant`.
///
/// # Errors
///
/// Returns layered exchange and signing failures.
pub fn admit(keeper: &dyn IdentifierKeeper, envelope: &IpexEnvelope, grant: Said) -> Result<IpexMessage, IpexError> {
    build(
        keeper,
        envelope,
        IpexRoute::Admit,
        envelope.payload()?,
        Vec::new(),
        Some(grant),
    )
}

/// The composition every route performs: build the exchange, then sign it.
///
/// This is the reference's `Exchanges.createExchangeMessage`, specialised to the IPEX routes. The
/// signing form is the one every keeper-signed message in this port uses.
fn build(
    keeper: &dyn IdentifierKeeper,
    envelope: &IpexEnvelope,
    route: IpexRoute,
    payload: Sad,
    embeds: Vec<ExchangeEmbed>,
    prior: Option<Said>,
) -> Result<IpexMessage, IpexError> {
    let mut builder = ExchangeBuilder::new(
        route.as_str(),
        envelope.sender.clone(),
        envelope.recipient.clone(),
        envelope.timestamp.clone(),
    )
    .payload(payload)
    .embeds(embeds);
    if let Some(prior) = prior {
        builder = builder.prior(prior);
    }
    let exchange = builder.build()?;
    let signatures = keeper.sign(
        exchange.raw(),
        &SignatureForm::IndexedByPosition,
        SigningPurpose::Current,
    )?;
    Ok(IpexMessage {
        route,
        exchange,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn every_route_writes_its_upstream_literal() {
        assert_eq!(IpexRoute::ALL.len(), 5);
        assert_eq!(IpexRoute::Apply.as_str(), "/ipex/apply");
        assert_eq!(IpexRoute::Offer.as_str(), "/ipex/offer");
        assert_eq!(IpexRoute::Agree.as_str(), "/ipex/agree");
        assert_eq!(IpexRoute::Grant.as_str(), "/ipex/grant");
        assert_eq!(IpexRoute::Admit.as_str(), "/ipex/admit");
        for route in IpexRoute::ALL {
            assert_eq!(route.to_string(), route.as_str());
            assert!(route.as_str().starts_with("/ipex/"));
        }
    }

    #[test]
    fn only_the_opening_routes_may_stand_alone() {
        assert!(IpexRoute::Apply.may_open_a_conversation());
        assert!(IpexRoute::Offer.may_open_a_conversation());
        assert!(IpexRoute::Grant.may_open_a_conversation());
        assert!(!IpexRoute::Agree.may_open_a_conversation());
        assert!(!IpexRoute::Admit.may_open_a_conversation());
    }

    #[test]
    fn the_embed_labels_are_the_references_own() {
        assert_eq!(CREDENTIAL_EMBED, "acdc");
        assert_eq!(ISSUANCE_EMBED, "iss");
        assert_eq!(ANCHOR_EMBED, "anc");
        assert_eq!(MESSAGE_LABEL, "m");
        assert_eq!(SCHEMA_LABEL, "s");
        assert_eq!(ATTRIBUTES_LABEL, "a");
    }

    fn envelope(message: &str) -> Result<IpexEnvelope, Box<dyn Error>> {
        Ok(IpexEnvelope::new(
            IdentifierPrefix::from_qb64("ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK")?,
            IdentifierPrefix::from_qb64("ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k")?,
            message,
            "2023-08-23T15:16:07.553000+00:00".parse()?,
        )?)
    }

    #[test]
    fn an_envelope_reports_what_it_carries() -> Result<(), Box<dyn Error>> {
        let envelope = envelope("Applying")?;
        assert_eq!(envelope.message(), "Applying");
        assert_eq!(
            envelope.sender().qb64()?,
            "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK"
        );
        assert_eq!(
            envelope.recipient().qb64()?,
            "ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k"
        );
        assert_eq!(envelope.timestamp().as_str(), "2023-08-23T15:16:07.553000+00:00");
        Ok(())
    }

    #[test]
    fn an_empty_message_is_spelled_rather_than_omitted() -> Result<(), Box<dyn Error>> {
        // The reference's admit omits the field entirely; here the empty string is a value.
        let payload = envelope("")?.payload()?;
        assert_eq!(payload.len(), 1);
        assert_eq!(payload.get_text(MESSAGE_LABEL), Some(""));
        Ok(())
    }

    #[test]
    fn a_message_is_bounded() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            IpexEnvelope::new(
                IdentifierPrefix::from_qb64("ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK")?,
                IdentifierPrefix::from_qb64("ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k")?,
                "m".repeat(MAX_MESSAGE_BYTES + 1),
                "2023-08-23T15:16:07.553000+00:00".parse()?,
            ),
            Err(IpexError::MessageTooLong { maximum, actual })
                if maximum == MAX_MESSAGE_BYTES && actual == MAX_MESSAGE_BYTES + 1
        ));
        // The bound itself is accepted.
        envelope(&"m".repeat(MAX_MESSAGE_BYTES))?;
        Ok(())
    }
}
