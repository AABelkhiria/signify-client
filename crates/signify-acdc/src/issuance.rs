//! Issuing a credential: the `iss` transaction event, its anchor, and the two CESR attachments a
//! disclosure carries.
//!
//! [`Credential`] construction produces a document; it does not
//! make that document *valid*. A credential becomes issued when three artifacts exist together:
//!
//! 1. an `iss` transaction event, at position zero of the credential's own transaction log, naming
//!    the registry that governs it;
//! 2. an interaction event in the issuer's key event log sealing that transaction event, signed by
//!    the issuer's keeper;
//! 3. the CESR attachments binding each artifact to the next, which a later IPEX grant carries.
//!
//! This module ports the pure half of `Credentials.issue` in the pinned
//! `src/keri/app/credentialing.ts`, together with `serializeACDCAttachment` and
//! `serializeIssExnAttachment` from `src/keri/core/utils.ts`. Submitting the result is Roadmap
//! 6.11; embedding it in an IPEX grant is Roadmap 6.3.
//!
//! # The transaction event borrows the credential's timestamp
//!
//! The reference writes `dt: subject.dt` — the credential's own attribute timestamp — rather than
//! reading the clock a second time, so a credential and its issuance always agree about when it
//! happened. That is reproduced and made structural here: [`IssuanceEvent::for_credential`] takes
//! no timestamp because there is nowhere for a second one to come from.
//!
//! # Example
//!
//! ```
//! use signify_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
//! use signify_acdc::issuance::IssuanceEvent;
//! use signify_keri::prefix::IdentifierPrefix;
//! use signify_keri::said::Said;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let credential = CredentialBuilder::new(
//!     IdentifierPrefix::from_qb64("EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1")?,
//!     RegistryIdentifier::from_qb64("EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df")?,
//!     Said::from_qb64("EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao")?,
//!     CredentialAttributes::new("2023-08-23T15:16:07.553000+00:00".parse()?)
//!         .issuee(&IdentifierPrefix::from_qb64("EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby")?)?
//!         .timestamp()?
//!         .text("LEI", "5493001KJTIIGC8Y1R17")?,
//! )
//! .build()?;
//!
//! let issuance = IssuanceEvent::for_credential(&credential)?;
//!
//! // The issuance event the pinned reference's own unit test publishes.
//! assert_eq!(issuance.said().qb64()?, "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW");
//! assert_eq!(issuance.sequence_number(), 0);
//! # Ok(())
//! # }
//! ```

use keria_types::api::KeyState;
use signify_keri::attachment::{AttachmentFraming, SealSourceCouple, SealSourceTriple};
use signify_keri::event::Timestamp;
use signify_keri::event::kind::EventKind;
use signify_keri::identifier::artifact::IdentifierArtifact;
use signify_keri::manager::keeper::IdentifierKeeper;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SerializedEvent};

use crate::credential::{Credential, RegistryIdentifier};
use crate::error::TransactionError;
use crate::transaction::{TransactionSeal, anchor, assemble};

/// Position of an issuance in a credential's transaction event log.
///
/// An `iss` event is always the first event about its credential, so this is always zero. The
/// reference writes the literal `'0'`.
pub const ISSUANCE_SEQUENCE_NUMBER: u128 = 0;

/// One `iss` transaction event: the record that a credential was issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceEvent {
    serialized: SerializedEvent,
    said: Said,
    credential: Said,
    registry: RegistryIdentifier,
    timestamp: Timestamp,
}

impl IssuanceEvent {
    /// Builds the issuance event for a credential built here.
    ///
    /// Everything it needs — the credential's identifier, its registry, and its attribute
    /// timestamp — is already on the credential, which is why there is nothing else to pass.
    ///
    /// # Errors
    ///
    /// Returns layered [`TransactionError::Said`], [`TransactionError::Sad`], and
    /// [`TransactionError::Serialization`] failures for material that cannot be encoded.
    pub fn for_credential(credential: &Credential) -> Result<Self, TransactionError> {
        Self::new(
            credential.said(),
            credential.registry().clone(),
            credential.timestamp().clone(),
        )
    }

    /// Builds the issuance event from its three values directly.
    ///
    /// Use this for a credential that arrived from elsewhere; for one built here,
    /// [`Self::for_credential`] cannot get any of the three wrong.
    ///
    /// # Errors
    ///
    /// Returns the failures listed on [`Self::for_credential`].
    pub fn new(credential: Said, registry: RegistryIdentifier, timestamp: Timestamp) -> Result<Self, TransactionError> {
        let (serialized, said) = assemble(
            EventKind::Issuance,
            credential,
            &registry.qb64()?,
            ISSUANCE_SEQUENCE_NUMBER,
            None,
            &timestamp,
        )?;
        Ok(Self {
            serialized,
            said,
            credential,
            registry,
            timestamp,
        })
    }

    /// Returns the exact serialized event bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.serialized.raw()
    }

    /// Borrows the ordered event fields.
    #[must_use]
    pub const fn sad(&self) -> &Sad {
        self.serialized.sad()
    }

    /// Borrows the serialized form, which carries the sized version string.
    #[must_use]
    pub const fn serialized(&self) -> &SerializedEvent {
        &self.serialized
    }

    /// Returns this event's own self-addressing identifier.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the credential this event issues, which is also its transaction log's identifier.
    #[must_use]
    pub const fn credential(&self) -> Said {
        self.credential
    }

    /// Returns the registry whose log this event belongs to.
    #[must_use]
    pub const fn registry(&self) -> &RegistryIdentifier {
        &self.registry
    }

    /// Returns the instant of issuance, which is the credential's own attribute timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Returns this event's position in the credential's transaction log; always
    /// [`ISSUANCE_SEQUENCE_NUMBER`].
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        ISSUANCE_SEQUENCE_NUMBER
    }

    /// Returns the seal a key event anchors this issuance with.
    #[must_use]
    pub const fn seal(&self) -> TransactionSeal {
        TransactionSeal::new(self.credential, ISSUANCE_SEQUENCE_NUMBER, self.said)
    }

    /// Encodes the CESR attachment that authenticates the **credential**.
    ///
    /// It is a seal-source triple naming this event — the credential's own transaction inception —
    /// written without pipelining. This is the reference's `serializeACDCAttachment`, whose
    /// parameter is named `anc` although every call site passes the issuance event; here it is a
    /// method, so there is no argument to get wrong.
    ///
    /// # Errors
    ///
    /// Returns layered [`TransactionError::Attachment`] and [`TransactionError::Said`] failures
    /// for material that cannot be encoded.
    pub fn credential_attachment(&self) -> Result<Vec<u8>, TransactionError> {
        let triple = SealSourceTriple::new(
            IdentifierPrefix::SelfAddressing(self.credential),
            ISSUANCE_SEQUENCE_NUMBER.into(),
            self.said,
        );
        Ok(triple.attachment(AttachmentFraming::Plain)?)
    }
}

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
    /// Encodes the CESR attachment that authenticates the **issuance event**.
    ///
    /// It is a pipelined seal-source couple naming the anchoring key event, which is the
    /// reference's `serializeIssExnAttachment`.
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
    /// Delegates to [`IssuanceEvent::credential_attachment`].
    ///
    /// # Errors
    ///
    /// Returns the failures listed there.
    pub fn credential_attachment(&self) -> Result<Vec<u8>, TransactionError> {
        self.issuance.credential_attachment()
    }
}

/// Issues `credential`: builds its transaction event and the signed key event anchoring it.
///
/// This is the pure half of the reference's `Credentials.issue`, given a credential Roadmap 6.1
/// already built. The anchor lands at the issuer's next sequence number over the state's digest.
///
/// # Errors
///
/// Returns [`TransactionError::EstablishmentOnlyIssuer`] when the issuer's configuration carries
/// `EO`, and the layered failures listed on [`crate::transaction::anchor`] and
/// [`IssuanceEvent::for_credential`].
pub fn issue_credential(
    keeper: &dyn IdentifierKeeper,
    state: &KeyState,
    credential: Credential,
) -> Result<IssuanceArtifacts, TransactionError> {
    let issuance = IssuanceEvent::for_credential(&credential)?;
    let anchor = anchor(keeper, state, &issuance.seal())?;
    Ok(IssuanceArtifacts {
        credential,
        issuance,
        anchor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{CredentialAttributes, CredentialBuilder};
    use crate::transaction::{PRIOR_LABEL, UNSIZED_VERSION_STRING};
    use signify_keri::said::{DEFAULT_SAID_LABEL, SaidVerification};
    use std::error::Error;

    const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
    const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
    const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
    const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
    const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";
    /// The issuance SAID the pinned `credentialing.test.ts` publishes.
    const PUBLISHED_ISSUANCE: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";

    fn credential() -> Result<Credential, Box<dyn Error>> {
        Ok(CredentialBuilder::new(
            IdentifierPrefix::from_qb64(ISSUER)?,
            RegistryIdentifier::from_qb64(REGISTRY)?,
            Said::from_qb64(SCHEMA)?,
            CredentialAttributes::new(STAMP.parse()?)
                .issuee(&IdentifierPrefix::from_qb64(HOLDER)?)?
                .timestamp()?
                .text("LEI", "5493001KJTIIGC8Y1R17")?,
        )
        .build()?)
    }

    #[test]
    fn an_issuance_reproduces_the_published_identifier() -> Result<(), Box<dyn Error>> {
        let issuance = IssuanceEvent::for_credential(&credential()?)?;
        assert_eq!(issuance.said().qb64()?, PUBLISHED_ISSUANCE);
        assert_eq!(
            core::str::from_utf8(issuance.raw())?,
            r#"{"v":"KERI10JSON0000ed_","t":"iss","d":"ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW","i":"EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo","s":"0","ri":"EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df","dt":"2023-08-23T15:16:07.553000+00:00"}"#
        );
        Ok(())
    }

    #[test]
    fn an_issuance_writes_the_reference_field_order() -> Result<(), Box<dyn Error>> {
        let issuance = IssuanceEvent::for_credential(&credential()?)?;
        let labels: Vec<&str> = issuance.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["v", "t", "d", "i", "s", "ri", "dt"]);
        // A revocation's prior field is absent, not empty.
        assert!(!issuance.sad().contains(PRIOR_LABEL));
        assert_eq!(issuance.sad().get_text("t"), Some("iss"));
        assert_eq!(issuance.sad().get_text("s"), Some("0"));
        assert!(UNSIZED_VERSION_STRING.starts_with("KERI"));
        Ok(())
    }

    #[test]
    fn an_issuance_borrows_the_credentials_timestamp() -> Result<(), Box<dyn Error>> {
        let credential = credential()?;
        let issuance = IssuanceEvent::for_credential(&credential)?;
        assert_eq!(issuance.timestamp(), credential.timestamp());
        assert_eq!(issuance.sad().get_text("dt"), Some(STAMP));
        // And it is the same instant the credential's attribute block carries.
        assert_eq!(
            credential.attributes().and_then(|block| block.get_text("dt")),
            Some(STAMP)
        );
        Ok(())
    }

    #[test]
    fn an_issuance_carries_its_own_identifier() -> Result<(), Box<dyn Error>> {
        let issuance = IssuanceEvent::for_credential(&credential()?)?;
        issuance
            .said()
            .verify(issuance.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())?;
        assert_eq!(issuance.serialized().size(), issuance.raw().len());
        assert_eq!(SerializedEvent::parse(issuance.raw())?.sad(), issuance.sad());
        Ok(())
    }

    #[test]
    fn an_issuance_names_the_credential_it_issues() -> Result<(), Box<dyn Error>> {
        let credential = credential()?;
        let issuance = IssuanceEvent::for_credential(&credential)?;
        assert_eq!(issuance.credential(), credential.said());
        assert_eq!(issuance.registry(), credential.registry());
        assert_eq!(issuance.sequence_number(), ISSUANCE_SEQUENCE_NUMBER);
        assert_eq!(issuance.sequence_number(), 0);
        Ok(())
    }

    #[test]
    fn the_seal_names_the_transaction_event() -> Result<(), Box<dyn Error>> {
        let issuance = IssuanceEvent::for_credential(&credential()?)?;
        let seal = issuance.seal();
        assert_eq!(seal.credential(), issuance.credential());
        assert_eq!(seal.sequence_number(), 0);
        assert_eq!(seal.said(), issuance.said());
        Ok(())
    }

    #[test]
    fn the_credential_attachment_is_the_published_triple() -> Result<(), Box<dyn Error>> {
        let issuance = IssuanceEvent::for_credential(&credential()?)?;
        assert_eq!(
            core::str::from_utf8(&issuance.credential_attachment()?)?,
            "-IABEMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo0AAAAAAAAAAAAAAAAAAAAAAAENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW"
        );
        Ok(())
    }

    #[test]
    fn building_from_values_and_from_a_credential_agree() -> Result<(), Box<dyn Error>> {
        let credential = credential()?;
        let direct = IssuanceEvent::new(
            credential.said(),
            RegistryIdentifier::from_qb64(REGISTRY)?,
            STAMP.parse()?,
        )?;
        assert_eq!(direct, IssuanceEvent::for_credential(&credential)?);
        Ok(())
    }

    #[test]
    fn a_different_timestamp_derives_a_different_issuance() -> Result<(), Box<dyn Error>> {
        let credential = credential()?;
        let first = IssuanceEvent::for_credential(&credential)?;
        let second = IssuanceEvent::new(
            credential.said(),
            RegistryIdentifier::from_qb64(REGISTRY)?,
            "2021-06-27T21:26:21.233257+00:00".parse()?,
        )?;
        assert_ne!(first.said(), second.said());
        assert_eq!(first.raw().len(), second.raw().len());
        Ok(())
    }
}
