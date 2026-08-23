//! Revoking a credential: the `rev` transaction event and the key event anchoring it.
//!
//! Revocation appends a second event to the credential's transaction log, naming the event it
//! supersedes, and the issuer anchors it exactly as it anchored the issuance. Nothing about the
//! credential document changes — a revoked credential is byte-identical to an issued one — so the
//! transaction log is the only thing that says which it is.
//!
//! This module ports the pure half of `Credentials.revoke` in the pinned
//! `src/keri/app/credentialing.ts`. Submitting the result is Roadmap 6.11.
//!
//! # What the reference cannot express
//!
//! Two of its inputs are effectively fixed. Its sequence number is the literal `'1'`, so it can
//! only revoke a credential whose transaction log holds exactly one prior event; and its prior
//! digest is read from `cred.status.d`, the state KERIA returns, so it cannot build a revocation
//! without a round trip first. Both are ordinary inputs here — defaulting to the reference's
//! values — which makes a revocation constructible offline and correct in a backed registry whose
//! log carries backer rotations. See `fixtures/acdc-issuance/`.
//!
//! # Example
//!
//! ```
//! use signify_acdc::credential::RegistryIdentifier;
//! use signify_acdc::revocation::RevocationEventBuilder;
//! use signify_keri::said::Said;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let revocation = RevocationEventBuilder::new(
//!     Said::from_qb64("EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo")?,
//!     RegistryIdentifier::from_qb64("EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df")?,
//!     Said::from_qb64("ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW")?,
//!     "2023-08-23T15:16:07.553000+00:00".parse()?,
//! )
//! .build()?;
//!
//! assert_eq!(revocation.sad().get_text("t"), Some("rev"));
//! assert_eq!(revocation.sequence_number(), 1);
//! # Ok(())
//! # }
//! ```

use signify_keri::event::Timestamp;
use signify_keri::event::kind::EventKind;
use signify_keri::identifier::artifact::IdentifierArtifact;
use signify_keri::manager::keeper::IdentifierKeeper;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SerializedEvent};
use signify_types::api::KeyState;

use crate::credential::RegistryIdentifier;
use crate::error::TransactionError;
use crate::transaction::{TransactionSeal, anchor, assemble};

/// Position of a revocation in a credential's transaction event log when nothing else intervenes.
///
/// The reference writes the literal `'1'`, which is correct exactly when the log holds only the
/// issuance. [`RevocationEventBuilder::sequence_number`] overrides it.
pub const DEFAULT_REVOCATION_SEQUENCE_NUMBER: u128 = 1;

/// One `rev` transaction event: the record that a credential was revoked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationEvent {
    serialized: SerializedEvent,
    said: Said,
    credential: Said,
    registry: RegistryIdentifier,
    prior: Said,
    sequence_number: u128,
    timestamp: Timestamp,
}

impl RevocationEvent {
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

    /// Returns the credential this event revokes.
    #[must_use]
    pub const fn credential(&self) -> Said {
        self.credential
    }

    /// Returns the registry whose log this event belongs to.
    #[must_use]
    pub const fn registry(&self) -> &RegistryIdentifier {
        &self.registry
    }

    /// Returns the digest of the transaction event this one supersedes.
    #[must_use]
    pub const fn prior(&self) -> Said {
        self.prior
    }

    /// Returns this event's position in the credential's transaction log.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the instant of revocation.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Returns the seal a key event anchors this revocation with.
    #[must_use]
    pub const fn seal(&self) -> TransactionSeal {
        TransactionSeal::new(self.credential, self.sequence_number, self.said)
    }
}

/// Builds a `rev` transaction event.
#[derive(Clone, Debug)]
pub struct RevocationEventBuilder {
    credential: Said,
    registry: RegistryIdentifier,
    prior: Said,
    timestamp: Timestamp,
    sequence_number: u128,
}

impl RevocationEventBuilder {
    /// Starts a revocation of `credential` in `registry`, superseding `prior`.
    ///
    /// `prior` is the digest of the credential's current transaction event — its issuance, unless
    /// the registry's log has moved on. The reference reads it from the credential state KERIA
    /// returns; here it is an input, so a revocation is constructible offline.
    ///
    /// The reference defaults the timestamp to a clock reading; a protocol crate reads no clock,
    /// so a caller supplies a validated [`Timestamp`].
    #[must_use]
    pub const fn new(credential: Said, registry: RegistryIdentifier, prior: Said, timestamp: Timestamp) -> Self {
        Self {
            credential,
            registry,
            prior,
            timestamp,
            sequence_number: DEFAULT_REVOCATION_SEQUENCE_NUMBER,
        }
    }

    /// Places the revocation elsewhere than immediately after the issuance.
    ///
    /// Defaults to [`DEFAULT_REVOCATION_SEQUENCE_NUMBER`], the only value the reference can write.
    #[must_use]
    pub const fn sequence_number(mut self, sequence_number: u128) -> Self {
        self.sequence_number = sequence_number;
        self
    }

    /// Derives the event's identifier and serializes it.
    ///
    /// # Errors
    ///
    /// Returns layered [`TransactionError::Said`], [`TransactionError::Sad`],
    /// [`TransactionError::Prefix`], and [`TransactionError::Serialization`] failures for material
    /// that cannot be encoded.
    pub fn build(self) -> Result<RevocationEvent, TransactionError> {
        let registry_text = self.registry.qb64()?;
        let (serialized, said) = assemble(
            EventKind::Revocation,
            self.credential,
            &registry_text,
            self.sequence_number,
            Some(self.prior),
            &self.timestamp,
        )?;
        Ok(RevocationEvent {
            serialized,
            said,
            credential: self.credential,
            registry: self.registry,
            prior: self.prior,
            sequence_number: self.sequence_number,
            timestamp: self.timestamp,
        })
    }
}

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
/// This is the pure half of the reference's `Credentials.revoke`. Unlike issuance it produces no
/// attachments, because nothing upstream carries a revocation in a disclosure.
///
/// # Errors
///
/// Returns [`TransactionError::EstablishmentOnlyIssuer`] when the issuer's configuration carries
/// `EO`, and the layered failures listed on [`crate::transaction::anchor`].
pub fn revoke_credential(
    keeper: &dyn IdentifierKeeper,
    state: &KeyState,
    revocation: RevocationEvent,
) -> Result<RevocationArtifacts, TransactionError> {
    let anchor = anchor(keeper, state, &revocation.seal())?;
    Ok(RevocationArtifacts { revocation, anchor })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::PRIOR_LABEL;
    use signify_keri::said::{DEFAULT_SAID_LABEL, SaidVerification};
    use std::error::Error;

    const CREDENTIAL: &str = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo";
    const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
    const ISSUANCE: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";
    const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

    fn builder() -> Result<RevocationEventBuilder, Box<dyn Error>> {
        Ok(RevocationEventBuilder::new(
            Said::from_qb64(CREDENTIAL)?,
            RegistryIdentifier::from_qb64(REGISTRY)?,
            Said::from_qb64(ISSUANCE)?,
            STAMP.parse()?,
        ))
    }

    #[test]
    fn a_revocation_writes_the_reference_field_order() -> Result<(), Box<dyn Error>> {
        let revocation = builder()?.build()?;
        let labels: Vec<&str> = revocation.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["v", "t", "d", "i", "s", "ri", "p", "dt"]);
        assert_eq!(revocation.sad().get_text("t"), Some("rev"));
        assert_eq!(revocation.sad().get_text("s"), Some("1"));
        assert_eq!(revocation.sad().get_text(PRIOR_LABEL), Some(ISSUANCE));
        Ok(())
    }

    #[test]
    fn a_revocation_carries_its_own_identifier() -> Result<(), Box<dyn Error>> {
        let revocation = builder()?.build()?;
        revocation
            .said()
            .verify(revocation.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())?;
        assert_eq!(revocation.serialized().size(), revocation.raw().len());
        assert_eq!(SerializedEvent::parse(revocation.raw())?.sad(), revocation.sad());
        Ok(())
    }

    #[test]
    fn a_revocation_reports_what_it_was_built_from() -> Result<(), Box<dyn Error>> {
        let revocation = builder()?.build()?;
        assert_eq!(revocation.credential().qb64()?, CREDENTIAL);
        assert_eq!(revocation.registry().qb64()?, REGISTRY);
        assert_eq!(revocation.prior().qb64()?, ISSUANCE);
        assert_eq!(revocation.timestamp().as_str(), STAMP);
        assert_eq!(revocation.sequence_number(), DEFAULT_REVOCATION_SEQUENCE_NUMBER);
        Ok(())
    }

    #[test]
    fn the_sequence_number_defaults_to_the_only_value_the_reference_writes() -> Result<(), Box<dyn Error>> {
        assert_eq!(DEFAULT_REVOCATION_SEQUENCE_NUMBER, 1);
        assert_eq!(builder()?.build()?.sequence_number(), 1);

        // And a log with intervening events can still be revoked here.
        let later = builder()?.sequence_number(9).build()?;
        assert_eq!(later.sad().get_text("s"), Some("9"));
        assert_eq!(later.sequence_number(), 9);

        let hexadecimal = builder()?.sequence_number(255).build()?;
        assert_eq!(hexadecimal.sad().get_text("s"), Some("ff"));
        Ok(())
    }

    #[test]
    fn the_seal_names_the_revocation_at_its_own_position() -> Result<(), Box<dyn Error>> {
        let revocation = builder()?.sequence_number(3).build()?;
        let seal = revocation.seal();
        assert_eq!(seal.credential(), revocation.credential());
        assert_eq!(seal.sequence_number(), 3);
        assert_eq!(seal.said(), revocation.said());
        assert_eq!(seal.to_sad()?.get_text("s"), Some("3"));
        Ok(())
    }

    #[test]
    fn every_named_field_changes_the_identifier() -> Result<(), Box<dyn Error>> {
        let reference = builder()?.build()?;
        let variants = [
            builder()?.sequence_number(2).build()?,
            RevocationEventBuilder::new(
                Said::from_qb64(ISSUANCE)?,
                RegistryIdentifier::from_qb64(REGISTRY)?,
                Said::from_qb64(ISSUANCE)?,
                STAMP.parse()?,
            )
            .build()?,
            RevocationEventBuilder::new(
                Said::from_qb64(CREDENTIAL)?,
                RegistryIdentifier::from_qb64(REGISTRY)?,
                Said::from_qb64(CREDENTIAL)?,
                STAMP.parse()?,
            )
            .build()?,
            RevocationEventBuilder::new(
                Said::from_qb64(CREDENTIAL)?,
                RegistryIdentifier::from_qb64(REGISTRY)?,
                Said::from_qb64(ISSUANCE)?,
                "2021-06-27T21:26:21.233257+00:00".parse()?,
            )
            .build()?,
        ];
        for variant in &variants {
            assert_ne!(variant.said(), reference.said());
            assert_ne!(variant.raw(), reference.raw());
        }
        Ok(())
    }
}
