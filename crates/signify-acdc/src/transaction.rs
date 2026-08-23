//! What issuance and revocation have in common: a transaction event's shape, the seal that binds
//! it to a key event log, and the interaction event that carries that seal.
//!
//! A credential's *status* lives in its registry's transaction event log, not in the credential.
//! Issuing writes an `iss` event to that log; revoking writes a `rev`. Neither is trusted on its
//! own: the issuer also appends an interaction event to its own key event log sealing the
//! transaction event's identifier, sequence number, and digest, and signs that. So a verifier
//! follows the seal from a signed key event to the transaction event to the credential.
//!
//! This module ports the parts of `Credentials.issue` and `Credentials.revoke` in the pinned
//! `src/keri/app/credentialing.ts` that both perform. The events themselves are
//! [`issuance`](crate::issuance) and [`revocation`](crate::revocation).

use signify_keri::event::ConfigurationTrait;
use signify_keri::event::interaction::InteractionBuilder;
use signify_keri::event::kind::EventKind;
use signify_keri::event::{KeyEvent, Timestamp};
use signify_keri::identifier::artifact::{IdentifierArtifact, interact_identifier};
use signify_keri::manager::keeper::IdentifierKeeper;
use signify_keri::prefix::{IdentifierPrefix, PrefixError};
use signify_keri::said::{DEFAULT_SAID_LABEL, Said};
use signify_keri::serialization::{
    IDENTIFIER_LABEL, KIND_LABEL, SAID_LABEL, SEQUENCE_LABEL, Sad, SadValue, SerializedEvent, VERSION_LABEL,
};
use signify_types::api::KeyState;

use crate::credential::REGISTRY_LABEL;
use crate::error::TransactionError;

/// Field label carrying the prior transaction event's digest; a revocation's `p`.
pub const PRIOR_LABEL: &str = "p";
/// Field label carrying a transaction event's timestamp; its `dt`.
pub const TIMESTAMP_LABEL: &str = "dt";

/// Version string written before a transaction event's size is known.
///
/// A transaction event is a KERI message, not an ACDC document, so its protocol is `KERI` even
/// though it exists only to talk about a credential.
pub const UNSIZED_VERSION_STRING: &str = "KERI10JSON000000_";

/// The `{i, s, d}` seal a key event carries to anchor a transaction event.
///
/// This is what makes a transaction event trustworthy: the issuer's signed key event commits to
/// exactly this identifier, position, and digest, so a verifier that trusts the key event log
/// trusts the transaction event it names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionSeal {
    credential: Said,
    sequence_number: u128,
    said: Said,
}

impl TransactionSeal {
    /// Builds a seal naming a transaction event's credential, position, and digest.
    #[must_use]
    pub const fn new(credential: Said, sequence_number: u128, said: Said) -> Self {
        Self {
            credential,
            sequence_number,
            said,
        }
    }

    /// Returns the credential the sealed event is about, which is also its transaction log's
    /// identifier.
    #[must_use]
    pub const fn credential(&self) -> Said {
        self.credential
    }

    /// Returns the sealed event's position in that log.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the sealed event's own digest.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Renders the seal as the ordered field map a key event anchors.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::Said`] when a digest cannot be encoded and
    /// [`TransactionError::Sad`] when the map cannot be assembled.
    pub fn to_sad(&self) -> Result<Sad, TransactionError> {
        let mut seal = Sad::new();
        seal.insert(IDENTIFIER_LABEL, SadValue::Text(self.credential.qb64()?))?;
        seal.insert(SEQUENCE_LABEL, SadValue::Text(format!("{:x}", self.sequence_number)))?;
        seal.insert(SAID_LABEL, SadValue::Text(self.said.qb64()?))?;
        Ok(seal)
    }
}

/// Builds and signs the interaction event anchoring `seal` in the issuer's key event log.
///
/// The event lands at the state's next sequence number, over the state's digest, carrying exactly
/// one seal — which is what both `issue` and `revoke` do.
///
/// # Errors
///
/// Returns [`TransactionError::EstablishmentOnlyIssuer`] when the state's configuration carries
/// `EO`, because such an identifier may only anchor in a rotation event; the reference throws
/// `Establishment only not implemented` in the same place.
/// [`TransactionError::SequenceNumberOverflow`] when the log cannot advance, and layered
/// [`TransactionError::Sad`], [`TransactionError::Said`], and [`TransactionError::Identifier`]
/// failures for material that cannot be encoded or signed.
pub fn anchor(
    keeper: &dyn IdentifierKeeper,
    state: &KeyState,
    seal: &TransactionSeal,
) -> Result<IdentifierArtifact, TransactionError> {
    if is_establishment_only(state) {
        return Err(TransactionError::establishment_only());
    }
    Ok(interact_identifier(keeper, state, vec![seal.to_sad()?])?)
}

/// Builds the same interaction event without signing it.
///
/// A multisig member's signature comes from somewhere else, and a caller may want to inspect the
/// event before committing a key to it, so the unsigned event is available on its own. It is byte
/// identical to the one [`anchor`] signs, which a test asserts.
///
/// # Errors
///
/// Returns [`TransactionError::EstablishmentOnlyIssuer`] and
/// [`TransactionError::SequenceNumberOverflow`] as [`anchor`] does, plus layered
/// [`TransactionError::Prefix`], [`TransactionError::Said`], and [`TransactionError::Event`]
/// failures for a key state this port cannot read.
pub fn anchor_event(state: &KeyState, seal: &TransactionSeal) -> Result<KeyEvent, TransactionError> {
    if is_establishment_only(state) {
        return Err(TransactionError::establishment_only());
    }
    let identifier = IdentifierPrefix::from_qb64(&state.identifier)?;
    let prior = Said::from_qb64(&state.digest)?;
    let sequence_number = next_sequence_number(state)?;
    Ok(InteractionBuilder::new(identifier, prior, sequence_number)
        .anchors(vec![seal.to_sad()?])
        .build()?)
}

/// Returns the sequence number an event appended to this key state would occupy.
///
/// The state's own number is hexadecimal text, as the protocol writes it.
fn next_sequence_number(state: &KeyState) -> Result<u128, TransactionError> {
    let current = u128::from_str_radix(&state.sequence_number, 16).map_err(|_| TransactionError::Prefix {
        source: Box::new(PrefixError::UnsupportedCode { code: "sequence" }),
    })?;
    current
        .checked_add(1)
        .ok_or(TransactionError::SequenceNumberOverflow { current })
}

/// Returns whether this key state forbids anchoring in an interaction event.
#[must_use]
pub fn is_establishment_only(state: &KeyState) -> bool {
    state
        .configuration
        .iter()
        .any(|entry| entry == ConfigurationTrait::EstablishmentOnly.as_str())
}

/// Assembles, derives, and serializes one transaction event.
///
/// The field order is the reference's: `v`, `t`, `d`, `i`, `s`, `ri`, then a revocation's `p`,
/// then `dt`. Both events are built by the same expression apart from that one field, so they are
/// built by the same code here.
pub(crate) fn assemble(
    kind: EventKind,
    credential: Said,
    registry: &str,
    sequence_number: u128,
    prior: Option<Said>,
    timestamp: &Timestamp,
) -> Result<(SerializedEvent, Said), TransactionError> {
    let mut fields = Sad::new();
    fields.insert(VERSION_LABEL, SadValue::text(UNSIZED_VERSION_STRING))?;
    fields.insert(KIND_LABEL, SadValue::text(kind.as_str()))?;
    fields.insert(SAID_LABEL, SadValue::text(""))?;
    fields.insert(IDENTIFIER_LABEL, SadValue::Text(credential.qb64()?))?;
    fields.insert(SEQUENCE_LABEL, SadValue::Text(format!("{sequence_number:x}")))?;
    fields.insert(REGISTRY_LABEL, SadValue::text(registry))?;
    if let Some(prior) = prior {
        fields.insert(PRIOR_LABEL, SadValue::Text(prior.qb64()?))?;
    }
    fields.insert(TIMESTAMP_LABEL, SadValue::text(timestamp.as_str()))?;

    let (said, completed) =
        Said::compute(&fields, crate::credential::DIGEST_ALGORITHM, DEFAULT_SAID_LABEL)?.into_parts();
    Ok((SerializedEvent::from_sad(completed)?, said))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const CREDENTIAL: &str = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo";
    const ISSUANCE: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";

    #[test]
    fn a_seal_renders_the_three_fields_a_key_event_anchors() -> Result<(), Box<dyn Error>> {
        let seal = TransactionSeal::new(Said::from_qb64(CREDENTIAL)?, 0, Said::from_qb64(ISSUANCE)?);
        assert_eq!(seal.credential().qb64()?, CREDENTIAL);
        assert_eq!(seal.sequence_number(), 0);
        assert_eq!(seal.said().qb64()?, ISSUANCE);

        let sad = seal.to_sad()?;
        let labels: Vec<&str> = sad.entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["i", "s", "d"]);
        assert_eq!(sad.get_text("i"), Some(CREDENTIAL));
        assert_eq!(sad.get_text("s"), Some("0"));
        assert_eq!(sad.get_text("d"), Some(ISSUANCE));
        Ok(())
    }

    #[test]
    fn a_seal_writes_its_position_in_lowercase_hexadecimal() -> Result<(), Box<dyn Error>> {
        let said = Said::from_qb64(CREDENTIAL)?;
        for (sequence_number, expected) in [
            (0_u128, "0"),
            (1, "1"),
            (10, "a"),
            (255, "ff"),
            (4_294_967_296, "100000000"),
        ] {
            let seal = TransactionSeal::new(said, sequence_number, said);
            assert_eq!(seal.to_sad()?.get_text("s"), Some(expected));
        }
        Ok(())
    }

    #[test]
    fn the_establishment_only_trait_is_recognised_by_its_wire_text() {
        assert_eq!(ConfigurationTrait::EstablishmentOnly.as_str(), "EO");
        assert!(matches!(
            TransactionError::establishment_only(),
            TransactionError::EstablishmentOnlyIssuer { trait_code: "EO" }
        ));
    }

    #[test]
    fn the_version_string_is_a_keri_message_not_an_acdc_document() {
        assert!(UNSIZED_VERSION_STRING.starts_with("KERI"));
        assert_eq!(UNSIZED_VERSION_STRING.len(), 17);
    }
}
