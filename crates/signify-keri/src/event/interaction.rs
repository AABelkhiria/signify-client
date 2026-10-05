//! Interaction events.
//!
//! An interaction event anchors data to an identifier's key event log without changing its keys.
//! Because it establishes nothing, it carries no thresholds, keys, or witnesses — only the
//! identifier, its place in the log, and the seals being anchored.
//!
//! This module ports `interact` from `src/keri/core/eventing.ts`.

use crate::event::error::EventError;
use crate::event::inception::ANCHORS_LABEL;
use crate::event::key_event::{KeyEvent, anchors_value, sequence_value};
use crate::event::kind::EventKind;
use crate::event::rotation::PRIOR_LABEL;
use crate::prefix::IdentifierPrefix;
use crate::said::{DEFAULT_SAID_LABEL, Said};
use crate::serialization::{
    IDENTIFIER_LABEL, KIND_LABEL, SAID_LABEL, SEQUENCE_LABEL, Sad, SadValue, SerializedEvent, VERSION_LABEL,
};
use keri_cesr::crypto::digest::DigestAlgorithm;

/// Builds an interaction (`ixn`) event.
///
/// ```
/// use signify_keri::event::interaction::InteractionBuilder;
/// use signify_keri::prefix::IdentifierPrefix;
/// use signify_keri::said::Said;
/// use signify_keri::serialization::{Sad, SadValue};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let identifier = IdentifierPrefix::from_qb64("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C")?;
/// let prior = Said::from_qb64("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C")?;
///
/// let mut seal = Sad::new();
/// seal.insert("i", SadValue::text("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"))?;
/// seal.insert("s", SadValue::text("0"))?;
///
/// let event = InteractionBuilder::new(identifier, prior, 2)
///     .anchors(vec![seal])
///     .build()?;
/// assert_eq!(event.sad().get_text("s"), Some("2"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct InteractionBuilder {
    identifier: IdentifierPrefix,
    prior: Said,
    sequence_number: u128,
    anchors: Vec<Sad>,
}

impl InteractionBuilder {
    /// Starts an interaction on `identifier` following the event whose digest is `prior`.
    #[must_use]
    pub const fn new(identifier: IdentifierPrefix, prior: Said, sequence_number: u128) -> Self {
        Self {
            identifier,
            prior,
            sequence_number,
            anchors: Vec::new(),
        }
    }

    /// Anchors seals in the event.
    #[must_use]
    pub fn anchors(mut self, anchors: Vec<Sad>) -> Self {
        self.anchors = anchors;
        self
    }

    /// Validates the sequence number and serializes the event.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::SequenceNumberTooSmall`] for sequence number zero, which belongs to
    /// the inception event, and layered failures for material that cannot be encoded.
    pub fn build(self) -> Result<KeyEvent, EventError> {
        if self.sequence_number < 1 {
            return Err(EventError::SequenceNumberTooSmall);
        }

        let mut fields = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            fields.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        insert(VERSION_LABEL, SadValue::text("KERI10JSON000000_"))?;
        insert(KIND_LABEL, SadValue::text(EventKind::Interaction.as_str()))?;
        insert(SAID_LABEL, SadValue::text(""))?;
        insert(
            IDENTIFIER_LABEL,
            SadValue::Text(self.identifier.qb64().map_err(EventError::prefix)?),
        )?;
        insert(SEQUENCE_LABEL, sequence_value(self.sequence_number))?;
        insert(
            PRIOR_LABEL,
            SadValue::Text(self.prior.qb64().map_err(EventError::said)?),
        )?;
        insert(ANCHORS_LABEL, anchors_value(&self.anchors))?;

        let computation =
            Said::compute(&fields, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL).map_err(EventError::said)?;
        let (event_said, completed) = computation.into_parts();
        let serialized = SerializedEvent::from_sad(completed).map_err(EventError::serialization)?;
        Ok(KeyEvent::new(
            serialized,
            self.identifier,
            event_said,
            EventKind::Interaction,
            self.sequence_number,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const IDENTIFIER: &str = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C";

    fn builder(sequence_number: u128) -> Result<InteractionBuilder, Box<dyn Error>> {
        Ok(InteractionBuilder::new(
            IdentifierPrefix::from_qb64(IDENTIFIER)?,
            Said::from_qb64(IDENTIFIER)?,
            sequence_number,
        ))
    }

    #[test]
    fn field_order_is_the_protocol_order() -> Result<(), Box<dyn Error>> {
        let event = builder(1)?.build()?;
        let labels: Vec<&str> = event.sad().entries().map(|(label, _)| label).collect();
        // An interaction establishes nothing, so it carries no keys, thresholds, or witnesses.
        assert_eq!(labels, ["v", "t", "d", "i", "s", "p", "a"]);
        assert_eq!(event.kind(), EventKind::Interaction);
        assert_eq!(event.sad().get("a"), Some(&SadValue::Array(Vec::new())));
        Ok(())
    }

    #[test]
    fn anchors_are_written_in_order() -> Result<(), Box<dyn Error>> {
        let mut first = Sad::new();
        first.insert("i", SadValue::text(IDENTIFIER))?;
        first.insert("s", SadValue::text("0"))?;
        let mut second = Sad::new();
        second.insert("d", SadValue::text(IDENTIFIER))?;

        let event = builder(2)?.anchors(vec![first.clone(), second.clone()]).build()?;
        assert_eq!(
            event.sad().get("a"),
            Some(&SadValue::Array(vec![SadValue::Map(first), SadValue::Map(second)]))
        );
        assert_eq!(event.sequence_number(), 2);
        assert_eq!(event.sad().get_text("s"), Some("2"));
        Ok(())
    }

    #[test]
    fn sequence_number_zero_belongs_to_the_inception_event() -> Result<(), Box<dyn Error>> {
        assert!(matches!(builder(0)?.build(), Err(EventError::SequenceNumberTooSmall)));
        // Large sequence numbers stay hexadecimal.
        assert_eq!(builder(255)?.build()?.sad().get_text("s"), Some("ff"));
        Ok(())
    }

    #[test]
    fn the_finished_event_is_self_consistent() -> Result<(), Box<dyn Error>> {
        let event = builder(1)?.build()?;
        assert_eq!(event.serialized().size(), event.raw().len());
        assert_eq!(SerializedEvent::parse(event.raw())?.sad(), event.sad());
        assert_eq!(event.identifier().qb64()?, IDENTIFIER);
        assert_eq!(event.sad().get_text("p"), Some(IDENTIFIER));
        assert_ne!(event.said().qb64()?, IDENTIFIER);
        Ok(())
    }
}
