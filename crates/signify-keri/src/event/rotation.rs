//! Rotation and delegated-rotation events.
//!
//! A rotation event replaces an identifier's signing keys with the ones its previous establishment
//! event committed to, commits to the next set in turn, and may add or remove witnesses.
//!
//! This module ports the `rotate` half of `src/keri/core/eventing.ts`.

use keri_cesr::crypto::digest::Digest;
use keri_cesr::crypto::verifier::VerificationKey;

use crate::event::error::EventError;
use crate::event::inception::{ANCHORS_LABEL, NEXT_THRESHOLD_LABEL, SIGNING_THRESHOLD_LABEL, WITNESS_THRESHOLD_LABEL};
use crate::event::key_event::{
    KeyEvent, ThresholdEncoding, anchors_value, check_distinct, check_next_threshold, check_signing_threshold,
    check_witness_threshold, default_next_threshold, default_signing_threshold, digests_value, keys_value,
    prefixes_value, sequence_value, textual_threshold, witness_threshold_value,
};
use crate::event::kind::EventKind;
use crate::event::witness::{AmpleMode, ample};
use crate::prefix::IdentifierPrefix;
use crate::said::{DEFAULT_SAID_LABEL, Said};
use crate::serialization::{
    IDENTIFIER_LABEL, KEYS_LABEL, KIND_LABEL, NEXT_KEYS_LABEL, SAID_LABEL, SEQUENCE_LABEL, Sad, SadValue,
    SerializedEvent, VERSION_LABEL,
};
use crate::threshold::SigningThreshold;
use keri_cesr::crypto::digest::DigestAlgorithm;

/// Field label carrying the prior event's digest.
pub const PRIOR_LABEL: &str = "p";
/// Field label carrying the witnesses being removed.
pub const WITNESS_CUTS_LABEL: &str = "br";
/// Field label carrying the witnesses being added.
pub const WITNESS_ADDS_LABEL: &str = "ba";

/// Whether a rotation is ordinary or delegated.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum RotationKind {
    /// An ordinary rotation (`rot`).
    #[default]
    Rotation,
    /// A rotation of a delegated identifier (`drt`).
    Delegated,
}

impl RotationKind {
    /// Returns the event kind this rotation writes.
    #[must_use]
    pub const fn event_kind(self) -> EventKind {
        match self {
            Self::Rotation => EventKind::Rotation,
            Self::Delegated => EventKind::DelegatedRotation,
        }
    }
}

/// Builds a rotation (`rot`) or delegated-rotation (`drt`) event.
///
/// ```
/// use keri_cesr::crypto::verifier::VerificationKey;
/// use signify_keri::event::rotation::RotationBuilder;
/// use signify_keri::prefix::IdentifierPrefix;
/// use signify_keri::said::Said;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let identifier = IdentifierPrefix::from_qb64("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C")?;
/// let prior = Said::from_qb64("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C")?;
/// let key = VerificationKey::from_qb64("DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ")?;
///
/// let event = RotationBuilder::new(identifier, prior, 1, vec![key]).build()?;
/// assert_eq!(event.sequence_number(), 1);
/// assert_eq!(event.sad().get_text("s"), Some("1"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct RotationBuilder {
    identifier: IdentifierPrefix,
    prior: Said,
    sequence_number: u128,
    keys: Vec<VerificationKey>,
    kind: RotationKind,
    signing_threshold: Option<SigningThreshold>,
    next_key_digests: Vec<Digest>,
    next_threshold: Option<SigningThreshold>,
    witnesses: Vec<IdentifierPrefix>,
    witness_cuts: Vec<IdentifierPrefix>,
    witness_adds: Vec<IdentifierPrefix>,
    witness_threshold: Option<u32>,
    anchors: Vec<Sad>,
    encoding: ThresholdEncoding,
}

impl RotationBuilder {
    /// Starts a rotation of `identifier` following the event whose digest is `prior`.
    ///
    /// The reference leaves the identifier and prior digest optional and writes an event with the
    /// corresponding field missing when either is absent; both are required here.
    #[must_use]
    pub fn new(identifier: IdentifierPrefix, prior: Said, sequence_number: u128, keys: Vec<VerificationKey>) -> Self {
        Self {
            identifier,
            prior,
            sequence_number,
            keys,
            kind: RotationKind::Rotation,
            signing_threshold: None,
            next_key_digests: Vec::new(),
            next_threshold: None,
            witnesses: Vec::new(),
            witness_cuts: Vec::new(),
            witness_adds: Vec::new(),
            witness_threshold: None,
            anchors: Vec::new(),
            encoding: ThresholdEncoding::Integer,
        }
    }

    /// Selects an ordinary or delegated rotation; ordinary by default.
    #[must_use]
    pub const fn kind(mut self, kind: RotationKind) -> Self {
        self.kind = kind;
        self
    }

    /// Sets how many of the new signing keys must sign; a simple majority by default.
    #[must_use]
    pub fn signing_threshold(mut self, threshold: SigningThreshold) -> Self {
        self.signing_threshold = Some(threshold);
        self
    }

    /// Commits to the digests of the keys this identifier may rotate to next.
    ///
    /// Leaving this empty abandons the identifier. The reference cannot express that: its default
    /// next threshold is at least one, and an explicit zero is rejected outright, so no rotation it
    /// builds can ever be the last one. See `PORTING.md` §9.
    #[must_use]
    pub fn next_key_digests(mut self, digests: Vec<Digest>) -> Self {
        self.next_key_digests = digests;
        self
    }

    /// Sets how many of the next keys must sign the following rotation.
    #[must_use]
    pub fn next_threshold(mut self, threshold: SigningThreshold) -> Self {
        self.next_threshold = Some(threshold);
        self
    }

    /// Names the witnesses currently in effect, before this event's cuts and additions.
    #[must_use]
    pub fn witnesses(mut self, witnesses: Vec<IdentifierPrefix>) -> Self {
        self.witnesses = witnesses;
        self
    }

    /// Removes witnesses; each must currently be in effect.
    #[must_use]
    pub fn witness_cuts(mut self, cuts: Vec<IdentifierPrefix>) -> Self {
        self.witness_cuts = cuts;
        self
    }

    /// Adds witnesses; none may already be in effect.
    #[must_use]
    pub fn witness_adds(mut self, adds: Vec<IdentifierPrefix>) -> Self {
        self.witness_adds = adds;
        self
    }

    /// Sets how many witness receipts an event needs after this rotation takes effect.
    ///
    /// Defaults to [`ample`] of the resulting witness set.
    #[must_use]
    pub fn witness_threshold(mut self, threshold: u32) -> Self {
        self.witness_threshold = Some(threshold);
        self
    }

    /// Anchors seals in the event.
    #[must_use]
    pub fn anchors(mut self, anchors: Vec<Sad>) -> Self {
        self.anchors = anchors;
        self
    }

    /// Chooses how the witness threshold is written.
    ///
    /// Rotation defaults to [`ThresholdEncoding::Integer`], matching the reference's `intive = true`
    /// — the opposite of inception's default. The setting affects only the witness threshold here:
    /// the reference writes rotation's signing thresholds as text either way, and that is
    /// reproduced because it is observable on the wire.
    #[must_use]
    pub const fn threshold_encoding(mut self, encoding: ThresholdEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// Validates every field and serializes the event.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::SequenceNumberTooSmall`] for sequence number zero, which belongs to
    /// the inception event; the threshold and witness errors listed on
    /// [`InceptionBuilder::build`](crate::event::inception::InceptionBuilder::build); and
    /// [`EventError::ConflictingWitnessLists`] or [`EventError::WitnessCutNotPresent`] when the
    /// cuts and additions do not describe a consistent change to the witness set.
    pub fn build(self) -> Result<KeyEvent, EventError> {
        if self.sequence_number < 1 {
            return Err(EventError::SequenceNumberTooSmall);
        }
        // Resolved before any field is moved out, because it inspects three lists together.
        let resulting = self.resulting_witnesses()?;

        let signing = match self.signing_threshold {
            Some(threshold) => threshold,
            None => default_signing_threshold(self.keys.len())?,
        };
        check_signing_threshold(&signing, self.keys.len())?;

        let next = match self.next_threshold {
            Some(threshold) => threshold,
            None => default_next_threshold(self.next_key_digests.len())?,
        };
        check_next_threshold(&next, self.next_key_digests.len())?;

        let resulting_count = u32::try_from(resulting).map_err(|_| EventError::ValueOutOfRange {
            context: "witness count",
        })?;
        let witness_threshold = match self.witness_threshold {
            Some(threshold) => threshold,
            None if resulting_count == 0 => 0,
            None => ample(resulting_count, None, AmpleMode::Weak)?,
        };
        check_witness_threshold(witness_threshold, resulting)?;

        let kind = self.kind.event_kind();
        let mut fields = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            fields.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        insert(VERSION_LABEL, SadValue::text("KERI10JSON000000_"))?;
        insert(KIND_LABEL, SadValue::text(kind.as_str()))?;
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
        // Rotation writes both signing thresholds as text whatever the encoding.
        insert(SIGNING_THRESHOLD_LABEL, textual_threshold(&signing))?;
        insert(KEYS_LABEL, keys_value(&self.keys)?)?;
        insert(NEXT_THRESHOLD_LABEL, textual_threshold(&next))?;
        insert(NEXT_KEYS_LABEL, digests_value(&self.next_key_digests)?)?;
        insert(
            WITNESS_THRESHOLD_LABEL,
            rotation_witness_threshold_value(witness_threshold, self.encoding),
        )?;
        insert(WITNESS_CUTS_LABEL, prefixes_value(&self.witness_cuts)?)?;
        insert(WITNESS_ADDS_LABEL, prefixes_value(&self.witness_adds)?)?;
        insert(ANCHORS_LABEL, anchors_value(&self.anchors))?;

        let computation =
            Said::compute(&fields, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL).map_err(EventError::said)?;
        let (event_said, completed) = computation.into_parts();
        let serialized = SerializedEvent::from_sad(completed).map_err(EventError::serialization)?;
        Ok(KeyEvent::new(
            serialized,
            self.identifier,
            event_said,
            kind,
            self.sequence_number,
        ))
    }

    /// Validates the witness change and returns the size of the resulting witness set.
    fn resulting_witnesses(&self) -> Result<usize, EventError> {
        let current = check_distinct(&self.witnesses, "b")?;
        let cuts = check_distinct(&self.witness_cuts, WITNESS_CUTS_LABEL)?;
        let adds = check_distinct(&self.witness_adds, WITNESS_ADDS_LABEL)?;

        if current.iter().any(|witness| adds.contains(witness)) {
            return Err(EventError::ConflictingWitnessLists {
                first: "b",
                second: WITNESS_ADDS_LABEL,
            });
        }
        if cuts.iter().any(|witness| adds.contains(witness)) {
            return Err(EventError::ConflictingWitnessLists {
                first: WITNESS_CUTS_LABEL,
                second: WITNESS_ADDS_LABEL,
            });
        }
        // Every removal has to name a witness that is actually in effect, or the resulting set
        // would not have the size the arithmetic below claims.
        if cuts.iter().any(|witness| !current.contains(witness)) {
            return Err(EventError::WitnessCutNotPresent);
        }

        current
            .len()
            .checked_sub(cuts.len())
            .and_then(|remaining| remaining.checked_add(adds.len()))
            .ok_or(EventError::ValueOutOfRange {
                context: "witness count",
            })
    }
}

/// Renders the witness threshold for a rotation event.
///
/// The reference writes a zero threshold as text even under integer encoding, because its guard
/// tests the value for truthiness before the encoding flag. That is reproduced exactly: it changes
/// the bytes the event commits to.
fn rotation_witness_threshold_value(threshold: u32, encoding: ThresholdEncoding) -> SadValue {
    if threshold == 0 {
        return witness_threshold_value(threshold, ThresholdEncoding::Text);
    }
    witness_threshold_value(threshold, encoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const IDENTIFIER: &str = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C";
    const KEY: &str = "DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ";
    const NEXT_DIGEST: &str = "EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W";
    const WITNESS_A: &str = "BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ";
    const WITNESS_B: &str = "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";

    fn builder() -> Result<RotationBuilder, Box<dyn Error>> {
        Ok(RotationBuilder::new(
            IdentifierPrefix::from_qb64(IDENTIFIER)?,
            Said::from_qb64(IDENTIFIER)?,
            1,
            vec![VerificationKey::from_qb64(KEY)?],
        ))
    }

    fn witness(qb64: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(qb64)?)
    }

    fn digest() -> Result<Digest, Box<dyn Error>> {
        Ok(Digest::from_qb64(NEXT_DIGEST)?)
    }

    #[test]
    fn field_order_is_the_protocol_order() -> Result<(), Box<dyn Error>> {
        let event = builder()?.next_key_digests(vec![digest()?]).build()?;
        let labels: Vec<&str> = event.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(
            labels,
            [
                "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"
            ]
        );
        // A rotation carries no configuration field; the reference accepts the argument and drops it.
        assert!(!event.sad().contains("c"));
        assert_eq!(event.kind(), EventKind::Rotation);
        Ok(())
    }

    #[test]
    fn a_delegated_rotation_only_changes_the_kind() -> Result<(), Box<dyn Error>> {
        let ordinary = builder()?.next_key_digests(vec![digest()?]).build()?;
        let delegated = builder()?
            .next_key_digests(vec![digest()?])
            .kind(RotationKind::Delegated)
            .build()?;
        assert_eq!(delegated.kind(), EventKind::DelegatedRotation);
        assert_eq!(delegated.sad().get_text("t"), Some("drt"));
        assert_eq!(RotationKind::default(), RotationKind::Rotation);
        // Same size, different content, so a different identifier.
        assert_eq!(ordinary.raw().len(), delegated.raw().len());
        assert_ne!(ordinary.said(), delegated.said());
        Ok(())
    }

    #[test]
    fn sequence_numbers_are_hexadecimal_and_start_at_one() -> Result<(), Box<dyn Error>> {
        for (number, expected) in [(1_u128, "1"), (10, "a"), (14, "e"), (255, "ff")] {
            let event = RotationBuilder::new(
                IdentifierPrefix::from_qb64(IDENTIFIER)?,
                Said::from_qb64(IDENTIFIER)?,
                number,
                vec![VerificationKey::from_qb64(KEY)?],
            )
            .next_key_digests(vec![digest()?])
            .build()?;
            assert_eq!(event.sad().get_text("s"), Some(expected));
            assert_eq!(event.sequence_number(), number);
        }
        // Sequence number zero belongs to the inception event.
        assert!(matches!(
            RotationBuilder::new(
                IdentifierPrefix::from_qb64(IDENTIFIER)?,
                Said::from_qb64(IDENTIFIER)?,
                0,
                vec![VerificationKey::from_qb64(KEY)?],
            )
            .build(),
            Err(EventError::SequenceNumberTooSmall)
        ));
        Ok(())
    }

    #[test]
    fn a_rotation_can_abandon_the_identifier() -> Result<(), Box<dyn Error>> {
        // The reference can express this for an inception but never for a rotation.
        let event = builder()?.build()?;
        assert_eq!(event.sad().get_text("nt"), Some("0"));
        assert_eq!(event.sad().get("n"), Some(&SadValue::Array(Vec::new())));
        Ok(())
    }

    #[test]
    fn witness_changes_must_describe_a_consistent_set() -> Result<(), Box<dyn Error>> {
        let event = builder()?
            .next_key_digests(vec![digest()?])
            .witnesses(vec![witness(WITNESS_A)?, witness(WITNESS_B)?])
            .witness_cuts(vec![witness(WITNESS_A)?])
            .build()?;
        // Two witnesses less one leaves one, which needs one receipt.
        assert_eq!(event.sad().get("bt"), Some(&SadValue::Integer(1)));
        assert_eq!(
            event.sad().get("br"),
            Some(&SadValue::Array(vec![SadValue::text(WITNESS_A)]))
        );

        assert!(matches!(
            builder()?
                .witness_cuts(vec![witness(WITNESS_A)?, witness(WITNESS_A)?])
                .build(),
            Err(EventError::DuplicateWitness { label: "br" })
        ));
        assert!(matches!(
            builder()?
                .witness_adds(vec![witness(WITNESS_A)?, witness(WITNESS_A)?])
                .build(),
            Err(EventError::DuplicateWitness { label: "ba" })
        ));
        assert!(matches!(
            builder()?
                .witnesses(vec![witness(WITNESS_A)?])
                .witness_adds(vec![witness(WITNESS_A)?])
                .build(),
            Err(EventError::ConflictingWitnessLists {
                first: "b",
                second: "ba"
            })
        ));
        assert!(matches!(
            builder()?
                .witness_cuts(vec![witness(WITNESS_A)?])
                .witness_adds(vec![witness(WITNESS_A)?])
                .build(),
            Err(EventError::ConflictingWitnessLists {
                first: "br",
                second: "ba"
            })
        ));
        assert!(matches!(
            builder()?
                .witnesses(vec![witness(WITNESS_A)?])
                .witness_cuts(vec![witness(WITNESS_B)?])
                .build(),
            Err(EventError::WitnessCutNotPresent)
        ));
        Ok(())
    }

    #[test]
    fn only_the_witness_threshold_honors_the_encoding() -> Result<(), Box<dyn Error>> {
        let integer = builder()?
            .next_key_digests(vec![digest()?])
            .witnesses(vec![witness(WITNESS_A)?])
            .build()?;
        let text = builder()?
            .next_key_digests(vec![digest()?])
            .witnesses(vec![witness(WITNESS_A)?])
            .threshold_encoding(ThresholdEncoding::Text)
            .build()?;

        // Rotation defaults to integer encoding, the opposite of inception.
        assert_eq!(integer.sad().get("bt"), Some(&SadValue::Integer(1)));
        assert_eq!(text.sad().get("bt"), Some(&SadValue::text("1")));
        // The signing thresholds stay textual either way, as the reference writes them.
        assert_eq!(integer.sad().get("kt"), Some(&SadValue::text("1")));
        assert_eq!(text.sad().get("kt"), Some(&SadValue::text("1")));
        assert_eq!(integer.sad().get("nt"), Some(&SadValue::text("1")));

        // A zero threshold stays textual even under integer encoding.
        let empty = builder()?.next_key_digests(vec![digest()?]).build()?;
        assert_eq!(empty.sad().get("bt"), Some(&SadValue::text("0")));
        Ok(())
    }

    #[test]
    fn the_finished_event_is_self_consistent() -> Result<(), Box<dyn Error>> {
        let event = builder()?.next_key_digests(vec![digest()?]).build()?;
        assert_eq!(event.serialized().size(), event.raw().len());
        assert_eq!(SerializedEvent::parse(event.raw())?.sad(), event.sad());
        assert_eq!(event.identifier().qb64()?, IDENTIFIER);
        assert_eq!(event.sad().get_text("p"), Some(IDENTIFIER));
        // The event's own SAID differs from the prior digest it references.
        assert_ne!(event.said().qb64()?, IDENTIFIER);
        Ok(())
    }
}
