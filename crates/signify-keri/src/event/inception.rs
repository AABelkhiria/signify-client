//! Inception and delegated-inception events.
//!
//! An inception event creates an identifier: it establishes the first signing keys, commits to the
//! digests of the next set, names the witnesses, and — because a KERI identifier *is* derived from
//! its inception event — determines the identifier prefix itself.
//!
//! This module ports the `incept` half of `src/keri/core/eventing.ts`.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::verifier::VerificationKey;

use crate::event::config::ConfigurationTrait;
use crate::event::error::EventError;
use crate::event::key_event::{
    KeyEvent, ThresholdEncoding, anchors_value, check_distinct, check_next_threshold, check_signing_threshold,
    check_witness_threshold, default_next_threshold, default_signing_threshold, digests_value, integer_threshold,
    keys_value, prefixes_value, replace, sequence_value, textual_threshold, traits_value, witness_threshold_value,
};
use crate::event::kind::EventKind;
use crate::event::witness::{AmpleMode, ample};
use crate::prefix::{IdentifierPrefix, PrefixDerivation};
use crate::said::{DEFAULT_SAID_LABEL, Said};
use crate::serialization::{
    IDENTIFIER_LABEL, KEYS_LABEL, KIND_LABEL, NEXT_KEYS_LABEL, SAID_LABEL, SEQUENCE_LABEL, Sad, SadValue,
    SerializedEvent, VERSION_LABEL,
};
use crate::threshold::SigningThreshold;

/// Field label carrying the signing threshold.
pub const SIGNING_THRESHOLD_LABEL: &str = "kt";
/// Field label carrying the next-key threshold.
pub const NEXT_THRESHOLD_LABEL: &str = "nt";
/// Field label carrying the witness threshold.
pub const WITNESS_THRESHOLD_LABEL: &str = "bt";
/// Field label carrying the witness list.
pub const WITNESSES_LABEL: &str = "b";
/// Field label carrying the configuration traits.
pub const CONFIGURATION_LABEL: &str = "c";
/// Field label carrying the anchored seals.
pub const ANCHORS_LABEL: &str = "a";
/// Field label carrying the delegator's identifier.
pub const DELEGATOR_LABEL: &str = "di";

/// Builds an inception (`icp`) or delegated-inception (`dip`) event.
///
/// The identifier prefix is derived from the event being built, so it is only known once
/// [`Self::build`] runs.
///
/// ```
/// use keri_cesr::crypto::verifier::VerificationKey;
/// use signify_keri::event::inception::InceptionBuilder;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let key = VerificationKey::from_qb64("DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH")?;
/// let event = InceptionBuilder::new(vec![key]).build()?;
///
/// // One transferable key and no explicit derivation makes the key itself the identifier.
/// assert_eq!(
///     event.identifier().qb64()?,
///     "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH",
/// );
/// assert_eq!(event.sequence_number(), 0);
/// assert!(event.raw().starts_with(br#"{"v":"KERI10JSON0000fd_","t":"icp""#));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct InceptionBuilder {
    keys: Vec<VerificationKey>,
    signing_threshold: Option<SigningThreshold>,
    next_key_digests: Vec<Digest>,
    next_threshold: Option<SigningThreshold>,
    witnesses: Vec<IdentifierPrefix>,
    witness_threshold: Option<u32>,
    configuration: Vec<ConfigurationTrait>,
    anchors: Vec<Sad>,
    delegator: Option<IdentifierPrefix>,
    derivation: Option<PrefixDerivation>,
    encoding: ThresholdEncoding,
}

impl InceptionBuilder {
    /// Starts an inception event for the given initial signing keys.
    #[must_use]
    pub fn new(keys: Vec<VerificationKey>) -> Self {
        Self {
            keys,
            signing_threshold: None,
            next_key_digests: Vec::new(),
            next_threshold: None,
            witnesses: Vec::new(),
            witness_threshold: None,
            configuration: Vec::new(),
            anchors: Vec::new(),
            delegator: None,
            derivation: None,
            encoding: ThresholdEncoding::Text,
        }
    }

    /// Sets how many of the signing keys must sign; a simple majority by default.
    #[must_use]
    pub fn signing_threshold(mut self, threshold: SigningThreshold) -> Self {
        self.signing_threshold = Some(threshold);
        self
    }

    /// Commits to the digests of the keys this identifier may rotate to.
    ///
    /// Leaving this empty abandons the identifier: no rotation will ever be accepted.
    #[must_use]
    pub fn next_key_digests(mut self, digests: Vec<Digest>) -> Self {
        self.next_key_digests = digests;
        self
    }

    /// Sets how many of the next keys must sign the rotation; a simple majority by default.
    #[must_use]
    pub fn next_threshold(mut self, threshold: SigningThreshold) -> Self {
        self.next_threshold = Some(threshold);
        self
    }

    /// Names the witnesses that receipt this identifier's events.
    #[must_use]
    pub fn witnesses(mut self, witnesses: Vec<IdentifierPrefix>) -> Self {
        self.witnesses = witnesses;
        self
    }

    /// Sets how many witness receipts an event needs.
    ///
    /// Defaults to [`ample`] of the witness count, and to zero when there are no witnesses.
    #[must_use]
    pub fn witness_threshold(mut self, threshold: u32) -> Self {
        self.witness_threshold = Some(threshold);
        self
    }

    /// Constrains what the identifier may do for the rest of its life.
    #[must_use]
    pub fn configuration(mut self, traits: Vec<ConfigurationTrait>) -> Self {
        self.configuration = traits;
        self
    }

    /// Anchors seals in the event.
    #[must_use]
    pub fn anchors(mut self, anchors: Vec<Sad>) -> Self {
        self.anchors = anchors;
        self
    }

    /// Makes this a delegated inception under the given delegator.
    ///
    /// A delegated identifier must commit to its delegator, so its prefix has to be
    /// self-addressing; [`PrefixDerivation::Blake3_256`] is used unless another digestive
    /// derivation is set explicitly.
    #[must_use]
    pub fn delegator(mut self, delegator: IdentifierPrefix) -> Self {
        self.delegator = Some(delegator);
        self
    }

    /// Chooses how the identifier prefix is derived.
    ///
    /// By default a single key with no delegator becomes a basic prefix — the key *is* the
    /// identifier — and anything else becomes self-addressing. The reference instead throws
    /// `Empty Material` for a multi-key inception with no explicit derivation, so multisig
    /// inception is unreachable through its documented path; see `PORTING.md` §9.
    #[must_use]
    pub fn prefix_derivation(mut self, derivation: PrefixDerivation) -> Self {
        self.derivation = Some(derivation);
        self
    }

    /// Chooses how numeric thresholds are written.
    ///
    /// Inception defaults to [`ThresholdEncoding::Text`], matching the reference's `intive = false`.
    #[must_use]
    pub fn threshold_encoding(mut self, encoding: ThresholdEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// Validates every field, derives the identifier prefix, and serializes the event.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::SigningThresholdIsZero`],
    /// [`EventError::SigningThresholdExceedsKeys`], or
    /// [`EventError::NextThresholdExceedsDigests`] for a threshold no key set could satisfy;
    /// [`EventError::UnrepresentableNextThreshold`] for the one threshold combination the
    /// reference writes as a missing field; [`EventError::DuplicateWitness`] and
    /// [`EventError::InvalidWitnessThreshold`] for an unusable witness set;
    /// [`EventError::DelegatedPrefixMustBeDigestive`] when a delegated identifier is given a basic
    /// derivation; and layered failures for material that cannot be encoded.
    pub fn build(self) -> Result<KeyEvent, EventError> {
        // Resolved before any field is moved out, because it inspects several of them together.
        let derivation = self.select_derivation()?;

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

        check_distinct(&self.witnesses, WITNESSES_LABEL)?;
        let witness_count = u32::try_from(self.witnesses.len()).map_err(|_| EventError::ValueOutOfRange {
            context: "witness count",
        })?;
        let witness_threshold = match self.witness_threshold {
            Some(threshold) => threshold,
            None if witness_count == 0 => 0,
            None => ample(witness_count, None, AmpleMode::Weak)?,
        };
        check_witness_threshold(witness_threshold, self.witnesses.len())?;

        let kind = if self.delegator.is_some() {
            EventKind::DelegatedInception
        } else {
            EventKind::Inception
        };

        let mut fields = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            fields.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        insert(VERSION_LABEL, SadValue::text("KERI10JSON000000_"))?;
        insert(KIND_LABEL, SadValue::text(kind.as_str()))?;
        insert(SAID_LABEL, SadValue::text(""))?;
        insert(IDENTIFIER_LABEL, SadValue::text(""))?;
        insert(SEQUENCE_LABEL, sequence_value(0))?;
        insert(SIGNING_THRESHOLD_LABEL, threshold_field(&signing, self.encoding)?)?;
        insert(KEYS_LABEL, keys_value(&self.keys)?)?;
        insert(
            NEXT_THRESHOLD_LABEL,
            next_threshold_field(&signing, &next, self.encoding)?,
        )?;
        insert(NEXT_KEYS_LABEL, digests_value(&self.next_key_digests)?)?;
        insert(
            WITNESS_THRESHOLD_LABEL,
            witness_threshold_value(witness_threshold, self.encoding),
        )?;
        insert(WITNESSES_LABEL, prefixes_value(&self.witnesses)?)?;
        insert(CONFIGURATION_LABEL, traits_value(&self.configuration))?;
        insert(ANCHORS_LABEL, anchors_value(&self.anchors))?;
        if let Some(delegator) = &self.delegator {
            let qb64 = delegator.qb64().map_err(EventError::prefix)?;
            insert(DELEGATOR_LABEL, SadValue::Text(qb64))?;
        }

        let identifier = IdentifierPrefix::derive(&fields, derivation).map_err(EventError::prefix)?;
        let prefix_qb64 = identifier.qb64().map_err(EventError::prefix)?;

        let mut completed = replace(&fields, IDENTIFIER_LABEL, &SadValue::Text(prefix_qb64.clone()))?;
        let event_said = if let IdentifierPrefix::SelfAddressing(prefix_said) = &identifier {
            // A self-addressing identifier is its own event's digest, so the event's SAID field
            // carries the prefix. Substituting it for the placeholder cannot change any byte count.
            completed = replace(&completed, SAID_LABEL, &SadValue::Text(prefix_qb64))?;
            *prefix_said
        } else {
            let computation =
                Said::compute(&completed, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL).map_err(EventError::said)?;
            let (computed, filled) = computation.into_parts();
            completed = filled;
            computed
        };

        let serialized = SerializedEvent::from_sad(completed).map_err(EventError::serialization)?;
        Ok(KeyEvent::new(serialized, identifier, event_said, kind, 0))
    }

    /// Chooses the prefix derivation, defaulting the way an identifier normally wants it.
    fn select_derivation(&self) -> Result<PrefixDerivation, EventError> {
        let derivation = match self.derivation {
            Some(derivation) => derivation,
            None if self.delegator.is_some() => PrefixDerivation::Blake3_256,
            None => match self.keys.as_slice() {
                // One key and nothing forcing a digest: the key is the identifier.
                [only] => PrefixDerivation::from_code(only.code()).map_err(EventError::prefix)?,
                _ => PrefixDerivation::Blake3_256,
            },
        };
        if self.delegator.is_some() && !derivation.is_digestive() {
            return Err(EventError::DelegatedPrefixMustBeDigestive {
                code: derivation.code().as_str(),
            });
        }
        Ok(derivation)
    }
}

/// Renders the signing threshold for an inception event.
fn threshold_field(threshold: &SigningThreshold, encoding: ThresholdEncoding) -> Result<SadValue, EventError> {
    if encoding == ThresholdEncoding::Integer
        && let Some(value) = integer_threshold(threshold)?
    {
        return Ok(value);
    }
    Ok(textual_threshold(threshold))
}

/// Renders the next-key threshold for an inception event.
///
/// The reference decides this field's encoding from the *current* threshold rather than this one.
/// That is reproduced exactly, because it changes the bytes the identifier commits to: a weighted
/// current threshold makes the next threshold textual even under integer encoding. The one
/// combination the reference cannot express — numeric current, weighted next, integer encoding —
/// makes it emit an event with no next-threshold field at all, so Rust refuses instead. Both are
/// recorded in `PORTING.md` §9.
fn next_threshold_field(
    signing: &SigningThreshold,
    next: &SigningThreshold,
    encoding: ThresholdEncoding,
) -> Result<SadValue, EventError> {
    if encoding == ThresholdEncoding::Integer && signing.numeric_value().is_some() {
        return integer_threshold(next)?.ok_or(EventError::UnrepresentableNextThreshold);
    }
    Ok(textual_threshold(next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const TRANSFERABLE: &str = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";
    const NON_TRANSFERABLE: &str = "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";
    const SECOND: &str = "DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ";
    const NEXT_DIGEST: &str = "EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W";
    const WITNESS: &str = "BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ";

    fn key(qb64: &str) -> Result<VerificationKey, Box<dyn Error>> {
        Ok(VerificationKey::from_qb64(qb64)?)
    }

    fn digest() -> Result<Digest, Box<dyn Error>> {
        Ok(Digest::from_qb64(NEXT_DIGEST)?)
    }

    fn witness() -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(WITNESS)?)
    }

    #[test]
    fn field_order_is_the_protocol_order() -> Result<(), Box<dyn Error>> {
        let event = InceptionBuilder::new(vec![key(TRANSFERABLE)?]).build()?;
        let labels: Vec<&str> = event.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(
            labels,
            ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"]
        );

        // Delegation appends its field at the end, where the reference puts it.
        let delegated = InceptionBuilder::new(vec![key(TRANSFERABLE)?])
            .next_key_digests(vec![digest()?])
            .delegator(IdentifierPrefix::from_qb64(
                "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C",
            )?)
            .build()?;
        let labels: Vec<&str> = delegated.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(labels.last(), Some(&"di"));
        assert_eq!(delegated.kind(), EventKind::DelegatedInception);
        Ok(())
    }

    #[test]
    fn defaults_match_the_reference() -> Result<(), Box<dyn Error>> {
        // One key, nothing else: a majority of one, no next commitment, no witnesses.
        let event = InceptionBuilder::new(vec![key(TRANSFERABLE)?]).build()?;
        assert_eq!(event.sad().get_text("kt"), Some("1"));
        assert_eq!(event.sad().get_text("nt"), Some("0"));
        assert_eq!(event.sad().get_text("bt"), Some("0"));
        assert_eq!(event.sad().get_text("s"), Some("0"));
        assert_eq!(event.sequence_number(), 0);
        assert_eq!(event.kind(), EventKind::Inception);

        // Three keys default to a two-of-three majority; two digests likewise.
        let event = InceptionBuilder::new(vec![key(TRANSFERABLE)?, key(SECOND)?, key(TRANSFERABLE)?])
            .next_key_digests(vec![digest()?, digest()?])
            .build()?;
        assert_eq!(event.sad().get_text("kt"), Some("2"));
        assert_eq!(event.sad().get_text("nt"), Some("1"));
        Ok(())
    }

    #[test]
    fn the_derivation_defaults_to_what_the_event_can_support() -> Result<(), Box<dyn Error>> {
        // A single key becomes the identifier itself, in whichever transferability it carries.
        let transferable = InceptionBuilder::new(vec![key(TRANSFERABLE)?]).build()?;
        assert_eq!(transferable.identifier().qb64()?, TRANSFERABLE);
        assert!(transferable.identifier().is_transferable());

        let non_transferable = InceptionBuilder::new(vec![key(NON_TRANSFERABLE)?]).build()?;
        assert_eq!(non_transferable.identifier().qb64()?, NON_TRANSFERABLE);
        assert!(!non_transferable.identifier().is_transferable());

        // More than one key cannot be a basic prefix, so the event digests itself. The reference
        // throws `Empty Material` here instead.
        let multisig = InceptionBuilder::new(vec![key(TRANSFERABLE)?, key(SECOND)?])
            .next_key_digests(vec![digest()?])
            .build()?;
        assert!(multisig.identifier().is_digestive());
        assert_eq!(multisig.identifier().qb64()?, multisig.said().qb64()?);
        assert_eq!(multisig.sad().get_text("i"), multisig.sad().get_text("d"));
        Ok(())
    }

    #[test]
    fn a_delegated_identifier_must_be_self_addressing() -> Result<(), Box<dyn Error>> {
        let delegator = IdentifierPrefix::from_qb64("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C")?;
        let delegated = InceptionBuilder::new(vec![key(TRANSFERABLE)?])
            .next_key_digests(vec![digest()?])
            .delegator(delegator.clone())
            .build()?;
        assert!(delegated.identifier().is_digestive());
        assert_eq!(delegated.sad().get_text("di"), Some(delegator.qb64()?.as_str()));

        for derivation in [PrefixDerivation::Ed25519, PrefixDerivation::Ed25519NonTransferable] {
            assert!(matches!(
                InceptionBuilder::new(vec![key(TRANSFERABLE)?])
                    .delegator(delegator.clone())
                    .prefix_derivation(derivation)
                    .build(),
                Err(EventError::DelegatedPrefixMustBeDigestive { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn thresholds_are_validated_against_what_can_satisfy_them() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            InceptionBuilder::new(vec![key(TRANSFERABLE)?])
                .signing_threshold(SigningThreshold::numeric(0))
                .build(),
            Err(EventError::SigningThresholdIsZero)
        ));
        assert!(matches!(
            InceptionBuilder::new(vec![key(TRANSFERABLE)?])
                .signing_threshold(SigningThreshold::numeric(2))
                .build(),
            Err(EventError::SigningThresholdExceedsKeys { required: 2, keys: 1 })
        ));
        // The next threshold is checked against the digests, not the keys -- the reference checks
        // it against the keys, which is the defect recorded in `PORTING.md` §9.
        assert!(matches!(
            InceptionBuilder::new(vec![key(TRANSFERABLE)?])
                .next_key_digests(vec![digest()?])
                .next_threshold(SigningThreshold::numeric(2))
                .build(),
            Err(EventError::NextThresholdExceedsDigests {
                required: 2,
                digests: 1
            })
        ));
        // A zero next threshold abandons the identifier and is allowed.
        let abandoned = InceptionBuilder::new(vec![key(TRANSFERABLE)?])
            .next_threshold(SigningThreshold::numeric(0))
            .build()?;
        assert_eq!(abandoned.sad().get_text("nt"), Some("0"));
        Ok(())
    }

    #[test]
    fn the_witness_set_and_its_threshold_are_consistent() -> Result<(), Box<dyn Error>> {
        let event = InceptionBuilder::new(vec![key(TRANSFERABLE)?])
            .next_key_digests(vec![digest()?])
            .witnesses(vec![witness()?])
            .build()?;
        // One witness needs one receipt.
        assert_eq!(event.sad().get_text("bt"), Some("1"));

        assert!(matches!(
            InceptionBuilder::new(vec![key(TRANSFERABLE)?])
                .witnesses(vec![witness()?, witness()?])
                .build(),
            Err(EventError::DuplicateWitness { label: "b" })
        ));
        for (witnesses, threshold) in [(vec![witness()?], 0_u32), (vec![witness()?], 2), (Vec::new(), 1)] {
            assert!(matches!(
                InceptionBuilder::new(vec![key(TRANSFERABLE)?])
                    .witnesses(witnesses)
                    .witness_threshold(threshold)
                    .build(),
                Err(EventError::InvalidWitnessThreshold { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn threshold_encoding_changes_the_json_types() -> Result<(), Box<dyn Error>> {
        let text = InceptionBuilder::new(vec![key(TRANSFERABLE)?])
            .next_key_digests(vec![digest()?])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()?;
        let integer = InceptionBuilder::new(vec![key(TRANSFERABLE)?])
            .next_key_digests(vec![digest()?])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .threshold_encoding(ThresholdEncoding::Integer)
            .build()?;

        assert_eq!(text.sad().get("kt"), Some(&SadValue::text("1")));
        assert_eq!(integer.sad().get("kt"), Some(&SadValue::Integer(1)));
        assert_eq!(text.sad().get("bt"), Some(&SadValue::text("0")));
        assert_eq!(integer.sad().get("bt"), Some(&SadValue::Integer(0)));
        // Different bytes mean a different identifier: the encoding is committed to.
        assert_ne!(text.said(), integer.said());
        assert_ne!(text.raw(), integer.raw());
        Ok(())
    }

    #[test]
    fn a_weighted_current_threshold_forces_the_next_one_to_text() -> Result<(), Box<dyn Error>> {
        let weighted = SigningThreshold::weighted(vec![vec![
            crate::threshold::RationalWeight::parse("1/2")?,
            crate::threshold::RationalWeight::parse("1/2")?,
        ]])?;
        let event = InceptionBuilder::new(vec![key(TRANSFERABLE)?, key(SECOND)?])
            .signing_threshold(weighted.clone())
            .next_key_digests(vec![digest()?])
            .next_threshold(SigningThreshold::numeric(1))
            .threshold_encoding(ThresholdEncoding::Integer)
            .build()?;
        // The reference reads the *current* threshold when choosing this field's encoding.
        assert_eq!(event.sad().get("nt"), Some(&SadValue::text("1")));
        assert_eq!(
            event.sad().get("kt"),
            Some(&SadValue::Array(vec![SadValue::text("1/2"), SadValue::text("1/2")]))
        );

        // The mirror case has no representation at all, so it is refused rather than written as a
        // missing field.
        assert!(matches!(
            InceptionBuilder::new(vec![key(TRANSFERABLE)?, key(SECOND)?])
                .signing_threshold(SigningThreshold::numeric(1))
                .next_key_digests(vec![digest()?, digest()?])
                .next_threshold(weighted)
                .threshold_encoding(ThresholdEncoding::Integer)
                .build(),
            Err(EventError::UnrepresentableNextThreshold)
        ));
        Ok(())
    }

    #[test]
    fn configuration_and_anchors_are_written_in_order() -> Result<(), Box<dyn Error>> {
        let mut seal = Sad::new();
        seal.insert("i", SadValue::text(TRANSFERABLE))?;
        let event = InceptionBuilder::new(vec![key(TRANSFERABLE)?])
            .configuration(vec![
                ConfigurationTrait::EstablishmentOnly,
                ConfigurationTrait::NoBackers,
            ])
            .anchors(vec![seal.clone()])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()?;
        assert_eq!(
            event.sad().get("c"),
            Some(&SadValue::Array(vec![SadValue::text("EO"), SadValue::text("NB")]))
        );
        assert_eq!(event.sad().get("a"), Some(&SadValue::Array(vec![SadValue::Map(seal)])));
        Ok(())
    }

    #[test]
    fn the_finished_event_is_self_consistent() -> Result<(), Box<dyn Error>> {
        let event = InceptionBuilder::new(vec![key(TRANSFERABLE)?])
            .next_key_digests(vec![digest()?])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()?;
        // The declared size, the byte length, and the parsed message all agree.
        assert_eq!(event.serialized().size(), event.raw().len());
        let reparsed = SerializedEvent::parse(event.raw())?;
        assert_eq!(reparsed.sad(), event.sad());
        // A self-addressing identifier is the event's own digest.
        assert_eq!(event.identifier().qb64()?, event.said().qb64()?);
        assert_eq!(event.clone().into_serialized().raw(), event.raw());
        Ok(())
    }
}
