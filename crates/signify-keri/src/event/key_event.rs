//! The finished key event shared by every builder, and the field encodings they agree on.

use keri_cesr::crypto::digest::Digest;
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::number::CesrNumber;

use crate::event::config::ConfigurationTrait;
use crate::event::error::EventError;
use crate::event::kind::EventKind;
use crate::prefix::IdentifierPrefix;
use crate::said::Said;
use crate::serialization::{Sad, SadValue, SerializedEvent};
use crate::threshold::SigningThreshold;

/// How a builder writes numeric thresholds and the witness threshold.
///
/// The reference calls this `intive`. It changes the JSON *type* of `kt`, `nt`, and `bt`, so it
/// changes the bytes an event commits to and therefore its identifier — two events that differ
/// only in this encoding have different SAIDs.
///
/// The reference applies it inconsistently, and both inconsistencies are reproduced because they
/// are observable on the wire (see `PORTING.md` §9):
///
/// - Inception honors it for all three fields; rotation honors it only for `bt`, always writing
///   `kt` and `nt` as text.
/// - Inception defaults to [`Self::Text`] while rotation defaults to [`Self::Integer`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ThresholdEncoding {
    /// Write thresholds as lowercase hexadecimal text, for example `"1"` and `"a"`.
    Text,
    /// Write numeric thresholds as JSON numbers, for example `1` and `10`.
    ///
    /// Weighted thresholds are always written as arrays; only numeric ones are affected.
    Integer,
}

/// A finished, serialized KERI key event.
///
/// Every builder in this module produces one. It pairs the exact wire bytes with the identifiers a
/// caller needs next: the identifier prefix the event belongs to and the event's own SAID, which is
/// what the following event references as its prior digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyEvent {
    serialized: SerializedEvent,
    identifier: IdentifierPrefix,
    said: Said,
    kind: EventKind,
    sequence_number: u128,
}

impl KeyEvent {
    pub(crate) const fn new(
        serialized: SerializedEvent,
        identifier: IdentifierPrefix,
        said: Said,
        kind: EventKind,
        sequence_number: u128,
    ) -> Self {
        Self {
            serialized,
            identifier,
            said,
            kind,
            sequence_number,
        }
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

    /// Borrows the serialized message, for version-string and parsing access.
    #[must_use]
    pub const fn serialized(&self) -> &SerializedEvent {
        &self.serialized
    }

    /// Returns the identifier prefix this event belongs to.
    ///
    /// For an inception event this is the prefix the builder derived; for every other kind it is
    /// the prefix the caller supplied.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns this event's own self-addressing identifier.
    ///
    /// The next event in the log references it as its prior digest.
    ///
    /// How a recipient re-checks it depends on how the identifier was derived. A rotation or
    /// interaction carries an ordinary SAID, so
    /// [`Said::verify`](crate::said::Said::verify) recomputes it. A **self-addressing inception**
    /// does not: its identifier and SAID fields hold the same value, and the digest is taken over
    /// an event with *both* replaced by placeholders. Recomputing that as an ordinary SAID
    /// replaces only the SAID field and therefore lands on a different digest, so such an event
    /// must be checked with
    /// [`IdentifierPrefix::verify`](crate::prefix::IdentifierPrefix::verify) instead.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the event kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Consumes the event, returning the serialized message.
    #[must_use]
    pub fn into_serialized(self) -> SerializedEvent {
        self.serialized
    }
}

/// Renders a threshold the way the reference writes textual `kt` and `nt`.
///
/// Numeric thresholds become bare lowercase hexadecimal text. Weighted thresholds become an array
/// of weight strings, or an array of such arrays when there is more than one clause — the single
/// clause is flattened exactly as the reference flattens it.
pub(crate) fn textual_threshold(threshold: &SigningThreshold) -> SadValue {
    match threshold.clauses() {
        None => SadValue::text(threshold.canonical_sith()),
        Some(clauses) => {
            let rendered: Vec<SadValue> = clauses
                .iter()
                .map(|clause| {
                    SadValue::Array(
                        clause
                            .weights()
                            .iter()
                            .map(|weight| SadValue::text(weight.to_string()))
                            .collect(),
                    )
                })
                .collect();
            match rendered.as_slice() {
                [only] => only.clone(),
                _ => SadValue::Array(rendered),
            }
        }
    }
}

/// Renders a numeric threshold as a JSON number, or `None` when the threshold is weighted.
pub(crate) fn integer_threshold(threshold: &SigningThreshold) -> Result<Option<SadValue>, EventError> {
    match threshold.numeric_value() {
        None => Ok(None),
        Some(value) => i64::try_from(value)
            .map(SadValue::Integer)
            .map(Some)
            .map_err(|_| EventError::ThresholdTooLarge { value }),
    }
}

/// Rejects a signing threshold that no set of the listed keys could ever satisfy.
pub(crate) fn check_signing_threshold(threshold: &SigningThreshold, keys: usize) -> Result<(), EventError> {
    if threshold.numeric_value() == Some(0) {
        return Err(EventError::SigningThresholdIsZero);
    }
    let available = u128::try_from(keys).map_err(|_| EventError::ValueOutOfRange { context: "key count" })?;
    if threshold.size() > available {
        return Err(EventError::SigningThresholdExceedsKeys {
            required: threshold.size(),
            keys,
        });
    }
    Ok(())
}

/// Rejects a next-key threshold that the listed digests could never satisfy.
///
/// A zero threshold is allowed here and means the identifier is being abandoned: no rotation will
/// ever be accepted. The reference compares this threshold against the *current* key count instead
/// of the digest count, which is a defect recorded in `PORTING.md` §9.
pub(crate) fn check_next_threshold(threshold: &SigningThreshold, digests: usize) -> Result<(), EventError> {
    let available = u128::try_from(digests).map_err(|_| EventError::ValueOutOfRange {
        context: "next-key digest count",
    })?;
    if threshold.size() > available {
        return Err(EventError::NextThresholdExceedsDigests {
            required: threshold.size(),
            digests,
        });
    }
    Ok(())
}

/// Returns the default threshold for a key list: a simple majority, but never zero.
pub(crate) fn default_signing_threshold(keys: usize) -> Result<SigningThreshold, EventError> {
    let count = u128::try_from(keys).map_err(|_| EventError::ValueOutOfRange { context: "key count" })?;
    Ok(SigningThreshold::numeric(1.max(count.div_ceil(2))))
}

/// Returns the default next-key threshold: a simple majority, or zero when nothing is committed.
pub(crate) fn default_next_threshold(digests: usize) -> Result<SigningThreshold, EventError> {
    let count = u128::try_from(digests).map_err(|_| EventError::ValueOutOfRange {
        context: "next-key digest count",
    })?;
    Ok(SigningThreshold::numeric(count.div_ceil(2)))
}

/// Encodes a key list as qualified Base64 text.
pub(crate) fn keys_value(keys: &[VerificationKey]) -> Result<SadValue, EventError> {
    keys.iter()
        .map(|key| key.qb64().map(SadValue::Text).map_err(EventError::crypto))
        .collect::<Result<Vec<_>, _>>()
        .map(SadValue::Array)
}

/// Encodes a next-key digest list as qualified Base64 text.
pub(crate) fn digests_value(digests: &[Digest]) -> Result<SadValue, EventError> {
    digests
        .iter()
        .map(|digest| digest.qb64().map(SadValue::Text).map_err(EventError::crypto))
        .collect::<Result<Vec<_>, _>>()
        .map(SadValue::Array)
}

/// Encodes an identifier-prefix list as qualified Base64 text.
pub(crate) fn prefixes_value(prefixes: &[IdentifierPrefix]) -> Result<SadValue, EventError> {
    prefixes
        .iter()
        .map(|prefix| prefix.qb64().map(SadValue::Text).map_err(EventError::prefix))
        .collect::<Result<Vec<_>, _>>()
        .map(SadValue::Array)
}

/// Encodes anchored seals.
pub(crate) fn anchors_value(anchors: &[Sad]) -> SadValue {
    SadValue::Array(anchors.iter().cloned().map(SadValue::Map).collect())
}

/// Encodes configuration traits.
pub(crate) fn traits_value(traits: &[ConfigurationTrait]) -> SadValue {
    SadValue::Array(traits.iter().map(|entry| SadValue::text(entry.as_str())).collect())
}

/// Encodes a sequence number as the bare lowercase hexadecimal the `s` field carries.
pub(crate) fn sequence_value(sequence_number: u128) -> SadValue {
    SadValue::text(CesrNumber::new(sequence_number).hex())
}

/// Rejects a witness list holding the same identifier twice.
pub(crate) fn check_distinct(prefixes: &[IdentifierPrefix], label: &'static str) -> Result<Vec<String>, EventError> {
    let mut seen = Vec::with_capacity(prefixes.len());
    for prefix in prefixes {
        let qb64 = prefix.qb64().map_err(EventError::prefix)?;
        if seen.contains(&qb64) {
            return Err(EventError::DuplicateWitness { label });
        }
        seen.push(qb64);
    }
    Ok(seen)
}

/// Rejects a witness threshold that the resulting witness set could never meet.
pub(crate) fn check_witness_threshold(threshold: u32, witnesses: usize) -> Result<(), EventError> {
    let fits = if witnesses == 0 {
        threshold == 0
    } else {
        let size = u32::try_from(witnesses).map_err(|_| EventError::ValueOutOfRange {
            context: "witness count",
        })?;
        threshold >= 1 && threshold <= size
    };
    if fits {
        Ok(())
    } else {
        Err(EventError::InvalidWitnessThreshold { threshold, witnesses })
    }
}

/// Renders the witness threshold, honoring the encoding the caller selected.
pub(crate) fn witness_threshold_value(threshold: u32, encoding: ThresholdEncoding) -> SadValue {
    match encoding {
        ThresholdEncoding::Integer => SadValue::Integer(i64::from(threshold)),
        ThresholdEncoding::Text => SadValue::text(CesrNumber::new(u128::from(threshold)).hex()),
    }
}

/// Rebuilds a SAD with one existing field replaced, preserving field order.
pub(crate) fn replace(sad: &Sad, label: &str, value: &SadValue) -> Result<Sad, EventError> {
    let mut rebuilt = Sad::new();
    for (existing, existing_value) in sad.entries() {
        let replacement = if existing == label {
            value.clone()
        } else {
            existing_value.clone()
        };
        rebuilt
            .insert(existing.to_owned(), replacement)
            .map_err(EventError::sad)?;
    }
    Ok(rebuilt)
}
