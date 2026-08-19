//! Failures raised while constructing KERI key events.

use core::fmt;
use std::error::Error;

use signify_cesr::CesrError;
use signify_crypto::CryptoError;

use crate::prefix::PrefixError;
use crate::said::SaidError;
use crate::serialization::{SadError, SerializationError};

/// Stable key-event construction failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum EventError {
    /// A rotation or interaction event needs a sequence number of at least one.
    ///
    /// Sequence number zero belongs to the inception event alone.
    SequenceNumberTooSmall,
    /// A signing threshold of zero can never be satisfied.
    SigningThresholdIsZero,
    /// The signing threshold needs more keys than the event lists.
    SigningThresholdExceedsKeys {
        /// Key positions the threshold requires.
        required: u128,
        /// Keys the event actually lists.
        keys: usize,
    },
    /// The next-key threshold needs more digests than the event lists.
    ///
    /// The reference compares this threshold against the *current* key count instead, which both
    /// rejects a valid rotation commitment and accepts an unsatisfiable one; see `PORTING.md` §9.
    NextThresholdExceedsDigests {
        /// Key positions the threshold requires.
        required: u128,
        /// Next-key digests the event actually lists.
        digests: usize,
    },
    /// A numeric threshold cannot be written as a JSON number.
    ThresholdTooLarge {
        /// Rejected threshold value.
        value: u128,
    },
    /// The next threshold is weighted while the current one is numeric under integer encoding.
    ///
    /// The reference emits an event with **no** next-threshold field at all in this case, because
    /// it selects the field's encoding from the current threshold and then writes an undefined
    /// value. Rust refuses rather than producing a structurally invalid event; see `PORTING.md` §9.
    UnrepresentableNextThreshold,
    /// A witness list contains the same identifier twice.
    DuplicateWitness {
        /// Field label whose list holds the duplicate.
        label: &'static str,
    },
    /// A witness appears in two lists that must not overlap.
    ConflictingWitnessLists {
        /// First field label.
        first: &'static str,
        /// Second field label.
        second: &'static str,
    },
    /// A removed witness is not among the current witnesses.
    WitnessCutNotPresent,
    /// The witness threshold does not fit the resulting witness set.
    ///
    /// A set with witnesses needs a threshold between one and its size; an empty set needs zero.
    InvalidWitnessThreshold {
        /// Requested threshold.
        threshold: u32,
        /// Size of the resulting witness set.
        witnesses: usize,
    },
    /// The tolerated fault count is too large for the witness count.
    FaultToleranceTooHigh {
        /// Witness count.
        witnesses: u32,
        /// Requested tolerated faults.
        faults: u32,
    },
    /// A delegated identifier needs a self-addressing prefix that commits to its delegator.
    DelegatedPrefixMustBeDigestive {
        /// Requested derivation code.
        code: &'static str,
    },
    /// A message route exceeds the accepted bound.
    RouteTooLong {
        /// Rejected route length in bytes.
        length: usize,
    },
    /// An exchange payload carries the identifier label, which names the recipient.
    ///
    /// The reference merges the payload over the recipient it just wrote, so a payload field
    /// silently replaces the addressee inside the attribute block while the top-level recipient
    /// field still names someone else; see `PORTING.md` §9.
    PayloadOverridesRecipient {
        /// Field label the payload may not carry.
        label: &'static str,
    },
    /// Two embeds in one exchange message share a label.
    DuplicateEmbedLabel {
        /// Bounded copy of the repeated label.
        label: String,
    },
    /// An embed label collides with one the embeds block itself writes.
    ///
    /// The identifier label carries the block's own SAID, and a version label makes the block look
    /// like a versioned message to the SAID machinery. The reference destroys the embed in the
    /// first case and throws in the second.
    ReservedEmbedLabel {
        /// Label that may not be used.
        label: &'static str,
    },
    /// An embed label is not a usable attachment-path component.
    ///
    /// A label must be nonempty, within the unpadded URL-safe Base64 alphabet, free of the `-`
    /// path separator, and not purely numeric.
    InvalidEmbedLabel {
        /// Bounded copy of the rejected label.
        label: String,
        /// Underlying path-component failure.
        source: Box<CesrError>,
    },
    /// An embed label exceeds the accepted bound.
    EmbedLabelTooLong {
        /// Rejected label length in bytes.
        length: usize,
    },
    /// A transposed attachment is not a whole number of CESR quadlets.
    ///
    /// The reference divides its length by four and rounds down, so the trailing bytes fall
    /// outside the count and corrupt the stream that follows.
    NonIntegralAttachment {
        /// Bounded copy of the embed label whose attachment is misaligned.
        label: String,
        /// Attachment length in bytes.
        length: usize,
    },
    /// A transposed attachment holds a byte outside the CESR text domain.
    InvalidAttachmentText {
        /// Bounded copy of the embed label whose attachment is invalid.
        label: String,
        /// Offset of the first offending byte.
        offset: usize,
    },
    /// A transposed attachment needs more quadlets than its counter can express.
    AttachmentTooLarge {
        /// Bounded copy of the embed label whose attachment is oversized.
        label: String,
        /// Quadlets the pathed group would need.
        quadlets: usize,
    },
    /// A length, count, or threshold exceeded the range the protocol can encode.
    ValueOutOfRange {
        /// Stable name of the quantity that overflowed.
        context: &'static str,
    },
    /// Identifier-prefix derivation failed.
    Prefix {
        /// Underlying prefix failure.
        source: Box<PrefixError>,
    },
    /// Self-addressing-identifier derivation failed.
    Said {
        /// Underlying identifier failure.
        source: Box<SaidError>,
    },
    /// Self-addressing data construction or encoding failed.
    Sad {
        /// Underlying value/codec failure.
        source: Box<SadError>,
    },
    /// Message sizing or serialization failed.
    Serialization {
        /// Underlying serialization failure.
        source: Box<SerializationError>,
    },
    /// Key or digest material could not be encoded.
    Crypto {
        /// Underlying cryptographic failure.
        source: Box<CryptoError>,
    },
    /// Counter or path material could not be encoded.
    Cesr {
        /// Underlying encoding failure.
        source: Box<CesrError>,
    },
}

impl EventError {
    pub(crate) fn prefix(source: PrefixError) -> Self {
        Self::Prefix {
            source: Box::new(source),
        }
    }

    pub(crate) fn said(source: SaidError) -> Self {
        Self::Said {
            source: Box::new(source),
        }
    }

    pub(crate) fn sad(source: SadError) -> Self {
        Self::Sad {
            source: Box::new(source),
        }
    }

    pub(crate) fn serialization(source: SerializationError) -> Self {
        Self::Serialization {
            source: Box::new(source),
        }
    }

    pub(crate) fn crypto(source: CryptoError) -> Self {
        Self::Crypto {
            source: Box::new(source),
        }
    }

    pub(crate) fn cesr(source: CesrError) -> Self {
        Self::Cesr {
            source: Box::new(source),
        }
    }
}

/// Copies at most thirty-two characters of a caller-supplied label into an error.
pub(crate) fn bounded_label(label: &str) -> String {
    label.chars().take(32).collect()
}

impl fmt::Display for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SequenceNumberTooSmall => formatter.write_str("sequence number zero belongs to the inception event"),
            Self::SigningThresholdIsZero => formatter.write_str("a signing threshold of zero can never be met"),
            Self::SigningThresholdExceedsKeys { required, keys } => write!(
                formatter,
                "signing threshold needs {required} key positions but the event lists {keys} keys"
            ),
            Self::NextThresholdExceedsDigests { required, digests } => write!(
                formatter,
                "next threshold needs {required} key positions but the event lists {digests} digests"
            ),
            Self::ThresholdTooLarge { value } => {
                write!(formatter, "threshold {value} cannot be written as a JSON number")
            }
            Self::UnrepresentableNextThreshold => formatter.write_str(
                "a weighted next threshold cannot be written under integer encoding when the current \
                 threshold is numeric",
            ),
            Self::DuplicateWitness { label } => {
                write!(formatter, "witness list {label:?} contains a duplicate")
            }
            Self::ConflictingWitnessLists { first, second } => {
                write!(formatter, "witness lists {first:?} and {second:?} overlap")
            }
            Self::WitnessCutNotPresent => formatter.write_str("a removed witness is not a current witness"),
            Self::InvalidWitnessThreshold { threshold, witnesses } => write!(
                formatter,
                "witness threshold {threshold} does not fit a witness set of {witnesses}"
            ),
            Self::FaultToleranceTooHigh { witnesses, faults } => write!(
                formatter,
                "tolerating {faults} faults is impossible with {witnesses} witnesses"
            ),
            Self::DelegatedPrefixMustBeDigestive { code } => write!(
                formatter,
                "delegated inception needs a self-addressing prefix, not derivation code {code}"
            ),
            Self::RouteTooLong { length } => write!(
                formatter,
                "message route of {length} bytes exceeds the maximum of {}",
                crate::event::reply::MAX_ROUTE_BYTES
            ),
            Self::PayloadOverridesRecipient { label } => write!(
                formatter,
                "an exchange payload may not carry the {label:?} field, which names the recipient"
            ),
            Self::DuplicateEmbedLabel { label } => {
                write!(formatter, "embed label {label:?} appears more than once")
            }
            Self::ReservedEmbedLabel { label } => write!(
                formatter,
                "embed label {label:?} is reserved by the embeds block itself"
            ),
            Self::InvalidEmbedLabel { label, .. } => write!(
                formatter,
                "embed label {label:?} is not a usable attachment-path component"
            ),
            Self::EmbedLabelTooLong { length } => write!(
                formatter,
                "embed label of {length} bytes exceeds the maximum of {}",
                crate::event::exchange::MAX_EMBED_LABEL_BYTES
            ),
            Self::NonIntegralAttachment { label, length } => write!(
                formatter,
                "attachment of {length} bytes for embed {label:?} is not a whole number of quadlets"
            ),
            Self::InvalidAttachmentText { label, offset } => write!(
                formatter,
                "attachment for embed {label:?} holds a non-CESR byte at offset {offset}"
            ),
            Self::AttachmentTooLarge { label, quadlets } => write!(
                formatter,
                "attachment for embed {label:?} needs {quadlets} quadlets, more than its counter can express"
            ),
            Self::ValueOutOfRange { context } => write!(formatter, "{context} exceeds its encodable range"),
            Self::Prefix { .. } => formatter.write_str("identifier prefix derivation failed"),
            Self::Said { .. } => formatter.write_str("self-addressing identifier derivation failed"),
            Self::Sad { .. } => formatter.write_str("self-addressing data is invalid"),
            Self::Serialization { .. } => formatter.write_str("event serialization failed"),
            Self::Crypto { .. } => formatter.write_str("key or digest material is invalid"),
            Self::Cesr { .. } => formatter.write_str("counter or path material is invalid"),
        }
    }
}

impl Error for EventError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Prefix { source } => Some(source.as_ref()),
            Self::Said { source } => Some(source.as_ref()),
            Self::Sad { source } => Some(source.as_ref()),
            Self::Serialization { source } => Some(source.as_ref()),
            Self::Crypto { source } => Some(source.as_ref()),
            Self::InvalidEmbedLabel { source, .. } | Self::Cesr { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}
