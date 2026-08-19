//! Failures raised while constructing KERI key events.

use core::fmt;
use std::error::Error;

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
            Self::ValueOutOfRange { context } => write!(formatter, "{context} exceeds its encodable range"),
            Self::Prefix { .. } => formatter.write_str("identifier prefix derivation failed"),
            Self::Said { .. } => formatter.write_str("self-addressing identifier derivation failed"),
            Self::Sad { .. } => formatter.write_str("self-addressing data is invalid"),
            Self::Serialization { .. } => formatter.write_str("event serialization failed"),
            Self::Crypto { .. } => formatter.write_str("key or digest material is invalid"),
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
            _ => None,
        }
    }
}
