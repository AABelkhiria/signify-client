//! Failures raised while building controller and agent state.

use core::fmt;
use std::error::Error;

use keri_cesr::CesrError;
use keri_cesr::crypto::CryptoError;

use crate::manager::ManagerError;
use keri_protocol::event::EventError;
use keri_protocol::prefix::PrefixError;
use keri_protocol::said::SaidError;
use keri_protocol::serialization::SerializationError;
use keri_protocol::threshold::ThresholdError;

/// Stable controller and agent failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum ControllerError {
    /// An agent's key state names a number of signing keys other than one.
    AgentKeyCount {
        /// The number of keys the state carried.
        count: usize,
    },
    /// An agent's key state names a number of next-key digests other than one.
    AgentNextDigestCount {
        /// The number of digests the state carried.
        count: usize,
    },
    /// An agent's signing or next-key threshold is not exactly one.
    ///
    /// A weighted threshold has no single numeric value at all, which the reference reports as
    /// `invalid threshold undefined`.
    AgentThresholdNotOne {
        /// Which threshold was rejected: `kt` or `nt`.
        label: &'static str,
        /// The numeric value the threshold has, when it has one.
        value: Option<u128>,
    },
    /// An agent's latest establishment event is not a delegated inception.
    AgentNotDelegated {
        /// The establishment kind the state carried.
        kind: String,
    },
    /// An agent's key state carries no delegator, so it anchors to no controller.
    MissingDelegatorAnchor,
    /// A restored establishment event is missing a field the controller must read.
    RestoredEventIncomplete {
        /// The absent field's wire label.
        label: &'static str,
    },
    /// A sequence number cannot advance without overflowing.
    SequenceNumberOverflow,
    /// A salty identifier's re-derived keys do not match its recorded key state.
    ///
    /// The reference reports `Invalid Salty AID`.
    InvalidSaltyIdentifier {
        /// The identifier's prefix.
        prefix: String,
    },
    /// A randy identifier's decrypted keys do not match its recorded key state.
    InvalidRandyIdentifier {
        /// The identifier's prefix.
        prefix: String,
    },
    /// A passcode rotation named the passcode the controller already has.
    ///
    /// Rotating would reuse the current signing key.
    UnchangedPasscode,
    /// A planned passcode rotation was not built from this controller's current event.
    StaleRotationPlan,
    /// An identifier record names a key manager a passcode rotation cannot re-encrypt.
    ///
    /// A group holds no keys of its own and an external module's keys never leave it, so neither
    /// has anything to re-seal; the reference reports `invalid aid type`.
    UnsupportedKeyManager {
        /// The identifier's prefix.
        prefix: String,
        /// The key-manager label the record carried.
        algorithm: &'static str,
    },
    /// Key derivation or passcode handling failed.
    Manager {
        /// Underlying failure.
        source: Box<ManagerError>,
    },
    /// Event construction failed.
    Event {
        /// Underlying failure.
        source: Box<EventError>,
    },
    /// A cryptographic operation failed.
    Crypto {
        /// Underlying failure.
        source: Box<CryptoError>,
    },
    /// An event could not be parsed or serialized.
    Serialization {
        /// Underlying failure.
        source: Box<SerializationError>,
    },
    /// A threshold could not be parsed.
    Threshold {
        /// Underlying failure.
        source: Box<ThresholdError>,
    },
    /// An identifier prefix could not be parsed.
    Prefix {
        /// Underlying failure.
        source: Box<PrefixError>,
    },
    /// A self-addressing identifier could not be parsed.
    Said {
        /// Underlying failure.
        source: Box<SaidError>,
    },
    /// Numeric material could not be parsed.
    Cesr {
        /// Underlying failure.
        source: Box<CesrError>,
    },
}

impl fmt::Display for ControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentKeyCount { count } => {
                write!(
                    formatter,
                    "an agent inception event must have exactly one key, not {count}"
                )
            }
            Self::AgentNextDigestCount { count } => write!(
                formatter,
                "an agent inception event must have exactly one next key digest, not {count}"
            ),
            Self::AgentThresholdNotOne { label, value } => match value {
                Some(value) => write!(formatter, "invalid agent threshold {label} = {value}, must be 1"),
                None => write!(formatter, "invalid agent threshold {label}: weighted, must be 1"),
            },
            Self::AgentNotDelegated { kind } => {
                write!(formatter, "invalid agent inception event type {kind:?}")
            }
            Self::MissingDelegatorAnchor => formatter.write_str("no anchor to controller AID"),
            Self::RestoredEventIncomplete { label } => write!(
                formatter,
                "a restored establishment event is missing its {label:?} field"
            ),
            Self::SequenceNumberOverflow => formatter.write_str("the sequence number cannot advance further"),
            Self::InvalidSaltyIdentifier { prefix } => {
                write!(formatter, "salty identifier {prefix} does not match its key state")
            }
            Self::InvalidRandyIdentifier { prefix } => {
                write!(formatter, "randy identifier {prefix} does not match its key state")
            }
            Self::UnchangedPasscode => formatter.write_str("the new passcode is the same as the current passcode"),
            Self::StaleRotationPlan => {
                formatter.write_str("the planned rotation does not follow this controller's current event")
            }
            Self::UnsupportedKeyManager { prefix, algorithm } => write!(
                formatter,
                "identifier {prefix} names a {algorithm} key manager, which a passcode rotation cannot re-encrypt"
            ),
            Self::Manager { source } => write!(formatter, "key management failed: {source}"),
            Self::Event { source } => write!(formatter, "event construction failed: {source}"),
            Self::Crypto { source } => write!(formatter, "cryptographic operation failed: {source}"),
            Self::Serialization { source } => write!(formatter, "event serialization failed: {source}"),
            Self::Threshold { source } => write!(formatter, "threshold parsing failed: {source}"),
            Self::Prefix { source } => write!(formatter, "identifier prefix parsing failed: {source}"),
            Self::Said { source } => write!(formatter, "identifier digest parsing failed: {source}"),
            Self::Cesr { source } => write!(formatter, "numeric material parsing failed: {source}"),
        }
    }
}

impl Error for ControllerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manager { source } => Some(source),
            Self::Event { source } => Some(source),
            Self::Crypto { source } => Some(source),
            Self::Serialization { source } => Some(source),
            Self::Threshold { source } => Some(source),
            Self::Prefix { source } => Some(source),
            Self::Said { source } => Some(source),
            Self::Cesr { source } => Some(source),
            _ => None,
        }
    }
}

macro_rules! layered {
    ($variant:ident, $source:ty) => {
        impl From<$source> for ControllerError {
            fn from(source: $source) -> Self {
                Self::$variant {
                    source: Box::new(source),
                }
            }
        }
    };
}

layered!(Manager, ManagerError);
layered!(Event, EventError);
layered!(Crypto, CryptoError);
layered!(Serialization, SerializationError);
layered!(Threshold, ThresholdError);
layered!(Prefix, PrefixError);
layered!(Said, SaidError);
layered!(Cesr, CesrError);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_displays_and_sources_correctly() {
        let cases: Vec<(ControllerError, &[&str], bool)> = vec![
            (ControllerError::AgentKeyCount { count: 1031 }, &["1031"], false),
            (ControllerError::AgentNextDigestCount { count: 1031 }, &["1031"], false),
            (
                ControllerError::AgentThresholdNotOne {
                    label: "kt",
                    value: Some(1031),
                },
                &["kt", "1031"],
                false,
            ),
            (
                ControllerError::AgentThresholdNotOne {
                    label: "nt",
                    value: None,
                },
                &["nt", "weighted"],
                false,
            ),
            (
                ControllerError::AgentNotDelegated { kind: "icp".to_owned() },
                &["\"icp\""],
                false,
            ),
            (
                ControllerError::RestoredEventIncomplete { label: "di" },
                &["\"di\""],
                false,
            ),
            (
                ControllerError::InvalidSaltyIdentifier {
                    prefix: "EPRE".to_owned(),
                },
                &["salty", "EPRE"],
                false,
            ),
            (
                ControllerError::InvalidRandyIdentifier {
                    prefix: "EPRE".to_owned(),
                },
                &["randy", "EPRE"],
                false,
            ),
            (
                ControllerError::UnsupportedKeyManager {
                    prefix: "EPRE".to_owned(),
                    algorithm: "group",
                },
                &["EPRE", "group"],
                false,
            ),
            (
                ControllerError::from(ManagerError::NoCurrentKeys),
                &["an inception named no current keys"],
                true,
            ),
            (ControllerError::from(EventError::SigningThresholdIsZero), &[], true),
        ];
        for (error, fragments, has_source) in cases {
            let rendered = error.to_string();
            for fragment in fragments {
                assert!(rendered.contains(fragment), "{rendered} lacks {fragment}");
            }
            assert_eq!(error.source().is_some(), has_source, "{error}");
        }

        for (error, expected) in [
            (ControllerError::MissingDelegatorAnchor, "no anchor to controller AID"),
            (
                ControllerError::SequenceNumberOverflow,
                "the sequence number cannot advance further",
            ),
            (
                ControllerError::UnchangedPasscode,
                "the new passcode is the same as the current passcode",
            ),
            (
                ControllerError::StaleRotationPlan,
                "the planned rotation does not follow this controller's current event",
            ),
        ] {
            assert_eq!(error.to_string(), expected);
            assert!(error.source().is_none());
        }
    }
}
