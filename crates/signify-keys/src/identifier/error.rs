//! Failures raised while creating and holding local identifier habitats and artifacts.

use core::fmt;
use std::error::Error;

use keri_cesr::CesrError;

use crate::manager::ManagerError;
use keri_protocol::event::EventError;
use keri_protocol::prefix::PrefixError;
use keri_protocol::said::SaidError;
use keri_protocol::threshold::ThresholdError;

/// Stable habitat-management failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum IdentifierError {
    /// A habitat already exists under the requested name.
    ///
    /// The reference's `makeHab` silently overwrites the map entry while still creating a second
    /// identifier in the manager, so the first habitat's handle is lost but its keys remain. That
    /// is refused here; the divergence is recorded in `PORTING.md` §9.
    DuplicateHabitat {
        /// The name already in use.
        name: String,
    },
    /// A non-transferable habitat was asked to commit to next keys.
    ///
    /// The reference silently forces the next-key count to zero; an explicit conflicting request
    /// is refused here instead of being discarded.
    NonTransferableNextKeys {
        /// The next-key count the request carried.
        requested: usize,
    },
    /// A non-transferable habitat was given a non-zero next-key threshold.
    ///
    /// The reference silently forces the threshold to zero; an explicit conflicting request is
    /// refused here instead of being discarded.
    NonTransferableNextThreshold,
    /// A non-transferable habitat was given a prefix derivation other than the basic
    /// non-transferable one.
    ///
    /// The reference silently replaces whatever derivation code was passed; an explicit
    /// conflicting request is refused here instead of being discarded.
    NonTransferableDerivation {
        /// The derivation code the request carried.
        code: &'static str,
    },
    /// A non-transferable habitat was given content its inception event may not carry.
    ///
    /// A non-transferable identifier can never rotate, so its inception event must not name
    /// witnesses or anchor data. The reference's own prefix derivation rejects this too, but only
    /// after every key has already been derived.
    NonTransferableContent {
        /// The event field that would not be empty.
        label: &'static str,
    },
    /// A basic prefix derivation was requested for a multi-key habitat.
    ///
    /// A basic prefix *is* a single public key, so it cannot represent an identifier with several.
    BasicDerivationNeedsOneKey {
        /// The current-key count the request carried.
        keys: usize,
    },
    /// A count does not fit the arithmetic performed on it.
    ValueOutOfRange {
        /// What was being computed.
        context: &'static str,
    },
    /// Key management failed.
    Manager {
        /// Underlying failure.
        source: Box<ManagerError>,
    },
    /// Event construction failed.
    Event {
        /// Underlying failure.
        source: Box<EventError>,
    },
    /// A threshold in a key state could not be parsed.
    Threshold {
        /// Underlying failure.
        source: Box<ThresholdError>,
    },
    /// An identifier prefix in a key state could not be parsed.
    Prefix {
        /// Underlying failure.
        source: Box<PrefixError>,
    },
    /// A digest in a key state could not be parsed.
    Said {
        /// Underlying failure.
        source: Box<SaidError>,
    },
    /// Numeric material in a key state could not be parsed.
    Cesr {
        /// Underlying failure.
        source: Box<CesrError>,
    },
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateHabitat { name } => {
                write!(formatter, "a habitat named {name:?} already exists")
            }
            Self::NonTransferableNextKeys { requested } => write!(
                formatter,
                "a non-transferable habitat cannot commit to {requested} next keys"
            ),
            Self::NonTransferableNextThreshold => {
                formatter.write_str("a non-transferable habitat's next-key threshold must be zero")
            }
            Self::NonTransferableDerivation { code } => write!(
                formatter,
                "a non-transferable habitat must use the basic non-transferable prefix derivation, not {code}"
            ),
            Self::NonTransferableContent { label } => write!(
                formatter,
                "a non-transferable habitat's inception event must leave field {label:?} empty"
            ),
            Self::BasicDerivationNeedsOneKey { keys } => write!(
                formatter,
                "a basic prefix derivation needs exactly one current key, not {keys}"
            ),
            Self::ValueOutOfRange { context } => write!(formatter, "{context} does not fit its arithmetic"),
            Self::Manager { source } => write!(formatter, "key management failed: {source}"),
            Self::Event { source } => write!(formatter, "event construction failed: {source}"),
            Self::Threshold { source } => write!(formatter, "threshold parsing failed: {source}"),
            Self::Prefix { source } => write!(formatter, "identifier prefix parsing failed: {source}"),
            Self::Said { source } => write!(formatter, "digest parsing failed: {source}"),
            Self::Cesr { source } => write!(formatter, "numeric material parsing failed: {source}"),
        }
    }
}

impl Error for IdentifierError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manager { source } => Some(source),
            Self::Event { source } => Some(source),
            Self::Threshold { source } => Some(source),
            Self::Prefix { source } => Some(source),
            Self::Said { source } => Some(source),
            Self::Cesr { source } => Some(source),
            _ => None,
        }
    }
}

impl From<ThresholdError> for IdentifierError {
    fn from(source: ThresholdError) -> Self {
        Self::Threshold {
            source: Box::new(source),
        }
    }
}

impl From<PrefixError> for IdentifierError {
    fn from(source: PrefixError) -> Self {
        Self::Prefix {
            source: Box::new(source),
        }
    }
}

impl From<SaidError> for IdentifierError {
    fn from(source: SaidError) -> Self {
        Self::Said {
            source: Box::new(source),
        }
    }
}

impl From<CesrError> for IdentifierError {
    fn from(source: CesrError) -> Self {
        Self::Cesr {
            source: Box::new(source),
        }
    }
}

impl From<ManagerError> for IdentifierError {
    fn from(source: ManagerError) -> Self {
        Self::Manager {
            source: Box::new(source),
        }
    }
}

impl From<EventError> for IdentifierError {
    fn from(source: EventError) -> Self {
        Self::Event {
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_displays_and_sources_correctly() {
        let cases: Vec<(IdentifierError, bool)> = vec![
            (
                IdentifierError::DuplicateHabitat {
                    name: "test".to_owned(),
                },
                false,
            ),
            (IdentifierError::NonTransferableNextKeys { requested: 2 }, false),
            (IdentifierError::NonTransferableNextThreshold, false),
            (IdentifierError::NonTransferableDerivation { code: "E" }, false),
            (IdentifierError::NonTransferableContent { label: "b" }, false),
            (IdentifierError::BasicDerivationNeedsOneKey { keys: 3 }, false),
            (IdentifierError::ValueOutOfRange { context: "key count" }, false),
            (IdentifierError::from(ManagerError::NoCurrentKeys), true),
            (IdentifierError::from(EventError::SigningThresholdIsZero), true),
            (IdentifierError::from(ThresholdError::EmptyThreshold), true),
            (IdentifierError::from(PrefixError::UnsupportedCode { code: "Z" }), true),
            (
                IdentifierError::from(SaidError::MissingLabelField { label: "d".to_owned() }),
                true,
            ),
            (IdentifierError::from(CesrError::EmptyInput { context: "number" }), true),
        ];
        for (error, has_source) in cases {
            assert_ne!(error.to_string(), "");
            assert_eq!(error.source().is_some(), has_source, "{error}");
        }
    }
}
