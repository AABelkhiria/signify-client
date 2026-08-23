//! Failures shared by the transaction events that change a credential's status.
//!
//! Credential *construction* has its own error, [`CredentialError`],
//! because it fails for entirely different reasons: a caller's field labels rather than an
//! issuer's key state. Issuance and revocation share this one, because they build the same shape
//! of event and anchor it the same way.

use core::fmt;
use std::error::Error;

use signify_keri::attachment::AttachmentError;
use signify_keri::event::EventError;
use signify_keri::identifier::IdentifierError;
use signify_keri::prefix::PrefixError;
use signify_keri::said::SaidError;
use signify_keri::serialization::{SadError, SerializationError};

use crate::credential::CredentialError;

/// Stable failures of issuance and revocation artifact construction.
#[derive(Debug)]
#[non_exhaustive]
pub enum TransactionError {
    /// The issuer's configuration forbids anchoring in an interaction event.
    ///
    /// An establishment-only identifier may only anchor in a rotation, which neither the reference
    /// nor this port builds; upstream both `issue` and `revoke` throw
    /// `Establishment only not implemented` here.
    EstablishmentOnlyIssuer {
        /// The configuration trait that forbids it, always `EO`.
        trait_code: &'static str,
    },
    /// The issuer's key state names a sequence number that cannot advance.
    SequenceNumberOverflow {
        /// The state's current sequence number.
        current: u128,
    },
    /// A credential value could not be read or encoded.
    Credential {
        /// Underlying failure.
        source: Box<CredentialError>,
    },
    /// Deriving the transaction event's identifier failed.
    Said {
        /// Underlying failure.
        source: Box<SaidError>,
    },
    /// Assembling the ordered fields failed.
    Sad {
        /// Underlying failure.
        source: Box<SadError>,
    },
    /// Serializing the transaction event failed.
    Serialization {
        /// Underlying failure.
        source: Box<SerializationError>,
    },
    /// Encoding an identifier prefix failed.
    Prefix {
        /// Underlying failure.
        source: Box<PrefixError>,
    },
    /// Building the anchoring interaction event failed.
    Event {
        /// Underlying failure.
        source: Box<EventError>,
    },
    /// Building or signing the anchor through the issuer's keeper failed.
    Identifier {
        /// Underlying failure.
        source: Box<IdentifierError>,
    },
    /// Encoding a CESR attachment failed.
    Attachment {
        /// Underlying failure.
        source: Box<AttachmentError>,
    },
}

impl TransactionError {
    /// Builds the establishment-only refusal, naming the trait that caused it.
    #[must_use]
    pub(crate) const fn establishment_only() -> Self {
        Self::EstablishmentOnlyIssuer { trait_code: "EO" }
    }
}

impl fmt::Display for TransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EstablishmentOnlyIssuer { trait_code } => write!(
                formatter,
                "an issuer configured {trait_code} cannot anchor in an interaction event"
            ),
            Self::SequenceNumberOverflow { current } => {
                write!(formatter, "a key event log at sequence number {current} cannot advance")
            }
            Self::Credential { source } => write!(formatter, "credential value unusable: {source}"),
            Self::Said { source } => write!(formatter, "identifier derivation failed: {source}"),
            Self::Sad { source } => write!(formatter, "field assembly failed: {source}"),
            Self::Serialization { source } => write!(formatter, "serialization failed: {source}"),
            Self::Prefix { source } => write!(formatter, "identifier encoding failed: {source}"),
            Self::Event { source } => write!(formatter, "anchor construction failed: {source}"),
            Self::Identifier { source } => write!(formatter, "anchor signing failed: {source}"),
            Self::Attachment { source } => write!(formatter, "attachment encoding failed: {source}"),
        }
    }
}

impl Error for TransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Credential { source } => Some(source),
            Self::Said { source } => Some(source),
            Self::Sad { source } => Some(source),
            Self::Serialization { source } => Some(source),
            Self::Prefix { source } => Some(source),
            Self::Event { source } => Some(source),
            Self::Identifier { source } => Some(source),
            Self::Attachment { source } => Some(source),
            Self::EstablishmentOnlyIssuer { .. } | Self::SequenceNumberOverflow { .. } => None,
        }
    }
}

macro_rules! layered {
    ($source:ty, $variant:ident) => {
        impl From<$source> for TransactionError {
            fn from(source: $source) -> Self {
                Self::$variant {
                    source: Box::new(source),
                }
            }
        }
    };
}

layered!(CredentialError, Credential);
layered!(SaidError, Said);
layered!(SadError, Sad);
layered!(SerializationError, Serialization);
layered!(PrefixError, Prefix);
layered!(EventError, Event);
layered!(IdentifierError, Identifier);
layered!(AttachmentError, Attachment);
