//! Failures of signing through a keeper, layered over keri-acdc's own.
//!
//! Building an artifact fails for keri-acdc's reasons, which [`TransactionError`] and
//! [`IpexError`] name; signing it fails for the keeper's. The two errors here carry both, so a
//! caller sees one error per operation.

use core::fmt;
use std::error::Error;

use crate::identifier::IdentifierError;
use crate::manager::ManagerError;
pub use keri_acdc::error::{IpexError, TransactionError};

/// Stable failures of anchoring a transaction event through the issuer's keeper.
#[derive(Debug)]
pub enum AnchorError {
    /// Building the artifact or its anchoring event failed before anything was signed.
    Transaction {
        /// Underlying failure.
        source: Box<TransactionError>,
    },
    /// Reading the key state or signing through the keeper failed.
    Identifier {
        /// Underlying failure.
        source: Box<IdentifierError>,
    },
}

impl fmt::Display for AnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transaction { source } => write!(formatter, "artifact construction failed: {source}"),
            Self::Identifier { source } => write!(formatter, "anchor signing failed: {source}"),
        }
    }
}

impl Error for AnchorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transaction { source } => Some(source),
            Self::Identifier { source } => Some(source),
        }
    }
}

impl From<TransactionError> for AnchorError {
    fn from(source: TransactionError) -> Self {
        Self::Transaction {
            source: Box::new(source),
        }
    }
}

impl From<IdentifierError> for AnchorError {
    fn from(source: IdentifierError) -> Self {
        Self::Identifier {
            source: Box::new(source),
        }
    }
}

/// Stable failures of building and signing an IPEX message through the sender's keeper.
#[derive(Debug)]
pub enum IpexSigningError {
    /// Building the message failed before anything was signed.
    Ipex {
        /// Underlying failure.
        source: Box<IpexError>,
    },
    /// Signing the message through the sender's keeper failed.
    Manager {
        /// Underlying failure.
        source: Box<ManagerError>,
    },
}

impl fmt::Display for IpexSigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipex { source } => write!(formatter, "message construction failed: {source}"),
            Self::Manager { source } => write!(formatter, "message signing failed: {source}"),
        }
    }
}

impl Error for IpexSigningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Ipex { source } => Some(source),
            Self::Manager { source } => Some(source),
        }
    }
}

impl From<IpexError> for IpexSigningError {
    fn from(source: IpexError) -> Self {
        Self::Ipex {
            source: Box::new(source),
        }
    }
}

impl From<ManagerError> for IpexSigningError {
    fn from(source: ManagerError) -> Self {
        Self::Manager {
            source: Box::new(source),
        }
    }
}
