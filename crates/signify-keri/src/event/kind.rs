//! Typed KERI and ACDC event kinds (ilks).
//!
//! This ports the `Ilks` table of the pinned reference's `src/keri/core/core.ts`: the fourteen
//! three-character message-type codes carried in the `t` field of KERI key events, TEL registry
//! events, and exchange messages. The pinned table has no `qry` entry; query construction, if
//! required, is Roadmap 3.6 scope. Unknown ilk text is a typed error, never an implicit string.

use core::fmt;
use std::error::Error;
use std::str::FromStr;

/// One KERI or ACDC event kind, written as a three-character ilk in the event `t` field.
///
/// Source: the `Ilks` constant of the pinned `src/keri/core/core.ts`, in table order.
///
/// ```
/// use signify_keri::event::kind::EventKind;
///
/// # fn main() -> Result<(), signify_keri::event::kind::EventKindError> {
/// assert_eq!(EventKind::Inception.as_str(), "icp");
/// assert_eq!("rot".parse::<EventKind>()?, EventKind::Rotation);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EventKind {
    /// Inception event, ilk `icp`.
    Inception,
    /// Rotation event, ilk `rot`.
    Rotation,
    /// Interaction event, ilk `ixn`.
    Interaction,
    /// Delegated inception event, ilk `dip`.
    DelegatedInception,
    /// Delegated rotation event, ilk `drt`.
    DelegatedRotation,
    /// Receipt message, ilk `rct`.
    Receipt,
    /// Validator receipt message, ilk `vrc`.
    ValidatorReceipt,
    /// Reply message, ilk `rpy`.
    Reply,
    /// Exchange message, ilk `exn`.
    Exchange,
    /// TEL registry inception event, ilk `vcp`.
    RegistryInception,
    /// TEL credential issuance event, ilk `iss`.
    Issuance,
    /// TEL credential revocation event, ilk `rev`.
    Revocation,
    /// TEL backed credential issuance event, ilk `bis`.
    BackedIssuance,
    /// TEL backed credential revocation event, ilk `brv`.
    BackedRevocation,
}

impl EventKind {
    /// Every event kind in the pinned reference's `Ilks` table, in table order.
    pub const ALL: [Self; 14] = [
        Self::Inception,
        Self::Rotation,
        Self::Interaction,
        Self::DelegatedInception,
        Self::DelegatedRotation,
        Self::Receipt,
        Self::ValidatorReceipt,
        Self::Reply,
        Self::Exchange,
        Self::RegistryInception,
        Self::Issuance,
        Self::Revocation,
        Self::BackedIssuance,
        Self::BackedRevocation,
    ];

    /// Returns the exact three-character ilk text used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inception => "icp",
            Self::Rotation => "rot",
            Self::Interaction => "ixn",
            Self::DelegatedInception => "dip",
            Self::DelegatedRotation => "drt",
            Self::Receipt => "rct",
            Self::ValidatorReceipt => "vrc",
            Self::Reply => "rpy",
            Self::Exchange => "exn",
            Self::RegistryInception => "vcp",
            Self::Issuance => "iss",
            Self::Revocation => "rev",
            Self::BackedIssuance => "bis",
            Self::BackedRevocation => "brv",
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EventKind {
    type Err = EventKindError;

    /// Parses one complete ilk exactly as spelled in the pinned table.
    ///
    /// # Errors
    ///
    /// Returns [`EventKindError::Unknown`] for any text outside the fourteen-entry table,
    /// including empty input, different casing, and surrounding characters.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "icp" => Ok(Self::Inception),
            "rot" => Ok(Self::Rotation),
            "ixn" => Ok(Self::Interaction),
            "dip" => Ok(Self::DelegatedInception),
            "drt" => Ok(Self::DelegatedRotation),
            "rct" => Ok(Self::Receipt),
            "vrc" => Ok(Self::ValidatorReceipt),
            "rpy" => Ok(Self::Reply),
            "exn" => Ok(Self::Exchange),
            "vcp" => Ok(Self::RegistryInception),
            "iss" => Ok(Self::Issuance),
            "rev" => Ok(Self::Revocation),
            "bis" => Ok(Self::BackedIssuance),
            "brv" => Ok(Self::BackedRevocation),
            _ => Err(EventKindError::Unknown {
                found: input.chars().take(16).collect(),
            }),
        }
    }
}

impl TryFrom<&str> for EventKind {
    type Error = EventKindError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

/// Stable event-kind parsing failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum EventKindError {
    /// The text names no event kind in the pinned reference's table.
    Unknown {
        /// Bounded copy of the rejected ilk text.
        found: String,
    },
}

impl fmt::Display for EventKindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown { found } => write!(formatter, "unknown event kind {found:?}"),
        }
    }
}

impl Error for EventKindError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_complete_unique_and_round_trips() -> Result<(), EventKindError> {
        assert_eq!(EventKind::ALL.len(), 14);
        for (index, kind) in EventKind::ALL.iter().enumerate() {
            assert_eq!(kind.as_str().len(), 3);
            assert!(kind.as_str().bytes().all(|byte| byte.is_ascii_lowercase()));
            assert_eq!(EventKind::from_str(kind.as_str())?, *kind);
            assert_eq!(kind.to_string(), kind.as_str());
            for other in EventKind::ALL.iter().skip(index + 1) {
                assert_ne!(kind.as_str(), other.as_str());
            }
        }
        assert_eq!(EventKind::try_from("exn")?, EventKind::Exchange);
        Ok(())
    }

    #[test]
    fn unknown_ilk_text_is_a_bounded_typed_error() {
        for rejected in ["", "ICP", "icpp", "ic", "qry", " icp", "icp ", "vcp\n"] {
            assert!(
                matches!(EventKind::from_str(rejected), Err(EventKindError::Unknown { .. })),
                "reference table unexpectedly accepted {rejected:?}"
            );
        }
        match EventKind::from_str(&"x".repeat(64)) {
            Err(EventKindError::Unknown { found }) => assert_eq!(found.chars().count(), 16),
            other => assert!(
                matches!(other, Err(EventKindError::Unknown { .. })),
                "unexpected result {other:?}"
            ),
        }
    }
}
