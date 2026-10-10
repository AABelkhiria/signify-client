//! The four key-generation algorithms an identifier's keys can come from.

use core::fmt;
use core::str::FromStr;

use keria_types::api::KeyManagerState;

use super::error::ManagerError;

/// Where an identifier's keys come from.
///
/// This is the reference's `Algos` enum. Two of the four have a key creator in this module; the
/// other two name a source outside it, which is why [`KeyCreator`](super::KeyCreator) has only two
/// variants and [`KeyAlgorithm::creator_kind`] returns an error for the rest.
///
/// ```
/// use signify_keys::manager::KeyAlgorithm;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert_eq!(KeyAlgorithm::Salty.as_str(), "salty");
/// assert_eq!("randy".parse::<KeyAlgorithm>()?, KeyAlgorithm::Randy);
/// assert!("hsm".parse::<KeyAlgorithm>().is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KeyAlgorithm {
    /// Keys derived deterministically from a salt and a path, so only the salt is stored.
    #[default]
    Salty,
    /// Keys generated at random, so each one must be stored encrypted.
    Randy,
    /// Keys belonging to a multisig group, held by the local member's own manager.
    Group,
    /// Keys held outside this process, by an HSM or a KMS.
    Extern,
}

/// Which key creator an algorithm selects.
///
/// Only two algorithms have one. Making this a separate two-variant enum is what lets
/// [`KeyCreator`](super::KeyCreator) be total: the reference's `Creatory` takes all four and throws
/// for two of them at the moment a key is needed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CreatorKind {
    /// Deterministic derivation from a salt.
    Salty,
    /// Random generation.
    Randy,
}

impl KeyAlgorithm {
    /// Every algorithm the reference declares, in declaration order.
    pub const ALL: [Self; 4] = [Self::Randy, Self::Salty, Self::Group, Self::Extern];

    /// Returns the exact wire text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Salty => "salty",
            Self::Randy => "randy",
            Self::Group => "group",
            Self::Extern => "extern",
        }
    }

    /// Returns which key creator this algorithm selects.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::UnsupportedAlgorithm`] for the group and external algorithms, whose
    /// keys come from a group member or an external module rather than from a creator.
    pub const fn creator_kind(self) -> Result<CreatorKind, ManagerError> {
        match self {
            Self::Salty => Ok(CreatorKind::Salty),
            Self::Randy => Ok(CreatorKind::Randy),
            other => Err(ManagerError::UnsupportedAlgorithm { algorithm: other }),
        }
    }

    /// Returns whether keys under this algorithm must be stored encrypted rather than re-derived.
    #[must_use]
    pub const fn needs_stored_keys(self) -> bool {
        matches!(self, Self::Randy)
    }
}

impl From<&KeyManagerState> for KeyAlgorithm {
    /// Reads the algorithm out of a KERIA identifier record.
    fn from(state: &KeyManagerState) -> Self {
        match state {
            KeyManagerState::Salty(_) => Self::Salty,
            KeyManagerState::Randy(_) => Self::Randy,
            KeyManagerState::Group(_) => Self::Group,
            KeyManagerState::Extern(_) => Self::Extern,
        }
    }
}

impl FromStr for KeyAlgorithm {
    type Err = ManagerError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.as_str() == text)
            .ok_or(ManagerError::UnsupportedAlgorithm {
                // An unknown name is reported against the algorithm the reference defaults to,
                // because there is no variant to name it with.
                algorithm: Self::Salty,
            })
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn every_algorithm_round_trips_through_its_wire_text() -> Result<(), Box<dyn Error>> {
        for algorithm in KeyAlgorithm::ALL {
            assert_eq!(algorithm.as_str().parse::<KeyAlgorithm>()?, algorithm);
            assert_eq!(algorithm.to_string(), algorithm.as_str());
        }
        assert_eq!(KeyAlgorithm::ALL.len(), 4);
        assert_eq!(KeyAlgorithm::default(), KeyAlgorithm::Salty);
        Ok(())
    }

    #[test]
    fn only_two_algorithms_have_a_creator() {
        assert!(matches!(KeyAlgorithm::Salty.creator_kind(), Ok(CreatorKind::Salty)));
        assert!(matches!(KeyAlgorithm::Randy.creator_kind(), Ok(CreatorKind::Randy)));
        for algorithm in [KeyAlgorithm::Group, KeyAlgorithm::Extern] {
            assert!(matches!(
                algorithm.creator_kind(),
                Err(ManagerError::UnsupportedAlgorithm { .. })
            ));
        }
    }

    #[test]
    fn only_random_keys_have_to_be_stored() {
        assert!(KeyAlgorithm::Randy.needs_stored_keys());
        for algorithm in [KeyAlgorithm::Salty, KeyAlgorithm::Group, KeyAlgorithm::Extern] {
            assert!(!algorithm.needs_stored_keys());
        }
    }

    #[test]
    fn unknown_algorithm_text_is_refused() {
        for text in ["", "SALTY", "hsm", "saltyy"] {
            assert!(text.parse::<KeyAlgorithm>().is_err(), "{text} was accepted");
        }
    }

    #[test]
    fn an_identifier_record_reports_its_algorithm() -> Result<(), Box<dyn Error>> {
        let randy: keria_types::api::Hab = serde_json::from_str(
            r#"{"name":"a","prefix":"E","icp_dt":"2023-12-01T10:05:25.062609+00:00","randy":{"prxs":[],"nxts":[]}}"#,
        )?;
        assert_eq!(KeyAlgorithm::from(&randy.common().key_manager), KeyAlgorithm::Randy);
        assert_eq!(
            KeyAlgorithm::from(&randy.common().key_manager).as_str(),
            randy.common().key_manager.label()
        );
        Ok(())
    }
}
