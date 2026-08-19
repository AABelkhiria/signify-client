//! Identifier configuration traits.
//!
//! An inception event may carry configuration traits in its `c` field that constrain what the
//! identifier is allowed to do for the rest of its life. The table is the reference's
//! `TraitCodex` in `src/keri/app/habery.ts`; it is modelled here because `incept` is its first
//! consumer, and the registry inception of Roadmap 4.7 is its second. Only the codex is ported —
//! the `Habery` that declares it remains Roadmap 4.4.

use core::fmt;
use std::str::FromStr;

/// One configuration trait constraining an identifier.
///
/// Source: `TraitCodex` in the pinned `src/keri/app/habery.ts`. The reference passes these as bare
/// strings; `AGENTS.md` §2.1 requires an enum for a protocol code table.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConfigurationTrait {
    /// `EO` — only establishment events are allowed in this identifier's key event log.
    EstablishmentOnly,
    /// `DND` — this identifier may not delegate.
    DoNotDelegate,
    /// `NB` — this identifier accepts no backers.
    NoBackers,
}

impl ConfigurationTrait {
    /// Every configuration trait declared by the pinned reference, in table order.
    pub const ALL: [Self; 3] = [Self::EstablishmentOnly, Self::DoNotDelegate, Self::NoBackers];

    /// Returns the exact wire text for this trait.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EstablishmentOnly => "EO",
            Self::DoNotDelegate => "DND",
            Self::NoBackers => "NB",
        }
    }
}

impl fmt::Display for ConfigurationTrait {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ConfigurationTrait {
    type Err = UnknownConfigurationTrait;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "EO" => Ok(Self::EstablishmentOnly),
            "DND" => Ok(Self::DoNotDelegate),
            "NB" => Ok(Self::NoBackers),
            _ => Err(UnknownConfigurationTrait {
                found: input.chars().take(16).collect(),
            }),
        }
    }
}

impl TryFrom<&str> for ConfigurationTrait {
    type Error = UnknownConfigurationTrait;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

/// The text names no configuration trait the pinned reference declares.
#[derive(Debug)]
pub struct UnknownConfigurationTrait {
    /// Bounded copy of the rejected text.
    found: String,
}

impl UnknownConfigurationTrait {
    /// Returns the bounded rejected text.
    #[must_use]
    pub fn found(&self) -> &str {
        &self.found
    }
}

impl fmt::Display for UnknownConfigurationTrait {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown configuration trait {:?}", self.found)
    }
}

impl std::error::Error for UnknownConfigurationTrait {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_trait_table_is_exact_and_unique() -> Result<(), UnknownConfigurationTrait> {
        for (index, entry) in ConfigurationTrait::ALL.into_iter().enumerate() {
            assert_eq!(ConfigurationTrait::from_str(entry.as_str())?, entry);
            assert_eq!(entry.to_string(), entry.as_str());
            for other in ConfigurationTrait::ALL.into_iter().skip(index + 1) {
                assert_ne!(entry.as_str(), other.as_str());
            }
        }
        assert_eq!(ConfigurationTrait::EstablishmentOnly.as_str(), "EO");
        assert_eq!(ConfigurationTrait::DoNotDelegate.as_str(), "DND");
        assert_eq!(ConfigurationTrait::NoBackers.as_str(), "NB");
        assert_eq!(ConfigurationTrait::try_from("NB")?, ConfigurationTrait::NoBackers);
        Ok(())
    }

    #[test]
    fn unknown_text_is_rejected_with_bounded_detail() {
        let error = ConfigurationTrait::from_str("eo")
            .err()
            .map(|error| error.found().to_owned());
        assert_eq!(error, Some("eo".to_owned()));

        let long = "X".repeat(64);
        let bounded = ConfigurationTrait::from_str(&long)
            .err()
            .map(|error| error.found().chars().count());
        assert_eq!(bounded, Some(16));
        assert!(ConfigurationTrait::from_str("").is_err());
    }
}
