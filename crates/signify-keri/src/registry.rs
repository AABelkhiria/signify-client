//! TEL registry inception: the `vcp` event that creates a credential registry.
//!
//! This ports the pinned reference's `src/keri/core/vdring.ts`, whose only export is
//! `vdr.incept`. The issuance and revocation TEL events live in `app/credentialing.ts` and are
//! Roadmap 6.2; nothing here constructs them.
//!
//! # Backers are text, not identifiers
//!
//! The reference validates nothing about a backer — its own pinned unit test commits the string
//! `'a backer'`, space and all, into a registry identifier — so backers here are bounded text
//! rather than [`IdentifierPrefix`] values, because refusing what the reference commits to would
//! derive a different registry from the same inputs. The registry SAID seals whatever is given.
//!
//! # The nonce is required
//!
//! The reference defaults its nonce to `randomNonce()` from `app/coring.ts`, whose port belongs
//! to Roadmap 6.4 (`PORTING.md` §5.8). Until then the nonce is a required builder input, exactly
//! as a reply's timestamp is; the client supplies its own randomness.

use core::fmt;
use std::collections::BTreeSet;
use std::error::Error;

use crate::event::inception::{CONFIGURATION_LABEL, WITNESS_THRESHOLD_LABEL, WITNESSES_LABEL};
use crate::event::kind::EventKind;
use crate::event::witness::{AmpleMode, ample};
use crate::event::{ConfigurationTrait, EventError, KeyEvent, replace, traits_value};
use crate::prefix::{IdentifierPrefix, PrefixDerivation};
use crate::serialization::{
    IDENTIFIER_LABEL, KIND_LABEL, SAID_LABEL, SEQUENCE_LABEL, Sad, SadValue, SerializedEvent, VERSION_LABEL,
};

/// Field label carrying the issuing identifier; the registry's `ii`.
pub const ISSUER_LABEL: &str = "ii";
/// Field label carrying the registry nonce.
pub const NONCE_LABEL: &str = "n";

/// Largest accepted nonce, in bytes.
///
/// The reference accepts any string; the bound exists because the nonce is caller- or
/// network-supplied text that is committed into the event, and a qualified nonce is 44 characters.
pub const MAX_NONCE_BYTES: usize = 256;
/// Largest accepted backer identifier, in bytes.
pub const MAX_BACKER_BYTES: usize = 256;
/// Largest accepted backer count.
pub const MAX_BACKERS: usize = 1_024;

/// Stable registry-event failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum RegistryError {
    /// A nonce exceeds [`MAX_NONCE_BYTES`].
    NonceTooLong {
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// A backer exceeds [`MAX_BACKER_BYTES`].
    BackerTooLong {
        /// Zero-based position of the oversized backer.
        index: usize,
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// The backer list exceeds [`MAX_BACKERS`].
    TooManyBackers {
        /// Accepted maximum.
        maximum: usize,
        /// Actual count.
        actual: usize,
    },
    /// The same backer appears more than once; the reference's `Invalid baks … has duplicates`.
    DuplicateBacker {
        /// Zero-based position of the repeated backer.
        index: usize,
    },
    /// Backers were given alongside the no-backers configuration trait; the reference's
    /// `… backers specified for NB vcp, 0 allowed`.
    BackersForbiddenByConfiguration {
        /// How many backers were given.
        count: usize,
    },
    /// The backer threshold does not fit the backer list; the reference's `Invalid toad …`.
    ///
    /// With backers present the threshold must be between one and their count; with none it must
    /// be zero.
    InvalidBackerThreshold {
        /// The threshold in question.
        threshold: u32,
        /// How many backers were given.
        backers: usize,
    },
    /// Event construction failed.
    Event {
        /// Underlying failure.
        source: Box<EventError>,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonceTooLong { maximum, actual } => {
                write!(formatter, "a nonce of {actual} bytes exceeds maximum {maximum}")
            }
            Self::BackerTooLong { index, maximum, actual } => {
                write!(formatter, "backer {index} of {actual} bytes exceeds maximum {maximum}")
            }
            Self::TooManyBackers { maximum, actual } => {
                write!(formatter, "{actual} backers exceed maximum {maximum}")
            }
            Self::DuplicateBacker { index } => {
                write!(formatter, "backer {index} repeats an earlier backer")
            }
            Self::BackersForbiddenByConfiguration { count } => write!(
                formatter,
                "{count} backers specified for a no-backers registry, 0 allowed"
            ),
            Self::InvalidBackerThreshold { threshold, backers } => write!(
                formatter,
                "a backer threshold of {threshold} does not fit {backers} backers"
            ),
            Self::Event { source } => write!(formatter, "event construction failed: {source}"),
        }
    }
}

impl Error for RegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event { source } => Some(source),
            _ => None,
        }
    }
}

impl From<EventError> for RegistryError {
    fn from(source: EventError) -> Self {
        Self::Event {
            source: Box::new(source),
        }
    }
}

/// Builds a registry inception (`vcp`) event; the reference's `vdr.incept`.
///
/// The registry identifier is the event's own BLAKE3-256 digest — the reference's `code`
/// parameter has no other usable value, because every alternative reads fields a registry
/// inception does not carry — so it is derived, not chosen, and appears in both the `i` and `d`
/// fields.
///
/// ```
/// use signify_keri::prefix::IdentifierPrefix;
/// use signify_keri::registry::RegistryInceptionBuilder;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let issuer = IdentifierPrefix::from_qb64("ECJIoBpEcCWMzvquk861dXP8JJZ-vbmJczlDR-NYcE3g")?;
/// let event = RegistryInceptionBuilder::new(issuer, "AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s")
///     .build()?;
///
/// // The pinned unit test's exact registry identifier.
/// assert_eq!(event.identifier().qb64()?, "EDAsrwU75uoh8sii7w-KN-Txy2d0dhHiUP34TQVBJiPS");
/// assert_eq!(event.sad().get_text("t"), Some("vcp"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct RegistryInceptionBuilder {
    issuer: IdentifierPrefix,
    nonce: String,
    backers: Vec<String>,
    backer_threshold: Option<u32>,
    configuration: Vec<ConfigurationTrait>,
}

impl RegistryInceptionBuilder {
    /// Starts a registry inception for the given issuer and nonce.
    ///
    /// The nonce makes the registry identifier unique per creation; the reference defaults it to
    /// its own random-nonce helper, whose port is Roadmap 6.4, so it is a required input here.
    #[must_use]
    pub fn new(issuer: IdentifierPrefix, nonce: impl Into<String>) -> Self {
        Self {
            issuer,
            nonce: nonce.into(),
            backers: Vec::new(),
            backer_threshold: None,
            configuration: Vec::new(),
        }
    }

    /// Names the registry's backers; the reference's `baks`.
    ///
    /// Backers are committed as given — see the module documentation for why they are text.
    #[must_use]
    pub fn backers(mut self, backers: Vec<String>) -> Self {
        self.backers = backers;
        self
    }

    /// Sets how many backer receipts an event needs; the reference's `toad`.
    ///
    /// Defaults to [`ample`] of the backer count, and to zero when there are no backers.
    #[must_use]
    pub const fn backer_threshold(mut self, threshold: u32) -> Self {
        self.backer_threshold = Some(threshold);
        self
    }

    /// Constrains what the registry may do; the reference's `cnfg`.
    #[must_use]
    pub fn configuration(mut self, traits: Vec<ConfigurationTrait>) -> Self {
        self.configuration = traits;
        self
    }

    /// Validates every field, derives the registry identifier, and serializes the event.
    ///
    /// # Errors
    ///
    /// Returns the bound, duplicate, configuration, and threshold refusals documented on
    /// [`RegistryError`], and a layered [`RegistryError::Event`] for material that cannot be
    /// encoded.
    pub fn build(self) -> Result<KeyEvent, RegistryError> {
        let threshold = self.validate()?;
        self.serialize(threshold)
    }

    /// Runs every refusal the reference performs, plus this port's bounds, and resolves the
    /// backer threshold.
    fn validate(&self) -> Result<u32, RegistryError> {
        if self.nonce.len() > MAX_NONCE_BYTES {
            return Err(RegistryError::NonceTooLong {
                maximum: MAX_NONCE_BYTES,
                actual: self.nonce.len(),
            });
        }
        if self.backers.len() > MAX_BACKERS {
            return Err(RegistryError::TooManyBackers {
                maximum: MAX_BACKERS,
                actual: self.backers.len(),
            });
        }
        let mut seen = BTreeSet::new();
        for (index, backer) in self.backers.iter().enumerate() {
            if backer.len() > MAX_BACKER_BYTES {
                return Err(RegistryError::BackerTooLong {
                    index,
                    maximum: MAX_BACKER_BYTES,
                    actual: backer.len(),
                });
            }
            if !seen.insert(backer.as_str()) {
                return Err(RegistryError::DuplicateBacker { index });
            }
        }
        if self.configuration.contains(&ConfigurationTrait::NoBackers) && !self.backers.is_empty() {
            return Err(RegistryError::BackersForbiddenByConfiguration {
                count: self.backers.len(),
            });
        }

        let backer_count = u32::try_from(self.backers.len()).map_err(|_| RegistryError::TooManyBackers {
            maximum: MAX_BACKERS,
            actual: self.backers.len(),
        })?;
        let threshold = match self.backer_threshold {
            Some(threshold) => threshold,
            None if backer_count == 0 => 0,
            None => ample(backer_count, None, AmpleMode::Weak)?,
        };
        let fits = if self.backers.is_empty() {
            threshold == 0
        } else {
            threshold >= 1 && threshold <= backer_count
        };
        if !fits {
            return Err(RegistryError::InvalidBackerThreshold {
                threshold,
                backers: self.backers.len(),
            });
        }
        Ok(threshold)
    }

    /// Assembles, derives, and serializes the validated event.
    fn serialize(self, threshold: u32) -> Result<KeyEvent, RegistryError> {
        let mut fields = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), RegistryError> {
            fields
                .insert(label.to_owned(), value)
                .map_err(EventError::sad)
                .map_err(RegistryError::from)
        };
        insert(VERSION_LABEL, SadValue::text("KERI10JSON000000_"))?;
        insert(KIND_LABEL, SadValue::text(EventKind::RegistryInception.as_str()))?;
        insert(SAID_LABEL, SadValue::text(""))?;
        insert(IDENTIFIER_LABEL, SadValue::text(""))?;
        insert(
            ISSUER_LABEL,
            SadValue::Text(
                self.issuer
                    .qb64()
                    .map_err(EventError::prefix)
                    .map_err(RegistryError::from)?,
            ),
        )?;
        insert(SEQUENCE_LABEL, SadValue::text("0"))?;
        insert(CONFIGURATION_LABEL, traits_value(&self.configuration))?;
        insert(WITNESS_THRESHOLD_LABEL, SadValue::Text(format!("{threshold:x}")))?;
        insert(
            WITNESSES_LABEL,
            SadValue::Array(self.backers.into_iter().map(SadValue::Text).collect()),
        )?;
        insert(NONCE_LABEL, SadValue::Text(self.nonce))?;

        let identifier = IdentifierPrefix::derive(&fields, PrefixDerivation::Blake3_256)
            .map_err(EventError::prefix)
            .map_err(RegistryError::from)?;
        let qb64 = identifier
            .qb64()
            .map_err(EventError::prefix)
            .map_err(RegistryError::from)?;
        let completed = replace(&fields, IDENTIFIER_LABEL, &SadValue::Text(qb64.clone()))?;
        let completed = replace(&completed, SAID_LABEL, &SadValue::Text(qb64))?;
        let said = match &identifier {
            IdentifierPrefix::SelfAddressing(said) => *said,
            // Unreachable: the derivation above is always self-addressing.
            other @ IdentifierPrefix::Basic(_) => {
                return Err(RegistryError::from(EventError::prefix(
                    crate::prefix::PrefixError::UnsupportedCode {
                        code: other.code().as_str(),
                    },
                )));
            }
        };

        let serialized = SerializedEvent::from_sad(completed)
            .map_err(EventError::serialization)
            .map_err(RegistryError::from)?;
        Ok(KeyEvent::new(
            serialized,
            identifier,
            said,
            EventKind::RegistryInception,
            0,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// The issuer and nonce the pinned `vdring.test.ts` uses throughout.
    const ISSUER: &str = "ECJIoBpEcCWMzvquk861dXP8JJZ-vbmJczlDR-NYcE3g";
    const NONCE: &str = "AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s";
    /// The pinned registry identifier and event bytes for the no-backer case.
    const PINNED_PREFIX: &str = "EDAsrwU75uoh8sii7w-KN-Txy2d0dhHiUP34TQVBJiPS";
    const PINNED_RAW: &str = r#"{"v":"KERI10JSON00010f_","t":"vcp","d":"EDAsrwU75uoh8sii7w-KN-Txy2d0dhHiUP34TQVBJiPS","i":"EDAsrwU75uoh8sii7w-KN-Txy2d0dhHiUP34TQVBJiPS","ii":"ECJIoBpEcCWMzvquk861dXP8JJZ-vbmJczlDR-NYcE3g","s":"0","c":[],"bt":"0","b":[],"n":"AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s"}"#;
    /// The pinned backer case, whose backer is the unvalidated string `a backer`.
    const PINNED_BACKER_PREFIX: &str = "ENlghG6_krj9YMzy5-E3j5sEjsd6FR1nskBtbtSQGOFL";

    fn issuer() -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(ISSUER)?)
    }

    fn builder() -> Result<RegistryInceptionBuilder, Box<dyn Error>> {
        Ok(RegistryInceptionBuilder::new(issuer()?, NONCE))
    }

    #[test]
    fn the_pinned_registry_inception_is_reproduced() -> Result<(), Box<dyn Error>> {
        // With an explicit zero threshold, and with the threshold left to its default: the
        // pinned unit test asserts both produce the same bytes.
        for event in [builder()?.backer_threshold(0).build()?, builder()?.build()?] {
            assert_eq!(event.raw(), PINNED_RAW.as_bytes());
            assert_eq!(event.identifier().qb64()?, PINNED_PREFIX);
            assert_eq!(event.said().qb64()?, PINNED_PREFIX);
            assert_eq!(event.raw().len(), 271);
            assert_eq!(event.kind(), EventKind::RegistryInception);
            assert_eq!(event.sequence_number(), 0);
        }
        Ok(())
    }

    #[test]
    fn the_pinned_backer_case_commits_unvalidated_text() -> Result<(), Box<dyn Error>> {
        // The reference's own vector commits the string `a backer` — not an identifier — which
        // is why backers are text here. Explicit and defaulted thresholds agree at one backer.
        for event in [
            builder()?
                .backers(vec!["a backer".to_owned()])
                .backer_threshold(1)
                .build()?,
            builder()?.backers(vec!["a backer".to_owned()]).build()?,
        ] {
            assert_eq!(event.identifier().qb64()?, PINNED_BACKER_PREFIX);
            assert_eq!(event.sad().get_text("bt"), Some("1"));
            assert_eq!(
                event.sad().get("b"),
                Some(&SadValue::Array(vec![SadValue::text("a backer")]))
            );
            assert_eq!(event.raw().len(), 281);
        }
        Ok(())
    }

    #[test]
    fn field_order_is_the_reference_order() -> Result<(), Box<dyn Error>> {
        let event = builder()?.build()?;
        let labels: Vec<&str> = event.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"]);
        Ok(())
    }

    #[test]
    fn no_backers_trait_conflicts_with_backers() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            builder()?
                .configuration(vec![ConfigurationTrait::NoBackers])
                .backers(vec!["a backer".to_owned()])
                .build(),
            Err(RegistryError::BackersForbiddenByConfiguration { count: 1 })
        ));
        // Without backers the trait is fine, and it is committed into the event.
        let event = builder()?.configuration(vec![ConfigurationTrait::NoBackers]).build()?;
        assert_eq!(event.sad().get("c"), Some(&SadValue::Array(vec![SadValue::text("NB")])));
        Ok(())
    }

    #[test]
    fn duplicate_backers_are_refused() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            builder()?
                .backers(vec!["a backer".to_owned(), "a backer".to_owned()])
                .build(),
            Err(RegistryError::DuplicateBacker { index: 1 })
        ));
        Ok(())
    }

    #[test]
    fn the_backer_threshold_must_fit_the_backers() -> Result<(), Box<dyn Error>> {
        // The pinned rejections: zero over one backer, and one over none.
        assert!(matches!(
            builder()?
                .backers(vec!["a backer".to_owned()])
                .backer_threshold(0)
                .build(),
            Err(RegistryError::InvalidBackerThreshold {
                threshold: 0,
                backers: 1
            })
        ));
        assert!(matches!(
            builder()?.backer_threshold(1).build(),
            Err(RegistryError::InvalidBackerThreshold {
                threshold: 1,
                backers: 0
            })
        ));
        assert!(matches!(
            builder()?
                .backers(vec!["a backer".to_owned()])
                .backer_threshold(2)
                .build(),
            Err(RegistryError::InvalidBackerThreshold {
                threshold: 2,
                backers: 1
            })
        ));
        Ok(())
    }

    #[test]
    fn the_default_threshold_is_ample_and_written_in_hexadecimal() -> Result<(), Box<dyn Error>> {
        let backers: Vec<String> = (0..5).map(|index| format!("backer-{index}")).collect();
        let event = builder()?.backers(backers.clone()).build()?;
        // Ample of five under the weak majority.
        assert_eq!(
            event.sad().get_text("bt"),
            Some(format!("{:x}", ample(5, None, AmpleMode::Weak)?).as_str())
        );

        // An explicit threshold above nine is written in hexadecimal, as `toString(16)` writes it.
        let many: Vec<String> = (0..12).map(|index| format!("backer-{index}")).collect();
        let event = builder()?.backers(many).backer_threshold(10).build()?;
        assert_eq!(event.sad().get_text("bt"), Some("a"));
        Ok(())
    }

    #[test]
    fn the_bounds_are_enforced() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            RegistryInceptionBuilder::new(issuer()?, "n".repeat(MAX_NONCE_BYTES + 1)).build(),
            Err(RegistryError::NonceTooLong { .. })
        ));
        assert!(matches!(
            builder()?.backers(vec!["b".repeat(MAX_BACKER_BYTES + 1)]).build(),
            Err(RegistryError::BackerTooLong { index: 0, .. })
        ));
        let too_many: Vec<String> = (0..=MAX_BACKERS).map(|index| format!("backer-{index}")).collect();
        assert!(matches!(
            builder()?.backers(too_many).build(),
            Err(RegistryError::TooManyBackers { .. })
        ));
        // An empty nonce is accepted, as the reference accepts it.
        let event = RegistryInceptionBuilder::new(issuer()?, "").build()?;
        assert_eq!(event.sad().get_text("n"), Some(""));
        Ok(())
    }

    #[test]
    fn the_finished_event_is_self_consistent() -> Result<(), Box<dyn Error>> {
        let event = builder()?
            .backers(vec!["a backer".to_owned()])
            .backer_threshold(1)
            .build()?;
        assert_eq!(event.serialized().size(), event.raw().len());
        let reparsed = SerializedEvent::parse(event.raw())?;
        assert_eq!(reparsed.sad(), event.sad());
        // The registry identifier is the event's own digest, in both fields.
        assert_eq!(event.sad().get_text("i"), event.sad().get_text("d"));
        assert!(event.identifier().is_digestive());
        assert_eq!(event.identifier().qb64()?, event.said().qb64()?);
        Ok(())
    }

    #[test]
    fn every_error_variant_displays_and_sources_correctly() {
        let cases: Vec<(RegistryError, bool)> = vec![
            (RegistryError::NonceTooLong { maximum: 1, actual: 2 }, false),
            (
                RegistryError::BackerTooLong {
                    index: 0,
                    maximum: 1,
                    actual: 2,
                },
                false,
            ),
            (RegistryError::TooManyBackers { maximum: 1, actual: 2 }, false),
            (RegistryError::DuplicateBacker { index: 1 }, false),
            (RegistryError::BackersForbiddenByConfiguration { count: 1 }, false),
            (
                RegistryError::InvalidBackerThreshold {
                    threshold: 0,
                    backers: 1,
                },
                false,
            ),
            (RegistryError::from(EventError::SigningThresholdIsZero), true),
        ];
        for (error, has_source) in cases {
            assert!(!error.to_string().is_empty());
            assert_eq!(error.source().is_some(), has_source, "{error}");
        }
    }
}
