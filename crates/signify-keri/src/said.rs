//! Self-addressing identifiers (SAIDs).
//!
//! A SAID is a digest a message carries *about itself*. Because the digest field cannot contain
//! its own digest, derivation replaces that field with a placeholder of exactly the same width —
//! the reference's `#` dummy — sizes the version string with the placeholder in place, serializes,
//! and hashes the result. Substituting the real SAID afterwards cannot change any byte count, so
//! the message the recipient hashes is byte-identical to the one the issuer hashed.
//!
//! This module ports `src/keri/core/saider.ts`. Two reference behaviors are deliberately not
//! reproduced because they are unsafe rather than merely different; both are recorded in
//! `PORTING.md` §9 and pinned by `fixtures/keri-said/`:
//!
//! - The reference's default `verify` never inspects the SAD's own identifier field, so it returns
//!   `true` for a message whose `d` is empty or holds an entirely different SAID. Rust requires the
//!   field to match unless the caller explicitly asks for [`SaidVerification::digest_only`].
//! - The reference's public `derive` inserts a missing label at the end of the field order rather
//!   than rejecting it, silently changing the bytes being committed to. Rust requires the field to
//!   already exist.

use core::fmt;
use std::error::Error;
use std::str::FromStr;

use signify_cesr::code::DerivationCode;
use signify_crypto::{
    CryptoError,
    digest::{Digest, DigestAlgorithm},
};

use crate::serialization::{Sad, SadError, SadValue, SerializationError, SerializedEvent, VERSION_LABEL};

/// Field label carrying a SAID unless a caller names another; the reference's `Ids.d`.
pub const DEFAULT_SAID_LABEL: &str = "d";

/// Placeholder character used to pad the identifier field during derivation.
pub const DUMMY_CHARACTER: char = '#';

/// One self-addressing identifier: a digest computed over a message that carries it.
///
/// ```
/// use signify_keri::{
///     said::{DEFAULT_SAID_LABEL, Said, SaidVerification},
///     serialization::{Sad, SadValue},
/// };
/// use signify_crypto::digest::DigestAlgorithm;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut sad = Sad::new();
/// sad.insert("d", SadValue::text(""))?;
/// sad.insert("name", SadValue::text("John Jones"))?;
///
/// let computed = Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL)?;
/// // The returned data carries the identifier it commits to.
/// assert_eq!(
///     computed.sad().get_text("d"),
///     Some(computed.said().qb64()?.as_str()),
/// );
/// computed.said().verify(
///     computed.sad(),
///     DEFAULT_SAID_LABEL,
///     SaidVerification::strict(),
/// )?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Said {
    digest: Digest,
}

/// A SAID together with the data that carries it.
///
/// The data has its identifier field filled in and, when it has a version string, that string
/// sized. It is therefore ready to serialize with
/// [`SerializedEvent::from_sad`](crate::serialization::SerializedEvent::from_sad).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaidComputation {
    said: Said,
    sad: Sad,
}

impl SaidComputation {
    /// Returns the computed identifier.
    #[must_use]
    pub const fn said(&self) -> &Said {
        &self.said
    }

    /// Borrows the completed self-addressing data.
    #[must_use]
    pub const fn sad(&self) -> &Sad {
        &self.sad
    }

    /// Splits this result into its identifier and completed data.
    #[must_use]
    pub fn into_parts(self) -> (Said, Sad) {
        (self.said, self.sad)
    }
}

/// Which commitments [`Said::verify`] checks in addition to the digest itself.
///
/// The digest is always recomputed and compared. The remaining checks exist because a digest match
/// alone does not prove the message *claims* the identifier being verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SaidVerification {
    require_label_match: bool,
    require_version_match: bool,
}

impl SaidVerification {
    /// Requires the identifier field and, when present, the version string to match.
    ///
    /// This is the default and the recommended policy for anything received from a peer.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            require_label_match: true,
            require_version_match: true,
        }
    }

    /// Requires the identifier field to match but tolerates a differing version string.
    #[must_use]
    pub const fn label_only() -> Self {
        Self {
            require_label_match: true,
            require_version_match: false,
        }
    }

    /// Compares only the recomputed digest, ignoring what the data claims about itself.
    ///
    /// This reproduces the pinned reference's default, which accepts a message whose identifier
    /// field is empty or holds an unrelated SAID. Prefer [`Self::strict`] unless the caller has
    /// already established the field's value by other means.
    #[must_use]
    pub const fn digest_only() -> Self {
        Self {
            require_label_match: false,
            require_version_match: false,
        }
    }
}

impl Default for SaidVerification {
    fn default() -> Self {
        Self::strict()
    }
}

impl Said {
    /// Computes the identifier for `sad` and returns it with the completed data.
    ///
    /// This is the reference's `saidify`, except that the input is borrowed rather than mutated.
    ///
    /// # Errors
    ///
    /// Returns [`SaidError::MissingLabelField`] when `label` is absent — the reference's public
    /// `derive` instead appends it, changing the committed field order — and layered
    /// [`SaidError::Sad`], [`SaidError::Serialization`], or [`SaidError::Crypto`] failures for
    /// invalid data, an invalid version string, or unencodable material.
    pub fn compute(sad: &Sad, algorithm: DigestAlgorithm, label: &str) -> Result<SaidComputation, SaidError> {
        let derived = Self::derive(sad, algorithm, label)?;
        let identifier = Self { digest: derived.digest };
        let qb64 = identifier.qb64()?;
        let mut completed = derived.sad;
        completed
            .replace_existing(label, SadValue::text(qb64))
            .map_err(|source| SaidError::Sad {
                source: Box::new(source),
            })?;
        Ok(SaidComputation {
            said: identifier,
            sad: completed,
        })
    }

    /// Recomputes the identifier for `sad` and checks it against this one.
    ///
    /// # Errors
    ///
    /// Returns [`SaidError::DigestMismatch`] when the recomputed digest differs,
    /// [`SaidError::LabelFieldMismatch`] when the policy requires the data to claim this
    /// identifier and it does not, [`SaidError::VersionStringMismatch`] when a required version
    /// string differs, and the derivation failures listed on [`Self::compute`].
    pub fn verify(&self, sad: &Sad, label: &str, policy: SaidVerification) -> Result<(), SaidError> {
        let derived = Self::derive(sad, self.algorithm(), label)?;
        if derived.digest != self.digest {
            return Err(SaidError::DigestMismatch);
        }
        if policy.require_label_match {
            let claimed = sad.get_text(label).ok_or_else(|| SaidError::MissingLabelField {
                label: label.to_owned(),
            })?;
            if claimed != self.qb64()? {
                return Err(SaidError::LabelFieldMismatch);
            }
        }
        if policy.require_version_match
            && sad.contains(VERSION_LABEL)
            && sad.get_text(VERSION_LABEL) != derived.sad.get_text(VERSION_LABEL)
        {
            return Err(SaidError::VersionStringMismatch);
        }
        Ok(())
    }

    /// Performs the placeholder-and-size derivation shared by computation and verification.
    fn derive(sad: &Sad, algorithm: DigestAlgorithm, label: &str) -> Result<Derived, SaidError> {
        let width = Self::placeholder_width(algorithm)?;
        let mut dummied = sad.clone();
        dummied
            .replace_existing(label, SadValue::text(DUMMY_CHARACTER.to_string().repeat(width)))
            .map_err(|_| SaidError::MissingLabelField {
                label: label.to_owned(),
            })?;

        // A message with a version string must be sized with the placeholder in place. Because the
        // placeholder is exactly as wide as the identifier that replaces it, the size stays correct
        // for the finished message.
        let (serialization, sad) = if dummied.contains(VERSION_LABEL) {
            let event = SerializedEvent::from_sad(dummied).map_err(|source| SaidError::Serialization {
                source: Box::new(source),
            })?;
            let sad = event.sad().clone();
            (event.raw().to_vec(), sad)
        } else {
            let serialization = dummied.to_json_bytes().map_err(|source| SaidError::Sad {
                source: Box::new(source),
            })?;
            (serialization, dummied)
        };

        Ok(Derived {
            digest: Digest::derive(algorithm, &serialization),
            sad,
        })
    }

    /// Returns how many placeholder characters stand in for an identifier of this algorithm.
    fn placeholder_width(algorithm: DigestAlgorithm) -> Result<usize, SaidError> {
        let code = algorithm.code();
        code.size()
            .full_size()
            .ok_or(SaidError::VariableWidthAlgorithm { code: code.as_str() })
    }

    /// Returns the underlying digest.
    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// Returns the digest algorithm that produced this identifier.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.digest.algorithm()
    }

    /// Returns the CESR derivation code for this identifier.
    #[must_use]
    pub fn code(&self) -> DerivationCode {
        self.digest.code()
    }

    /// Encodes the identifier as canonical qualified Base64.
    ///
    /// # Errors
    ///
    /// Returns a layered [`SaidError::Crypto`] if the shared code table is internally inconsistent.
    pub fn qb64(&self) -> Result<String, SaidError> {
        self.digest.qb64().map_err(|source| SaidError::Crypto {
            source: Box::new(source),
        })
    }

    /// Parses one canonical qualified-Base64 identifier.
    ///
    /// # Errors
    ///
    /// Returns a layered [`SaidError::Crypto`] for malformed, non-digest, or trailing material.
    pub fn from_qb64(input: &str) -> Result<Self, SaidError> {
        Digest::from_qb64(input)
            .map(|digest| Self { digest })
            .map_err(|source| SaidError::Crypto {
                source: Box::new(source),
            })
    }
}

impl From<Digest> for Said {
    fn from(digest: Digest) -> Self {
        Self { digest }
    }
}

impl From<Said> for Digest {
    fn from(said: Said) -> Self {
        said.digest
    }
}

impl FromStr for Said {
    type Err = SaidError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_qb64(input)
    }
}

impl TryFrom<&str> for Said {
    type Error = SaidError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::from_qb64(input)
    }
}

impl fmt::Display for Said {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.qb64()
            .map_err(|_| fmt::Error)
            .and_then(|qb64| formatter.write_str(&qb64))
    }
}

/// One derivation result: the digest and the placeholder-bearing, version-sized data.
struct Derived {
    digest: Digest,
    sad: Sad,
}

/// Stable self-addressing-identifier failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum SaidError {
    /// The data has no field with the requested identifier label.
    MissingLabelField {
        /// Requested label.
        label: String,
    },
    /// The selected digest algorithm has no fixed encoded width to pad.
    VariableWidthAlgorithm {
        /// Derivation code lacking a fixed size.
        code: &'static str,
    },
    /// The recomputed digest differs from this identifier.
    DigestMismatch,
    /// The data's identifier field does not claim this identifier.
    LabelFieldMismatch,
    /// The data's version string differs from the recomputed one.
    VersionStringMismatch,
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
    /// Digest material could not be produced or parsed.
    Crypto {
        /// Underlying cryptographic failure.
        source: Box<CryptoError>,
    },
}

impl fmt::Display for SaidError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLabelField { label } => {
                write!(formatter, "self-addressing data has no field labeled {label:?}")
            }
            Self::VariableWidthAlgorithm { code } => write!(
                formatter,
                "digest code {code} has no fixed width to reserve for an identifier"
            ),
            Self::DigestMismatch => formatter.write_str("recomputed identifier does not match"),
            Self::LabelFieldMismatch => formatter.write_str("self-addressing data does not claim this identifier"),
            Self::VersionStringMismatch => {
                formatter.write_str("self-addressing data version string does not match the derived one")
            }
            Self::Sad { .. } => formatter.write_str("self-addressing data is invalid"),
            Self::Serialization { .. } => formatter.write_str("message serialization failed"),
            Self::Crypto { .. } => formatter.write_str("digest material is invalid"),
        }
    }
}

impl Error for SaidError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sad { source } => Some(source.as_ref()),
            Self::Serialization { source } => Some(source.as_ref()),
            Self::Crypto { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact `rep` message asserted by the pinned `test/core/saider.test.ts`.
    const REFERENCE_SAID: &str = "ELzewBpZHSENRP-sL_G_2Ji4YDdNkns9AzFzufleJqdw";

    fn reference_sad() -> Result<Sad, SadError> {
        let mut attributes = Sad::new();
        attributes.insert("d", SadValue::text("EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg"))?;
        attributes.insert("i", SadValue::text("EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb"))?;
        attributes.insert("name", SadValue::text("John Jones"))?;
        attributes.insert("role", SadValue::text("Founder"))?;

        let mut sad = Sad::new();
        sad.insert("v", SadValue::text("KERI10JSON000000_"))?;
        sad.insert("t", SadValue::text("rep"))?;
        sad.insert("d", SadValue::text(""))?;
        sad.insert("dt", SadValue::text("2020-08-22T17:50:12.988921+00:00"))?;
        sad.insert("r", SadValue::text("logs/processor"))?;
        sad.insert("a", SadValue::Map(attributes))?;
        Ok(sad)
    }

    #[test]
    fn pinned_reference_said_is_exact() -> Result<(), Box<dyn Error>> {
        let computed = Said::compute(&reference_sad()?, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL)?;
        assert_eq!(computed.said().qb64()?, REFERENCE_SAID);
        assert_eq!(computed.said().code(), DerivationCode::BLAKE3_256);
        assert_eq!(computed.said().to_string(), REFERENCE_SAID);
        // The completed data claims the identifier and carries the sized version string.
        assert_eq!(computed.sad().get_text("d"), Some(REFERENCE_SAID));
        assert_eq!(computed.sad().get_text("v"), Some("KERI10JSON000124_"));
        Ok(())
    }

    #[test]
    fn completed_data_serializes_at_its_declared_size() -> Result<(), Box<dyn Error>> {
        let computed = Said::compute(&reference_sad()?, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL)?;
        let (_, sad) = computed.into_parts();
        let event = SerializedEvent::from_sad(sad)?;
        // Substituting the identifier for the placeholder cannot change the byte count, so the
        // size derived during placeholder hashing is still correct.
        assert_eq!(event.size(), 0x124);
        assert_eq!(event.sad().get_text("v"), Some("KERI10JSON000124_"));
        Ok(())
    }

    #[test]
    fn version_less_data_derives_without_sizing() -> Result<(), Box<dyn Error>> {
        let mut sad = Sad::new();
        sad.insert("d", SadValue::text(""))?;
        sad.insert("i", SadValue::text("EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb"))?;
        sad.insert("name", SadValue::text("John Jones"))?;

        let computed = Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL)?;
        assert_eq!(computed.said().qb64()?, "EKMziJHwuy7bm7XhtQtFE1kduVFoxm3fp45Iyt-MQT1K");
        assert!(!computed.sad().contains("v"));
        computed
            .said()
            .verify(computed.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())?;
        Ok(())
    }

    #[test]
    fn verification_is_strict_about_the_claimed_identifier() -> Result<(), Box<dyn Error>> {
        let computed = Said::compute(&reference_sad()?, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL)?;
        let said = *computed.said();
        said.verify(computed.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())?;

        // The original data has an empty `d`. The digest still matches, because derivation
        // replaces that field either way -- which is precisely why the reference's default accepts
        // it. Rust rejects it unless the caller opts out explicitly.
        let original = reference_sad()?;
        assert!(matches!(
            said.verify(&original, DEFAULT_SAID_LABEL, SaidVerification::strict()),
            Err(SaidError::LabelFieldMismatch)
        ));
        said.verify(&original, DEFAULT_SAID_LABEL, SaidVerification::digest_only())?;

        // An unrelated identifier in the field is likewise accepted only by the permissive policy.
        let mut wrong = reference_sad()?;
        wrong.replace_existing("d", SadValue::text("EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg"))?;
        assert!(matches!(
            said.verify(&wrong, DEFAULT_SAID_LABEL, SaidVerification::strict()),
            Err(SaidError::LabelFieldMismatch)
        ));
        said.verify(&wrong, DEFAULT_SAID_LABEL, SaidVerification::digest_only())?;
        Ok(())
    }

    #[test]
    fn modified_content_fails_the_digest() -> Result<(), Box<dyn Error>> {
        let computed = Said::compute(&reference_sad()?, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL)?;
        let said = *computed.said();

        let mut tampered = computed.sad().clone();
        tampered.replace_existing("r", SadValue::text("logs/tampered"))?;
        assert!(matches!(
            said.verify(&tampered, DEFAULT_SAID_LABEL, SaidVerification::digest_only()),
            Err(SaidError::DigestMismatch)
        ));

        // A different identifier over the same data also fails.
        let other = Said::from_qb64("EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg")?;
        assert!(matches!(
            other.verify(computed.sad(), DEFAULT_SAID_LABEL, SaidVerification::digest_only()),
            Err(SaidError::DigestMismatch)
        ));
        Ok(())
    }

    #[test]
    fn version_string_policy_is_enforced_separately() -> Result<(), Box<dyn Error>> {
        let computed = Said::compute(&reference_sad()?, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL)?;
        let said = *computed.said();

        // A version string that disagrees with the derived one is caught only by the strict policy.
        let mut restamped = computed.sad().clone();
        restamped.replace_existing("v", SadValue::text("KERI10JSON000000_"))?;
        assert!(matches!(
            said.verify(&restamped, DEFAULT_SAID_LABEL, SaidVerification::strict()),
            Err(SaidError::VersionStringMismatch)
        ));
        said.verify(&restamped, DEFAULT_SAID_LABEL, SaidVerification::label_only())?;
        Ok(())
    }

    #[test]
    fn a_missing_label_is_rejected_rather_than_appended() -> Result<(), Box<dyn Error>> {
        let mut sad = Sad::new();
        sad.insert("v", SadValue::text("KERI10JSON000000_"))?;
        sad.insert("t", SadValue::text("rep"))?;
        assert!(matches!(
            Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL),
            Err(SaidError::MissingLabelField { .. })
        ));

        // A non-default label works when it is present.
        let mut labeled = Sad::new();
        labeled.insert("id", SadValue::text(""))?;
        labeled.insert("name", SadValue::text("John Jones"))?;
        let computed = Said::compute(&labeled, DigestAlgorithm::Blake3_256, "id")?;
        assert_eq!(computed.sad().get_text("id"), Some(computed.said().qb64()?.as_str()));
        assert!(matches!(
            Said::compute(&labeled, DigestAlgorithm::Blake3_256, "d"),
            Err(SaidError::MissingLabelField { .. })
        ));
        Ok(())
    }

    #[test]
    fn placeholder_width_matches_the_encoded_identifier() -> Result<(), Box<dyn Error>> {
        let width = Said::placeholder_width(DigestAlgorithm::Blake3_256)?;
        assert_eq!(width, 44);
        assert_eq!(REFERENCE_SAID.len(), width);
        Ok(())
    }

    #[test]
    fn material_conversions_round_trip() -> Result<(), Box<dyn Error>> {
        let said = Said::from_qb64(REFERENCE_SAID)?;
        assert_eq!(said.qb64()?, REFERENCE_SAID);
        assert_eq!(REFERENCE_SAID.parse::<Said>()?, said);
        assert_eq!(Said::try_from(REFERENCE_SAID)?, said);
        assert_eq!(Said::from(said.digest()), said);
        assert_eq!(Digest::from(said), said.digest());
        assert_eq!(said.algorithm(), DigestAlgorithm::Blake3_256);

        assert!(Said::from_qb64("not-a-said").is_err());
        assert!(Said::from_qb64("").is_err());
        // A non-digest code cannot become an identifier.
        assert!(Said::from_qb64("DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e").is_err());
        Ok(())
    }

    #[test]
    fn errors_carry_sources_and_readable_text() -> Result<(), Box<dyn Error>> {
        let mut broken = Sad::new();
        broken.insert("v", SadValue::text("KERI10CBOR000000_"))?;
        broken.insert("d", SadValue::text(""))?;
        let error = Said::compute(&broken, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL)
            .err()
            .ok_or("expected a serialization failure")?;
        assert!(matches!(error, SaidError::Serialization { .. }));
        assert!(error.source().is_some());
        assert!(!error.to_string().is_empty());

        assert!(!SaidError::DigestMismatch.to_string().is_empty());
        assert!(SaidError::DigestMismatch.source().is_none());
        Ok(())
    }

    #[test]
    fn verification_policies_are_explicit() {
        assert_eq!(SaidVerification::default(), SaidVerification::strict());
        assert_ne!(SaidVerification::strict(), SaidVerification::digest_only());
        assert_ne!(SaidVerification::label_only(), SaidVerification::strict());
    }
}
