//! Autonomic identifier prefixes.
//!
//! A KERI identifier *is* its prefix, and the prefix is derived from the inception event itself.
//! Two families exist in the pinned reference:
//!
//! - **Basic**: the controller's Ed25519 public key is the identifier, in either the transferable
//!   (`D`) or non-transferable (`B`) form. A non-transferable identifier can never rotate, so its
//!   inception event must carry no next-key digests, backers, or anchors.
//! - **Self-addressing**: a BLAKE3-256 digest of the inception event (`E`). Derivation replaces
//!   both the identifier field and the SAID field with a placeholder exactly as wide as the
//!   identifier that will replace them, sizes the version string with the placeholders in place,
//!   serializes, and hashes the result — the same trick [`crate::said`] uses, applied to two
//!   fields at once so the finished event commits to itself.
//!
//! This module ports `src/keri/core/prefixer.ts`. Four reference behaviors are deliberately not
//! reproduced; all four are pinned by `fixtures/keri-prefix/` and recorded in `PORTING.md` §9:
//!
//! - The public `derive` and `verify` methods gate on `sad['i']`, the *identifier* field, instead
//!   of `sad['t']`, the event kind. Both therefore throw `Non-incepting ilk` for every real event,
//!   and `verify(sad, true)` can never return `true`: reaching the comparison requires `i` to be
//!   the literal text `icp`, which is exactly what the comparison then rejects. Rust gates on the
//!   event kind and makes [`PrefixVerification::Strict`] the default and the useful case.
//! - The transferable basic derivation's key-code check is written `verfer.code in [MtrDex.Ed25519]`,
//!   which tests array *property keys* and is therefore never true. A non-transferable `B` key
//!   passed to a transferable `D` derivation silently produces a `B` prefix. Rust rejects the
//!   mismatch.
//! - Non-transferable *verification* checks only the next-key field, though its own derivation also
//!   rejects backers and anchors. Rust verifies by re-deriving, so all three are checked.
//! - Self-addressing verification mutates the caller's event, leaving the identifier and SAID
//!   fields full of placeholder characters. Rust borrows the data and clones internally.

use core::fmt;
use std::error::Error;
use std::str::FromStr;

use signify_cesr::CesrError;
use signify_cesr::code::{DerivationCode, hard_code_size};
use signify_crypto::CryptoError;
use signify_crypto::digest::{Digest, DigestAlgorithm};
use signify_crypto::verifier::{KeyTransferability, VerificationKey};

use crate::event::kind::{EventKind, EventKindError};
use crate::said::{DUMMY_CHARACTER, Said};
use crate::serialization::{
    IDENTIFIER_LABEL, KEYS_LABEL, KIND_LABEL, NEXT_KEYS_LABEL, SAID_LABEL, Sad, SadError, SadValue, SerializationError,
    SerializedEvent,
};

/// Field label listing an inception event's backers (witnesses); the reference's `b`.
const BACKERS_LABEL: &str = "b";

/// Field label carrying an inception event's anchored data; the reference's `a`.
const ANCHORS_LABEL: &str = "a";

/// How an identifier prefix is derived from its inception event.
///
/// Each variant corresponds to exactly one CESR derivation code, and only these three are
/// supported by the pinned reference.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrefixDerivation {
    /// Basic non-transferable Ed25519 public key (`B`).
    ///
    /// The identifier can never rotate, so the inception event must carry no next-key digests,
    /// backers, or anchors.
    Ed25519NonTransferable,
    /// Basic transferable Ed25519 public key (`D`).
    Ed25519,
    /// Self-addressing BLAKE3-256 digest of the inception event (`E`).
    Blake3_256,
}

impl PrefixDerivation {
    /// Every derivation supported by the pinned reference, in code-table order.
    pub const ALL: [Self; 3] = [Self::Ed25519NonTransferable, Self::Ed25519, Self::Blake3_256];

    /// Returns the CESR derivation code this derivation produces.
    #[must_use]
    pub const fn code(self) -> DerivationCode {
        match self {
            Self::Ed25519NonTransferable => DerivationCode::ED25519_NONTRANSFERABLE,
            Self::Ed25519 => DerivationCode::ED25519,
            Self::Blake3_256 => DerivationCode::BLAKE3_256,
        }
    }

    /// Whether the prefix is a digest of the inception event rather than a public key.
    ///
    /// This is the reference's `Matter.digestive`, restricted to prefix codes. Delegated inception
    /// requires it, because a delegated identifier must commit to its delegator.
    #[must_use]
    pub const fn is_digestive(self) -> bool {
        matches!(self, Self::Blake3_256)
    }

    /// Whether an identifier derived this way may rotate its keys.
    ///
    /// This is the reference's `Matter.transferable`: every prefix code except the explicitly
    /// non-transferable ones.
    #[must_use]
    pub const fn is_transferable(self) -> bool {
        !matches!(self, Self::Ed25519NonTransferable)
    }

    /// Selects the derivation identified by a CESR derivation code.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixError::UnsupportedCode`] for any code outside the three the pinned
    /// reference implements.
    pub fn from_code(code: DerivationCode) -> Result<Self, PrefixError> {
        Self::ALL
            .into_iter()
            .find(|derivation| derivation.code() == code)
            .ok_or(PrefixError::UnsupportedCode { code: code.as_str() })
    }
}

/// A basic prefix: the controller's public key *is* the identifier.
///
/// The inner key is private because only Ed25519 keys may form a prefix in the pinned reference;
/// [`Self::new`] rejects anything else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicPrefix {
    key: VerificationKey,
}

impl BasicPrefix {
    /// Wraps a verification key that is usable as an identifier prefix.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixError::UnsupportedCode`] for a key whose code is not `B` or `D`; the pinned
    /// reference supports no ECDSA basic prefix.
    pub fn new(key: VerificationKey) -> Result<Self, PrefixError> {
        PrefixDerivation::from_code(key.code()).and_then(|derivation| {
            if derivation.is_digestive() {
                Err(PrefixError::UnsupportedCode {
                    code: key.code().as_str(),
                })
            } else {
                Ok(Self { key })
            }
        })
    }

    /// Borrows the public key that forms this identifier.
    #[must_use]
    pub const fn key(&self) -> &VerificationKey {
        &self.key
    }

    /// Returns whether the identifier may rotate its keys.
    #[must_use]
    pub const fn transferability(&self) -> KeyTransferability {
        self.key.transferability()
    }
}

/// One autonomic identifier prefix.
///
/// ```
/// use signify_keri::prefix::{IdentifierPrefix, PrefixDerivation, PrefixVerification};
/// use signify_keri::serialization::{Sad, SadValue};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut inception = Sad::new();
/// inception.insert("v", SadValue::text("KERI10JSON000000_"))?;
/// inception.insert("i", SadValue::text(""))?;
/// inception.insert("s", SadValue::text("0"))?;
/// inception.insert("t", SadValue::text("icp"))?;
/// inception.insert("kt", SadValue::text("1"))?;
/// inception.insert(
///     "k",
///     SadValue::Array(vec![SadValue::text(
///         "DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx",
///     )]),
/// )?;
/// inception.insert("n", SadValue::text(""))?;
/// inception.insert("wt", SadValue::text("0"))?;
/// inception.insert("w", SadValue::Array(Vec::new()))?;
/// inception.insert("c", SadValue::Array(Vec::new()))?;
///
/// // The controller's key can be the identifier directly...
/// let basic = IdentifierPrefix::derive(&inception, PrefixDerivation::Ed25519)?;
/// assert_eq!(basic.qb64()?, "DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx");
/// assert!(basic.is_transferable());
///
/// // ...or the identifier can be a digest of the whole inception event.
/// let self_addressing = IdentifierPrefix::derive(&inception, PrefixDerivation::Blake3_256)?;
/// assert_eq!(
///     self_addressing.qb64()?,
///     "ELEjyRTtmfyp4VpTBTkv_b6KONMS1V8-EW-aGJ5P_QMo",
/// );
/// assert!(self_addressing.is_digestive());
///
/// // Verification recomputes the derivation. The event above does not yet claim either prefix,
/// // so only the derivation itself can be checked.
/// self_addressing.verify(&inception, PrefixVerification::DerivationOnly)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "a verification key carries a decompressed curve point, so the basic variant is \
              inherently larger than a digest; boxing it would add a heap allocation to every \
              identifier for no benefit, since prefixes are short-lived values passed by reference"
)]
pub enum IdentifierPrefix {
    /// The controller's public key is the identifier.
    Basic(BasicPrefix),
    /// A digest of the inception event is the identifier.
    SelfAddressing(Said),
}

/// Which commitments [`IdentifierPrefix::verify`] checks beyond the derivation itself.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum PrefixVerification {
    /// Requires the event's identifier field to claim this prefix.
    ///
    /// This is the default and the right policy for anything received from a peer. It is the check
    /// the reference's `prefixed` flag intends but can never perform, because its own event-kind
    /// gate rejects every event whose identifier field is not the literal text `icp`.
    #[default]
    Strict,
    /// Checks only that this prefix derives from the event, ignoring what the event claims.
    ///
    /// Useful while building an event, before its identifier field has been filled in.
    DerivationOnly,
}

impl IdentifierPrefix {
    /// Derives an identifier prefix from inception data.
    ///
    /// For [`PrefixDerivation::Blake3_256`] the event must carry a version string as its first
    /// field and an event kind of `icp`, `dip`, or `vcp`. For the basic derivations the event must
    /// carry exactly one verification key whose code matches the requested derivation.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixError::MissingKeysField`], [`PrefixError::InvalidKeysField`],
    /// [`PrefixError::KeyCount`], or [`PrefixError::KeyCodeMismatch`] for unusable basic key
    /// material; [`PrefixError::NonTransferableFieldNotEmpty`] when a non-transferable inception
    /// event carries rotation, backer, or anchor content; [`PrefixError::MissingEventKind`],
    /// [`PrefixError::EventKind`], or [`PrefixError::NonInceptingEventKind`] when the event kind
    /// cannot support self-addressing derivation; and layered [`PrefixError::Sad`],
    /// [`PrefixError::Serialization`], or [`PrefixError::Crypto`] failures otherwise.
    pub fn derive(sad: &Sad, derivation: PrefixDerivation) -> Result<Self, PrefixError> {
        match derivation {
            PrefixDerivation::Ed25519NonTransferable => {
                let key = single_verification_key(sad, derivation.code())?;
                // A non-transferable identifier cannot rotate, so committing to next keys,
                // backers, or anchors would be a promise it can never keep.
                for label in [NEXT_KEYS_LABEL, BACKERS_LABEL, ANCHORS_LABEL] {
                    if !is_empty_field(sad, label) {
                        return Err(PrefixError::NonTransferableFieldNotEmpty { label });
                    }
                }
                Ok(Self::Basic(BasicPrefix { key }))
            }
            PrefixDerivation::Ed25519 => {
                let key = single_verification_key(sad, derivation.code())?;
                Ok(Self::Basic(BasicPrefix { key }))
            }
            PrefixDerivation::Blake3_256 => {
                let preimage = self_addressing_preimage(sad)?;
                Ok(Self::SelfAddressing(Said::from(Digest::derive(
                    DigestAlgorithm::Blake3_256,
                    &preimage,
                ))))
            }
        }
    }

    /// Re-derives this prefix from `sad` and checks that the result is this prefix.
    ///
    /// Because verification re-derives, every invariant [`Self::derive`] enforces is enforced here
    /// too. The reference's non-transferable verification instead checks only the next-key field,
    /// accepting an event with backers or anchors that its own derivation would have rejected.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixError::PrefixMismatch`] when the event derives a different prefix,
    /// [`PrefixError::MissingIdentifierField`] or [`PrefixError::IdentifierFieldMismatch`] when
    /// [`PrefixVerification::Strict`] is requested and the event does not claim this prefix, and
    /// the derivation failures listed on [`Self::derive`].
    pub fn verify(&self, sad: &Sad, policy: PrefixVerification) -> Result<(), PrefixError> {
        let derived = Self::derive(sad, self.derivation())?;
        if &derived != self {
            return Err(PrefixError::PrefixMismatch);
        }
        if policy == PrefixVerification::Strict {
            let claimed = sad
                .get_text(IDENTIFIER_LABEL)
                .ok_or(PrefixError::MissingIdentifierField)?;
            if claimed != self.qb64()? {
                return Err(PrefixError::IdentifierFieldMismatch);
            }
        }
        Ok(())
    }

    /// Returns the derivation that produced, and that verifies, this prefix.
    #[must_use]
    pub const fn derivation(&self) -> PrefixDerivation {
        match self {
            Self::Basic(basic) => match basic.transferability() {
                KeyTransferability::Transferable => PrefixDerivation::Ed25519,
                KeyTransferability::NonTransferable => PrefixDerivation::Ed25519NonTransferable,
            },
            Self::SelfAddressing(_) => PrefixDerivation::Blake3_256,
        }
    }

    /// Returns the CESR derivation code of this prefix.
    #[must_use]
    pub const fn code(&self) -> DerivationCode {
        self.derivation().code()
    }

    /// Whether this identifier may rotate its keys; the reference's `Matter.transferable`.
    #[must_use]
    pub const fn is_transferable(&self) -> bool {
        self.derivation().is_transferable()
    }

    /// Whether this identifier is a digest of its inception event; the reference's
    /// `Matter.digestive`.
    #[must_use]
    pub const fn is_digestive(&self) -> bool {
        self.derivation().is_digestive()
    }

    /// Encodes the prefix as canonical qualified Base64.
    ///
    /// # Errors
    ///
    /// Returns a layered [`PrefixError::Crypto`] if the shared code table is internally
    /// inconsistent.
    pub fn qb64(&self) -> Result<String, PrefixError> {
        match self {
            Self::Basic(basic) => basic.key.qb64().map_err(PrefixError::crypto),
            Self::SelfAddressing(said) => said.digest().qb64().map_err(PrefixError::crypto),
        }
    }

    /// Parses one canonical qualified-Base64 prefix.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixError::UnsupportedCode`] for material that is not a prefix code, a layered
    /// [`PrefixError::Cesr`] for an unreadable code, and a layered [`PrefixError::Crypto`] for
    /// malformed or trailing material.
    pub fn from_qb64(input: &str) -> Result<Self, PrefixError> {
        match PrefixDerivation::from_code(leading_code(input)?)? {
            PrefixDerivation::Ed25519 | PrefixDerivation::Ed25519NonTransferable => {
                let key = VerificationKey::from_qb64(input).map_err(PrefixError::crypto)?;
                BasicPrefix::new(key).map(Self::Basic)
            }
            PrefixDerivation::Blake3_256 => Digest::from_qb64(input)
                .map(|digest| Self::SelfAddressing(Said::from(digest)))
                .map_err(PrefixError::crypto),
        }
    }
}

impl From<Said> for IdentifierPrefix {
    fn from(said: Said) -> Self {
        Self::SelfAddressing(said)
    }
}

impl From<BasicPrefix> for IdentifierPrefix {
    fn from(basic: BasicPrefix) -> Self {
        Self::Basic(basic)
    }
}

impl TryFrom<VerificationKey> for BasicPrefix {
    type Error = PrefixError;

    fn try_from(key: VerificationKey) -> Result<Self, Self::Error> {
        Self::new(key)
    }
}

impl FromStr for IdentifierPrefix {
    type Err = PrefixError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_qb64(input)
    }
}

impl TryFrom<&str> for IdentifierPrefix {
    type Error = PrefixError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::from_qb64(input)
    }
}

impl fmt::Display for IdentifierPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.qb64()
            .map_err(|_| fmt::Error)
            .and_then(|qb64| formatter.write_str(&qb64))
    }
}

/// Reads the derivation code from the front of qualified Base64 text.
fn leading_code(input: &str) -> Result<DerivationCode, PrefixError> {
    let selector = input.as_bytes().first().copied().ok_or(PrefixError::Cesr {
        source: Box::new(CesrError::EmptyInput {
            context: "identifier prefix",
        }),
    })?;
    let hard = hard_code_size(selector).map_err(PrefixError::cesr)?;
    let text = input.get(..hard).ok_or_else(|| {
        PrefixError::cesr(CesrError::Truncated {
            context: "identifier prefix",
            needed: hard,
            available: input.len(),
        })
    })?;
    text.parse().map_err(PrefixError::cesr)
}

/// Extracts the single verification key a basic derivation requires.
fn single_verification_key(sad: &Sad, expected: DerivationCode) -> Result<VerificationKey, PrefixError> {
    let keys = sad
        .get(KEYS_LABEL)
        .ok_or(PrefixError::MissingKeysField)?
        .as_array()
        .ok_or(PrefixError::InvalidKeysField)?;
    let [only] = keys else {
        return Err(PrefixError::KeyCount { count: keys.len() });
    };
    let qb64 = only.as_text().ok_or(PrefixError::InvalidKeysField)?;
    let key = VerificationKey::from_qb64(qb64).map_err(PrefixError::crypto)?;
    if key.code() == expected {
        Ok(key)
    } else {
        Err(PrefixError::KeyCodeMismatch {
            expected: expected.as_str(),
            found: key.code().as_str(),
        })
    }
}

/// Returns whether a field is absent, an empty list, or empty text.
///
/// The reference reads `.length`, which is why both the empty list an inception event normally
/// carries and the empty string the pinned unit test uses count as empty. A value with no length —
/// a nested block, a number — reads as `undefined > 0`, so the reference silently treats it as
/// empty; `null` throws a `TypeError` instead. Rust reports every such value as non-empty rather
/// than ignoring content it cannot interpret, which rejects strictly more than the reference does.
fn is_empty_field(sad: &Sad, label: &str) -> bool {
    match sad.get(label) {
        None => true,
        Some(SadValue::Array(items)) => items.is_empty(),
        Some(SadValue::Text(text)) => text.is_empty(),
        Some(_) => false,
    }
}

/// Builds the exact bytes a self-addressing prefix is the digest of.
fn self_addressing_preimage(sad: &Sad) -> Result<Vec<u8>, PrefixError> {
    let kind_text = sad.get_text(KIND_LABEL).ok_or(PrefixError::MissingEventKind)?;
    let kind: EventKind = kind_text.parse().map_err(PrefixError::event_kind)?;
    match kind {
        EventKind::Inception | EventKind::DelegatedInception | EventKind::RegistryInception => {}
        other => return Err(PrefixError::NonInceptingEventKind { found: other }),
    }

    // Both the identifier and the SAID commit to the finished event, so both are replaced by a
    // placeholder of exactly the width their qualified encoding will occupy. Substituting the real
    // prefix afterwards cannot change any byte count.
    let placeholder: String = core::iter::repeat_n(DUMMY_CHARACTER, PLACEHOLDER_WIDTH).collect();
    let mut dummied = sad.clone();
    for label in [IDENTIFIER_LABEL, SAID_LABEL] {
        let value = SadValue::text(placeholder.clone());
        let result = if dummied.contains(label) {
            dummied.replace_existing(label, value)
        } else {
            // The reference appends an absent field at the end of the event, and the pinned unit
            // test's inception data has no SAID field at all. Matching that placement is what makes
            // its expected prefix reproducible; keripy places it identically.
            dummied.insert(label, value)
        };
        result.map_err(PrefixError::sad)?;
    }

    SerializedEvent::from_sad(dummied)
        .map(|event| event.raw().to_vec())
        .map_err(PrefixError::serialization)
}

/// Encoded width of a self-addressing prefix, and therefore of its placeholder.
const PLACEHOLDER_WIDTH: usize = 44;

/// Stable identifier-prefix failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum PrefixError {
    /// The derivation code cannot form an identifier prefix.
    UnsupportedCode {
        /// Rejected derivation code.
        code: &'static str,
    },
    /// The inception data has no verification-key field.
    MissingKeysField,
    /// The verification-key field is not a list of qualified text.
    InvalidKeysField,
    /// Basic derivation needs exactly one verification key.
    KeyCount {
        /// Number of keys present.
        count: usize,
    },
    /// The verification key's code does not match the requested derivation.
    KeyCodeMismatch {
        /// Code the requested derivation needs.
        expected: &'static str,
        /// Code the key actually carries.
        found: &'static str,
    },
    /// A non-transferable identifier's inception data carries content it can never honor.
    NonTransferableFieldNotEmpty {
        /// Field label that must be empty.
        label: &'static str,
    },
    /// The inception data has no event-kind field.
    MissingEventKind,
    /// The event kind cannot originate an identifier.
    NonInceptingEventKind {
        /// Event kind found instead of `icp`, `dip`, or `vcp`.
        found: EventKind,
    },
    /// The derivation produced a different prefix.
    PrefixMismatch,
    /// The data has no identifier field to compare against.
    MissingIdentifierField,
    /// The data's identifier field does not claim this prefix.
    IdentifierFieldMismatch,
    /// The event-kind field is not a known ilk.
    EventKind {
        /// Underlying event-kind failure.
        source: Box<EventKindError>,
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
    /// Key or digest material could not be produced or parsed.
    Crypto {
        /// Underlying cryptographic failure.
        source: Box<CryptoError>,
    },
    /// Qualified material could not be read.
    Cesr {
        /// Underlying encoding failure.
        source: Box<CesrError>,
    },
}

impl PrefixError {
    fn event_kind(source: EventKindError) -> Self {
        Self::EventKind {
            source: Box::new(source),
        }
    }

    fn sad(source: SadError) -> Self {
        Self::Sad {
            source: Box::new(source),
        }
    }

    fn serialization(source: SerializationError) -> Self {
        Self::Serialization {
            source: Box::new(source),
        }
    }

    fn crypto(source: CryptoError) -> Self {
        Self::Crypto {
            source: Box::new(source),
        }
    }

    fn cesr(source: CesrError) -> Self {
        Self::Cesr {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for PrefixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCode { code } => {
                write!(formatter, "derivation code {code} cannot form an identifier prefix")
            }
            Self::MissingKeysField => write!(formatter, "inception data has no {KEYS_LABEL:?} field"),
            Self::InvalidKeysField => write!(
                formatter,
                "inception data field {KEYS_LABEL:?} is not a list of qualified keys"
            ),
            Self::KeyCount { count } => {
                write!(formatter, "basic derivation needs exactly one key, found {count}")
            }
            Self::KeyCodeMismatch { expected, found } => write!(
                formatter,
                "verification key code {found} does not match derivation code {expected}"
            ),
            Self::NonTransferableFieldNotEmpty { label } => write!(
                formatter,
                "non-transferable inception data field {label:?} must be empty"
            ),
            Self::MissingEventKind => write!(formatter, "inception data has no {KIND_LABEL:?} field"),
            Self::NonInceptingEventKind { found } => {
                write!(formatter, "event kind {found} cannot originate an identifier")
            }
            Self::PrefixMismatch => formatter.write_str("recomputed identifier prefix does not match"),
            Self::MissingIdentifierField => {
                write!(formatter, "data has no {IDENTIFIER_LABEL:?} field to compare")
            }
            Self::IdentifierFieldMismatch => formatter.write_str("data does not claim this identifier prefix"),
            Self::EventKind { .. } => formatter.write_str("event kind is not a known ilk"),
            Self::Sad { .. } => formatter.write_str("self-addressing data is invalid"),
            Self::Serialization { .. } => formatter.write_str("message serialization failed"),
            Self::Crypto { .. } => formatter.write_str("identifier material is invalid"),
            Self::Cesr { .. } => formatter.write_str("qualified material is invalid"),
        }
    }
}

impl Error for PrefixError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EventKind { source } => Some(source.as_ref()),
            Self::Sad { source } => Some(source.as_ref()),
            Self::Serialization { source } => Some(source.as_ref()),
            Self::Crypto { source } => Some(source.as_ref()),
            Self::Cesr { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transferable key from the pinned `test/core/prefixer.test.ts`.
    const PINNED_KEY: &str = "DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";
    /// The same key material in non-transferable form.
    const PINNED_KEY_NONTRANSFERABLE: &str = "BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";
    /// The self-addressing prefix the pinned unit test asserts.
    const PINNED_PREFIX: &str = "ELEjyRTtmfyp4VpTBTkv_b6KONMS1V8-EW-aGJ5P_QMo";

    /// The exact inception data from the pinned `test/core/prefixer.test.ts`, which carries no
    /// SAID field.
    fn pinned_inception(key: &str) -> Result<Sad, SadError> {
        let mut sad = Sad::new();
        sad.insert("v", SadValue::text("KERI10JSON000000_"))?;
        sad.insert("i", SadValue::text(""))?;
        sad.insert("s", SadValue::text("0"))?;
        sad.insert("t", SadValue::text("icp"))?;
        sad.insert("kt", SadValue::text("1"))?;
        sad.insert("k", SadValue::Array(vec![SadValue::text(key)]))?;
        sad.insert("n", SadValue::text(""))?;
        sad.insert("wt", SadValue::text("0"))?;
        sad.insert("w", SadValue::Array(Vec::new()))?;
        sad.insert("c", SadValue::Array(Vec::new()))?;
        Ok(sad)
    }

    /// Rebuilds a SAD with one field replaced, preserving field order.
    fn with_field(sad: &Sad, label: &str, value: &SadValue) -> Result<Sad, SadError> {
        let mut rebuilt = Sad::new();
        for (existing, existing_value) in sad.entries() {
            if existing == label {
                rebuilt.insert(existing.to_owned(), value.clone())?;
            } else {
                rebuilt.insert(existing.to_owned(), existing_value.clone())?;
            }
        }
        Ok(rebuilt)
    }

    #[test]
    fn pinned_reference_prefixes_are_exact() -> Result<(), Box<dyn Error>> {
        let inception = pinned_inception(PINNED_KEY)?;

        let self_addressing = IdentifierPrefix::derive(&inception, PrefixDerivation::Blake3_256)?;
        assert_eq!(self_addressing.qb64()?, PINNED_PREFIX);
        assert_eq!(self_addressing.to_string(), PINNED_PREFIX);
        assert_eq!(self_addressing.code(), DerivationCode::BLAKE3_256);
        assert!(self_addressing.is_digestive());
        assert!(self_addressing.is_transferable());

        let basic = IdentifierPrefix::derive(&inception, PrefixDerivation::Ed25519)?;
        assert_eq!(basic.qb64()?, PINNED_KEY);
        assert_eq!(basic.code(), DerivationCode::ED25519);
        assert!(!basic.is_digestive());
        assert!(basic.is_transferable());
        Ok(())
    }

    #[test]
    fn non_transferable_derivation_rejects_rotatable_content() -> Result<(), Box<dyn Error>> {
        let inception = pinned_inception(PINNED_KEY_NONTRANSFERABLE)?;
        let prefix = IdentifierPrefix::derive(&inception, PrefixDerivation::Ed25519NonTransferable)?;
        assert_eq!(prefix.qb64()?, PINNED_KEY_NONTRANSFERABLE);
        assert!(!prefix.is_transferable());

        for (label, value) in [
            ("n", SadValue::Array(vec![SadValue::text(PINNED_PREFIX)])),
            ("b", SadValue::Array(vec![SadValue::text(PINNED_KEY)])),
            ("a", SadValue::Array(vec![SadValue::text("anchor")])),
        ] {
            let mut populated = inception.clone();
            if populated.contains(label) {
                populated = with_field(&populated, label, &value)?;
            } else {
                populated.insert(label, value)?;
            }
            assert!(
                matches!(
                    IdentifierPrefix::derive(&populated, PrefixDerivation::Ed25519NonTransferable),
                    Err(PrefixError::NonTransferableFieldNotEmpty { .. })
                ),
                "field {label} was accepted"
            );
            // The same content is fine for a transferable identifier, which can rotate.
            let transferable = with_field(&populated, "k", &SadValue::Array(vec![SadValue::text(PINNED_KEY)]))?;
            IdentifierPrefix::derive(&transferable, PrefixDerivation::Ed25519)?;
        }
        Ok(())
    }

    #[test]
    fn a_mismatched_key_code_is_rejected() -> Result<(), Box<dyn Error>> {
        // The reference's transferable check is a no-op, so it silently returns a `B` prefix here.
        let non_transferable = pinned_inception(PINNED_KEY_NONTRANSFERABLE)?;
        assert!(matches!(
            IdentifierPrefix::derive(&non_transferable, PrefixDerivation::Ed25519),
            Err(PrefixError::KeyCodeMismatch {
                expected: "D",
                found: "B"
            })
        ));

        let transferable = pinned_inception(PINNED_KEY)?;
        assert!(matches!(
            IdentifierPrefix::derive(&transferable, PrefixDerivation::Ed25519NonTransferable),
            Err(PrefixError::KeyCodeMismatch {
                expected: "B",
                found: "D"
            })
        ));

        // A P-256 key parses but can never form a prefix in the pinned reference.
        let p256 = with_field(
            &transferable,
            "k",
            &SadValue::Array(vec![SadValue::text("1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ")]),
        )?;
        assert!(matches!(
            IdentifierPrefix::derive(&p256, PrefixDerivation::Ed25519),
            Err(PrefixError::KeyCodeMismatch { found: "1AAJ", .. })
        ));
        Ok(())
    }

    #[test]
    fn unusable_key_fields_are_typed_errors() -> Result<(), Box<dyn Error>> {
        let inception = pinned_inception(PINNED_KEY)?;

        let mut without_keys = Sad::new();
        for (label, value) in inception.entries() {
            if label != "k" {
                without_keys.insert(label.to_owned(), value.clone())?;
            }
        }
        assert!(matches!(
            IdentifierPrefix::derive(&without_keys, PrefixDerivation::Ed25519),
            Err(PrefixError::MissingKeysField)
        ));

        let text_keys = with_field(&inception, "k", &SadValue::text(PINNED_KEY))?;
        assert!(matches!(
            IdentifierPrefix::derive(&text_keys, PrefixDerivation::Ed25519),
            Err(PrefixError::InvalidKeysField)
        ));

        let nested_key = with_field(&inception, "k", &SadValue::Array(vec![SadValue::Null]))?;
        assert!(matches!(
            IdentifierPrefix::derive(&nested_key, PrefixDerivation::Ed25519),
            Err(PrefixError::InvalidKeysField)
        ));

        for count in [0_usize, 2, 3] {
            let keys = with_field(
                &inception,
                "k",
                &SadValue::Array(core::iter::repeat_n(SadValue::text(PINNED_KEY), count).collect()),
            )?;
            assert!(matches!(
                IdentifierPrefix::derive(&keys, PrefixDerivation::Ed25519),
                Err(PrefixError::KeyCount { count: found }) if found == count
            ));
        }

        let malformed = with_field(&inception, "k", &SadValue::Array(vec![SadValue::text("not-a-key")]))?;
        assert!(matches!(
            IdentifierPrefix::derive(&malformed, PrefixDerivation::Ed25519),
            Err(PrefixError::Crypto { .. })
        ));
        Ok(())
    }

    #[test]
    fn only_incepting_event_kinds_derive_self_addressing_prefixes() -> Result<(), Box<dyn Error>> {
        let inception = pinned_inception(PINNED_KEY)?;
        for kind in ["icp", "dip", "vcp"] {
            let event = with_field(&inception, "t", &SadValue::text(kind))?;
            IdentifierPrefix::derive(&event, PrefixDerivation::Blake3_256)?;
        }
        for kind in ["rot", "ixn", "drt", "rpy", "exn", "iss", "bis"] {
            let event = with_field(&inception, "t", &SadValue::text(kind))?;
            assert!(
                matches!(
                    IdentifierPrefix::derive(&event, PrefixDerivation::Blake3_256),
                    Err(PrefixError::NonInceptingEventKind { .. })
                ),
                "event kind {kind} was accepted"
            );
        }

        let unknown = with_field(&inception, "t", &SadValue::text("zzz"))?;
        assert!(matches!(
            IdentifierPrefix::derive(&unknown, PrefixDerivation::Blake3_256),
            Err(PrefixError::EventKind { .. })
        ));

        let mut without_kind = Sad::new();
        for (label, value) in inception.entries() {
            if label != "t" {
                without_kind.insert(label.to_owned(), value.clone())?;
            }
        }
        assert!(matches!(
            IdentifierPrefix::derive(&without_kind, PrefixDerivation::Blake3_256),
            Err(PrefixError::MissingEventKind)
        ));

        // A basic derivation never inspects the event kind, matching the reference.
        IdentifierPrefix::derive(&without_kind, PrefixDerivation::Ed25519)?;
        Ok(())
    }

    #[test]
    fn self_addressing_derivation_needs_a_sizable_message() -> Result<(), Box<dyn Error>> {
        let inception = pinned_inception(PINNED_KEY)?;
        let mut without_version = Sad::new();
        for (label, value) in inception.entries() {
            if label != "v" {
                without_version.insert(label.to_owned(), value.clone())?;
            }
        }
        assert!(matches!(
            IdentifierPrefix::derive(&without_version, PrefixDerivation::Blake3_256),
            Err(PrefixError::Serialization { .. })
        ));
        // The basic derivations do not serialize, so they still work.
        IdentifierPrefix::derive(&without_version, PrefixDerivation::Ed25519)?;
        Ok(())
    }

    #[test]
    fn verification_is_strict_about_the_claimed_prefix() -> Result<(), Box<dyn Error>> {
        let inception = pinned_inception(PINNED_KEY)?;
        let prefix = IdentifierPrefix::derive(&inception, PrefixDerivation::Blake3_256)?;

        // The event does not yet claim the prefix, so only the derivation can be checked.
        prefix.verify(&inception, PrefixVerification::DerivationOnly)?;
        assert!(matches!(
            prefix.verify(&inception, PrefixVerification::Strict),
            Err(PrefixError::IdentifierFieldMismatch)
        ));

        // Once the event claims it, strict verification succeeds. Substituting the prefix for the
        // placeholder cannot change any byte count, so the digest is unchanged.
        let completed = with_field(&inception, "i", &SadValue::text(prefix.qb64()?))?;
        prefix.verify(&completed, PrefixVerification::Strict)?;
        assert_eq!(PrefixVerification::default(), PrefixVerification::Strict);

        // Tampering with any committed field breaks the derivation.
        let tampered = with_field(&completed, "s", &SadValue::text("1"))?;
        assert!(matches!(
            tampered
                .get_text("i")
                .map(str::to_owned)
                .and_then(|_| prefix.verify(&tampered, PrefixVerification::Strict).err()),
            Some(PrefixError::PrefixMismatch)
        ));

        // A basic prefix verifies against the key the event lists, and nothing else.
        let basic = IdentifierPrefix::derive(&inception, PrefixDerivation::Ed25519)?;
        basic.verify(&inception, PrefixVerification::DerivationOnly)?;
        let other_key = with_field(
            &inception,
            "k",
            &SadValue::Array(vec![SadValue::text("DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e")]),
        )?;
        assert!(matches!(
            basic.verify(&other_key, PrefixVerification::DerivationOnly),
            Err(PrefixError::PrefixMismatch)
        ));
        Ok(())
    }

    #[test]
    fn verification_reports_an_absent_identifier_field() -> Result<(), Box<dyn Error>> {
        let inception = pinned_inception(PINNED_KEY)?;
        let basic = IdentifierPrefix::derive(&inception, PrefixDerivation::Ed25519)?;
        let mut without_identifier = Sad::new();
        for (label, value) in inception.entries() {
            if label != "i" {
                without_identifier.insert(label.to_owned(), value.clone())?;
            }
        }
        assert!(matches!(
            basic.verify(&without_identifier, PrefixVerification::Strict),
            Err(PrefixError::MissingIdentifierField)
        ));
        basic.verify(&without_identifier, PrefixVerification::DerivationOnly)?;
        Ok(())
    }

    #[test]
    fn verification_does_not_disturb_the_caller_s_event() -> Result<(), Box<dyn Error>> {
        // The reference's self-addressing verification mutates the event it is handed, leaving the
        // identifier and SAID fields full of placeholder characters.
        let inception = pinned_inception(PINNED_KEY)?;
        let prefix = IdentifierPrefix::derive(&inception, PrefixDerivation::Blake3_256)?;
        let before = inception.clone();
        prefix.verify(&inception, PrefixVerification::DerivationOnly)?;
        assert_eq!(inception, before);
        assert_eq!(inception.get_text("i"), Some(""));
        assert!(!inception.contains("d"));
        Ok(())
    }

    #[test]
    fn material_conversions_round_trip() -> Result<(), Box<dyn Error>> {
        for text in [PINNED_PREFIX, PINNED_KEY, PINNED_KEY_NONTRANSFERABLE] {
            let prefix = IdentifierPrefix::from_qb64(text)?;
            assert_eq!(prefix.qb64()?, text);
            assert_eq!(text.parse::<IdentifierPrefix>()?, prefix);
            assert_eq!(IdentifierPrefix::try_from(text)?, prefix);
            assert_eq!(prefix.to_string(), text);
            assert_eq!(PrefixDerivation::from_code(prefix.code())?, prefix.derivation());
        }

        let said = Said::from_qb64(PINNED_PREFIX)?;
        assert_eq!(
            IdentifierPrefix::from(said),
            IdentifierPrefix::from_qb64(PINNED_PREFIX)?
        );

        let key = VerificationKey::from_qb64(PINNED_KEY)?;
        let basic = BasicPrefix::new(key.clone())?;
        assert_eq!(basic.key(), &key);
        assert_eq!(basic.transferability(), KeyTransferability::Transferable);
        assert_eq!(IdentifierPrefix::from(basic.clone()), IdentifierPrefix::Basic(basic));
        assert_eq!(BasicPrefix::try_from(key)?.key().qb64()?, PINNED_KEY);
        Ok(())
    }

    #[test]
    fn non_prefix_material_is_rejected() {
        // A digest code that is not BLAKE3-256, a seed, a signature, and a P-256 key are all valid
        // CESR material and none of them can be an identifier.
        for text in [
            "HLEjyRTtmfyp4VpTBTkv_b6KONMS1V8-EW-aGJ5P_QMo",
            "AKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx",
            "1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ",
        ] {
            assert!(
                matches!(
                    IdentifierPrefix::from_qb64(text),
                    Err(PrefixError::UnsupportedCode { .. })
                ),
                "{text} was accepted as a prefix"
            );
        }

        assert!(IdentifierPrefix::from_qb64("").is_err());
        assert!(IdentifierPrefix::from_qb64("E").is_err());
        assert!(IdentifierPrefix::from_qb64("*").is_err());
        // Trailing material is not silently ignored.
        assert!(IdentifierPrefix::from_qb64(&format!("{PINNED_PREFIX}extra")).is_err());
    }

    #[test]
    fn a_basic_prefix_cannot_wrap_a_digest_code() -> Result<(), Box<dyn Error>> {
        // `BasicPrefix` only ever holds a verification key, so the digestive rejection is
        // unreachable through `new`; the derivation table is the guard that keeps it that way.
        assert!(matches!(
            PrefixDerivation::from_code(DerivationCode::SHA3_256),
            Err(PrefixError::UnsupportedCode { code: "H" })
        ));
        assert!(PrefixDerivation::from_code(DerivationCode::BLAKE3_256)?.is_digestive());
        Ok(())
    }

    #[test]
    fn the_derivation_table_is_consistent() -> Result<(), Box<dyn Error>> {
        for (index, derivation) in PrefixDerivation::ALL.into_iter().enumerate() {
            assert_eq!(PrefixDerivation::from_code(derivation.code())?, derivation);
            assert_eq!(derivation.code().size().full_size(), Some(PLACEHOLDER_WIDTH));
            for other in PrefixDerivation::ALL.into_iter().skip(index + 1) {
                assert_ne!(derivation.code(), other.code());
            }
        }
        assert!(!PrefixDerivation::Ed25519NonTransferable.is_transferable());
        assert!(PrefixDerivation::Ed25519.is_transferable());
        assert!(PrefixDerivation::Blake3_256.is_transferable());
        assert!(!PrefixDerivation::Ed25519.is_digestive());
        // The placeholder must be exactly as wide as the prefix that replaces it.
        assert_eq!(PLACEHOLDER_WIDTH, PINNED_PREFIX.len());
        Ok(())
    }

    #[test]
    fn empty_field_detection_matches_the_reference_length_test() -> Result<(), Box<dyn Error>> {
        let mut sad = Sad::new();
        sad.insert("empty_text", SadValue::text(""))?;
        sad.insert("empty_list", SadValue::Array(Vec::new()))?;
        sad.insert("text", SadValue::text("x"))?;
        sad.insert("list", SadValue::Array(vec![SadValue::Null]))?;
        sad.insert("block", SadValue::Map(Sad::new()))?;
        sad.insert("null", SadValue::Null)?;

        assert!(is_empty_field(&sad, "absent"));
        assert!(is_empty_field(&sad, "empty_text"));
        assert!(is_empty_field(&sad, "empty_list"));
        assert!(!is_empty_field(&sad, "text"));
        assert!(!is_empty_field(&sad, "list"));
        // The reference reads `undefined > 0` for these and treats them as empty; Rust does not
        // ignore content it cannot interpret.
        assert!(!is_empty_field(&sad, "block"));
        assert!(!is_empty_field(&sad, "null"));
        Ok(())
    }

    #[test]
    fn errors_carry_sources_and_readable_text() -> Result<(), Box<dyn Error>> {
        let inception = pinned_inception(PINNED_KEY)?;
        let broken = with_field(&inception, "v", &SadValue::text("KERI10CBOR000000_"))?;
        let error = IdentifierPrefix::derive(&broken, PrefixDerivation::Blake3_256)
            .err()
            .ok_or("expected a serialization failure")?;
        assert!(matches!(error, PrefixError::Serialization { .. }));
        assert!(error.source().is_some());
        assert!(!error.to_string().is_empty());

        for error in [
            PrefixError::UnsupportedCode { code: "H" },
            PrefixError::MissingKeysField,
            PrefixError::InvalidKeysField,
            PrefixError::KeyCount { count: 2 },
            PrefixError::KeyCodeMismatch {
                expected: "D",
                found: "B",
            },
            PrefixError::NonTransferableFieldNotEmpty { label: "n" },
            PrefixError::MissingEventKind,
            PrefixError::NonInceptingEventKind {
                found: EventKind::Rotation,
            },
            PrefixError::PrefixMismatch,
            PrefixError::MissingIdentifierField,
            PrefixError::IdentifierFieldMismatch,
        ] {
            assert!(!error.to_string().is_empty());
            assert!(error.source().is_none());
        }
        Ok(())
    }
}
