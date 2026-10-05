//! Deterministic KERI message serialization and parsing.
//!
//! This is the Rust equivalent of the pinned reference's `Serder`, `dumps`, and `sizeify`. A
//! [`SerializedEvent`] pairs an ordered [`Sad`] with the exact bytes that carry it on the wire and
//! the [`VersionString`] describing them, so callers that must hash, sign, or size a message never
//! have to re-derive its encoding.

use core::fmt;
use std::error::Error;

use keri_cesr::crypto::{CryptoError, digest::Digest, verifier::VerificationKey};
use keri_cesr::{CesrError, number::CesrNumber};

use crate::event::kind::{EventKind, EventKindError};
use crate::serialization::sad::{Sad, SadError, SadValue};
use crate::serialization::{Protocol, SerializationKind, VersionError, VersionString};

/// Field label carrying the CESR version string; must be first in every KERI message.
pub const VERSION_LABEL: &str = "v";
/// Field label carrying a message's self-addressing identifier.
pub const SAID_LABEL: &str = "d";
/// Field label carrying an identifier prefix.
pub const IDENTIFIER_LABEL: &str = "i";
/// Field label carrying a sequence number as lowercase hexadecimal text.
pub const SEQUENCE_LABEL: &str = "s";
/// Field label carrying the message type (ilk).
pub const KIND_LABEL: &str = "t";
/// Field label carrying current signing keys.
pub const KEYS_LABEL: &str = "k";
/// Field label carrying next-key digests.
pub const NEXT_KEYS_LABEL: &str = "n";

/// One KERI message together with its exact serialization.
///
/// Construction from a [`Sad`] computes the serialized size and writes it into the version string,
/// matching the reference's `sizeify`. Parsing is strict: the declared size must equal the actual
/// byte length, and the input must already be in canonical form, so bytes that were signed or
/// hashed elsewhere cannot be silently reshaped here.
///
/// ```
/// use signify_keri::serialization::{Sad, SadValue, SerializedEvent};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut sad = Sad::new();
/// sad.insert("v", SadValue::text("KERI10JSON000000_"))?;
/// sad.insert("t", SadValue::text("icp"))?;
/// let event = SerializedEvent::from_sad(sad)?;
///
/// // The version string now carries the exact byte size of the message.
/// assert_eq!(event.size(), event.raw().len());
/// assert_eq!(SerializedEvent::parse(event.raw())?, event);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SerializedEvent {
    sad: Sad,
    raw: Vec<u8>,
    version: VersionString,
}

impl SerializedEvent {
    /// Serializes self-addressing data, computing and inserting its version-string size.
    ///
    /// The version field must be present and first; the protocol places it there so a stream
    /// parser can size a message from its opening bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SerializationError::MissingVersionField`] or
    /// [`SerializationError::VersionFieldNotFirst`] for misplaced version data, a layered
    /// [`SerializationError::Version`] for an unparsable version string, and
    /// [`SerializationError::MessageTooLarge`] when the encoding exceeds the protocol ceiling.
    pub fn from_sad(mut sad: Sad) -> Result<Self, SerializationError> {
        let declared = Self::require_version_field(&sad)?;
        // The version string is fixed width, so the encoding's length does not change when its
        // size digits are rewritten. The reference relies on the same invariant, but reaches it
        // only because its own version parser happens to accept exactly this shape.
        let sized = sad.to_json_bytes()?;
        let size = u32::try_from(sized.len()).map_err(|_| SerializationError::MessageTooLarge {
            size: sized.len(),
            maximum: VersionString::MAX_SIZE as usize,
        })?;
        let version =
            VersionString::new(declared.protocol(), declared.version(), declared.kind(), size).map_err(|source| {
                SerializationError::Version {
                    source: Box::new(source),
                }
            })?;
        sad.replace_existing(VERSION_LABEL, SadValue::text(version.to_string()))?;
        let raw = sad.to_json_bytes()?;
        debug_assert_eq!(raw.len(), sized.len(), "version string width must be stable");
        Ok(Self { sad, raw, version })
    }

    /// Parses one complete, canonical KERI message.
    ///
    /// # Errors
    ///
    /// Returns a layered [`SerializationError::Sad`] for malformed JSON, the version errors listed
    /// on [`Self::from_sad`], [`SerializationError::SizeMismatch`] when the declared size does not
    /// match the input, and [`SerializationError::NonCanonicalEncoding`] when re-encoding the
    /// parsed data does not reproduce the input byte for byte.
    pub fn parse(raw: &[u8]) -> Result<Self, SerializationError> {
        let sad = Sad::from_json_bytes(raw)?;
        let version = Self::require_version_field(&sad)?;
        let declared = version.size() as usize;
        if declared != raw.len() {
            return Err(SerializationError::SizeMismatch {
                declared,
                actual: raw.len(),
            });
        }
        let canonical = sad.to_json_bytes()?;
        if canonical != raw {
            return Err(SerializationError::NonCanonicalEncoding);
        }
        Ok(Self {
            sad,
            raw: canonical,
            version,
        })
    }

    fn require_version_field(sad: &Sad) -> Result<VersionString, SerializationError> {
        let text = sad
            .get_text(VERSION_LABEL)
            .ok_or(SerializationError::MissingVersionField)?;
        match sad.first_label() {
            Some(VERSION_LABEL) => {}
            other => {
                return Err(SerializationError::VersionFieldNotFirst {
                    found: other.unwrap_or_default().to_owned(),
                });
            }
        }
        text.parse::<VersionString>()
            .map_err(|source| SerializationError::Version {
                source: Box::new(source),
            })
    }

    /// Returns the exact serialized bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Borrows the ordered self-addressing data.
    #[must_use]
    pub const fn sad(&self) -> &Sad {
        &self.sad
    }

    /// Returns the parsed version string.
    #[must_use]
    pub const fn version_string(&self) -> VersionString {
        self.version
    }

    /// Returns the message's protocol.
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.version.protocol()
    }

    /// Returns the message's serialization kind.
    #[must_use]
    pub const fn serialization_kind(&self) -> SerializationKind {
        self.version.kind()
    }

    /// Returns the serialized size in bytes, which always equals `raw().len()`.
    ///
    /// The reference's equivalent accessor reports a JavaScript string length instead, so it
    /// undercounts any message containing non-ASCII text.
    #[must_use]
    pub fn size(&self) -> usize {
        self.raw.len()
    }

    /// Returns the message's self-addressing identifier, when present.
    #[must_use]
    pub fn said(&self) -> Option<&str> {
        self.sad.get_text(SAID_LABEL)
    }

    /// Returns the message's identifier prefix, when present.
    #[must_use]
    pub fn identifier_prefix(&self) -> Option<&str> {
        self.sad.get_text(IDENTIFIER_LABEL)
    }

    /// Returns the typed message kind, when the `t` field is present.
    ///
    /// # Errors
    ///
    /// Returns [`SerializationError::EventKind`] when the field names no known ilk.
    pub fn event_kind(&self) -> Result<Option<EventKind>, SerializationError> {
        self.sad
            .get_text(KIND_LABEL)
            .map(|text| {
                text.parse::<EventKind>()
                    .map_err(|source| SerializationError::EventKind {
                        source: Box::new(source),
                    })
            })
            .transpose()
    }

    /// Returns the exact sequence number parsed from the `s` field, when present.
    ///
    /// # Errors
    ///
    /// Returns [`SerializationError::Cesr`] when the field is not canonical hexadecimal.
    pub fn sequence_number(&self) -> Result<Option<CesrNumber>, SerializationError> {
        self.sad
            .get_text(SEQUENCE_LABEL)
            .map(|text| {
                text.parse::<CesrNumber>().map_err(|source| SerializationError::Cesr {
                    source: Box::new(source),
                })
            })
            .transpose()
    }

    /// Parses the current signing keys from the `k` field.
    ///
    /// Returns an empty vector for non-establishment messages, matching the reference.
    ///
    /// # Errors
    ///
    /// Returns [`SerializationError::Crypto`] for malformed key material and
    /// [`SerializationError::UnexpectedFieldShape`] when `k` is not an array of text.
    pub fn verification_keys(&self) -> Result<Vec<VerificationKey>, SerializationError> {
        self.qualified_list(KEYS_LABEL)?
            .into_iter()
            .map(|text| {
                VerificationKey::from_qb64(text).map_err(|source| SerializationError::Crypto {
                    source: Box::new(source),
                })
            })
            .collect()
    }

    /// Parses the next-key digests from the `n` field.
    ///
    /// Returns an empty vector for non-establishment messages, matching the reference.
    ///
    /// # Errors
    ///
    /// Returns [`SerializationError::Crypto`] for malformed digest material and
    /// [`SerializationError::UnexpectedFieldShape`] when `n` is not an array of text.
    pub fn next_key_digests(&self) -> Result<Vec<Digest>, SerializationError> {
        self.qualified_list(NEXT_KEYS_LABEL)?
            .into_iter()
            .map(|text| {
                Digest::from_qb64(text).map_err(|source| SerializationError::Crypto {
                    source: Box::new(source),
                })
            })
            .collect()
    }

    fn qualified_list(&self, label: &'static str) -> Result<Vec<&str>, SerializationError> {
        let Some(value) = self.sad.get(label) else {
            return Ok(Vec::new());
        };
        let items = value
            .as_array()
            .ok_or(SerializationError::UnexpectedFieldShape { label })?;
        items
            .iter()
            .map(|item| item.as_text().ok_or(SerializationError::UnexpectedFieldShape { label }))
            .collect()
    }
}

/// Stable KERI message serialization and parsing failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum SerializationError {
    /// Self-addressing data construction or JSON coding failed.
    Sad {
        /// Underlying value/codec failure.
        source: Box<SadError>,
    },
    /// The message has no `v` field.
    MissingVersionField,
    /// The `v` field is present but is not the first field.
    VersionFieldNotFirst {
        /// Label actually found in first position.
        found: String,
    },
    /// The version string could not be parsed or rebuilt.
    Version {
        /// Underlying version-string failure.
        source: Box<VersionError>,
    },
    /// The serialized message exceeds the protocol's size ceiling.
    MessageTooLarge {
        /// Serialized size in bytes.
        size: usize,
        /// Maximum representable size in bytes.
        maximum: usize,
    },
    /// The version string's declared size does not match the actual input length.
    SizeMismatch {
        /// Size declared by the version string.
        declared: usize,
        /// Actual input length in bytes.
        actual: usize,
    },
    /// Re-encoding the parsed data did not reproduce the input byte for byte.
    NonCanonicalEncoding,
    /// A message field holds a different shape than the protocol defines.
    UnexpectedFieldShape {
        /// Field label whose shape is wrong.
        label: &'static str,
    },
    /// The `t` field names no known message kind.
    EventKind {
        /// Underlying ilk failure.
        source: Box<EventKindError>,
    },
    /// Exact CESR material inside a field could not be parsed.
    Cesr {
        /// Underlying CESR failure.
        source: Box<CesrError>,
    },
    /// Cryptographic material inside a field could not be parsed.
    Crypto {
        /// Underlying cryptographic failure.
        source: Box<CryptoError>,
    },
}

impl fmt::Display for SerializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sad { .. } => formatter.write_str("self-addressing data is invalid"),
            Self::MissingVersionField => formatter.write_str("message has no version field"),
            Self::VersionFieldNotFirst { found } => {
                write!(formatter, "version field must be first, found {found:?}")
            }
            Self::Version { .. } => formatter.write_str("message version string is invalid"),
            Self::MessageTooLarge { size, maximum } => {
                write!(formatter, "serialized message size {size} exceeds maximum {maximum}")
            }
            Self::SizeMismatch { declared, actual } => write!(
                formatter,
                "version string declares size {declared} but the message is {actual} bytes"
            ),
            Self::NonCanonicalEncoding => {
                formatter.write_str("message bytes are not the canonical encoding of their contents")
            }
            Self::UnexpectedFieldShape { label } => {
                write!(formatter, "field {label:?} has an unexpected shape")
            }
            Self::EventKind { .. } => formatter.write_str("message kind is not a known ilk"),
            Self::Cesr { .. } => formatter.write_str("message field holds invalid CESR material"),
            Self::Crypto { .. } => formatter.write_str("message field holds invalid cryptographic material"),
        }
    }
}

impl Error for SerializationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sad { source } => Some(source.as_ref()),
            Self::Version { source } => Some(source.as_ref()),
            Self::EventKind { source } => Some(source.as_ref()),
            Self::Cesr { source } => Some(source.as_ref()),
            Self::Crypto { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<SadError> for SerializationError {
    fn from(source: SadError) -> Self {
        Self::Sad {
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact inception event asserted by the pinned `test/core/serder.test.ts`.
    const REFERENCE_ICP: &str = concat!(
        r#"{"v":"KERI10JSON0000d3_","t":"icp","d":"","i":"","s":"0","kt":"1","k":"#,
        r#"["DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e"],"nt":"1","n":"#,
        r#"["EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj"],"bt":"0","b":[],"c":[],"a":[]}"#
    );

    fn reference_icp_sad(size_text: &str) -> Result<Sad, SadError> {
        let mut sad = Sad::new();
        sad.insert("v", SadValue::text(size_text))?;
        sad.insert("t", SadValue::text("icp"))?;
        sad.insert("d", SadValue::text(""))?;
        sad.insert("i", SadValue::text(""))?;
        sad.insert("s", SadValue::text("0"))?;
        sad.insert("kt", SadValue::text("1"))?;
        sad.insert(
            "k",
            SadValue::Array(vec![SadValue::text("DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e")]),
        )?;
        sad.insert("nt", SadValue::text("1"))?;
        sad.insert(
            "n",
            SadValue::Array(vec![SadValue::text("EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj")]),
        )?;
        sad.insert("bt", SadValue::text("0"))?;
        sad.insert("b", SadValue::Array(Vec::new()))?;
        sad.insert("c", SadValue::Array(Vec::new()))?;
        sad.insert("a", SadValue::Array(Vec::new()))?;
        Ok(sad)
    }

    #[test]
    fn reference_inception_event_serializes_byte_exactly() -> Result<(), Box<dyn Error>> {
        let event = SerializedEvent::from_sad(reference_icp_sad("KERI10JSON000000_")?)?;
        assert_eq!(event.raw(), REFERENCE_ICP.as_bytes());
        assert_eq!(event.size(), 0xd3);
        assert_eq!(event.version_string().size(), 0xd3);
        assert_eq!(event.protocol(), Protocol::Keri);
        assert_eq!(event.serialization_kind(), SerializationKind::Json);
        assert_eq!(event.event_kind()?, Some(EventKind::Inception));
        assert_eq!(event.said(), Some(""));
        assert_eq!(event.identifier_prefix(), Some(""));
        Ok(())
    }

    #[test]
    fn sizing_is_idempotent_regardless_of_the_incoming_size_digits() -> Result<(), Box<dyn Error>> {
        // Any well-formed version string yields the same result, because the field is fixed width.
        let from_zero = SerializedEvent::from_sad(reference_icp_sad("KERI10JSON000000_")?)?;
        let from_wrong = SerializedEvent::from_sad(reference_icp_sad("KERI10JSONffffff_")?)?;
        let from_correct = SerializedEvent::from_sad(reference_icp_sad("KERI10JSON0000d3_")?)?;
        assert_eq!(from_zero.raw(), from_wrong.raw());
        assert_eq!(from_zero.raw(), from_correct.raw());
        Ok(())
    }

    #[test]
    fn non_ascii_size_counts_utf8_bytes_not_utf16_units() -> Result<(), Box<dyn Error>> {
        let mut sad = reference_icp_sad("KERI10JSON000000_")?;
        let mut anchor = Sad::new();
        anchor.insert("n", SadValue::text("Lenksjö"))?;
        sad.replace_existing("a", SadValue::Map(anchor))?;
        let event = SerializedEvent::from_sad(sad)?;

        let raw = event.raw();
        assert_eq!(usize::try_from(event.version_string().size())?, raw.len());
        assert_eq!(event.size(), raw.len());
        // `ö` occupies two UTF-8 bytes but one UTF-16 code unit, so the reference's own `size`
        // accessor — which reports a JavaScript string length — would undercount by exactly one.
        let utf16_units = core::str::from_utf8(raw)?.chars().map(char::len_utf16).sum::<usize>();
        assert_eq!(utf16_units + 1, raw.len());
        Ok(())
    }

    #[test]
    fn parse_round_trips_and_exposes_typed_fields() -> Result<(), Box<dyn Error>> {
        let event = SerializedEvent::parse(REFERENCE_ICP.as_bytes())?;
        assert_eq!(event.raw(), REFERENCE_ICP.as_bytes());
        assert_eq!(event.event_kind()?, Some(EventKind::Inception));
        assert_eq!(event.verification_keys()?.len(), 1);
        assert_eq!(event.next_key_digests()?.len(), 1);
        assert_eq!(
            SerializedEvent::from_sad(event.sad().clone())?.raw(),
            REFERENCE_ICP.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn interaction_event_sequence_number_is_exact() -> Result<(), Box<dyn Error>> {
        let raw = concat!(
            r#"{"v":"KERI10JSON00013b_","t":"ixn","d":"EDMbT6cc2P4aPozDJhat1T_S-G98Gc7Jj8K0qxAL7EuC","#,
            r#""i":"EDKLs7y-U4N_EIv_oqJqdmWOvR5Y-nSEHJPrprT1RLFb","s":"39","#,
            r#""p":"EI696dhEGo9cDK7MpvSsPkNkVhF4pwwgof3GaRVVESXb","#,
            r#""a":[{"i":"EFMXIFSIyEL6JTCyZAbO3nHgSdOw5UbLH9fAr9zO8_LH","s":"0","#,
            r#""d":"EFMXIFSIyEL6JTCyZAbO3nHgSdOw5UbLH9fAr9zO8_LH"}]}"#
        );
        let event = SerializedEvent::parse(raw.as_bytes())?;
        assert_eq!(event.size(), 0x13b);
        assert_eq!(event.event_kind()?, Some(EventKind::Interaction));
        let sequence = event
            .sequence_number()?
            .ok_or("interaction event lacks a sequence number")?;
        assert_eq!(sequence.value(), 57);
        // Non-establishment messages have no key fields at all.
        assert!(event.verification_keys()?.is_empty());
        assert!(event.next_key_digests()?.is_empty());
        Ok(())
    }

    #[test]
    fn version_field_placement_is_enforced() -> Result<(), Box<dyn Error>> {
        let mut missing = Sad::new();
        missing.insert("t", SadValue::text("icp"))?;
        assert!(matches!(
            SerializedEvent::from_sad(missing),
            Err(SerializationError::MissingVersionField)
        ));

        let mut late = Sad::new();
        late.insert("t", SadValue::text("icp"))?;
        late.insert("v", SadValue::text("KERI10JSON000000_"))?;
        assert!(matches!(
            SerializedEvent::from_sad(late),
            Err(SerializationError::VersionFieldNotFirst { .. })
        ));

        let mut malformed = Sad::new();
        malformed.insert("v", SadValue::text("KERI10CBOR000000_"))?;
        assert!(matches!(
            SerializedEvent::from_sad(malformed),
            Err(SerializationError::Version { .. })
        ));
        Ok(())
    }

    #[test]
    fn parsing_rejects_wrong_sizes_and_non_canonical_bytes() {
        // Declared size one byte short of the real message.
        let short = r#"{"v":"KERI10JSON000022_","t":"icp"}"#;
        assert!(matches!(
            SerializedEvent::parse(short.as_bytes()),
            Err(SerializationError::SizeMismatch { .. })
        ));

        // Correct size, but padded with whitespace so the bytes are not canonical.
        let padded = "{\"v\":\"KERI10JSON000024_\", \"t\":\"icp\"}";
        assert_eq!(padded.len(), 0x24);
        assert!(matches!(
            SerializedEvent::parse(padded.as_bytes()),
            Err(SerializationError::NonCanonicalEncoding)
        ));

        assert!(matches!(
            SerializedEvent::parse(br#"{"t":"icp"}"#),
            Err(SerializationError::MissingVersionField)
        ));
        assert!(matches!(
            SerializedEvent::parse(b"not json"),
            Err(SerializationError::Sad { .. })
        ));
    }

    #[test]
    fn malformed_field_contents_are_typed_errors() -> Result<(), Box<dyn Error>> {
        let mut sad = Sad::new();
        sad.insert("v", SadValue::text("KERI10JSON000000_"))?;
        sad.insert("t", SadValue::text("nope"))?;
        sad.insert("s", SadValue::text("zz"))?;
        sad.insert("k", SadValue::text("not-an-array"))?;
        let event = SerializedEvent::from_sad(sad)?;
        assert!(matches!(event.event_kind(), Err(SerializationError::EventKind { .. })));
        assert!(matches!(event.sequence_number(), Err(SerializationError::Cesr { .. })));
        assert!(matches!(
            event.verification_keys(),
            Err(SerializationError::UnexpectedFieldShape { label: "k" })
        ));

        let mut bad_key = Sad::new();
        bad_key.insert("v", SadValue::text("KERI10JSON000000_"))?;
        bad_key.insert("k", SadValue::Array(vec![SadValue::text("not-a-key")]))?;
        let event = SerializedEvent::from_sad(bad_key)?;
        assert!(matches!(
            event.verification_keys(),
            Err(SerializationError::Crypto { .. })
        ));
        Ok(())
    }

    #[test]
    fn error_sources_are_preserved() -> Result<(), Box<dyn Error>> {
        let mut malformed = Sad::new();
        malformed.insert("v", SadValue::text("KERI10CBOR000000_"))?;
        let error = SerializedEvent::from_sad(malformed)
            .err()
            .ok_or("expected a version failure")?;
        assert!(error.source().is_some());
        assert!(!error.to_string().is_empty());
        Ok(())
    }
}
