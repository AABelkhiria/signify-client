//! KERI, TEL, and ACDC message records as KERIA embeds them in API documents.
//!
//! These are *decoded documents*, not protocol artifacts. `signify-keri` owns building a KERI
//! event, sizing its version string, and deriving its SAID; this module owns the shape KERIA
//! returns when it hands one back inside a JSON response. A record therefore carries no bytes and
//! derives nothing — see the byte-order rule in [`crate::api`].
//!
//! # Message type and the `t` field
//!
//! The upstream schema types every message's `t` as a bare `string`, so nothing stops a document
//! labelled `ICP_V_1` from carrying `"t": "rot"`. Here the Rust type *is* the ilk: each record
//! carries a marker whose only value is that record's own ilk, so the mismatch cannot be built and
//! cannot be decoded. [`KeyEvent`] chooses its variant from the same field.
//!
//! # Protocol versions
//!
//! The schema splits each message into a `_V_1` and a `_V_2` shape. Every pair is either identical
//! or differs only by additional optional fields, so one Rust record covers both: a KERI 2 document
//! decodes and re-encodes without losing the fields KERI 1 does not have. The `PORTING.md` §5.12
//! ledger records the pairing. Nothing here interprets a version string; that is
//! `signify-keri::serialization`.

use core::fmt;

use serde::de::{self, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// Declares a message-kind marker whose only legal value is one ilk.
///
/// The marker occupies the `t` field, so a record's ilk is fixed by its Rust type. The generated
/// type is a unit struct: a caller writes `kind: InceptionIlk` and cannot write anything else.
macro_rules! ilk_marker {
    ($name:ident, $text:literal, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Occupies the `t` field. Decoding refuses any other value.
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name;

        impl $name {
            /// The exact ilk text carried on the wire.
            pub const TEXT: &'static str = $text;
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($text)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str($text)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct IlkVisitor;

                impl Visitor<'_> for IlkVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(formatter, "the ilk {:?}", $text)
                    }

                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                        if value == $text {
                            Ok($name)
                        } else {
                            Err(E::invalid_value(Unexpected::Str(value), &self))
                        }
                    }
                }

                deserializer.deserialize_str(IlkVisitor)
            }
        }
    };
}

ilk_marker!(InceptionIlk, "icp", "Inception, ilk `icp`.");
ilk_marker!(DelegatedInceptionIlk, "dip", "Delegated inception, ilk `dip`.");
ilk_marker!(RotationIlk, "rot", "Rotation, ilk `rot`.");
ilk_marker!(DelegatedRotationIlk, "drt", "Delegated rotation, ilk `drt`.");
ilk_marker!(InteractionIlk, "ixn", "Interaction, ilk `ixn`.");
ilk_marker!(ReplyIlk, "rpy", "Reply, ilk `rpy`.");
ilk_marker!(ExchangeIlk, "exn", "Exchange, ilk `exn`.");
ilk_marker!(RegistryInceptionIlk, "vcp", "TEL registry inception, ilk `vcp`.");
ilk_marker!(RevocationIlk, "rev", "TEL credential revocation, ilk `rev`.");

/// A signing, rotation, or witness threshold as a KERI message spells it.
///
/// The schema writes a threshold three ways: a single value such as `"1"` or `"1/2"`, one clause of
/// weights, or several clauses. A key state declares only the first two forms and a key event all
/// three; this one type covers both positions, which is a deliberate widening of the key-state
/// field recorded in `PORTING.md` §9. Weights stay as written — reducing a rational and deciding
/// whether a threshold is satisfied is `signify-keri::threshold`, which owns exact arithmetic.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Threshold {
    /// One value, such as `"1"` or `"1/2"`.
    Simple(String),
    /// One clause of weights, such as `["1/2", "1/2", "1/2"]`.
    Clause(Vec<String>),
    /// Several weighted clauses, all of which must be satisfied.
    Clauses(Vec<Vec<String>>),
}

/// A seal anchored in a key event, naming an event in another log.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Seal {
    /// Sequence number of the sealed event, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Digest of the sealed event, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Identifier prefix of the sealed log, wire label `i`.
    #[serde(rename = "i", default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
}

/// The event a long-running KERIA operation is waiting to see anchored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Anchor {
    /// Identifier prefix of the anchoring log, wire label `pre`.
    pub pre: String,
    /// Sequence number of the anchoring event, wire label `sn`.
    pub sn: u64,
    /// Digest of the anchoring event, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
}

/// A JSON Schema document describing a credential type.
///
/// `properties` stays untyped because JSON Schema is itself an open vocabulary; validating a
/// credential against it is out of this crate's scope.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Schema {
    /// Schema identifier, wire label `$id`.
    #[serde(rename = "$id")]
    pub id: String,
    /// Meta-schema this document conforms to, wire label `$schema`.
    #[serde(rename = "$schema")]
    pub meta_schema: String,
    /// Human-readable title.
    pub title: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema type, normally `object`.
    #[serde(rename = "type")]
    pub schema_type: String,
    /// Credential type this schema defines.
    #[serde(rename = "credentialType")]
    pub credential_type: String,
    /// Schema version.
    pub version: String,
    /// Declared properties, left as JSON Schema.
    pub properties: Map<String, Value>,
    /// Whether the schema admits properties it does not declare.
    #[serde(rename = "additionalProperties")]
    pub additional_properties: bool,
    /// Property names the schema requires.
    pub required: Vec<String>,
}

/// The attribute block of an ACDC credential.
///
/// The schema declares three optional fields and an open index signature, so every other attribute
/// is captured in [`AcdcAttributes::additional`] and survives a round trip.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct AcdcAttributes {
    /// Issuance timestamp, wire label `dt`.
    #[serde(rename = "dt", default, skip_serializing_if = "Option::is_none")]
    pub stamp: Option<String>,
    /// Issuee identifier prefix, wire label `i`.
    #[serde(rename = "i", default, skip_serializing_if = "Option::is_none")]
    pub issuee: Option<String>,
    /// Salty nonce, wire label `u`.
    #[serde(rename = "u", default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Every attribute the schema does not name, preserved as received.
    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

/// An ACDC credential document.
///
/// The schema declares `a` and `A` as alternatives — an attribute block or an aggregate — and both
/// are optional in each arm, so both appear here. `ri` and `rd` are the KERI 1 and KERI 2 spellings
/// of the registry field.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AcdcRecord {
    /// Version string, wire label `v`.
    #[serde(rename = "v")]
    pub version: String,
    /// Credential SAID, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Salty nonce, wire label `u`.
    #[serde(rename = "u", default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Issuer identifier prefix, wire label `i`.
    #[serde(rename = "i")]
    pub issuer: String,
    /// Registry identifier, wire label `ri`.
    #[serde(rename = "ri", default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// Registry digest, wire label `rd`; the KERI 2 spelling of the field above.
    #[serde(rename = "rd", default, skip_serializing_if = "Option::is_none")]
    pub registry_digest: Option<String>,
    /// Schema SAID, wire label `s`.
    #[serde(rename = "s")]
    pub schema: String,
    /// Attribute block, wire label `a`.
    #[serde(rename = "a", default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<AcdcAttributes>,
    /// Attribute aggregate, wire label `A`; the alternative to the block above.
    #[serde(rename = "A", default, skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<Value>,
    /// Edge block linking to other credentials, wire label `e`.
    #[serde(rename = "e", default, skip_serializing_if = "Option::is_none")]
    pub edges: Option<Map<String, Value>>,
    /// Rule block, wire label `r`.
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Map<String, Value>>,
}

/// An inception event as KERIA returns it, ilk `icp`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct InceptionRecord {
    /// Version string, wire label `v`.
    #[serde(rename = "v")]
    pub version: String,
    /// Event kind, wire label `t`.
    #[serde(rename = "t")]
    pub kind: InceptionIlk,
    /// Event SAID, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Identifier prefix, wire label `i`.
    #[serde(rename = "i")]
    pub identifier: String,
    /// Sequence number, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Current signing threshold, wire label `kt`.
    #[serde(rename = "kt")]
    pub signing_threshold: Threshold,
    /// Current signing keys, wire label `k`.
    #[serde(rename = "k")]
    pub signing_keys: Vec<String>,
    /// Next signing threshold, wire label `nt`.
    #[serde(rename = "nt")]
    pub next_threshold: Threshold,
    /// Digests committing to the next signing keys, wire label `n`.
    #[serde(rename = "n")]
    pub next_key_digests: Vec<String>,
    /// Witness threshold, wire label `bt`.
    #[serde(rename = "bt")]
    pub witness_threshold: String,
    /// Witness identifier prefixes, wire label `b`.
    #[serde(rename = "b")]
    pub witnesses: Vec<String>,
    /// Configuration traits, wire label `c`.
    #[serde(rename = "c")]
    pub configuration: Vec<String>,
    /// Anchored seals, wire label `a`; the schema types this `unknown`.
    #[serde(rename = "a")]
    pub anchors: Value,
}

/// A delegated inception event as KERIA returns it, ilk `dip`.
///
/// Identical to [`InceptionRecord`] apart from the trailing delegator field.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DelegatedInceptionRecord {
    /// Version string, wire label `v`.
    #[serde(rename = "v")]
    pub version: String,
    /// Event kind, wire label `t`.
    #[serde(rename = "t")]
    pub kind: DelegatedInceptionIlk,
    /// Event SAID, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Identifier prefix, wire label `i`.
    #[serde(rename = "i")]
    pub identifier: String,
    /// Sequence number, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Current signing threshold, wire label `kt`.
    #[serde(rename = "kt")]
    pub signing_threshold: Threshold,
    /// Current signing keys, wire label `k`.
    #[serde(rename = "k")]
    pub signing_keys: Vec<String>,
    /// Next signing threshold, wire label `nt`.
    #[serde(rename = "nt")]
    pub next_threshold: Threshold,
    /// Digests committing to the next signing keys, wire label `n`.
    #[serde(rename = "n")]
    pub next_key_digests: Vec<String>,
    /// Witness threshold, wire label `bt`.
    #[serde(rename = "bt")]
    pub witness_threshold: String,
    /// Witness identifier prefixes, wire label `b`.
    #[serde(rename = "b")]
    pub witnesses: Vec<String>,
    /// Configuration traits, wire label `c`.
    #[serde(rename = "c")]
    pub configuration: Vec<String>,
    /// Anchored seals, wire label `a`; the schema types this `unknown`.
    #[serde(rename = "a")]
    pub anchors: Value,
    /// Delegator identifier prefix, wire label `di`.
    #[serde(rename = "di")]
    pub delegator: String,
}

/// A rotation event as KERIA returns it, ilk `rot`.
///
/// The `c` field exists only in the KERI 2 shape, so it is optional here and omitted when absent.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RotationRecord<K = RotationIlk> {
    /// Version string, wire label `v`.
    #[serde(rename = "v")]
    pub version: String,
    /// Event kind, wire label `t`.
    #[serde(rename = "t")]
    pub kind: K,
    /// Event SAID, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Identifier prefix, wire label `i`.
    #[serde(rename = "i")]
    pub identifier: String,
    /// Sequence number, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Prior event digest, wire label `p`.
    #[serde(rename = "p")]
    pub prior: String,
    /// Current signing threshold, wire label `kt`.
    #[serde(rename = "kt")]
    pub signing_threshold: Threshold,
    /// Current signing keys, wire label `k`.
    #[serde(rename = "k")]
    pub signing_keys: Vec<String>,
    /// Next signing threshold, wire label `nt`.
    #[serde(rename = "nt")]
    pub next_threshold: Threshold,
    /// Digests committing to the next signing keys, wire label `n`.
    #[serde(rename = "n")]
    pub next_key_digests: Vec<String>,
    /// Witness threshold, wire label `bt`.
    #[serde(rename = "bt")]
    pub witness_threshold: String,
    /// Witness prefixes cut by this rotation, wire label `br`.
    #[serde(rename = "br")]
    pub witnesses_removed: Vec<String>,
    /// Witness prefixes added by this rotation, wire label `ba`.
    #[serde(rename = "ba")]
    pub witnesses_added: Vec<String>,
    /// Configuration traits, wire label `c`; present only in the KERI 2 shape.
    #[serde(rename = "c", default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<Vec<String>>,
    /// Anchored seals, wire label `a`; the schema types this `unknown`.
    #[serde(rename = "a")]
    pub anchors: Value,
}

/// An interaction event as KERIA returns it, ilk `ixn`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct InteractionRecord {
    /// Version string, wire label `v`.
    #[serde(rename = "v")]
    pub version: String,
    /// Event kind, wire label `t`.
    #[serde(rename = "t")]
    pub kind: InteractionIlk,
    /// Event SAID, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Identifier prefix, wire label `i`.
    #[serde(rename = "i")]
    pub identifier: String,
    /// Sequence number, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Prior event digest, wire label `p`.
    #[serde(rename = "p")]
    pub prior: String,
    /// Anchored seals, wire label `a`; the schema types this `unknown`.
    #[serde(rename = "a")]
    pub anchors: Value,
}

/// A reply message as KERIA returns it, ilk `rpy`.
///
/// The identifier field exists only in the KERI 2 shape.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReplyRecord {
    /// Version string, wire label `v`.
    #[serde(rename = "v")]
    pub version: String,
    /// Message kind, wire label `t`.
    #[serde(rename = "t")]
    pub kind: ReplyIlk,
    /// Message SAID, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Identifier prefix, wire label `i`; present only in the KERI 2 shape.
    #[serde(rename = "i", default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// Timestamp, wire label `dt`.
    #[serde(rename = "dt")]
    pub stamp: String,
    /// Route, wire label `r`.
    #[serde(rename = "r")]
    pub route: String,
    /// Attribute block, wire label `a`; the schema types this `unknown`.
    #[serde(rename = "a")]
    pub attributes: Value,
}

/// An exchange message as KERIA returns it, ilk `exn`.
///
/// `rp` and `e` belong to the KERI 1 shape and `x` to the KERI 2 shape.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExchangeRecord {
    /// Version string, wire label `v`.
    #[serde(rename = "v")]
    pub version: String,
    /// Message kind, wire label `t`.
    #[serde(rename = "t")]
    pub kind: ExchangeIlk,
    /// Message SAID, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Sender identifier prefix, wire label `i`.
    #[serde(rename = "i")]
    pub sender: String,
    /// Recipient identifier prefix, wire label `rp`; the KERI 1 shape.
    #[serde(rename = "rp", default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// Transaction state SAID, wire label `x`; the KERI 2 shape.
    #[serde(rename = "x", default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
    /// Prior message SAID, wire label `p`.
    #[serde(rename = "p")]
    pub prior: String,
    /// Timestamp, wire label `dt`.
    #[serde(rename = "dt")]
    pub stamp: String,
    /// Route, wire label `r`.
    #[serde(rename = "r")]
    pub route: String,
    /// Modifiers, wire label `q`.
    #[serde(rename = "q")]
    pub modifiers: Map<String, Value>,
    /// Attribute block, wire label `a`; the schema types this `unknown`.
    #[serde(rename = "a")]
    pub attributes: Value,
    /// Embedded messages, wire label `e`; the KERI 1 shape.
    #[serde(rename = "e", default, skip_serializing_if = "Option::is_none")]
    pub embeds: Option<Map<String, Value>>,
}

/// A TEL registry inception event as KERIA returns it, ilk `vcp`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RegistryInceptionRecord {
    /// Version string, wire label `v`.
    #[serde(rename = "v")]
    pub version: String,
    /// Event kind, wire label `t`.
    #[serde(rename = "t")]
    pub kind: RegistryInceptionIlk,
    /// Event SAID, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Registry identifier, wire label `i`.
    #[serde(rename = "i")]
    pub registry: String,
    /// Issuer identifier prefix, wire label `ii`.
    #[serde(rename = "ii")]
    pub issuer: String,
    /// Sequence number, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Configuration traits, wire label `c`.
    #[serde(rename = "c")]
    pub configuration: Vec<String>,
    /// Backer threshold, wire label `bt`.
    #[serde(rename = "bt")]
    pub backer_threshold: String,
    /// Backer identifier prefixes, wire label `b`.
    #[serde(rename = "b")]
    pub backers: Vec<String>,
    /// Registry nonce, wire label `n`.
    #[serde(rename = "n")]
    pub nonce: String,
}

/// A TEL credential revocation event as KERIA returns it, ilk `rev`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationRecord {
    /// Version string, wire label `v`.
    #[serde(rename = "v")]
    pub version: String,
    /// Event kind, wire label `t`.
    #[serde(rename = "t")]
    pub kind: RevocationIlk,
    /// Event SAID, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Credential SAID, wire label `i`.
    #[serde(rename = "i")]
    pub credential: String,
    /// Sequence number, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Registry identifier, wire label `ri`.
    #[serde(rename = "ri")]
    pub registry: String,
    /// Prior TEL event digest, wire label `p`.
    #[serde(rename = "p")]
    pub prior: String,
    /// Timestamp, wire label `dt`.
    #[serde(rename = "dt")]
    pub stamp: String,
}

/// One key event from a key event log.
///
/// The variant is chosen by the `t` field, which is the only thing distinguishing the five shapes
/// the schema's `KeyEvent` union admits. Decoding refuses any other ilk rather than guessing, so a
/// receipt or a reply arriving where a key event is expected is a typed failure.
///
/// ```
/// use signify_types::api::KeyEvent;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let body = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EABC","i":"EDEF","s":"1","p":"EGHI","a":[]}"#;
/// let event: KeyEvent = serde_json::from_slice(body)?;
/// assert!(matches!(event, KeyEvent::Interaction(_)));
/// assert_eq!(event.identifier(), "EDEF");
/// assert_eq!(event.kind(), "ixn");
///
/// // The `t` field selects the variant, so a mislabelled record cannot be built.
/// let mislabelled = br#"{"v":"KERI10JSON0000cb_","t":"rct","d":"EABC","i":"EDEF","s":"1","p":"E","a":[]}"#;
/// assert!(serde_json::from_slice::<KeyEvent>(mislabelled).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub enum KeyEvent {
    /// Inception, ilk `icp`.
    Inception(InceptionRecord),
    /// Rotation, ilk `rot`.
    Rotation(RotationRecord<RotationIlk>),
    /// Interaction, ilk `ixn`.
    Interaction(InteractionRecord),
    /// Delegated inception, ilk `dip`.
    DelegatedInception(DelegatedInceptionRecord),
    /// Delegated rotation, ilk `drt`.
    DelegatedRotation(RotationRecord<DelegatedRotationIlk>),
}

/// Every ilk [`KeyEvent`] accepts, in the schema's union order.
pub const KEY_EVENT_ILKS: &[&str] = &["ixn", "icp", "rot", "dip", "drt"];

impl KeyEvent {
    /// Returns the ilk this event carries.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Inception(_) => InceptionIlk::TEXT,
            Self::Rotation(_) => RotationIlk::TEXT,
            Self::Interaction(_) => InteractionIlk::TEXT,
            Self::DelegatedInception(_) => DelegatedInceptionIlk::TEXT,
            Self::DelegatedRotation(_) => DelegatedRotationIlk::TEXT,
        }
    }

    /// Returns the identifier prefix whose log this event belongs to.
    #[must_use]
    pub fn identifier(&self) -> &str {
        match self {
            Self::Inception(event) => &event.identifier,
            Self::Rotation(event) => &event.identifier,
            Self::Interaction(event) => &event.identifier,
            Self::DelegatedInception(event) => &event.identifier,
            Self::DelegatedRotation(event) => &event.identifier,
        }
    }

    /// Returns the event SAID.
    #[must_use]
    pub fn digest(&self) -> &str {
        match self {
            Self::Inception(event) => &event.digest,
            Self::Rotation(event) => &event.digest,
            Self::Interaction(event) => &event.digest,
            Self::DelegatedInception(event) => &event.digest,
            Self::DelegatedRotation(event) => &event.digest,
        }
    }

    /// Returns the sequence number exactly as the message spells it.
    ///
    /// KERI writes this as lowercase hexadecimal without a prefix; parsing it is
    /// `signify-cesr::number`.
    #[must_use]
    pub fn sequence_number(&self) -> &str {
        match self {
            Self::Inception(event) => &event.sequence_number,
            Self::Rotation(event) => &event.sequence_number,
            Self::Interaction(event) => &event.sequence_number,
            Self::DelegatedInception(event) => &event.sequence_number,
            Self::DelegatedRotation(event) => &event.sequence_number,
        }
    }

    /// Returns whether this event establishes or rotates signing authority.
    #[must_use]
    pub const fn is_establishment(&self) -> bool {
        !matches!(self, Self::Interaction(_))
    }
}

impl Serialize for KeyEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Inception(event) => event.serialize(serializer),
            Self::Rotation(event) => event.serialize(serializer),
            Self::Interaction(event) => event.serialize(serializer),
            Self::DelegatedInception(event) => event.serialize(serializer),
            Self::DelegatedRotation(event) => event.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for KeyEvent {
    /// Chooses the variant from the `t` field.
    ///
    /// The document is buffered once so the ilk can be read before the shape is known. That needs a
    /// self-describing format, which every KERIA response is.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let document = Value::deserialize(deserializer)?;
        let ilk = document
            .get("t")
            .and_then(Value::as_str)
            .ok_or_else(|| de::Error::missing_field("t"))?
            .to_owned();
        let event = match ilk.as_str() {
            InceptionIlk::TEXT => serde_json::from_value(document).map(Self::Inception),
            RotationIlk::TEXT => serde_json::from_value(document).map(Self::Rotation),
            InteractionIlk::TEXT => serde_json::from_value(document).map(Self::Interaction),
            DelegatedInceptionIlk::TEXT => serde_json::from_value(document).map(Self::DelegatedInception),
            DelegatedRotationIlk::TEXT => serde_json::from_value(document).map(Self::DelegatedRotation),
            other => return Err(de::Error::unknown_variant(other, KEY_EVENT_ILKS)),
        };
        event.map_err(de::Error::custom)
    }
}

/// One key event together with the CESR attachments received with it.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct KeyEventRecord {
    /// The key event itself, wire label `ked`.
    pub ked: KeyEvent,
    /// The CESR attachment stream received with it, wire label `atc`.
    pub atc: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const INTERACTION: &str = r#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EAB","i":"ECD","s":"1","p":"EEF","a":[]}"#;

    #[test]
    fn an_ilk_marker_accepts_exactly_one_value() -> Result<(), Box<dyn Error>> {
        assert_eq!(serde_json::to_string(&InteractionIlk)?, r#""ixn""#);
        assert_eq!(serde_json::from_str::<InteractionIlk>(r#""ixn""#)?, InteractionIlk);
        assert_eq!(InteractionIlk::TEXT, "ixn");
        assert_eq!(InteractionIlk.to_string(), "ixn");
        for wrong in [r#""icp""#, r#""IXN""#, r#""""#, "1", "null"] {
            assert!(
                serde_json::from_str::<InteractionIlk>(wrong).is_err(),
                "{wrong} was accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn a_key_event_round_trips_in_schema_field_order() -> Result<(), Box<dyn Error>> {
        let event: KeyEvent = serde_json::from_str(INTERACTION)?;
        assert_eq!(serde_json::to_string(&event)?, INTERACTION);
        assert_eq!(event.kind(), "ixn");
        assert_eq!(event.identifier(), "ECD");
        assert_eq!(event.digest(), "EAB");
        assert_eq!(event.sequence_number(), "1");
        assert!(!event.is_establishment());
        Ok(())
    }

    #[test]
    fn every_key_event_ilk_selects_its_own_record() -> Result<(), Box<dyn Error>> {
        let common = r#""d":"EAB","i":"ECD","s":"1","kt":"1","k":["DAA"],"nt":"1","n":["EAA"],"bt":"0","b":[],"c":[]"#;
        let icp = format!(r#"{{"v":"KERI10JSON000_","t":"icp",{common},"a":[]}}"#);
        let dip = format!(r#"{{"v":"KERI10JSON000_","t":"dip",{common},"a":[],"di":"EDD"}}"#);
        let rotation_common = r#""d":"EAB","i":"ECD","s":"1","p":"EPP","kt":"1","k":["DAA"],"nt":"1","n":["EAA"],"bt":"0","br":[],"ba":[]"#;
        let rot = format!(r#"{{"v":"KERI10JSON000_","t":"rot",{rotation_common},"a":[]}}"#);
        let drt = format!(r#"{{"v":"KERI10JSON000_","t":"drt",{rotation_common},"a":[]}}"#);

        for (document, expected) in [
            (icp.as_str(), "icp"),
            (dip.as_str(), "dip"),
            (rot.as_str(), "rot"),
            (drt.as_str(), "drt"),
            (INTERACTION, "ixn"),
        ] {
            let event: KeyEvent = serde_json::from_str(document)?;
            assert_eq!(event.kind(), expected);
            assert_eq!(serde_json::to_string(&event)?, document);
            assert_eq!(event.is_establishment(), expected != "ixn");
        }
        Ok(())
    }

    #[test]
    fn a_key_event_refuses_an_ilk_outside_the_union() {
        for ilk in ["rct", "vrc", "rpy", "exn", "vcp", "", "ICP"] {
            let document = format!(r#"{{"v":"KERI10JSON0000cb_","t":"{ilk}","d":"E","i":"E","s":"1","p":"E","a":[]}}"#);
            assert!(
                serde_json::from_str::<KeyEvent>(&document).is_err(),
                "ilk {ilk:?} was accepted"
            );
        }
        // A message with no `t` at all names no variant.
        assert!(serde_json::from_str::<KeyEvent>(r#"{"v":"KERI10JSON0000cb_"}"#).is_err());
        // The right ilk with the wrong body is still refused.
        assert!(serde_json::from_str::<KeyEvent>(r#"{"t":"ixn"}"#).is_err());
    }

    #[test]
    fn the_rotation_shape_carries_the_optional_keri_two_field() -> Result<(), Box<dyn Error>> {
        let with_configuration = r#"{"v":"KERI20JSON000_","t":"rot","d":"EAB","i":"ECD","s":"1","p":"EPP","kt":"1","k":["DAA"],"nt":"1","n":["EAA"],"bt":"0","br":[],"ba":[],"c":["EO"],"a":[]}"#;
        let event: KeyEvent = serde_json::from_str(with_configuration)?;
        let KeyEvent::Rotation(rotation) = &event else {
            return Err("a rot document decoded as something else".into());
        };
        assert_eq!(rotation.configuration.as_deref(), Some(["EO".to_owned()].as_slice()));
        // The field keeps its schema position and disappears when the KERI 1 shape omits it.
        assert_eq!(serde_json::to_string(&event)?, with_configuration);
        Ok(())
    }

    #[test]
    fn unknown_fields_are_ignored_but_open_blocks_are_kept() -> Result<(), Box<dyn Error>> {
        let extended = r#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EAB","i":"ECD","s":"1","p":"EEF","a":[],"zz":1}"#;
        let event: KeyEvent = serde_json::from_str(extended)?;
        // A newer agent adding a field does not break decoding, and the field is not echoed back.
        assert_eq!(serde_json::to_string(&event)?, INTERACTION);

        let attributes: AcdcAttributes = serde_json::from_str(r#"{"d":"EAB","i":"ECD","LEI":"254900OP"}"#)?;
        assert_eq!(attributes.issuee.as_deref(), Some("ECD"));
        assert_eq!(
            attributes.additional.get("LEI").and_then(Value::as_str),
            Some("254900OP")
        );
        // An index signature means the extra fields survive the round trip.
        assert!(serde_json::to_string(&attributes)?.contains(r#""LEI":"254900OP""#));
        assert_eq!(AcdcAttributes::default().additional.len(), 0);
        Ok(())
    }

    #[test]
    fn a_threshold_keeps_the_shape_it_arrived_in() -> Result<(), Box<dyn Error>> {
        for (document, expected) in [
            (r#""1""#, Threshold::Simple("1".to_owned())),
            (r#"["1/2","1/2"]"#, Threshold::Clause(vec!["1/2".into(), "1/2".into()])),
            (
                r#"[["1/2","1/2"],["1"]]"#,
                Threshold::Clauses(vec![vec!["1/2".into(), "1/2".into()], vec!["1".into()]]),
            ),
        ] {
            let threshold: Threshold = serde_json::from_str(document)?;
            assert_eq!(threshold, expected);
            assert_eq!(serde_json::to_string(&threshold)?, document);
        }
        assert!(serde_json::from_str::<Threshold>("1").is_err());
        assert!(serde_json::from_str::<Threshold>("[1]").is_err());
        Ok(())
    }

    #[test]
    fn a_seal_omits_the_identifier_it_did_not_carry() -> Result<(), Box<dyn Error>> {
        let seal: Seal = serde_json::from_str(r#"{"s":"0","d":"EAB"}"#)?;
        assert_eq!(seal.identifier, None);
        assert_eq!(serde_json::to_string(&seal)?, r#"{"s":"0","d":"EAB"}"#);

        let full: Seal = serde_json::from_str(r#"{"s":"0","d":"EAB","i":"ECD"}"#)?;
        assert_eq!(full.identifier.as_deref(), Some("ECD"));
        assert_eq!(serde_json::to_string(&full)?, r#"{"s":"0","d":"EAB","i":"ECD"}"#);
        Ok(())
    }

    #[test]
    fn an_anchor_requires_an_integral_sequence_number() -> Result<(), Box<dyn Error>> {
        let anchor: Anchor = serde_json::from_str(r#"{"pre":"ECD","sn":3,"d":"EAB"}"#)?;
        assert_eq!(anchor.sn, 3);
        assert_eq!(serde_json::to_string(&anchor)?, r#"{"pre":"ECD","sn":3,"d":"EAB"}"#);
        for wrong in [r#"{"pre":"E","sn":-1,"d":"E"}"#, r#"{"pre":"E","sn":1.5,"d":"E"}"#] {
            assert!(serde_json::from_str::<Anchor>(wrong).is_err(), "{wrong} was accepted");
        }
        Ok(())
    }

    #[test]
    fn a_credential_keeps_both_registry_spellings_apart() -> Result<(), Box<dyn Error>> {
        let version_one = r#"{"v":"ACDC10JSON000_","d":"EAB","i":"ECD","ri":"EREG","s":"ESCH"}"#;
        let credential: AcdcRecord = serde_json::from_str(version_one)?;
        assert_eq!(credential.registry.as_deref(), Some("EREG"));
        assert_eq!(credential.registry_digest, None);
        assert_eq!(serde_json::to_string(&credential)?, version_one);

        let version_two = r#"{"v":"ACDC20JSON000_","d":"EAB","i":"ECD","rd":"EREG","s":"ESCH"}"#;
        let credential: AcdcRecord = serde_json::from_str(version_two)?;
        assert_eq!(credential.registry, None);
        assert_eq!(credential.registry_digest.as_deref(), Some("EREG"));
        assert_eq!(serde_json::to_string(&credential)?, version_two);
        Ok(())
    }

    #[test]
    fn the_remaining_message_records_round_trip() -> Result<(), Box<dyn Error>> {
        let reply = r#"{"v":"KERI10JSON000_","t":"rpy","d":"EAB","dt":"2023-08-19T21:04:57.948863+00:00","r":"/end/role/add","a":{}}"#;
        let decoded: ReplyRecord = serde_json::from_str(reply)?;
        assert_eq!(decoded.identifier, None);
        assert_eq!(decoded.route, "/end/role/add");
        assert_eq!(serde_json::to_string(&decoded)?, reply);

        let exchange = r#"{"v":"KERI10JSON000_","t":"exn","d":"EAB","i":"ECD","rp":"ERP","p":"","dt":"2023-08-19T21:04:57.948863+00:00","r":"/ipex/grant","q":{},"a":{},"e":{}}"#;
        let decoded: ExchangeRecord = serde_json::from_str(exchange)?;
        assert_eq!(decoded.recipient.as_deref(), Some("ERP"));
        assert_eq!(decoded.transaction, None);
        assert_eq!(serde_json::to_string(&decoded)?, exchange);

        let registry = r#"{"v":"KERI10JSON000_","t":"vcp","d":"EAB","i":"EREG","ii":"ECD","s":"0","c":["NB"],"bt":"0","b":[],"n":"AKl"}"#;
        let decoded: RegistryInceptionRecord = serde_json::from_str(registry)?;
        assert_eq!(decoded.issuer, "ECD");
        assert_eq!(serde_json::to_string(&decoded)?, registry);

        let revocation = r#"{"v":"KERI10JSON000_","t":"rev","d":"EAB","i":"ECRED","s":"1","ri":"EREG","p":"EPP","dt":"2023-08-19T21:04:57.948863+00:00"}"#;
        let decoded: RevocationRecord = serde_json::from_str(revocation)?;
        assert_eq!(decoded.credential, "ECRED");
        assert_eq!(serde_json::to_string(&decoded)?, revocation);
        Ok(())
    }

    #[test]
    fn a_key_event_record_pairs_the_event_with_its_attachments() -> Result<(), Box<dyn Error>> {
        let document = format!(r#"{{"ked":{INTERACTION},"atc":"-AABAAA"}}"#);
        let record: KeyEventRecord = serde_json::from_str(&document)?;
        assert_eq!(record.atc, "-AABAAA");
        assert_eq!(record.ked.kind(), "ixn");
        assert_eq!(serde_json::to_string(&record)?, document);
        Ok(())
    }

    #[test]
    fn a_schema_document_round_trips() -> Result<(), Box<dyn Error>> {
        let document = r#"{"$id":"EBfd","$schema":"http://json-schema.org/draft-07/schema#","title":"Legal Entity","description":"vLEI","type":"object","credentialType":"LegalEntityvLEICredential","version":"1.0.0","properties":{},"additionalProperties":false,"required":["i"]}"#;
        let schema: Schema = serde_json::from_str(document)?;
        assert_eq!(schema.id, "EBfd");
        assert!(!schema.additional_properties);
        assert_eq!(serde_json::to_string(&schema)?, document);
        Ok(())
    }
}
