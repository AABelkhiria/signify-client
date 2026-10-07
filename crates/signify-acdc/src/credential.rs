//! ACDC credentials: the container itself, and the two self-addressing identifiers it carries.
//!
//! An Authentic Chained Data Container is a JSON document naming its issuer, the registry whose
//! transaction event log governs its status, the schema it claims to satisfy, and a block of
//! attributes about its subject. Two of its fields are digests of the document that carries them:
//! the attribute block's `d` commits to the attributes, and the credential's own `d` commits to
//! the whole container including that first digest. Nothing else identifies a credential, so
//! deriving those two digests *is* issuing it.
//!
//! This module ports the two `Saider.saidify(...)` expressions inside `Credentials.issue` in the
//! pinned `src/keri/app/credentialing.ts`. The TEL issuance event those expressions feed, the
//! interaction event anchoring it, and the request that submits all three are Roadmap 6.2 and
//! 6.11; nothing here is aware of a registry's event log or of KERIA.
//!
//! # Field order is the credential's identity
//!
//! Both digests are taken over the exact serialization, so field order is not cosmetic. The
//! container's order is fixed — `v`, `d`, `u`, `i`, `ri`, `s`, `a`, `e`, `r`, with absent optional
//! fields simply absent — but the *attribute* block's order is the caller's, because the reference
//! spreads the caller's attributes into it. [`CredentialAttributes`] therefore preserves the order
//! its methods are called in, and [`CredentialAttributes::timestamp`] exists so a caller can place
//! `dt` where the reference's callers place it rather than at the end.
//!
//! # What this port refuses
//!
//! The reference validates none of its inputs. Four of its behaviours are recorded in
//! `fixtures/acdc-credential/` and deliberately not reproduced, because each derives an identifier
//! from something other than what the caller supplied:
//!
//! - **JavaScript hoists array-index-like keys.** An attribute named `0` is serialized ahead of
//!   every other field, including the `d` written first, and the digest commits to that order. An
//!   insertion-ordered map cannot reproduce it — ADR `0008` settled that — so such a label is
//!   rejected in every caller-supplied block rather than silently committing to different bytes.
//! - **An attribute named `v` is treated as a version string** and rewritten to the block's own
//!   length. `v` is reserved here, as is `d`, which the reference overwrites with its placeholder.
//! - **A fractional or oversized number is committed as a double.** `SadValue` accepts only exact
//!   safe integers, for the reason ADR `0008` gives.
//! - **The issuer, registry, schema, and issuee are unchecked text.** Here they are typed.
//!
//! # Example
//!
//! ```
//! use signify_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
//! use signify_keri::prefix::IdentifierPrefix;
//! use signify_keri::said::Said;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let issuer = IdentifierPrefix::from_qb64("EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1")?;
//! let holder = IdentifierPrefix::from_qb64("EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby")?;
//! let registry = RegistryIdentifier::from_qb64("EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df")?;
//! let schema = Said::from_qb64("EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao")?;
//!
//! let attributes = CredentialAttributes::new("2023-08-23T15:16:07.553000+00:00".parse()?)
//!     .issuee(&holder)?
//!     .timestamp()?
//!     .text("LEI", "5493001KJTIIGC8Y1R17")?;
//!
//! let credential = CredentialBuilder::new(issuer, registry, schema, attributes).build()?;
//!
//! // The credential the pinned reference's own test helper checks in.
//! assert_eq!(
//!     credential.said().qb64()?,
//!     "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo",
//! );
//! assert_eq!(
//!     credential.attributes_said().qb64()?,
//!     "EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P",
//! );
//! # Ok(())
//! # }
//! ```

use core::fmt;
use std::error::Error;

use keri_cesr::crypto::digest::DigestAlgorithm;
use signify_keri::event::timestamp::Timestamp;
use signify_keri::prefix::{IdentifierPrefix, PrefixError};
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidError};
use signify_keri::serialization::{
    IDENTIFIER_LABEL, SAID_LABEL, Sad, SadError, SadValue, SerializationError, SerializedEvent, VERSION_LABEL,
};

/// Field label carrying the attribute block; the credential's `a`.
pub const ATTRIBUTES_LABEL: &str = "a";
/// Field label carrying the edge block that chains this credential to others; the credential's `e`.
pub const EDGES_LABEL: &str = "e";
/// Field label carrying the rule block; the credential's `r`.
pub const RULES_LABEL: &str = "r";
/// Field label carrying a privacy salt; the `u` of a credential or of its attribute block.
pub const NONCE_LABEL: &str = "u";
/// Field label naming the governing registry; the credential's `ri`.
pub const REGISTRY_LABEL: &str = "ri";
/// Field label naming the schema; the credential's `s`.
pub const SCHEMA_LABEL: &str = "s";
/// Field label naming the subject of an attribute block; the block's `i`.
pub const ISSUEE_LABEL: &str = "i";
/// Field label carrying an attribute block's issuance timestamp; the block's `dt`.
pub const TIMESTAMP_LABEL: &str = "dt";

/// Version string written before the container's size is known.
///
/// The digits are rewritten by [`SerializedEvent`] once the encoding's byte length is final; this
/// is the reference's `versify(Protocols.ACDC, undefined, Serials.JSON, 0)`.
pub const UNSIZED_VERSION_STRING: &str = "ACDC10JSON000000_";

/// Digest algorithm both identifiers use.
///
/// The reference's `saidify` defaults to BLAKE3-256 and `issue` never overrides it, so there is no
/// other value to express.
pub const DIGEST_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Blake3_256;

/// Largest privacy salt this builder accepts, in bytes.
///
/// The reference accepts any string; its own callers supply a qualified salt of 24 characters.
/// The bound exists because the value is committed into an identifier.
pub const MAX_NONCE_BYTES: usize = 256;

/// Largest field label this builder accepts inside a caller-supplied block, in bytes.
pub const MAX_LABEL_BYTES: usize = 256;

/// Largest number of fields one caller-supplied block may hold, counted through nested maps.
pub const MAX_BLOCK_FIELDS: usize = 4_096;

/// Deepest nesting accepted inside a caller-supplied block.
///
/// Serialization is recursive, so an unbounded depth is a stack-exhaustion path for data that may
/// have arrived from a peer. The bound is half the parser's, because a block is itself nested
/// inside the credential that carries it.
pub const MAX_BLOCK_DEPTH: usize = 32;

/// Which caller-supplied block a failure came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialBlock {
    /// The attribute block, the credential's `a`.
    Attributes,
    /// The edge block, the credential's `e`.
    Edges,
    /// The rule block, the credential's `r`.
    Rules,
}

impl CredentialBlock {
    /// Returns the wire label of this block.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Attributes => ATTRIBUTES_LABEL,
            Self::Edges => EDGES_LABEL,
            Self::Rules => RULES_LABEL,
        }
    }

    /// Returns a human-readable name for error messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Attributes => "attribute",
            Self::Edges => "edge",
            Self::Rules => "rule",
        }
    }
}

impl fmt::Display for CredentialBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// The identifier of a credential registry.
///
/// A registry identifier is the self-addressing prefix of the `vcp` event that created it, so it
/// is an [`IdentifierPrefix`] like any other. The newtype exists because a credential names two
/// prefixes — its issuer and its registry — whose meanings are unrelated and whose positions the
/// reference has no way to distinguish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryIdentifier {
    prefix: IdentifierPrefix,
}

impl RegistryIdentifier {
    /// Parses a registry identifier from its qualified Base64 text.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::Prefix`] when the text is not a valid identifier prefix.
    pub fn from_qb64(input: &str) -> Result<Self, CredentialError> {
        Ok(Self {
            prefix: IdentifierPrefix::from_qb64(input)?,
        })
    }

    /// Borrows the underlying prefix.
    #[must_use]
    pub const fn prefix(&self) -> &IdentifierPrefix {
        &self.prefix
    }

    /// Returns the qualified Base64 text.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::Prefix`] when the prefix cannot be encoded.
    pub fn qb64(&self) -> Result<String, CredentialError> {
        Ok(self.prefix.qb64()?)
    }
}

impl From<IdentifierPrefix> for RegistryIdentifier {
    fn from(prefix: IdentifierPrefix) -> Self {
        Self { prefix }
    }
}

/// The attribute block of a credential, in the order it will be serialized.
///
/// The block always opens with its own identifier field and always carries a timestamp. Everything
/// between them is the caller's, written in the order these methods are called; the timestamp goes
/// wherever [`Self::timestamp`] places it, or last when it is never called — which is exactly what
/// the reference does with `{ d: '', ...args.a, dt: args.a.dt ?? now }`.
///
/// ```
/// use signify_acdc::credential::CredentialAttributes;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let stamp: signify_keri::event::timestamp::Timestamp =
///     "2023-08-23T15:16:07.553000+00:00".parse()?;
///
/// // `dt` appended after the caller's fields, as the pinned unit test's arguments produce.
/// let appended = CredentialAttributes::new(stamp.clone()).text("LEI", "1234")?;
/// assert_eq!(appended.labels(), ["d", "LEI", "dt"]);
///
/// // `dt` placed by the caller, as the pinned vLEI suites write it.
/// let placed = CredentialAttributes::new(stamp).timestamp()?.text("LEI", "1234")?;
/// assert_eq!(placed.labels(), ["d", "dt", "LEI"]);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAttributes {
    fields: Sad,
    timestamp: Timestamp,
}

impl CredentialAttributes {
    /// Starts an attribute block stamped at `timestamp`.
    ///
    /// The reference defaults this to the system clock. A protocol crate reads no clock, so the
    /// caller supplies a validated [`Timestamp`], exactly as a reply's and a registry nonce's are
    /// supplied.
    #[must_use]
    pub fn new(timestamp: Timestamp) -> Self {
        Self {
            fields: Sad::new(),
            timestamp,
        }
    }

    /// Names the credential's subject; the block's `i`.
    ///
    /// A credential with no issuee is untargeted, which the reference and this builder both allow.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::DuplicateLabel`] when an issuee is already named, and
    /// [`CredentialError::Prefix`] when the prefix cannot be encoded.
    pub fn issuee(self, issuee: &IdentifierPrefix) -> Result<Self, CredentialError> {
        let qb64 = issuee.qb64()?;
        self.insert(ISSUEE_LABEL, SadValue::Text(qb64))
    }

    /// Writes the issuance timestamp here rather than after the caller's fields; the block's `dt`.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::DuplicateLabel`] when the timestamp is already placed.
    pub fn timestamp(self) -> Result<Self, CredentialError> {
        let text = self.timestamp.as_str().to_owned();
        self.insert(TIMESTAMP_LABEL, SadValue::Text(text))
    }

    /// Adds a privacy salt to the attribute block; the block's `u`.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::EmptyNonce`], [`CredentialError::NonceTooLong`], and
    /// [`CredentialError::DuplicateLabel`].
    pub fn nonce(self, nonce: &str) -> Result<Self, CredentialError> {
        check_nonce(nonce)?;
        self.insert(NONCE_LABEL, SadValue::text(nonce))
    }

    /// Adds one text attribute.
    ///
    /// # Errors
    ///
    /// Returns the label failures listed on [`Self::attribute`].
    pub fn text(self, label: impl Into<String>, value: impl Into<String>) -> Result<Self, CredentialError> {
        self.attribute(label, SadValue::Text(value.into()))
    }

    /// Adds one attribute of any representable shape.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::ReservedLabel`] for `d` or `v`, which the reference overwrites
    /// or reinterprets; [`CredentialError::TypedLabel`] for `i`, `u`, or `dt`, which have their
    /// own validated methods; [`CredentialError::ArrayIndexLabel`] for a label JavaScript would
    /// hoist; [`CredentialError::LabelTooLong`]; [`CredentialError::DuplicateLabel`]; and the
    /// nested-value failures listed on [`CredentialBuilder::edges`].
    pub fn attribute(self, label: impl Into<String>, value: impl Into<SadValue>) -> Result<Self, CredentialError> {
        let label = label.into();
        let value = value.into();
        match label.as_str() {
            ISSUEE_LABEL | NONCE_LABEL | TIMESTAMP_LABEL => {
                return Err(CredentialError::TypedLabel {
                    block: CredentialBlock::Attributes,
                    label,
                });
            }
            _ => {}
        }
        check_reserved_label(CredentialBlock::Attributes, &label)?;
        check_block_label(CredentialBlock::Attributes, &label)?;
        check_value(CredentialBlock::Attributes, &value, 1, &mut 0)?;
        self.insert(label, value)
    }

    /// Returns the labels written so far, including the leading identifier field and, when the
    /// timestamp has not been placed, the trailing `dt`.
    #[must_use]
    pub fn labels(&self) -> Vec<&str> {
        let mut labels = vec![DEFAULT_SAID_LABEL];
        labels.extend(self.fields.entries().map(|(label, _)| label));
        if !self.fields.contains(TIMESTAMP_LABEL) {
            labels.push(TIMESTAMP_LABEL);
        }
        labels
    }

    /// Returns the timestamp this block carries.
    #[must_use]
    pub const fn stamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Appends one already-validated field.
    fn insert(mut self, label: impl Into<String>, value: SadValue) -> Result<Self, CredentialError> {
        let label = label.into();
        if self.fields.contains(&label) {
            return Err(CredentialError::DuplicateLabel {
                block: CredentialBlock::Attributes,
                label,
            });
        }
        if self.fields.len() >= MAX_BLOCK_FIELDS {
            return Err(CredentialError::BlockTooLarge {
                block: CredentialBlock::Attributes,
                maximum: MAX_BLOCK_FIELDS,
            });
        }
        self.fields.insert(label, value)?;
        Ok(self)
    }

    /// Materializes the block the reference's first `saidify` receives, with a placeholder `d`.
    fn to_sad(&self) -> Result<Sad, CredentialError> {
        let mut sad = Sad::new();
        sad.insert(SAID_LABEL, SadValue::text(""))?;
        for (label, value) in self.fields.entries() {
            sad.insert(label.to_owned(), value.clone())?;
        }
        if !sad.contains(TIMESTAMP_LABEL) {
            sad.insert(TIMESTAMP_LABEL, SadValue::text(self.timestamp.as_str()))?;
        }
        Ok(sad)
    }
}

/// One completed credential: its exact bytes, both identifiers it carries, and the typed values it
/// was built from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    serialized: SerializedEvent,
    said: Said,
    attributes_said: Said,
    issuer: IdentifierPrefix,
    registry: RegistryIdentifier,
    schema: Said,
    timestamp: Timestamp,
}

impl Credential {
    /// Returns the exact serialized bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.serialized.raw()
    }

    /// Borrows the ordered container fields.
    #[must_use]
    pub const fn sad(&self) -> &Sad {
        self.serialized.sad()
    }

    /// Borrows the serialized form, which carries the sized version string.
    #[must_use]
    pub const fn serialized(&self) -> &SerializedEvent {
        &self.serialized
    }

    /// Returns the credential's own identifier; its `d`.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the attribute block's identifier; its `a.d`.
    #[must_use]
    pub const fn attributes_said(&self) -> Said {
        self.attributes_said
    }

    /// Borrows the completed attribute block.
    ///
    /// Returns `None` only if the container somehow carries no map at `a`, which this builder
    /// cannot produce.
    #[must_use]
    pub fn attributes(&self) -> Option<&Sad> {
        self.serialized.sad().get(ATTRIBUTES_LABEL).and_then(SadValue::as_map)
    }

    /// Returns the identifier that issued this credential; its `i`.
    #[must_use]
    pub const fn issuer(&self) -> &IdentifierPrefix {
        &self.issuer
    }

    /// Returns the registry whose transaction event log governs this credential's status; its
    /// `ri`.
    #[must_use]
    pub const fn registry(&self) -> &RegistryIdentifier {
        &self.registry
    }

    /// Returns the identifier of the schema this credential claims to satisfy; its `s`.
    #[must_use]
    pub const fn schema(&self) -> Said {
        self.schema
    }

    /// Returns the attribute block's issuance timestamp; its `a.dt`.
    ///
    /// A credential's transaction event commits to this same instant rather than reading a clock
    /// of its own, which is why it is retained here.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Splits this credential into its serialized form and both identifiers.
    #[must_use]
    pub fn into_parts(self) -> (SerializedEvent, Said, Said) {
        (self.serialized, self.said, self.attributes_said)
    }
}

/// Builds one ACDC credential and derives both of its identifiers.
///
/// The issuer, registry, schema, and attribute block are all required. The reference declares the
/// registry and schema optional and would issue a credential naming neither; both are required
/// here, because a credential outside a registry has no status to check and one without a schema
/// claims nothing. The fixture records what the reference emits for each.
#[derive(Clone, Debug)]
pub struct CredentialBuilder {
    issuer: IdentifierPrefix,
    registry: RegistryIdentifier,
    schema: Said,
    attributes: CredentialAttributes,
    nonce: Option<String>,
    edges: Option<Sad>,
    rules: Option<Sad>,
}

impl CredentialBuilder {
    /// Starts a credential issued by `issuer` into `registry` against `schema`.
    #[must_use]
    pub const fn new(
        issuer: IdentifierPrefix,
        registry: RegistryIdentifier,
        schema: Said,
        attributes: CredentialAttributes,
    ) -> Self {
        Self {
            issuer,
            registry,
            schema,
            attributes,
            nonce: None,
            edges: None,
            rules: None,
        }
    }

    /// Adds a privacy salt to the container; the credential's `u`.
    ///
    /// This is the salt that blinds the credential as a whole. The attribute block has its own,
    /// set with [`CredentialAttributes::nonce`]; the reference's ECR credential carries both.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::EmptyNonce`] and [`CredentialError::NonceTooLong`].
    pub fn nonce(mut self, nonce: impl Into<String>) -> Result<Self, CredentialError> {
        let nonce = nonce.into();
        check_nonce(&nonce)?;
        self.nonce = Some(nonce);
        Ok(self)
    }

    /// Chains this credential to others; the credential's `e`.
    ///
    /// The block is committed exactly as given. Its callers build it with a self-addressing
    /// identifier of its own, which is [`Said::compute`] over the same data.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::ArrayIndexLabel`] for a label JavaScript would hoist ahead of
    /// the others, [`CredentialError::LabelTooLong`], [`CredentialError::BlockTooLarge`], and
    /// [`CredentialError::BlockTooDeep`].
    pub fn edges(mut self, edges: Sad) -> Result<Self, CredentialError> {
        check_block(CredentialBlock::Edges, &edges)?;
        self.edges = Some(edges);
        Ok(self)
    }

    /// Attaches the rules a holder accepts with the credential; the credential's `r`.
    ///
    /// # Errors
    ///
    /// Returns the block failures listed on [`Self::edges`].
    pub fn rules(mut self, rules: Sad) -> Result<Self, CredentialError> {
        check_block(CredentialBlock::Rules, &rules)?;
        self.rules = Some(rules);
        Ok(self)
    }

    /// Derives both identifiers and serializes the credential.
    ///
    /// # Errors
    ///
    /// Returns the block failures listed on [`Self::edges`] for an attribute block that grew past
    /// its bounds, and layered [`CredentialError::Said`], [`CredentialError::Sad`],
    /// [`CredentialError::Serialization`], or [`CredentialError::Prefix`] failures for material
    /// that cannot be encoded.
    pub fn build(self) -> Result<Credential, CredentialError> {
        let timestamp = self.attributes.timestamp.clone();
        let attributes = self.attributes.to_sad()?;
        check_block(CredentialBlock::Attributes, &attributes)?;
        let (attributes_said, attributes) =
            Said::compute(&attributes, DIGEST_ALGORITHM, DEFAULT_SAID_LABEL)?.into_parts();

        let mut container = Sad::new();
        container.insert(VERSION_LABEL, SadValue::text(UNSIZED_VERSION_STRING))?;
        container.insert(SAID_LABEL, SadValue::text(""))?;
        if let Some(nonce) = self.nonce {
            container.insert(NONCE_LABEL, SadValue::Text(nonce))?;
        }
        container.insert(IDENTIFIER_LABEL, SadValue::Text(self.issuer.qb64()?))?;
        container.insert(REGISTRY_LABEL, SadValue::Text(self.registry.qb64()?))?;
        container.insert(SCHEMA_LABEL, SadValue::Text(self.schema.qb64()?))?;
        container.insert(ATTRIBUTES_LABEL, SadValue::Map(attributes))?;
        if let Some(edges) = self.edges {
            container.insert(EDGES_LABEL, SadValue::Map(edges))?;
        }
        if let Some(rules) = self.rules {
            container.insert(RULES_LABEL, SadValue::Map(rules))?;
        }

        let (said, container) = Said::compute(&container, DIGEST_ALGORITHM, DEFAULT_SAID_LABEL)?.into_parts();
        Ok(Credential {
            serialized: SerializedEvent::from_sad(container)?,
            said,
            attributes_said,
            issuer: self.issuer,
            registry: self.registry,
            schema: self.schema,
            timestamp: timestamp.clone(),
        })
    }
}

/// Rejects a privacy salt the reference would commit unchecked.
fn check_nonce(nonce: &str) -> Result<(), CredentialError> {
    if nonce.is_empty() {
        return Err(CredentialError::EmptyNonce);
    }
    if nonce.len() > MAX_NONCE_BYTES {
        return Err(CredentialError::NonceTooLong {
            maximum: MAX_NONCE_BYTES,
            actual: nonce.len(),
        });
    }
    Ok(())
}

/// Rejects a label the builder writes itself into the block it saidifies.
///
/// This applies only where the caller adds a field to a block *this* module derives an identifier
/// for — the attribute block. An edge or rule block arrives complete and already carries a `d` of
/// its own, and its `v`, if any, is an ordinary field because nothing here saidifies it.
fn check_reserved_label(block: CredentialBlock, label: &str) -> Result<(), CredentialError> {
    match label {
        SAID_LABEL => Err(CredentialError::ReservedLabel {
            block,
            label: SAID_LABEL,
        }),
        VERSION_LABEL => Err(CredentialError::ReservedLabel {
            block,
            label: VERSION_LABEL,
        }),
        _ => Ok(()),
    }
}

/// Validates one complete caller-supplied block, counting fields and nesting as it goes.
fn check_block(block: CredentialBlock, sad: &Sad) -> Result<(), CredentialError> {
    let mut fields = 0_usize;
    check_map(block, sad, 1, &mut fields)
}

/// Validates one map at `depth`, adding its fields to `fields`.
fn check_map(block: CredentialBlock, sad: &Sad, depth: usize, fields: &mut usize) -> Result<(), CredentialError> {
    if depth > MAX_BLOCK_DEPTH {
        return Err(CredentialError::BlockTooDeep {
            block,
            maximum: MAX_BLOCK_DEPTH,
        });
    }
    for (label, value) in sad.entries() {
        *fields = fields.checked_add(1).ok_or(CredentialError::BlockTooLarge {
            block,
            maximum: MAX_BLOCK_FIELDS,
        })?;
        if *fields > MAX_BLOCK_FIELDS {
            return Err(CredentialError::BlockTooLarge {
                block,
                maximum: MAX_BLOCK_FIELDS,
            });
        }
        check_block_label(block, label)?;
        check_value(block, value, depth, fields)?;
    }
    Ok(())
}

/// Bounds one label and rejects the array-index spelling JavaScript would hoist.
fn check_block_label(block: CredentialBlock, label: &str) -> Result<(), CredentialError> {
    if label.len() > MAX_LABEL_BYTES {
        return Err(CredentialError::LabelTooLong {
            block,
            maximum: MAX_LABEL_BYTES,
            actual: label.len(),
        });
    }
    if is_array_index_label(label) {
        return Err(CredentialError::ArrayIndexLabel {
            block,
            label: label.to_owned(),
        });
    }
    Ok(())
}

/// Validates one value, recursing through arrays and maps.
fn check_value(
    block: CredentialBlock,
    value: &SadValue,
    depth: usize,
    fields: &mut usize,
) -> Result<(), CredentialError> {
    match value {
        SadValue::Map(nested) => {
            let deeper = depth.checked_add(1).ok_or(CredentialError::BlockTooDeep {
                block,
                maximum: MAX_BLOCK_DEPTH,
            })?;
            check_map(block, nested, deeper, fields)
        }
        SadValue::Array(items) => {
            let deeper = depth.checked_add(1).ok_or(CredentialError::BlockTooDeep {
                block,
                maximum: MAX_BLOCK_DEPTH,
            })?;
            if deeper > MAX_BLOCK_DEPTH {
                return Err(CredentialError::BlockTooDeep {
                    block,
                    maximum: MAX_BLOCK_DEPTH,
                });
            }
            for item in items {
                *fields = fields.checked_add(1).ok_or(CredentialError::BlockTooLarge {
                    block,
                    maximum: MAX_BLOCK_FIELDS,
                })?;
                if *fields > MAX_BLOCK_FIELDS {
                    return Err(CredentialError::BlockTooLarge {
                        block,
                        maximum: MAX_BLOCK_FIELDS,
                    });
                }
                check_value(block, item, deeper, fields)?;
            }
            Ok(())
        }
        // Every remaining shape is a leaf. `SadValue` is `#[non_exhaustive]`, so a shape added
        // later is accepted as one too, which is safe because every bound above has already been
        // applied to the field carrying it.
        _ => Ok(()),
    }
}

/// Returns whether JavaScript would treat this label as an array index and hoist it.
///
/// The rule is the ECMAScript one: the canonical decimal spelling of an integer in
/// `0..=4294967294`. A leading zero, a sign, or `4294967295` is an ordinary string key.
fn is_array_index_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 10 {
        return false;
    }
    if !label.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if label.len() > 1 && label.starts_with('0') {
        return false;
    }
    label.parse::<u32>().is_ok_and(|value| value != u32::MAX)
}

/// Stable credential-construction failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum CredentialError {
    /// A label the builder writes itself was supplied by the caller.
    ///
    /// The reference overwrites `d` with its derivation placeholder and treats `v` as a version
    /// string to be resized, so either would commit to something the caller did not write.
    ReservedLabel {
        /// Which block the label appeared in.
        block: CredentialBlock,
        /// The reserved label.
        label: &'static str,
    },
    /// A label with a validated method of its own was supplied as a free-form attribute.
    TypedLabel {
        /// Which block the label appeared in.
        block: CredentialBlock,
        /// The label; use `issuee`, `nonce`, or `timestamp` instead.
        label: String,
    },
    /// A label JavaScript would hoist ahead of the others, changing the bytes a digest commits to.
    ArrayIndexLabel {
        /// Which block the label appeared in.
        block: CredentialBlock,
        /// The offending label.
        label: String,
    },
    /// The same label appears twice in one block.
    DuplicateLabel {
        /// Which block the label appeared in.
        block: CredentialBlock,
        /// The repeated label.
        label: String,
    },
    /// A label exceeds [`MAX_LABEL_BYTES`].
    LabelTooLong {
        /// Which block the label appeared in.
        block: CredentialBlock,
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// A block holds more fields than [`MAX_BLOCK_FIELDS`], counted through nesting.
    BlockTooLarge {
        /// Which block overflowed.
        block: CredentialBlock,
        /// Accepted maximum.
        maximum: usize,
    },
    /// A block nests deeper than [`MAX_BLOCK_DEPTH`].
    BlockTooDeep {
        /// Which block overflowed.
        block: CredentialBlock,
        /// Accepted maximum.
        maximum: usize,
    },
    /// A privacy salt is empty; the reference would commit the empty string.
    EmptyNonce,
    /// A privacy salt exceeds [`MAX_NONCE_BYTES`].
    NonceTooLong {
        /// Accepted maximum in bytes.
        maximum: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// Deriving one of the two identifiers failed.
    Said {
        /// Underlying failure.
        source: Box<SaidError>,
    },
    /// Assembling the ordered fields failed.
    Sad {
        /// Underlying failure.
        source: Box<SadError>,
    },
    /// Serializing the container failed.
    Serialization {
        /// Underlying failure.
        source: Box<SerializationError>,
    },
    /// Encoding an identifier prefix failed.
    Prefix {
        /// Underlying failure.
        source: Box<PrefixError>,
    },
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedLabel { block, label } => {
                write!(
                    formatter,
                    "the {block} block may not carry the reserved label {label:?}"
                )
            }
            Self::TypedLabel { block, label } => write!(
                formatter,
                "the {block} label {label:?} has a validated method of its own"
            ),
            Self::ArrayIndexLabel { block, label } => write!(
                formatter,
                "the {block} label {label:?} is an array index, which JavaScript would order first"
            ),
            Self::DuplicateLabel { block, label } => {
                write!(formatter, "the {block} block already carries the label {label:?}")
            }
            Self::LabelTooLong { block, maximum, actual } => {
                write!(formatter, "a {block} label of {actual} bytes exceeds maximum {maximum}")
            }
            Self::BlockTooLarge { block, maximum } => {
                write!(formatter, "the {block} block exceeds maximum {maximum} fields")
            }
            Self::BlockTooDeep { block, maximum } => {
                write!(formatter, "the {block} block nests deeper than maximum {maximum}")
            }
            Self::EmptyNonce => formatter.write_str("a privacy salt may not be empty"),
            Self::NonceTooLong { maximum, actual } => {
                write!(formatter, "a privacy salt of {actual} bytes exceeds maximum {maximum}")
            }
            Self::Said { source } => write!(formatter, "identifier derivation failed: {source}"),
            Self::Sad { source } => write!(formatter, "field assembly failed: {source}"),
            Self::Serialization { source } => write!(formatter, "serialization failed: {source}"),
            Self::Prefix { source } => write!(formatter, "identifier encoding failed: {source}"),
        }
    }
}

impl Error for CredentialError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Said { source } => Some(source),
            Self::Sad { source } => Some(source),
            Self::Serialization { source } => Some(source),
            Self::Prefix { source } => Some(source),
            _ => None,
        }
    }
}

impl From<SaidError> for CredentialError {
    fn from(source: SaidError) -> Self {
        Self::Said {
            source: Box::new(source),
        }
    }
}

impl From<SadError> for CredentialError {
    fn from(source: SadError) -> Self {
        Self::Sad {
            source: Box::new(source),
        }
    }
}

impl From<SerializationError> for CredentialError {
    fn from(source: SerializationError) -> Self {
        Self::Serialization {
            source: Box::new(source),
        }
    }
}

impl From<PrefixError> for CredentialError {
    fn from(source: PrefixError) -> Self {
        Self::Prefix {
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signify_keri::said::SaidVerification;
    use std::error::Error;

    const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
    const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
    const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
    const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
    const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

    fn stamp() -> Result<Timestamp, Box<dyn Error>> {
        Ok(STAMP.parse()?)
    }

    fn attributes() -> Result<CredentialAttributes, Box<dyn Error>> {
        Ok(CredentialAttributes::new(stamp()?)
            .issuee(&IdentifierPrefix::from_qb64(HOLDER)?)?
            .timestamp()?
            .text("LEI", "5493001KJTIIGC8Y1R17")?)
    }

    fn builder() -> Result<CredentialBuilder, Box<dyn Error>> {
        Ok(CredentialBuilder::new(
            IdentifierPrefix::from_qb64(ISSUER)?,
            RegistryIdentifier::from_qb64(REGISTRY)?,
            Said::from_qb64(SCHEMA)?,
            attributes()?,
        ))
    }

    #[test]
    fn a_credential_carries_both_identifiers_and_its_own_size() -> Result<(), Box<dyn Error>> {
        let credential = builder()?.build()?;
        assert_eq!(
            credential.said().qb64()?,
            "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo"
        );
        assert_eq!(
            credential.attributes_said().qb64()?,
            "EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P"
        );
        // The version string counts the finished bytes, not the placeholder's.
        assert_eq!(credential.sad().get_text(VERSION_LABEL), Some("ACDC10JSON000197_"));
        assert_eq!(credential.raw().len(), 0x197);
        assert_eq!(credential.serialized().raw(), credential.raw());
        Ok(())
    }

    #[test]
    fn the_container_writes_its_fields_in_the_protocol_order() -> Result<(), Box<dyn Error>> {
        let mut edges = Sad::new();
        edges.insert("qvi", SadValue::text("EQVI"))?;
        let mut rules = Sad::new();
        rules.insert("usageDisclaimer", SadValue::text("some rule"))?;

        let credential = builder()?
            .nonce("0AD6E0lCLBQ0-JOFBoTd9k8I")?
            .edges(edges)?
            .rules(rules)?
            .build()?;
        let labels: Vec<&str> = credential.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["v", "d", "u", "i", "ri", "s", "a", "e", "r"]);
        Ok(())
    }

    #[test]
    fn an_absent_optional_field_is_absent_rather_than_empty() -> Result<(), Box<dyn Error>> {
        let credential = builder()?.build()?;
        let labels: Vec<&str> = credential.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["v", "d", "i", "ri", "s", "a"]);
        assert!(!credential.sad().contains(NONCE_LABEL));
        assert!(!credential.sad().contains(EDGES_LABEL));
        assert!(!credential.sad().contains(RULES_LABEL));
        Ok(())
    }

    #[test]
    fn an_attribute_block_places_its_timestamp_where_the_caller_did() -> Result<(), Box<dyn Error>> {
        let placed = CredentialAttributes::new(stamp()?).timestamp()?.text("LEI", "1")?;
        assert_eq!(placed.labels(), ["d", "dt", "LEI"]);

        let appended = CredentialAttributes::new(stamp()?).text("LEI", "1")?;
        assert_eq!(appended.labels(), ["d", "LEI", "dt"]);

        // The two are different credentials, because the digest covers the order.
        let first = CredentialBuilder::new(
            IdentifierPrefix::from_qb64(ISSUER)?,
            RegistryIdentifier::from_qb64(REGISTRY)?,
            Said::from_qb64(SCHEMA)?,
            placed,
        )
        .build()?;
        let second = CredentialBuilder::new(
            IdentifierPrefix::from_qb64(ISSUER)?,
            RegistryIdentifier::from_qb64(REGISTRY)?,
            Said::from_qb64(SCHEMA)?,
            appended,
        )
        .build()?;
        assert_ne!(first.said(), second.said());
        assert_eq!(first.raw().len(), second.raw().len());
        Ok(())
    }

    #[test]
    fn an_untargeted_credential_still_carries_a_stamped_block() -> Result<(), Box<dyn Error>> {
        let credential = CredentialBuilder::new(
            IdentifierPrefix::from_qb64(ISSUER)?,
            RegistryIdentifier::from_qb64(REGISTRY)?,
            Said::from_qb64(SCHEMA)?,
            CredentialAttributes::new(stamp()?),
        )
        .build()?;
        let block = credential.attributes().ok_or("no attribute block")?;
        let labels: Vec<&str> = block.entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["d", "dt"]);
        assert_eq!(block.get_text(TIMESTAMP_LABEL), Some(STAMP));
        Ok(())
    }

    #[test]
    fn both_identifiers_verify_against_the_data_that_carries_them() -> Result<(), Box<dyn Error>> {
        let credential = builder()?.build()?;
        credential
            .said()
            .verify(credential.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())?;
        let block = credential.attributes().ok_or("no attribute block")?;
        credential
            .attributes_said()
            .verify(block, DEFAULT_SAID_LABEL, SaidVerification::strict())?;

        // Changing one byte of the attributes breaks the container's identifier too, because the
        // block's identifier is committed inside it.
        let tampered = CredentialBuilder::new(
            IdentifierPrefix::from_qb64(ISSUER)?,
            RegistryIdentifier::from_qb64(REGISTRY)?,
            Said::from_qb64(SCHEMA)?,
            CredentialAttributes::new(stamp()?)
                .issuee(&IdentifierPrefix::from_qb64(HOLDER)?)?
                .timestamp()?
                .text("LEI", "5493001KJTIIGC8Y1R18")?,
        )
        .build()?;
        assert_ne!(tampered.said(), credential.said());
        assert_ne!(tampered.attributes_said(), credential.attributes_said());
        Ok(())
    }

    #[test]
    fn the_reserved_labels_are_the_two_the_reference_reinterprets() -> Result<(), Box<dyn Error>> {
        let base = CredentialAttributes::new(stamp()?);
        assert!(matches!(
            base.clone().text(SAID_LABEL, "x"),
            Err(CredentialError::ReservedLabel {
                block: CredentialBlock::Attributes,
                label: "d"
            })
        ));
        assert!(matches!(
            base.clone().text(VERSION_LABEL, "x"),
            Err(CredentialError::ReservedLabel { label: "v", .. })
        ));
        // These three have validated methods of their own.
        for label in [ISSUEE_LABEL, NONCE_LABEL, TIMESTAMP_LABEL] {
            assert!(
                matches!(base.clone().text(label, "x"), Err(CredentialError::TypedLabel { .. })),
                "{label} was accepted as a free-form attribute"
            );
        }
        Ok(())
    }

    #[test]
    fn an_array_index_label_is_refused_in_every_block() -> Result<(), Box<dyn Error>> {
        // The exact boundary of the ECMAScript rule.
        for hoisted in ["0", "1", "10", "4294967294"] {
            assert!(
                matches!(
                    CredentialAttributes::new(stamp()?).text(hoisted, "v"),
                    Err(CredentialError::ArrayIndexLabel { .. })
                ),
                "{hoisted} was accepted"
            );
        }
        // Neither a leading zero, a sign, the 2^32-1 sentinel, nor a non-integer is an index.
        for ordinary in ["01", "-1", "4294967295", "4294967296", "1.0", "1e3", " 1", "1 ", ""] {
            CredentialAttributes::new(stamp()?)
                .text(ordinary, "v")
                .map_err(|error| format!("{ordinary:?} was refused: {error}"))?;
        }

        // The same rule applies to an edge or rule block, and through its nesting.
        let mut nested = Sad::new();
        nested.insert("0", SadValue::text("v"))?;
        let mut edges = Sad::new();
        edges.insert("qvi", SadValue::Map(nested))?;
        assert!(matches!(
            builder()?.edges(edges.clone()),
            Err(CredentialError::ArrayIndexLabel {
                block: CredentialBlock::Edges,
                ..
            })
        ));
        assert!(matches!(
            builder()?.rules(edges),
            Err(CredentialError::ArrayIndexLabel {
                block: CredentialBlock::Rules,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn an_edge_or_rule_block_may_carry_its_own_identifier() -> Result<(), Box<dyn Error>> {
        // The reference's own edge and rule blocks are saidified before they reach `issue`, so
        // their `d` is an ordinary field here rather than a reserved one.
        let mut edges = Sad::new();
        edges.insert(SAID_LABEL, SadValue::text("EEDGE"))?;
        edges.insert(VERSION_LABEL, SadValue::text("anything"))?;
        let credential = builder()?.edges(edges)?.build()?;
        let block = credential
            .sad()
            .get(EDGES_LABEL)
            .and_then(SadValue::as_map)
            .ok_or("no edge block")?;
        assert_eq!(block.get_text(SAID_LABEL), Some("EEDGE"));
        Ok(())
    }

    #[test]
    fn a_repeated_label_is_refused() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            CredentialAttributes::new(stamp()?).text("LEI", "1")?.text("LEI", "2"),
            Err(CredentialError::DuplicateLabel { label, .. }) if label == "LEI"
        ));
        let holder = IdentifierPrefix::from_qb64(HOLDER)?;
        assert!(matches!(
            CredentialAttributes::new(stamp()?).issuee(&holder)?.issuee(&holder),
            Err(CredentialError::DuplicateLabel { label, .. }) if label == ISSUEE_LABEL
        ));
        assert!(matches!(
            CredentialAttributes::new(stamp()?).timestamp()?.timestamp(),
            Err(CredentialError::DuplicateLabel { label, .. }) if label == TIMESTAMP_LABEL
        ));
        Ok(())
    }

    #[test]
    fn a_privacy_salt_is_bounded_and_never_empty() -> Result<(), Box<dyn Error>> {
        assert!(matches!(builder()?.nonce(""), Err(CredentialError::EmptyNonce)));
        assert!(matches!(
            CredentialAttributes::new(stamp()?).nonce(""),
            Err(CredentialError::EmptyNonce)
        ));
        assert!(matches!(
            builder()?.nonce("0".repeat(MAX_NONCE_BYTES + 1)),
            Err(CredentialError::NonceTooLong { maximum, actual })
                if maximum == MAX_NONCE_BYTES && actual == MAX_NONCE_BYTES + 1
        ));
        // The bound itself is accepted, on both blocks.
        builder()?.nonce("0".repeat(MAX_NONCE_BYTES))?;
        CredentialAttributes::new(stamp()?).nonce(&"0".repeat(MAX_NONCE_BYTES))?;
        Ok(())
    }

    #[test]
    fn a_label_is_bounded() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            CredentialAttributes::new(stamp()?).text("a".repeat(MAX_LABEL_BYTES + 1), "v"),
            Err(CredentialError::LabelTooLong { maximum, actual, .. })
                if maximum == MAX_LABEL_BYTES && actual == MAX_LABEL_BYTES + 1
        ));
        CredentialAttributes::new(stamp()?).text("a".repeat(MAX_LABEL_BYTES), "v")?;

        let mut edges = Sad::new();
        edges.insert("a".repeat(MAX_LABEL_BYTES + 1), SadValue::text("v"))?;
        assert!(matches!(
            builder()?.edges(edges),
            Err(CredentialError::LabelTooLong {
                block: CredentialBlock::Edges,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn a_block_is_bounded_in_depth_and_in_field_count() -> Result<(), Box<dyn Error>> {
        // Nesting past the ceiling is refused rather than recursed into.
        let mut deep = Sad::new();
        deep.insert("leaf", SadValue::text("v"))?;
        for _ in 0..MAX_BLOCK_DEPTH {
            let mut wrapper = Sad::new();
            wrapper.insert("next", SadValue::Map(deep))?;
            deep = wrapper;
        }
        assert!(matches!(
            builder()?.edges(deep),
            Err(CredentialError::BlockTooDeep {
                block: CredentialBlock::Edges,
                maximum
            }) if maximum == MAX_BLOCK_DEPTH
        ));

        // An array counts as a level too, so a deeply nested list cannot smuggle depth past it.
        let mut nested = SadValue::text("leaf");
        for _ in 0..MAX_BLOCK_DEPTH {
            nested = SadValue::Array(vec![nested]);
        }
        let mut arrays = Sad::new();
        arrays.insert("list", nested)?;
        assert!(matches!(
            builder()?.rules(arrays),
            Err(CredentialError::BlockTooDeep { .. })
        ));

        // And the field count is a ceiling on the whole block, not on one map.
        let mut wide = Sad::new();
        for index in 0..=MAX_BLOCK_FIELDS {
            wide.insert(format!("f{index}"), SadValue::text("v"))?;
        }
        assert!(matches!(
            builder()?.edges(wide),
            Err(CredentialError::BlockTooLarge { maximum, .. }) if maximum == MAX_BLOCK_FIELDS
        ));
        Ok(())
    }

    #[test]
    fn an_attribute_block_is_bounded_too() -> Result<(), Box<dyn Error>> {
        let mut attributes = CredentialAttributes::new(stamp()?);
        for index in 0..MAX_BLOCK_FIELDS {
            attributes = attributes.text(format!("f{index}"), "v")?;
        }
        assert!(matches!(
            attributes.text("one_more", "v"),
            Err(CredentialError::BlockTooLarge {
                block: CredentialBlock::Attributes,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn a_registry_identifier_round_trips_through_its_text() -> Result<(), Box<dyn Error>> {
        let registry = RegistryIdentifier::from_qb64(REGISTRY)?;
        assert_eq!(registry.qb64()?, REGISTRY);
        assert_eq!(registry.prefix(), &IdentifierPrefix::from_qb64(REGISTRY)?);
        assert_eq!(
            RegistryIdentifier::from(IdentifierPrefix::from_qb64(REGISTRY)?),
            registry
        );
        assert!(matches!(
            RegistryIdentifier::from_qb64("not a registry"),
            Err(CredentialError::Prefix { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_block_names_itself_in_its_failures() {
        for (block, label, name) in [
            (CredentialBlock::Attributes, ATTRIBUTES_LABEL, "attribute"),
            (CredentialBlock::Edges, EDGES_LABEL, "edge"),
            (CredentialBlock::Rules, RULES_LABEL, "rule"),
        ] {
            assert_eq!(block.label(), label);
            assert_eq!(block.name(), name);
            assert_eq!(block.to_string(), name);
        }
    }

    #[test]
    fn every_failure_describes_itself_without_repeating_secret_material() {
        let failures: Vec<CredentialError> = vec![
            CredentialError::ReservedLabel {
                block: CredentialBlock::Attributes,
                label: SAID_LABEL,
            },
            CredentialError::TypedLabel {
                block: CredentialBlock::Attributes,
                label: ISSUEE_LABEL.to_owned(),
            },
            CredentialError::ArrayIndexLabel {
                block: CredentialBlock::Edges,
                label: "0".to_owned(),
            },
            CredentialError::DuplicateLabel {
                block: CredentialBlock::Rules,
                label: "LEI".to_owned(),
            },
            CredentialError::LabelTooLong {
                block: CredentialBlock::Attributes,
                maximum: MAX_LABEL_BYTES,
                actual: MAX_LABEL_BYTES + 1,
            },
            CredentialError::BlockTooLarge {
                block: CredentialBlock::Edges,
                maximum: MAX_BLOCK_FIELDS,
            },
            CredentialError::BlockTooDeep {
                block: CredentialBlock::Rules,
                maximum: MAX_BLOCK_DEPTH,
            },
            CredentialError::EmptyNonce,
            CredentialError::NonceTooLong {
                maximum: MAX_NONCE_BYTES,
                actual: MAX_NONCE_BYTES + 1,
            },
        ];
        for failure in &failures {
            let rendered = failure.to_string();
            assert_ne!(rendered, "");
            assert!(!rendered.contains("  "), "{rendered}");
            // Only labels and bounds are quoted; no value ever is.
            assert!(!rendered.contains("5493001KJTIIGC8Y1R17"));
            assert!(failure.source().is_none());
        }

        // The layered variants preserve their source chain.
        let layered = CredentialError::from(SadError::DuplicateField { label: "d".to_owned() });
        assert!(layered.source().is_some());
        assert!(layered.to_string().starts_with("field assembly failed"));
    }

    #[test]
    fn the_pinned_constants_are_the_references_own() {
        assert_eq!(UNSIZED_VERSION_STRING, "ACDC10JSON000000_");
        assert_eq!(UNSIZED_VERSION_STRING.len(), 17);
        assert_eq!(DIGEST_ALGORITHM, DigestAlgorithm::Blake3_256);
        assert_eq!(ATTRIBUTES_LABEL, "a");
        assert_eq!(EDGES_LABEL, "e");
        assert_eq!(RULES_LABEL, "r");
        assert_eq!(NONCE_LABEL, "u");
        assert_eq!(REGISTRY_LABEL, "ri");
        assert_eq!(SCHEMA_LABEL, "s");
        assert_eq!(ISSUEE_LABEL, "i");
        assert_eq!(TIMESTAMP_LABEL, "dt");
    }

    #[test]
    fn the_array_index_rule_matches_the_ecmascript_one() {
        for hoisted in ["0", "9", "10", "999", "4294967294"] {
            assert!(is_array_index_label(hoisted), "{hoisted}");
        }
        for ordinary in [
            "",
            "01",
            "007",
            "-0",
            "-1",
            "+1",
            "1.0",
            "0x1",
            "1e3",
            " 0",
            "0 ",
            "4294967295",
            "4294967296",
            "99999999999",
            "d",
            "LEI",
        ] {
            assert!(!is_array_index_label(ordinary), "{ordinary}");
        }
    }

    #[test]
    fn the_attribute_block_reports_what_it_will_serialize() -> Result<(), Box<dyn Error>> {
        let attributes = attributes()?;
        assert_eq!(attributes.stamp().as_str(), STAMP);
        assert_eq!(attributes.labels(), ["d", "i", "dt", "LEI"]);
        let credential = CredentialBuilder::new(
            IdentifierPrefix::from_qb64(ISSUER)?,
            RegistryIdentifier::from_qb64(REGISTRY)?,
            Said::from_qb64(SCHEMA)?,
            attributes,
        )
        .build()?;
        let serialized: Vec<&str> = credential
            .attributes()
            .ok_or("no attribute block")?
            .entries()
            .map(|(label, _)| label)
            .collect();
        assert_eq!(serialized, ["d", "i", "dt", "LEI"]);
        Ok(())
    }

    #[test]
    fn a_credential_splits_into_its_parts() -> Result<(), Box<dyn Error>> {
        let credential = builder()?.build()?;
        let raw = credential.raw().to_vec();
        let (said, attributes_said) = (credential.said(), credential.attributes_said());
        let (serialized, split_said, split_attributes) = credential.into_parts();
        assert_eq!(serialized.raw(), raw);
        assert_eq!(split_said, said);
        assert_eq!(split_attributes, attributes_said);
        Ok(())
    }
}
