//! CESR attachments.
//!
//! A KERI message travels as its serialized event followed by a CESR attachment stream: counted
//! groups of signatures, and seals binding those signatures to the establishment event that
//! authorises them. This module composes that stream and keeps the boundary between the two
//! halves, so a caller can hand the event to a verifier and the attachments to a parser
//! separately.
//!
//! It ports `messagize` from `src/keri/core/eventing.ts` together with the two seal-source
//! serializers in `src/keri/core/utils.ts`.
//!
//! # References
//!
//! Controller signature groups, both seal kinds, seal-source couples/triples, and pipelined
//! framing are verified against the pinned `signify-ts` reference. Witness indexed-signature
//! groups and non-transferable receipt couples are verified against the pinned `keripy` reference
//! instead (ADR 0009): the TypeScript paths for both are unreachable — they guard with
//! `!(verfer.code in NonTransDex)`, and because JavaScript's `in` tests an object's *property
//! keys* rather than its values, every signature carrying a verifier is rejected — and both write
//! the controller counter rather than their own. keripy's `messagize` implements both correctly:
//! the witness group is introduced by the `-B` (`WitnessIdxSigs`) counter, the receipt group by
//! `-C` (`NonTransReceiptCouples`) followed by verification-key/signature couples, and a
//! transferable key in either is refused.

use keri_cesr::CesrError;
use keri_cesr::counter::{Counter, CounterCode};
use keri_cesr::crypto::CryptoError;
use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::sequence::SequenceNumber;

use crate::prefix::{IdentifierPrefix, PrefixError};
use crate::said::{Said, SaidError};
use crate::serialization::SerializedEvent;

use core::fmt;
use std::error::Error;

/// Whether an attachment stream is preceded by a total-size counter.
///
/// Pipelining lets a parser skip an entire attachment stream without interpreting it, which is
/// what makes streamed processing possible; it requires the stream to be a whole number of
/// quadlets.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum AttachmentFraming {
    /// Write the attachment groups directly, with no enclosing count.
    #[default]
    Plain,
    /// Prefix the stream with an attached-material quadlet count.
    Pipelined,
}

/// A seal binding attached signatures to the establishment event that authorises them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureSeal {
    /// Names the exact establishment event by identifier, sequence number, and digest.
    ///
    /// Encoded as a transferable indexed-signature group.
    Event {
        /// Identifier whose establishment event authorises the signatures.
        identifier: IdentifierPrefix,
        /// Sequence number of that event.
        sequence_number: SequenceNumber,
        /// Digest of that event.
        said: Said,
    },
    /// Defers to whatever the signer's latest establishment event is.
    ///
    /// Encoded as a transferable last-indexed-signature group.
    Last {
        /// Identifier whose latest establishment event authorises the signatures.
        identifier: IdentifierPrefix,
    },
}

impl SignatureSeal {
    /// Returns the counter code introducing this seal's group.
    #[must_use]
    pub const fn counter_code(&self) -> CounterCode {
        match self {
            Self::Event { .. } => CounterCode::TRANSFERABLE_INDEXED_SIGNATURE_GROUPS,
            Self::Last { .. } => CounterCode::TRANSFERABLE_LAST_INDEXED_SIGNATURE_GROUPS,
        }
    }

    /// Encodes the seal group, without the signatures that follow it.
    fn encode(&self) -> Result<Vec<u8>, AttachmentError> {
        let mut bytes = counter_bytes(self.counter_code(), 1)?;
        match self {
            Self::Event {
                identifier,
                sequence_number,
                said,
            } => {
                bytes.extend_from_slice(identifier.qb64().map_err(AttachmentError::prefix)?.as_bytes());
                bytes.extend_from_slice(&sequence_number.qb64_bytes().map_err(AttachmentError::cesr)?);
                bytes.extend_from_slice(said.qb64().map_err(AttachmentError::said)?.as_bytes());
            }
            Self::Last { identifier } => {
                bytes.extend_from_slice(identifier.qb64().map_err(AttachmentError::prefix)?.as_bytes());
            }
        }
        Ok(bytes)
    }
}

/// A witness or watcher receipt: a non-transferable verification key coupled with its unindexed
/// signature over the event.
///
/// Encoded inside a `NonTransReceiptCouples` (`-C`) group as the key's qualified form followed by
/// the signature's. Construction refuses a transferable key — a receipt is a standalone
/// attestation, so its key must be self-certifying with no rotation history to consult — which is
/// the reference's `messagize`-time `ValueError` moved to where the invalid value would first
/// exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptCouple {
    verifier: VerificationKey,
    signature: UnindexedSignature,
}

impl ReceiptCouple {
    /// Couples a non-transferable verification key with its signature.
    ///
    /// # Errors
    ///
    /// Returns [`AttachmentError::TransferableReceiptKey`] when the key's derivation code is
    /// transferable, and [`AttachmentError::Crypto`] when the signature and key algorithms do not
    /// match.
    pub fn new(verifier: VerificationKey, signature: UnindexedSignature) -> Result<Self, AttachmentError> {
        if verifier.is_transferable() {
            return Err(AttachmentError::TransferableReceiptKey);
        }
        let signature = signature
            .with_verifier(verifier.clone())
            .map_err(AttachmentError::crypto)?;
        Ok(Self { verifier, signature })
    }

    /// Returns the receiptor's verification key.
    #[must_use]
    pub const fn verifier(&self) -> &VerificationKey {
        &self.verifier
    }

    /// Returns the receiptor's signature.
    #[must_use]
    pub const fn signature(&self) -> &UnindexedSignature {
        &self.signature
    }

    /// Encodes the couple: the qualified key followed by the qualified signature.
    fn encode_into(&self, bytes: &mut Vec<u8>) -> Result<(), AttachmentError> {
        bytes.extend_from_slice(&self.verifier.qb64_bytes().map_err(AttachmentError::crypto)?);
        bytes.extend_from_slice(&self.signature.qb64_bytes().map_err(AttachmentError::crypto)?);
        Ok(())
    }
}

/// A reference to the event that authorised something, without naming its identifier.
///
/// Used where the identifier is already unambiguous from context, as it is for a credential's
/// issuance event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealSourceCouple {
    sequence_number: SequenceNumber,
    said: Said,
}

impl SealSourceCouple {
    /// Builds a couple naming the anchoring event's position and digest.
    #[must_use]
    pub const fn new(sequence_number: SequenceNumber, said: Said) -> Self {
        Self { sequence_number, said }
    }

    /// Returns the anchoring event's sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }

    /// Returns the anchoring event's digest.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Encodes this couple as a complete attachment stream.
    ///
    /// The reference's `serializeIssExnAttachment` is this with
    /// [`AttachmentFraming::Pipelined`]; its `serializeACDCAttachment` uses a triple with
    /// [`AttachmentFraming::Plain`]. Framing is an explicit choice here rather than being baked
    /// into two differently named functions.
    ///
    /// # Errors
    ///
    /// Returns [`AttachmentError::NonIntegralQuadlets`] if a pipelined stream is not a whole
    /// number of quadlets, and layered failures for material that cannot be encoded.
    pub fn attachment(&self, framing: AttachmentFraming) -> Result<Vec<u8>, AttachmentError> {
        let mut bytes = counter_bytes(CounterCode::SEAL_SOURCE_COUPLES, 1)?;
        bytes.extend_from_slice(&self.sequence_number.qb64_bytes().map_err(AttachmentError::cesr)?);
        bytes.extend_from_slice(self.said.qb64().map_err(AttachmentError::said)?.as_bytes());
        frame(bytes, framing)
    }
}

/// A reference to the event that authorised something, naming its identifier as well.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealSourceTriple {
    identifier: IdentifierPrefix,
    sequence_number: SequenceNumber,
    said: Said,
}

impl SealSourceTriple {
    /// Builds a triple naming the anchoring event's identifier, position, and digest.
    #[must_use]
    pub const fn new(identifier: IdentifierPrefix, sequence_number: SequenceNumber, said: Said) -> Self {
        Self {
            identifier,
            sequence_number,
            said,
        }
    }

    /// Returns the anchoring identifier.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the anchoring event's sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }

    /// Returns the anchoring event's digest.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Encodes this triple as a complete attachment stream.
    ///
    /// # Errors
    ///
    /// Returns [`AttachmentError::NonIntegralQuadlets`] if a pipelined stream is not a whole
    /// number of quadlets, and layered failures for material that cannot be encoded.
    pub fn attachment(&self, framing: AttachmentFraming) -> Result<Vec<u8>, AttachmentError> {
        let mut bytes = counter_bytes(CounterCode::SEAL_SOURCE_TRIPLES, 1)?;
        bytes.extend_from_slice(self.identifier.qb64().map_err(AttachmentError::prefix)?.as_bytes());
        bytes.extend_from_slice(&self.sequence_number.qb64_bytes().map_err(AttachmentError::cesr)?);
        bytes.extend_from_slice(self.said.qb64().map_err(AttachmentError::said)?.as_bytes());
        frame(bytes, framing)
    }
}

/// A serialized event together with its CESR attachments.
///
/// The boundary between the two is retained, so a caller can verify the event and parse the
/// attachments independently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedMessage {
    bytes: Vec<u8>,
    event_length: usize,
}

impl SignedMessage {
    /// Returns the complete message: event followed by attachments.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns just the serialized event.
    #[must_use]
    pub fn event(&self) -> &[u8] {
        self.bytes.get(..self.event_length).unwrap_or_default()
    }

    /// Returns just the CESR attachment stream.
    #[must_use]
    pub fn attachments(&self) -> &[u8] {
        self.bytes.get(self.event_length..).unwrap_or_default()
    }

    /// Consumes the message, returning its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Attaches signatures and seals to a serialized event.
///
/// ```
/// use keri_cesr::crypto::digest::Digest;
/// use keri_cesr::crypto::signature::IndexedSignature;
/// use keri_cesr::crypto::verifier::VerificationKey;
/// use signify_keri::attachment::SignedMessageBuilder;
/// use signify_keri::event::inception::InceptionBuilder;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let key = VerificationKey::from_qb64("DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH")?;
/// let next = Digest::from_qb64("EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W")?;
/// let event = InceptionBuilder::new(vec![key]).next_key_digests(vec![next]).build()?;
///
/// let signature = IndexedSignature::from_qb64(
///     "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I",
/// )?;
/// let message = SignedMessageBuilder::new(event.serialized())
///     .controller_signatures(vec![signature])
///     .build()?;
///
/// // The event and its attachments stay separable.
/// assert_eq!(message.event(), event.raw());
/// assert!(message.attachments().starts_with(b"-AAB"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct SignedMessageBuilder<'a> {
    event: &'a SerializedEvent,
    controller_signatures: Vec<IndexedSignature>,
    witness_signatures: Vec<IndexedSignature>,
    receipt_couples: Vec<ReceiptCouple>,
    seal: Option<SignatureSeal>,
    framing: AttachmentFraming,
}

impl<'a> SignedMessageBuilder<'a> {
    /// Starts a message from a serialized event.
    #[must_use]
    pub const fn new(event: &'a SerializedEvent) -> Self {
        Self {
            event,
            controller_signatures: Vec::new(),
            witness_signatures: Vec::new(),
            receipt_couples: Vec::new(),
            seal: None,
            framing: AttachmentFraming::Plain,
        }
    }

    /// Attaches the controller's indexed signatures.
    ///
    /// At least one signature of some kind — controller, witness, or receipt — is required: an
    /// unsigned message asserts nothing.
    #[must_use]
    pub fn controller_signatures(mut self, signatures: Vec<IndexedSignature>) -> Self {
        self.controller_signatures = signatures;
        self
    }

    /// Attaches witness indexed signatures, written as a `WitnessIdxSigs` (`-B`) group.
    ///
    /// A witness signature's index names its position in the event's witness list. A signature
    /// carrying a transferable verifier is refused at [`build`](Self::build): a witness is
    /// identified by a self-certifying, non-transferable key.
    #[must_use]
    pub fn witness_signatures(mut self, signatures: Vec<IndexedSignature>) -> Self {
        self.witness_signatures = signatures;
        self
    }

    /// Attaches non-transferable receipt couples, written as a `NonTransReceiptCouples` (`-C`)
    /// group.
    #[must_use]
    pub fn receipt_couples(mut self, couples: Vec<ReceiptCouple>) -> Self {
        self.receipt_couples = couples;
        self
    }

    /// Binds the signatures to the establishment event that authorises them.
    #[must_use]
    pub fn seal(mut self, seal: SignatureSeal) -> Self {
        self.seal = Some(seal);
        self
    }

    /// Chooses whether the attachment stream carries a total-size counter.
    #[must_use]
    pub const fn framing(mut self, framing: AttachmentFraming) -> Self {
        self.framing = framing;
        self
    }

    /// Composes the message.
    ///
    /// Groups are written in the reference order: the controller group (preceded by its seal, if
    /// any), then witness signatures, then receipt couples.
    ///
    /// # Errors
    ///
    /// Returns [`AttachmentError::MissingSignatures`] when no signature of any kind was attached,
    /// [`AttachmentError::SealWithoutControllerSignatures`] when a seal has no controller group to
    /// bind, [`AttachmentError::TransferableWitnessKey`] when a witness signature carries a
    /// transferable verifier, [`AttachmentError::TooManySignatures`] when a count exceeds what a
    /// counter can express, [`AttachmentError::NonIntegralQuadlets`] when a pipelined stream is
    /// not a whole number of quadlets, and layered failures for material that cannot be encoded.
    pub fn build(self) -> Result<SignedMessage, AttachmentError> {
        if self.controller_signatures.is_empty()
            && self.witness_signatures.is_empty()
            && self.receipt_couples.is_empty()
        {
            return Err(AttachmentError::MissingSignatures);
        }
        // The reference silently drops a seal when there are no controller signatures to bind it
        // to; a silently missing authorization is refused here instead.
        if self.seal.is_some() && self.controller_signatures.is_empty() {
            return Err(AttachmentError::SealWithoutControllerSignatures);
        }

        let mut attachments = Vec::new();
        if !self.controller_signatures.is_empty() {
            if let Some(seal) = &self.seal {
                attachments = seal.encode()?;
            }
            attachments.extend_from_slice(&counter_bytes(
                CounterCode::CONTROLLER_INDEXED_SIGNATURES,
                checked_count(self.controller_signatures.len())?,
            )?);
            for signature in &self.controller_signatures {
                attachments.extend_from_slice(&signature.qb64_bytes().map_err(AttachmentError::crypto)?);
            }
        }

        if !self.witness_signatures.is_empty() {
            attachments.extend_from_slice(&counter_bytes(
                CounterCode::WITNESS_INDEXED_SIGNATURES,
                checked_count(self.witness_signatures.len())?,
            )?);
            for (index, signature) in self.witness_signatures.iter().enumerate() {
                if signature.verifier().is_some_and(VerificationKey::is_transferable) {
                    return Err(AttachmentError::TransferableWitnessKey { index });
                }
                attachments.extend_from_slice(&signature.qb64_bytes().map_err(AttachmentError::crypto)?);
            }
        }

        if !self.receipt_couples.is_empty() {
            attachments.extend_from_slice(&counter_bytes(
                CounterCode::NON_TRANSFERABLE_RECEIPT_COUPLES,
                checked_count(self.receipt_couples.len())?,
            )?);
            for couple in &self.receipt_couples {
                couple.encode_into(&mut attachments)?;
            }
        }

        let attachments = frame(attachments, self.framing)?;
        let event = self.event.raw();
        let mut bytes = Vec::with_capacity(event.len().saturating_add(attachments.len()));
        bytes.extend_from_slice(event);
        bytes.extend_from_slice(&attachments);
        Ok(SignedMessage {
            bytes,
            event_length: event.len(),
        })
    }
}

/// Converts a group's element count into counter range.
fn checked_count(count: usize) -> Result<u32, AttachmentError> {
    u32::try_from(count).map_err(|_| AttachmentError::TooManySignatures { count })
}

/// Encodes one counter as qualified Base64 bytes.
fn counter_bytes(code: CounterCode, count: u32) -> Result<Vec<u8>, AttachmentError> {
    if count > code.maximum_count() {
        return Err(AttachmentError::TooManySignatures { count: count as usize });
    }
    Counter::new(code, count)
        .and_then(Counter::qb64_bytes)
        .map_err(AttachmentError::cesr)
}

/// Applies the requested framing to a finished attachment stream.
fn frame(attachments: Vec<u8>, framing: AttachmentFraming) -> Result<Vec<u8>, AttachmentError> {
    match framing {
        AttachmentFraming::Plain => Ok(attachments),
        AttachmentFraming::Pipelined => {
            if !attachments.len().is_multiple_of(4) {
                return Err(AttachmentError::NonIntegralQuadlets {
                    length: attachments.len(),
                });
            }
            let quadlets = u32::try_from(attachments.len() / 4).map_err(|_| AttachmentError::TooManySignatures {
                count: attachments.len(),
            })?;
            let mut framed = counter_bytes(CounterCode::ATTACHED_MATERIAL_QUADLETS, quadlets)?;
            framed.extend_from_slice(&attachments);
            Ok(framed)
        }
    }
}

/// Stable CESR attachment failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum AttachmentError {
    /// A message was composed with no signatures attached.
    MissingSignatures,
    /// More signatures or quadlets than a counter can express.
    TooManySignatures {
        /// Rejected count.
        count: usize,
    },
    /// A pipelined attachment stream is not a whole number of quadlets.
    NonIntegralQuadlets {
        /// Stream length in bytes.
        length: usize,
    },
    /// A seal was set with no controller signatures to bind it to.
    ///
    /// The reference silently drops the seal in this case; that loses the authorization binding,
    /// so it is refused here instead.
    SealWithoutControllerSignatures,
    /// A witness signature carries a transferable verifier.
    TransferableWitnessKey {
        /// Position of the rejected signature in the witness group.
        index: usize,
    },
    /// A receipt couple was given a transferable verification key.
    TransferableReceiptKey,
    /// Identifier-prefix material could not be encoded.
    Prefix {
        /// Underlying prefix failure.
        source: Box<PrefixError>,
    },
    /// Self-addressing-identifier material could not be encoded.
    Said {
        /// Underlying identifier failure.
        source: Box<SaidError>,
    },
    /// Signature material could not be encoded.
    Crypto {
        /// Underlying cryptographic failure.
        source: Box<CryptoError>,
    },
    /// Counter or sequence material could not be encoded.
    Cesr {
        /// Underlying encoding failure.
        source: Box<CesrError>,
    },
}

impl AttachmentError {
    fn prefix(source: PrefixError) -> Self {
        Self::Prefix {
            source: Box::new(source),
        }
    }

    fn said(source: SaidError) -> Self {
        Self::Said {
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

impl fmt::Display for AttachmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSignatures => formatter.write_str("a message needs at least one attached signature"),
            Self::TooManySignatures { count } => {
                write!(formatter, "count {count} exceeds what a CESR counter can express")
            }
            Self::NonIntegralQuadlets { length } => write!(
                formatter,
                "pipelined attachments of {length} bytes are not a whole number of quadlets"
            ),
            Self::SealWithoutControllerSignatures => formatter.write_str("a seal needs controller signatures to bind"),
            Self::TransferableWitnessKey { index } => write!(
                formatter,
                "witness signature {index} carries a transferable verifier; a witness key must be non-transferable"
            ),
            Self::TransferableReceiptKey => {
                formatter.write_str("a receipt couple needs a non-transferable verification key")
            }
            Self::Prefix { .. } => formatter.write_str("identifier prefix material is invalid"),
            Self::Said { .. } => formatter.write_str("self-addressing identifier material is invalid"),
            Self::Crypto { .. } => formatter.write_str("signature material is invalid"),
            Self::Cesr { .. } => formatter.write_str("qualified material is invalid"),
        }
    }
}

impl Error for AttachmentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Prefix { source } => Some(source.as_ref()),
            Self::Said { source } => Some(source.as_ref()),
            Self::Crypto { source } => Some(source.as_ref()),
            Self::Cesr { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// The inception event and signature from the pinned `test/core/eventing.test.ts`.
    const EVENT: &str = concat!(
        r#"{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","#,
        r#""i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,"#,
        r#""k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,"#,
        r#""n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}"#
    );
    const SIGNATURE: &str = "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I";
    const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";

    /// Witness material from `fixtures/keri-attachment-keripy/v1.json` (seed bytes `0..31`).
    const WITNESS_KEY: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const TRANSFERABLE_KEY: &str = "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const WITNESS_SIGNATURE: &str =
        "AACeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";
    const RECEIPT_SIGNATURE: &str =
        "0BCeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";

    fn event() -> Result<SerializedEvent, Box<dyn Error>> {
        Ok(SerializedEvent::parse(EVENT.as_bytes())?)
    }

    fn signature() -> Result<IndexedSignature, Box<dyn Error>> {
        Ok(IndexedSignature::from_qb64(SIGNATURE)?)
    }

    fn identifier() -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(IDENTIFIER)?)
    }

    fn said() -> Result<Said, Box<dyn Error>> {
        Ok(Said::from_qb64(IDENTIFIER)?)
    }

    #[test]
    fn a_signed_message_is_the_event_followed_by_its_attachments() -> Result<(), Box<dyn Error>> {
        let event = event()?;
        let message = SignedMessageBuilder::new(&event)
            .controller_signatures(vec![signature()?])
            .build()?;

        assert_eq!(message.event(), event.raw());
        assert_eq!(core::str::from_utf8(message.attachments())?, format!("-AAB{SIGNATURE}"));
        assert_eq!([message.event(), message.attachments()].concat(), message.as_bytes());
        assert_eq!(message.clone().into_bytes(), message.as_bytes());
        Ok(())
    }

    #[test]
    fn a_message_needs_at_least_one_signature() -> Result<(), Box<dyn Error>> {
        let event = event()?;
        assert!(matches!(
            SignedMessageBuilder::new(&event).build(),
            Err(AttachmentError::MissingSignatures)
        ));
        assert!(matches!(
            SignedMessageBuilder::new(&event)
                .controller_signatures(Vec::new())
                .build(),
            Err(AttachmentError::MissingSignatures)
        ));
        Ok(())
    }

    #[test]
    fn the_signature_counter_tracks_the_signature_count() -> Result<(), Box<dyn Error>> {
        let event = event()?;
        for count in 1_usize..=4 {
            let message = SignedMessageBuilder::new(&event)
                .controller_signatures(core::iter::repeat_n(signature()?, count).collect())
                .build()?;
            let attachments = core::str::from_utf8(message.attachments())?;
            // Counts are Base64: 1 is B, 2 is C, and so on.
            let expected = ['A', 'B', 'C', 'D', 'E'].get(count).copied().unwrap_or('?');
            assert!(
                attachments.starts_with(&format!("-AA{expected}")),
                "count {count} produced {}",
                attachments.get(..8).unwrap_or_default()
            );
            assert_eq!(attachments.matches(SIGNATURE).count(), count);
        }
        Ok(())
    }

    #[test]
    fn seals_are_written_before_the_signatures_they_authorise() -> Result<(), Box<dyn Error>> {
        let event = event()?;
        let with_event_seal = SignedMessageBuilder::new(&event)
            .controller_signatures(vec![signature()?])
            .seal(SignatureSeal::Event {
                identifier: identifier()?,
                sequence_number: SequenceNumber::new(0),
                said: said()?,
            })
            .build()?;
        let attachments = core::str::from_utf8(with_event_seal.attachments())?;
        assert!(attachments.starts_with(&format!("-FAB{IDENTIFIER}0AAAAAAAAAAAAAAAAAAAAAAA{IDENTIFIER}-AAB")));

        let with_last_seal = SignedMessageBuilder::new(&event)
            .controller_signatures(vec![signature()?])
            .seal(SignatureSeal::Last {
                identifier: identifier()?,
            })
            .build()?;
        assert!(core::str::from_utf8(with_last_seal.attachments())?.starts_with(&format!("-HAB{IDENTIFIER}-AAB")));

        assert_eq!(
            SignatureSeal::Last {
                identifier: identifier()?
            }
            .counter_code(),
            CounterCode::TRANSFERABLE_LAST_INDEXED_SIGNATURE_GROUPS
        );
        Ok(())
    }

    #[test]
    fn a_seal_commits_to_the_sequence_number_it_was_given() -> Result<(), Box<dyn Error>> {
        // The reference reads this field with `parseInt`, so hexadecimal `a` becomes zero and `10`
        // becomes ten; a typed sequence number cannot be misread.
        let event = event()?;
        let encode = |value: u128| -> Result<String, Box<dyn Error>> {
            let message = SignedMessageBuilder::new(&event)
                .controller_signatures(vec![signature()?])
                .seal(SignatureSeal::Event {
                    identifier: identifier()?,
                    sequence_number: SequenceNumber::new(value),
                    said: said()?,
                })
                .build()?;
            Ok(core::str::from_utf8(message.attachments())?.to_owned())
        };
        let (zero, ten, sixteen) = (encode(0)?, encode(10)?, encode(16)?);
        assert_ne!(zero, ten);
        assert_ne!(ten, sixteen);
        assert_eq!(zero.len(), ten.len());
        Ok(())
    }

    #[test]
    fn pipelining_prefixes_a_quadlet_count() -> Result<(), Box<dyn Error>> {
        let event = event()?;
        let plain = SignedMessageBuilder::new(&event)
            .controller_signatures(vec![signature()?])
            .build()?;
        let pipelined = SignedMessageBuilder::new(&event)
            .controller_signatures(vec![signature()?])
            .framing(AttachmentFraming::Pipelined)
            .build()?;

        let plain_attachments = plain.attachments();
        let pipelined_attachments = core::str::from_utf8(pipelined.attachments())?;
        assert!(pipelined_attachments.starts_with("-VAX"));
        // The count covers exactly the plain stream that follows it.
        assert!(pipelined_attachments.ends_with(core::str::from_utf8(plain_attachments)?));
        assert!(plain_attachments.len().is_multiple_of(4));
        assert_eq!(pipelined.attachments().len(), plain_attachments.len() + 4);
        assert_eq!(AttachmentFraming::default(), AttachmentFraming::Plain);
        Ok(())
    }

    #[test]
    fn seal_sources_encode_their_own_groups() -> Result<(), Box<dyn Error>> {
        let couple = SealSourceCouple::new(SequenceNumber::new(1), said()?);
        assert_eq!(couple.sequence_number(), SequenceNumber::new(1));
        assert_eq!(couple.said(), said()?);
        let encoded = couple.attachment(AttachmentFraming::Plain)?;
        assert!(core::str::from_utf8(&encoded)?.starts_with("-GAB"));

        let triple = SealSourceTriple::new(identifier()?, SequenceNumber::new(1), said()?);
        assert_eq!(triple.identifier(), &identifier()?);
        assert_eq!(triple.sequence_number(), SequenceNumber::new(1));
        assert_eq!(triple.said(), said()?);
        let encoded = triple.attachment(AttachmentFraming::Plain)?;
        assert!(core::str::from_utf8(&encoded)?.starts_with(&format!("-IAB{IDENTIFIER}")));

        // A triple names the identifier a couple leaves to context, so it is exactly one
        // qualified prefix longer.
        assert_eq!(
            triple.attachment(AttachmentFraming::Plain)?.len(),
            couple.attachment(AttachmentFraming::Plain)?.len() + IDENTIFIER.len()
        );
        Ok(())
    }

    #[test]
    fn every_encoded_group_is_a_whole_number_of_quadlets() -> Result<(), Box<dyn Error>> {
        // This is what makes pipelining possible, so it is worth asserting directly.
        let couple = SealSourceCouple::new(SequenceNumber::new(7), said()?);
        let triple = SealSourceTriple::new(identifier()?, SequenceNumber::new(7), said()?);
        for encoded in [
            couple.attachment(AttachmentFraming::Plain)?,
            triple.attachment(AttachmentFraming::Plain)?,
            couple.attachment(AttachmentFraming::Pipelined)?,
            triple.attachment(AttachmentFraming::Pipelined)?,
        ] {
            assert!(encoded.len().is_multiple_of(4), "group is not quadlet-aligned");
        }
        Ok(())
    }

    #[test]
    fn errors_carry_sources_and_readable_text() {
        for error in [
            AttachmentError::MissingSignatures,
            AttachmentError::TooManySignatures { count: 9 },
            AttachmentError::NonIntegralQuadlets { length: 7 },
            AttachmentError::SealWithoutControllerSignatures,
            AttachmentError::TransferableWitnessKey { index: 2 },
            AttachmentError::TransferableReceiptKey,
        ] {
            assert_ne!(error.to_string(), "");
            assert!(error.source().is_none());
        }
    }

    fn witness_signature() -> Result<IndexedSignature, Box<dyn Error>> {
        Ok(IndexedSignature::from_qb64(WITNESS_SIGNATURE)?.with_verifier(VerificationKey::from_qb64(WITNESS_KEY)?)?)
    }

    fn receipt_couple() -> Result<ReceiptCouple, Box<dyn Error>> {
        Ok(ReceiptCouple::new(
            VerificationKey::from_qb64(WITNESS_KEY)?,
            UnindexedSignature::from_qb64(RECEIPT_SIGNATURE)?,
        )?)
    }

    #[test]
    fn witness_signatures_form_their_own_counted_group() -> Result<(), Box<dyn Error>> {
        let event = event()?;
        let message = SignedMessageBuilder::new(&event)
            .witness_signatures(vec![witness_signature()?])
            .build()?;
        assert_eq!(
            core::str::from_utf8(message.attachments())?,
            format!("-BAB{WITNESS_SIGNATURE}")
        );

        let two = SignedMessageBuilder::new(&event)
            .witness_signatures(vec![witness_signature()?, witness_signature()?])
            .build()?;
        assert!(two.attachments().starts_with(b"-BAC"));
        Ok(())
    }

    #[test]
    fn a_witness_signature_may_omit_its_verifier_but_not_carry_a_transferable_one() -> Result<(), Box<dyn Error>> {
        let event = event()?;
        // Without a verifier there is nothing to test, as in the reference.
        let bare = IndexedSignature::from_qb64(WITNESS_SIGNATURE)?;
        assert!(
            SignedMessageBuilder::new(&event)
                .witness_signatures(vec![bare])
                .build()
                .is_ok()
        );

        let transferable = IndexedSignature::from_qb64(WITNESS_SIGNATURE)?
            .with_verifier(VerificationKey::from_qb64(TRANSFERABLE_KEY)?)?;
        assert!(matches!(
            SignedMessageBuilder::new(&event)
                .witness_signatures(vec![witness_signature()?, transferable])
                .build(),
            Err(AttachmentError::TransferableWitnessKey { index: 1 })
        ));
        Ok(())
    }

    #[test]
    fn receipt_couples_write_the_key_then_the_signature() -> Result<(), Box<dyn Error>> {
        let event = event()?;
        let couple = receipt_couple()?;
        assert_eq!(couple.verifier().qb64()?, WITNESS_KEY);
        assert_eq!(couple.signature().qb64()?, RECEIPT_SIGNATURE);

        let message = SignedMessageBuilder::new(&event)
            .receipt_couples(vec![couple])
            .build()?;
        assert_eq!(
            core::str::from_utf8(message.attachments())?,
            format!("-CAB{WITNESS_KEY}{RECEIPT_SIGNATURE}")
        );
        Ok(())
    }

    #[test]
    fn a_receipt_couple_refuses_a_transferable_key() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            ReceiptCouple::new(
                VerificationKey::from_qb64(TRANSFERABLE_KEY)?,
                UnindexedSignature::from_qb64(RECEIPT_SIGNATURE)?,
            ),
            Err(AttachmentError::TransferableReceiptKey)
        ));
        Ok(())
    }

    #[test]
    fn groups_are_written_controller_then_witness_then_receipt() -> Result<(), Box<dyn Error>> {
        let event = event()?;
        let message = SignedMessageBuilder::new(&event)
            .controller_signatures(vec![signature()?])
            .witness_signatures(vec![witness_signature()?])
            .receipt_couples(vec![receipt_couple()?])
            .build()?;
        assert_eq!(
            core::str::from_utf8(message.attachments())?,
            format!("-AAB{SIGNATURE}-BAB{WITNESS_SIGNATURE}-CAB{WITNESS_KEY}{RECEIPT_SIGNATURE}")
        );
        Ok(())
    }

    #[test]
    fn a_seal_needs_a_controller_group_to_bind() -> Result<(), Box<dyn Error>> {
        // The reference silently drops the seal here; losing an authorization binding silently is
        // refused instead.
        let event = event()?;
        assert!(matches!(
            SignedMessageBuilder::new(&event)
                .witness_signatures(vec![witness_signature()?])
                .seal(SignatureSeal::Last {
                    identifier: identifier()?,
                })
                .build(),
            Err(AttachmentError::SealWithoutControllerSignatures)
        ));
        Ok(())
    }
}
