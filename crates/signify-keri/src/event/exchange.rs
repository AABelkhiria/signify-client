//! Exchange (`exn`) messages.
//!
//! An exchange message is how one controller sends another a routed, self-addressing payload:
//! multisig coordination, IPEX credential negotiation, and anything else that travels between
//! agents rather than into a key event log. Besides its own attributes it may carry *embedded*
//! messages — an inception event, a credential, a TEL event — and, for each embed, the CESR
//! attachments that authorise it.
//!
//! Those attachments cannot simply be concatenated, because the embed no longer sits at the top of
//! a stream: each one is *transposed* by prefixing it with the attachment path naming the field it
//! belongs to (`-e-<label>`) and wrapping the result in a pathed-material counter. The builder
//! therefore produces two things — the serialized `exn` and a separate transposed attachment
//! stream — which the sender concatenates after its own signatures.
//!
//! This module ports the pure `exchange(...)` function of `src/keri/app/exchanging.ts`. The
//! `Exchanges` class around it is transport, and belongs to Roadmap 7.7; the typed route table is
//! Roadmap 8.1.

use signify_cesr::counter::{Counter, CounterCode};
use signify_cesr::path::{PathComponent, SadPath};
use signify_crypto::digest::DigestAlgorithm;

use crate::event::error::{EventError, bounded_label};
use crate::event::inception::ANCHORS_LABEL;
use crate::event::kind::EventKind;
use crate::event::reply::{MAX_ROUTE_BYTES, ROUTE_LABEL, TIMESTAMP_LABEL};
use crate::event::timestamp::Timestamp;
use crate::prefix::IdentifierPrefix;
use crate::said::{DEFAULT_SAID_LABEL, Said};
use crate::serialization::{IDENTIFIER_LABEL, KIND_LABEL, SAID_LABEL, Sad, SadValue, SerializedEvent, VERSION_LABEL};

/// Field label naming the message's recipient.
pub const RECIPIENT_LABEL: &str = "rp";
/// Field label carrying the prior exchange message's identifier.
pub const PRIOR_LABEL: &str = "p";
/// Field label carrying route modifiers.
pub const MODIFIERS_LABEL: &str = "q";
/// Field label carrying the block of embedded messages.
pub const EMBEDS_LABEL: &str = "e";

/// Largest embed label this builder accepts, in bytes.
///
/// The reference imposes no bound. Every label it uses is a three- or four-character message kind
/// such as `acdc` or `icp`; this ceiling exists because the label is written into an attachment
/// path, where an unbounded one would inflate every transposed group.
pub const MAX_EMBED_LABEL_BYTES: usize = 64;

/// One message embedded in an exchange, with the attachments that authorise it.
///
/// The embedded message is written into the exchange's `e` block under `label`, and its
/// attachments — if any — are transposed into the exchange's attachment stream under the path
/// `-e-<label>`.
///
/// The label is validated as an attachment-path component at construction, so a label that would
/// produce an ambiguous or unencodable path cannot reach a message. The reference validates only
/// when an attachment is present, and its `-` check happens too late to matter: a label such as
/// `a-b` yields the path `-e-a-b`, which parses back as three components naming a different field
/// entirely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExchangeEmbed {
    label: String,
    sad: Sad,
    attachment: Option<Vec<u8>>,
}

impl ExchangeEmbed {
    /// Embeds `event` under `label`, with no attachments.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::EmbedLabelTooLong`] above [`MAX_EMBED_LABEL_BYTES`],
    /// [`EventError::ReservedEmbedLabel`] for the identifier and version labels, which the embeds
    /// block writes itself, and [`EventError::InvalidEmbedLabel`] for a label that is not a usable
    /// attachment-path component.
    pub fn new(label: impl Into<String>, event: &SerializedEvent) -> Result<Self, EventError> {
        let label = label.into();
        if label.len() > MAX_EMBED_LABEL_BYTES {
            return Err(EventError::EmbedLabelTooLong { length: label.len() });
        }
        // `d` holds the embeds block's own SAID; a `v` at that level makes the block look like a
        // versioned message to the sizing step.
        for reserved in [DEFAULT_SAID_LABEL, VERSION_LABEL] {
            if label == reserved {
                return Err(EventError::ReservedEmbedLabel { label: reserved });
            }
        }
        PathComponent::field(&label).map_err(|source| EventError::InvalidEmbedLabel {
            label: bounded_label(&label),
            source: Box::new(source),
        })?;
        Ok(Self {
            label,
            sad: event.sad().clone(),
            attachment: None,
        })
    }

    /// Attaches the CESR material that authorises this embed.
    ///
    /// The attachment is the raw group stream — indexed signatures, seals, receipt couples — as a
    /// [`SignedMessage`](crate::attachment::SignedMessage)'s
    /// [`attachments`](crate::attachment::SignedMessage::attachments) half produces it.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::NonIntegralAttachment`] unless the attachment is a whole number of
    /// quadlets, [`EventError::InvalidAttachmentText`] for a byte outside the CESR text domain,
    /// and [`EventError::AttachmentTooLarge`] when the transposed group would need more quadlets
    /// than its counter can express.
    pub fn with_attachment(mut self, attachment: impl Into<Vec<u8>>) -> Result<Self, EventError> {
        let attachment = attachment.into();
        // Validate eagerly so an unusable attachment is rejected where it is supplied rather than
        // at build time.
        transpose(&self.label, &attachment)?;
        self.attachment = Some(attachment);
        Ok(self)
    }

    /// Returns the field label this message is embedded under.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Borrows the embedded message's fields.
    #[must_use]
    pub const fn sad(&self) -> &Sad {
        &self.sad
    }

    /// Returns the attachments authorising this embed, if any.
    #[must_use]
    pub fn attachment(&self) -> Option<&[u8]> {
        self.attachment.as_deref()
    }
}

/// A finished, serialized exchange message and its transposed attachments.
///
/// The two halves stay separate: the reference returns them as a pair, and the sender signs the
/// serialized message but appends the transposed stream after those signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExchangeMessage {
    serialized: SerializedEvent,
    said: Said,
    attachments: Vec<u8>,
}

impl ExchangeMessage {
    /// Returns the exact serialized message bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.serialized.raw()
    }

    /// Borrows the ordered message fields.
    #[must_use]
    pub const fn sad(&self) -> &Sad {
        self.serialized.sad()
    }

    /// Borrows the serialized message, for version-string and parsing access.
    #[must_use]
    pub const fn serialized(&self) -> &SerializedEvent {
        &self.serialized
    }

    /// Returns the message's self-addressing identifier.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the transposed attachment stream, empty when no embed carried attachments.
    ///
    /// These are *not* the sender's own signatures over this message. They authorise the embedded
    /// messages, and are appended after the sender's signature groups.
    #[must_use]
    pub fn attachments(&self) -> &[u8] {
        &self.attachments
    }

    /// Returns the route this message is addressed to.
    #[must_use]
    pub fn route(&self) -> Option<&str> {
        self.sad().get_text(ROUTE_LABEL)
    }

    /// Returns the qualified sender identifier.
    #[must_use]
    pub fn sender(&self) -> Option<&str> {
        self.sad().get_text(IDENTIFIER_LABEL)
    }

    /// Returns the qualified recipient identifier.
    #[must_use]
    pub fn recipient(&self) -> Option<&str> {
        self.sad().get_text(RECIPIENT_LABEL)
    }

    /// Splits the message into its serialized event and transposed attachments.
    #[must_use]
    pub fn into_parts(self) -> (SerializedEvent, Vec<u8>) {
        (self.serialized, self.attachments)
    }
}

/// Builds an exchange (`exn`) message.
///
/// ```
/// use signify_keri::event::exchange::ExchangeBuilder;
/// use signify_keri::event::timestamp::Timestamp;
/// use signify_keri::prefix::IdentifierPrefix;
/// use signify_keri::serialization::{Sad, SadValue};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let sender = IdentifierPrefix::from_qb64("EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL")?;
/// let recipient = IdentifierPrefix::from_qb64("EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj")?;
///
/// let mut payload = Sad::new();
/// payload.insert("m", SadValue::text(""))?;
///
/// let message = ExchangeBuilder::new(
///     "/ipex/apply",
///     sender,
///     recipient,
///     "2023-08-30T17:22:54.183000+00:00".parse::<Timestamp>()?,
/// )
/// .payload(payload)
/// .build()?;
///
/// assert_eq!(message.route(), Some("/ipex/apply"));
/// assert_eq!(
///     message.recipient(),
///     Some("EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj"),
/// );
/// // Nothing is embedded, so there is nothing to transpose.
/// assert!(message.attachments().is_empty());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ExchangeBuilder {
    route: String,
    sender: IdentifierPrefix,
    recipient: IdentifierPrefix,
    timestamp: Timestamp,
    prior: Option<Said>,
    payload: Sad,
    modifiers: Sad,
    embeds: Vec<ExchangeEmbed>,
}

impl ExchangeBuilder {
    /// Starts an exchange message from `sender` to `recipient`, stamped at `timestamp`.
    ///
    /// All four are required. The reference takes the sender and recipient as free text and
    /// defaults the timestamp to the system clock; here they are the validated types the protocol
    /// means, and a caller that wants "now" formats it and parses a [`Timestamp`].
    ///
    /// The route is a plain string because the typed route table — the multisig and IPEX
    /// constants — is Roadmap 8.1.
    #[must_use]
    pub fn new(
        route: impl Into<String>,
        sender: IdentifierPrefix,
        recipient: IdentifierPrefix,
        timestamp: Timestamp,
    ) -> Self {
        Self {
            route: route.into(),
            sender,
            recipient,
            timestamp,
            prior: None,
            payload: Sad::new(),
            modifiers: Sad::new(),
            embeds: Vec::new(),
        }
    }

    /// Names the exchange message this one replies to.
    ///
    /// IPEX chains its steps this way: an offer names the apply it answers, an agree names the
    /// offer, and so on. Absent by default, written as an empty field.
    #[must_use]
    pub const fn prior(mut self, prior: Said) -> Self {
        self.prior = Some(prior);
        self
    }

    /// Sets the message's attributes; empty by default.
    ///
    /// The recipient is written into this block first, so the payload may not carry the
    /// identifier label itself.
    #[must_use]
    pub fn payload(mut self, payload: Sad) -> Self {
        self.payload = payload;
        self
    }

    /// Sets the route modifiers; empty by default.
    #[must_use]
    pub fn modifiers(mut self, modifiers: Sad) -> Self {
        self.modifiers = modifiers;
        self
    }

    /// Sets the embedded messages, in the order they are written.
    #[must_use]
    pub fn embeds(mut self, embeds: Vec<ExchangeEmbed>) -> Self {
        self.embeds = embeds;
        self
    }

    /// Validates the inputs, derives both identifiers, and serializes the message.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::RouteTooLong`] for a route above [`MAX_ROUTE_BYTES`],
    /// [`EventError::PayloadOverridesRecipient`] for a payload carrying the identifier label,
    /// [`EventError::DuplicateEmbedLabel`] for repeated embeds, the attachment failures listed on
    /// [`ExchangeEmbed::with_attachment`], and layered [`EventError::Said`], [`EventError::Sad`],
    /// [`EventError::Prefix`], [`EventError::Cesr`], or [`EventError::Serialization`] failures for
    /// material that cannot be encoded.
    pub fn build(self) -> Result<ExchangeMessage, EventError> {
        if self.route.len() > MAX_ROUTE_BYTES {
            return Err(EventError::RouteTooLong {
                length: self.route.len(),
            });
        }
        // The reference spreads the payload over the recipient it just wrote, so a payload field
        // silently replaces the addressee the attribute block names.
        if self.payload.contains(IDENTIFIER_LABEL) {
            return Err(EventError::PayloadOverridesRecipient {
                label: IDENTIFIER_LABEL,
            });
        }

        let (embeds, attachments) = self.build_embeds()?;
        let recipient = self.recipient.qb64().map_err(EventError::prefix)?;

        let mut attributes = Sad::new();
        attributes
            .insert(IDENTIFIER_LABEL, SadValue::text(recipient.clone()))
            .map_err(EventError::sad)?;
        for (label, value) in self.payload.entries() {
            attributes
                .insert(label.to_owned(), value.clone())
                .map_err(EventError::sad)?;
        }

        let prior = match self.prior {
            Some(said) => said.qb64().map_err(EventError::said)?,
            None => String::new(),
        };

        let mut fields = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            fields.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        insert(VERSION_LABEL, SadValue::text("KERI10JSON000000_"))?;
        insert(KIND_LABEL, SadValue::text(EventKind::Exchange.as_str()))?;
        insert(SAID_LABEL, SadValue::text(""))?;
        insert(
            IDENTIFIER_LABEL,
            SadValue::Text(self.sender.qb64().map_err(EventError::prefix)?),
        )?;
        insert(RECIPIENT_LABEL, SadValue::Text(recipient))?;
        insert(PRIOR_LABEL, SadValue::Text(prior))?;
        insert(TIMESTAMP_LABEL, SadValue::Text(self.timestamp.into_string()))?;
        insert(ROUTE_LABEL, SadValue::Text(self.route))?;
        insert(MODIFIERS_LABEL, SadValue::Map(self.modifiers))?;
        insert(ANCHORS_LABEL, SadValue::Map(attributes))?;
        insert(EMBEDS_LABEL, SadValue::Map(embeds))?;

        let computation =
            Said::compute(&fields, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL).map_err(EventError::said)?;
        let (said, completed) = computation.into_parts();
        let serialized = SerializedEvent::from_sad(completed).map_err(EventError::serialization)?;
        Ok(ExchangeMessage {
            serialized,
            said,
            attachments,
        })
    }

    /// Builds the embeds block and the transposed attachment stream together.
    ///
    /// A nonempty block carries its own SAID in a trailing identifier field, exactly as the
    /// reference appends one after the embeds themselves.
    fn build_embeds(&self) -> Result<(Sad, Vec<u8>), EventError> {
        let mut block = Sad::new();
        let mut attachments = Vec::new();
        for embed in &self.embeds {
            block
                .insert(embed.label.clone(), SadValue::Map(embed.sad.clone()))
                .map_err(|_| EventError::DuplicateEmbedLabel {
                    label: bounded_label(&embed.label),
                })?;
            if let Some(attachment) = &embed.attachment {
                attachments.extend_from_slice(&transpose(&embed.label, attachment)?);
            }
        }
        if block.is_empty() {
            return Ok((block, attachments));
        }
        block
            .insert(DEFAULT_SAID_LABEL, SadValue::text(""))
            .map_err(EventError::sad)?;
        let computation =
            Said::compute(&block, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL).map_err(EventError::said)?;
        Ok((computation.into_parts().1, attachments))
    }
}

/// Returns whether a byte belongs to the CESR text domain, the unpadded URL-safe Base64 alphabet.
const fn is_cesr_text(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// Transposes one embed's attachments: the pathed-material counter, the attachment path naming the
/// embed's field, then the attachment itself.
fn transpose(label: &str, attachment: &[u8]) -> Result<Vec<u8>, EventError> {
    if !attachment.len().is_multiple_of(4) {
        return Err(EventError::NonIntegralAttachment {
            label: bounded_label(label),
            length: attachment.len(),
        });
    }
    if let Some(offset) = attachment.iter().position(|byte| !is_cesr_text(*byte)) {
        return Err(EventError::InvalidAttachmentText {
            label: bounded_label(label),
            offset,
        });
    }

    let path = SadPath::from_components([EMBEDS_LABEL, label]).map_err(|source| EventError::InvalidEmbedLabel {
        label: bounded_label(label),
        source: Box::new(source),
    })?;
    let mut pathed = path.qb64_bytes().map_err(EventError::cesr)?;
    pathed.extend_from_slice(attachment);

    let code = CounterCode::PATHED_MATERIAL_QUADLETS;
    // Both lengths are quadlet-aligned, so the division is exact.
    let quadlets = pathed.len() / 4;
    let count = u32::try_from(quadlets)
        .ok()
        .filter(|count| *count <= code.maximum_count())
        .ok_or_else(|| EventError::AttachmentTooLarge {
            label: bounded_label(label),
            quadlets,
        })?;
    let mut group = Counter::new(code, count)
        .and_then(Counter::qb64_bytes)
        .map_err(EventError::cesr)?;
    group.extend_from_slice(&pathed);
    Ok(group)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::said::SaidVerification;
    use std::error::Error;

    const SENDER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
    const RECIPIENT: &str = "EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj";
    const STAMP: &str = "2023-08-30T17:22:54.183000+00:00";
    /// A registry-inception event with the shape the pinned `test/app/exchanging.test.ts` embeds.
    const VCP: &str = r#"{"v":"KERI10JSON000049_","t":"vcp","d":"","i":"","s":"0","bt":"0","b":[]}"#;
    /// A controller signature group, as `SignedMessage::attachments` produces one.
    const ATTACHMENT: &str =
        "-AABAAAPkMTS3LrrhVuQB0k4UndDN0xIfEiKYaN7rTlQ_q9ImnBcugwNO8VWTALXzWoaldJEC1IOpEGkEnjZfxxIleoI";

    fn sender() -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(SENDER)?)
    }

    fn recipient() -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(RECIPIENT)?)
    }

    fn stamp() -> Result<Timestamp, Box<dyn Error>> {
        Ok(Timestamp::parse(STAMP)?)
    }

    fn builder() -> Result<ExchangeBuilder, Box<dyn Error>> {
        Ok(ExchangeBuilder::new("/multisig/vcp", sender()?, recipient()?, stamp()?))
    }

    fn embedded() -> Result<SerializedEvent, Box<dyn Error>> {
        Ok(SerializedEvent::parse(VCP.as_bytes())?)
    }

    #[test]
    fn field_order_is_the_protocol_order() -> Result<(), Box<dyn Error>> {
        let message = builder()?.build()?;
        let labels: Vec<&str> = message.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["v", "t", "d", "i", "rp", "p", "dt", "r", "q", "a", "e"]);
        assert_eq!(message.sad().get_text("t"), Some("exn"));
        assert_eq!(message.sender(), Some(SENDER));
        assert_eq!(message.recipient(), Some(RECIPIENT));
        assert_eq!(message.route(), Some("/multisig/vcp"));
        Ok(())
    }

    #[test]
    fn the_recipient_is_written_into_the_attributes() -> Result<(), Box<dyn Error>> {
        let mut payload = Sad::new();
        payload.insert("m", SadValue::text("hello"))?;
        let message = builder()?.payload(payload).build()?;

        let attributes = message
            .sad()
            .get("a")
            .and_then(SadValue::as_map)
            .ok_or("no attributes")?;
        // The recipient comes first, then the payload in its own order.
        let labels: Vec<&str> = attributes.entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["i", "m"]);
        assert_eq!(attributes.get_text("i"), Some(RECIPIENT));
        Ok(())
    }

    #[test]
    fn a_payload_may_not_replace_the_recipient() -> Result<(), Box<dyn Error>> {
        // Upstream the payload is spread over the recipient, so this field silently readdresses
        // the attribute block while `rp` still names someone else.
        let mut payload = Sad::new();
        payload.insert("i", SadValue::text("EOTHERTHANTHERECIPIENT"))?;
        assert!(matches!(
            builder()?.payload(payload).build(),
            Err(EventError::PayloadOverridesRecipient { label: "i" })
        ));
        Ok(())
    }

    #[test]
    fn an_absent_prior_is_an_empty_field() -> Result<(), Box<dyn Error>> {
        let without = builder()?.build()?;
        assert_eq!(without.sad().get_text("p"), Some(""));

        let prior = Said::from_qb64(RECIPIENT)?;
        let with = builder()?.prior(prior).build()?;
        assert_eq!(with.sad().get_text("p"), Some(RECIPIENT));
        assert_ne!(with.said(), without.said());
        Ok(())
    }

    #[test]
    fn modifiers_and_embeds_default_to_empty_blocks() -> Result<(), Box<dyn Error>> {
        let message = builder()?.build()?;
        assert!(core::str::from_utf8(message.raw())?.contains(r#""q":{}"#));
        assert!(core::str::from_utf8(message.raw())?.contains(r#""e":{}"#));
        // An empty embeds block carries no SAID of its own, as upstream.
        let embeds = message.sad().get("e").and_then(SadValue::as_map).ok_or("no embeds")?;
        assert!(embeds.is_empty());
        assert!(message.attachments().is_empty());
        Ok(())
    }

    #[test]
    fn an_embeds_block_carries_its_own_identifier_last() -> Result<(), Box<dyn Error>> {
        let event = embedded()?;
        let message = builder()?.embeds(vec![ExchangeEmbed::new("vcp", &event)?]).build()?;

        let embeds = message.sad().get("e").and_then(SadValue::as_map).ok_or("no embeds")?;
        let labels: Vec<&str> = embeds.entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["vcp", "d"]);

        // The block's identifier commits to the block, and the embedded event survives untouched.
        let claimed = Said::from_qb64(embeds.get_text("d").ok_or("no embeds identifier")?)?;
        claimed.verify(embeds, DEFAULT_SAID_LABEL, SaidVerification::strict())?;
        let carried = embeds.get("vcp").and_then(SadValue::as_map).ok_or("no embed")?;
        assert_eq!(carried.to_json_bytes()?, event.raw());
        Ok(())
    }

    #[test]
    fn an_attachment_is_transposed_under_its_embed_path() -> Result<(), Box<dyn Error>> {
        let event = embedded()?;
        let message = builder()?
            .embeds(vec![
                ExchangeEmbed::new("vcp", &event)?.with_attachment(ATTACHMENT.as_bytes())?,
            ])
            .build()?;

        // Counter, path, then the attachment verbatim.
        assert_eq!(
            core::str::from_utf8(message.attachments())?,
            format!("-LAa5AACAA-e-vcp{ATTACHMENT}")
        );
        assert!(message.attachments().len().is_multiple_of(4));
        Ok(())
    }

    #[test]
    fn embeds_without_attachments_transpose_nothing() -> Result<(), Box<dyn Error>> {
        let event = embedded()?;
        let message = builder()?
            .embeds(vec![
                ExchangeEmbed::new("one", &event)?,
                ExchangeEmbed::new("two", &event)?.with_attachment(ATTACHMENT.as_bytes())?,
            ])
            .build()?;

        let embeds = message.sad().get("e").and_then(SadValue::as_map).ok_or("no embeds")?;
        let labels: Vec<&str> = embeds.entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["one", "two", "d"]);
        // Only the second embed contributes a group.
        assert_eq!(
            core::str::from_utf8(message.attachments())?,
            format!("-LAa5AACAA-e-two{ATTACHMENT}")
        );
        Ok(())
    }

    #[test]
    fn an_empty_attachment_still_transposes_its_path() -> Result<(), Box<dyn Error>> {
        // The reference's guard is `atc == undefined`, so an empty attachment writes the path with
        // nothing after it; the behavior is reproduced because a group naming a field with no
        // material is harmless and the bytes must match.
        let event = embedded()?;
        let message = builder()?
            .embeds(vec![ExchangeEmbed::new("vcp", &event)?.with_attachment(Vec::new())?])
            .build()?;
        assert_eq!(core::str::from_utf8(message.attachments())?, "-LAD5AACAA-e-vcp");
        Ok(())
    }

    #[test]
    fn embed_labels_are_validated_as_path_components() -> Result<(), Box<dyn Error>> {
        let event = embedded()?;
        // `-` separates path components, so upstream `a-b` yields a path naming `e`, `a`, `b`.
        assert!(matches!(
            ExchangeEmbed::new("a-b", &event),
            Err(EventError::InvalidEmbedLabel { .. })
        ));
        assert!(matches!(
            ExchangeEmbed::new("a/b", &event),
            Err(EventError::InvalidEmbedLabel { .. })
        ));
        assert!(matches!(
            ExchangeEmbed::new("", &event),
            Err(EventError::InvalidEmbedLabel { .. })
        ));
        // A purely numeric label is an ordinal in a path, and JavaScript hoists it ahead of the
        // other fields, so the reference's own byte order would differ from the insertion order.
        assert!(matches!(
            ExchangeEmbed::new("0", &event),
            Err(EventError::InvalidEmbedLabel { .. })
        ));
        assert!(matches!(
            ExchangeEmbed::new(DEFAULT_SAID_LABEL, &event),
            Err(EventError::ReservedEmbedLabel { label: "d" })
        ));
        assert!(matches!(
            ExchangeEmbed::new(VERSION_LABEL, &event),
            Err(EventError::ReservedEmbedLabel { label: "v" })
        ));
        assert!(matches!(
            ExchangeEmbed::new("a".repeat(MAX_EMBED_LABEL_BYTES + 1), &event),
            Err(EventError::EmbedLabelTooLong { length }) if length == MAX_EMBED_LABEL_BYTES + 1
        ));
        // The bound itself is accepted.
        ExchangeEmbed::new("a".repeat(MAX_EMBED_LABEL_BYTES), &event)?;
        Ok(())
    }

    #[test]
    fn a_repeated_embed_label_is_refused() -> Result<(), Box<dyn Error>> {
        let event = embedded()?;
        assert!(matches!(
            builder()?
                .embeds(vec![
                    ExchangeEmbed::new("vcp", &event)?,
                    ExchangeEmbed::new("vcp", &event)?,
                ])
                .build(),
            Err(EventError::DuplicateEmbedLabel { label }) if label == "vcp"
        ));
        Ok(())
    }

    #[test]
    fn attachments_are_bounded_and_quadlet_aligned() -> Result<(), Box<dyn Error>> {
        let event = embedded()?;
        let embed = ExchangeEmbed::new("vcp", &event)?;

        // The reference divides by four and rounds down, leaving the remainder outside the count.
        assert!(matches!(
            embed.clone().with_attachment(b"-AAB-AABAB".to_vec()),
            Err(EventError::NonIntegralAttachment { label, length: 10 }) if label == "vcp"
        ));
        // The stream is CESR text; anything else would be injected into it verbatim.
        assert!(matches!(
            embed.clone().with_attachment(br#"{"a":1}!"#.to_vec()),
            Err(EventError::InvalidAttachmentText { label, offset: 0 }) if label == "vcp"
        ));
        assert!(matches!(
            embed.clone().with_attachment(b"-AAB\n\n\n\n".to_vec()),
            Err(EventError::InvalidAttachmentText { offset: 4, .. })
        ));

        // The path occupies three of the counter's 4095 quadlets.
        let widest = vec![b'A'; (4095 - 3) * 4];
        assert!(embed.clone().with_attachment(widest).is_ok());
        let overlong = vec![b'A'; (4096 - 3) * 4];
        assert!(matches!(
            embed.with_attachment(overlong),
            Err(EventError::AttachmentTooLarge { quadlets: 4096, .. })
        ));
        Ok(())
    }

    #[test]
    fn a_route_is_bounded() -> Result<(), Box<dyn Error>> {
        builder()?;
        let longest = "/".repeat(MAX_ROUTE_BYTES);
        ExchangeBuilder::new(longest, sender()?, recipient()?, stamp()?).build()?;
        let overlong = "/".repeat(MAX_ROUTE_BYTES + 1);
        assert!(matches!(
            ExchangeBuilder::new(overlong, sender()?, recipient()?, stamp()?).build(),
            Err(EventError::RouteTooLong { length }) if length == MAX_ROUTE_BYTES + 1
        ));
        Ok(())
    }

    #[test]
    fn the_finished_message_is_self_consistent() -> Result<(), Box<dyn Error>> {
        let event = embedded()?;
        let message = builder()?
            .embeds(vec![
                ExchangeEmbed::new("vcp", &event)?.with_attachment(ATTACHMENT.as_bytes())?,
            ])
            .build()?;

        assert_eq!(message.serialized().size(), message.raw().len());
        assert_eq!(SerializedEvent::parse(message.raw())?.sad(), message.sad());
        message
            .said()
            .verify(message.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())?;
        assert_eq!(message.sad().get_text("dt"), Some(STAMP));

        let (serialized, attachments) = message.clone().into_parts();
        assert_eq!(serialized.raw(), message.raw());
        assert_eq!(attachments, message.attachments());
        Ok(())
    }

    #[test]
    fn embed_accessors_report_what_was_supplied() -> Result<(), Box<dyn Error>> {
        let event = embedded()?;
        let bare = ExchangeEmbed::new("vcp", &event)?;
        assert_eq!(bare.label(), "vcp");
        assert_eq!(bare.sad(), event.sad());
        assert_eq!(bare.attachment(), None);

        let attached = bare.with_attachment(ATTACHMENT.as_bytes())?;
        assert_eq!(attached.attachment(), Some(ATTACHMENT.as_bytes()));
        Ok(())
    }

    #[test]
    fn errors_carry_readable_text_and_sources() {
        for error in [
            EventError::PayloadOverridesRecipient { label: "i" },
            EventError::DuplicateEmbedLabel {
                label: "vcp".to_owned(),
            },
            EventError::ReservedEmbedLabel { label: "d" },
            EventError::EmbedLabelTooLong { length: 99 },
            EventError::NonIntegralAttachment {
                label: "vcp".to_owned(),
                length: 7,
            },
            EventError::InvalidAttachmentText {
                label: "vcp".to_owned(),
                offset: 3,
            },
            EventError::AttachmentTooLarge {
                label: "vcp".to_owned(),
                quadlets: 4096,
            },
        ] {
            assert!(!error.to_string().is_empty());
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn error_labels_are_bounded() -> Result<(), Box<dyn Error>> {
        // Labels come from the caller, so a long one is truncated before it reaches an error.
        let long = "a".repeat(MAX_EMBED_LABEL_BYTES);
        let event = embedded()?;
        match builder()?
            .embeds(vec![
                ExchangeEmbed::new(long.clone(), &event)?,
                ExchangeEmbed::new(long, &event)?,
            ])
            .build()
        {
            Err(EventError::DuplicateEmbedLabel { label }) => assert_eq!(label.chars().count(), 32),
            other => return Err(format!("unexpected result {other:?}").into()),
        }
        Ok(())
    }
}
