//! The exchange endpoint: peer-to-peer messages handed to the agent for delivery.
//!
//! An `exn` is how one controller says something to another that is not a key event — propose a
//! multisig inception, answer a challenge, disclose a credential. This family builds one, signs it
//! with the sender's own keeper, posts it for delivery, and reads one back by SAID.
//!
//! This ports the `Exchanges` class of the pinned `src/keri/app/exchanging.ts`. The message itself
//! is Roadmap 3.8's [`ExchangeBuilder`], already byte-exact; what is new here is the signing, the
//! request body, and the two addresses. The IPEX specialisation of the same composition is Roadmap
//! 6.3's `signify_keys::acdc::ipex`, and the typed route table over `/multisig/*` and `/ipex/*` is
//! Roadmap 8.1's — so a route is borrowed text here, exactly as [`ExchangeBuilder`] leaves it.
//!
//! # The addressee is not the delivery list
//!
//! An `exn` names **one** addressee, in its own `rp` and `a.i` fields. Upstream `send` takes a list
//! and loops over it — but `return`s inside the loop, so only the first pass ever runs: the message
//! is addressed to `recipients[0]` and then delivered to every recipient. The reference's own
//! `test-integration/multisig.test.ts` calls it that way eighteen times, so every member but the
//! first is handed a message addressed to somebody else.
//!
//! Here the two are separate: [`ExchangeDraft`] carries the addressee and [`Exchanges::send`] takes
//! the delivery list. The reference's behaviour is still expressible — address it to one member and
//! deliver to all — but a caller has to write it down rather than get it by accident.
//!
//! # One alias, not two identifiers
//!
//! Upstream `send(name, topic, sender, …)` posts under `/identifiers/{name}/exchanges` while
//! signing with `sender`'s keeper, and nothing compares them. Roadmap 3.10 signs `@path`, so the
//! resource, the signing key, and the message's own `i` field can all disagree. Here the alias is
//! the only identifier argument and the record is looked up from it, so they agree by construction.
//!
//! # The answer has two declared types upstream
//!
//! `sendFromEvents` declares `Promise<Exn>`; the sibling `Ipex.submit*` methods declare
//! `Promise<ExchangeOperation>` for the same shape of POST to the same agent. Both are unchecked
//! `res.json()` casts, so at most one is right and the pinned tree settles nothing — its only unit
//! case ignores the answer. [`SentExchange`] therefore keeps the body and offers a decoder for each
//! shape rather than imposing one; `PORTING.md` §10 raised the question for Roadmap 9.2.
//!
//! **Roadmap 9.2c answered it against a deployment: both paths answer with an operation.** So
//! `sendFromEvents`'s `Promise<Exn>` is the wrong one, and [`SentExchange::operation`] is the
//! decoder a real agent justifies. Keeping both is now shown to be necessary rather than merely
//! cautious — a single declared return type would have been wrong for one of the two endpoints, and
//! which one is not something the reference's own tree could have told anybody.
//!
//! # The route table and the classifiers
//!
//! Roadmap 8.1 adds the other half of `exchanging.ts` beside this family: [`route`] holds the
//! thirteen-route table and [`message`] the classifier that replaces the reference's thirteen type
//! guards and thirteen assertions. Both are re-exported here, so a caller who reads a message with
//! [`Exchanges::get`] can classify it without a second import.
//!
//! See `fixtures/client-exchanges/` and `fixtures/client-exchange-routes/`.

pub mod message;
pub mod route;

pub use message::{
    ClassifiedExchange, GROUP_LABEL, GroupAttributes, IpexPayload, IpexStep, MultisigProposal, OfferedCredential,
    ROTATION_MEMBERS_LABEL, SIGNING_MEMBERS_LABEL, USAGE_LABEL,
};
pub use route::{ExchangeRoute, MultisigRoute, UnknownExchangeRoute};

use keri_protocol::event::exchange::{ExchangeBuilder, ExchangeEmbed, ExchangeMessage};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::{ExchangeOperation, ExchangeRecord, ExchangeResource, Hab};
use signify_http::request::ResourcePath;
use signify_http::transport::Method;
use signify_keys::manager::{ManagedSignatures, SignatureForm, SigningPurpose};

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::body::{sad_error, text_array};
use crate::endpoint::decode_json;
use crate::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use crate::error::ClientError;

/// Path segment the exchange resources live under.
///
/// The same word addresses two different things upstream: `/identifiers/{name}/exchanges` is where
/// a message is submitted, and `/exchanges/{said}` is where one is read back.
pub const EXCHANGES_SEGMENT: &str = "exchanges";

/// Notification topic the reference files multisig coordination under.
pub const MULTISIG_TOPIC: &str = "multisig";

/// Notification topic the reference files registry coordination under.
pub const REGISTRY_TOPIC: &str = "registry";

/// An exchange message that has not been signed yet.
///
/// This is the argument list of the reference's `createExchangeMessage`, minus the sender — which
/// is not the caller's to state here, because it is derived from the alias the message is posted
/// under. It mirrors Roadmap 3.8's [`ExchangeBuilder`] with that one field removed.
///
/// The timestamp is **required**. The reference passes none from `send`, so `exchange(...)` reads
/// the system clock and the message's `dt` — and therefore its SAID and every signature over it —
/// depends on when it was built. That is the decision Roadmap 3.8 took for the builder itself and
/// Roadmap 4.6 for the authorization replies.
///
/// Modifiers (`q`) are deliberately absent: the reference's own wrapper passes `undefined` and has
/// no way to set them. A caller who needs them builds the message with [`ExchangeBuilder`] directly
/// and signs it with [`Exchanges::create_message`]'s sibling path.
///
/// ```
/// use signify_client::endpoint::exchanges::ExchangeDraft;
/// use keri_protocol::prefix::IdentifierPrefix;
/// use keri_protocol::serialization::{Sad, SadValue};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let addressee = IdentifierPrefix::from_qb64("EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p")?;
/// let mut payload = Sad::new();
/// payload.insert(
///     "words",
///     SadValue::Array(vec![SadValue::text("shell"), SadValue::text("gloom")]),
/// )?;
///
/// let draft = ExchangeDraft::new(
///     "/challenge/response",
///     addressee,
///     "2023-11-14T22:13:20.123000+00:00".parse()?,
/// )
/// .payload(payload);
///
/// assert_eq!(draft.route(), "/challenge/response");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ExchangeDraft {
    route: String,
    addressee: IdentifierPrefix,
    timestamp: Timestamp,
    payload: Sad,
    embeds: Vec<ExchangeEmbed>,
    prior: Option<Said>,
}

impl ExchangeDraft {
    /// Starts a message on `route`, addressed to `addressee`, stamped at `timestamp`.
    #[must_use]
    pub fn new(route: impl Into<String>, addressee: IdentifierPrefix, timestamp: Timestamp) -> Self {
        Self {
            route: route.into(),
            addressee,
            timestamp,
            payload: Sad::new(),
            embeds: Vec::new(),
            prior: None,
        }
    }

    /// Sets the message's attributes; empty by default.
    ///
    /// The addressee is written into this block first, so the payload may not carry the identifier
    /// label itself — [`ExchangeBuilder`] refuses it.
    #[must_use]
    pub fn payload(mut self, payload: Sad) -> Self {
        self.payload = payload;
        self
    }

    /// Sets the messages embedded in this one, with their attachments; none by default.
    #[must_use]
    pub fn embeds(mut self, embeds: Vec<ExchangeEmbed>) -> Self {
        self.embeds = embeds;
        self
    }

    /// Names the exchange message this one replies to; absent by default.
    #[must_use]
    pub fn prior(mut self, prior: Said) -> Self {
        self.prior = Some(prior);
        self
    }

    /// Returns the route this message is addressed to.
    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    /// Returns the single identifier this message is addressed to.
    ///
    /// This is **not** the delivery list: see [`Exchanges::send`].
    #[must_use]
    pub const fn addressee(&self) -> &IdentifierPrefix {
        &self.addressee
    }
}

/// One exchange message with the sender's signatures over it.
///
/// The reference returns these as a three-element tuple of a `Serder`, a string array, and a
/// string, so a caller can pass `sendFromEvents` a message, somebody else's signatures, and a third
/// party's attachment. Bundling them means they cannot disagree — the decision Roadmap 6.3 took for
/// a grant's three artifacts.
///
/// Not [`Clone`]: [`ManagedSignatures`] deliberately is not, so a signature set has one owner.
#[derive(Debug)]
pub struct SignedExchange {
    exchange: ExchangeMessage,
    signatures: ManagedSignatures,
}

impl SignedExchange {
    /// Borrows the message itself.
    #[must_use]
    pub const fn message(&self) -> &ExchangeMessage {
        &self.exchange
    }

    /// Borrows the sender's signatures over the message bytes.
    #[must_use]
    pub const fn signatures(&self) -> &ManagedSignatures {
        &self.signatures
    }

    /// Returns the message's self-addressing identifier.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.exchange.said()
    }

    /// Returns the route the message carries.
    #[must_use]
    pub fn route(&self) -> Option<&str> {
        self.exchange.route()
    }

    /// Returns the transposed attachment stream the embeds produced, which may be empty.
    #[must_use]
    pub fn attachments(&self) -> &[u8] {
        self.exchange.attachments()
    }

    /// Splits this into its message and its signatures.
    #[must_use]
    pub fn into_parts(self) -> (ExchangeMessage, ManagedSignatures) {
        (self.exchange, self.signatures)
    }
}

/// One submitted exchange message, with the agent's answer.
///
/// The answer is kept as owned bytes because the reference declares **two incompatible types** for
/// it: `sendFromEvents` says `Exn` and `Ipex.submitGrant` says `ExchangeOperation`, for the same
/// shape of POST to the same agent, both unchecked casts. Neither reading is imposed here; a caller
/// decodes the one they expect and a wrong-shaped answer is refused rather than cast.
///
/// Roadmap 9.2c asked a live KERIA, which answers **both** paths with an operation — so
/// [`Self::operation`] is the decoder to reach for, and [`Self::exchange`] is kept for the shape the
/// reference declares rather than for one that has been seen.
#[derive(Clone, Debug)]
pub struct SentExchange {
    response: Vec<u8>,
}

impl SentExchange {
    /// Wraps one write's answer.
    ///
    /// Crate-private: the two endpoints that produce one are Roadmap 7.7's submission and Roadmap
    /// 8.2's group request, which post the same message to different addresses and are declared to
    /// be answered the same way. Sharing the type is what keeps that one decision in one place.
    pub(crate) const fn from_body(response: Vec<u8>) -> Self {
        Self { response }
    }

    /// Returns the agent's answer, unparsed.
    #[must_use]
    pub fn response_body(&self) -> &[u8] {
        &self.response
    }

    /// Reads the answer as the long-running operation that delivers the message.
    ///
    /// This is what the sibling `Ipex.submit*` methods declare, and what every other write in this
    /// crate is answered with.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the answer is not an exchange operation.
    pub fn operation(&self) -> Result<ExchangeOperation, ClientError> {
        decode_json(&self.response)
    }

    /// Reads the answer as an exchange message.
    ///
    /// This is what `sendFromEvents` itself declares — and Roadmap 9.2c found that the declaration
    /// is **wrong**. A live KERIA 1.0.1 answers both this path and `/ipex/{route}` with an
    /// operation, so [`Self::operation`] is the decoder a deployment justifies and this one has
    /// never been observed to succeed against a real agent. It is kept rather than removed: the
    /// reference declares it, the two shapes are disjoint so it cannot silently accept an
    /// operation, and one deployment is evidence about that deployment. See `PORTING.md` §10.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the answer is not an exchange message.
    pub fn exchange(&self) -> Result<ExchangeRecord, ClientError> {
        decode_json(&self.response)
    }
}

/// The exchange endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through. This is the shape Roadmap 6.5 settled for every family.
#[derive(Debug)]
pub struct Exchanges<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Exchanges<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Builds and signs one exchange message on behalf of the identifier `alias` names.
    ///
    /// This is the reference's `createExchangeMessage`. The sender is the identifier the alias
    /// resolves to, and the signature is its keeper's, so the message's `i` field and the key that
    /// signed it are the same identifier by construction.
    ///
    /// Nothing is sent: the message is returned for the caller to submit with
    /// [`Self::send_signed`], hand to a multisig peer, or keep.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Identifiers::get`](crate::endpoint::identifiers::Identifiers::get)
    /// returns, [`ClientError::Manager`] when the record's keeper cannot be rebuilt or cannot sign,
    /// and [`ClientError::Exchange`] when the message cannot be built.
    pub async fn create_message(&self, alias: &str, draft: &ExchangeDraft) -> Result<SignedExchange, ClientError> {
        let record = self.client.identifiers().get(alias).await?;
        let sender = IdentifierPrefix::from_qb64(&record.common.prefix)?;
        let keeper = self.client.keepers().keeper_for(&Hab::Accepted(record.clone()))?;

        let mut builder = ExchangeBuilder::new(
            draft.route.clone(),
            sender,
            draft.addressee.clone(),
            draft.timestamp.clone(),
        )
        .payload(draft.payload.clone())
        .embeds(draft.embeds.clone());
        if let Some(prior) = draft.prior {
            builder = builder.prior(prior);
        }
        let exchange = builder.build()?;
        let signatures = keeper.sign(
            exchange.raw(),
            &SignatureForm::IndexedByPosition,
            SigningPurpose::Current,
        )?;
        Ok(SignedExchange { exchange, signatures })
    }

    /// Builds, signs, and submits one exchange message.
    ///
    /// `recipients` is the **delivery list**, which is not the same as the message's addressee: the
    /// draft names exactly one identifier in the message's own `rp` and `a.i` fields, and this list
    /// says who the agent should hand it to. Upstream the two are conflated — `send` loops over the
    /// recipients but returns on the first pass, addressing the message to `recipients[0]` and
    /// delivering it to all of them — so a multisig sender there tells every member but the first
    /// that the message was for somebody else.
    ///
    /// **The delivery list is not checked against the addressee.** A multisig proposal plausibly
    /// goes to every member while naming one, which is exactly what the reference's own integration
    /// tests do, so the list stays the caller's. What is refused is an **empty** one, which asks the
    /// agent to deliver to nobody.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoExchangeRecipients`] for an empty recipient list and
    /// [`ClientError::EmptyExchangeTopic`] for an empty topic — both checked before anything is
    /// built — plus whatever [`Self::create_message`] and [`Self::send_signed`] return.
    pub async fn send(
        &self,
        alias: &str,
        topic: &str,
        draft: &ExchangeDraft,
        recipients: &[IdentifierPrefix],
    ) -> Result<SentExchange, ClientError> {
        Self::check_submission(topic, recipients)?;
        let message = self.create_message(alias, draft).await?;
        self.send_signed(alias, topic, &message, recipients).await
    }

    /// Submits one already-signed exchange message for delivery.
    ///
    /// This is the reference's `sendFromEvents`, renamed for what it does. `alias` is the
    /// identifier the message is posted under — the same one that signed it, when the message came
    /// from [`Self::create_message`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoExchangeRecipients`] for an empty recipient list,
    /// [`ClientError::EmptyExchangeTopic`] for an empty topic, [`ClientError::Decode`] when the
    /// message's attachment stream is not UTF-8, [`ClientError::Serialization`] when the body
    /// cannot be written, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn send_signed(
        &self,
        alias: &str,
        topic: &str,
        message: &SignedExchange,
        recipients: &[IdentifierPrefix],
    ) -> Result<SentExchange, ClientError> {
        Self::check_submission(topic, recipients)?;

        let mut body = Sad::new();
        body.insert("tpc", topic.to_owned()).map_err(sad_error)?;
        body.insert("exn", SadValue::Map(message.exchange.sad().clone()))
            .map_err(sad_error)?;
        body.insert("sigs", text_array(message.signatures.qb64()?))
            .map_err(sad_error)?;
        body.insert("atc", attachment_text(message)?.to_owned())
            .map_err(sad_error)?;
        let addresses = recipients
            .iter()
            .map(|recipient| Ok(recipient.qb64()?))
            .collect::<Result<Vec<String>, ClientError>>()?;
        body.insert("rec", text_array(addresses)).map_err(sad_error)?;

        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(alias)
            .segment(EXCHANGES_SEGMENT)
            .build()?;
        let request = ClientRequest::new(Method::Post, path).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(request).await?;

        Ok(SentExchange {
            response: response.into_body(),
        })
    }

    /// Reads one exchange message the agent holds, by its SAID.
    ///
    /// The answer carries the message and the attachments transposed under it. The reference
    /// interpolates its argument straight into the path, so a value carrying `/` or `?` addresses
    /// a different resource; here it is Roadmap 3.3's validated [`Said`], which cannot hold one.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the body
    /// is not an exchange resource, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn get(&self, said: &Said) -> Result<ExchangeResource, ClientError> {
        let path = ResourcePath::builder()
            .segment(EXCHANGES_SEGMENT)
            .segment(&said.qb64()?)
            .build()?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode_json(response.body())
    }

    /// Refuses the two empty values the reference sends unchallenged.
    ///
    /// Both are checked before anything is built or signed, so a mistake costs no key derivation.
    fn check_submission(topic: &str, recipients: &[IdentifierPrefix]) -> Result<(), ClientError> {
        if topic.is_empty() {
            return Err(ClientError::EmptyExchangeTopic);
        }
        if recipients.is_empty() {
            return Err(ClientError::NoExchangeRecipients);
        }
        Ok(())
    }
}

/// Reads a message's attachment stream as the text the body carries it as.
///
/// A CESR stream is text by definition and this one was produced by `signify-keys`, so a failure
/// here would be a defect rather than hostile input; it is still typed rather than assumed.
fn attachment_text(message: &SignedExchange) -> Result<&str, ClientError> {
    core::str::from_utf8(message.attachments()).map_err(|error| ClientError::Decode {
        source: Box::new(signify_http::response::ResponseError::NotUtf8 {
            offset: error.valid_up_to(),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
    const RECIPIENT: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
    const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

    fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(text)?)
    }

    fn submission_path(alias: &str) -> Result<ResourcePath, Box<dyn Error>> {
        Ok(ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(alias)
            .segment(EXCHANGES_SEGMENT)
            .build()?)
    }

    fn read_path(said: &Said) -> Result<ResourcePath, Box<dyn Error>> {
        Ok(ResourcePath::builder()
            .segment(EXCHANGES_SEGMENT)
            .segment(&said.qb64()?)
            .build()?)
    }

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(EXCHANGES_SEGMENT, "exchanges");
        assert_eq!(MULTISIG_TOPIC, "multisig");
        assert_eq!(REGISTRY_TOPIC, "registry");
    }

    #[test]
    fn the_submission_addresses_the_pinned_path() -> Result<(), Box<dyn Error>> {
        // Exactly the URL `exchanging.test.ts` and `contacting.test.ts` both assert.
        assert_eq!(submission_path("aid1")?.as_str(), "/identifiers/aid1/exchanges");
        assert_eq!(submission_path("aid1")?.query(), None);
        Ok(())
    }

    #[test]
    fn the_read_addresses_the_pinned_path() -> Result<(), Box<dyn Error>> {
        let said: Said = SAID.parse()?;
        assert_eq!(read_path(&said)?.as_str(), format!("/exchanges/{SAID}"));
        Ok(())
    }

    #[test]
    fn an_alias_can_never_leave_its_own_path_segment() -> Result<(), Box<dyn Error>> {
        // The reference concatenates the alias raw, so `a/b` would address a different resource
        // and change the path Roadmap 3.10 signs.
        let path = submission_path("a/b?c=d")?;
        assert_eq!(path.as_str(), "/identifiers/a%2Fb%3Fc%3Dd/exchanges");
        assert_eq!(path.path().split('/').count(), 4);
        assert_eq!(path.query(), None);
        Ok(())
    }

    #[test]
    fn a_value_that_would_escape_the_read_path_is_not_a_said() {
        // The reference interpolates any string; the recorded `../identifiers/aid1?x=1` reached
        // the wire as three extra segments and a query.
        for hostile in ["../identifiers/aid1?x=1", "", "a/b", "not a said", "EBfdlu8R27Fbx"] {
            assert!(
                hostile.parse::<Said>().is_err(),
                "{hostile:?} was accepted as an exchange SAID"
            );
        }
    }

    #[test]
    fn an_empty_topic_is_refused() -> Result<(), Box<dyn Error>> {
        // The pinned unit test sends `''`, asking the agent to file the notification under no
        // topic at all.
        let recipients = [prefix(RECIPIENT)?];
        assert!(matches!(
            Exchanges::check_submission("", &recipients),
            Err(ClientError::EmptyExchangeTopic)
        ));
        assert!(Exchanges::check_submission(MULTISIG_TOPIC, &recipients).is_ok());
        Ok(())
    }

    #[test]
    fn an_empty_recipient_list_is_refused() -> Result<(), Box<dyn Error>> {
        // `send` throws upstream, and only because its loop cannot run; `sendFromEvents` accepts
        // it, and the pinned unit test sends exactly that.
        assert!(matches!(
            Exchanges::check_submission(MULTISIG_TOPIC, &[]),
            Err(ClientError::NoExchangeRecipients)
        ));
        assert!(Exchanges::check_submission(MULTISIG_TOPIC, &[prefix(RECIPIENT)?]).is_ok());
        Ok(())
    }

    #[test]
    fn the_topic_is_checked_before_the_recipients() {
        // Both are caller mistakes, and the order is fixed so the failure is deterministic.
        assert!(matches!(
            Exchanges::check_submission("", &[]),
            Err(ClientError::EmptyExchangeTopic)
        ));
    }

    #[test]
    fn a_draft_keeps_its_addressee_apart_from_any_delivery_list() -> Result<(), Box<dyn Error>> {
        let draft = ExchangeDraft::new(
            "/multisig/icp",
            prefix(RECIPIENT)?,
            "2023-11-14T22:13:20.123000+00:00".parse()?,
        );
        assert_eq!(draft.route(), "/multisig/icp");
        assert_eq!(draft.addressee(), &prefix(RECIPIENT)?);
        // There is no list on the draft at all: who it is addressed to and who it is delivered to
        // are different arguments in different places.
        Ok(())
    }

    #[test]
    fn a_draft_builds_the_message_the_reference_builds() -> Result<(), Box<dyn Error>> {
        // The same composition `create_message` performs, minus the keeper: this is Roadmap 3.8's
        // builder, so the bytes are already proven.
        let mut payload = Sad::new();
        payload.insert("gid", SadValue::text(SENDER))?;
        let draft = ExchangeDraft::new(
            "/multisig/icp",
            prefix(RECIPIENT)?,
            "2023-11-14T22:13:20.123000+00:00".parse()?,
        )
        .payload(payload);

        let message = ExchangeBuilder::new(
            draft.route.clone(),
            prefix(SENDER)?,
            draft.addressee.clone(),
            draft.timestamp.clone(),
        )
        .payload(draft.payload.clone())
        .build()?;

        assert_eq!(message.route(), Some("/multisig/icp"));
        assert_eq!(message.sender(), Some(SENDER));
        assert_eq!(message.recipient(), Some(RECIPIENT));
        assert_eq!(message.attachments(), b"");
        Ok(())
    }

    #[test]
    fn an_answer_of_either_declared_shape_decodes_and_the_other_is_refused() {
        let operation = br#"{"name":"exchange.E","metadata":{"said":"E"},"done":true,"response":{"said":"E"}}"#;
        let sent = SentExchange {
            response: operation.to_vec(),
        };
        assert!(sent.operation().is_ok());
        // An operation is not an exchange message, and is refused rather than cast.
        assert!(sent.exchange().is_err());
        assert_eq!(sent.response_body(), operation.as_slice());
    }

    #[test]
    fn an_answer_that_is_neither_shape_is_refused_both_ways() {
        for wrong in [&b"{}"[..], b"[]", b"null", br#""text""#, b"7"] {
            let sent = SentExchange {
                response: wrong.to_vec(),
            };
            assert!(sent.operation().is_err(), "{wrong:?} decoded as an operation");
            assert!(sent.exchange().is_err(), "{wrong:?} decoded as an exchange");
        }
    }

    #[test]
    fn an_exchange_answer_decodes_as_an_exchange() -> Result<(), Box<dyn Error>> {
        let exchange = format!(
            r#"{{"v":"KERI10JSON0000bf_","t":"exn","d":"{SAID}","i":"{SENDER}","rp":"{RECIPIENT}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"/multisig/icp","q":{{}},"a":{{"i":"{RECIPIENT}"}},"e":{{}}}}"#
        );
        let sent = SentExchange {
            response: exchange.into_bytes(),
        };
        let decoded = sent.exchange()?;
        assert_eq!(decoded.route, "/multisig/icp");
        assert_eq!(decoded.sender, SENDER);
        // And it is not an operation, so neither reading silently accepts the other's shape.
        assert!(sent.operation().is_err());
        Ok(())
    }

    #[test]
    fn an_exchange_resource_needs_both_of_its_halves() {
        let exn = format!(
            r#"{{"v":"KERI10JSON0000bf_","t":"exn","d":"{SAID}","i":"{SENDER}","rp":"{RECIPIENT}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"/multisig/icp","q":{{}},"a":{{}},"e":{{}}}}"#
        );
        assert!(serde_json::from_str::<ExchangeResource>(&format!(r#"{{"exn":{exn},"pathed":{{}}}}"#)).is_ok());
        // The reference casts each of these to an `ExchangeResourceV1` and hands it over.
        assert!(serde_json::from_str::<ExchangeResource>(&format!(r#"{{"exn":{exn}}}"#)).is_err());
        assert!(serde_json::from_str::<ExchangeResource>(r#"{"pathed":{}}"#).is_err());
        assert!(serde_json::from_str::<ExchangeResource>("{}").is_err());
    }
}
