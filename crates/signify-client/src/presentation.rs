//! Disclosing a credential, and asking for one.
//!
//! IPEX is a conversation. One side asks, the other answers, and each message names the one it
//! answers in its own `p` field, so the whole exchange is a chain that can be checked link by
//! link. There are five steps and two ways through them:
//!
//! | | who sends | answering |
//! |---|---|---|
//! | [`request`](Presentation::request) — apply | the verifier | nothing; this opens the conversation |
//! | [`offer`](Presentation::offer) | the holder | the apply |
//! | [`agree`](Presentation::agree) | the verifier | the offer |
//! | [`disclose`](Presentation::disclose) — grant | the holder | the agree |
//! | [`admit`](Presentation::admit) | the verifier | the grant |
//!
//! and the shorter one an issuer uses, which skips the negotiation because nobody asked:
//! [`deliver`](Presentation::deliver) grants a freshly issued credential, and the recipient
//! [`admit`](Presentation::admit)s it.
//!
//! Roadmap 6.3 builds these five messages and Roadmap 6.12 submits them. What is here is the part
//! between: reading what arrived, checking it belongs to the conversation it claims to, and
//! building the answer from it.
//!
//! # Every step is read from the step it answers
//!
//! A message reaches this client as a *notification* — an identifier, a route, and the SAID of the
//! message it concerns. [`Presentation::read`] turns one into a [`ReceivedStep`]: it requires the
//! notification to name a SAID, fetches that exchange message, classifies it, and requires the
//! route the notification claimed to be the route the message actually carries. Every method that
//! answers a step takes that [`ReceivedStep`] and reads what it needs out of it, so the SAID a
//! reply chains to is the SAID of the message in hand and cannot be anything else.
//!
//! **Upstream a notification's SAID is not required to exist.** `waitAndMarkNotification` ends
//! `return notes[notes.length - 1]?.a.d ?? ''`, so a notification without an `a.d` yields the empty
//! string — and `admitMultisig` passes that straight into `grantSaid` and builds an admit chained
//! to nothing. The integration test that runs the same step by hand guards it with
//! `assert(grantNotification.a.d)` first; the helper beside it does not.
//!
//! # And every step is read only once
//!
//! `waitAndMarkNotification` marks **every** matching notification read and returns the SAID of the
//! last one. A holder group waiting on `/exn/ipex/grant` with several grants outstanding therefore
//! admits an arbitrary one and silently marks the rest read; the parameter that would have said how
//! many to expect is still in the tree, commented out, on `admitMultisig`. Here
//! [`Presentation::waiting`] returns them all and the caller answers each.
//!
//! # A disclosure carries the credential it already has
//!
//! A grant embeds the credential, its issuance, and the key event anchoring that issuance — each
//! with its own CESR attachment. A holder disclosing a credential it received holds all six pieces
//! already, and [`disclosure_of`] assembles them.
//!
//! The reference assembles them three different ways in one tree. Its presentation grant passes all
//! three attachments; its issuance grant passes only the anchor's; and
//! `multisig-holder.test.ts` passes none at all — which sends `Ipex.grant` down the branch that
//! **re-signs the anchoring event with the sender's own keeper**, whether or not the sender is the
//! issuer. Roadmap 6.11 refused that branch; this module never reaches it, because the attachments
//! come from the credential.
//!
//! # What is checked, and what is not
//!
//! The chain is checked: each answer names the message it was built from. The route is checked:
//! answering a grant with an [`agree`](Presentation::agree) is a typed error rather than a message
//! nobody can read. And the credential is checked on the way out — [`disclosure_of`] re-serializes
//! each of the three events and refuses one whose bytes do not reproduce exactly, because the SAID
//! that names it is a digest of those bytes. The reference rebuilds the same three with
//! `new Serder(record.sad)` and compares nothing.
//!
//! What is *not* checked is whether the credential being disclosed is the one that was asked for.
//! An agree names the offer it accepts and nothing else, so the link from the offered credential to
//! the granted one exists only in the caller's hands; [`Presentation::disclose`] documents that it
//! does not close it.

use keria_types::api::{Credential, ExchangeRecord, ExchangeResource, Hab, Notification};
use signify_acdc::credential::Credential as AcdcCredential;
use signify_acdc::ipex::{self, Disclosure, IpexEnvelope, IpexMessage, IpexRoute};
use signify_http::request::ItemRange;
use signify_keri::event::Timestamp;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

use crate::client::ConnectedClient;
use crate::endpoint::credentials::CredentialFilter;
use crate::endpoint::exchanges::{ClassifiedExchange, IpexStep};
use crate::endpoint::ipex::SubmittedIpexMessage;
use crate::error::ClientError;

/// Attribute label naming the schema an apply asks for.
pub const SCHEMA_LABEL: &str = "s";

/// Attribute label carrying the attributes an apply asks to match.
pub const ATTRIBUTES_LABEL: &str = "a";

/// Filter label matching a credential's schema, the reference's `-s`.
pub const SCHEMA_FILTER: &str = "-s";

/// Prefix of a filter label matching one credential attribute, the reference's `-a-`.
pub const ATTRIBUTE_FILTER_PREFIX: &str = "-a-";

/// What an apply asks a holder for.
///
/// The schema is required and the attributes narrow it: an apply for a schema with no attributes
/// asks for any credential of that schema, which is what the reference's own unprompted case
/// sends.
#[derive(Clone, Debug)]
pub struct DisclosureRequest {
    /// Who is being asked.
    pub holder: IdentifierPrefix,
    /// The schema the credential must satisfy.
    pub schema: Said,
    /// Attribute values the credential must carry.
    pub attributes: Sad,
    /// Human-readable text carried in the message's `m` field.
    pub message: String,
    /// When the message is stamped.
    pub timestamp: Timestamp,
}

/// One step of a conversation that has arrived, with the notification that announced it.
///
/// Produced by [`Presentation::read`], which is the only way to build one: a step exists here only
/// because a notification named it and the message it named was fetched and classified.
#[derive(Clone, Debug)]
pub struct ReceivedStep {
    notification: String,
    exchange: ExchangeRecord,
    step: IpexStep,
}

impl ReceivedStep {
    /// Builds a step from a message already in hand.
    ///
    /// [`Presentation::read`] fetches the message a notification names and calls this; use it
    /// directly when the message came from somewhere else. `notification` is the identifier to
    /// hand [`Presentation::close`] afterwards, and is empty when there is none.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotADisclosureStep`] when the message is not an IPEX step, and
    /// whatever [`ClassifiedExchange::classify`] returns for an embed that does not decode.
    pub fn of(notification: &str, resource: &ExchangeResource) -> Result<Self, ClientError> {
        let classified = ClassifiedExchange::try_from(resource)?;
        let step = classified
            .as_ipex()
            .ok_or_else(|| ClientError::NotADisclosureStep {
                route: resource.exn.route.clone(),
            })?
            .clone();
        Ok(Self {
            notification: notification.to_owned(),
            exchange: resource.exn.clone(),
            step,
        })
    }

    /// Returns which step of the conversation this is.
    #[must_use]
    pub const fn route(&self) -> IpexRoute {
        self.step.route
    }

    /// Returns what this step embeds.
    #[must_use]
    pub const fn step(&self) -> &IpexStep {
        &self.step
    }

    /// Returns the message itself, as the agent returned it.
    #[must_use]
    pub const fn exchange(&self) -> &ExchangeRecord {
        &self.exchange
    }

    /// Returns the identifier of the notification that announced this step.
    ///
    /// Hand it to [`Presentation::close`] once the step has been answered.
    #[must_use]
    pub fn notification(&self) -> &str {
        &self.notification
    }

    /// Returns this step's own SAID — what an answer to it chains to.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Said`] when the message's `d` field is not a qualified digest.
    pub fn said(&self) -> Result<Said, ClientError> {
        Ok(Said::from_qb64(&self.exchange.digest)?)
    }

    /// Returns who sent this step.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Identifier`] when the message's `i` field is not a qualified prefix.
    pub fn sender(&self) -> Result<IdentifierPrefix, ClientError> {
        Ok(IdentifierPrefix::from_qb64(&self.exchange.sender)?)
    }

    /// Returns the SAID this step itself answers, when it answers one.
    ///
    /// An apply opens a conversation and chains to nothing, so its `p` is empty; every other step
    /// names its predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Said`] when the `p` field is neither empty nor a qualified digest.
    pub fn answers(&self) -> Result<Option<Said>, ClientError> {
        if self.exchange.prior.is_empty() {
            return Ok(None);
        }
        Ok(Some(Said::from_qb64(&self.exchange.prior)?))
    }

    /// Requires this step to be on `expected`, returning it unchanged.
    fn require(&self, expected: IpexRoute) -> Result<(), ClientError> {
        if self.step.route == expected {
            Ok(())
        } else {
            Err(ClientError::WrongDisclosureStep {
                expected: expected.as_str(),
                found: self.step.route.as_str(),
            })
        }
    }
}

/// Assembles the three events and three attachments a grant embeds from a credential in hand.
///
/// This is the whole of what a holder needs to disclose a credential it received: the ACDC with the
/// attachment it arrived with, the TEL issuance event with its own, and the key event anchoring
/// that issuance with the issuer's signatures over it. `ancatc` is a list upstream and is joined in
/// order, which is what the reference's `.join('')` does.
///
/// Each event is re-serialized and required to reproduce its own bytes exactly, because the SAID
/// naming it is a digest of those bytes: a credential whose field order did not survive the
/// agent's JSON is refused here rather than disclosed under a SAID that no longer describes it.
///
/// # Errors
///
/// Returns [`ClientError::Serialization`] when one of the three events cannot be written, and
/// [`ClientError::NonCanonicalCredential`] when re-serializing does not reproduce it byte for byte.
pub fn disclosure_of(credential: &Credential) -> Result<Disclosure, ClientError> {
    let acdc = canonical(&credential.sad, "the credential")?;
    let issuance = canonical(&credential.iss, "the issuance event")?;
    let anchor = canonical(&credential.anc, "the anchoring event")?;

    Ok(Disclosure::new(
        acdc,
        credential.atc.clone().into_bytes(),
        issuance,
        credential.issatc.clone().into_bytes(),
        anchor,
        credential.ancatc.concat().into_bytes(),
    ))
}

/// Re-serializes one record of a credential and requires the bytes to be canonical.
fn canonical<T: serde::Serialize>(record: &T, what: &'static str) -> Result<SerializedEvent, ClientError> {
    let written = serde_json::to_vec(record).map_err(|_| ClientError::NonCanonicalCredential { part: what })?;
    SerializedEvent::parse(&written).map_err(|_| ClientError::NonCanonicalCredential { part: what })
}

/// The IPEX disclosure workflow.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through.
#[derive(Debug)]
pub struct Presentation<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Presentation<'client> {
    /// Binds this workflow to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Asks a holder to disclose a credential — the apply that opens a conversation.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Ipex`] when the message cannot be built or signed — including
    /// `ReservedPayloadLabel` when the requested attributes carry the `i` label that names the
    /// recipient — plus whatever [`crate::endpoint::ipex::Ipex::submit`] returns.
    pub async fn request(&self, alias: &str, request: &DisclosureRequest) -> Result<SubmittedIpexMessage, ClientError> {
        let (keeper, sender) = self.signer(alias).await?;
        let envelope = IpexEnvelope::new(
            sender,
            request.holder.clone(),
            &request.message,
            request.timestamp.clone(),
        )?;
        let message = ipex::apply(keeper.as_ref(), &envelope, request.schema, request.attributes.clone())?;
        self.submit(alias, &message, &request.holder).await
    }

    /// Answers an apply with a credential that satisfies it — the offer.
    ///
    /// The offer is addressed to whoever sent the apply and chains to it, both read from `apply`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongDisclosureStep`] when `apply` is not an apply, and the build,
    /// signing, and submission failures the other steps return.
    pub async fn offer(
        &self,
        alias: &str,
        apply: &ReceivedStep,
        credential: &AcdcCredential,
        message: &str,
        timestamp: &Timestamp,
    ) -> Result<SubmittedIpexMessage, ClientError> {
        apply.require(IpexRoute::Apply)?;
        let verifier = apply.sender()?;
        let (keeper, sender) = self.signer(alias).await?;
        let envelope = IpexEnvelope::new(sender, verifier.clone(), message, timestamp.clone())?;
        let offer = ipex::offer(keeper.as_ref(), &envelope, credential, Some(apply.said()?))?;
        self.submit(alias, &offer, &verifier).await
    }

    /// Accepts an offer — the agree.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongDisclosureStep`] when `offer` is not an offer, and the build,
    /// signing, and submission failures the other steps return.
    pub async fn agree(
        &self,
        alias: &str,
        offer: &ReceivedStep,
        message: &str,
        timestamp: &Timestamp,
    ) -> Result<SubmittedIpexMessage, ClientError> {
        offer.require(IpexRoute::Offer)?;
        let holder = offer.sender()?;
        let (keeper, sender) = self.signer(alias).await?;
        let envelope = IpexEnvelope::new(sender, holder.clone(), message, timestamp.clone())?;
        let agree = ipex::agree(keeper.as_ref(), &envelope, offer.said()?)?;
        self.submit(alias, &agree, &holder).await
    }

    /// Discloses a credential to the verifier that agreed to it — the grant that closes a
    /// negotiation.
    ///
    /// **The credential is not checked against the conversation.** An agree names the offer it
    /// accepts and carries nothing else, so nothing in `agree` says which credential was offered;
    /// keeping the offer and passing the credential it embedded is the caller's to do. What is
    /// checked is the chain — the grant answers this agree and no other — and the credential's own
    /// bytes, which [`disclosure_of`] refuses if they are not canonical.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongDisclosureStep`] when `agree` is not an agree, and the build,
    /// signing, and submission failures the other steps return.
    pub async fn disclose(
        &self,
        alias: &str,
        agree: &ReceivedStep,
        disclosure: &Disclosure,
        message: &str,
        timestamp: &Timestamp,
    ) -> Result<SubmittedIpexMessage, ClientError> {
        agree.require(IpexRoute::Agree)?;
        let verifier = agree.sender()?;
        let (keeper, sender) = self.signer(alias).await?;
        let envelope = IpexEnvelope::new(sender, verifier.clone(), message, timestamp.clone())?;
        let grant = ipex::grant(keeper.as_ref(), &envelope, disclosure, Some(agree.said()?))?;
        self.submit(alias, &grant, &verifier).await
    }

    /// Grants a credential nobody asked for — what an issuer sends its subject.
    ///
    /// This is [`Self::disclose`] without a conversation behind it: the grant chains to nothing,
    /// because there is no agree to answer. The reference reaches the same message by leaving
    /// `agreeSaid` undefined.
    ///
    /// # Errors
    ///
    /// Returns the build, signing, and submission failures the other steps return.
    pub async fn deliver(
        &self,
        alias: &str,
        recipient: &IdentifierPrefix,
        disclosure: &Disclosure,
        message: &str,
        timestamp: &Timestamp,
    ) -> Result<SubmittedIpexMessage, ClientError> {
        let (keeper, sender) = self.signer(alias).await?;
        let envelope = IpexEnvelope::new(sender, recipient.clone(), message, timestamp.clone())?;
        let grant = ipex::grant(keeper.as_ref(), &envelope, disclosure, None)?;
        self.submit(alias, &grant, recipient).await
    }

    /// Acknowledges a grant — the admit that ends a conversation.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongDisclosureStep`] when `grant` is not a grant, and the build,
    /// signing, and submission failures the other steps return.
    pub async fn admit(
        &self,
        alias: &str,
        grant: &ReceivedStep,
        message: &str,
        timestamp: &Timestamp,
    ) -> Result<SubmittedIpexMessage, ClientError> {
        grant.require(IpexRoute::Grant)?;
        let discloser = grant.sender()?;
        let (keeper, sender) = self.signer(alias).await?;
        let envelope = IpexEnvelope::new(sender, discloser.clone(), message, timestamp.clone())?;
        let admit = ipex::admit(keeper.as_ref(), &envelope, grant.said()?)?;
        self.submit(alias, &admit, &discloser).await
    }

    /// Lists the unread notifications announcing steps on one route.
    ///
    /// **All of them**, in the order the agent returned them. The reference's own waiter marks
    /// every match read and returns only the last, so a holder with several grants outstanding
    /// answers one and loses the others.
    ///
    /// # Errors
    ///
    /// Returns whatever [`crate::endpoint::notifications::Notifications::list`] returns.
    pub async fn waiting(&self, route: IpexRoute, window: ItemRange) -> Result<Vec<Notification>, ClientError> {
        let listing = self.client.notifications().list(window).await?;
        Ok(listing
            .unread()
            .filter(|notification| notification.attributes.route.as_deref() == Some(route.as_str()))
            .cloned()
            .collect())
    }

    /// Reads the step one notification announces.
    ///
    /// The notification must name a SAID, and the message it names must carry the route the
    /// notification claimed. Upstream neither holds: the waiter yields the empty string when a
    /// notification has no `a.d`, and nothing anywhere compares the two routes.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnaddressedNotification`] when the notification names no message,
    /// [`ClientError::NotADisclosureStep`] when the message it names is not an IPEX step,
    /// [`ClientError::DisclosureRouteMismatch`] when that step's route is not the notified one,
    /// [`ClientError::Said`] for a malformed SAID, and whatever
    /// [`crate::endpoint::exchanges::Exchanges::get`] returns.
    pub async fn read(&self, notification: &Notification) -> Result<ReceivedStep, ClientError> {
        let named = notification
            .attributes
            .digest
            .as_deref()
            .filter(|digest| !digest.is_empty())
            .ok_or_else(|| ClientError::UnaddressedNotification {
                notification: notification.id.clone(),
            })?;
        let said = Said::from_qb64(named)?;

        let resource = self.client.exchanges().get(&said).await?;
        let step = ReceivedStep::of(&notification.id, &resource)?;

        if let Some(notified) = notification.attributes.route.as_deref()
            && notified != step.route().as_str()
        {
            return Err(ClientError::DisclosureRouteMismatch {
                notified: notified.to_owned(),
                carried: step.route().as_str(),
            });
        }

        Ok(step)
    }

    /// Finishes with one step: marks its notification read and removes it.
    ///
    /// The removal follows the marking whether or not the marking succeeded, which is the
    /// reference's `try`/`finally` and the reason it is one method here.
    ///
    /// # Errors
    ///
    /// Returns the marking failure when the removal succeeded, and the removal failure otherwise.
    pub async fn close(&self, step: &ReceivedStep) -> Result<(), ClientError> {
        let marked = self.client.notifications().mark(&step.notification).await;
        let removed = self.client.notifications().delete(&step.notification).await;
        removed?;
        marked?;
        Ok(())
    }

    /// Lists the credentials in this client that satisfy an apply.
    ///
    /// # Errors
    ///
    /// Returns whatever [`requested_credentials`] and
    /// [`crate::endpoint::credentials::Credentials::list`] return.
    pub async fn matching_credentials(&self, apply: &ReceivedStep) -> Result<Vec<Credential>, ClientError> {
        let filter = requested_credentials(apply)?;
        self.client.credentials().list(&filter).await
    }

    /// Reads the local identifier's keeper and prefix.
    async fn signer(
        &self,
        alias: &str,
    ) -> Result<(Box<dyn signify_keri::manager::IdentifierKeeper>, IdentifierPrefix), ClientError> {
        let record = self.client.identifiers().get(alias).await?;
        let sender = IdentifierPrefix::from_qb64(&record.common.prefix)?;
        let keeper = self.client.keepers().keeper_for(&Hab::Accepted(record))?;
        Ok((keeper, sender))
    }

    /// Submits one built message to exactly the identifier it is addressed to.
    ///
    /// Roadmap 6.12's endpoint takes a delivery list and does not compare it with the message's
    /// addressee, because a multisig sender plausibly needs more than one. Every step here is
    /// addressed to one identifier and delivered to that identifier, so the two cannot disagree.
    async fn submit(
        &self,
        alias: &str,
        message: &IpexMessage,
        recipient: &IdentifierPrefix,
    ) -> Result<SubmittedIpexMessage, ClientError> {
        self.client
            .ipex()
            .submit(alias, message, std::slice::from_ref(recipient))
            .await
    }
}

/// Builds the credential filter an apply asks for.
///
/// An apply names a schema and any number of attribute values; a credential satisfies it when its
/// schema matches and every named attribute matches. The labels are the agent's own query
/// language: `-s` for the schema and `-a-` followed by the attribute name for each attribute,
/// which is what the reference assembles inline.
///
/// # Errors
///
/// Returns [`ClientError::WrongDisclosureStep`] when `apply` is not an apply and
/// [`ClientError::MalformedDisclosureRequest`] when its attribute block is not an object or names
/// no schema.
pub fn requested_credentials(apply: &ReceivedStep) -> Result<CredentialFilter, ClientError> {
    apply.require(IpexRoute::Apply)?;
    let block = apply
        .exchange
        .attributes
        .as_object()
        .ok_or(ClientError::MalformedDisclosureRequest { what: "an object" })?;

    let schema = block
        .get(SCHEMA_LABEL)
        .and_then(serde_json::Value::as_str)
        .ok_or(ClientError::MalformedDisclosureRequest { what: "a schema" })?;

    let mut filter = Sad::new();
    filter
        .insert(SCHEMA_FILTER, schema.to_owned())
        .map_err(crate::endpoint::body::sad_error)?;

    if let Some(attributes) = block.get(ATTRIBUTES_LABEL).and_then(serde_json::Value::as_object) {
        for (label, value) in attributes {
            filter
                .insert(format!("{ATTRIBUTE_FILTER_PREFIX}{label}"), json_to_sad(value)?)
                .map_err(crate::endpoint::body::sad_error)?;
        }
    }

    Ok(CredentialFilter::new().with_filter(filter))
}

/// Converts one requested attribute value into the filter's own value type.
fn json_to_sad(value: &serde_json::Value) -> Result<SadValue, ClientError> {
    let text = serde_json::to_string(value).map_err(|_| ClientError::MalformedDisclosureRequest {
        what: "attribute values that can be written",
    })?;
    Ok(Sad::from_json_bytes(format!(r#"{{"v":{text}}}"#).as_bytes())
        .map_err(crate::endpoint::body::sad_error)?
        .get("v")
        .cloned()
        .unwrap_or(SadValue::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;

    const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
    const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
    const APPLY_SAID: &str = "EDgvqnAQWAks1nXM1WD8kXRAan4ZkdoGAhP9_UtkGfFg";
    const CREDENTIAL: &str = "EGdeVjXib7lVynr1NAddi1YTO2BCU5oi_I5DT69n9zJd";
    const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

    /// One exchange resource, as the agent returns it.
    fn resource(route: &str, attributes: &str, embeds: &str) -> Result<ExchangeResource, Box<dyn Error>> {
        let document = format!(
            r#"{{"exn":{{"v":"KERI10JSON000100_","t":"exn","d":"{APPLY_SAID}","i":"{LOCAL}","rp":"{PEER}",
               "p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{attributes},
               "e":{embeds}}},"pathed":{{}}}}"#
        );
        Ok(serde_json::from_str(
            &document.replace('\n', "").replace("               ", ""),
        )?)
    }

    fn apply_step() -> Result<ReceivedStep, Box<dyn Error>> {
        let attributes = format!(r#"{{"m":"","s":"{SCHEMA}","a":{{"LEI":"5493001KJTIIGC8Y1R17"}}}}"#);
        Ok(ReceivedStep::of(
            "0AAnote",
            &resource("/ipex/apply", &attributes, "{}")?,
        )?)
    }

    #[test]
    fn a_step_reads_its_own_chain() -> Result<(), Box<dyn Error>> {
        let step = apply_step()?;
        assert_eq!(step.route(), IpexRoute::Apply);
        assert_eq!(step.said()?.qb64()?, APPLY_SAID);
        assert_eq!(step.sender()?.qb64()?, LOCAL);
        assert_eq!(step.notification(), "0AAnote");
        // An apply opens a conversation, so it answers nothing.
        assert!(step.answers()?.is_none());
        Ok(())
    }

    #[test]
    fn a_step_that_answers_one_names_it() -> Result<(), Box<dyn Error>> {
        let document = format!(
            r#"{{"exn":{{"v":"KERI10JSON000100_","t":"exn","d":"EOFFER","i":"{PEER}","rp":"{LOCAL}",
               "p":"{APPLY_SAID}","dt":"2023-11-14T22:13:20.123000+00:00","r":"/ipex/offer","q":{{}},
               "a":{{"m":""}},"e":{{"d":"EEMB","acdc":{{"v":"ACDC10JSON000100_","d":"{CREDENTIAL}",
               "i":"{LOCAL}","s":"{SCHEMA}","a":{{"LEI":"5493001KJTIIGC8Y1R17"}}}}}}}},"pathed":{{}}}}"#
        );
        let resource: ExchangeResource =
            serde_json::from_str(&document.replace('\n', "").replace("               ", ""))?;
        let step = ReceivedStep::of("", &resource)?;
        assert_eq!(step.route(), IpexRoute::Offer);
        assert_eq!(
            step.answers()?.map(|said| said.qb64()).transpose()?,
            Some(APPLY_SAID.to_owned())
        );
        Ok(())
    }

    #[test]
    fn a_message_on_another_route_is_not_a_step() -> Result<(), Box<dyn Error>> {
        let resource = resource("/challenge/response", r#"{"words":["shell"]}"#, "{}")?;
        let refused = matches!(
            ReceivedStep::of("", &resource),
            Err(ClientError::NotADisclosureStep { .. })
        );
        assert!(refused, "a challenge answer classified as a disclosure step");
        Ok(())
    }

    #[test]
    fn a_step_answers_only_its_own_kind() -> Result<(), Box<dyn Error>> {
        let step = apply_step()?;
        assert!(step.require(IpexRoute::Apply).is_ok());
        for wrong in [IpexRoute::Offer, IpexRoute::Agree, IpexRoute::Grant, IpexRoute::Admit] {
            let refused = matches!(step.require(wrong), Err(ClientError::WrongDisclosureStep { .. }));
            assert!(refused, "an apply was accepted as a {}", wrong.as_str());
        }
        Ok(())
    }

    #[test]
    fn an_apply_becomes_the_filter_it_asks_for() -> Result<(), Box<dyn Error>> {
        let filter = requested_credentials(&apply_step()?)?;
        let written = String::from_utf8(filter.to_json_bytes()?)?;
        // The agent's own query language: `-s` for the schema, `-a-` for each attribute.
        assert!(
            written.contains(&format!(r#""{SCHEMA_FILTER}":"{SCHEMA}""#)),
            "{written}"
        );
        assert!(
            written.contains(&format!(r#""{ATTRIBUTE_FILTER_PREFIX}LEI":"5493001KJTIIGC8Y1R17""#)),
            "{written}"
        );
        Ok(())
    }

    #[test]
    fn an_apply_with_no_attributes_asks_for_the_schema_alone() -> Result<(), Box<dyn Error>> {
        let attributes = format!(r#"{{"m":"","s":"{SCHEMA}","a":{{}}}}"#);
        let step = ReceivedStep::of("", &resource("/ipex/apply", &attributes, "{}")?)?;
        let written = String::from_utf8(requested_credentials(&step)?.to_json_bytes()?)?;
        assert!(written.contains(SCHEMA_FILTER));
        assert!(!written.contains(ATTRIBUTE_FILTER_PREFIX));
        Ok(())
    }

    #[test]
    fn only_an_apply_asks_for_credentials() -> Result<(), Box<dyn Error>> {
        let attributes = r#"{"m":""}"#;
        let step = ReceivedStep::of("", &resource("/ipex/agree", attributes, "{}")?)?;
        let refused = matches!(
            requested_credentials(&step),
            Err(ClientError::WrongDisclosureStep { .. })
        );
        assert!(refused, "an agree was read as a request for credentials");
        Ok(())
    }

    #[test]
    fn an_apply_naming_no_schema_is_refused() -> Result<(), Box<dyn Error>> {
        let step = ReceivedStep::of("", &resource("/ipex/apply", r#"{"m":"","a":{}}"#, "{}")?)?;
        let refused = matches!(
            requested_credentials(&step),
            Err(ClientError::MalformedDisclosureRequest { .. })
        );
        assert!(refused, "an apply with no schema produced a filter");
        Ok(())
    }

    #[test]
    fn an_attribute_keeps_the_type_it_was_asked_with() -> Result<(), Box<dyn Error>> {
        let attributes = format!(r#"{{"m":"","s":"{SCHEMA}","a":{{"count":3,"exact":true}}}}"#);
        let step = ReceivedStep::of("", &resource("/ipex/apply", &attributes, "{}")?)?;
        let written = String::from_utf8(requested_credentials(&step)?.to_json_bytes()?)?;
        // Not `"3"` and `"true"`: a filter that stringified its values would match nothing.
        assert!(written.contains(r#""-a-count":3"#), "{written}");
        assert!(written.contains(r#""-a-exact":true"#), "{written}");
        Ok(())
    }

    #[test]
    fn the_labels_are_the_ones_the_agent_reads() {
        assert_eq!(SCHEMA_FILTER, "-s");
        assert_eq!(ATTRIBUTE_FILTER_PREFIX, "-a-");
        assert_eq!(SCHEMA_LABEL, "s");
        assert_eq!(ATTRIBUTES_LABEL, "a");
    }
}
