//! The identifier endpoint family: what a controller has, and what it submits about it.
//!
//! A KERIA agent stores one record per managed identifier — an alias, a prefix, the key state, and
//! whichever key-manager block holds its keys — and accepts the events the edge signs for it. This
//! family is the calls that read and write those records: `list`, `get`, `update`, `create`,
//! `interact`, `rotate`, `prepare_rotation`, `submit_rotation`, `add_end_role`,
//! `add_location_scheme`, and `members`.
//!
//! This ports the HTTP half of the pinned `src/keri/app/aiding.ts`. The artifacts themselves are
//! `signify_keys::identifier`'s: this module supplies the keeper, assembles the request body around
//! what that module returns, and addresses the resource. Nothing here builds an event.
//!
//! # A request body is an ordered document
//!
//! The reference builds each body as an object literal and hands it to `JSON.stringify`, so its
//! field order is the literal's and an `undefined` field is dropped rather than written as null.
//! Both are reproduced with the ordered [`Sad`], which is why a creation without a proxy sends four
//! fields and a group creation sends seven. The algorithm block is the keeper's own `params()`
//! order rather than the schema's declaration order — a salty keeper writes `sxlt` first and `tier`
//! fifth, and the two genuinely differ upstream because one is a request and the other a response.
//!
//! # Every path component is encoded
//!
//! Of the seven name-bearing paths in this file the reference encodes two — `get` and `update` —
//! and concatenates the other five raw, so an alias holding a slash addresses a different resource
//! *and* changes what a signature covers, because request signing covers `@path`. [`ResourcePath`]
//! encodes every dynamic component exactly once and offers no way to skip it, so all seven agree
//! here with the two the reference encodes. See `fixtures/client-identifiers/`.

use core::marker::PhantomData;

use keri_protocol::event::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::{AcceptedHab, GroupMember, Hab, KeyState, Operation, Role, UntypedOperation};
use serde::de::DeserializeOwned;
use signify_http::request::{ItemRange, RangeUnit, ResourcePath};
use signify_http::response::ContentRange;
use signify_http::transport::Method;
use signify_keys::identifier::{
    CreateIdentifierRequest, IdentifierArtifact, RotateIdentifierRequest, SignedReply, end_role_reply,
    incept_identifier, interact_identifier, location_scheme_reply, rotate_identifier, sign_reply,
};

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::body::{insert_algorithm, sad_error, stored_transferability, text_array};
use crate::endpoint::decode_json;
use crate::error::ClientError;

/// Path segment the identifiers resource lives under.
pub const IDENTIFIERS_SEGMENT: &str = "identifiers";
/// Path segment an identifier's event submissions live under.
pub const EVENTS_SEGMENT: &str = "events";
/// Path segment an identifier's end-role authorizations live under.
pub const END_ROLES_SEGMENT: &str = "endroles";
/// Path segment an identifier's location authorizations live under.
pub const LOCATION_SCHEMES_SEGMENT: &str = "locschemes";
/// Path segment a group identifier's members live under.
pub const MEMBERS_SEGMENT: &str = "members";
/// Range unit a listing is windowed by; the reference's `aids`.
pub const IDENTIFIER_RANGE_UNIT: &str = "aids";

/// The identifier endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through. This is the shape every family here shares.
#[derive(Debug)]
pub struct Identifiers<'client> {
    client: &'client ConnectedClient,
}

/// One window of an agent's identifier records.
///
/// The reference returns `{start, end, total, aids}`, filling the first three with zeroes when the
/// answer carries no `content-range` at all — so a listing with entries reports a total of zero.
/// Here the window is an [`Option`], because the response decoder already decided an absent header
/// is `None` rather than three zeroes, and a caller can tell an empty window from an unreported
/// one.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct IdentifierListing {
    /// The window the agent reported, when it reported one.
    pub window: Option<ContentRange>,
    /// The records in this window, accepted or still pending.
    pub identifiers: Vec<Hab>,
}

/// What an update changes about a managed identifier; the reference's `IdentifierInfo`.
///
/// The reference sends this argument as the whole request body, and it declares exactly one field.
/// Keeping it a one-field struct means a caller cannot send a field KERIA does not read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentifierUpdate {
    /// The alias the identifier should have.
    pub name: String,
}

impl IdentifierUpdate {
    /// Renames an identifier.
    #[must_use]
    pub fn rename(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Refuses an alias KERIA would split at a `/`, which no name-based path could then reach.
fn require_routable(name: &str) -> Result<(), ClientError> {
    if name.contains('/') {
        return Err(ClientError::InvalidAlias { name: name.to_owned() });
    }
    Ok(())
}

/// What to authorize as an endpoint location; the reference's `LocSchemeArgs`.
#[derive(Clone, Debug)]
pub struct LocationSchemeRequest {
    /// The URL being authorized. Carried as text, because the reference validates nothing and the
    /// reply's meaning belongs to its consumer.
    pub url: String,
    /// The scheme, defaulting to the reference's `http`.
    pub scheme: Option<String>,
    /// The endpoint provider, defaulting to the identifier itself.
    pub endpoint: Option<IdentifierPrefix>,
    /// The reply's timestamp. Required, because a protocol crate never reads the clock.
    pub stamp: Timestamp,
}

/// One artifact submitted to the agent, with the answer that came back.
///
/// This is the reference's `EventResult`, whose `op()` calls `response.json()` on a response the
/// caller may already have read — so calling it twice throws. Here the body is owned bytes, so
/// [`Self::operation`] can be called as often as a caller likes.
#[derive(Clone, Debug)]
pub struct Submission<A> {
    artifact: A,
    response: Vec<u8>,
}

impl<A> Submission<A> {
    /// Pairs an artifact with the agent's answer.
    ///
    /// Every family here builds one from a request it just made. The multisig transaction rounds
    /// need one from an artifact another endpoint returned — a registry's anchoring key event, an
    /// issuance's — so the pairing is available inside the crate.
    pub(crate) const fn from_parts(artifact: A, response: Vec<u8>) -> Self {
        Self { artifact, response }
    }

    /// Returns what was submitted: the event or reply with its signatures.
    #[must_use]
    pub const fn artifact(&self) -> &A {
        &self.artifact
    }

    /// Takes ownership of what was submitted.
    #[must_use]
    pub fn into_artifact(self) -> A {
        self.artifact
    }

    /// Returns the agent's answer, unparsed.
    #[must_use]
    pub fn response_body(&self) -> &[u8] {
        &self.response
    }

    /// Reads the agent's answer as a long-running operation.
    ///
    /// The result is untyped, for the reason the operations family gives: the answer names its
    /// family only in its metadata. Use [`Self::operation_typed`] when the family is known.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the answer is not an operation.
    pub fn operation(&self) -> Result<UntypedOperation, ClientError> {
        decode_json(&self.response)
    }

    /// Reads the agent's answer as an operation of a known family.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the answer is not an operation of that family.
    pub fn operation_typed<M, R>(&self) -> Result<Operation<M, R>, ClientError>
    where
        M: DeserializeOwned,
        R: DeserializeOwned,
    {
        decode_json(&self.response)
    }
}

/// Body fields a key manager block may be written under.
const KEY_MANAGER_LABELS: [&str; 4] = ["salty", "randy", "group", "extern"];

/// A signed rotation that has not been sent.
///
/// It holds the exact request body, so a caller can store it and resend it unchanged after a crash
/// or a lost answer. Calling [`Identifiers::rotate`] again would rotate a second time, and a randy
/// identifier generates new keys each time it builds one, so stored bytes are its only safe retry.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedRotation {
    said: String,
    body: Vec<u8>,
}

impl PreparedRotation {
    /// Restores a rotation from the bytes [`Self::as_body`] returned.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidPreparedRotation`] when `body` lacks a rotation event's SAID,
    /// signatures, or a key manager block.
    pub fn from_body(body: Vec<u8>) -> Result<Self, ClientError> {
        let document = Sad::from_json_bytes(&body).map_err(|_| ClientError::InvalidPreparedRotation)?;
        let Some(SadValue::Map(event)) = document.get("rot") else {
            return Err(ClientError::InvalidPreparedRotation);
        };
        let signed = matches!(document.get("sigs"), Some(SadValue::Array(signatures)) if !signatures.is_empty());
        let managed = KEY_MANAGER_LABELS.iter().any(|label| document.get(label).is_some());
        let said = event.get_text("d").filter(|_| signed && managed);
        let said = said.ok_or(ClientError::InvalidPreparedRotation)?.to_owned();
        Ok(Self { said, body })
    }

    /// Returns the rotation event's SAID.
    #[must_use]
    pub fn said(&self) -> &str {
        &self.said
    }

    /// Returns the request body to store.
    #[must_use]
    pub fn as_body(&self) -> &[u8] {
        &self.body
    }
}

impl core::fmt::Debug for PreparedRotation {
    /// Names the event and leaves out the body.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedRotation")
            .field("said", &self.said)
            .finish_non_exhaustive()
    }
}

impl<'client> Identifiers<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Lists the agent's identifier records over one window.
    ///
    /// This is the only call in the family that sends a header: a `Range` of
    /// `aids=<start>-<end>`, whose answer is read back out of `content-range`. The reference
    /// defaults the window to `0-24`, which is [`ItemRange::DEFAULT`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when a
    /// record does not decode, [`ClientError::Decode`] when the reported window is malformed, and
    /// the request, transport, and authentication failures [`ConnectedClient::fetch`] returns.
    pub async fn list(&self, window: ItemRange) -> Result<IdentifierListing, ClientError> {
        let unit = RangeUnit::new(IDENTIFIER_RANGE_UNIT)?;
        let path = ResourcePath::builder().segment(IDENTIFIERS_SEGMENT).build()?;
        let request = ClientRequest::new(Method::Get, path).header("range", &window.header_value(&unit))?;
        let response = self.client.fetch(request).await?;
        let window = match response.headers().get("content-range") {
            Some(value) => Some(ContentRange::parse(value, &unit)?),
            None => None,
        };
        Ok(IdentifierListing {
            window,
            identifiers: decode_json(response.body())?,
        })
    }

    /// Reads one identifier record, requiring its key state.
    ///
    /// A multisig group still collecting member signatures has no key state; that is the one case
    /// this refuses and [`Self::get_any`] does not. The reference selects between them with a
    /// boolean parameter and three overload signatures, and throws
    /// `No key state for identifier <name>`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::IdentifierNotAccepted`] for a record with no key state, plus
    /// whatever [`Self::get_any`] returns.
    pub async fn get(&self, name: &str) -> Result<AcceptedHab, ClientError> {
        require_accepted(name, self.get_any(name).await?)
    }

    /// Reads one identifier record, accepted or still pending.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the
    /// record does not decode, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn get_any(&self, name: &str) -> Result<Hab, ClientError> {
        let response = self
            .client
            .fetch(ClientRequest::new(Method::Get, Self::record_path(name)?))
            .await?;
        decode_json(response.body())
    }

    /// Updates one identifier record, requiring its key state on the way back.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::IdentifierNotAccepted`] for a record with no key state, plus
    /// whatever [`Self::update_any`] returns.
    pub async fn update(&self, name: &str, update: &IdentifierUpdate) -> Result<AcceptedHab, ClientError> {
        require_accepted(name, self.update_any(name, update).await?)
    }

    /// Updates one identifier record, accepting a still-pending one.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidAlias`] for a new alias holding a `/`, plus whatever
    /// [`Self::get_any`] returns.
    pub async fn update_any(&self, name: &str, update: &IdentifierUpdate) -> Result<Hab, ClientError> {
        require_routable(&update.name)?;
        let mut body = Sad::new();
        body.insert("name", update.name.clone()).map_err(sad_error)?;
        let request =
            ClientRequest::new(Method::Put, Self::record_path(name)?).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(request).await?;
        decode_json(response.body())
    }

    /// Creates a managed identifier: derives its keys, signs its inception, and submits both.
    ///
    /// The prefix index the keys derive under is reserved from the client before anything is
    /// derived, so two concurrent creations can never produce the same identifier. The reference
    /// increments its shared `pidx` *after* signing instead, which two concurrent calls would
    /// read identically.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidAlias`] for an alias holding a `/`,
    /// [`ClientError::Manager`] when the keeper cannot be built, layered identifier failures when
    /// the request is inconsistent or the event cannot be signed, and whatever
    /// [`ConnectedClient::fetch`] returns.
    pub async fn create(
        &self,
        name: &str,
        request: &CreateIdentifierRequest,
    ) -> Result<Submission<IdentifierArtifact>, ClientError> {
        require_routable(name)?;
        let index = self.client.reserve_prefix_index();
        let mut keeper = self.client.keepers().create(request.keeper_request(index)?)?;
        let artifact = incept_identifier(keeper.as_mut(), request)?;

        let mut body = Sad::new();
        body.insert("name", name.to_owned()).map_err(sad_error)?;
        body.insert("icp", SadValue::Map(artifact.event.sad().clone()))
            .map_err(sad_error)?;
        insert_signatures(&mut body, &artifact)?;
        if let Some(proxy) = &request.proxy {
            body.insert("proxy", proxy.clone()).map_err(sad_error)?;
        }
        // The reference names `smids` and `rmids` in every creation body but leaves them
        // `undefined` outside a group, and `JSON.stringify` drops an undefined field.
        if let Some(members) = request.member_identifiers() {
            body.insert("smids", text_array(members)).map_err(sad_error)?;
        }
        if let Some(members) = request.rotation_member_identifiers() {
            body.insert("rmids", text_array(members)).map_err(sad_error)?;
        }
        insert_algorithm(&mut body, keeper.as_ref(), request.transferability)?;

        let path = ResourcePath::builder().segment(IDENTIFIERS_SEGMENT).build()?;
        let submitted = ClientRequest::new(Method::Post, path).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(submitted).await?;
        Ok(Submission {
            artifact,
            response: response.into_body(),
        })
    }

    /// Anchors data in an interaction event on a managed identifier.
    ///
    /// The record is read first, exactly as the reference reads it, because the event chains on
    /// the state's sequence number and prior digest.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::get`] returns, [`ClientError::Manager`] when the record's keeper
    /// cannot be rebuilt, layered identifier failures, and whatever [`ConnectedClient::fetch`]
    /// returns.
    pub async fn interact(&self, name: &str, anchors: Vec<Sad>) -> Result<Submission<IdentifierArtifact>, ClientError> {
        self.submit_interaction(name, EVENTS_SEGMENT, anchors).await
    }

    /// Builds and signs one interaction event and posts it under `segment`.
    ///
    /// Two addresses take the same body. [`Self::interact`] posts it to `events`, and
    /// [`Delegations::approve`](crate::endpoint::delegations::Delegations::approve) posts the
    /// identical bytes to `delegation` — which is the whole of the difference between them, in the
    /// reference as here.
    pub(crate) async fn submit_interaction(
        &self,
        name: &str,
        segment: &str,
        anchors: Vec<Sad>,
    ) -> Result<Submission<IdentifierArtifact>, ClientError> {
        let (artifact, body) = self.build_interaction(name, anchors).await?;
        self.submit_event(name, segment, artifact, &body).await
    }

    /// Builds and signs an interaction and its request body.
    pub(crate) async fn build_interaction(
        &self,
        name: &str,
        anchors: Vec<Sad>,
    ) -> Result<(IdentifierArtifact, Sad), ClientError> {
        let record = self.get(name).await?;
        let keeper = self.client.keepers().keeper_for(&Hab::Accepted(record.clone()))?;
        let artifact = interact_identifier(keeper.as_ref(), &record.state, anchors)?;

        let mut body = Sad::new();
        body.insert("ixn", SadValue::Map(artifact.event.sad().clone()))
            .map_err(sad_error)?;
        insert_signatures(&mut body, &artifact)?;
        insert_algorithm(&mut body, keeper.as_ref(), stored_transferability(&record)?)?;
        Ok((artifact, body))
    }

    /// Rotates a managed identifier to the keys it committed to.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::interact`] returns, plus the rotation's own layered failures.
    pub async fn rotate(
        &self,
        name: &str,
        request: &RotateIdentifierRequest,
    ) -> Result<Submission<IdentifierArtifact>, ClientError> {
        let (artifact, body) = self.build_rotation(name, request, None).await?;
        self.submit_event(name, EVENTS_SEGMENT, artifact, &body).await
    }

    /// Builds and signs a rotation without sending it.
    ///
    /// `prior_state` replaces the agent's current key state, to rebuild a group rotation that
    /// landed without this member; it reproduces the event while the member keys are unchanged.
    /// Keys still come from the stored keeper, so a salty identifier reproduces its event only
    /// until the agent advances that keeper, and a randy identifier never does.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::get`] returns, [`ClientError::Manager`] when the record's keeper
    /// cannot be rebuilt, and layered identifier failures.
    pub async fn prepare_rotation(
        &self,
        name: &str,
        request: &RotateIdentifierRequest,
        prior_state: Option<&KeyState>,
    ) -> Result<PreparedRotation, ClientError> {
        let (artifact, body) = self.build_rotation(name, request, prior_state).await?;
        Ok(PreparedRotation {
            said: artifact.event.said().qb64()?,
            body: body.to_json_bytes().map_err(sad_error)?,
        })
    }

    /// Sends a rotation from [`Self::prepare_rotation`].
    ///
    /// Resending is safe until the identifier's next establishment event; after that the agent
    /// would apply this rotation's keeper state over a newer one. Each send returns a new
    /// operation and may repeat group, witness, or delegation processing.
    ///
    /// # Errors
    ///
    /// Returns whatever [`ConnectedClient::fetch`] returns.
    pub async fn submit_rotation(
        &self,
        name: &str,
        rotation: &PreparedRotation,
    ) -> Result<Submission<PreparedRotation>, ClientError> {
        let response = self.post_event(name, EVENTS_SEGMENT, rotation.body.clone()).await?;
        Ok(Submission::from_parts(rotation.clone(), response))
    }

    /// Builds and signs a rotation and its request body.
    pub(crate) async fn build_rotation(
        &self,
        name: &str,
        request: &RotateIdentifierRequest,
        prior_state: Option<&KeyState>,
    ) -> Result<(IdentifierArtifact, Sad), ClientError> {
        let record = self.get(name).await?;
        let mut keeper = self.client.keepers().keeper_for(&Hab::Accepted(record.clone()))?;
        let state = prior_state.unwrap_or(&record.state);
        let artifact = rotate_identifier(keeper.as_mut(), state, request)?;

        let mut body = Sad::new();
        body.insert("rot", SadValue::Map(artifact.event.sad().clone()))
            .map_err(sad_error)?;
        insert_signatures(&mut body, &artifact)?;
        // A rotation always writes both member lists, empty for a single-signature identifier,
        // where a creation omits them: the reference defaults `states`/`rstates` to `[]` before
        // mapping them. The asymmetry is what the agent receives.
        body.insert("smids", text_array(request.member_identifiers()))
            .map_err(sad_error)?;
        body.insert("rmids", text_array(request.rotation_member_identifiers()))
            .map_err(sad_error)?;
        insert_algorithm(&mut body, keeper.as_ref(), request.transferability)?;

        Ok((artifact, body))
    }

    /// Authorizes an endpoint provider in a role for a managed identifier.
    ///
    /// The reply's timestamp is required rather than defaulted to the system clock, continuing
    /// the reply builder's convention; the SAID commits to it.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::get`] returns, layered identifier failures, and whatever
    /// [`ConnectedClient::fetch`] returns.
    pub async fn add_end_role(
        &self,
        name: &str,
        role: &Role,
        endpoint: Option<&IdentifierPrefix>,
        stamp: Timestamp,
    ) -> Result<Submission<SignedReply>, ClientError> {
        let record = self.get(name).await?;
        let prefix = IdentifierPrefix::from_qb64(&record.common.prefix)?;
        let reply = end_role_reply(&prefix, role, endpoint, stamp)?;
        self.submit_reply(name, END_ROLES_SEGMENT, &record, reply).await
    }

    /// Authorizes a location for an endpoint provider of a managed identifier.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::add_end_role`] returns.
    pub async fn add_location_scheme(
        &self,
        name: &str,
        request: &LocationSchemeRequest,
    ) -> Result<Submission<SignedReply>, ClientError> {
        let record = self.get(name).await?;
        let prefix = IdentifierPrefix::from_qb64(&record.common.prefix)?;
        let reply = location_scheme_reply(
            &prefix,
            &request.url,
            request.scheme.as_deref(),
            request.endpoint.as_ref(),
            request.stamp.clone(),
        )?;
        self.submit_reply(name, LOCATION_SCHEMES_SEGMENT, &record, reply).await
    }

    /// Reads the members of a group identifier, by the authority each holds.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the
    /// answer is not a member listing, and whatever [`ConnectedClient::fetch`] returns.
    pub async fn members(&self, name: &str) -> Result<GroupMember, ClientError> {
        let path = Self::sub_path(name, MEMBERS_SEGMENT)?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode_json(response.body())
    }

    /// Posts one signed key event to an identifier's event resource.
    pub(crate) async fn submit_event(
        &self,
        name: &str,
        segment: &str,
        artifact: IdentifierArtifact,
        body: &Sad,
    ) -> Result<Submission<IdentifierArtifact>, ClientError> {
        let response = self
            .post_event(name, segment, body.to_json_bytes().map_err(sad_error)?)
            .await?;
        Ok(Submission::from_parts(artifact, response))
    }

    /// Posts a request body under one of an identifier's segments and returns the agent's answer.
    async fn post_event(&self, name: &str, segment: &str, body: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        let path = Self::sub_path(name, segment)?;
        let response = self
            .client
            .fetch(ClientRequest::new(Method::Post, path).body(body))
            .await?;
        Ok(response.into_body())
    }

    /// Signs one reply with the record's keeper and posts it to `segment`.
    async fn submit_reply(
        &self,
        name: &str,
        segment: &str,
        record: &AcceptedHab,
        reply: keri_protocol::event::reply::ReplyMessage,
    ) -> Result<Submission<SignedReply>, ClientError> {
        let keeper = self.client.keepers().keeper_for(&Hab::Accepted(record.clone()))?;
        let signed = sign_reply(keeper.as_ref(), &reply)?;

        let mut body = Sad::new();
        body.insert("rpy", SadValue::Map(signed.reply.sad().clone()))
            .map_err(sad_error)?;
        body.insert("sigs", text_array(signed.signatures.qb64()?))
            .map_err(sad_error)?;

        let path = Self::sub_path(name, segment)?;
        let request = ClientRequest::new(Method::Post, path).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(request).await?;
        Ok(Submission {
            artifact: signed,
            response: response.into_body(),
        })
    }

    /// Builds `/identifiers/<name>`.
    fn record_path(name: &str) -> Result<ResourcePath, ClientError> {
        Ok(ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(name)
            .build()?)
    }

    /// Builds `/identifiers/<name>/<segment>`.
    fn sub_path(name: &str, segment: &str) -> Result<ResourcePath, ClientError> {
        Ok(ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(name)
            .segment(segment)
            .build()?)
    }
}

/// Writes the `sigs` field every submission carries.
fn insert_signatures(body: &mut Sad, artifact: &IdentifierArtifact) -> Result<(), ClientError> {
    body.insert("sigs", text_array(artifact.signatures.qb64()?))
        .map_err(sad_error)
}

/// Demands the key state a still-pending group has not got.
fn require_accepted(name: &str, record: Hab) -> Result<AcceptedHab, ClientError> {
    match record {
        Hab::Accepted(record) => Ok(record),
        Hab::Pending(_) => Err(ClientError::IdentifierNotAccepted { name: name.to_owned() }),
    }
}

/// Keeps the phantom-free generic parameter list honest for documentation links.
const _: Option<PhantomData<UntypedOperation>> = None;

#[cfg(test)]
mod tests {
    use super::*;
    use keria_types::api::HabCommon;
    use std::error::Error;

    #[test]
    fn a_pending_record_is_refused_where_key_state_is_required() -> Result<(), Box<dyn Error>> {
        let pending: Hab = serde_json::from_str(
            r#"{"name":"group1","prefix":"EGRP","icp_dt":"2023-12-01T10:05:25.062609+00:00","transferable":true,"windexes":[],"randy":{"prxs":[],"nxts":[]}}"#,
        )?;
        let outcome = require_accepted("group1", pending);
        assert!(matches!(
            outcome,
            Err(ClientError::IdentifierNotAccepted { ref name }) if name == "group1"
        ));
        // The reference throws `No key state for identifier group1`; the message names the same
        // thing without being one.
        assert!(outcome.err().is_some_and(|error| error.to_string().contains("group1")));
        Ok(())
    }

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(IDENTIFIERS_SEGMENT, "identifiers");
        assert_eq!(EVENTS_SEGMENT, "events");
        assert_eq!(END_ROLES_SEGMENT, "endroles");
        assert_eq!(LOCATION_SCHEMES_SEGMENT, "locschemes");
        assert_eq!(MEMBERS_SEGMENT, "members");
        assert_eq!(IDENTIFIER_RANGE_UNIT, "aids");
    }

    #[test]
    fn every_name_bearing_path_encodes_its_component() -> Result<(), Box<dyn Error>> {
        // The reference encodes only `get` and `update`; here an alias can never leave its own
        // segment, whichever path it reaches.
        assert_eq!(Identifiers::record_path("a/b")?.as_str(), "/identifiers/a%2Fb");
        assert_eq!(
            Identifiers::sub_path("a/b", EVENTS_SEGMENT)?.as_str(),
            "/identifiers/a%2Fb/events"
        );
        assert_eq!(
            Identifiers::record_path("a name with ñ!")?.as_str(),
            "/identifiers/a%20name%20with%20%C3%B1%21"
        );
        Ok(())
    }

    #[test]
    fn an_update_body_carries_exactly_one_field() -> Result<(), Box<dyn Error>> {
        let mut body = Sad::new();
        body.insert("name", IdentifierUpdate::rename("aid2").name)?;
        assert_eq!(String::from_utf8(body.to_json_bytes()?)?, r#"{"name":"aid2"}"#);
        Ok(())
    }

    #[test]
    fn a_submission_can_be_read_as_often_as_a_caller_likes() -> Result<(), Box<dyn Error>> {
        let submission = Submission {
            artifact: (),
            response: br#"{"name":"witness.EABC.0","metadata":{"pre":"EABC","sn":0},"done":false}"#.to_vec(),
        };
        // The reference's `op()` consumes the response body, so a second call throws.
        assert_eq!(submission.operation()?.name, "witness.EABC.0");
        assert_eq!(submission.operation()?.name, "witness.EABC.0");
        assert!(submission.response_body().starts_with(b"{"));
        Ok(())
    }

    /// The common fields are reachable from this module, which the record test relies on.
    const _: Option<HabCommon> = None;
}
