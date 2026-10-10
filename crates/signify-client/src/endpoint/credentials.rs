//! The credentials endpoint: the ACDCs an agent holds, and the two writes that change their status.
//!
//! Six calls. [`Credentials::list`], [`Credentials::get`], [`Credentials::get_cesr`],
//! [`Credentials::delete`], and [`Credentials::state`] read; [`Credentials::issue`] and
//! [`Credentials::revoke`] submit a credential's transaction event with the interaction event
//! anchoring it in the issuer's key event log.
//!
//! This ports `Credentials` from the pinned `src/keri/app/credentialing.ts`. The artifacts
//! themselves are `keri-acdc`'s, signed through `signify_acdc`: this module supplies the keeper,
//! assembles the request body around what those modules return, and addresses the resource.
//! Nothing here builds a credential or an event.
//!
//! # A credential arrives already built
//!
//! Upstream `issue` takes a loose `CredentialData` and assembles the ACDC, the issuance event, and
//! the anchor inside the same method that performs the HTTP. Here the caller builds the credential
//! with Roadmap 6.1's `CredentialBuilder` and hands it over, which is what lets this module do the
//! one thing the reference cannot: **check that the credential's issuer is the identifier being
//! used to anchor it.** Upstream the issuer is `args.i ?? hab.prefix` and nothing compares the two,
//! so a credential can claim an issuer whose log contains no anchor for it — a credential no
//! verifier can ever resolve. Here that is [`ClientError::CredentialIssuerMismatch`], refused
//! before anything is signed.
//!
//! # A revocation is an input, not a lookup
//!
//! Upstream `revoke` reads the credential back from the agent to learn the registry it commits to
//! and the prior digest it supersedes, so a revocation cannot be built offline and both values are
//! the server's rather than the caller's. Roadmap 6.2 already made all three ordinary inputs
//! defaulting to the reference's, so [`Credentials::revoke`] takes the built event and looks up
//! nothing. A caller who wants the reference's arrangement composes it from [`Credentials::state`].
//!
//! # Every path component is encoded
//!
//! Five of the six methods interpolate their arguments raw upstream — seven dynamic values in all —
//! so a SAID holding `/`, `?`, or `#` addresses a different resource, and Roadmap 3.10 signs
//! `@path`, so it also changes what the signature commits to. Here a SAID and a registry identifier
//! are validated types before they are path components, and Roadmap 5.3's [`ResourcePath`] encodes
//! an alias exactly once. See `fixtures/client-credentials/`.

use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::{Credential as CredentialRecord, CredentialOperation, CredentialState, Hab, UntypedOperation};
use signify_acdc::credential::{Credential, RegistryIdentifier};
use signify_acdc::issuance::{IssuanceArtifacts, issue_credential};
use signify_acdc::revocation::{RevocationArtifacts, RevocationEvent, revoke_credential};
use signify_acdc::transaction::is_establishment_only;
use signify_http::request::{MediaType, ResourcePath};
use signify_http::response::ResponseError;
use signify_http::transport::Method;

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::body::{index_value, insert_algorithm, sad_error, stored_transferability, text_array};
use crate::endpoint::decode_json;
use crate::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use crate::endpoint::registries::REGISTRIES_SEGMENT;
use crate::error::ClientError;

/// Path segment the credentials resource lives under.
pub const CREDENTIALS_SEGMENT: &str = "credentials";

/// Path segment a credential listing is queried through.
///
/// A listing is the only read in this family that is a `POST`: its filter travels as a JSON body
/// rather than as a query, so it addresses `/credentials/query` rather than `/credentials`.
pub const CREDENTIAL_QUERY_SEGMENT: &str = "query";

/// How many credentials a listing asks for when the caller names no limit.
///
/// The reference's `kargs.limit === undefined ? 25 : kargs.limit`. It is written into every body,
/// so an unfiltered listing is silently limited rather than unlimited.
pub const DEFAULT_CREDENTIAL_LIMIT: u32 = 25;

/// Which credentials a listing asks for; the reference's `CredentialFilter`.
///
/// All four fields are written into the body whether or not the caller set them, which is what the
/// reference does — so [`Default`] here is the reference's defaults rather than an empty document.
/// The filter and sort clauses are ordered documents because they reach the wire as JSON and the
/// agent's query language is the agent's; nothing in this crate interprets them.
///
/// ```
/// use signify_client::endpoint::credentials::{CredentialFilter, DEFAULT_CREDENTIAL_LIMIT};
///
/// let unfiltered = CredentialFilter::new();
/// assert_eq!(unfiltered.limit, DEFAULT_CREDENTIAL_LIMIT);
/// assert_eq!(unfiltered.skip, 0);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialFilter {
    /// The agent's own query document; the reference's `filter`, defaulting to `{}`.
    pub filter: Sad,
    /// Sort clauses, each an ordered document; the reference's `sort`, defaulting to `[]`.
    pub sort: Vec<Sad>,
    /// How many matches to skip; the reference's `skip`, defaulting to zero.
    pub skip: u32,
    /// How many matches to return; the reference's `limit`, defaulting to
    /// [`DEFAULT_CREDENTIAL_LIMIT`].
    pub limit: u32,
}

impl Default for CredentialFilter {
    /// The reference's own defaults, which are not the zero values: a listing with no limit set
    /// still asks for [`DEFAULT_CREDENTIAL_LIMIT`] matches.
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialFilter {
    /// An unfiltered listing with the reference's own defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            filter: Sad::new(),
            sort: Vec::new(),
            skip: 0,
            limit: DEFAULT_CREDENTIAL_LIMIT,
        }
    }

    /// Sets the agent's query document.
    #[must_use]
    pub fn with_filter(mut self, filter: Sad) -> Self {
        self.filter = filter;
        self
    }

    /// Sets the sort clauses.
    #[must_use]
    pub fn with_sort(mut self, sort: Vec<Sad>) -> Self {
        self.sort = sort;
        self
    }

    /// Sets how many matches to skip.
    #[must_use]
    pub const fn with_skip(mut self, skip: u32) -> Self {
        self.skip = skip;
        self
    }

    /// Sets how many matches to return.
    #[must_use]
    pub const fn with_limit(mut self, limit: u32) -> Self {
        self.limit = limit;
        self
    }

    /// Renders the request body, in the reference's own field order.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Serialization`] when a clause holds a value that cannot be written,
    /// and [`ClientError::UnrepresentableNumber`] when a bound exceeds the exact integer range.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ClientError> {
        let mut body = Sad::new();
        body.insert("filter", SadValue::Map(self.filter.clone()))
            .map_err(sad_error)?;
        body.insert(
            "sort",
            SadValue::Array(self.sort.iter().cloned().map(SadValue::Map).collect()),
        )
        .map_err(sad_error)?;
        body.insert("skip", index_value(self.skip)?).map_err(sad_error)?;
        body.insert("limit", index_value(self.limit)?).map_err(sad_error)?;
        body.to_json_bytes().map_err(sad_error)
    }
}

/// A submitted issuance: the credential, both events, the signatures, and the agent's answer.
///
/// This is the reference's `IssueCredentialResult`, whose `op` is `await res.json()` performed once
/// at construction. Here the body is owned bytes, so [`Self::operation`] can be read as often as a
/// caller likes.
///
/// Not `Clone`: it owns the anchoring signatures, and Roadmap 2.5 deliberately made signing
/// material non-cloneable.
#[derive(Debug)]
pub struct IssuedCredential {
    /// The credential, its issuance event, and the signed interaction event anchoring it.
    pub artifacts: IssuanceArtifacts,
    response: Vec<u8>,
}

impl IssuedCredential {
    /// Returns the agent's answer, unparsed.
    #[must_use]
    pub fn response_body(&self) -> &[u8] {
        &self.response
    }

    /// Reads the agent's answer as the long-running operation that issues the credential.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the answer is not a credential operation.
    pub fn operation(&self) -> Result<CredentialOperation, ClientError> {
        decode_json(&self.response)
    }
}

/// A submitted revocation: the revocation event, its anchor, and the agent's answer.
///
/// This is the reference's `RevokeCredentialResult`.
#[derive(Debug)]
pub struct RevokedCredential {
    /// The revocation event and the signed interaction event anchoring it.
    pub artifacts: RevocationArtifacts,
    response: Vec<u8>,
}

impl RevokedCredential {
    /// Returns the agent's answer, unparsed.
    #[must_use]
    pub fn response_body(&self) -> &[u8] {
        &self.response
    }

    /// Reads the agent's answer as a long-running operation.
    ///
    /// The result is untyped because upstream declares a **four-way union** here — a group,
    /// delegation, witness, or done operation — and the answer names its family only in its
    /// metadata, which is the reason Roadmap 6.5 gave for the same shape. Narrow it with
    /// [`Self::operation_typed`] when the family is known.
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
    pub fn operation_typed<M, R>(&self) -> Result<keria_types::api::Operation<M, R>, ClientError>
    where
        M: serde::de::DeserializeOwned,
        R: serde::de::DeserializeOwned,
    {
        decode_json(&self.response)
    }
}

/// The credentials endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through.
#[derive(Debug)]
pub struct Credentials<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Credentials<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Lists the credentials the agent holds, filtered by the agent's own query language.
    ///
    /// This is the family's only `POST` read: the filter travels as a body to
    /// `/credentials/query`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when a record
    /// does not decode, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn list(&self, filter: &CredentialFilter) -> Result<Vec<CredentialRecord>, ClientError> {
        let path = ResourcePath::builder()
            .segment(CREDENTIALS_SEGMENT)
            .segment(CREDENTIAL_QUERY_SEGMENT)
            .build()?;
        let request = ClientRequest::new(Method::Post, path).body(filter.to_json_bytes()?);
        let response = self.client.fetch(request).await?;
        decode_json(response.body())
    }

    /// Reads one credential record by its SAID.
    ///
    /// The answer is decoded rather than cast, which is what Roadmap 6.8 and 6.10 decided: a record
    /// missing any of the eleven fields the schema declares is a typed failure rather than
    /// something a caller reads as a credential. The reference's own `mockCredential` is missing
    /// seven of them and is handed over regardless.
    ///
    /// Nothing here checks that the credential came back under the SAID that was asked for; the
    /// reference does not either. A caller who needs that guarantee should compare, or verify the
    /// digest, which is `keri-protocol::said`'s job.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the body
    /// is not a credential record, and whatever [`ConnectedClient::fetch`] returns.
    pub async fn get(&self, said: &Said) -> Result<CredentialRecord, ClientError> {
        let response = self.fetch_credential(said, MediaType::json()).await?;
        decode_json(response.body())
    }

    /// Reads one credential as a CESR stream: the ACDC with its attachments, as text.
    ///
    /// This is the reference's `get(said, true)`. It is a separate method rather than a flag,
    /// because the two answers are unrelated types — upstream one method with a boolean second
    /// parameter and four overload signatures returns either a document or a string.
    ///
    /// A body that is not valid UTF-8 is a typed failure here, where the reference's `res.text()`
    /// substitutes replacement characters into the stream and hands back something that still
    /// parses but says something else.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Decode`] when the body is not UTF-8, plus whatever [`Self::get`]
    /// returns apart from its decoding failure.
    pub async fn get_cesr(&self, said: &Said) -> Result<String, ClientError> {
        let response = self.fetch_credential(said, MediaType::json_cesr()).await?;
        let body = response.into_body();
        String::from_utf8(body).map_err(|error| ClientError::Decode {
            source: Box::new(ResponseError::NotUtf8 {
                offset: error.utf8_error().valid_up_to(),
            }),
        })
    }

    /// Deletes one credential from the agent's store.
    ///
    /// The request carries **no body**: the reference calls its own `fetch` with three arguments,
    /// so `JSON.stringify(undefined)` leaves the request empty where every other write in the file
    /// carries a document. This does not revoke the credential — [`Self::revoke`] does — it only
    /// removes the agent's copy.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer and whatever
    /// [`ConnectedClient::fetch`] returns.
    pub async fn delete(&self, said: &Said) -> Result<(), ClientError> {
        let path = Self::credential_path(said)?;
        self.client.fetch(ClientRequest::new(Method::Delete, path)).await?;
        Ok(())
    }

    /// Reads one credential's status in its registry's transaction event log.
    ///
    /// The status is what says whether a credential is in force; the credential document itself
    /// says nothing about it. This is also where a caller finds the digest a revocation must
    /// supersede, which is the value the reference looks up inside `revoke`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the body
    /// is not a credential status, and whatever [`ConnectedClient::fetch`] returns.
    pub async fn state(&self, registry: &RegistryIdentifier, said: &Said) -> Result<CredentialState, ClientError> {
        let path = ResourcePath::builder()
            .segment(REGISTRIES_SEGMENT)
            .segment(&registry.qb64()?)
            .segment(&said.qb64()?)
            .build()?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode_json(response.body())
    }

    /// Issues `credential`: anchors its issuance event in the issuer's log and submits both.
    ///
    /// The identifier is read first, exactly as the reference reads it, because the anchor chains
    /// on the state's sequence number and prior digest. Two checks then run **before anything is
    /// derived**: the identifier must be able to carry an interaction event, and the credential's
    /// issuer must be that identifier. Neither exists upstream in this order — the establishment
    /// check does but the issuer check does not exist at all.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EstablishmentOnlyIssuer`] when the identifier may carry only
    /// establishment events, [`ClientError::CredentialIssuerMismatch`] when the credential names a
    /// different issuer, [`ClientError::Manager`] when the keeper cannot be rebuilt, layered
    /// transaction failures, and whatever [`Self::get`] and [`ConnectedClient::fetch`] return.
    pub async fn issue(&self, identifier: &str, credential: Credential) -> Result<IssuedCredential, ClientError> {
        let record = self.client.identifiers().get(identifier).await?;

        // The reference throws here too, but only after the lookup; nothing derives until both of
        // these hold.
        if is_establishment_only(&record.state) {
            return Err(ClientError::EstablishmentOnlyIssuer {
                identifier: record.common.prefix.clone(),
            });
        }
        let issuer = credential.issuer().qb64()?;
        if issuer != record.common.prefix {
            return Err(ClientError::CredentialIssuerMismatch {
                credential: issuer,
                anchoring: record.common.prefix.clone(),
            });
        }

        let keeper = self.client.keepers().keeper_for(&Hab::Accepted(record.clone()))?;
        let artifacts = issue_credential(keeper.as_ref(), &record.state, credential)?;

        let mut body = Sad::new();
        body.insert("acdc", SadValue::Map(artifacts.credential.sad().clone()))
            .map_err(sad_error)?;
        body.insert("iss", SadValue::Map(artifacts.issuance.sad().clone()))
            .map_err(sad_error)?;
        body.insert("ixn", SadValue::Map(artifacts.anchor.event.sad().clone()))
            .map_err(sad_error)?;
        body.insert("sigs", text_array(artifacts.anchor.signatures.qb64()?))
            .map_err(sad_error)?;
        insert_algorithm(&mut body, keeper.as_ref(), stored_transferability(&record)?)?;

        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(identifier)
            .segment(CREDENTIALS_SEGMENT)
            .build()?;
        let request = ClientRequest::new(Method::Post, path).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(request).await?;

        Ok(IssuedCredential {
            artifacts,
            response: response.into_body(),
        })
    }

    /// Revokes a credential: anchors `revocation` in the issuer's log and submits both.
    ///
    /// The revocation event is built by Roadmap 6.2's `RevocationEventBuilder`, so the registry it
    /// commits to, the digest it supersedes, and its position in the log are the caller's rather
    /// than the agent's. The reference reads all three back from the agent inside this call, which
    /// is why it cannot revoke offline and why it always writes position `'1'`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EstablishmentOnlyIssuer`] when the identifier may carry only
    /// establishment events, [`ClientError::Manager`] when the keeper cannot be rebuilt, layered
    /// transaction failures, and whatever [`Self::get`] and [`ConnectedClient::fetch`] return.
    pub async fn revoke(
        &self,
        identifier: &str,
        revocation: RevocationEvent,
    ) -> Result<RevokedCredential, ClientError> {
        let record = self.client.identifiers().get(identifier).await?;
        if is_establishment_only(&record.state) {
            return Err(ClientError::EstablishmentOnlyIssuer {
                identifier: record.common.prefix.clone(),
            });
        }

        let credential = revocation.credential();
        let keeper = self.client.keepers().keeper_for(&Hab::Accepted(record.clone()))?;
        let artifacts = revoke_credential(keeper.as_ref(), &record.state, revocation)?;

        let mut body = Sad::new();
        body.insert("rev", SadValue::Map(artifacts.revocation.sad().clone()))
            .map_err(sad_error)?;
        body.insert("ixn", SadValue::Map(artifacts.anchor.event.sad().clone()))
            .map_err(sad_error)?;
        body.insert("sigs", text_array(artifacts.anchor.signatures.qb64()?))
            .map_err(sad_error)?;
        insert_algorithm(&mut body, keeper.as_ref(), stored_transferability(&record)?)?;

        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(identifier)
            .segment(CREDENTIALS_SEGMENT)
            .segment(&credential.qb64()?)
            .build()?;
        let request = ClientRequest::new(Method::Delete, path).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(request).await?;

        Ok(RevokedCredential {
            artifacts,
            response: response.into_body(),
        })
    }

    /// Sends one credential read, declaring which representation the caller wants.
    ///
    /// The `Accept` header is added after the request is otherwise complete and is deliberately not
    /// covered by the signature, which is where the reference puts it: `extraHeaders` are appended
    /// to the already-signed set.
    async fn fetch_credential(
        &self,
        said: &Said,
        accept: MediaType,
    ) -> Result<signify_http::transport::Response, ClientError> {
        let request =
            ClientRequest::new(Method::Get, Self::credential_path(said)?).header("accept", accept.essence())?;
        self.client.fetch(request).await
    }

    /// Builds `/credentials/<said>`.
    fn credential_path(said: &Said) -> Result<ResourcePath, ClientError> {
        Ok(ResourcePath::builder()
            .segment(CREDENTIALS_SEGMENT)
            .segment(&said.qb64()?)
            .build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const CREDENTIAL: &str = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo";
    const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(CREDENTIALS_SEGMENT, "credentials");
        assert_eq!(CREDENTIAL_QUERY_SEGMENT, "query");
        assert_eq!(DEFAULT_CREDENTIAL_LIMIT, 25);
    }

    #[test]
    fn an_unfiltered_listing_writes_all_four_defaults() -> Result<(), Box<dyn Error>> {
        // The reference writes every field whether or not it was given, so the limit is a silent
        // default rather than an absent one.
        let body = CredentialFilter::new().to_json_bytes()?;
        assert_eq!(
            String::from_utf8(body)?,
            r#"{"filter":{},"sort":[],"skip":0,"limit":25}"#
        );
        assert_eq!(CredentialFilter::default(), CredentialFilter::new());
        Ok(())
    }

    #[test]
    fn a_filter_is_written_in_the_references_field_order() -> Result<(), Box<dyn Error>> {
        // The exact filter the pinned `credentialing.test.ts` sends.
        let mut equality = Sad::new();
        equality.insert("$eq", "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX")?;
        let mut clause = Sad::new();
        clause.insert("-i", SadValue::Map(equality))?;
        let mut sort = Sad::new();
        sort.insert("-s", SadValue::integer(1)?)?;

        let filter = CredentialFilter::new()
            .with_filter(clause)
            .with_sort(vec![sort])
            .with_skip(5)
            .with_limit(25);
        assert_eq!(
            String::from_utf8(filter.to_json_bytes()?)?,
            r#"{"filter":{"-i":{"$eq":"EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX"}},"sort":[{"-s":1}],"skip":5,"limit":25}"#
        );
        Ok(())
    }

    #[test]
    fn a_partial_filter_still_writes_the_fields_it_was_not_given() -> Result<(), Box<dyn Error>> {
        let filter = CredentialFilter::new().with_limit(1);
        assert_eq!(
            String::from_utf8(filter.to_json_bytes()?)?,
            r#"{"filter":{},"sort":[],"skip":0,"limit":1}"#
        );
        Ok(())
    }

    #[test]
    fn a_said_reaches_the_path_byte_identically() -> Result<(), Box<dyn Error>> {
        let said = Said::from_qb64(CREDENTIAL)?;
        let path = Credentials::credential_path(&said)?;
        // A qualified digest is URL-safe Base64, so encoding leaves it unchanged — which is why
        // this matches the reference exactly while still being encoded.
        assert_eq!(path.as_str(), format!("/credentials/{CREDENTIAL}"));
        assert_eq!(path.query(), None);
        Ok(())
    }

    #[test]
    fn a_value_that_would_reshape_a_path_is_not_a_said() {
        // The reference interpolates its argument raw, so each of these addresses a different
        // resource — and changes the path Roadmap 3.10 signs.
        for hostile in [
            "E/../identifiers?x=1#y",
            "c/d",
            "",
            "not a said",
            "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJ",
        ] {
            assert!(Said::from_qb64(hostile).is_err(), "{hostile:?} was accepted as a SAID");
        }
    }

    #[test]
    fn a_state_read_addresses_two_validated_segments() -> Result<(), Box<dyn Error>> {
        let registry = RegistryIdentifier::from_qb64(REGISTRY)?;
        let said = Said::from_qb64(CREDENTIAL)?;
        let path = ResourcePath::builder()
            .segment(REGISTRIES_SEGMENT)
            .segment(&registry.qb64()?)
            .segment(&said.qb64()?)
            .build()?;
        assert_eq!(path.as_str(), format!("/registries/{REGISTRY}/{CREDENTIAL}"));
        // Three segments, where the reference's `state('a/b','c/d')` sends five.
        assert_eq!(path.path().split('/').count(), 4);
        assert!(RegistryIdentifier::from_qb64("a/b").is_err());
        Ok(())
    }

    #[test]
    fn an_alias_can_never_leave_its_own_path_segment() -> Result<(), Box<dyn Error>> {
        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment("a/b")
            .segment(CREDENTIALS_SEGMENT)
            .build()?;
        assert_eq!(path.as_str(), "/identifiers/a%2Fb/credentials");
        assert_eq!(path.path().split('/').count(), 4);
        Ok(())
    }

    #[test]
    fn a_listing_addresses_the_query_resource_rather_than_the_collection() -> Result<(), Box<dyn Error>> {
        let path = ResourcePath::builder()
            .segment(CREDENTIALS_SEGMENT)
            .segment(CREDENTIAL_QUERY_SEGMENT)
            .build()?;
        assert_eq!(path.as_str(), "/credentials/query");
        assert_eq!(path.query(), None);
        Ok(())
    }

    #[test]
    fn a_credential_record_missing_a_required_field_is_refused() {
        // The reference casts `res.json()` to `Credential` and hands it over, which is why its own
        // `mockCredential` — missing seven of the eleven fields — reads as a credential there.
        for wrong in [
            r#"{"sad":{},"pre":"E","sadsigers":[],"sadcigars":[],"chains":[],"status":{}}"#,
            "[]",
            r#""text""#,
            "null",
        ] {
            assert!(
                serde_json::from_str::<CredentialRecord>(wrong).is_err(),
                "{wrong} was accepted as a credential record"
            );
        }
    }

    #[test]
    fn the_two_reads_declare_different_representations() {
        // One upstream method with a boolean parameter returns either a document or a string; the
        // header is the only thing that differs on the wire.
        assert_eq!(MediaType::json().essence(), "application/json");
        assert_eq!(MediaType::json_cesr().essence(), "application/json+cesr");
    }
}
