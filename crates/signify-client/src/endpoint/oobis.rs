//! The OOBI endpoint: how two identifiers learn about each other.
//!
//! An out-of-band introduction is a URL that, when fetched, yields somebody's key event log. Two
//! controllers who have never met exchange OOBIs, resolve each other's, and only then can verify
//! anything the other signs. This family is the three calls that do it: [`Oobis::get`] publishes
//! the OOBIs one *managed* identifier advertises for a role, [`Oobis::resolve`] asks the agent to
//! go and fetch somebody else's, and [`Oobis::end_roles`] reads the endpoint authorizations an
//! identifier has granted.
//!
//! This ports `Oobis` from the pinned `src/keri/app/coring.ts`.
//!
//! # Resolving does not wait
//!
//! [`Oobis::resolve`] returns an [`OobiOperation`], not a resolved OOBI: the agent has to go and
//! fetch the URL, which can take as long as the far end takes. Every caller in the pinned tree
//! hands the operation straight to `waitOperation`. Polling is Roadmap 7.2's item — Roadmap 5.4
//! already built and pinned the schedule `Operations.wait` uses — so until then a caller drives the
//! operation itself through [`operations`](crate::endpoint::operations).
//!
//! # An OOBI is a URL
//!
//! The reference declares `resolve(oobi: string)` and sends whatever it is given, so an empty
//! string, a sentence, or a value carrying a newline all become `{"url":…}` and the agent is asked
//! to fetch them. Here the argument is Roadmap 5.1's [`RequestUrl`] — an absolute `http` or `https`
//! URL of visible ASCII, no fragment, bounded — which is the same validator this crate's own
//! requests use, and which preserves its bytes exactly rather than normalizing them. That matters
//! for the same reason it mattered there: the URL is fetched byte for byte by somebody else.
//!
//! Two narrowings come with it, and neither refuses anything the pinned tree resolves. A scheme
//! must be lowercase `http` or `https`, though RFC 3986 makes a scheme case-insensitive; and the
//! whole URL must be visible ASCII, so an internationalized host has to arrive already in
//! Punycode. Both are [`RequestUrl`]'s rules rather than this family's — it validates without
//! normalizing, so it cannot lowercase a scheme or encode a host without changing the bytes the
//! agent would fetch — and both are pinned by tests below.
//!
//! # Every dynamic component is encoded exactly once
//!
//! All three of the reference's paths are built by string interpolation, and none of the four
//! dynamic values is encoded: an alias holding `/` addresses a different identifier, a role holding
//! `&` adds a query parameter of the caller's choosing, and an AID or a role filter holding `..`
//! climbs out of its own segment. Roadmap 3.10 signs `@path`, so each also changes what a
//! signature commits to. Roadmap 5.3's [`ResourcePath`] closes all four. See
//! `fixtures/client-oobis/`.

use signify_http::request::ResourcePath;
use signify_http::transport::{Method, RequestUrl};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::serialization::Sad;
use signify_types::api::{EndRole, Oobi, OobiOperation, Role};

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::body::sad_error;
use crate::endpoint::decode_json;
use crate::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use crate::error::ClientError;

/// Path segment a managed identifier's published OOBIs live under.
pub const OOBIS_SEGMENT: &str = "oobis";

/// Path segment an OOBI resolution is posted to.
///
/// The same word as [`OOBIS_SEGMENT`], but a different resource: this one is at the root and takes
/// somebody else's OOBI, where that one hangs off a managed identifier and publishes its own.
pub const RESOLUTIONS_SEGMENT: &str = "oobis";

/// Path segment an identifier's endpoint authorizations live under.
///
/// The same word as
/// [`identifiers::END_ROLES_SEGMENT`](crate::endpoint::identifiers::END_ROLES_SEGMENT), and again
/// a different resource: Roadmap 6.6's is `/identifiers/{name}/endroles`, which *grants* a role for
/// a managed identifier, while this one is `/endroles/{aid}`, which *reads* what any identifier has
/// granted.
pub const END_ROLES_SEGMENT: &str = "endroles";

/// Query parameter naming the role whose OOBIs are wanted; the reference's `role`.
pub const ROLE_PARAMETER: &str = "role";

/// The role the reference falls back to when a caller names none.
///
/// `get(name, role = 'agent')` writes this default into the query, so an omitted role is still an
/// observable request. [`Oobis::get`] takes the role as an ordinary argument instead, so what
/// reaches the wire is visible at the call site; this constant is here for a caller who wants the
/// reference's choice by name. Exactly one call site in the pinned tree takes the default.
pub const DEFAULT_ROLE: Role = Role::Agent;

/// What to ask the agent to resolve; the reference's `resolve(oobi, alias?)` arguments.
///
/// The URL is validated and the alias optional, which is the distinction the reference draws with
/// `undefined`: an absent alias is not written into the body at all, while an explicitly empty one
/// is written as `"oobialias":""`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OobiResolution {
    /// The OOBI to fetch; the reference's `oobi`, sent as the body's `url`.
    pub url: RequestUrl,
    /// The contact alias to file the resolution under; the reference's `alias`, sent as
    /// `oobialias`.
    pub alias: Option<String>,
}

impl OobiResolution {
    /// Resolves one OOBI without filing it under a contact alias.
    #[must_use]
    pub const fn new(url: RequestUrl) -> Self {
        Self { url, alias: None }
    }

    /// Files the resolution under a contact alias.
    ///
    /// An empty alias is accepted and written, because the reference distinguishes it from an
    /// absent one and both reach the agent.
    #[must_use]
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.alias = Some(alias.into());
        self
    }

    /// Builds the exact JSON body this resolution carries.
    ///
    /// Exposed because it is the one part of a resolution that is pure. The field order is the
    /// reference's own object literal — `url`, then `oobialias` — and an absent alias is not
    /// written, exactly as `JSON.stringify` drops an `undefined` field.
    ///
    /// ```
    /// use signify_client::endpoint::oobis::OobiResolution;
    /// use signify_http::transport::RequestUrl;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let url = RequestUrl::new("http://oobiurl.com")?;
    /// let plain = OobiResolution::new(url.clone());
    /// assert_eq!(plain.body()?, br#"{"url":"http://oobiurl.com"}"#);
    ///
    /// let aliased = OobiResolution::new(url).with_alias("witness");
    /// assert_eq!(
    ///     aliased.body()?,
    ///     br#"{"url":"http://oobiurl.com","oobialias":"witness"}"#,
    /// );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Serialization`] when the body cannot be written.
    pub fn body(&self) -> Result<Vec<u8>, ClientError> {
        let mut body = Sad::new();
        body.insert("url", self.url.as_str().to_owned()).map_err(sad_error)?;
        if let Some(alias) = &self.alias {
            body.insert("oobialias", alias.clone()).map_err(sad_error)?;
        }
        body.to_json_bytes().map_err(sad_error)
    }
}

/// The OOBI endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through. This is the shape Roadmap 6.5 settled for every family.
#[derive(Debug)]
pub struct Oobis<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Oobis<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Reads the OOBIs one managed identifier publishes for a role.
    ///
    /// This is what a controller hands to somebody who needs to verify what it signs. The role is
    /// required rather than defaulted; [`DEFAULT_ROLE`] is the reference's own fallback.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the body
    /// is not an OOBI listing, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn get(&self, name: &str, role: &Role) -> Result<Oobi, ClientError> {
        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(name)
            .segment(OOBIS_SEGMENT)
            .parameter(ROLE_PARAMETER, role.as_str())
            .build()?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode_json(response.body())
    }

    /// Asks the agent to resolve somebody else's OOBI.
    ///
    /// The answer is a *long-running operation*, not a resolved OOBI: the agent has to fetch the
    /// URL and process whatever key event log comes back. Drive it through
    /// [`operations`](crate::endpoint::operations) until Roadmap 7.2 adds the waiting helper.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the answer is not an OOBI operation, plus whatever
    /// [`Self::get`] returns.
    pub async fn resolve(&self, request: &OobiResolution) -> Result<OobiOperation, ClientError> {
        let path = ResourcePath::builder().segment(RESOLUTIONS_SEGMENT).build()?;
        let submitted = ClientRequest::new(Method::Post, path).body(request.body()?);
        let response = self.client.fetch(submitted).await?;
        decode_json(response.body())
    }

    /// Reads the endpoint authorizations an identifier has granted, optionally filtered by role.
    ///
    /// The identifier is any AID, not only a managed one — the reference's own integration test
    /// asks about one the agent has never heard of and expects an empty list rather than a
    /// failure, which is reproduced here.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the body is not a list of end roles, plus whatever
    /// [`Self::get`] returns.
    pub async fn end_roles(
        &self,
        identifier: &IdentifierPrefix,
        role: Option<&Role>,
    ) -> Result<Vec<EndRole>, ClientError> {
        let mut builder = ResourcePath::builder()
            .segment(END_ROLES_SEGMENT)
            .segment(&identifier.qb64()?);
        if let Some(role) = role {
            builder = builder.segment(role.as_str());
        }
        let response = self
            .client
            .fetch(ClientRequest::new(Method::Get, builder.build()?))
            .await?;
        decode_json(response.body())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const GROUP_AID: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
    /// The AID `endroles-by-aid.test.ts` asks about — 43 characters, where a qualified `E` prefix
    /// is 44, so it is not a prefix at all.
    const UNKNOWN_AID: &str = "EXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    /// The same shape at the length a prefix actually is, which is what this port sends instead.
    const UNKNOWN_VALID_AID: &str = "EAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

    fn oobi_path(name: &str, role: &Role) -> Result<ResourcePath, Box<dyn Error>> {
        Ok(ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(name)
            .segment(OOBIS_SEGMENT)
            .parameter(ROLE_PARAMETER, role.as_str())
            .build()?)
    }

    fn end_role_path(identifier: &str, role: Option<&Role>) -> Result<ResourcePath, Box<dyn Error>> {
        let mut builder = ResourcePath::builder()
            .segment(END_ROLES_SEGMENT)
            .segment(&IdentifierPrefix::from_qb64(identifier)?.qb64()?);
        if let Some(role) = role {
            builder = builder.segment(role.as_str());
        }
        Ok(builder.build()?)
    }

    fn rendered(resolution: &OobiResolution) -> Result<String, Box<dyn Error>> {
        Ok(String::from_utf8(resolution.body()?)?)
    }

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(OOBIS_SEGMENT, "oobis");
        assert_eq!(RESOLUTIONS_SEGMENT, "oobis");
        assert_eq!(END_ROLES_SEGMENT, "endroles");
        assert_eq!(ROLE_PARAMETER, "role");
        // Two resources, one word each, deliberately spelled separately: `/oobis` publishes and
        // `/oobis` resolves, and `/endroles/{aid}` reads what Roadmap 6.6's
        // `/identifiers/{name}/endroles` grants.
        assert_eq!(END_ROLES_SEGMENT, crate::endpoint::identifiers::END_ROLES_SEGMENT);
    }

    #[test]
    fn the_default_role_is_the_references_own() {
        assert_eq!(DEFAULT_ROLE, Role::Agent);
        assert_eq!(DEFAULT_ROLE.as_str(), "agent");
    }

    #[test]
    fn a_published_listing_addresses_the_references_path() -> Result<(), Box<dyn Error>> {
        let path = oobi_path("aid", &Role::Agent)?;
        assert_eq!(path.as_str(), "/identifiers/aid/oobis?role=agent");
        // Roadmap 3.10 strips the query before signing, so every role signs identically.
        assert_eq!(path.path(), "/identifiers/aid/oobis");
        assert_eq!(
            oobi_path("name1", &Role::Witness)?.as_str(),
            "/identifiers/name1/oobis?role=witness"
        );
        assert_eq!(
            oobi_path("aid1", &Role::Mailbox)?.as_str(),
            "/identifiers/aid1/oobis?role=mailbox"
        );
        Ok(())
    }

    #[test]
    fn an_alias_can_never_leave_its_own_path_segment() -> Result<(), Box<dyn Error>> {
        // Upstream `get('a/b?c=d', 'agent')` addresses `/identifiers/a/b?c=d/oobis?role=agent`:
        // one argument becoming two segments, a query, and a different signed path.
        let path = oobi_path("a/b?c=d", &Role::Agent)?;
        assert_eq!(path.as_str(), "/identifiers/a%2Fb%3Fc%3Dd/oobis?role=agent");
        assert_eq!(path.path(), "/identifiers/a%2Fb%3Fc%3Dd/oobis");
        assert_eq!(path.path().split('/').count(), 4);
        Ok(())
    }

    #[test]
    fn a_role_can_never_introduce_a_second_query_parameter() -> Result<(), Box<dyn Error>> {
        // Upstream `get('aid', 'agent&extra=1')` sends `?role=agent&extra=1`, because the query is
        // built by interpolation rather than with `URLSearchParams`.
        let role = Role::Other("agent&extra=1".to_owned());
        let path = oobi_path("aid", &role)?;
        assert_eq!(path.as_str(), "/identifiers/aid/oobis?role=agent%26extra%3D1");
        assert_eq!(path.query(), Some("role=agent%26extra%3D1"));
        assert_eq!(path.query().map(|query| query.matches('=').count()), Some(1));
        Ok(())
    }

    #[test]
    fn an_end_role_listing_addresses_both_pinned_paths() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            end_role_path(GROUP_AID, None)?.as_str(),
            format!("/endroles/{GROUP_AID}")
        );
        assert_eq!(
            end_role_path(GROUP_AID, Some(&Role::Agent))?.as_str(),
            format!("/endroles/{GROUP_AID}/agent")
        );
        // The AID the reference's integration test asks about and expects nothing back for is
        // one character short of a qualified prefix, so this port cannot send it; the case it is
        // making is reproduced with a valid one.
        assert_eq!(UNKNOWN_AID.len(), 43);
        assert_eq!(GROUP_AID.len(), 44);
        assert!(IdentifierPrefix::from_qb64(UNKNOWN_AID).is_err());
        assert_eq!(
            end_role_path(UNKNOWN_VALID_AID, None)?.as_str(),
            format!("/endroles/{UNKNOWN_VALID_AID}")
        );
        Ok(())
    }

    #[test]
    fn a_role_filter_can_never_climb_out_of_its_segment() -> Result<(), Box<dyn Error>> {
        // Upstream `endroles(aid, '../identifiers')` addresses a resource two levels up.
        let role = Role::Other("../identifiers".to_owned());
        let path = end_role_path(GROUP_AID, Some(&role))?;
        assert_eq!(path.as_str(), format!("/endroles/{GROUP_AID}/..%2Fidentifiers"));
        assert_eq!(path.path().split('/').count(), 4);
        Ok(())
    }

    #[test]
    fn a_value_that_would_escape_the_path_is_not_an_identifier_prefix() {
        // The reference accepts any string as an AID and concatenates it raw.
        for hostile in [
            "a/b?c=d",
            "",
            "../identifiers",
            "not a prefix",
            "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwr",
            // The reference's own integration test sends this one.
            UNKNOWN_AID,
        ] {
            assert!(
                IdentifierPrefix::from_qb64(hostile).is_err(),
                "{hostile:?} was accepted as an identifier prefix"
            );
        }
    }

    #[test]
    fn a_resolution_body_writes_only_what_it_was_given() -> Result<(), Box<dyn Error>> {
        let url = RequestUrl::new("http://oobiurl.com")?;
        assert_eq!(
            rendered(&OobiResolution::new(url.clone()))?,
            r#"{"url":"http://oobiurl.com"}"#
        );
        assert_eq!(
            rendered(&OobiResolution::new(url).with_alias("witness"))?,
            r#"{"url":"http://oobiurl.com","oobialias":"witness"}"#
        );
        Ok(())
    }

    #[test]
    fn an_empty_alias_is_written_rather_than_dropped() -> Result<(), Box<dyn Error>> {
        // Upstream drops `undefined` only, so `resolve(url, '')` sends an empty alias.
        let resolution = OobiResolution::new(RequestUrl::new("http://oobiurl.com")?).with_alias("");
        assert_eq!(rendered(&resolution)?, r#"{"url":"http://oobiurl.com","oobialias":""}"#);
        assert_eq!(resolution.alias.as_deref(), Some(""));
        Ok(())
    }

    #[test]
    fn an_oobi_that_could_not_resolve_is_not_a_url() {
        // Every one of these is sent unchallenged by the reference.
        for hostile in [
            "",
            "not a url at all",
            "http://oobiurl.com/\n\r x",
            "ftp://oobiurl.com/oobi",
            "//oobiurl.com/oobi",
            "http://",
            "http://oobiurl.com/oobi#fragment",
        ] {
            assert!(
                RequestUrl::new(hostile).is_err(),
                "{hostile:?} was accepted as an OOBI URL"
            );
        }
    }

    #[test]
    fn the_two_narrowings_an_oobi_url_inherits_are_deliberate() {
        // RFC 3986 makes a scheme case-insensitive, and an internationalized host is legal in a
        // browser. `RequestUrl` validates without normalizing, so it can accept neither without
        // changing the bytes the agent fetches. Nothing the pinned tree resolves looks like this.
        for narrowed in [
            "HTTP://oobiurl.com/oobi/E",
            "Http://oobiurl.com/oobi/E",
            "http://exämple.com/oobi/E",
        ] {
            assert!(
                RequestUrl::new(narrowed).is_err(),
                "{narrowed:?} was accepted, so this narrowing is no longer real"
            );
        }
        // The already-Punycode spelling of the same host is accepted, unchanged.
        assert!(RequestUrl::new("http://xn--exmple-cua.com/oobi/E").is_ok());
    }

    #[test]
    fn every_oobi_the_pinned_tree_resolves_is_accepted_byte_for_byte() -> Result<(), Box<dyn Error>> {
        for accepted in [
            "http://oobiurl.com",
            "http://vlei-server:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
            "http://witness-demo:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller",
            "https://keria.example/oobi/EABC/agent/EDEF?role=agent",
        ] {
            let url = RequestUrl::new(accepted)?;
            // Preserved rather than normalized: the agent fetches these bytes.
            assert_eq!(url.as_str(), accepted);
            let body = rendered(&OobiResolution::new(url))?;
            assert!(body.contains(accepted), "{accepted} was rewritten into {body}");
        }
        Ok(())
    }

    #[test]
    fn an_answer_of_the_wrong_shape_is_refused() {
        // The reference casts each of these to its declared type and hands it to the caller.
        for wrong in [r#"{"unexpected":true}"#, r#"{"role":"agent"}"#, "[]", "null"] {
            assert!(
                serde_json::from_str::<Oobi>(wrong).is_err(),
                "{wrong} was accepted as an OOBI listing"
            );
        }
        for wrong in [r#"[{"cid":"ELUv"}]"#, r#"{"cid":"ELUv"}"#, "null"] {
            assert!(
                serde_json::from_str::<Vec<EndRole>>(wrong).is_err(),
                "{wrong} was accepted as an end-role listing"
            );
        }
    }

    #[test]
    fn a_well_formed_answer_decodes_with_its_role() -> Result<(), Box<dyn Error>> {
        let listing: Oobi = serde_json::from_str(r#"{"role":"agent","oobis":["http://a/oobi/E"]}"#)?;
        assert_eq!(listing.role, Role::Agent);
        assert_eq!(listing.oobis, ["http://a/oobi/E".to_owned()]);

        // A role the schema does not name is kept rather than refused, which is Roadmap 4.1's rule
        // for an extensible registry.
        let unnamed: Oobi = serde_json::from_str(r#"{"role":"gatekeeper","oobis":[]}"#)?;
        assert_eq!(unnamed.role, Role::Other("gatekeeper".to_owned()));

        let roles: Vec<EndRole> = serde_json::from_str(&format!(
            r#"[{{"cid":"{GROUP_AID}","role":"agent","eid":"{GROUP_AID}"}}]"#
        ))?;
        assert_eq!(roles.len(), 1);
        assert_eq!(roles.first().map(|role| &role.role), Some(&Role::Agent));

        // The empty listing both `endroles` integration cases expect.
        let empty: Vec<EndRole> = serde_json::from_str("[]")?;
        assert!(empty.is_empty());
        Ok(())
    }
}
