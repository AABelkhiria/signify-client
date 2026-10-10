//! The schemas endpoint: the credential schemas an agent holds.
//!
//! Two reads. [`Schemas::get`] fetches one schema by its SAID; [`Schemas::list`] fetches every
//! schema the agent has. This ports `Schemas` from the pinned `src/keri/app/credentialing.ts`.
//!
//! # The path segment is singular
//!
//! Both addresses are `/schema`, not `/schemas`, while the class, the accessor, and this module are
//! all plural. It is the one place in the file where the resource name and its accessor disagree,
//! so the segment is a named constant here rather than a literal that could drift.
//!
//! # A SAID is a SAID, not a string
//!
//! `get` upstream interpolates its argument straight into the path, so a value carrying `/`, `?`,
//! or `#` addresses a different resource — and Roadmap 3.10 signs `@path`, so it changes what the
//! signature commits to. Here the argument is Roadmap 3.3's validated [`Said`], which cannot hold a
//! delimiter; a qualified digest's alphabet is URL-safe Base64, so every real SAID reaches the path
//! byte-identical to what the reference sends. See `fixtures/client-schemas/`.

use keria_types::api::Schema;
use signify_http::request::ResourcePath;
use signify_http::transport::Method;
use signify_keri::said::Said;

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::decode_json;
use crate::error::ClientError;

/// Path segment the schema resource lives under.
///
/// **Singular**, which is what the reference addresses, where the class and the accessor are
/// plural.
pub const SCHEMA_SEGMENT: &str = "schema";

/// The schemas endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through.
#[derive(Debug)]
pub struct Schemas<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Schemas<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Reads one credential schema by its SAID.
    ///
    /// The answer is returned as the agent sent it. Nothing here checks that the schema's own
    /// `$id` is the SAID that was asked for — the reference does not either, and its integration
    /// test makes that check at the call site. A caller who needs the guarantee should compare, or
    /// verify the digest, which is `keri-protocol::said`'s job rather than an endpoint's.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the
    /// body is not a schema, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn get(&self, said: &Said) -> Result<Schema, ClientError> {
        let path = ResourcePath::builder()
            .segment(SCHEMA_SEGMENT)
            .segment(&said.qb64()?)
            .build()?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode_json(response.body())
    }

    /// Reads every credential schema the agent holds.
    ///
    /// There is no filter, range, or paging: the reference offers none and neither does this, so
    /// an agent holding many schemas answers with all of them in one body, bounded only by
    /// Roadmap 5.1's transport limit.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::get`] returns.
    pub async fn list(&self) -> Result<Vec<Schema>, ClientError> {
        let path = ResourcePath::builder().segment(SCHEMA_SEGMENT).build()?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode_json(response.body())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const QVI: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

    #[test]
    fn the_segment_is_the_references_singular_one() -> Result<(), Box<dyn Error>> {
        // The class, the accessor, and this module are plural; the address is not.
        assert_eq!(SCHEMA_SEGMENT, "schema");
        assert_ne!(SCHEMA_SEGMENT, "schemas");
        let listing = ResourcePath::builder().segment(SCHEMA_SEGMENT).build()?;
        assert_eq!(listing.as_str(), "/schema");
        assert_eq!(listing.query(), None);
        Ok(())
    }

    #[test]
    fn a_said_reaches_the_path_byte_identically() -> Result<(), Box<dyn Error>> {
        let said = Said::from_qb64(QVI)?;
        let path = ResourcePath::builder()
            .segment(SCHEMA_SEGMENT)
            .segment(&said.qb64()?)
            .build()?;
        // A qualified digest is URL-safe Base64, so encoding leaves it unchanged — which is why
        // this matches the reference exactly while still being encoded.
        assert_eq!(path.as_str(), format!("/schema/{QVI}"));
        assert_eq!(path.path(), path.as_str());
        Ok(())
    }

    #[test]
    fn a_value_that_would_escape_the_path_is_not_a_said() {
        // The reference accepts any string and interpolates it raw, so `E/../schema?x=1#y`
        // addresses a different resource entirely. There is no such value of this type.
        for hostile in [
            "E/../schema?x=1#y",
            "",
            "not a said",
            "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqa",
            "ABfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        ] {
            assert!(
                Said::from_qb64(hostile).is_err(),
                "{hostile:?} was accepted as a schema SAID"
            );
        }
    }

    #[test]
    fn a_schema_missing_a_required_field_is_refused() {
        // The reference casts this to `Schema` and hands it to the caller.
        for wrong in [
            r#"{"$id":"EBfd"}"#,
            r#"{"$id":"EBfd","$schema":"x","title":"t","description":"d","type":"object"}"#,
            "[]",
            r#""text""#,
            "null",
        ] {
            assert!(
                serde_json::from_str::<Schema>(wrong).is_err(),
                "{wrong} was accepted as a schema"
            );
        }
    }

    #[test]
    fn a_complete_schema_decodes_and_keeps_its_open_properties() -> Result<(), Box<dyn Error>> {
        let document = r#"{"$id":"EBfd","$schema":"http://json-schema.org/draft-07/schema#","title":"Q","description":"d","type":"object","credentialType":"QC","version":"1.0.0","properties":{"LEI":{"type":"string"},"nested":{"a":{"b":1}}},"additionalProperties":false,"required":["i","d"]}"#;
        let schema: Schema = serde_json::from_str(document)?;
        assert_eq!(schema.id, "EBfd");
        assert_eq!(schema.credential_type, "QC");
        assert!(!schema.additional_properties);
        assert_eq!(schema.required, ["i".to_owned(), "d".to_owned()]);
        // `properties` stays JSON Schema, which is an open vocabulary — Roadmap 4.1 recorded that
        // validating a credential against it is not a capability the reference has either.
        assert_eq!(schema.properties.len(), 2);
        assert!(schema.properties.contains_key("nested"));
        Ok(())
    }
}
