//! The configuration endpoint: what the agent was set up with.
//!
//! One call, `get`, returning the agent's own configuration — today a single optional list of
//! introduction OOBIs the agent resolves at startup. This ports `Config` from the pinned
//! `src/keri/app/coring.ts`. It is the last capability *that file* owes apart from its OOBI and
//! polling halves, which are Roadmap 7.1 and 7.2.
//!
//! # The only address in the port that carries no caller input
//!
//! Every other family interpolates something — an alias, a prefix, an operation name — and every
//! other one had to decide what happens when that something carries a delimiter. This one does
//! not: the path is the constant `/config`, so there is nothing to encode and nothing to validate.
//!
//! # The answer is decoded, not cast
//!
//! `get` upstream returns `res.json()` typed as `AgentConfig`, which is a compile-time claim about
//! a run-time value: an agent answering `{"iurls": "not-a-list"}` produces a value a caller will
//! read as configuration. Here the answer is decoded, so it either is an [`AgentConfig`] or is
//! [`ClientError::Api`]. See `fixtures/client-config/`.

use signify_http::request::ResourcePath;
use signify_http::transport::Method;
use signify_types::api::AgentConfig;

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::decode_json;
use crate::error::ClientError;

/// Path segment the agent's configuration lives under.
pub const CONFIG_SEGMENT: &str = "config";

/// The configuration endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through.
#[derive(Debug)]
pub struct Config<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Config<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Reads the agent's configuration.
    ///
    /// An agent that was never given introduction OOBIs and one that was given none are told
    /// apart: the first omits the field and the second sends an empty list, which
    /// [`AgentConfig::introduction_urls`] keeps as `None` and `Some(vec![])`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the
    /// body is not an agent configuration, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn get(&self) -> Result<AgentConfig, ClientError> {
        let path = ResourcePath::builder().segment(CONFIG_SEGMENT).build()?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode_json(response.body())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn the_path_is_the_references_own_and_carries_nothing() -> Result<(), Box<dyn Error>> {
        assert_eq!(CONFIG_SEGMENT, "config");
        let path = ResourcePath::builder().segment(CONFIG_SEGMENT).build()?;
        assert_eq!(path.as_str(), "/config");
        // No query, ever: there is no caller input to put in one.
        assert_eq!(path.query(), None);
        assert_eq!(path.path(), path.as_str());
        Ok(())
    }

    #[test]
    fn an_absent_list_is_not_an_empty_one() -> Result<(), Box<dyn Error>> {
        let absent: AgentConfig = serde_json::from_str("{}")?;
        let empty: AgentConfig = serde_json::from_str(r#"{"iurls":[]}"#)?;
        assert_eq!(absent.introduction_urls, None);
        assert_eq!(empty.introduction_urls, Some(Vec::new()));
        assert_ne!(absent, empty);
        Ok(())
    }

    #[test]
    fn a_configured_agent_reports_its_introductions() -> Result<(), Box<dyn Error>> {
        let config: AgentConfig =
            serde_json::from_str(r#"{"iurls":["http://127.0.0.1:5642/oobi/BBil/controller?name=Wan"]}"#)?;
        assert_eq!(
            config.introduction_urls.as_deref(),
            Some(["http://127.0.0.1:5642/oobi/BBil/controller?name=Wan".to_owned()].as_slice())
        );
        Ok(())
    }

    #[test]
    fn an_undeclared_field_is_ignored_rather_than_kept() -> Result<(), Box<dyn Error>> {
        // Roadmap 4.1's rule for a schema with no index signature (ADR `0012`): unknown fields are
        // ignored. The reference's `res.json()` keeps them, so a caller there can read one.
        let config: AgentConfig = serde_json::from_str(r#"{"iurls":[],"curls":["http://x"],"unknown":7}"#)?;
        assert_eq!(config.introduction_urls, Some(Vec::new()));
        assert_eq!(serde_json::to_string(&config)?, r#"{"iurls":[]}"#);
        Ok(())
    }

    #[test]
    fn an_answer_of_the_wrong_shape_is_refused() {
        // The reference casts every one of these to `AgentConfig` and hands it to the caller.
        for wrong in [
            r#"{"iurls":"not-a-list"}"#,
            r#"{"iurls":[1,2]}"#,
            r#"{"iurls":{}}"#,
            r#"{"iurls":[null]}"#,
            r#""text""#,
            "7",
            "true",
            "null",
        ] {
            assert!(
                serde_json::from_str::<AgentConfig>(wrong).is_err(),
                "{wrong} was accepted as an agent configuration"
            );
        }
    }

    #[test]
    fn a_sequence_answer_is_read_positionally_rather_than_refused() -> Result<(), Box<dyn Error>> {
        // Serde reads a struct positionally from a JSON sequence, so these decode where an
        // object-only reader would refuse them. It is a leniency rather than a wrong belief: the
        // sequence spelling yields exactly what the object spelling yields, and it applies to every
        // `signify-types::api` record rather than to this endpoint. `PORTING.md` records it for the
        // Roadmap 9.1 audit.
        assert_eq!(serde_json::from_str::<AgentConfig>("[]")?.introduction_urls, None);
        assert_eq!(serde_json::from_str::<AgentConfig>("[null]")?.introduction_urls, None);
        assert_eq!(
            serde_json::from_str::<AgentConfig>(r#"[["http://x"]]"#)?,
            serde_json::from_str::<AgentConfig>(r#"{"iurls":["http://x"]}"#)?
        );
        // A sequence whose first element is not a list is still refused.
        assert!(serde_json::from_str::<AgentConfig>("[1,2]").is_err());
        Ok(())
    }
}
