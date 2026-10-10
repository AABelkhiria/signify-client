//! The key-events endpoint: the log behind an identifier's current state.
//!
//! One call, `get`, which returns every key event a KERIA agent holds for a prefix together with
//! the CESR attachments received with each. This ports `KeyEvents` from the pinned
//! `src/keri/app/coring.ts`.
//!
//! # A prefix is a prefix, not a string
//!
//! The reference interpolates its argument straight into the query — `` `/events?pre=${pre}` `` —
//! so a value carrying `&` adds a parameter and one carrying `#` truncates the query into a
//! fragment. Here the argument is a validated [`IdentifierPrefix`], and Roadmap 5.3's
//! [`ResourcePath`] would encode it exactly once even if it were not. See
//! `fixtures/client-key-state/`.

use keri_protocol::prefix::IdentifierPrefix;
use keria_types::api::KeyEventRecord;
use signify_http::request::ResourcePath;
use signify_http::transport::Method;

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::decode_json;
use crate::error::ClientError;

/// Path segment the key-event log lives under.
pub const EVENTS_SEGMENT: &str = "events";

/// Query parameter naming the identifier whose log is wanted; the reference's `pre`.
pub const PREFIX_PARAMETER: &str = "pre";

/// The key-events endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through.
#[derive(Debug)]
pub struct KeyEvents<'client> {
    client: &'client ConnectedClient,
}

impl<'client> KeyEvents<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Reads the key events the agent holds for one identifier.
    ///
    /// The result is in the agent's own order, which is the log's: the inception first. Each
    /// record carries the event and the CESR attachment stream received with it.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the
    /// body is not a list of key-event records, and the request, transport, and authentication
    /// failures [`ConnectedClient::fetch`] returns.
    pub async fn get(&self, prefix: &IdentifierPrefix) -> Result<Vec<KeyEventRecord>, ClientError> {
        let path = ResourcePath::builder()
            .segment(EVENTS_SEGMENT)
            .parameter(PREFIX_PARAMETER, &prefix.qb64()?)
            .build()?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode_json(response.body())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(EVENTS_SEGMENT, "events");
        assert_eq!(PREFIX_PARAMETER, "pre");
    }

    #[test]
    fn a_prefix_reaches_the_query_encoded_exactly_once() -> Result<(), Box<dyn Error>> {
        let prefix = IdentifierPrefix::from_qb64("EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX")?;
        let path = ResourcePath::builder()
            .segment(EVENTS_SEGMENT)
            .parameter(PREFIX_PARAMETER, &prefix.qb64()?)
            .build()?;
        // A KERI prefix's alphabet is URL-safe Base64, so encoding leaves it unchanged — which is
        // why this matches the reference byte for byte while still being encoded.
        assert_eq!(
            path.as_str(),
            "/events?pre=EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX"
        );
        assert_eq!(path.path(), "/events");
        Ok(())
    }

    #[test]
    fn a_value_that_would_inject_a_parameter_is_not_a_prefix() {
        // The reference accepts any string here and interpolates it raw, so `E&pre=EOTHER#x`
        // becomes a second `pre` parameter and a fragment. There is no such value of this type.
        for hostile in [
            "E&pre=EOTHER#x",
            "",
            "not a prefix",
            "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbg",
        ] {
            assert!(
                IdentifierPrefix::from_qb64(hostile).is_err(),
                "{hostile:?} was accepted as a prefix"
            );
        }
    }
}
