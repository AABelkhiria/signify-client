//! The escrows endpoint: messages the agent received and could not yet accept.
//!
//! A KERI agent that receives a message it cannot process — a reply whose signer it cannot verify,
//! whose prior event it has not seen, or whose subject it does not yet know — does not discard it.
//! It *escrows* it, and reconsiders when the missing evidence arrives. One read,
//! [`Escrows::list_replies`], is the only window the reference offers onto that holding area.
//!
//! This ports the whole of the pinned `src/keri/app/escrowing.ts`: one class with one method, and
//! one type alias, `Rpy`, which is Roadmap 4.1's [`ReplyRecord`].
//!
//! # A route is a filter, not a resource
//!
//! The one caller value in this file reaches the **query**, not the path, and the reference builds
//! that query with `URLSearchParams` — so unlike Roadmap 7.1's `Oobis.get`, which interpolates four
//! values raw into the same position, this one escapes what it is given. The pinned unit test says
//! so from upstream's own side: the URL it asserts is
//! `/escrows/rpy?route=%2Fpresentation%2Frequest`, the encoded form. This port agrees with it byte
//! for byte, which is why a route can stay borrowed text: there is no address for it to move.
//!
//! # The vocabulary is not a closed set
//!
//! The pinned tree names exactly one escrow route, `/presentation/request`, and only inside that
//! unit test; the two reply routes the reference actually *produces* — `/end/role/add` and
//! `/loc/scheme` — are never used to filter an escrow. keripy, which is where the escrow itself
//! lives, settles it the other way: its three reply routers register seven route templates and
//! `/presentation/request` is not among them, appearing there once, in a specification document,
//! as the route of an `exn`. So the single literal signify-ts offers is not evidence about reply
//! escrows at all. There is nothing to enumerate, so the route is a `&str`, which is the decision
//! Roadmap 3.6 already took for
//! [`ReplyBuilder`](keri_protocol::event::reply::ReplyBuilder)'s own route. Roadmap 8.1's typed
//! route table covers *exchange* routes, which these are not. keripy is read here as scoped
//! corroboration only (`PORTING.md` §1.1); signify-ts governs every byte this family sends.
//!
//! # The answer is decoded, not cast
//!
//! `listReply` upstream returns `res.json()` cast to `Rpy[]`, and `Rpy` types its `t` as a bare
//! string — so an agent answering with inception events, with an object, or with a reply carrying
//! no timestamp hands the caller something they will count as escrowed replies. Here the answer is
//! decoded into [`ReplyRecord`]s, whose ilk marker refuses a message that is not a reply. See
//! `fixtures/client-escrows/`.
//!
//! # What this does not do
//!
//! Nothing here verifies an escrowed message. A reply arrives unsigned as far as this family is
//! concerned — the signatures that would justify it are exactly what the agent is still missing —
//! so a listing says what the agent is holding, not what is true. Nor could it: a
//! [`ReplyRecord`]'s attribute block is open, so it re-serializes in sorted key order, while the
//! `d` it carries is a SAID over the bytes the agent actually sent. Roadmap 4.1 documents that for
//! every record with an open field; here it is the reason a caller who needs to check an escrowed
//! reply must do it against the response body rather than against the decoded record.

use keria_types::api::ReplyRecord;
use signify_http::request::ResourcePath;
use signify_http::transport::Method;

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::decode_json;
use crate::error::ClientError;

/// Path segment the escrow resources live under.
pub const ESCROWS_SEGMENT: &str = "escrows";

/// Path segment the escrowed *reply* messages live under; the reference's `rpy`.
///
/// It is the reply ilk, and the only escrow kind the reference exposes.
pub const REPLY_SEGMENT: &str = "rpy";

/// Query parameter naming the route a listing filters on; the reference's `route`.
pub const ROUTE_PARAMETER: &str = "route";

/// The only escrow route the pinned reference names.
///
/// It appears exactly once in the whole pinned tree, in `test/app/escrowing.test.ts`, and nothing
/// in the reference ever produces a reply on it — nor does keripy register it as a reply route.
/// It is published here because it is what the reference's own test filters on, and because
/// naming it is the honest way to record that the escrow vocabulary is otherwise undetermined; it
/// is not a recommendation.
pub const PRESENTATION_REQUEST_ROUTE: &str = "/presentation/request";

/// The escrows endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through. This is the shape Roadmap 6.5 settled for every family.
#[derive(Debug)]
pub struct Escrows<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Escrows<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Lists the reply messages the agent is holding in escrow, optionally filtered by route.
    ///
    /// `route` distinguishes three requests, as it does upstream: `None` sends no parameter,
    /// `Some("")` sends `?route=`, and any other value sends it encoded exactly once. The
    /// reference's guard is `route !== undefined`, so an empty string is a route there too.
    ///
    /// A listing with no route addresses `/escrows/rpy`, where the reference addresses
    /// `/escrows/rpy?` — the deliberate difference ADR `0028` argued for an unfiltered
    /// `/operations` listing, and for the same three reasons. The signed path is identical either
    /// way, because Roadmap 3.10 strips the query.
    ///
    /// There is no paging: the agent answers with every match in one body, bounded only by
    /// Roadmap 5.1's transport limit.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Request`] when the route is too long for a query,
    /// [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the body is not
    /// a list of reply messages, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn list_replies(&self, route: Option<&str>) -> Result<Vec<ReplyRecord>, ClientError> {
        let response = self
            .client
            .fetch(ClientRequest::new(Method::Get, Self::reply_path(route)?))
            .await?;
        decode_json(response.body())
    }

    /// Builds the one address this family has.
    fn reply_path(route: Option<&str>) -> Result<ResourcePath, ClientError> {
        Ok(ResourcePath::builder()
            .segment(ESCROWS_SEGMENT)
            .segment(REPLY_SEGMENT)
            .optional_parameter(ROUTE_PARAMETER, route)
            .build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// The two replies the fixture's pinned listing carries, in its own field order.
    const PINNED_REPLY: &str = r#"{"v":"KERI10JSON00013f_","t":"rpy","d":"EKpb2k5qGRzqhqpgTCL8wWyMb9Mv7HNZlS69ck7_3KDK","dt":"2023-11-14T22:13:20.123000+00:00","r":"/presentation/request","a":{"i":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose","s":"EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao","a":{"d":"EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo"}}}"#;

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(ESCROWS_SEGMENT, "escrows");
        assert_eq!(REPLY_SEGMENT, "rpy");
        assert_eq!(ROUTE_PARAMETER, "route");
        assert_eq!(PRESENTATION_REQUEST_ROUTE, "/presentation/request");
    }

    #[test]
    fn the_pinned_route_addresses_the_pinned_path() -> Result<(), Box<dyn Error>> {
        let path = Escrows::reply_path(Some(PRESENTATION_REQUEST_ROUTE))?;
        // Exactly the URL `escrowing.test.ts` asserts, after its base URL.
        assert_eq!(path.as_str(), "/escrows/rpy?route=%2Fpresentation%2Frequest");
        // Roadmap 3.10 strips the query, so every listing signs the same path.
        assert_eq!(path.path(), "/escrows/rpy");
        Ok(())
    }

    #[test]
    fn an_unfiltered_listing_omits_the_references_bare_question_mark() -> Result<(), Box<dyn Error>> {
        let path = Escrows::reply_path(None)?;
        // Upstream concatenates `'?' + params.toString()` unconditionally, so it sends
        // `/escrows/rpy?`.
        assert_eq!(path.as_str(), "/escrows/rpy");
        assert_eq!(path.query(), None);
        assert_eq!(path.path(), "/escrows/rpy");
        Ok(())
    }

    #[test]
    fn an_empty_route_is_a_route() -> Result<(), Box<dyn Error>> {
        // The reference's guard tests `!== undefined`, not truthiness, so these are two requests.
        assert_eq!(Escrows::reply_path(Some(""))?.as_str(), "/escrows/rpy?route=");
        assert_eq!(Escrows::reply_path(None)?.as_str(), "/escrows/rpy");
        assert_ne!(Escrows::reply_path(Some(""))?, Escrows::reply_path(None)?);
        Ok(())
    }

    #[test]
    fn the_routes_the_reference_produces_address_their_recorded_paths() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            Escrows::reply_path(Some("/end/role/add"))?.as_str(),
            "/escrows/rpy?route=%2Fend%2Frole%2Fadd"
        );
        assert_eq!(
            Escrows::reply_path(Some("/loc/scheme"))?.as_str(),
            "/escrows/rpy?route=%2Floc%2Fscheme"
        );
        Ok(())
    }

    #[test]
    fn a_route_can_never_add_a_query_parameter_or_climb() -> Result<(), Box<dyn Error>> {
        // The reference encodes this one — `URLSearchParams`, not interpolation — so this agrees
        // with it rather than diverging.
        let injecting = Escrows::reply_path(Some("a&b=c"))?;
        assert_eq!(injecting.as_str(), "/escrows/rpy?route=a%26b%3Dc");
        assert_eq!(injecting.query().map(|query| query.matches('&').count()), Some(0));

        let climbing = Escrows::reply_path(Some("../../identifiers"))?;
        assert_eq!(climbing.as_str(), "/escrows/rpy?route=..%2F..%2Fidentifiers");
        assert_eq!(climbing.path(), "/escrows/rpy");

        // A space is `+`, which is what `URLSearchParams` writes and not what a path component
        // would get.
        assert_eq!(Escrows::reply_path(Some("a b"))?.as_str(), "/escrows/rpy?route=a+b");
        Ok(())
    }

    #[test]
    fn the_address_is_always_two_segments() -> Result<(), Box<dyn Error>> {
        for route in [None, Some(""), Some(PRESENTATION_REQUEST_ROUTE), Some("../../x")] {
            let path = Escrows::reply_path(route)?;
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(segments, [ESCROWS_SEGMENT, REPLY_SEGMENT], "route {route:?}");
        }
        Ok(())
    }

    #[test]
    fn a_route_too_long_for_a_query_is_refused_rather_than_truncated() {
        // Roadmap 5.3's builder bounds the query at 1 KiB; the reference bounds nothing, so a
        // route of any size reaches the wire there.
        let outcome = Escrows::reply_path(Some(&"x".repeat(4096)));
        assert!(
            matches!(outcome, Err(ClientError::Request { .. })),
            "an oversized route was accepted: {outcome:?}"
        );
    }

    #[test]
    fn an_escrowed_reply_decodes_into_its_declared_fields() -> Result<(), Box<dyn Error>> {
        let reply: ReplyRecord = serde_json::from_str(PINNED_REPLY)?;
        assert_eq!(reply.version, "KERI10JSON00013f_");
        assert_eq!(reply.digest, "EKpb2k5qGRzqhqpgTCL8wWyMb9Mv7HNZlS69ck7_3KDK");
        assert_eq!(reply.route, PRESENTATION_REQUEST_ROUTE);
        assert_eq!(reply.stamp, "2023-11-14T22:13:20.123000+00:00");
        // The KERI 1 shape carries no identifier; the KERI 2 shape does.
        assert_eq!(reply.identifier, None);
        // The attribute block is open, so it survives whole.
        assert!(reply.attributes.get("s").is_some());
        Ok(())
    }

    #[test]
    fn a_message_that_is_not_a_reply_is_refused() {
        // `Rpy` types `t` as a bare `string`, so the reference counts each of these as an escrowed
        // reply.
        for ilk in ["icp", "ixn", "exn", "rot", "", "RPY"] {
            let document = PINNED_REPLY.replace(r#""t":"rpy""#, &format!(r#""t":"{ilk}""#));
            assert!(
                serde_json::from_str::<ReplyRecord>(&document).is_err(),
                "a {ilk:?} message was accepted as an escrowed reply"
            );
        }
    }

    #[test]
    fn an_answer_of_the_wrong_shape_is_refused() {
        for wrong in [
            // An object where a listing belongs.
            r#"{"count":0}"#,
            // A listing whose one entry has no timestamp.
            r#"[{"v":"KERI10JSON000000_","t":"rpy","d":"E","r":"/x","a":{}}]"#,
            // A listing of scalars.
            r#"["rpy"]"#,
            "null",
            r#""text""#,
        ] {
            assert!(
                serde_json::from_str::<Vec<ReplyRecord>>(wrong).is_err(),
                "{wrong} was accepted as an escrow listing"
            );
        }
    }

    #[test]
    fn an_empty_listing_is_an_answer_rather_than_an_absence() -> Result<(), Box<dyn Error>> {
        let listing: Vec<ReplyRecord> = serde_json::from_str("[]")?;
        assert_eq!(listing, [] as [ReplyRecord; 0]);
        Ok(())
    }

    #[test]
    fn one_bad_entry_refuses_the_whole_listing() -> Result<(), Box<dyn Error>> {
        // The reference casts the array, so a caller there iterates the good entries and the bad
        // one alike.
        let good: Vec<ReplyRecord> = serde_json::from_str(&format!("[{PINNED_REPLY}]"))?;
        assert_eq!(good.len(), 1);
        let mixed = format!(r#"[{PINNED_REPLY},{{"t":"icp"}}]"#);
        assert!(serde_json::from_str::<Vec<ReplyRecord>>(&mixed).is_err());
        Ok(())
    }

    #[test]
    fn an_undeclared_field_is_ignored_while_the_attribute_block_stays_open() -> Result<(), Box<dyn Error>> {
        // Roadmap 4.1's rule for a schema with no index signature (ADR `0012`): unknown fields are
        // ignored. `a` is declared `unknown`, so it is captured whole.
        let document = PINNED_REPLY.replace(r#""a":{"i""#, r#""escrowed":true,"a":{"i""#);
        let reply: ReplyRecord = serde_json::from_str(&document)?;
        let encoded = serde_json::to_string(&reply)?;
        assert!(!encoded.contains("escrowed"), "an undeclared field survived: {encoded}");

        // Everything the block carried is still there, and equal to what arrived.
        let original: ReplyRecord = serde_json::from_str(PINNED_REPLY)?;
        assert_eq!(reply.attributes, original.attributes);
        for label in ["i", "s", "a"] {
            assert!(reply.attributes.get(label).is_some(), "the block lost {label}");
        }
        Ok(())
    }

    #[test]
    fn a_decoded_reply_does_not_re_encode_into_the_bytes_it_arrived_as() -> Result<(), Box<dyn Error>> {
        // Roadmap 4.1 documents this for every record with an open field: a `serde_json::Value`
        // object re-serializes in *sorted* key order. A reply's `d` is a SAID over the bytes it
        // arrived as, so the identifier cannot be recomputed from a round-tripped record — which
        // is why this family says a listing reports what the agent holds rather than verifying it.
        let reply: ReplyRecord = serde_json::from_str(PINNED_REPLY)?;
        let encoded = serde_json::to_string(&reply)?;
        assert_ne!(encoded, PINNED_REPLY);
        // Specifically: the attribute block's own labels come back sorted.
        assert!(
            encoded.contains(r#""a":{"a":{"d":"#),
            "the block was not re-sorted: {encoded}"
        );
        assert!(PINNED_REPLY.contains(r#""a":{"i":"#));

        // Every *declared* field is unchanged, and decoding again is a fixed point.
        let again: ReplyRecord = serde_json::from_str(&encoded)?;
        assert_eq!(again, reply);
        assert_eq!(serde_json::to_string(&again)?, encoded);
        Ok(())
    }
}
