#![no_main]

//! Fuzzes the escrows endpoint over hostile routes and agent answers.
//!
//! Two things come from outside, and they are unusually asymmetric.
//!
//! The **route** is the one caller value in `escrowing.ts`, and it reaches the query rather than
//! the path — the reference builds it with `URLSearchParams`, so this is a position where the two
//! implementations already agree. The target asserts what that agreement buys: whatever a route
//! holds, the resource stays `/escrows/rpy`, the query holds exactly one parameter, and the signed
//! path Roadmap 3.10 covers never varies.
//!
//! The **answer** is where the risk is. An escrowed reply is a message *somebody else* wrote that
//! the agent could not accept — the missing evidence is exactly the signatures that would justify
//! it — so a listing is a set of unverified claims, and upstream `listReply` casts them to `Rpy[]`
//! without looking. The target asserts they are decoded instead: a message whose ilk is not `rpy`
//! is never counted as a reply, a listing decodes whole or not at all, and every declared field
//! survives a round trip.
//!
//! It also asserts the limit this port does **not** have. A decoded reply re-encodes with its open
//! attribute block sorted, so it is not byte-faithful and its own SAID cannot be recomputed from
//! it. What does hold is that re-encoding is a fixed point from the second time onward, which is
//! what makes a stored record safe to re-read — the same invariant Roadmap 6.10's fuzz run
//! established for a captured number.
//!
//! Nothing panics, no route escapes its parameter, and no non-reply is ever counted as one.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::escrows::{ESCROWS_SEGMENT, REPLY_SEGMENT, ROUTE_PARAMETER};
use signify_http::request::{ResourcePath, encode_query_component};
use keria_types::api::ReplyRecord;

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let route = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let document = parts.next().unwrap_or_default();

    // -----------------------------------------------------------------------
    // The address: one resource, one query parameter, one signed path.
    // -----------------------------------------------------------------------
    if let Ok(path) = ResourcePath::builder()
        .segment(ESCROWS_SEGMENT)
        .segment(REPLY_SEGMENT)
        .optional_parameter(ROUTE_PARAMETER, Some(route.as_str()))
        .build()
    {
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        assert_eq!(segments, [ESCROWS_SEGMENT, REPLY_SEGMENT], "route {route:?} moved the resource");

        let query = path.query().unwrap_or_default();
        assert_eq!(query.matches('&').count(), 0, "the query was {query:?}");
        assert_eq!(query.matches('=').count(), 1, "the query was {query:?}");
        assert!(query.starts_with("route="), "the query was {query:?}");

        // Encoded exactly once, and exactly as the reference's `URLSearchParams` does.
        assert_eq!(
            path.as_str(),
            format!("/escrows/rpy?route={}", encode_query_component(&route))
        );
        // Roadmap 3.10 strips the query, so nothing a route holds changes what is signed.
        assert_eq!(path.path(), "/escrows/rpy");
        assert_eq!(path.as_str().matches('?').count(), 1);
        assert_eq!(path.as_str().matches('#').count(), 0);
    }

    // An unfiltered listing is always the bare resource — never the reference's `/escrows/rpy?`.
    if let Ok(path) = ResourcePath::builder()
        .segment(ESCROWS_SEGMENT)
        .segment(REPLY_SEGMENT)
        .optional_parameter(ROUTE_PARAMETER, None)
        .build()
    {
        assert_eq!(path.as_str(), "/escrows/rpy");
        assert_eq!(path.query(), None);
    }

    // -----------------------------------------------------------------------
    // One escrowed reply: an unverified claim from somebody the agent cannot yet check.
    // -----------------------------------------------------------------------
    if let Ok(reply) = serde_json::from_slice::<ReplyRecord>(document) {
        // The ilk is a marker type, so this is the one thing a cast could not have guaranteed.
        let encoded = serde_json::to_vec(&reply);
        assert!(encoded.is_ok(), "a decoded reply failed to re-encode");
        let encoded = encoded.unwrap_or_default();
        assert!(
            encoded.starts_with(br#"{"v":"#),
            "a reply did not write its declared fields in the schema's order"
        );
        let text = core::str::from_utf8(&encoded).unwrap_or_default();
        assert!(
            text.contains(r#""t":"rpy""#),
            "a decoded reply did not write the reply ilk back: {text}"
        );

        let again = serde_json::from_slice::<ReplyRecord>(&encoded);
        assert!(again.is_ok(), "a re-encoded reply failed to decode");
        if let Ok(again) = again {
            assert_eq!(again.version, reply.version);
            assert_eq!(again.digest, reply.digest, "a round trip changed a reply's identifier");
            assert_eq!(again.identifier, reply.identifier);
            assert_eq!(again.stamp, reply.stamp);
            assert_eq!(again.route, reply.route, "a round trip changed a reply's route");
            assert_eq!(again.attributes, reply.attributes);

            // Re-encoding is a fixed point from here on, which is what makes a stored record safe
            // to re-read even though the first encoding is not byte-faithful.
            let twice = serde_json::to_vec(&again).unwrap_or_default();
            assert_eq!(twice, encoded, "re-encoding a reply is not a fixed point");
        }
    }

    // -----------------------------------------------------------------------
    // A listing: whole or nothing, where the reference casts the array.
    // -----------------------------------------------------------------------
    if let Ok(listing) = serde_json::from_slice::<Vec<ReplyRecord>>(document) {
        for entry in &listing {
            // Every entry that survived carries the fields the schema declares required.
            let _ = entry.route.len();
            let _ = entry.digest.len();
            let _ = entry.stamp.len();
        }
        let encoded = serde_json::to_vec(&listing);
        assert!(encoded.is_ok(), "a decoded listing failed to re-encode");
        let again = serde_json::from_slice::<Vec<ReplyRecord>>(&encoded.unwrap_or_default());
        assert_eq!(
            again.map(|records| records.len()).ok(),
            Some(listing.len()),
            "a listing did not survive a round trip"
        );
    }
});
