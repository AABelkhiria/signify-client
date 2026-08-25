//! Invariants of the escrows endpoint.
//!
//! Two things vary: the route a listing filters on, and the answer the agent gives.
//!
//! The route is the more interesting of the two, because it is the one caller value in this file
//! and it reaches the **query** rather than the path. So the properties are about what a query
//! value can and cannot do: whatever it holds, the resource is `/escrows/rpy`, the query holds
//! exactly one parameter, and the signed path never varies at all.
//!
//! The answer's properties are the trust boundary. An escrow listing decodes whole or not at all,
//! a message that is not a reply is never counted as one, and a decoded reply keeps every declared
//! field — while deliberately *not* keeping its own bytes, which is stated by name below because a
//! reply's identifier commits to them.

use std::error::Error;

use proptest::prelude::*;
use serde_json::{Value, json};
use signify_client::endpoint::escrows::{ESCROWS_SEGMENT, PRESENTATION_REQUEST_ROUTE, REPLY_SEGMENT, ROUTE_PARAMETER};
use signify_http::request::{MAX_QUERY_BYTES, ResourcePath, encode_query_component};
use signify_types::api::ReplyRecord;

/// The address this family builds, for a route that may be absent.
fn listing(route: Option<&str>) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(ESCROWS_SEGMENT)
        .segment(REPLY_SEGMENT)
        .optional_parameter(ROUTE_PARAMETER, route)
        .build()?)
}

/// Routes of the shape KERI writes, plus the ones that would inject, split, or climb.
fn routes() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(PRESENTATION_REQUEST_ROUTE.to_owned()),
        Just("/end/role/add".to_owned()),
        Just("/loc/scheme".to_owned()),
        Just(String::new()),
        "/[a-z]{1,8}(/[a-z]{1,8}){0,3}",
        "[\\PC]{0,64}",
        Just("a&b=c".to_owned()),
        Just("../../identifiers".to_owned()),
        Just("?route=other".to_owned()),
        Just("#fragment".to_owned()),
        Just("a b".to_owned()),
        Just("a+b".to_owned()),
    ]
}

/// One escrowed reply document, in the field order a KERI message carries.
///
/// Written as text rather than with `json!`, because a `serde_json::Value` sorts its keys and the
/// order is exactly what several of these tests are about.
fn reply_document(route: &str, stamp: &str, block: &Value) -> String {
    format!(
        r#"{{"v":"KERI10JSON00013f_","t":"rpy","d":"EKpb2k5qGRzqhqpgTCL8wWyMb9Mv7HNZlS69ck7_3KDK","dt":{stamp},"r":{route},"a":{block}}}"#,
        stamp = Value::String(stamp.to_owned()),
        route = Value::String(route.to_owned()),
    )
}

/// Attribute blocks a reply may carry, including the empty one and a deeply nested one.
fn attribute_blocks() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!({})),
        Just(json!({ "cid": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose", "role": "agent" })),
        Just(json!({ "a": { "d": "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo" } })),
        Just(json!([1, 2, 3])),
        Just(json!("text")),
        Just(json!(null)),
    ]
}

/// Ilks other than `rpy`, including the near-misses.
fn other_ilks() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("icp".to_owned()),
        Just("rot".to_owned()),
        Just("ixn".to_owned()),
        Just("exn".to_owned()),
        Just("vcp".to_owned()),
        Just("RPY".to_owned()),
        Just("rpy ".to_owned()),
        Just(" rpy".to_owned()),
        Just("rp".to_owned()),
        Just("rpyx".to_owned()),
        Just(String::new()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Whatever a route holds, the resource is `/escrows/rpy` and the query is one parameter.
    ///
    /// This is what makes the route safe as borrowed text: it reaches a `URLSearchParams` position,
    /// which the reference escapes too, so there is no address for it to move.
    #[test]
    fn a_route_never_leaves_its_own_query_parameter(route in routes()) {
        let path = listing(Some(&route))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        prop_assert_eq!(path.path(), "/escrows/rpy");
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(segments, [ESCROWS_SEGMENT, REPLY_SEGMENT]);

        let query = path.query().unwrap_or_default();
        prop_assert_eq!(query.matches('&').count(), 0, "the query was {}", query);
        prop_assert_eq!(query.matches('=').count(), 1, "the query was {}", query);
        prop_assert!(query.starts_with("route="));
        prop_assert_eq!(path.as_str().matches('?').count(), 1);
        prop_assert_eq!(path.as_str().matches('#').count(), 0);
    }

    /// The route is encoded exactly once, and exactly as the reference's `URLSearchParams` does.
    #[test]
    fn a_route_is_encoded_exactly_once(route in routes()) {
        let path = listing(Some(&route))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(
            path.as_str(),
            format!("/escrows/rpy?route={}", encode_query_component(&route))
        );
    }

    /// Roadmap 3.10 signs `@path`, so no route changes what a signature commits to.
    #[test]
    fn the_signed_path_never_varies(route in proptest::option::of(routes())) {
        let path = listing(route.as_deref())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(path.path(), "/escrows/rpy");
    }

    /// An absent route and a present one are always two different requests — including when the
    /// present one is empty, which is the case the reference's `!== undefined` guard creates.
    #[test]
    fn an_absent_route_is_never_a_present_one(route in routes()) {
        let absent = listing(None)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let present = listing(Some(&route))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(absent.query(), None);
        prop_assert!(present.query().is_some());
        prop_assert_ne!(absent.as_str(), present.as_str());
        // And never the reference's bare question mark.
        prop_assert_eq!(absent.as_str(), "/escrows/rpy");
    }

    /// A route too long for a query is refused rather than truncated, where the reference bounds
    /// nothing at all.
    #[test]
    fn an_oversized_route_is_refused(length in (MAX_QUERY_BYTES + 1)..(MAX_QUERY_BYTES * 3)) {
        let outcome = listing(Some(&"x".repeat(length)));
        prop_assert!(outcome.is_err(), "a route of {} bytes was accepted", length);
    }

    /// An accepted reply keeps every declared field and its whole attribute block, and decoding is
    /// a fixed point from the first re-encoding onward.
    #[test]
    fn an_accepted_reply_keeps_its_declared_fields(
        route in routes(),
        block in attribute_blocks(),
    ) {
        let document = reply_document(&route, "2023-11-14T22:13:20.123000+00:00", &block);
        let reply: ReplyRecord = serde_json::from_str(&document)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(&reply.route, &route);
        prop_assert_eq!(&reply.stamp, "2023-11-14T22:13:20.123000+00:00");
        prop_assert_eq!(&reply.attributes, &block);
        // The KERI 1 shape carries no identifier, and none is invented.
        prop_assert_eq!(reply.identifier.as_deref(), None);

        let encoded = serde_json::to_string(&reply)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let again: ReplyRecord = serde_json::from_str(&encoded)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(&again, &reply);
        let twice = serde_json::to_string(&again)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(twice, encoded);
    }

    /// A message that is not a reply is never counted as one, whatever its ilk says.
    ///
    /// The reference cannot make this check: `Rpy` types `t` as a bare `string`.
    #[test]
    fn a_message_that_is_not_a_reply_is_never_accepted(ilk in other_ilks()) {
        let document = json!({
            "v": "KERI10JSON00013f_",
            "t": ilk,
            "d": "EKpb2k5qGRzqhqpgTCL8wWyMb9Mv7HNZlS69ck7_3KDK",
            "dt": "2023-11-14T22:13:20.123000+00:00",
            "r": "/presentation/request",
            "a": {},
        })
        .to_string();
        let outcome = serde_json::from_str::<ReplyRecord>(&document);
        prop_assert!(outcome.is_err(), "{} was accepted as a reply", document);
        if let Err(error) = outcome {
            prop_assert!(!error.to_string().is_empty());
        }
    }

    /// A listing decodes whole or not at all: one entry that is not a reply refuses the answer,
    /// where the reference casts the array and hands every entry over.
    #[test]
    fn a_listing_decodes_whole_or_not_at_all(
        good in 0_usize..4,
        bad in proptest::bool::ANY,
        ilk in other_ilks(),
    ) {
        let mut entries: Vec<String> = (0..good)
            .map(|_| reply_document(PRESENTATION_REQUEST_ROUTE, "2023-11-14T22:13:20.123000+00:00", &json!({})))
            .collect();
        if bad {
            entries.push(json!({ "t": ilk }).to_string());
        }
        let document = format!("[{}]", entries.join(","));
        match serde_json::from_str::<Vec<ReplyRecord>>(&document) {
            Ok(listing) => {
                prop_assert!(!bad, "a listing with a non-reply entry was accepted");
                prop_assert_eq!(listing.len(), good);
            }
            Err(error) => {
                prop_assert!(bad, "a listing of {} replies was refused: {}", good, error);
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    /// Arbitrary bytes never panic: a listing either decodes or is refused with a reason.
    #[test]
    fn arbitrary_bytes_decode_or_are_refused(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        match serde_json::from_slice::<Vec<ReplyRecord>>(&bytes) {
            Ok(listing) => {
                let encoded = serde_json::to_vec(&listing)
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                let again: Vec<ReplyRecord> = serde_json::from_slice(&encoded)
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                prop_assert_eq!(again, listing);
            }
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }
}

/// Regression: the pinned route produces the exact URL `escrowing.test.ts` asserts.
#[test]
fn the_pinned_route_writes_the_pinned_url() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        listing(Some(PRESENTATION_REQUEST_ROUTE))?.as_str(),
        "/escrows/rpy?route=%2Fpresentation%2Frequest"
    );
    Ok(())
}

/// Regression: an empty route asks for `?route=`, where an absent one asks for nothing.
///
/// The reference's guard is `route !== undefined` rather than a truthiness test, so upstream makes
/// the same distinction — and a port that collapsed them would silently turn a filtered listing
/// into an unfiltered one, which is the class of mistake Roadmap 7.3 refused to make representable.
#[test]
fn an_empty_route_is_still_a_filter() -> Result<(), Box<dyn Error>> {
    assert_eq!(listing(Some(""))?.as_str(), "/escrows/rpy?route=");
    assert_eq!(listing(None)?.as_str(), "/escrows/rpy");
    Ok(())
}

/// Regression: a decoded reply does **not** re-encode into the bytes it arrived as.
///
/// Roadmap 4.1 documents this for every record with an open field, and here it has teeth: a
/// reply's `d` is a SAID over exactly those bytes, so an escrowed message must be checked against
/// the response body rather than against the record decoded from it. The port states the
/// limitation rather than pretending to a guarantee it does not have.
#[test]
fn a_decoded_reply_is_not_byte_faithful() -> Result<(), Box<dyn Error>> {
    // Written by hand, with the block's own labels *not* in sorted order — which is how a KERI
    // message arrives and what `json!` would have quietly destroyed.
    let document = concat!(
        r#"{"v":"KERI10JSON00013f_","t":"rpy","d":"EKpb2k5qGRzqhqpgTCL8wWyMb9Mv7HNZlS69ck7_3KDK","#,
        r#""dt":"2023-11-14T22:13:20.123000+00:00","r":"/presentation/request","#,
        r#""a":{"i":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose","a":{"d":"E"}}}"#
    )
    .to_owned();
    let reply: ReplyRecord = serde_json::from_str(&document)?;
    let encoded = serde_json::to_string(&reply)?;

    // The declared fields keep the schema's order, so the difference is the open block alone.
    assert!(encoded.starts_with(r#"{"v":"#));
    assert_ne!(encoded, document);
    assert!(document.contains(r#""a":{"i":"#));
    assert!(encoded.contains(r#""a":{"a":{"d":"E"},"i":"#));

    // What is stable is the second encoding onward, so a stored record re-reads unchanged.
    let again: ReplyRecord = serde_json::from_str(&encoded)?;
    assert_eq!(serde_json::to_string(&again)?, encoded);
    Ok(())
}

/// Regression: an entry missing a required field refuses the listing rather than yielding a
/// half-built record.
#[test]
fn a_reply_missing_a_declared_field_is_refused() -> Result<(), Box<dyn Error>> {
    let whole = reply_document(
        PRESENTATION_REQUEST_ROUTE,
        "2023-11-14T22:13:20.123000+00:00",
        &json!({}),
    );
    let value: Value = serde_json::from_str(&whole)?;
    let fields = value.as_object().ok_or("the reply is not an object")?;
    assert_eq!(fields.len(), 6);

    for label in ["v", "t", "d", "dt", "r", "a"] {
        let mut reduced = fields.clone();
        assert!(reduced.remove(label).is_some());
        let document = Value::Object(reduced).to_string();
        assert!(
            serde_json::from_str::<ReplyRecord>(&document).is_err(),
            "a reply with no {label} was accepted"
        );
        assert!(serde_json::from_str::<Vec<ReplyRecord>>(&format!("[{document}]")).is_err());
    }

    // The one field a KERI 1 reply may omit is the identifier the KERI 2 shape adds.
    let mut with_identifier = fields.clone();
    with_identifier.insert("i".to_owned(), json!("ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"));
    let decoded: ReplyRecord = serde_json::from_str(&Value::Object(with_identifier).to_string())?;
    assert_eq!(
        decoded.identifier.as_deref(),
        Some("ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose")
    );
    Ok(())
}
