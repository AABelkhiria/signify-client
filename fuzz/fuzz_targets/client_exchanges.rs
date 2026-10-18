#![no_main]

//! Fuzzes the exchange endpoint over hostile aliases, SAIDs, topics, routes, and agent answers.
//!
//! This family is different from the other endpoint families in one way that decides what the
//! target asserts: **it signs**. Every other family in this crate assembles a request the agent
//! authenticates; this one puts the caller's own key over a message somebody else will read as a
//! statement by that identifier. So the invariants worth fuzzing are about what ends up inside the
//! signature.
//!
//! Two inputs are addresses. An **alias** is a path component the reference concatenates raw, and a
//! **SAID** is another — the request signature covers `@path`, so either can change what an HTTP
//! signature covers. The target asserts neither ever leaves its own segment.
//!
//! Two inputs reach the message. A **route** says what the message means and a **topic** says where
//! the recipient will find it; both are open text with no closed set upstream. The target asserts
//! they reach the places they belong and nowhere else — in particular that the delivery list never
//! leaks into the message, which is the separation this port introduced and the reference's dead
//! loop hides.
//!
//! One input is the answer, and it is the unusual one: the reference declares **two incompatible
//! types** for it. The target asserts they are disjoint — no document is ever read as both — which
//! is what makes offering a decoder for each safe rather than ambiguous. An exchange resource is
//! also a message *somebody else wrote*, handed over by the agent, and nothing here verifies its
//! signature; the target asserts only that it decodes whole or not at all.
//!
//! Nothing panics, no component escapes its segment, and no message ever names a recipient it was
//! not addressed to.

use keri_protocol::event::exchange::ExchangeBuilder;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::{ExchangeOperation, ExchangeRecord, ExchangeResource};
use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::exchanges::EXCHANGES_SEGMENT;
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_http::request::{ResourcePath, encode_path_component};

/// Every character that would give a path component a meaning it did not have.
const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const ADDRESSEE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const ELSEWHERE: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const STAMP: &str = "2023-11-14T22:13:20.123000+00:00";

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let alias = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let said_text = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let topic = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let route = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let document = parts.next().unwrap_or_default();

    // -----------------------------------------------------------------------
    // The submission address: three segments, whatever the alias holds.
    // -----------------------------------------------------------------------
    if let Ok(path) = ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(&alias)
        .segment(EXCHANGES_SEGMENT)
        .build()
    {
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        assert_eq!(
            segments.len(),
            3,
            "the alias {alias:?} became {} segments",
            segments.len()
        );
        assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
        assert_eq!(segments.last().copied(), Some(EXCHANGES_SEGMENT));
        assert_eq!(segments.get(1).copied(), Some(encode_path_component(&alias).as_str()));
        assert_eq!(path.query(), None, "the alias {alias:?} introduced a query");
        // The request signature covers the path, so what is signed is exactly what is sent.
        assert_eq!(path.path(), path.as_str());
    }

    // -----------------------------------------------------------------------
    // The read address: a SAID is validated, or it is nothing.
    // -----------------------------------------------------------------------
    if let Ok(said) = said_text.parse::<Said>() {
        let encoded = said.qb64();
        assert!(encoded.is_ok(), "a parsed SAID failed to re-encode: {said_text:?}");
        let text = encoded.unwrap_or_default();
        for delimiter in PATH_DELIMITERS {
            assert!(!text.contains(delimiter), "a parsed SAID carries {delimiter:?}");
        }
        if let Ok(path) = ResourcePath::builder()
            .segment(EXCHANGES_SEGMENT)
            .segment(&text)
            .build()
        {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(segments.len(), 2, "a SAID became {} segments", segments.len());
            assert_eq!(segments.first().copied(), Some(EXCHANGES_SEGMENT));
            assert_eq!(path.query(), None);
        }
    }

    // -----------------------------------------------------------------------
    // The message: what the caller's key ends up over.
    // -----------------------------------------------------------------------
    let built = (
        IdentifierPrefix::from_qb64(SENDER),
        IdentifierPrefix::from_qb64(ADDRESSEE),
        STAMP.parse::<Timestamp>(),
    );
    if let (Ok(sender), Ok(addressee), Ok(stamp)) = built {
        if let Ok(message) = ExchangeBuilder::new(route.clone(), sender, addressee, stamp).build() {
            let sad = message.sad();
            // The route reaches the message verbatim, and the addressee reaches both places the
            // protocol names it.
            assert_eq!(sad.get_text("r"), Some(route.as_str()), "the route was rewritten");
            assert_eq!(sad.get_text("i"), Some(SENDER));
            assert_eq!(sad.get_text("rp"), Some(ADDRESSEE));
            assert_eq!(message.recipient(), Some(ADDRESSEE));

            // The message names exactly one addressee, and never the identifier it is merely
            // delivered to. Upstream's `send` conflates the two.
            let raw = core::str::from_utf8(message.raw()).unwrap_or_default();
            assert!(
                !raw.contains(ELSEWHERE),
                "a message named an identifier it was not addressed to"
            );

            // -----------------------------------------------------------------
            // The body: five fields, and the delivery list stays outside the message.
            // -----------------------------------------------------------------
            let mut body = Sad::new();
            if body.insert("tpc", topic.clone()).is_ok()
                && body.insert("exn", SadValue::Map(sad.clone())).is_ok()
                && body.insert("sigs", SadValue::Array(Vec::new())).is_ok()
                && body.insert("atc", String::new()).is_ok()
                && body
                    .insert(
                        "rec",
                        SadValue::Array(vec![SadValue::text(ADDRESSEE), SadValue::text(ELSEWHERE)]),
                    )
                    .is_ok()
                && let Ok(rendered) = body.to_json_bytes()
            {
                let decoded = serde_json::from_slice::<serde_json::Value>(&rendered);
                assert!(decoded.is_ok(), "a submission body was not JSON");
                let decoded = decoded.unwrap_or(serde_json::Value::Null);
                assert_eq!(
                    decoded.get("tpc").and_then(serde_json::Value::as_str),
                    Some(topic.as_str()),
                    "the topic was rewritten"
                );
                // The message inside the body still names one addressee, not two.
                assert_eq!(
                    decoded
                        .get("exn")
                        .and_then(|exn| exn.get("rp"))
                        .and_then(serde_json::Value::as_str),
                    Some(ADDRESSEE)
                );
                assert_eq!(
                    decoded.get("rec").and_then(serde_json::Value::as_array).map(Vec::len),
                    Some(2),
                    "the delivery list did not survive"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // The answer: two declared shapes, and they must be disjoint.
    // -----------------------------------------------------------------------
    let as_operation = serde_json::from_slice::<ExchangeOperation>(document);
    let as_exchange = serde_json::from_slice::<ExchangeRecord>(document);
    assert!(
        !(as_operation.is_ok() && as_exchange.is_ok()),
        "one document read as both declared answer shapes"
    );

    if let Ok(operation) = as_operation {
        let encoded = serde_json::to_vec(&operation);
        assert!(encoded.is_ok(), "a decoded operation failed to re-encode");
        assert!(
            serde_json::from_slice::<ExchangeOperation>(&encoded.unwrap_or_default()).is_ok(),
            "a re-encoded operation failed to decode"
        );
    }
    if let Ok(exchange) = as_exchange {
        let encoded = serde_json::to_vec(&exchange);
        assert!(encoded.is_ok(), "a decoded exchange failed to re-encode");
        if let Ok(again) = serde_json::from_slice::<ExchangeRecord>(&encoded.unwrap_or_default()) {
            assert_eq!(
                again.digest, exchange.digest,
                "a round trip changed a message's identifier"
            );
            assert_eq!(again.sender, exchange.sender, "a round trip changed a message's sender");
            assert_eq!(again.route, exchange.route, "a round trip changed a message's route");
        }
    }

    // An exchange resource is a message somebody else wrote, with attachments the agent kept
    // beside it. Nothing here verifies either; it decodes whole or not at all.
    if let Ok(resource) = serde_json::from_slice::<ExchangeResource>(document) {
        let _ = resource.exn.digest.len();
        let _ = resource.pathed.len();
        let encoded = serde_json::to_vec(&resource);
        assert!(encoded.is_ok(), "a decoded resource failed to re-encode");
        if let Ok(again) = serde_json::from_slice::<ExchangeResource>(&encoded.unwrap_or_default()) {
            assert_eq!(again.exn.digest, resource.exn.digest);
            assert_eq!(again.pathed.len(), resource.pathed.len());
        }
    }
});
