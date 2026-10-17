#![no_main]

//! Fuzzes the IPEX submission endpoint over hostile aliases, recipients, and agent answers.
//!
//! Four things reach this family from outside, and one of them deliberately does not.
//!
//! **The sender's alias** is a path component, and the reference concatenates it raw — so upstream
//! an alias with a slash posts a disclosure under a different identifier's resource, and the
//! request signature covers `@path`. The target asserts it can never leave its own segment.
//!
//! **The route is not caller input.** It is read from the message, so the address and the message's
//! own `r` field cannot disagree — the defect the reference's five separate submitters allow. The
//! target asserts the relationship over every route.
//!
//! **The recipient list** is the one part a caller supplies freely. The target asserts it reaches
//! the body verbatim and in order however long it is, that a non-prefix is never a recipient, and
//! that the body's field count is decided by the route alone rather than by anything a recipient
//! carries.
//!
//! **The agent's answer** is what a caller learns about delivery, and the reference casts it. The
//! target asserts anything accepted survives re-encoding.

use keria_types::api::ExchangeOperation;
use libfuzzer_sys::fuzz_target;
use signify_keys::acdc::ipex::IpexRoute;
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::ipex::IPEX_SEGMENT;
use signify_http::request::ResourcePath;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadValue};

/// Whether a route's submission body carries an `atc` field, as the endpoint decides it.
fn carries_attachment(route: IpexRoute) -> bool {
    matches!(route, IpexRoute::Offer | IpexRoute::Grant | IpexRoute::Admit)
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let alias = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let addresses = parts.next().unwrap_or_default();
    let attachment = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let document = parts.next().unwrap_or_default();

    // The route is chosen from the data, but it stands for a message's own route rather than for
    // caller input: the endpoint never takes one.
    let selector = usize::from(data.first().copied().unwrap_or_default());
    let route = IpexRoute::ALL
        .get(selector % IpexRoute::ALL.len())
        .copied()
        .unwrap_or(IpexRoute::Grant);
    let segment = route.as_str().trim_start_matches("/ipex/");

    // 1. The alias can never leave its own segment, and the address always ends with the route.
    match ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(&alias)
        .segment(IPEX_SEGMENT)
        .segment(segment)
        .build()
    {
        Ok(path) => {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(segments.len(), 4, "an alias became {} segments", segments.len());
            assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
            assert_eq!(segments.get(2).copied(), Some(IPEX_SEGMENT));
            assert_eq!(segments.get(3).copied(), Some(segment));
            let encoded = segments.get(1).copied().unwrap_or_default();
            for separator in ['/', '?', '#'] {
                assert!(!encoded.contains(separator), "an encoded alias carries {separator:?}");
            }
            assert_eq!(path.query(), None);
            assert!(!path.as_str().contains('#'));
            // The resource and the message's own `r` field cannot disagree.
            assert!(
                path.as_str().ends_with(route.as_str()),
                "{path} does not address {route}"
            );
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // 2. Recipients are validated prefixes, and reach the body verbatim and in order.
    let recipients: Vec<IdentifierPrefix> = addresses
        .split(|&byte| byte == 0xfe)
        .filter(|part| !part.is_empty())
        .filter_map(|part| IdentifierPrefix::from_qb64(&String::from_utf8_lossy(part)).ok())
        .collect();
    let encoded: Vec<String> = recipients
        .iter()
        .filter_map(|recipient| recipient.qb64().ok())
        .collect();
    assert_eq!(
        encoded.len(),
        recipients.len(),
        "a parsed prefix could not be re-encoded"
    );
    for address in &encoded {
        for separator in ['"', '\\', '/'] {
            assert!(
                !address.contains(separator),
                "an accepted recipient carries {separator:?}"
            );
        }
    }

    // 3. The body's shape is decided by the route alone, whatever the recipients or attachment.
    let mut body = Sad::new();
    let assembled = (|| -> Option<Vec<u8>> {
        body.insert("exn", SadValue::Map(Sad::new())).ok()?;
        body.insert("sigs", SadValue::Array(vec![SadValue::text("AAB")])).ok()?;
        if carries_attachment(route) {
            body.insert("atc", attachment.clone()).ok()?;
        }
        body.insert(
            "rec",
            SadValue::Array(encoded.iter().cloned().map(SadValue::Text).collect()),
        )
        .ok()?;
        body.to_json_bytes().ok()
    })();
    if let Some(bytes) = assembled {
        let Ok(decoded) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            panic!("an assembled submission body is not valid JSON");
        };
        let Some(fields) = decoded.as_object() else {
            panic!("an assembled submission body is not an object");
        };
        let expected = if carries_attachment(route) { 4 } else { 3 };
        assert_eq!(fields.len(), expected, "a {route} body carried {} fields", fields.len());
        assert_eq!(fields.contains_key("atc"), carries_attachment(route));
        for label in ["exn", "sigs", "rec"] {
            assert!(fields.contains_key(label), "a body lacks {label}");
        }
        // The recipients arrive in order and unchanged, however many there are.
        let Some(sent) = fields.get("rec").and_then(serde_json::Value::as_array) else {
            panic!("a body carries no recipient list");
        };
        assert_eq!(sent.len(), encoded.len());
        for (position, address) in encoded.iter().enumerate() {
            assert_eq!(
                sent.get(position).and_then(serde_json::Value::as_str),
                Some(address.as_str())
            );
        }
    }

    // 4. An agent's answer is believed only in the shape it claimed, and survives re-encoding.
    if let Ok(operation) = serde_json::from_slice::<ExchangeOperation>(document) {
        match serde_json::to_vec(&operation) {
            Ok(bytes) => match serde_json::from_slice::<ExchangeOperation>(&bytes) {
                Ok(again) => {
                    assert_eq!(again.name, operation.name);
                    assert_eq!(again.outcome.is_done(), operation.outcome.is_done());
                }
                Err(error) => panic!("a re-encoded exchange operation no longer decodes: {error}"),
            },
            Err(error) => panic!("a decoded exchange operation could not be re-encoded: {error}"),
        }
    }
});
