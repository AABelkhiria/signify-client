#![no_main]

//! Fuzzes the contacts endpoint over hostile identifiers, filters, info bodies, and agent answers.
//!
//! Four things come from outside. A **contact's identifier** is a path component the reference
//! concatenates raw — the `http-request-response` fixture recorded `contacts().delete("a/b")`
//! reaching two segments — and the request signature covers `@path`. A **group** and a **filter**
//! are query values. A caller's **info body** is an open document whose bytes this port promises to
//! preserve exactly.
//!
//! The fourth is the one worth naming: **an agent's answer is a trust statement**. A `Contact`
//! carries `ends`, which say which endpoints may speak for that identifier, and `challenges`, whose
//! `authenticated` flag says whether somebody proved they control it. A caller that believes a
//! wrong-shaped answer believes those. So the target asserts a contact is decoded rather than cast:
//! it needs its identifier, and everything else it carries survives a round trip unchanged.
//!
//! Nothing panics, no component escapes its segment, a filter is always whole, and an info body is
//! always exactly what it was given.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::contacts::{
    CONTACTS_SEGMENT, ContactFilter, FILTER_FIELD_PARAMETER, FILTER_VALUE_PARAMETER, GROUP_PARAMETER,
};
use signify_client::protocol::prefix::IdentifierPrefix;
use signify_client::protocol::serialization::{Sad, SadValue};
use signify_client::types::api::Contact;
use signify_http::request::ResourcePath;

/// Every character that would give a path component a meaning it did not have.
const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let identifier = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let group = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let field = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let value = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let label = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let document = parts.next().unwrap_or_default();

    // -----------------------------------------------------------------------
    // The record path: an identifier is a validated prefix or it is nothing.
    // -----------------------------------------------------------------------
    if let Ok(prefix) = IdentifierPrefix::from_qb64(&identifier) {
        let re_encoded = prefix.qb64();
        assert!(
            re_encoded.is_ok(),
            "a parsed prefix failed to re-encode: {identifier:?}"
        );
        let text = re_encoded.unwrap_or_default();
        // A qualified prefix's alphabet is URL-safe Base64, so it reaches the path unchanged.
        for delimiter in PATH_DELIMITERS {
            assert!(
                !text.contains(delimiter),
                "a parsed prefix carries {delimiter:?}: {identifier:?}"
            );
        }
        if let Ok(path) = ResourcePath::builder().segment(CONTACTS_SEGMENT).segment(&text).build() {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(segments.len(), 2, "an identifier became {} segments", segments.len());
            assert_eq!(segments.first().copied(), Some(CONTACTS_SEGMENT));
            assert_eq!(path.query(), None, "an identifier introduced a query");
        }
    }

    // -----------------------------------------------------------------------
    // The listing path: a filter is whole, and no value adds a parameter.
    // -----------------------------------------------------------------------
    let filter = ContactFilter::new(field.clone(), value.clone());
    assert_eq!(filter.field, field, "a filter changed its own field");
    assert_eq!(filter.value, value, "a filter changed its own value");

    if let Ok(path) = ResourcePath::builder()
        .segment(CONTACTS_SEGMENT)
        .parameter(GROUP_PARAMETER, &group)
        .parameter(FILTER_FIELD_PARAMETER, &filter.field)
        .parameter(FILTER_VALUE_PARAMETER, &filter.value)
        .build()
    {
        // Exactly the three parameters asked for, whatever any of them held.
        let query = path.query().unwrap_or_default();
        assert_eq!(query.split('&').count(), 3, "the query was {query:?}");
        assert_eq!(query.matches('=').count(), 3, "the query was {query:?}");
        assert!(query.contains(FILTER_FIELD_PARAMETER));
        assert!(query.contains(FILTER_VALUE_PARAMETER));
        // The signed path never carries the query, so no filter changes what is signed.
        assert_eq!(path.path(), "/contacts");
    }

    // An unfiltered listing is always the bare resource — never the reference's `/contacts?`.
    if let Ok(path) = ResourcePath::builder().segment(CONTACTS_SEGMENT).build() {
        assert_eq!(path.as_str(), "/contacts");
        assert_eq!(path.query(), None);
    }

    // -----------------------------------------------------------------------
    // The info body: exactly what it was given, in the order it was given.
    // -----------------------------------------------------------------------
    let mut info = Sad::new();
    let first = info.insert(label.clone(), SadValue::text(value.clone()));
    if first.is_ok() {
        // A duplicate label is refused rather than overwriting, which is where this port is
        // stricter than `JSON.stringify`.
        assert!(
            info.insert(label.clone(), SadValue::text("other")).is_err(),
            "a duplicate label was accepted"
        );
        if let Ok(bytes) = info.to_json_bytes() {
            let decoded = serde_json::from_slice::<serde_json::Value>(&bytes);
            assert!(decoded.is_ok(), "an info body was not JSON");
            let decoded = decoded.unwrap_or(serde_json::Value::Null);
            assert_eq!(
                decoded.get(&label).and_then(serde_json::Value::as_str),
                Some(value.as_str()),
                "an info body rewrote its own value"
            );
            assert_eq!(decoded.as_object().map(serde_json::Map::len), Some(1));
        }
    }

    // -----------------------------------------------------------------------
    // The agent's answer, which is a trust statement about somebody else.
    // -----------------------------------------------------------------------
    if let Ok(contact) = serde_json::from_slice::<Contact>(document) {
        // The one field the schema requires is the one the reference casts past.
        let _ = contact.id.len();

        // Everything the agent sent survives a round trip, including the endpoint authorizations
        // and challenge verdicts a caller may act on.
        let encoded = serde_json::to_vec(&contact);
        assert!(encoded.is_ok(), "a decoded contact failed to re-encode");
        let again = serde_json::from_slice::<Contact>(&encoded.unwrap_or_default());
        assert!(again.is_ok(), "a re-encoded contact failed to decode");
        if let Ok(again) = again {
            assert_eq!(again.id, contact.id, "a round trip changed a contact's identifier");
            assert_eq!(again.alias, contact.alias);
            assert_eq!(again.ends, contact.ends, "a round trip changed a contact's endpoints");
            assert_eq!(
                again.challenges, contact.challenges,
                "a round trip changed a contact's challenge verdicts"
            );
            assert_eq!(again.well_knowns, contact.well_knowns);
        }
    }

    // A listing decodes as a whole or not at all: one bad entry refuses the answer, where the
    // reference casts the array and hands every entry over.
    if let Ok(listing) = serde_json::from_slice::<Vec<Contact>>(document) {
        for entry in &listing {
            let _ = entry.id.len();
        }
        let encoded = serde_json::to_vec(&listing);
        assert!(encoded.is_ok(), "a decoded listing failed to re-encode");
        let again = serde_json::from_slice::<Vec<Contact>>(&encoded.unwrap_or_default());
        assert_eq!(
            again.map(|records| records.len()).ok(),
            Some(listing.len()),
            "a listing did not survive a round trip"
        );
    }
});
