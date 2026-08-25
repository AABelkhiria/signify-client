//! Invariants of the contacts endpoint.
//!
//! Three dynamic values reach an address here — a contact's identifier as a path segment, and a
//! group and a filter as query values — and the reference concatenates the first raw while encoding
//! the other two. The properties that matter are that none of them can reshape a request whatever
//! they hold, and that **a filter is always whole**: upstream, naming one half without the other
//! drops both and answers with an unfiltered listing, which is a mistake that succeeds.
//!
//! The fourth untrusted value is the agent's answer, and the fifth is the caller's own contact info
//! — an open bag whose bytes this port lets them control exactly.

use std::error::Error;

use proptest::prelude::*;
use serde_json::{Value, json};
use signify_client::endpoint::contacts::{
    ALIAS_FIELD, CONTACTS_SEGMENT, ContactFilter, FILTER_FIELD_PARAMETER, FILTER_VALUE_PARAMETER, GROUP_PARAMETER,
};
use signify_http::request::ResourcePath;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::serialization::{Sad, SadValue};
use signify_types::api::Contact;

const CONTACT: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

/// Syntactically valid Blake3-256 identifier prefixes.
fn prefixes() -> impl Strategy<Value = IdentifierPrefix> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a prefix", |body| {
        IdentifierPrefix::from_qb64(&format!("E{body}")).ok()
    })
}

/// Text that would reshape a path or a query if it ever reached one unencoded.
fn hostile_text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[\\PC]{0,48}",
        Just("a/b?c=d".to_owned()),
        Just("../identifiers".to_owned()),
        Just("a&b=c".to_owned()),
        Just("^alice$".to_owned()),
        Just("#fragment".to_owned()),
        Just(String::new()),
    ]
}

/// Field labels a caller might put in a contact info body.
fn labels() -> impl Strategy<Value = String> {
    prop_oneof!["[a-zA-Z][a-zA-Z0-9_-]{0,16}", hostile_text()]
}

fn listing(group: Option<&str>, filter: Option<&ContactFilter>) -> Result<ResourcePath, TestCaseError> {
    let mut builder = ResourcePath::builder()
        .segment(CONTACTS_SEGMENT)
        .optional_parameter(GROUP_PARAMETER, group);
    if let Some(filter) = filter {
        builder = builder
            .parameter(FILTER_FIELD_PARAMETER, &filter.field)
            .parameter(FILTER_VALUE_PARAMETER, &filter.value);
    }
    builder.build().map_err(fail)
}

fn record_path(prefix: &IdentifierPrefix) -> Result<ResourcePath, TestCaseError> {
    ResourcePath::builder()
        .segment(CONTACTS_SEGMENT)
        .segment(&prefix.qb64().map_err(fail)?)
        .build()
        .map_err(fail)
}

/// Every character that would give a path component a meaning it did not have.
const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// A contact's identifier reaches the path byte-identically to what the reference concatenates
    /// raw — because a qualified prefix's alphabet is URL-safe Base64.
    ///
    /// This is what makes taking a validated type a refusal of hostile input rather than a
    /// divergence: every real contact identifier addresses exactly what upstream addresses.
    #[test]
    fn a_prefix_reaches_the_path_unchanged(prefix in prefixes()) {
        let text = prefix.qb64().map_err(fail)?;
        let path = record_path(&prefix)?;
        prop_assert_eq!(path.as_str(), format!("/{CONTACTS_SEGMENT}/{text}"));
        prop_assert_eq!(path.query(), None);
        prop_assert_eq!(path.path().split('/').count(), 3);
        for delimiter in PATH_DELIMITERS {
            prop_assert!(!text.contains(delimiter));
        }
    }

    /// **A filter is always whole.** Both parameters are written or neither is, whatever either
    /// half holds — where upstream drops both when one is missing.
    #[test]
    fn a_filter_always_writes_both_halves(
        group in proptest::option::of("[a-z]{1,12}"),
        field in labels(),
        value in hostile_text(),
    ) {
        let filter = ContactFilter::new(field, value);
        let filtered = listing(group.as_deref(), Some(&filter))?;
        let query = filtered.query().unwrap_or_default();
        prop_assert!(query.contains(FILTER_FIELD_PARAMETER), "a filter wrote no field");
        prop_assert!(query.contains(FILTER_VALUE_PARAMETER), "a filter wrote no value");
        // Exactly the parameters that were asked for: two, or three with a group.
        let expected = if group.is_some() { 3 } else { 2 };
        prop_assert_eq!(query.split('&').count(), expected, "the query was {}", query);
    }

    /// A group and a filter value can never introduce a query parameter of their own.
    ///
    /// The reference encodes these two — `URLSearchParams`, not interpolation — so this agrees with
    /// it rather than diverging from it, which is worth stating because Roadmap 7.1 found the
    /// opposite in the same position.
    #[test]
    fn a_query_value_never_adds_a_parameter(group in hostile_text(), value in hostile_text()) {
        let filter = ContactFilter::new(ALIAS_FIELD, value);
        let path = listing(Some(&group), Some(&filter))?;
        let query = path.query().unwrap_or_default();
        prop_assert_eq!(query.split('&').count(), 3, "the query was {}", query);
        prop_assert_eq!(query.matches('=').count(), 3);
        // And the signed path never carries the query, so every listing signs identically.
        prop_assert_eq!(path.path(), format!("/{CONTACTS_SEGMENT}"));
    }

    /// A listing carries a query exactly when it was asked to, and never a bare `?`.
    ///
    /// Upstream concatenates `'?' + params.toString()` unconditionally, so the empty case is the
    /// one deliberate byte difference — and it is the *only* one, whichever arguments are given.
    #[test]
    fn a_listing_carries_a_query_exactly_when_asked(
        group in proptest::option::of(hostile_text()),
        filter_value in proptest::option::of(hostile_text()),
    ) {
        let filter = filter_value.map(|value| ContactFilter::new(ALIAS_FIELD, value));
        let path = listing(group.as_deref(), filter.as_ref())?;
        let asked = group.is_some() || filter.is_some();
        prop_assert_eq!(path.query().is_some(), asked, "the path was {}", path.as_str());
        // Never a bare question mark, whichever way it went.
        prop_assert!(!path.as_str().ends_with('?'));
        if !asked {
            prop_assert_eq!(path.as_str(), "/contacts");
        }
        // And the resource itself never moves.
        prop_assert_eq!(path.path(), format!("/{CONTACTS_SEGMENT}"));
    }

    /// A contact info body writes exactly the fields it was given, in the order it was given them.
    ///
    /// The reference hands the caller's object literal to `JSON.stringify`, so the order is theirs;
    /// Roadmap 3.2's ordered document reproduces that exactly.
    #[test]
    fn an_info_body_is_exactly_what_it_was_given(
        entries in proptest::collection::vec((labels(), hostile_text()), 0..8),
    ) {
        let mut info = Sad::new();
        let mut written: Vec<(String, String)> = Vec::new();
        for (label, value) in entries {
            // A duplicate label is refused rather than silently overwriting, which is `Sad`'s rule.
            if info.insert(label.clone(), SadValue::text(value.clone())).is_ok() {
                written.push((label, value));
            }
        }
        let bytes = info.to_json_bytes().map_err(fail)?;
        let decoded: Value = serde_json::from_slice(&bytes).map_err(fail)?;
        let object = decoded.as_object().ok_or_else(|| fail("an info body is not an object"))?;

        prop_assert_eq!(object.len(), written.len());
        for (label, value) in &written {
            prop_assert_eq!(object.get(label).and_then(Value::as_str), Some(value.as_str()));
        }
        // Order is preserved, which a sorted map would not do.
        let text = String::from_utf8(bytes).map_err(fail)?;
        let mut cursor = 0;
        for (label, _) in &written {
            let needle = format!("{}:", serde_json::to_string(label).map_err(fail)?);
            let found = text[cursor..].find(&needle).ok_or_else(|| fail("a field went missing"))?;
            cursor = cursor.saturating_add(found).saturating_add(needle.len());
        }
    }

    /// A contact needs its identifier and keeps every other field the agent sent.
    #[test]
    fn a_contact_needs_its_identifier_and_keeps_the_rest(
        id in prefixes(),
        extra in labels(),
        alias in proptest::option::of("[a-z]{1,12}"),
    ) {
        let id = id.qb64().map_err(fail)?;
        let mut document = json!({ "id": id });
        if let Some(object) = document.as_object_mut() {
            if let Some(alias) = &alias {
                object.insert("alias".to_owned(), json!(alias));
            }
            if extra != "id" && extra != "alias" {
                object.insert(extra.clone(), json!("kept"));
            }
        }
        let contact: Contact = serde_json::from_value(document.clone()).map_err(fail)?;
        prop_assert_eq!(&contact.id, &id);
        prop_assert_eq!(contact.alias.as_deref(), alias.as_deref());
        if extra != "id" && extra != "alias" {
            // A field the schema does not name lands in the open map rather than being dropped.
            prop_assert_eq!(contact.additional.get(&extra).and_then(Value::as_str), Some("kept"));
        }

        // Without an identifier there is no contact, which is what the reference casts past.
        if let Some(object) = document.as_object_mut() {
            object.remove("id");
        }
        prop_assert!(serde_json::from_value::<Contact>(document).is_err());
    }
}

/// A filter value of exactly `^alice$` reaches the wire as the reference encodes it.
///
/// The named regression for the reference's own integration helper, whose filter value is a regular
/// expression: the anchors are percent-encoded on both sides, so the agent sees the same pattern.
#[test]
fn the_integration_helpers_regular_expression_is_encoded_identically() -> Result<(), Box<dyn Error>> {
    let filter = ContactFilter::alias("^alice$");
    let path = ResourcePath::builder()
        .segment(CONTACTS_SEGMENT)
        .parameter(FILTER_FIELD_PARAMETER, &filter.field)
        .parameter(FILTER_VALUE_PARAMETER, &filter.value)
        .build()?;
    assert_eq!(path.as_str(), "/contacts?filter_field=alias&filter_value=%5Ealice%24");
    Ok(())
}

/// A group of exactly `..` stays a query value and never becomes a path segment.
///
/// Found while writing the properties: a group is the one listing argument that is *not* a path
/// component here or upstream, so the dot segments that matter elsewhere are inert.
#[test]
fn a_group_of_two_dots_stays_a_query_value() -> Result<(), Box<dyn Error>> {
    let path = ResourcePath::builder()
        .segment(CONTACTS_SEGMENT)
        .parameter(GROUP_PARAMETER, "..")
        .build()?;
    assert_eq!(path.as_str(), "/contacts?group=..");
    assert_eq!(path.path(), "/contacts");
    Ok(())
}

/// A duplicate label in a contact info body is refused rather than silently overwriting.
///
/// The named regression for the one place this port is stricter than `JSON.stringify`, which keeps
/// the last of two identically-named object properties.
#[test]
fn a_duplicate_info_label_is_refused() -> Result<(), Box<dyn Error>> {
    let mut info = Sad::new();
    info.insert("company", "First".to_owned())?;
    assert!(info.insert("company", "Second".to_owned()).is_err());
    assert_eq!(String::from_utf8(info.to_json_bytes()?)?, r#"{"company":"First"}"#);
    Ok(())
}

/// A hostile identifier never reaches a contact path, whatever it holds.
///
/// The named regression for the defect Roadmap 5.3's own fixture recorded:
/// `contacts().delete("a/b")` addresses two segments upstream.
#[test]
fn a_hostile_identifier_is_not_a_prefix() {
    for hostile in [
        "a/b",
        "a/b?c=d",
        "../identifiers",
        "..",
        "",
        "not a prefix",
        // One character short of the real one.
        "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqa",
    ] {
        assert!(
            IdentifierPrefix::from_qb64(hostile).is_err(),
            "{hostile:?} was accepted as a contact identifier"
        );
    }
    // And the real one still parses, so nothing legitimate was narrowed away.
    assert!(IdentifierPrefix::from_qb64(CONTACT).is_ok());
}
