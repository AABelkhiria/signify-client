//! Invariants of the contacts endpoint.
//!
//! Five untrusted values, none of which can reshape a request, and a filter that is always whole or absent.

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

fn prefixes() -> impl Strategy<Value = IdentifierPrefix> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a prefix", |body| {
        IdentifierPrefix::from_qb64(&format!("E{body}")).ok()
    })
}

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

const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

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
        let expected = if group.is_some() { 3 } else { 2 };
        prop_assert_eq!(query.split('&').count(), expected, "the query was {}", query);
    }

    #[test]
    fn a_query_value_never_adds_a_parameter(group in hostile_text(), value in hostile_text()) {
        let filter = ContactFilter::new(ALIAS_FIELD, value);
        let path = listing(Some(&group), Some(&filter))?;
        let query = path.query().unwrap_or_default();
        prop_assert_eq!(query.split('&').count(), 3, "the query was {}", query);
        prop_assert_eq!(query.matches('=').count(), 3);
        prop_assert_eq!(path.path(), format!("/{CONTACTS_SEGMENT}"));
    }

    #[test]
    fn a_listing_carries_a_query_exactly_when_asked(
        group in proptest::option::of(hostile_text()),
        filter_value in proptest::option::of(hostile_text()),
    ) {
        let filter = filter_value.map(|value| ContactFilter::new(ALIAS_FIELD, value));
        let path = listing(group.as_deref(), filter.as_ref())?;
        let asked = group.is_some() || filter.is_some();
        prop_assert_eq!(path.query().is_some(), asked, "the path was {}", path.as_str());
        prop_assert!(!path.as_str().ends_with('?'));
        if !asked {
            prop_assert_eq!(path.as_str(), "/contacts");
        }
        prop_assert_eq!(path.path(), format!("/{CONTACTS_SEGMENT}"));
    }

    #[test]
    fn an_info_body_is_exactly_what_it_was_given(
        entries in proptest::collection::vec((labels(), hostile_text()), 0..8),
    ) {
        let mut info = Sad::new();
        let mut written: Vec<(String, String)> = Vec::new();
        for (label, value) in entries {
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
        let text = String::from_utf8(bytes).map_err(fail)?;
        let mut cursor = 0;
        for (label, _) in &written {
            let needle = format!("{}:", serde_json::to_string(label).map_err(fail)?);
            let found = text[cursor..].find(&needle).ok_or_else(|| fail("a field went missing"))?;
            cursor = cursor.saturating_add(found).saturating_add(needle.len());
        }
    }

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
            prop_assert_eq!(contact.additional.get(&extra).and_then(Value::as_str), Some("kept"));
        }

        if let Some(object) = document.as_object_mut() {
            object.remove("id");
        }
        prop_assert!(serde_json::from_value::<Contact>(document).is_err());
    }
}

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

#[test]
fn a_duplicate_info_label_is_refused() -> Result<(), Box<dyn Error>> {
    let mut info = Sad::new();
    info.insert("company", "First".to_owned())?;
    assert!(info.insert("company", "Second".to_owned()).is_err());
    assert_eq!(String::from_utf8(info.to_json_bytes()?)?, r#"{"company":"First"}"#);
    Ok(())
}

#[test]
fn a_hostile_identifier_is_not_a_prefix() {
    for hostile in [
        "a/b",
        "a/b?c=d",
        "../identifiers",
        "..",
        "",
        "not a prefix",
        "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqa",
    ] {
        assert!(
            IdentifierPrefix::from_qb64(hostile).is_err(),
            "{hostile:?} was accepted as a contact identifier"
        );
    }
    assert!(IdentifierPrefix::from_qb64(CONTACT).is_ok());
}
