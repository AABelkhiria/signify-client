//! Invariants of the schema endpoint family.
//!
//! One dynamic value reaches a path here — a schema SAID — and the reference interpolates it raw.
//! The property that matters is that it can never do so: what is not a SAID is refused, and what is
//! one carries no delimiter to escape with.
//!
//! The rest is about the answer. A `Schema` is the largest document any endpoint in this crate
//! returns, because `properties` is an open JSON Schema map of arbitrary depth — so what it accepts,
//! what it refuses, and what survives re-encoding are worth stating for every shape rather than the
//! two the fixture records.

use std::error::Error;

use proptest::prelude::*;
use serde_json::{Value, json};
use signify_client::endpoint::schemas::SCHEMA_SEGMENT;
use signify_http::request::ResourcePath;
use signify_keri::said::Said;
use signify_types::api::{MAX_NESTING_DEPTH, Schema};

const QVI: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/// Syntactically valid Blake3-256 SAIDs.
fn saids() -> impl Strategy<Value = Said> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a said", |body| Said::from_qb64(&format!("E{body}")).ok())
}

/// Text that would reshape a path if it ever reached one unencoded.
fn hostile_text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[\\PC]{0,48}",
        Just("E/../schema".to_owned()),
        Just("E?x=1".to_owned()),
        Just("E#y".to_owned()),
        Just("..".to_owned()),
        Just(String::new()),
    ]
}

/// A complete schema document with the given open `properties` block.
fn schema_document(said: &str, properties: &Value) -> String {
    json!({
        "$id": said,
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "t",
        "description": "d",
        "type": "object",
        "credentialType": "C",
        "version": "1.0.0",
        "properties": properties.clone(),
        "additionalProperties": false,
        "required": ["i", "d"],
    })
    .to_string()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// A SAID reaches the path as exactly one segment and byte-identically to what the reference
    /// interpolates raw — because a qualified digest's alphabet is URL-safe Base64.
    #[test]
    fn a_said_is_always_exactly_one_path_segment(said in saids()) {
        let text = said.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let path = ResourcePath::builder()
            .segment(SCHEMA_SEGMENT)
            .segment(&text)
            .build()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(segments.len(), 2, "a SAID became {} segments", segments.len());
        prop_assert_eq!(segments.first().copied(), Some(SCHEMA_SEGMENT));
        prop_assert_eq!(path.query(), None);
        prop_assert!(!path.as_str().contains('#'));
        // Byte for byte what the reference sends, encoding notwithstanding.
        prop_assert_eq!(path.as_str(), format!("/{SCHEMA_SEGMENT}/{text}"));
    }

    /// Nothing that would reshape a path is ever a valid SAID, so the reference's injection has no
    /// representable input here.
    #[test]
    fn hostile_text_is_never_a_said(text in hostile_text()) {
        if let Ok(said) = Said::from_qb64(&text) {
            let encoded = said.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
            for delimiter in ['/', '?', '#', '=', '&', '%', '.'] {
                prop_assert!(!encoded.contains(delimiter), "a valid SAID carries {:?}", delimiter);
            }
        }
    }

    /// A complete schema keeps its open `properties` block verbatim, whatever it holds, and
    /// survives its own encoding.
    #[test]
    fn an_accepted_schema_keeps_its_properties_verbatim(
        labels in proptest::collection::vec("[a-zA-Z][a-zA-Z0-9_]{0,12}", 0..8),
    ) {
        let mut properties = serde_json::Map::new();
        for (index, label) in labels.iter().enumerate() {
            properties.insert(label.clone(), json!({ "type": "string", "index": index }));
        }
        let expected = properties.len();
        let document = schema_document(QVI, &Value::Object(properties));

        let schema: Schema = serde_json::from_str(&document)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(schema.properties.len(), expected);
        prop_assert_eq!(schema.id.as_str(), QVI);

        let encoded = serde_json::to_string(&schema)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let again: Schema = serde_json::from_str(&encoded)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(again, schema);
    }

    /// A schema missing any one of its ten required fields is refused — where the reference casts
    /// whatever arrived and hands it over.
    #[test]
    fn a_schema_missing_any_required_field_is_refused(dropped in 0_usize..10) {
        const FIELDS: [&str; 10] = [
            "$id", "$schema", "title", "description", "type",
            "credentialType", "version", "properties", "additionalProperties", "required",
        ];
        let complete = schema_document(QVI, &json!({}));
        let mut document: Value = serde_json::from_str(&complete)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let label = FIELDS.get(dropped).copied().unwrap_or("$id");
        if let Some(fields) = document.as_object_mut() {
            fields.remove(label);
        }
        prop_assert!(
            serde_json::from_str::<Schema>(&document.to_string()).is_err(),
            "a schema without {} was accepted",
            label
        );
    }

    /// Arbitrary bytes never panic: an answer either decodes or is refused with a reason.
    #[test]
    fn arbitrary_bytes_decode_or_are_refused(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        match serde_json::from_slice::<Schema>(&bytes) {
            Ok(schema) => {
                let encoded = serde_json::to_vec(&schema)
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                let again: Schema = serde_json::from_slice(&encoded)
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                prop_assert_eq!(again, schema);
            }
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }
}

/// Regression: the listing's address is constant, so nothing a caller does can change it.
#[test]
fn the_listing_address_carries_no_input() -> Result<(), Box<dyn Error>> {
    let first = ResourcePath::builder().segment(SCHEMA_SEGMENT).build()?;
    let second = ResourcePath::builder().segment(SCHEMA_SEGMENT).build()?;
    assert_eq!(first.as_str(), second.as_str());
    assert_eq!(first.as_str(), "/schema");
    assert_eq!(first.query(), None);
    Ok(())
}

/// Regression: a deeply nested `properties` block is bounded rather than a stack overflow.
///
/// `properties` is open JSON Schema, so an agent can nest it arbitrarily deep. `serde_json`'s own
/// recursion limit refuses beyond its depth — which is what keeps the endpoint decoder safe, since
/// it calls `serde_json` directly rather than Roadmap 4.1's bounded
/// [`from_json_slice`](signify_types::api::from_json_slice). This asserts that rather than assuming
/// it; `PORTING.md` records the inconsistency for Roadmap 9.3.
#[test]
fn a_deeply_nested_properties_block_is_refused_rather_than_crashing() -> Result<(), Box<dyn Error>> {
    /// Builds a schema whose `properties` nests `depth` objects deep, as raw text.
    fn nested_document(depth: usize) -> String {
        let mut properties = String::new();
        for _ in 0..depth {
            properties.push_str(r#"{"a":"#);
        }
        properties.push('1');
        for _ in 0..depth {
            properties.push('}');
        }
        format!(
            r#"{{"$id":"{QVI}","$schema":"s","title":"t","description":"d","type":"object","credentialType":"C","version":"1.0.0","properties":{properties},"additionalProperties":false,"required":[]}}"#
        )
    }

    // Shallow nesting decodes and keeps every level.
    let shallow: Schema = serde_json::from_str(&nested_document(8))?;
    assert_eq!(shallow.properties.len(), 1);

    // Deep nesting is a typed refusal rather than a crash, and it names why.
    let deep = serde_json::from_str::<Schema>(&nested_document(MAX_NESTING_DEPTH * 4));
    let error = deep.err().ok_or("a deeply nested schema was accepted")?;
    assert!(
        error.to_string().contains("recursion limit"),
        "the refusal did not name the depth bound: {error}"
    );
    Ok(())
}

/// Regression: an empty `properties` block and an absent one are not the same thing — the field is
/// required, so only the first is a schema at all.
#[test]
fn an_empty_properties_block_is_a_schema_and_an_absent_one_is_not() -> Result<(), Box<dyn Error>> {
    let empty: Schema = serde_json::from_str(&schema_document(QVI, &json!({})))?;
    assert!(empty.properties.is_empty());

    let mut absent: Value = serde_json::from_str(&schema_document(QVI, &json!({})))?;
    if let Some(fields) = absent.as_object_mut() {
        fields.remove("properties");
    }
    assert!(serde_json::from_str::<Schema>(&absent.to_string()).is_err());
    Ok(())
}

/// Regression: the two SAIDs the reference's integration test uses are both valid, and neither
/// changes under encoding.
#[test]
fn the_integration_saids_survive_the_path_unchanged() -> Result<(), Box<dyn Error>> {
    for said in [QVI, "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"] {
        let parsed = Said::from_qb64(said)?;
        let path = ResourcePath::builder()
            .segment(SCHEMA_SEGMENT)
            .segment(&parsed.qb64()?)
            .build()?;
        assert_eq!(path.as_str(), format!("/schema/{said}"));
    }
    Ok(())
}
