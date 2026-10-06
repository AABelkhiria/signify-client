//! Invariants of the credentials endpoint family.
//!
//! Seven raw-interpolated path values that can never escape their segment, and the two documents this family owns.

use std::error::Error;

use keria_types::api::Credential as CredentialRecord;
use proptest::prelude::*;
use serde_json::{Value, json};
use signify_acdc::credential::RegistryIdentifier;
use signify_client::endpoint::credentials::{
    CREDENTIAL_QUERY_SEGMENT, CREDENTIALS_SEGMENT, CredentialFilter, DEFAULT_CREDENTIAL_LIMIT,
};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::registries::REGISTRIES_SEGMENT;
use signify_http::request::ResourcePath;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};

const CREDENTIAL: &str = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const ISSUANCE: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";
const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

fn saids() -> impl Strategy<Value = Said> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a said", |body| Said::from_qb64(&format!("E{body}")).ok())
}

fn hostile_text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[\\PC]{0,48}",
        Just("E/../identifiers".to_owned()),
        Just("E?x=1".to_owned()),
        Just("E#y".to_owned()),
        Just("a/b".to_owned()),
        Just("..".to_owned()),
        Just(String::new()),
    ]
}

fn query_labels() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("-i".to_owned()),
        Just("-s".to_owned()),
        Just("$eq".to_owned()),
        Just("-d".to_owned()),
        "[a-zA-Z$-][a-zA-Z0-9$_-]{0,12}",
    ]
}

fn credential_document(status: &str) -> String {
    json!({
        "sad": {
            "v": "ACDC10JSON000197_",
            "d": CREDENTIAL,
            "i": ISSUER,
            "ri": REGISTRY,
            "s": SCHEMA,
            "a": { "d": "EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P", "i": ISSUER, "dt": "2023-08-23T15:16:07.553000+00:00" },
        },
        "atc": "-IAB",
        "iss": {
            "v": "KERI10JSON0000ed_",
            "t": "iss",
            "d": ISSUANCE,
            "i": CREDENTIAL,
            "s": "0",
            "ri": REGISTRY,
            "dt": "2023-08-23T15:16:07.553000+00:00",
        },
        "issatc": "-VAS",
        "pre": ISSUER,
        "schema": {
            "$id": SCHEMA,
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "t",
            "description": "d",
            "type": "object",
            "credentialType": "C",
            "version": "1.0.0",
            "properties": {},
            "additionalProperties": false,
            "required": ["i", "d"],
        },
        "chains": [],
        "status": {
            "vn": [1, 0],
            "i": CREDENTIAL,
            "s": "0",
            "d": ISSUANCE,
            "ri": REGISTRY,
            "a": { "s": "2", "d": "EIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt" },
            "dt": "2023-08-23T15:16:07.553000+00:00",
            "et": status,
            "ra": {},
        },
        "anchor": { "pre": ISSUER, "sn": 2, "d": "EIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt" },
        "anc": {
            "v": "KERI10JSON0000cb_",
            "t": "ixn",
            "d": "EIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt",
            "i": ISSUER,
            "s": "2",
            "p": "EIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt",
            "a": [],
        },
        "ancatc": [],
    })
    .to_string()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn a_said_is_always_one_unchanged_segment(said in saids()) {
        let text = said.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;

        let read = ResourcePath::builder()
            .segment(CREDENTIALS_SEGMENT)
            .segment(&text)
            .build()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(read.as_str(), format!("/credentials/{text}"));
        prop_assert_eq!(read.query(), None);
        prop_assert_eq!(read.path().split('/').count(), 3);

        let state = ResourcePath::builder()
            .segment(REGISTRIES_SEGMENT)
            .segment(REGISTRY)
            .segment(&text)
            .build()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(state.as_str(), format!("/registries/{REGISTRY}/{text}"));
        prop_assert_eq!(state.path().split('/').count(), 4);
    }

    #[test]
    fn nothing_that_reshapes_a_path_is_a_credential_reference(text in hostile_text()) {
        let reshapes = text.contains('/') || text.contains('?') || text.contains('#') || text.is_empty();
        if reshapes {
            prop_assert!(Said::from_qb64(&text).is_err(), "{text:?} parsed as a SAID");
            prop_assert!(
                RegistryIdentifier::from_qb64(&text).is_err(),
                "{text:?} parsed as a registry identifier"
            );
        }
    }

    #[test]
    fn an_alias_is_always_one_segment(alias in hostile_text()) {
        prop_assume!(!alias.is_empty());
        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(&alias)
            .segment(CREDENTIALS_SEGMENT)
            .build()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(path.path().split('/').count(), 4);
        prop_assert!(path.as_str().starts_with("/identifiers/"));
        prop_assert!(path.as_str().ends_with("/credentials"));
        prop_assert_eq!(path.query(), None);
    }

    #[test]
    fn a_filter_always_renders_four_fields_in_order(
        label in query_labels(),
        value in "[A-Za-z0-9_-]{0,32}",
        skip in 0_u32..1_000_000,
        limit in 0_u32..1_000_000,
    ) {
        let mut clause = Sad::new();
        clause
            .insert(label.clone(), SadValue::Text(value))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let filter = CredentialFilter::new()
            .with_filter(clause)
            .with_skip(skip)
            .with_limit(limit);

        let body = filter
            .to_json_bytes()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let text = String::from_utf8(body).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let opens_with_the_filter = text.starts_with("{\"filter\":");
        let carries_an_empty_sort = text.contains("\"sort\":[]");
        let tail = format!("\"skip\":{skip},\"limit\":{limit}}}");
        let ends_with_the_bounds = text.ends_with(&tail);
        prop_assert!(opens_with_the_filter);
        prop_assert!(carries_an_empty_sort);
        prop_assert!(ends_with_the_bounds);

        let document: Value =
            serde_json::from_str(&text).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let fields = document.as_object().ok_or_else(|| TestCaseError::fail("not an object"))?;
        prop_assert_eq!(fields.len(), 4);
        for expected in ["filter", "sort", "skip", "limit"] {
            prop_assert!(fields.contains_key(expected), "the body lacks {}", expected);
        }
    }

    #[test]
    fn a_listing_never_carries_input_in_its_path(skip in 0_u32..u32::MAX, limit in 0_u32..u32::MAX) {
        let _ = CredentialFilter::new().with_skip(skip).with_limit(limit);
        let path = ResourcePath::builder()
            .segment(CREDENTIALS_SEGMENT)
            .segment(CREDENTIAL_QUERY_SEGMENT)
            .build()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(path.as_str(), "/credentials/query");
        prop_assert_eq!(path.query(), None);
    }

    #[test]
    fn a_credential_record_accepts_only_the_declared_status_kinds(status in "[a-z]{3}") {
        let document = credential_document(&status);
        let decoded = serde_json::from_str::<CredentialRecord>(&document);
        if status == "iss" || status == "rev" {
            prop_assert!(decoded.is_ok(), "{status} was refused: {decoded:?}");
        } else {
            prop_assert!(decoded.is_err(), "{status} was accepted");
        }
    }

    #[test]
    fn arbitrary_bytes_decode_or_are_refused(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        match serde_json::from_slice::<CredentialRecord>(&bytes) {
            Ok(record) => {
                let encoded = serde_json::to_vec(&record)
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                let again = serde_json::from_slice::<CredentialRecord>(&encoded)
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                prop_assert_eq!(record.sad.digest, again.sad.digest);
            }
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }
}

// --- Named regressions ---
#[test]
fn the_default_filter_is_the_references_defaults_rather_than_the_zero_values() -> Result<(), Box<dyn Error>> {
    let default = CredentialFilter::default();
    assert_eq!(default, CredentialFilter::new());
    assert_eq!(default.limit, DEFAULT_CREDENTIAL_LIMIT);
    assert_eq!(default.skip, 0);
    assert_eq!(
        String::from_utf8(default.to_json_bytes()?)?,
        r#"{"filter":{},"sort":[],"skip":0,"limit":25}"#
    );
    Ok(())
}

#[test]
fn a_filter_carrying_nested_clauses_survives_re_encoding() -> Result<(), Box<dyn Error>> {
    let mut equality = Sad::new();
    equality.insert("$eq", CREDENTIAL)?;
    let mut clause = Sad::new();
    clause.insert("-i", SadValue::Map(equality))?;
    let mut ascending = Sad::new();
    ascending.insert("-s", SadValue::integer(1)?)?;
    let mut descending = Sad::new();
    descending.insert("-d", SadValue::integer(-1)?)?;

    let filter = CredentialFilter::new()
        .with_filter(clause)
        .with_sort(vec![ascending, descending]);
    let text = String::from_utf8(filter.to_json_bytes()?)?;
    assert_eq!(
        text,
        format!(
            r#"{{"filter":{{"-i":{{"$eq":"{CREDENTIAL}"}}}},"sort":[{{"-s":1}},{{"-d":-1}}],"skip":0,"limit":25}}"#
        )
    );
    let document: Value = serde_json::from_str(&text)?;
    assert_eq!(document.get("sort").and_then(Value::as_array).map(Vec::len), Some(2));
    Ok(())
}

#[test]
fn a_registry_identifier_is_one_unchanged_segment() -> Result<(), Box<dyn Error>> {
    let registry = RegistryIdentifier::from_qb64(REGISTRY)?;
    let said = Said::from_qb64(CREDENTIAL)?;
    let path = ResourcePath::builder()
        .segment(REGISTRIES_SEGMENT)
        .segment(&registry.qb64()?)
        .segment(&said.qb64()?)
        .build()?;
    assert_eq!(path.as_str(), format!("/registries/{REGISTRY}/{CREDENTIAL}"));
    Ok(())
}

#[test]
fn a_deeply_nested_answer_is_a_typed_refusal_rather_than_a_crash() {
    let mut document = String::from(r#"{"sad":"#);
    document.push_str(&"[".repeat(4096));
    document.push_str(&"]".repeat(4096));
    document.push('}');
    let outcome = serde_json::from_str::<CredentialRecord>(&document);
    assert!(outcome.is_err(), "a deeply nested answer was accepted");
}

#[test]
fn the_reference_mock_credentials_two_defects_are_each_enough_to_refuse_it() -> Result<(), Box<dyn Error>> {
    let complete = credential_document("iss");
    assert!(serde_json::from_str::<CredentialRecord>(&complete).is_ok());

    let mut numeric_seal: Value = serde_json::from_str(&complete)?;
    if let Some(seal) = numeric_seal
        .get_mut("status")
        .and_then(|status| status.get_mut("a"))
        .and_then(Value::as_object_mut)
    {
        seal.insert("s".to_owned(), Value::from(2));
    }
    assert!(
        serde_json::from_str::<CredentialRecord>(&numeric_seal.to_string()).is_err(),
        "a numeric seal sequence was accepted"
    );

    let mut missing: Value = serde_json::from_str(&complete)?;
    if let Some(fields) = missing.as_object_mut() {
        fields.remove("issatc");
    }
    assert!(
        serde_json::from_str::<CredentialRecord>(&missing.to_string()).is_err(),
        "a record missing `issatc` was accepted"
    );
    Ok(())
}
