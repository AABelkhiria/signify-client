//! Invariants of the key-event and key-state families that hold for every input.
//!
//! A prefix encodes exactly once, a query body keeps its field order, and a sequence base round-trips.

use std::error::Error;

use keria_types::api::Seal;
use proptest::prelude::*;
use serde_json::Value;
use signify_client::endpoint::key_events::{EVENTS_SEGMENT, PREFIX_PARAMETER};
use signify_client::endpoint::key_states::{KeyStateQuery, QuerySequence, STATES_SEGMENT};
use signify_http::request::{MAX_QUERY_PARAMETERS, ResourcePath};
use signify_keri::prefix::IdentifierPrefix;

const PREFIX: &str = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";

fn prefixes() -> impl Strategy<Value = IdentifierPrefix> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a prefix", |body| {
        IdentifierPrefix::from_qb64(&format!("E{body}")).ok()
    })
}

fn hostile_text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[\\PC]{0,32}",
        Just("&pre=EOTHER".to_owned()),
        Just("#fragment".to_owned()),
        Just("?x=1".to_owned()),
        Just("%2F".to_owned()),
        Just(String::new()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn a_prefix_is_always_exactly_one_query_parameter(prefix in prefixes()) {
        let text = prefix.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
        for segment in [EVENTS_SEGMENT, STATES_SEGMENT] {
            let path = ResourcePath::builder()
                .segment(segment)
                .parameter(PREFIX_PARAMETER, &text)
                .build()
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(path.path(), format!("/{segment}"));
            let expected_query = format!("pre={text}");
            prop_assert_eq!(path.query(), Some(expected_query.as_str()));
            prop_assert_eq!(path.query().unwrap_or_default().matches('&').count(), 0);
            prop_assert!(!path.as_str().contains('#'));
            prop_assert_eq!(path.as_str(), format!("/{segment}?pre={text}"));
        }
    }

    #[test]
    fn a_listing_writes_one_parameter_per_prefix(prefixes in proptest::collection::vec(prefixes(), 1..8)) {
        let mut builder = ResourcePath::builder().segment(STATES_SEGMENT);
        let mut texts = Vec::new();
        for prefix in &prefixes {
            let text = prefix.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
            builder = builder.parameter(PREFIX_PARAMETER, &text);
            texts.push(text);
        }
        let path = builder.build().map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(path.path(), "/states");
        let expected_query = texts
            .iter()
            .map(|text| format!("pre={text}"))
            .collect::<Vec<_>>()
            .join("&");
        prop_assert_eq!(path.query(), Some(expected_query.as_str()));
        prop_assert_eq!(path.query().unwrap_or_default().matches("pre=").count(), prefixes.len());
    }

    #[test]
    fn a_query_body_writes_exactly_what_it_was_given(
        prefix in prefixes(),
        sequence in proptest::option::of(0_u64..u64::MAX),
        anchor_digest in proptest::option::of("[A-Za-z0-9_-]{44}"),
    ) {
        let anchor = anchor_digest.clone().map(|digest| Seal {
            identifier: Some(PREFIX.to_owned()),
            sequence_number: "0".to_owned(),
            digest,
        });
        let query = KeyStateQuery {
            prefix: prefix.clone(),
            sequence_number: sequence.map(QuerySequence::Decimal),
            anchor,
        };
        let body = query.body().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let rendered = String::from_utf8(body).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let document: Value = serde_json::from_str(&rendered)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let fields = document.as_object().ok_or_else(|| TestCaseError::fail("not an object"))?;

        let expected = prefix.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(fields.get("pre").and_then(Value::as_str), Some(expected.as_str()));
        prop_assert_eq!(fields.contains_key("sn"), sequence.is_some());
        prop_assert_eq!(fields.contains_key("anchor"), anchor_digest.is_some());
        prop_assert_eq!(fields.len(), 1 + usize::from(sequence.is_some()) + usize::from(anchor_digest.is_some()));

        let pre_at = rendered.find(r#""pre""#);
        if let Some(sn_at) = rendered.find(r#""sn""#) {
            prop_assert!(pre_at < Some(sn_at));
        }
        if let Some(anchor_at) = rendered.find(r#""anchor""#) {
            prop_assert!(pre_at < Some(anchor_at));
            if let Some(sn_at) = rendered.find(r#""sn""#) {
                prop_assert!(sn_at < anchor_at);
            }
        }
    }

    #[test]
    fn a_sequence_number_round_trips_through_the_base_its_caller_chose(value in 0_u64..u64::MAX) {
        let decimal = QuerySequence::Decimal(value);
        let hexadecimal = QuerySequence::Hexadecimal(value);
        prop_assert_eq!(decimal.value(), value);
        prop_assert_eq!(hexadecimal.value(), value);
        prop_assert_eq!(decimal.to_text().parse::<u64>().ok(), Some(value));
        prop_assert_eq!(u64::from_str_radix(&hexadecimal.to_text(), 16).ok(), Some(value));
        prop_assert_eq!(decimal.to_text() == hexadecimal.to_text(), value < 10);
    }

    #[test]
    fn hostile_text_is_never_a_prefix(text in hostile_text()) {
        prop_assume!(!text.is_empty());
        if let Ok(prefix) = IdentifierPrefix::from_qb64(&text) {
            let encoded = prefix.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
            for delimiter in ['&', '?', '#', '='] {
                prop_assert!(!encoded.contains(delimiter));
            }
        }
    }
}

#[test]
fn an_over_long_listing_is_refused_before_it_is_sent() -> Result<(), Box<dyn Error>> {
    let prefix = IdentifierPrefix::from_qb64(PREFIX)?;
    let text = prefix.qb64()?;
    let mut builder = ResourcePath::builder().segment(STATES_SEGMENT);
    for _ in 0..=MAX_QUERY_PARAMETERS {
        builder = builder.parameter(PREFIX_PARAMETER, &text);
    }
    assert!(builder.build().is_err(), "an unbounded listing was accepted");

    let mut bounded = ResourcePath::builder().segment(STATES_SEGMENT);
    for _ in 0..21 {
        bounded = bounded.parameter(PREFIX_PARAMETER, &text);
    }
    assert!(bounded.build().is_err(), "a query beyond the byte bound was accepted");
    Ok(())
}

#[test]
fn an_anchor_without_an_identifier_writes_two_fields() -> Result<(), Box<dyn Error>> {
    let query = KeyStateQuery::anchoring(
        IdentifierPrefix::from_qb64(PREFIX)?,
        Seal {
            identifier: None,
            sequence_number: "3".to_owned(),
            digest: PREFIX.to_owned(),
        },
    );
    let rendered = String::from_utf8(query.body()?)?;
    let document: Value = serde_json::from_str(&rendered)?;
    let anchor = document
        .get("anchor")
        .and_then(Value::as_object)
        .ok_or("the body carries no anchor")?;
    assert_eq!(anchor.len(), 2);
    assert!(!anchor.contains_key("i"));
    assert!(!rendered.contains("null"));
    Ok(())
}

#[test]
fn the_query_constructors_are_the_shapes_they_name() -> Result<(), Box<dyn Error>> {
    let prefix = IdentifierPrefix::from_qb64(PREFIX)?;
    let latest = KeyStateQuery::latest(prefix.clone());
    assert!(latest.sequence_number.is_none() && latest.anchor.is_none());

    let at = KeyStateQuery::at(prefix.clone(), QuerySequence::Hexadecimal(255));
    assert_eq!(at.sequence_number.map(QuerySequence::value), Some(255));
    assert!(at.anchor.is_none());
    assert!(String::from_utf8(at.body()?)?.contains(r#""sn":"ff""#));

    let anchoring = KeyStateQuery::anchoring(
        prefix,
        Seal {
            identifier: None,
            sequence_number: "0".to_owned(),
            digest: PREFIX.to_owned(),
        },
    );
    assert!(anchoring.sequence_number.is_none() && anchoring.anchor.is_some());
    Ok(())
}
