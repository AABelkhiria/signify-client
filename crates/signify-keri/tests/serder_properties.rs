//! Property and invalid-near-miss coverage for deterministic SAD serialization.
//!
//! Several properties cross-validate the hand-written codec against `serde_json`, an independent
//! implementation. That guards the escaping and structure rules without giving `serde_json` any
//! authority over field order or byte layout, which it does not preserve.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_keri::serialization::{
    MAX_SAFE_INTEGER, MIN_SAFE_INTEGER, Sad, SadError, SadValue, SerializationError, SerializedEvent,
};

fn sad_value<T>(result: Result<T, SadError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn event_value<T>(result: Result<T, SerializationError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

/// Field labels and strings deliberately include escape-triggering and multi-byte content.
fn text_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]{1,8}",
        r#"[\x00-\x1f"\\/]{0,6}"#,
        "[\\u{80}-\\u{7ff}]{0,4}",
        "[\\u{10000}-\\u{10ffff}]{0,3}",
        any::<String>(),
    ]
}

fn value_strategy() -> impl Strategy<Value = SadValue> {
    let leaf = prop_oneof![
        Just(SadValue::Null),
        any::<bool>().prop_map(SadValue::Bool),
        (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).prop_map(SadValue::Integer),
        text_strategy().prop_map(SadValue::Text),
    ];
    leaf.prop_recursive(4, 24, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(SadValue::Array),
            proptest::collection::vec(("[a-z]{1,4}", inner), 0..4).prop_map(|entries| {
                let mut map = Sad::new();
                for (label, value) in entries {
                    // Duplicates are rejected by design; skipping them keeps the generator total.
                    let _ = map.insert(label, value);
                }
                SadValue::Map(map)
            }),
        ]
    })
}

fn sad_strategy() -> impl Strategy<Value = Sad> {
    proptest::collection::vec((text_strategy(), value_strategy()), 0..6).prop_map(|entries| {
        let mut sad = Sad::new();
        for (label, value) in entries {
            let _ = sad.insert(label, value);
        }
        sad
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn encoding_then_parsing_is_the_identity(sad in sad_strategy()) {
        let encoded = sad_value(sad.to_json_bytes())?;
        let parsed = sad_value(Sad::from_json_bytes(&encoded))?;
        prop_assert_eq!(&parsed, &sad);
        // Encoding is a fixed point, which is what makes a SAID over these bytes stable.
        prop_assert_eq!(sad_value(parsed.to_json_bytes())?, encoded);
    }

    #[test]
    fn field_order_is_preserved_exactly(labels in proptest::collection::vec("[a-z]{1,6}", 0..8)) {
        let mut sad = Sad::new();
        let mut expected = Vec::new();
        for label in labels {
            if sad.insert(label.clone(), SadValue::Null).is_ok() {
                expected.push(label);
            }
        }
        let observed: Vec<String> = sad.entries().map(|(label, _)| label.to_owned()).collect();
        prop_assert_eq!(&observed, &expected);

        let reparsed = sad_value(Sad::from_json_bytes(&sad_value(sad.to_json_bytes())?))?;
        let round_tripped: Vec<String> = reparsed.entries().map(|(label, _)| label.to_owned()).collect();
        prop_assert_eq!(round_tripped, expected);
    }

    #[test]
    fn escaping_agrees_with_an_independent_json_implementation(text in text_strategy()) {
        let mut sad = Sad::new();
        sad_value(sad.insert("a", SadValue::Text(text.clone())))?;
        let encoded = sad_value(sad.to_json_bytes())?;

        let independent: serde_json::Value = serde_json::from_slice(&encoded)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let recovered = independent
            .get("a")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| TestCaseError::fail("independent parser lost the field"))?;
        prop_assert_eq!(recovered, text.as_str());
    }

    #[test]
    fn arbitrary_documents_agree_with_an_independent_parser(sad in sad_strategy()) {
        let encoded = sad_value(sad.to_json_bytes())?;
        // Anything this codec emits must be valid JSON to an independent implementation.
        let independent: Result<serde_json::Value, _> = serde_json::from_slice(&encoded);
        prop_assert!(independent.is_ok(), "independent parser rejected our output");
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_only_yield_typed_errors(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        match Sad::from_json_bytes(&bytes) {
            Ok(sad) => {
                // Anything accepted must re-encode and re-parse to itself.
                let encoded = sad_value(sad.to_json_bytes())?;
                prop_assert_eq!(sad_value(Sad::from_json_bytes(&encoded))?, sad);
            }
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }

    #[test]
    fn sized_messages_declare_their_own_byte_length(mut sad in sad_strategy()) {
        // Force a well-formed version field into first position.
        let mut prefixed = Sad::new();
        sad_value(prefixed.insert("v", SadValue::text("KERI10JSON000000_")))?;
        for (label, value) in sad.entries() {
            if label != "v" {
                let _ = prefixed.insert(label.to_owned(), value.clone());
            }
        }
        sad = prefixed;

        let event = event_value(SerializedEvent::from_sad(sad))?;
        prop_assert_eq!(event.size(), event.raw().len());
        prop_assert_eq!(usize::try_from(event.version_string().size()).unwrap_or(0), event.raw().len());
        let starts_with_version = event.raw().starts_with(br#"{"v":"KERI10JSON"#);
        prop_assert!(starts_with_version);

        // Parsing our own message reproduces it exactly, and re-sizing is idempotent.
        let parsed = event_value(SerializedEvent::parse(event.raw()))?;
        prop_assert_eq!(&parsed, &event);
        let resized = event_value(SerializedEvent::from_sad(parsed.sad().clone()))?;
        prop_assert_eq!(resized.raw(), event.raw());
    }

    #[test]
    fn any_trailing_byte_breaks_the_declared_size(suffix in proptest::collection::vec(any::<u8>(), 1..8)) {
        let mut sad = Sad::new();
        sad_value(sad.insert("v", SadValue::text("KERI10JSON000000_")))?;
        sad_value(sad.insert("t", SadValue::text("icp")))?;
        let event = event_value(SerializedEvent::from_sad(sad))?;

        let mut extended = event.raw().to_vec();
        extended.extend_from_slice(&suffix);
        prop_assert!(SerializedEvent::parse(&extended).is_err());
    }

    #[test]
    fn non_integer_numbers_are_always_rejected(
        whole in -1_000_000_i64..1_000_000,
        fraction in 1_u32..9999,
    ) {
        let document = format!(r#"{{"a":{whole}.{fraction}}}"#);
        let fractional_rejected = matches!(
            Sad::from_json_bytes(document.as_bytes()),
            Err(SadError::UnsupportedNumber { .. })
        );
        prop_assert!(fractional_rejected);

        let exponent = format!(r#"{{"a":{whole}e3}}"#);
        let exponent_rejected = matches!(
            Sad::from_json_bytes(exponent.as_bytes()),
            Err(SadError::UnsupportedNumber { .. })
        );
        prop_assert!(exponent_rejected);
    }

    #[test]
    fn integers_beyond_the_safe_range_are_always_rejected(excess in 1_i128..1_000_000) {
        let above = i128::from(MAX_SAFE_INTEGER) + excess;
        let below = i128::from(MIN_SAFE_INTEGER) - excess;
        for value in [above, below] {
            let document = format!(r#"{{"a":{value}}}"#);
            let rejected = matches!(
                Sad::from_json_bytes(document.as_bytes()),
                Err(SadError::IntegerOutOfRangeAt { .. })
            );
            prop_assert!(rejected, "accepted out-of-range integer {}", value);
        }
    }
}
