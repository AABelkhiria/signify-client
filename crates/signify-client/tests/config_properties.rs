//! Invariants of the configuration endpoint.
//!
//! This family has exactly one input that varies: the agent's answer. The address is constant, so
//! there is no path or query property to state — which is itself worth saying, because every other
//! family in this crate needed one.
//!
//! What is left is the trust boundary. An answer either is an agent configuration or is refused;
//! one that is accepted keeps exactly the introduction list it carried, in order, and survives
//! re-encoding; and an absent list never becomes an empty one.

use std::error::Error;

use proptest::prelude::*;
use serde_json::{Value, json};
use signify_client::endpoint::config::CONFIG_SEGMENT;
use signify_http::request::ResourcePath;
use signify_types::api::AgentConfig;

/// Introduction OOBIs of the shape a witness publishes, plus the awkward ones.
fn introduction_urls() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(
        prop_oneof![
            "http://127\\.0\\.0\\.1:[0-9]{4}/oobi/[A-Za-z0-9_-]{44}/controller",
            "[\\PC]{0,64}",
            Just(String::new()),
        ],
        0..8,
    )
}

/// Values that are not a list of strings, and are not `null`.
///
/// `null` is excluded deliberately: Roadmap 4.1's nullable-is-optional rule (ADR `0012`) makes an
/// explicit null say what an absent field says, so it is *accepted*. That is asserted by name
/// below rather than generated here.
fn wrong_list_values() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!("not-a-list")),
        Just(json!(7)),
        Just(json!(true)),
        Just(json!({})),
        Just(json!([1, 2])),
        Just(json!([["nested"]])),
        Just(json!([null])),
    ]
}

/// Answers that are neither an object nor a sequence.
fn scalar_answers() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!("text")),
        Just(json!(7)),
        Just(json!(-1)),
        Just(json!(1.5)),
        Just(json!(true)),
        Just(json!(false)),
        Just(json!(null)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// An accepted configuration keeps exactly the list it carried, in order, and survives its own
    /// encoding — which is what makes a stored one stable.
    #[test]
    fn an_accepted_configuration_keeps_its_list_verbatim(urls in introduction_urls()) {
        let document = json!({ "iurls": urls }).to_string();
        let config: AgentConfig = serde_json::from_str(&document)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(config.introduction_urls.as_deref(), Some(urls.as_slice()));

        let encoded = serde_json::to_string(&config)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let again: AgentConfig = serde_json::from_str(&encoded)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(again, config);
    }

    /// Whatever an agent adds beyond the schema is ignored, and never changes the one field that
    /// is declared.
    #[test]
    fn an_undeclared_field_never_changes_what_is_declared(
        urls in introduction_urls(),
        label in "[a-z]{1,12}",
        extra in wrong_list_values(),
    ) {
        prop_assume!(label != "iurls");
        let document = json!({ "iurls": urls, label.as_str(): extra }).to_string();
        let config: AgentConfig = serde_json::from_str(&document)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(config.introduction_urls.as_deref(), Some(urls.as_slice()));

        // Nothing undeclared survives into what is written back. Compared by *key*, because a URL
        // may legitimately contain the label's characters.
        let encoded = serde_json::to_value(&config)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let fields = encoded.as_object().ok_or_else(|| TestCaseError::fail("not an object"))?;
        prop_assert_eq!(fields.keys().cloned().collect::<Vec<_>>(), ["iurls".to_owned()]);
    }

    /// An `iurls` that is not a list of strings is refused, whatever it is — where the reference
    /// casts it and hands it over.
    #[test]
    fn a_wrong_shaped_list_is_always_refused(wrong in wrong_list_values()) {
        let document = json!({ "iurls": wrong }).to_string();
        let outcome = serde_json::from_str::<AgentConfig>(&document);
        prop_assert!(outcome.is_err(), "{} was accepted", document);
        if let Err(error) = outcome {
            prop_assert!(!error.to_string().is_empty());
        }
    }

    /// A scalar answer is never a configuration.
    ///
    /// Note what this does *not* claim: a JSON **sequence** is accepted, because serde decodes a
    /// struct positionally from one. That is asserted by name below.
    #[test]
    fn a_scalar_answer_is_never_a_configuration(answer in scalar_answers()) {
        let outcome = serde_json::from_str::<AgentConfig>(&answer.to_string());
        prop_assert!(outcome.is_err(), "{} was accepted", answer);
        if let Err(error) = outcome {
            prop_assert!(!error.to_string().is_empty());
        }
    }

    /// Arbitrary bytes never panic: an answer either decodes or is refused with a reason.
    #[test]
    fn arbitrary_bytes_decode_or_are_refused(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        match serde_json::from_slice::<AgentConfig>(&bytes) {
            Ok(config) => {
                // Anything accepted re-encodes into something that decodes to an equal value.
                let encoded = serde_json::to_vec(&config)
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                let again: AgentConfig = serde_json::from_slice(&encoded)
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                prop_assert_eq!(again, config);
            }
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }
}

/// Regression: the address is constant, so it cannot vary with anything — which is why this file
/// states no path property at all.
#[test]
fn the_address_carries_no_input() -> Result<(), Box<dyn Error>> {
    let first = ResourcePath::builder().segment(CONFIG_SEGMENT).build()?;
    let second = ResourcePath::builder().segment(CONFIG_SEGMENT).build()?;
    assert_eq!(first.as_str(), second.as_str());
    assert_eq!(first.as_str(), "/config");
    assert_eq!(first.query(), None);
    Ok(())
}

/// Regression: a JSON **sequence** decodes as a configuration, because serde reads a struct
/// positionally from one.
///
/// This is a property of every `signify-types::api` record rather than of this endpoint, and it is
/// recorded here because this is the first item whose trust boundary is a single small document
/// where it is visible. It is a *leniency*, not a wrong belief: `[["a"]]` yields exactly what
/// `{"iurls":["a"]}` yields, so an agent spelling its answer positionally would be understood
/// rather than misunderstood. No KERIA does; `PORTING.md` records it as a limitation for the
/// Roadmap 9.1 audit rather than changing a verified type for it.
#[test]
fn a_sequence_answer_decodes_positionally() -> Result<(), Box<dyn Error>> {
    let empty: AgentConfig = serde_json::from_str("[]")?;
    assert_eq!(empty.introduction_urls, None);

    let null_first: AgentConfig = serde_json::from_str("[null]")?;
    assert_eq!(null_first.introduction_urls, None);

    let listed: AgentConfig = serde_json::from_str(r#"[["http://x"]]"#)?;
    assert_eq!(
        listed.introduction_urls.as_deref(),
        Some(["http://x".to_owned()].as_slice())
    );
    // Exactly what the object spelling yields, which is why this is leniency rather than risk.
    assert_eq!(
        listed,
        serde_json::from_str::<AgentConfig>(r#"{"iurls":["http://x"]}"#)?
    );

    // A sequence whose first element is not a list is still refused.
    assert!(serde_json::from_str::<AgentConfig>("[1,2]").is_err());
    Ok(())
}

/// Regression: an absent list is not an empty one, and neither is a null.
#[test]
fn an_absent_list_is_told_apart_from_an_empty_one_and_from_a_null() -> Result<(), Box<dyn Error>> {
    let absent: AgentConfig = serde_json::from_str("{}")?;
    let empty: AgentConfig = serde_json::from_str(r#"{"iurls":[]}"#)?;
    assert_eq!(absent.introduction_urls, None);
    assert_eq!(empty.introduction_urls, Some(Vec::new()));
    assert_ne!(absent, empty);

    // Roadmap 4.1's nullable-is-optional rule (ADR `0012`) makes an explicit null say what an
    // absent field says, so an agent may spell it either way.
    let null: AgentConfig = serde_json::from_str(r#"{"iurls":null}"#)?;
    assert_eq!(null.introduction_urls, None);
    assert_eq!(null, absent);

    // An absent list writes nothing back, so a stored configuration does not gain a field.
    assert_eq!(serde_json::to_string(&absent)?, "{}");
    Ok(())
}
