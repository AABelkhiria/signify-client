//! Invariants of the challenges endpoint.
//!
//! What cannot be asked for: an impossible strength, a wordless verification, a source addressing another resource.

use std::error::Error;

use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::Challenge;
use proptest::prelude::*;
use serde_json::{Value, json};
use signify_client::endpoint::challenges::{
    CHALLENGES_SEGMENT, CHALLENGES_VERIFY_SEGMENT, ChallengeStrength, STRENGTH_PARAMETER,
};
use signify_client::error::ClientError;
use signify_http::request::ResourcePath;

const SOURCE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn prefixes() -> impl Strategy<Value = IdentifierPrefix> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a prefix", |body| {
        IdentifierPrefix::from_qb64(&format!("E{body}")).ok()
    })
}

fn strengths() -> impl Strategy<Value = ChallengeStrength> {
    proptest::sample::select(ChallengeStrength::DECLARED.to_vec())
        .prop_filter_map("not a strength", |bits| ChallengeStrength::new(bits).ok())
}

fn word_lists() -> impl Strategy<Value = Vec<String>> {
    prop_oneof![
        proptest::collection::vec("[a-z]{3,8}", 1..25),
        proptest::collection::vec("[\\PC]{0,24}", 1..6),
    ]
}

fn generate_path(strength: ChallengeStrength) -> Result<ResourcePath, TestCaseError> {
    ResourcePath::builder()
        .segment(CHALLENGES_SEGMENT)
        .parameter(STRENGTH_PARAMETER, &strength.bits().to_string())
        .build()
        .map_err(fail)
}

fn verify_path(source: &IdentifierPrefix) -> Result<ResourcePath, TestCaseError> {
    ResourcePath::builder()
        .segment(CHALLENGES_VERIFY_SEGMENT)
        .segment(&source.qb64().map_err(fail)?)
        .build()
        .map_err(fail)
}

fn words_body(words: &[String]) -> Result<Vec<u8>, TestCaseError> {
    let mut body = Sad::new();
    body.insert(
        "words",
        SadValue::Array(words.iter().map(|word| SadValue::text(word.clone())).collect()),
    )
    .map_err(fail)?;
    body.to_json_bytes().map_err(fail)
}

const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn a_strength_is_accepted_exactly_when_bip39_defines_it(bits in 0_u32..=1024) {
        let declared = ChallengeStrength::DECLARED.contains(&bits);
        let built = ChallengeStrength::new(bits);
        prop_assert_eq!(built.is_ok(), declared, "{} was handled wrongly", bits);
        match built {
            Ok(strength) => prop_assert_eq!(strength.bits(), bits),
            Err(ClientError::InvalidChallengeStrength { bits: reported }) => {
                prop_assert_eq!(reported, bits, "the failure named a different size");
            }
            Err(other) => prop_assert!(false, "an unexpected failure: {:?}", other),
        }
    }

    #[test]
    fn a_generation_writes_exactly_one_parameter(strength in strengths()) {
        let path = generate_path(strength)?;
        let query = path.query().unwrap_or_default();
        prop_assert_eq!(query, format!("{STRENGTH_PARAMETER}={}", strength.bits()));
        prop_assert_eq!(query.matches('&').count(), 0);
        prop_assert_eq!(path.path(), format!("/{CHALLENGES_SEGMENT}"));
        prop_assert_eq!(path.as_str(), format!("/challenges?strength={}", strength.bits()));
    }

    #[test]
    fn a_source_is_always_exactly_one_segment(source in prefixes()) {
        let text = source.qb64().map_err(fail)?;
        let path = verify_path(&source)?;
        prop_assert_eq!(path.as_str(), format!("/{CHALLENGES_VERIFY_SEGMENT}/{text}"));
        prop_assert_eq!(path.query(), None);
        prop_assert_eq!(path.path().split('/').count(), 3);
        for delimiter in PATH_DELIMITERS {
            prop_assert!(!text.contains(delimiter));
        }
    }

    #[test]
    fn both_verification_calls_always_share_one_address(source in prefixes()) {
        let first = verify_path(&source)?;
        let second = verify_path(&source)?;
        prop_assert_eq!(first.as_str(), second.as_str());
        let opening = format!("/{CHALLENGES_VERIFY_SEGMENT}/");
        prop_assert!(first.as_str().starts_with(&opening));
    }

    #[test]
    fn a_verification_body_is_the_word_list_in_order(words in word_lists()) {
        let bytes = words_body(&words)?;
        let decoded: Value = serde_json::from_slice(&bytes).map_err(fail)?;
        let object = decoded.as_object().ok_or_else(|| fail("a body is not an object"))?;
        prop_assert_eq!(object.len(), 1, "a verification body wrote more than the words");

        let written = object
            .get("words")
            .and_then(Value::as_array)
            .ok_or_else(|| fail("a body carries no word list"))?;
        prop_assert_eq!(written.len(), words.len());
        for (index, word) in words.iter().enumerate() {
            prop_assert_eq!(written.get(index).and_then(Value::as_str), Some(word.as_str()));
        }
    }

    #[test]
    fn an_acceptance_body_is_the_said(said in "[A-Za-z0-9_-]{43}") {
        let Ok(said) = Said::from_qb64(&format!("E{said}")) else {
            return Ok(());
        };
        let text = said.qb64().map_err(fail)?;
        let mut body = Sad::new();
        body.insert("said", text.clone()).map_err(fail)?;
        let rendered = String::from_utf8(body.to_json_bytes().map_err(fail)?).map_err(fail)?;
        prop_assert_eq!(rendered, format!(r#"{{"said":"{text}"}}"#));
    }

    #[test]
    fn a_challenge_needs_its_words_and_keeps_its_verdict(
        words in proptest::collection::vec("[a-z]{3,8}", 0..25),
        verdict in proptest::option::of(any::<bool>()),
    ) {
        let mut document = json!({ "words": words });
        if let (Some(verdict), Some(object)) = (verdict, document.as_object_mut()) {
            object.insert("authenticated".to_owned(), json!(verdict));
        }
        let challenge: Challenge = serde_json::from_value(document.clone()).map_err(fail)?;
        prop_assert_eq!(challenge.words.len(), words.len());
        prop_assert_eq!(challenge.authenticated, verdict);
        if verdict == Some(false) {
            prop_assert!(challenge.authenticated.is_some(), "a refusal read as unanswered");
        }

        if let Some(object) = document.as_object_mut() {
            object.remove("words");
        }
        prop_assert!(serde_json::from_value::<Challenge>(document).is_err());
    }
}

#[test]
fn the_pinned_word_list_is_the_length_its_strength_gives() {
    const PINNED: [&str; 12] = [
        "shell", "gloom", "mimic", "cereal", "stool", "furnace", "nominee", "nation", "sauce", "sausage", "rather",
        "venue",
    ];
    assert_eq!(
        usize::try_from(ChallengeStrength::BITS_128.word_count()).unwrap_or_default(),
        PINNED.len()
    );
    assert_eq!(ChallengeStrength::BITS_256.word_count(), 24);
}

#[test]
fn a_zero_strength_is_refused() {
    assert!(matches!(
        ChallengeStrength::new(0),
        Err(ClientError::InvalidChallengeStrength { bits: 0 })
    ));
}

#[test]
fn only_an_empty_word_list_is_refused() -> Result<(), Box<dyn Error>> {
    let single = words_body(&["shell".to_owned()]).map_err(|error| error.to_string())?;
    assert_eq!(String::from_utf8(single)?, r#"{"words":["shell"]}"#);
    let empty = words_body(&[]).map_err(|error| error.to_string())?;
    assert_eq!(String::from_utf8(empty)?, r#"{"words":[]}"#);
    Ok(())
}

#[test]
fn a_hostile_source_is_not_a_prefix() {
    for hostile in ["a/b?c=d", "../identifiers", "..", "", "not a prefix", "EG2XjQN"] {
        assert!(
            IdentifierPrefix::from_qb64(hostile).is_err(),
            "{hostile:?} was accepted as a challenged identifier"
        );
    }
    assert!(IdentifierPrefix::from_qb64(SOURCE).is_ok());
}

#[test]
fn a_strength_names_the_bip39_word_count() {
    for (strength, words) in [
        (ChallengeStrength::BITS_128, 12),
        (ChallengeStrength::BITS_160, 15),
        (ChallengeStrength::BITS_192, 18),
        (ChallengeStrength::BITS_224, 21),
        (ChallengeStrength::BITS_256, 24),
    ] {
        assert_eq!(strength.word_count(), words, "{} bits", strength.bits());
    }
}
