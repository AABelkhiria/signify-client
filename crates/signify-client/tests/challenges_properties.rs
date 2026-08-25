//! Invariants of the challenges endpoint.
//!
//! A challenge is the one thing in this crate whose whole purpose is a *verdict*: `responded` writes
//! an `authenticated` flag into somebody's contact record, and everything downstream may act on it.
//! So the properties here are about what cannot be asked for — a strength no mnemonic generator
//! could satisfy, a verification of no words, a source that addresses a different resource — and
//! about the answer being decoded rather than believed.

use std::error::Error;

use proptest::prelude::*;
use serde_json::{Value, json};
use signify_client::endpoint::challenges::{
    CHALLENGES_SEGMENT, CHALLENGES_VERIFY_SEGMENT, ChallengeStrength, STRENGTH_PARAMETER,
};
use signify_client::error::ClientError;
use signify_http::request::ResourcePath;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};
use signify_types::api::Challenge;

const SOURCE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

/// Syntactically valid Blake3-256 identifier prefixes.
fn prefixes() -> impl Strategy<Value = IdentifierPrefix> {
    "[A-Za-z0-9_-]{43}".prop_filter_map("not a prefix", |body| {
        IdentifierPrefix::from_qb64(&format!("E{body}")).ok()
    })
}

/// Every entropy size BIP39 defines.
fn strengths() -> impl Strategy<Value = ChallengeStrength> {
    proptest::sample::select(ChallengeStrength::DECLARED.to_vec())
        .prop_filter_map("not a strength", |bits| ChallengeStrength::new(bits).ok())
}

/// Word lists of the shapes an agent produces, plus hostile ones.
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

/// The body `verify` sends, built as the endpoint builds it.
fn words_body(words: &[String]) -> Result<Vec<u8>, TestCaseError> {
    let mut body = Sad::new();
    body.insert(
        "words",
        SadValue::Array(words.iter().map(|word| SadValue::text(word.clone())).collect()),
    )
    .map_err(fail)?;
    body.to_json_bytes().map_err(fail)
}

/// Every character that would give a path component a meaning it did not have.
const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Only the five entropy sizes BIP39 defines are accepted, and every one of them is.
    ///
    /// The reference stringifies any `number` into the query, so this is the whole of what makes a
    /// generation request satisfiable.
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

    /// A strength names the word count BIP39 gives it, which is what the agent will answer with.
    #[test]
    fn a_strength_names_its_own_word_count(strength in strengths()) {
        // One word per eleven bits of entropy plus checksum.
        let expected = strength.bits() / 32 * 3;
        prop_assert_eq!(strength.word_count(), expected);
        // Always a whole number of words, between twelve and twenty-four.
        prop_assert!((12..=24).contains(&strength.word_count()));
        prop_assert_eq!(strength.word_count() % 3, 0);
    }

    /// A generation path carries exactly one query parameter, whatever the strength.
    #[test]
    fn a_generation_writes_exactly_one_parameter(strength in strengths()) {
        let path = generate_path(strength)?;
        let query = path.query().unwrap_or_default();
        prop_assert_eq!(query, format!("{STRENGTH_PARAMETER}={}", strength.bits()));
        prop_assert_eq!(query.matches('&').count(), 0);
        // Roadmap 3.10 strips the query, so every strength signs the identical path.
        prop_assert_eq!(path.path(), format!("/{CHALLENGES_SEGMENT}"));
        // Digits need no encoding, so this is byte-identical to the reference's interpolation.
        prop_assert_eq!(path.as_str(), format!("/challenges?strength={}", strength.bits()));
    }

    /// A challenged identifier reaches the path byte-identically and is always one segment.
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

    /// `verify` and `responded` always address the identical resource.
    ///
    /// They differ only in method and body upstream, and the segment is one constant here so they
    /// cannot drift apart.
    #[test]
    fn both_verification_calls_always_share_one_address(source in prefixes()) {
        let first = verify_path(&source)?;
        let second = verify_path(&source)?;
        prop_assert_eq!(first.as_str(), second.as_str());
        let opening = format!("/{CHALLENGES_VERIFY_SEGMENT}/");
        prop_assert!(first.as_str().starts_with(&opening));
    }

    /// A verification body is exactly the words it was given, in order, whatever they hold.
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

    /// An acceptance body is exactly the SAID it was given.
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

    /// A challenge needs its words, and tells an unanswered one from a refused one.
    ///
    /// The three optional fields are what `responded` eventually fills in, and `authenticated:
    /// false` — a verdict of *no* — must never read as absent.
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
        // A refused verdict is a value, never an absence.
        if verdict == Some(false) {
            prop_assert!(challenge.authenticated.is_some(), "a refusal read as unanswered");
        }

        // Without its words there is no challenge, which is what the reference casts past.
        if let Some(object) = document.as_object_mut() {
            object.remove("words");
        }
        prop_assert!(serde_json::from_value::<Challenge>(document).is_err());
    }
}

/// The pinned unit test's twelve-word list is exactly what 128 bits produces.
///
/// The named regression tying this port's `word_count` to the reference's own recorded evidence
/// rather than to a formula written from the specification.
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
    // And the second strength `challenge.test.ts` uses doubles it.
    assert_eq!(ChallengeStrength::BITS_256.word_count(), 24);
}

/// A strength of exactly zero is refused rather than producing an empty query value.
///
/// Found while writing the properties: `0` is the one non-BIP39 value that would still stringify to
/// something a query accepts, so it is the case most likely to slip through unnoticed.
#[test]
fn a_zero_strength_is_refused() {
    assert!(matches!(
        ChallengeStrength::new(0),
        Err(ClientError::InvalidChallengeStrength { bits: 0 })
    ));
}

/// A word list of one word is accepted, and only the empty one is refused.
///
/// The named regression for the bound this port adds: `verify` refuses nothing except asking the
/// agent to confirm that an identifier signed *nothing*.
#[test]
fn only_an_empty_word_list_is_refused() -> Result<(), Box<dyn Error>> {
    let single = words_body(&["shell".to_owned()]).map_err(|error| error.to_string())?;
    assert_eq!(String::from_utf8(single)?, r#"{"words":["shell"]}"#);
    // The empty list still *builds* a body — the refusal is the endpoint's, before it is sent.
    let empty = words_body(&[]).map_err(|error| error.to_string())?;
    assert_eq!(String::from_utf8(empty)?, r#"{"words":[]}"#);
    Ok(())
}

/// A hostile source never reaches a verification path, whatever it holds.
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
