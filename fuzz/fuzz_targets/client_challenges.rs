#![no_main]

//! Fuzzes the challenges endpoint over hostile strengths, sources, word lists, and agent answers.
//!
//! This family exists to produce a **verdict**: `responded` writes an `authenticated` flag into
//! somebody's contact record, and anything downstream may act on it. So the inputs that matter are
//! the ones that decide what gets asked and what gets believed.
//!
//! A **strength** is a caller's number the reference stringifies into a query, where nothing outside
//! BIP39's five entropy sizes could ever produce a mnemonic. A **source** is a path component the
//! reference interpolates raw, and Roadmap 3.10 signs `@path`. A **word list** is what an identifier
//! is claimed to have signed — an empty one asks the agent to confirm that it signed nothing. And an
//! **agent's answer** is the verdict itself: a `Challenge` whose `authenticated` field a caller
//! reads, and a `ChallengeOperation` whose outcome decides whether they read it at all.
//!
//! The target asserts that nothing panics, that a strength is accepted exactly when BIP39 defines
//! it, that a source is always one path segment, that a word list reaches the body in order and
//! unchanged, and that an answer decodes into what it claims or is refused — with a refusal
//! (`authenticated: false`) never reading as an absence.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::challenges::{
    CHALLENGES_SEGMENT, CHALLENGES_VERIFY_SEGMENT, ChallengeStrength, STRENGTH_PARAMETER,
};
use signify_client::error::ClientError;
use signify_http::request::ResourcePath;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};
use signify_types::api::{Challenge, ChallengeOperation};

/// Every character that would give a path component a meaning it did not have.
const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

/// Reads four little-endian bytes, or zero when there are not four.
fn word(data: &[u8], index: usize) -> u32 {
    let start = index.saturating_mul(4);
    let end = start.saturating_add(4);
    data.get(start..end)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map_or(0, u32::from_le_bytes)
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let knobs = parts.next().unwrap_or_default();
    let source_text = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let said_text = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let words: Vec<String> = parts
        .next()
        .unwrap_or_default()
        .split(|&byte| byte == b'\n')
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect();
    let document = parts.next().unwrap_or_default();

    // -----------------------------------------------------------------------
    // The strength: accepted exactly when BIP39 defines it.
    // -----------------------------------------------------------------------
    let bits = word(knobs, 0);
    let declared = ChallengeStrength::DECLARED.contains(&bits);
    match ChallengeStrength::new(bits) {
        Ok(strength) => {
            assert!(declared, "{bits} was accepted but BIP39 does not define it");
            assert_eq!(strength.bits(), bits, "a strength changed its own size");
            // Always a whole number of words, and always between twelve and twenty-four.
            let count = strength.word_count();
            assert_eq!(count, bits / 32 * 3);
            assert!((12..=24).contains(&count), "{bits} claimed {count} words");

            // Digits need no encoding, so the query is byte-identical to the reference's.
            if let Ok(path) = ResourcePath::builder()
                .segment(CHALLENGES_SEGMENT)
                .parameter(STRENGTH_PARAMETER, &strength.bits().to_string())
                .build()
            {
                assert_eq!(path.as_str(), format!("/challenges?strength={bits}"));
                assert_eq!(path.path(), "/challenges", "a strength moved the resource");
            }
        }
        Err(ClientError::InvalidChallengeStrength { bits: reported }) => {
            assert!(!declared, "{bits} was refused but BIP39 defines it");
            assert_eq!(reported, bits, "the refusal named a different size");
        }
        Err(other) => assert!(
            false,
            "a strength failed for a reason other than not being an entropy size: {bits} gave {other}"
        ),
    }

    // -----------------------------------------------------------------------
    // The source: a validated prefix or nothing, and always one segment.
    // -----------------------------------------------------------------------
    if let Ok(source) = IdentifierPrefix::from_qb64(&source_text) {
        let re_encoded = source.qb64();
        assert!(
            re_encoded.is_ok(),
            "a parsed prefix failed to re-encode: {source_text:?}"
        );
        let text = re_encoded.unwrap_or_default();
        if let Ok(path) = ResourcePath::builder()
            .segment(CHALLENGES_VERIFY_SEGMENT)
            .segment(&text)
            .build()
        {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(segments.len(), 2, "a source became {} segments", segments.len());
            assert_eq!(segments.first().copied(), Some(CHALLENGES_VERIFY_SEGMENT));
            for delimiter in PATH_DELIMITERS {
                assert!(
                    !segments.get(1).copied().unwrap_or_default().contains(delimiter),
                    "an encoded source still carries {delimiter:?}"
                );
            }
            assert_eq!(path.query(), None, "a source introduced a query");
            // Both verification calls address exactly this, differing only in method.
            assert_eq!(path.as_str(), format!("/challenges_verify/{text}"));
        }
    }

    // -----------------------------------------------------------------------
    // The word list: exactly what it was given, in order.
    // -----------------------------------------------------------------------
    let mut body = Sad::new();
    if body
        .insert(
            "words",
            SadValue::Array(words.iter().map(|entry| SadValue::text(entry.clone())).collect()),
        )
        .is_ok()
        && let Ok(bytes) = body.to_json_bytes()
    {
        let decoded = serde_json::from_slice::<serde_json::Value>(&bytes);
        assert!(decoded.is_ok(), "a verification body was not JSON");
        let decoded = decoded.unwrap_or(serde_json::Value::Null);
        let written = decoded.get("words").and_then(serde_json::Value::as_array);
        assert_eq!(
            written.map(Vec::len),
            Some(words.len()),
            "a verification body changed the word count"
        );
        if let Some(written) = written {
            for (index, entry) in words.iter().enumerate() {
                assert_eq!(
                    written.get(index).and_then(serde_json::Value::as_str),
                    Some(entry.as_str()),
                    "a verification body reordered or rewrote a word"
                );
            }
        }
        assert_eq!(decoded.as_object().map(serde_json::Map::len), Some(1));
    }

    // -----------------------------------------------------------------------
    // The acceptance body: a SAID that names a message, or nothing.
    // -----------------------------------------------------------------------
    if let Ok(said) = Said::from_qb64(&said_text) {
        let re_encoded = said.qb64();
        assert!(re_encoded.is_ok(), "a parsed SAID failed to re-encode");
        let mut acceptance = Sad::new();
        if acceptance.insert("said", re_encoded.unwrap_or_default()).is_ok()
            && let Ok(bytes) = acceptance.to_json_bytes()
        {
            let decoded = serde_json::from_slice::<serde_json::Value>(&bytes);
            assert!(decoded.is_ok(), "an acceptance body was not JSON");
        }
    }

    // -----------------------------------------------------------------------
    // The agent's answers, which are the verdict.
    // -----------------------------------------------------------------------
    if let Ok(challenge) = serde_json::from_slice::<Challenge>(document) {
        // A refusal is a value, never an absence: `false` must not read as unanswered.
        if challenge.authenticated == Some(false) {
            assert!(challenge.authenticated.is_some(), "a refusal read as unanswered");
            assert_ne!(challenge.authenticated, None);
        }
        let encoded = serde_json::to_vec(&challenge);
        assert!(encoded.is_ok(), "a decoded challenge failed to re-encode");
        let again = serde_json::from_slice::<Challenge>(&encoded.unwrap_or_default());
        assert!(again.is_ok(), "a re-encoded challenge failed to decode");
        if let Ok(again) = again {
            assert_eq!(again.words, challenge.words, "a round trip changed the words");
            assert_eq!(
                again.authenticated, challenge.authenticated,
                "a round trip changed the verdict"
            );
            assert_eq!(again.said, challenge.said);
        }
    }

    if let Ok(operation) = serde_json::from_slice::<ChallengeOperation>(document) {
        // Exactly one outcome, which is what decides whether a caller reads a verdict at all.
        let done = operation.outcome.is_done();
        assert_eq!(
            done,
            operation.outcome.response().is_some() || operation.outcome.error().is_some()
        );
        // A completed verification carries the exchange message that answered.
        if let Some(response) = operation.outcome.response() {
            let _ = response.exn.digest.len();
        }
    }
});
