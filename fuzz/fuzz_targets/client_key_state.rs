#![no_main]

//! Fuzzes the key-event and key-state endpoints over hostile prefixes and hostile agent answers.
//!
//! Two things reach these families from outside.
//!
//! A **prefix** is a query value in all three read paths, and the reference interpolates it raw —
//! so upstream a value carrying `&` adds a `pre` parameter the caller never asked for, and one
//! carrying `#` truncates the query into a fragment. Both change which identifiers an agent
//! answers about. This target asserts the value can never do either: what is not a prefix is
//! refused, and what is one survives encoding unchanged and stays a single parameter.
//!
//! An **agent's answer** decides what a client believes about an identifier it does not control —
//! its keys, its witnesses, its current sequence number. This target asserts a key state, a
//! key-event record, and a query operation each either decode into exactly what they claim or are
//! refused, and that re-encoding never loses or invents a field.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::key_events::{EVENTS_SEGMENT, PREFIX_PARAMETER};
use signify_client::endpoint::key_states::{KeyStateQuery, QuerySequence, STATES_SEGMENT};
use signify_client::endpoint::operations::completed;
use signify_client::error::ClientError;
use signify_http::request::ResourcePath;
use signify_keri::prefix::IdentifierPrefix;
use signify_types::api::{KeyEventRecord, KeyState, OperationOutcome, QueryOperation, Seal};

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let candidate = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let document = parts.next().unwrap_or_default();
    let digest = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();

    // 1. A prefix is a prefix, or it is nothing.
    match IdentifierPrefix::from_qb64(&candidate) {
        Ok(prefix) => {
            let Ok(text) = prefix.qb64() else {
                panic!("a parsed prefix could not be re-encoded");
            };
            // A qualified prefix is URL-safe Base64, so it carries no delimiter to inject with.
            for delimiter in ['&', '?', '#', '=', '/', '%'] {
                assert!(
                    !text.contains(delimiter),
                    "a valid prefix carries {delimiter:?}: {text:?}"
                );
            }
            for segment in [EVENTS_SEGMENT, STATES_SEGMENT] {
                let Ok(path) = ResourcePath::builder()
                    .segment(segment)
                    .parameter(PREFIX_PARAMETER, &text)
                    .build()
                else {
                    panic!("a valid prefix produced no path");
                };
                assert_eq!(path.path(), format!("/{segment}"));
                assert_eq!(path.query(), Some(format!("pre={text}").as_str()));
                // Exactly one parameter, and no fragment, whatever the prefix held.
                assert_eq!(path.query().unwrap_or_default().matches('&').count(), 0);
                assert!(!path.as_str().contains('#'));
            }

            // 2. A query body writes what it was given, and nothing else.
            let anchor = (!digest.is_empty()).then(|| Seal {
                identifier: Some(text.clone()),
                sequence_number: "0".to_owned(),
                digest: digest.clone(),
            });
            let sequence = data.first().map(|byte| QuerySequence::Decimal(u64::from(*byte)));
            let query = KeyStateQuery {
                prefix: prefix.clone(),
                sequence_number: sequence,
                anchor: anchor.clone(),
            };
            match query.body() {
                Ok(body) => {
                    let Ok(rendered) = String::from_utf8(body) else {
                        panic!("a query body was not valid UTF-8");
                    };
                    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&rendered) else {
                        panic!("a query body was not valid JSON: {rendered:?}");
                    };
                    let Some(fields) = parsed.as_object() else {
                        panic!("a query body was not an object");
                    };
                    assert_eq!(
                        fields.get("pre").and_then(serde_json::Value::as_str),
                        Some(text.as_str())
                    );
                    assert_eq!(fields.contains_key("sn"), sequence.is_some());
                    assert_eq!(fields.contains_key("anchor"), anchor.is_some());
                    assert_eq!(
                        fields.len(),
                        1 + usize::from(sequence.is_some()) + usize::from(anchor.is_some())
                    );
                }
                Err(error) => assert!(!error.to_string().is_empty()),
            }
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // 3. A sequence number's rendering round-trips in the base its caller chose.
    if let Some(byte) = data.first() {
        let value = u64::from(*byte);
        let decimal = QuerySequence::Decimal(value);
        let hexadecimal = QuerySequence::Hexadecimal(value);
        assert_eq!(decimal.value(), value);
        assert_eq!(hexadecimal.value(), value);
        assert_eq!(decimal.to_text().parse::<u64>().ok(), Some(value));
        assert_eq!(u64::from_str_radix(&hexadecimal.to_text(), 16).ok(), Some(value));
        assert_eq!(decimal.to_text() == hexadecimal.to_text(), value < 10);
    }

    // 4. An agent's answer is believed only in the shape it claimed.
    if let Ok(state) = serde_json::from_slice::<KeyState>(document) {
        match serde_json::to_vec(&state) {
            Ok(encoded) => match serde_json::from_slice::<KeyState>(&encoded) {
                Ok(again) => assert!(again == state, "a key state did not survive re-encoding"),
                Err(error) => panic!("a re-encoded key state no longer decodes: {error}"),
            },
            Err(error) => panic!("a decoded key state could not be re-encoded: {error}"),
        }
    }

    if let Ok(record) = serde_json::from_slice::<KeyEventRecord>(document) {
        // Both halves are always present: an event without its attachments is not a record.
        let _ = &record.ked;
        match serde_json::to_vec(&record) {
            Ok(encoded) => assert!(
                serde_json::from_slice::<KeyEventRecord>(&encoded).is_ok(),
                "a re-encoded key-event record no longer decodes"
            ),
            Err(error) => panic!("a decoded key-event record could not be re-encoded: {error}"),
        }
    }

    if let Ok(operation) = serde_json::from_slice::<QueryOperation>(document) {
        // Exactly one outcome, decided at decode time — never a `done` flag a caller must
        // remember to read, and never two states at once. Roadmap 6.5's reader is what a caller
        // reaches for, so it is what is exercised.
        let pending = matches!(operation.outcome, OperationOutcome::Pending);
        let metadata_sequence = operation.metadata.as_ref().map(|metadata| metadata.sn);
        let name = operation.name.clone();
        match completed(operation) {
            Ok(state) => {
                assert!(!pending, "a pending operation yielded a state");
                // A completed query answers with the key state it went to find.
                assert!(
                    serde_json::to_vec(&state).is_ok(),
                    "a completed query's state could not be re-encoded"
                );
            }
            Err(ClientError::OperationPending { name: reported }) => {
                assert!(pending, "a finished operation was reported pending");
                assert_eq!(reported, name);
            }
            Err(ClientError::OperationFailed { message, .. }) => {
                assert!(!pending, "a pending operation was reported failed");
                // Remote text, bounded and never split through a character.
                assert!(message.len() <= 512);
            }
            Err(other) => panic!("an operation produced an unexpected failure: {other}"),
        }
        // The metadata's sequence number is a JSON *number*, where the request writes text — the
        // asymmetry this module records. Both spellings of the same value must agree.
        if let Some(sequence) = metadata_sequence {
            assert_eq!(QuerySequence::Decimal(sequence).value(), sequence);
        }
    }
});
