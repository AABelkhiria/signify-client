#![no_main]

//! Fuzzes the operations endpoint over hostile names, filters, and agent answers.
//!
//! Two things here come from outside. An **operation name** is a path component, and the reference
//! interpolates it unencoded — so a name carrying `/` or `?` addresses a different resource
//! entirely, and, because Roadmap 3.10 signs `@path`, changes what a signature commits to. An
//! **agent's answer** is a document that decides whether a caller believes an operation succeeded.
//!
//! The target asserts that nothing panics, that a name can never escape its own path segment
//! whatever it holds, that a filter always writes exactly one query parameter and an absent one
//! writes none, and that an agent's answer either decodes into exactly one of the three outcomes
//! or is refused — never resolved to a state it did not claim.

use keria_types::api::{KeyEvent, UntypedOperation, WitnessMetadata};
use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::operations::{MAX_FAILURE_MESSAGE_BYTES, OPERATIONS_SEGMENT, TYPE_PARAMETER, completed};
use signify_client::error::ClientError;
use signify_http::request::ResourcePath;

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let name = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let filter = parts.next().map(|part| String::from_utf8_lossy(part).into_owned());
    let document = parts.next().unwrap_or_default();

    // The path `get` and `delete` share. A name is a single component, always.
    match ResourcePath::builder()
        .segment(OPERATIONS_SEGMENT)
        .segment(&name)
        .build()
    {
        Ok(path) => {
            assert!(path.as_str().starts_with("/operations/"));
            assert_eq!(path.query(), None, "a name introduced a query: {name:?}");
            assert_eq!(path.path(), path.as_str());
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(segments.len(), 2, "a name became {} segments: {name:?}", segments.len());
            assert_eq!(segments.first().copied(), Some(OPERATIONS_SEGMENT));
            let encoded = segments.get(1).copied().unwrap_or_default();
            for separator in ['/', '?', '#'] {
                assert!(
                    !encoded.contains(separator),
                    "an encoded name still carries {separator:?}"
                );
            }
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // The listing path. A filter writes exactly one parameter; no filter writes no query.
    match ResourcePath::builder()
        .segment(OPERATIONS_SEGMENT)
        .optional_parameter(TYPE_PARAMETER, filter.as_deref())
        .build()
    {
        Ok(path) => {
            // Whatever the filter held, the *signed* path never changes — Roadmap 3.10 strips the
            // query, so a filter can never alter what a signature commits to.
            assert_eq!(path.path(), "/operations");
            match filter.as_deref() {
                Some(_) => {
                    let query = path.query().unwrap_or_default();
                    assert!(query.starts_with("type="), "a filter wrote {query:?}");
                    assert_eq!(query.matches('&').count(), 0, "a filter wrote two parameters");
                }
                None => {
                    assert_eq!(path.query(), None, "an absent filter wrote a query");
                    assert_eq!(path.as_str(), "/operations");
                }
            }
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // The agent's answer.
    let Ok(untyped) = serde_json::from_slice::<UntypedOperation>(document) else {
        return;
    };
    let done = untyped.outcome.is_done();
    let name = untyped.name.clone();

    let Ok(typed) = untyped.into_typed::<WitnessMetadata, KeyEvent>() else {
        // A narrowing that does not fit is a refusal, never a silently wrong branch.
        return;
    };
    assert_eq!(typed.outcome.is_done(), done, "narrowing changed the outcome");
    assert_eq!(typed.name, name, "narrowing changed the name");

    match completed(typed) {
        Ok(_) => assert!(done, "a running operation yielded a response"),
        Err(ClientError::OperationPending { name: reported }) => {
            assert!(!done, "a finished operation was reported as pending");
            assert_eq!(reported, name);
        }
        Err(ClientError::OperationFailed {
            name: reported,
            message,
            details,
            ..
        }) => {
            assert!(done, "a running operation was reported as failed");
            assert_eq!(reported, name);
            // The message is bounded and never split through a character.
            assert!(message.len() <= MAX_FAILURE_MESSAGE_BYTES);
            assert!(core::str::from_utf8(message.as_bytes()).is_ok());
            // A rendered detail block is valid JSON, or absent.
            if let Some(details) = &details {
                assert!(serde_json::from_str::<serde_json::Value>(details).is_ok());
            }
        }
        Err(other) => panic!("an unexpected outcome: {other}"),
    }
});
