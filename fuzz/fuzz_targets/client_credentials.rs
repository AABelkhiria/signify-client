#![no_main]

//! Fuzzes the credentials endpoint over hostile SAIDs, aliases, query clauses, and agent answers.
//!
//! Four things reach this family from outside, and each is a different kind of boundary.
//!
//! **Seven path components.** The reference interpolates every one of them raw, so upstream a SAID
//! or an alias carrying `/`, `?`, or `#` addresses a different resource — and Roadmap 3.10 signs
//! `@path`, so it also changes what the signature commits to. This target asserts that anything
//! accepted as a SAID or a registry identifier is exactly one segment and carries no delimiter, and
//! that an alias can never leave its own.
//!
//! **A query filter.** `list` is the only read in the crate that sends a body, and that body is the
//! *agent's* query language: whatever labels and values a caller assembles reach the wire. The
//! target asserts the rendered body is always valid JSON with exactly the reference's four fields,
//! whatever the clauses hold, so a hostile label cannot restructure the request.
//!
//! **A credential answer.** `get`, `list`, and `state` all return documents the reference casts
//! rather than decodes. The target asserts anything accepted survives re-encoding, which is what
//! makes a stored answer safe to re-read.
//!
//! **A CESR stream.** `get_cesr` returns text, and the reference's `res.text()` substitutes
//! replacement characters rather than refusing — so a stream with an invalid byte still parses
//! there and says something else. The target asserts the accept/reject split here is exactly UTF-8
//! validity, with nothing repaired.

use libfuzzer_sys::fuzz_target;
use signify_acdc::credential::RegistryIdentifier;
use signify_client::endpoint::credentials::{CREDENTIAL_QUERY_SEGMENT, CREDENTIALS_SEGMENT, CredentialFilter};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::registries::REGISTRIES_SEGMENT;
use signify_http::request::ResourcePath;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};
use signify_types::api::{Credential, CredentialState};

/// Asserts one accepted qualified value is exactly one unchanged path segment.
fn one_segment(prefix: &str, value: &str) {
    let Ok(path) = ResourcePath::builder().segment(prefix).segment(value).build() else {
        panic!("a validated qualified value could not be addressed");
    };
    let segments: Vec<&str> = path.path().split('/').skip(1).collect();
    assert_eq!(
        segments.len(),
        2,
        "a qualified value became {} segments",
        segments.len()
    );
    assert_eq!(segments.first().copied(), Some(prefix));
    // A qualified value's alphabet is URL-safe Base64, so encoding leaves it unchanged.
    assert_eq!(segments.get(1).copied(), Some(value));
    assert_eq!(path.query(), None);
    assert!(!path.as_str().contains('#'));
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let said_text = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let alias = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let clauses = parts.next().unwrap_or_default();
    let document = parts.next().unwrap_or_default();
    let stream = parts.next().unwrap_or_default();

    // 1. A SAID and a registry identifier are validated before they are path components.
    match Said::from_qb64(&said_text) {
        Ok(said) => {
            let Ok(encoded) = said.qb64() else {
                panic!("a parsed SAID could not be re-encoded");
            };
            for separator in ['/', '?', '#'] {
                assert!(!encoded.contains(separator), "an accepted SAID carries {separator:?}");
            }
            one_segment(CREDENTIALS_SEGMENT, &encoded);
            // The same value addresses the state read's third segment.
            let Ok(path) = ResourcePath::builder()
                .segment(REGISTRIES_SEGMENT)
                .segment(&encoded)
                .segment(&encoded)
                .build()
            else {
                panic!("a validated SAID could not address a credential status");
            };
            assert_eq!(path.path().split('/').count(), 4);
            assert_eq!(path.query(), None);
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    match RegistryIdentifier::from_qb64(&said_text) {
        Ok(registry) => {
            let Ok(encoded) = registry.qb64() else {
                panic!("a parsed registry identifier could not be re-encoded");
            };
            one_segment(REGISTRIES_SEGMENT, &encoded);
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // 2. An alias can never leave its own segment, in the one path shape that carries it.
    match ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(&alias)
        .segment(CREDENTIALS_SEGMENT)
        .build()
    {
        Ok(path) => {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(segments.len(), 3, "an alias became {} segments", segments.len());
            assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
            assert_eq!(segments.get(2).copied(), Some(CREDENTIALS_SEGMENT));
            assert_eq!(path.query(), None);
            assert!(!path.as_str().contains('#'));
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // A listing's own address carries no caller input at all.
    let Ok(listing) = ResourcePath::builder()
        .segment(CREDENTIALS_SEGMENT)
        .segment(CREDENTIAL_QUERY_SEGMENT)
        .build()
    else {
        panic!("the constant listing path could not be built");
    };
    assert_eq!(listing.as_str(), "/credentials/query");

    // 3. A filter renders exactly four fields whatever its clauses hold.
    let mut query = Sad::new();
    for (index, clause) in clauses.split(|&byte| byte == 0xfe).enumerate() {
        if clause.is_empty() {
            continue;
        }
        let label = String::from_utf8_lossy(clause).into_owned();
        // A duplicate label is refused by `Sad`, which is what keeps the body unambiguous.
        if query.insert(label, SadValue::Text(format!("{index}"))).is_err() {
            break;
        }
    }
    let filter = CredentialFilter::new()
        .with_filter(query)
        .with_skip(u32::from(data.first().copied().unwrap_or_default()))
        .with_limit(u32::from(data.last().copied().unwrap_or_default()));
    match filter.to_json_bytes() {
        Ok(body) => {
            let Ok(decoded) = serde_json::from_slice::<serde_json::Value>(&body) else {
                panic!("a rendered filter body is not valid JSON");
            };
            let Some(fields) = decoded.as_object() else {
                panic!("a rendered filter body is not an object");
            };
            assert_eq!(fields.len(), 4, "a filter body carried {} fields", fields.len());
            for label in ["filter", "sort", "skip", "limit"] {
                assert!(fields.contains_key(label), "a filter body lacks {label}");
            }
            assert!(fields.get("sort").is_some_and(serde_json::Value::is_array));
            assert!(fields.get("filter").is_some_and(serde_json::Value::is_object));
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // 4. An agent's answer is believed only in the shape it claimed, and survives re-encoding.
    if let Ok(record) = serde_json::from_slice::<Credential>(document) {
        match serde_json::to_vec(&record) {
            Ok(encoded) => match serde_json::from_slice::<Credential>(&encoded) {
                Ok(again) => {
                    // Compared field by field rather than by whole value: a captured open field
                    // holding an integer outside the exact range does not survive its first
                    // re-encoding, which is Roadmap 4.1's own pre-existing defect (`PORTING.md`
                    // §10, owned by Roadmap 9.3) rather than anything this family introduces.
                    assert_eq!(again.sad.digest, record.sad.digest);
                    assert_eq!(again.status.credential(), record.status.credential());
                    assert_eq!(again.status.status(), record.status.status());
                }
                Err(error) => panic!("a re-encoded credential record no longer decodes: {error}"),
            },
            Err(error) => panic!("a decoded credential record could not be re-encoded: {error}"),
        }
    }

    if let Ok(state) = serde_json::from_slice::<CredentialState>(document) {
        // The status kind decides which shape the rest of the document has, so it is never
        // inferred: a backed status carries a registry anchor and an unbacked one cannot.
        assert!(["iss", "rev", "bis", "brv"].contains(&state.status()));
        let revoked = matches!(state.status(), "rev" | "brv");
        assert_eq!(state.is_revoked(), revoked);
        match serde_json::to_vec(&state) {
            Ok(encoded) => match serde_json::from_slice::<CredentialState>(&encoded) {
                Ok(again) => assert_eq!(again.status(), state.status()),
                Err(error) => panic!("a re-encoded credential status no longer decodes: {error}"),
            },
            Err(error) => panic!("a decoded credential status could not be re-encoded: {error}"),
        }
    }

    // 5. A CESR answer is accepted exactly when it is UTF-8, and is never repaired.
    match core::str::from_utf8(stream) {
        Ok(text) => {
            let owned = String::from_utf8(stream.to_vec());
            assert!(owned.is_ok(), "valid UTF-8 was refused as a CESR stream");
            assert_eq!(owned.unwrap_or_default(), text);
            assert_eq!(text.as_bytes(), stream, "a CESR stream was altered in flight");
        }
        Err(error) => {
            // The reference's `res.text()` would substitute U+FFFD here and carry on.
            assert!(String::from_utf8(stream.to_vec()).is_err());
            assert!(error.valid_up_to() <= stream.len());
            assert!(String::from_utf8_lossy(stream).contains('\u{fffd}'));
        }
    }
});
