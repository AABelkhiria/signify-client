#![no_main]

//! Fuzzes the identifier endpoint family over hostile aliases and hostile agent records.
//!
//! Two things reach this family from outside, and both decide something a caller cannot check
//! afterwards.
//!
//! An **alias** is a path component in seven places, and the reference encodes it in only two — so
//! upstream an alias holding `/` addresses a different identifier *and* changes what a signature
//! commits to, because the request signature covers `@path`. This target asserts the component can
//! never escape its segment whatever it holds.
//!
//! An **identifier record** is the document a keeper is rebuilt from and an interaction or rotation
//! chains on. A record that decodes into the wrong shape would make a client sign an event for
//! keys it does not hold, or sign with a key state it never had. This target asserts a record is
//! believed only in the state it actually claimed: an accepted record always carries key state, a
//! pending one never does, and either re-encodes losslessly.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::identifiers::{
    END_ROLES_SEGMENT, EVENTS_SEGMENT, IDENTIFIER_RANGE_UNIT, IDENTIFIERS_SEGMENT, LOCATION_SCHEMES_SEGMENT,
    MEMBERS_SEGMENT,
};
use signify_client::types::api::Hab;
use signify_http::request::{ItemRange, RangeUnit, ResourcePath};
use signify_http::response::ContentRange;

/// Every trailing segment an alias can be followed by, plus the bare record path.
const TRAILING: [Option<&str>; 5] = [
    None,
    Some(EVENTS_SEGMENT),
    Some(END_ROLES_SEGMENT),
    Some(LOCATION_SCHEMES_SEGMENT),
    Some(MEMBERS_SEGMENT),
];

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let alias = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let document = parts.next().unwrap_or_default();
    let range = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();

    // 1. An alias is one path segment, in every path this family builds.
    for trailing in TRAILING {
        let mut builder = ResourcePath::builder().segment(IDENTIFIERS_SEGMENT).segment(&alias);
        if let Some(trailing) = trailing {
            builder = builder.segment(trailing);
        }
        match builder.build() {
            Ok(path) => {
                assert!(path.as_str().starts_with("/identifiers/"));
                assert_eq!(path.query(), None, "an alias introduced a query: {alias:?}");
                assert_eq!(path.path(), path.as_str());
                let segments: Vec<&str> = path.path().split('/').skip(1).collect();
                let expected = if trailing.is_some() { 3 } else { 2 };
                assert_eq!(
                    segments.len(),
                    expected,
                    "an alias became {} segments: {alias:?}",
                    segments.len()
                );
                assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
                let encoded = segments.get(1).copied().unwrap_or_default();
                for separator in ['/', '?', '#'] {
                    assert!(
                        !encoded.contains(separator),
                        "an encoded alias still carries {separator:?}"
                    );
                }
                if let Some(trailing) = trailing {
                    assert_eq!(segments.get(2).copied(), Some(trailing));
                }
            }
            Err(error) => assert!(!error.to_string().is_empty()),
        }
    }

    // 2. An identifier record is believed only in the state it claimed.
    match serde_json::from_slice::<Hab>(document) {
        Ok(record) => {
            match &record {
                Hab::Accepted(accepted) => {
                    // The key state an interaction or rotation chains on is the record's own, and
                    // reaching it needs no guard the way the reference's `requireKeyState` does.
                    let Some(state) = record.key_state() else {
                        panic!("an accepted record carried no key state");
                    };
                    assert_eq!(state.identifier, accepted.state.identifier);
                    assert_eq!(state.digest, accepted.state.digest);
                    assert_eq!(state.sequence_number, accepted.state.sequence_number);
                }
                Hab::Pending(_) => assert!(record.key_state().is_none(), "a pending record produced key state"),
            }
            // Exactly one key manager, always: a record naming none or two does not decode, so a
            // keeper can never be rebuilt from an ambiguous one.
            assert!(
                ["salty", "randy", "group", "extern"].contains(&record.common().key_manager.label()),
                "a record named an unknown key manager"
            );
            // Re-encoding is what a group creation does with its local member, so it must not lose
            // or invent a field.
            if let Ok(encoded) = serde_json::to_vec(&record) {
                match serde_json::from_slice::<Hab>(&encoded) {
                    Ok(again) => assert!(again == record, "a record did not survive re-encoding"),
                    Err(error) => panic!("a re-encoded record no longer decodes: {error}"),
                }
            }
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // 3. A window is sent only when it is satisfiable, and read back only when it parses.
    let Ok(unit) = RangeUnit::new(IDENTIFIER_RANGE_UNIT) else {
        return;
    };
    let mut bounds = data.iter().copied();
    let start = u64::from(bounds.next().unwrap_or_default());
    let end = u64::from(bounds.next().unwrap_or_default());
    match ItemRange::new(start, end) {
        Ok(window) => {
            assert!(start <= end);
            let header = window.header_value(&unit);
            assert!(header.starts_with("aids="));
            assert_eq!(header, format!("aids={start}-{end}"));
            assert_eq!(window.count(), end.saturating_sub(start).saturating_add(1));
        }
        Err(error) => {
            assert!(start > end, "a satisfiable window was refused: {start}-{end}");
            assert!(!error.to_string().is_empty());
        }
    }
    match ContentRange::parse(&range, &unit) {
        Ok(reported) => {
            // A window the agent reports is read once and read the same way twice; nothing here
            // repairs a malformed header, so a second parse must agree exactly.
            assert!(range.starts_with(IDENTIFIER_RANGE_UNIT));
            match ContentRange::parse(&range, &unit) {
                Ok(again) => {
                    assert_eq!(again.start(), reported.start());
                    assert_eq!(again.end(), reported.end());
                    assert_eq!(again.total(), reported.total());
                }
                Err(error) => panic!("a window parsed once and refused twice: {error}"),
            }
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }
});
