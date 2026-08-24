#![no_main]

//! Fuzzes the KERIA API record decoders.
//!
//! Every one of these records is built from a response body, so the bytes come from whatever the
//! agent — or whatever is between the client and the agent — chose to send. The first input byte
//! selects which record the rest is decoded as, so one corpus entry drives every decoder in turn.
//!
//! The target asserts that nothing panics, that every rejection is one of the expected typed
//! errors, that anything accepted re-encodes into something that decodes to an equal value, and
//! that the byte bound is enforced before any parsing happens.

use libfuzzer_sys::fuzz_target;
use signify_types::api::{
    AcdcRecord, AgentConfig, ApiError, Contact, Credential, Hab, KeyEvent, KeyState, MAX_DOCUMENT_BYTES,
    Notification, Oobi, Registry, Threshold, UntypedOperation, from_json_slice, from_json_slice_with_limit,
    to_json_string,
};

/// Returns whether a rejection is one of the variants this crate is allowed to produce.
fn is_expected(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Json { .. }
            | ApiError::DocumentTooLarge { .. }
            | ApiError::MissingKeyManagerState
            | ApiError::AmbiguousKeyManagerState { .. }
            | ApiError::MissingKeyState
            | ApiError::UnexpectedKeyState
            | ApiError::UnexpectedEventKind { .. }
    )
}

/// Decodes, and if that succeeds asserts the record survives its own encoding.
macro_rules! round_trip {
    ($record:ty, $body:expr) => {{
        match from_json_slice::<$record>($body) {
            Ok(record) => {
                let encoded = to_json_string(&record).expect("a decoded record must encode");
                let again: $record =
                    from_json_slice(encoded.as_bytes()).expect("an encoded record must decode again");
                assert_eq!(record, again, "encoding a record changed it");
                // Encoding is idempotent, so a stored record is stable.
                assert_eq!(encoded, to_json_string(&again).expect("re-encoding must succeed"));
                true
            }
            Err(error) => {
                assert!(is_expected(&error), "unexpected error variant: {error:?}");
                assert!(!error.to_string().is_empty(), "a rejection carried no reason");
                false
            }
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };

    // The bound is checked before the parser sees anything, whatever the record.
    if body.len() > MAX_DOCUMENT_BYTES {
        assert!(matches!(
            from_json_slice::<KeyState>(body),
            Err(ApiError::DocumentTooLarge { .. })
        ));
        return;
    }
    // A caller-chosen bound behaves the same way.
    let narrow = usize::from(selector);
    if body.len() > narrow {
        assert!(matches!(
            from_json_slice_with_limit::<KeyState>(body, narrow),
            Err(ApiError::DocumentTooLarge { length, limit })
                if length == body.len() && limit == narrow
        ));
    }

    let accepted = match selector % 13 {
        0 => round_trip!(KeyState, body),
        1 => round_trip!(Hab, body),
        2 => round_trip!(KeyEvent, body),
        3 => round_trip!(UntypedOperation, body),
        4 => round_trip!(Contact, body),
        5 => round_trip!(Threshold, body),
        6 => round_trip!(Credential, body),
        7 => round_trip!(Registry, body),
        8 => round_trip!(Notification, body),
        9 => round_trip!(Oobi, body),
        10 => round_trip!(AcdcRecord, body),
        11 => round_trip!(AgentConfig, body),
        _ => round_trip!(signify_types::api::ExchangeEmbeds, body),
    };

    // An accepted document is JSON, so it can never be empty.
    if accepted {
        assert!(!body.is_empty());
    }

    // An identifier record that decodes always names exactly one key manager, and its acceptance
    // is decided by key state alone — the two invariants the hand-written union guard exists for.
    if let Ok(hab) = from_json_slice::<Hab>(body) {
        let label = hab.common().key_manager.label();
        assert!(matches!(label, "salty" | "randy" | "group" | "extern"));
        assert_eq!(hab.key_state().is_some(), matches!(hab, Hab::Accepted(_)));
    }

    // A key event that decodes always reports the ilk it was chosen by, and writes it back.
    if let Ok(event) = from_json_slice::<KeyEvent>(body) {
        assert!(signify_types::api::KEY_EVENT_ILKS.contains(&event.kind()));
        let encoded = to_json_string(&event).expect("a decoded key event must encode");
        assert!(encoded.contains(&format!("\"t\":\"{}\"", event.kind())));
        assert_eq!(event.is_establishment(), event.kind() != "ixn");
    }

    // An operation that decodes always has exactly one outcome, and `done` follows from it.
    if let Ok(operation) = from_json_slice::<UntypedOperation>(body) {
        let done = operation.outcome.is_done();
        let response = operation.outcome.response().is_some();
        let error = operation.outcome.error().is_some();
        assert!(!(response && error), "an operation reported both a result and a failure");
        assert_eq!(done, response || error);
    }
});
