#![no_main]

//! Fuzzes agent key-state validation, controller passcodes, and restored establishment events.
//!
//! An agent's key state is a KERIA response — the module's one genuinely remote input — so the
//! bulk of the corpus drives arbitrary replacements through its fields. A passcode is typed by a
//! person, and a restored establishment event comes back from stored state; both are driven with
//! the same bytes. The target asserts that nothing panics, that every rejection is a typed
//! [`ControllerError`] with a non-empty description, and that anything accepted upholds the
//! module's invariants: a validated agent is delegated, single-key, and threshold-one, and a
//! restored controller's current event always carries an identifier, a SAID, and a sequence
//! number.
//!
//! Every derivation uses the ephemeral cost; the production profile is covered by the
//! cross-language vectors, and the validation under test does not depend on it.

use keri_cesr::crypto::salt::SecurityTier;
use keria_types::api::KeyState;
use libfuzzer_sys::fuzz_target;
use signify_keys::controller::{Agent, Controller, ControllerError, ControllerOptions};
use signify_keys::manager::DerivationCost;
use keri_protocol::serialization::SerializedEvent;

/// The fields of an agent key state the fuzzer replaces, selected by the first input byte.
const FIELDS: [&str; 9] = ["i", "s", "d", "et", "kt", "k", "nt", "n", "di"];

/// A well-formed delegated agent state; every case mutates one field of it.
fn base_state() -> serde_json::Value {
    serde_json::json!({
        "i": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
        "s": "0",
        "p": "",
        "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
        "f": "0",
        "dt": "2023-12-01T10:05:25.062609+00:00",
        "et": "dip",
        "kt": "1",
        "k": ["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE"],
        "nt": "1",
        "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", "br": [], "ba": []},
        "di": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"
    })
}

/// Asserts that an accepted agent upholds every invariant its type claims.
fn assert_agent_invariants(agent: &Agent) {
    assert_eq!(agent.state().signing_keys.len(), 1);
    assert_eq!(agent.state().next_key_digests.len(), 1);
    assert_eq!(agent.state().establishment_kind, "dip");
    assert!(agent.state().delegator().is_some());
    let anchor = agent.anchor().qb64().ok();
    assert!(anchor.is_some(), "an accepted agent has no encodable anchor");
    assert_eq!(anchor.as_deref(), agent.state().delegator());
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(body).into_owned();

    // One field of a KERIA agent state, replaced by attacker-chosen text — either as a bare
    // string or as a single-element list, whichever the field carries.
    let Some(&field) = FIELDS.get(usize::from(selector) % FIELDS.len()) else {
        return;
    };
    let mut mutated = base_state();
    mutated[field] = if matches!(field, "k" | "n") && selector & 0x80 == 0 {
        serde_json::json!([text.clone()])
    } else {
        serde_json::json!(text.clone())
    };
    match serde_json::from_value::<KeyState>(mutated) {
        Ok(state) => match Agent::from_key_state(state) {
            Ok(agent) => assert_agent_invariants(&agent),
            Err(error) => assert!(!error.to_string().is_empty()),
        },
        Err(_) => {
            // The typed decode itself may refuse the shape, which is Roadmap 4.1's boundary.
        }
    }

    // The same text as a passcode a person typed.
    let options = ControllerOptions {
        derivation_cost: DerivationCost::Ephemeral,
        ..ControllerOptions::default()
    };
    match Controller::with_options(&text, SecurityTier::Low, options) {
        Ok(controller) => {
            assert!(text.chars().count() >= 21);
            assert_eq!(controller.current_sequence_number(), 0);
            assert!(controller.current_event().identifier_prefix().is_some());
        }
        Err(error) => {
            assert!(matches!(&error, ControllerError::Manager { .. }), "{error:?}");
            assert!(!error.to_string().is_empty());
        }
    }

    // The same bytes as a stored establishment event.
    if let Ok(event) = SerializedEvent::parse(body) {
        match Controller::restore("0123456789abcdefghijk", SecurityTier::Low, options, event) {
            Ok(controller) => {
                // Whatever was adopted or rebuilt carries the three fields the controller reads.
                assert!(controller.current_event().identifier_prefix().is_some());
                assert!(controller.current_event().said().is_some());
            }
            Err(error) => assert!(!error.to_string().is_empty()),
        }
    }
});
