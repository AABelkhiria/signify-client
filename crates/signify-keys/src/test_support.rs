//! Helpers shared by the crate's unit tests.

#![allow(
    dead_code,
    reason = "compiled once per test binary; not every binary uses every helper"
)]

use std::error::Error;

use keri_cesr::crypto::CryptoError;
use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::verifier::VerificationKey;
use keria_types::api::KeyState;

use crate::controller::{Agent, Controller, ControllerError, ControllerOptions};
use crate::manager::DerivationCost;

/// The test agent's identifier, which is also its inception digest.
const AGENT_PREFIX: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";
/// The test agent's signing key.
const AGENT_KEY: &str = "DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE";
/// The test agent's delegator.
const AGENT_DELEGATOR: &str = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose";

/// The raw salt the pinned reference tests use throughout.
pub(crate) fn salt() -> Result<Salt, CryptoError> {
    Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)
}

/// The Blake3 digest that commits to a public key.
pub(crate) fn key_digest(key: &str) -> Result<String, CryptoError> {
    let verifier = VerificationKey::from_qb64(key)?;
    Digest::derive(DigestAlgorithm::Blake3_256, &verifier.qb64_bytes()?).qb64()
}

/// A controller at the ephemeral derivation cost.
pub(crate) fn ephemeral_controller(passcode: &str) -> Result<Controller, ControllerError> {
    Controller::with_options(
        passcode,
        SecurityTier::Low,
        ControllerOptions {
            derivation_cost: DerivationCost::Ephemeral,
            ..ControllerOptions::default()
        },
    )
}

/// A key state at the test agent's prefix, using real key material from the fixtures.
pub(crate) fn key_state_value(
    sequence_number_hex: &str,
    event_type: &str,
    keys: &[String],
    delegator: &str,
) -> serde_json::Value {
    serde_json::json!({
        "i": AGENT_PREFIX,
        "s": sequence_number_hex,
        "p": "",
        "d": AGENT_PREFIX,
        "f": "0",
        "dt": "2023-12-01T10:05:25.062609+00:00",
        "et": event_type,
        "kt": "1",
        "k": keys,
        "nt": "1",
        "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": AGENT_PREFIX, "br": [], "ba": []},
        "di": delegator
    })
}

/// A well-formed delegated agent key state at a sequence number.
pub(crate) fn agent_state_value(sequence_number_hex: &str) -> serde_json::Value {
    key_state_value(sequence_number_hex, "dip", &[AGENT_KEY.to_owned()], AGENT_DELEGATOR)
}

/// An agent whose inception a controller can anchor.
pub(crate) fn agent(sequence_number_hex: &str) -> Result<Agent, Box<dyn Error>> {
    let state: KeyState = serde_json::from_value(agent_state_value(sequence_number_hex))?;
    Ok(Agent::from_key_state(state)?)
}

/// The key state document of an incepted single-key member.
pub(crate) fn member_state_json(prefix: &str, key: &str, next_digest: &str) -> String {
    format!(
        r#"{{"i":"{prefix}","s":"0","p":"","d":"{prefix}","f":"0","dt":"","et":"icp","kt":"1","k":["{key}"],"nt":"1","n":["{next_digest}"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{prefix}"}},"di":""}}"#
    )
}

/// The key state of an incepted single-key member.
pub(crate) fn member_state(prefix: &str, key: &str, next_digest: &str) -> Result<KeyState, serde_json::Error> {
    serde_json::from_str(&member_state_json(prefix, key, next_digest))
}
