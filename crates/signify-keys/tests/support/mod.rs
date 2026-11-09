//! Helpers shared by the integration tests.

#![allow(
    dead_code,
    reason = "compiled once per test binary; not every binary uses every helper"
)]

use keri_cesr::crypto::CryptoError;
use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::verifier::{KeyTransferability, VerificationKey};
use keria_types::api::{AcceptedHab, KeyState};
use proptest::test_runner::TestCaseError;
use signify_keys::identifier::{CreateAlgorithm, CreateIdentifierRequest, IdentifierError};
use signify_keys::manager::{DerivationCost, IdentifierKeeper, KeeperFactory, ManagerError};

/// The pinned reference's own test passcode. PUBLIC TEST MATERIAL, not a secret.
pub(crate) const PASSCODE: &str = "0123456789abcdefghijk";

/// The encryption seed the pinned test calls `cryptseed0`.
pub(crate) const CRYPT_SEED: [u8; 32] = [
    104, 44, 35, 124, 138, 112, 34, 18, 196, 51, 116, 50, 166, 225, 24, 25, 240, 102, 50, 44, 121, 196, 194, 49, 64,
    245, 64, 21, 46, 162, 26, 207,
];

pub(crate) const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
pub(crate) const ISSUANCE: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";
pub(crate) const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

/// The test agent's identifier, which is also its inception digest.
const AGENT_PREFIX: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";

/// Turns any displayable error into a failed property case.
pub(crate) fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

/// The raw salt the pinned reference tests use throughout.
pub(crate) fn salt() -> Result<Salt, CryptoError> {
    Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)
}

/// Maps a generated flag onto a key transferability.
pub(crate) fn transferability(transferable: bool) -> KeyTransferability {
    if transferable {
        KeyTransferability::Transferable
    } else {
        KeyTransferability::NonTransferable
    }
}

/// The Blake3 digest that commits to a public key.
pub(crate) fn key_digest(key: &str) -> Result<String, CryptoError> {
    let verifier = VerificationKey::from_qb64(key)?;
    Digest::derive(DigestAlgorithm::Blake3_256, &verifier.qb64_bytes()?).qb64()
}

/// A deterministic, cheap salty request.
pub(crate) fn salty_request(passcode: &str, current: usize, next: usize) -> CreateIdentifierRequest {
    CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some(passcode.into()),
        tier: SecurityTier::Low,
        current_count: current,
        next_count: next,
        cost: DerivationCost::Ephemeral,
    })
}

/// A keeper for a request, from a factory over the fixed salt.
pub(crate) fn keeper_for(request: &CreateIdentifierRequest) -> Result<Box<dyn IdentifierKeeper>, IdentifierError> {
    let factory = KeeperFactory::new(salt().map_err(ManagerError::from)?);
    Ok(factory.create(request.keeper_request(0)?)?)
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

/// A member identifier record naming one signing key and one committed-to digest.
pub(crate) fn member_habitat(name: &str, key: &str, next_digest: &str) -> Result<AcceptedHab, serde_json::Error> {
    serde_json::from_str(&format!(
        r#"{{"name":"{name}","prefix":"EMEM","icp_dt":"2023-12-01T10:05:25.062609+00:00","randy":{{"prxs":[],"nxts":[]}},"state":{{"i":"EMEM","s":"0","p":"","d":"EMEM","f":"0","dt":"","et":"icp","kt":"1","k":["{key}"],"nt":"1","n":["{next_digest}"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"EMEM"}},"di":""}}}}"#
    ))
}

/// The issuer's key state at a sequence number, with a configuration.
pub(crate) fn issuer_state(sequence_number: u128, configuration: &[&str]) -> Result<KeyState, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "i": ISSUER,
        "s": format!("{sequence_number:x}"),
        "p": "",
        "d": ISSUANCE,
        "f": "0",
        "dt": STAMP,
        "et": "icp",
        "kt": "1",
        "k": ["DAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"],
        "nt": "1",
        "n": [ISSUANCE],
        "bt": "0",
        "b": [],
        "c": configuration,
        "ee": {"s": "0", "d": ISSUANCE, "br": [], "ba": []},
        "di": "",
    }))
}

/// The key state an inception event describes, as of a timestamp.
pub(crate) fn incepted_state(event: &serde_json::Value, stamp: &str) -> serde_json::Value {
    serde_json::json!({
        "i": event.get("i"),
        "s": "0",
        "p": "",
        "d": event.get("d"),
        "f": "0",
        "dt": stamp,
        "et": "icp",
        "kt": event.get("kt"),
        "k": event.get("k"),
        "nt": event.get("nt"),
        "n": event.get("n"),
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": event.get("d"), "br": [], "ba": []},
        "di": "",
    })
}
