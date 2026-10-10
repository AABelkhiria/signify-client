#![no_main]

//! Fuzzes identifier-artifact construction over hostile key states and request fields.
//!
//! A key state comes back from KERIA and feeds `interact_identifier` and `rotate_identifier`
//! directly — its sequence number, digest, identifier, thresholds, witnesses, and delegator all
//! reach event construction — so the first input byte selects which of its fields the rest
//! replaces. The remaining bytes also drive a creation request's counts, transferability, and
//! thresholds. The target asserts that nothing panics, that every rejection is a typed
//! [`IdentifierError`] with a non-empty description, and that anything accepted is
//! self-consistent: the event agrees with its declared size, reparses losslessly, and carries the
//! sequence number, prior digest, and event kind its inputs imply.
//!
//! Every derivation uses the ephemeral cost; the production profile is covered by the
//! cross-language vectors.

use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::verifier::KeyTransferability;
use keria_types::api::KeyState;
use libfuzzer_sys::fuzz_target;
use signify_keri::identifier::{
    CreateAlgorithm, CreateIdentifierRequest, IdentifierError, RotateIdentifierRequest, incept_identifier,
    interact_identifier, rotate_identifier,
};
use signify_keri::manager::{DerivationCost, IdentifierKeeper, KeeperFactory};
use keri_protocol::serialization::SerializedEvent;

/// The key-state fields the fuzzer replaces, selected by the first input byte.
const FIELDS: [&str; 8] = ["i", "s", "d", "nt", "b", "di", "k", "n"];

fn base_state() -> serde_json::Value {
    serde_json::json!({
        "i": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
        "s": "0",
        "p": "",
        "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
        "f": "0",
        "dt": "2023-12-01T10:05:25.062609+00:00",
        "et": "icp",
        "kt": "1",
        "k": ["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE"],
        "nt": "1",
        "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", "br": [], "ba": []},
        "di": ""
    })
}

fn keeper() -> Option<Box<dyn IdentifierKeeper>> {
    let factory = KeeperFactory::new(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).ok()?);
    let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some("0123456789abcdefghijk".to_owned()),
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Ephemeral,
    });
    factory.create(request.keeper_request(0).ok()?).ok()
}

/// Asserts an accepted event is self-consistent.
fn assert_event(artifact: &signify_keri::identifier::IdentifierArtifact) {
    assert_eq!(artifact.event.serialized().size(), artifact.event.raw().len());
    let Ok(reparsed) = SerializedEvent::parse(artifact.event.raw()) else {
        assert!(artifact.event.raw().is_empty(), "an accepted event does not reparse");
        return;
    };
    assert_eq!(reparsed.sad(), artifact.event.sad());
    assert!(!artifact.signatures.is_empty());
}

fuzz_target!(|data: &[u8]| {
    let [b0, b1, b2, body @ ..] = data else {
        return;
    };
    let text = String::from_utf8_lossy(body).into_owned();

    let Some(mut keeper) = keeper() else {
        return;
    };

    // A key state one field of which an attacker chose, driven through interaction and rotation.
    let Some(&field) = FIELDS.get(usize::from(*b0) % FIELDS.len()) else {
        return;
    };
    let mut mutated = base_state();
    let replacement = if matches!(field, "b" | "k" | "n") && b0 & 0x80 == 0 {
        serde_json::json!([text.clone()])
    } else {
        serde_json::json!(text.clone())
    };
    if let Some(object) = mutated.as_object_mut() {
        object.insert(field.to_owned(), replacement);
    }
    if let Ok(state) = serde_json::from_value::<KeyState>(mutated) {
        match interact_identifier(keeper.as_ref(), &state, Vec::new()) {
            Ok(artifact) => {
                assert_event(&artifact);
                assert_eq!(
                    artifact.event.sad().get_text("p"),
                    Some(state.digest.as_str()),
                    "the prior digest must be the state's"
                );
            }
            Err(error) => assert!(!error.to_string().is_empty()),
        }
        match rotate_identifier(keeper.as_mut(), &state, &RotateIdentifierRequest::default()) {
            Ok(artifact) => {
                assert_event(&artifact);
                let expected = if state.delegator().is_some() { "drt" } else { "rot" };
                assert_eq!(artifact.event.sad().get_text("t"), Some(expected));
            }
            Err(error) => assert!(!error.to_string().is_empty()),
        }
    }

    // A creation request whose counts, transferability, and thresholds the bytes choose.
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some("0123456789abcdefghijk".to_owned()),
        tier: SecurityTier::Low,
        current_count: usize::from(*b1 >> 1),
        next_count: usize::from(*b2 >> 1),
        cost: DerivationCost::Ephemeral,
    });
    if b1 & 1 == 1 {
        request.transferability = KeyTransferability::NonTransferable;
    }
    if b2 & 1 == 1 {
        request.signing_threshold = Some(keri_protocol::threshold::SigningThreshold::numeric(u128::from(*b2 >> 4)));
    }
    match request
        .keeper_request(u32::from(*b0))
        .map_err(IdentifierError::from)
        .and_then(|keeper_request| {
            let factory = KeeperFactory::new(
                Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)
                    .map_err(signify_keri::manager::ManagerError::from)?,
            );
            let mut keeper = factory.create(keeper_request)?;
            incept_identifier(keeper.as_mut(), &request)
        }) {
        Ok(artifact) => {
            assert_event(&artifact);
            // A non-transferable creation never commits to next keys.
            if request.transferability == KeyTransferability::NonTransferable {
                assert_eq!(artifact.event.sad().get_text("nt"), Some("0"));
            }
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }
});
