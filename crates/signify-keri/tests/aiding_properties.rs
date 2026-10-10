//! Invariants of the identifier artifacts.
//!
//! Every case uses the ephemeral derivation cost. The production profile costs 64 MiB per key,
//! which a property test would multiply by its case count; the composition under test does not
//! depend on the profile, and the cross-language vectors cover the production one exactly.

use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::event::kind::EventKind;
use keri_protocol::serialization::{Sad, SadValue, SerializedEvent};
use keri_protocol::threshold::SigningThreshold;
use keria_types::api::KeyState;
use proptest::prelude::*;
use signify_keri::identifier::{
    CreateAlgorithm, CreateIdentifierRequest, IdentifierError, RotateIdentifierRequest, incept_identifier,
    interact_identifier, rotate_identifier,
};
use signify_keri::manager::{DerivationCost, IdentifierKeeper, KeeperFactory, ManagedSignatures};

const PASSCODE: &str = "0123456789abcdefghijk";

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn factory() -> Result<KeeperFactory, TestCaseError> {
    Ok(KeeperFactory::new(
        Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).map_err(fail)?,
    ))
}

fn salty_request(passcode: &str, current: usize, next: usize) -> CreateIdentifierRequest {
    CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some(passcode.to_owned()),
        tier: SecurityTier::Low,
        current_count: current,
        next_count: next,
        cost: DerivationCost::Ephemeral,
    })
}

fn keeper_for(request: &CreateIdentifierRequest) -> Result<Box<dyn IdentifierKeeper>, TestCaseError> {
    factory()?
        .create(request.keeper_request(0).map_err(fail)?)
        .map_err(fail)
}

/// The key state an incepted artifact's event describes, with optional overrides.
fn state_of(
    artifact: &signify_keri::identifier::IdentifierArtifact,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> Result<KeyState, TestCaseError> {
    let event: serde_json::Value = serde_json::from_slice(artifact.event.raw()).map_err(fail)?;
    let mut state = serde_json::json!({
        "i": event.get("i").cloned().unwrap_or_default(),
        "s": "0",
        "p": "",
        "d": event.get("d").cloned().unwrap_or_default(),
        "f": "0",
        "dt": "2023-12-01T10:05:25.062609+00:00",
        "et": "icp",
        "kt": event.get("kt").cloned().unwrap_or_default(),
        "k": event.get("k").cloned().unwrap_or_default(),
        "nt": event.get("nt").cloned().unwrap_or_default(),
        "n": event.get("n").cloned().unwrap_or_default(),
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": event.get("d").cloned().unwrap_or_default(), "br": [], "ba": []},
        "di": ""
    });
    mutate(&mut state);
    serde_json::from_value(state).map_err(fail)
}

fn signature_count(signatures: &ManagedSignatures) -> usize {
    signatures.len()
}

proptest! {
    /// Creation is deterministic for a passcode-backed keeper, and its event is self-consistent:
    /// the declared counts arrive, the bytes reparse, and every signature indexes a key.
    #[test]
    fn creation_is_deterministic_and_self_consistent(
        passcode in "[A-Za-z0-9_-]{21}",
        current in 1_usize..4,
        next in 0_usize..4,
    ) {
        let mut request = salty_request(&passcode, current, next);
        if next == 0 {
            request.next_threshold = Some(SigningThreshold::numeric(0));
        } else if current > 1 || next > 1 {
            let bound = current.min(next).max(1) as u128;
            request.signing_threshold = Some(SigningThreshold::numeric(bound.min(current as u128)));
            request.next_threshold = Some(SigningThreshold::numeric(bound.min(next as u128)));
        }
        let mut first = keeper_for(&request)?;
        let mut second = keeper_for(&request)?;
        let left = incept_identifier(first.as_mut(), &request).map_err(fail)?;
        let right = incept_identifier(second.as_mut(), &request).map_err(fail)?;
        prop_assert_eq!(left.event.raw(), right.event.raw());
        prop_assert_eq!(left.signatures.qb64().map_err(fail)?, right.signatures.qb64().map_err(fail)?);

        prop_assert_eq!(left.event.kind(), EventKind::Inception);
        prop_assert_eq!(signature_count(&left.signatures), current);
        let reparsed = SerializedEvent::parse(left.event.raw()).map_err(fail)?;
        prop_assert_eq!(reparsed.sad(), left.event.sad());
        let keys = reparsed.verification_keys().map_err(fail)?;
        prop_assert_eq!(keys.len(), current);
        prop_assert_eq!(reparsed.next_key_digests().map_err(fail)?.len(), next);
    }

    /// The default thresholds are one on both sides — not the majority formula — so a multi-key
    /// creation without explicit thresholds still writes `kt: "1"`.
    #[test]
    fn default_thresholds_are_one(current in 1_usize..4) {
        let request = salty_request(PASSCODE, current, 1);
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request).map_err(fail)?;
        prop_assert_eq!(artifact.event.sad().get_text("kt"), Some("1"));
        prop_assert_eq!(artifact.event.sad().get_text("nt"), Some("1"));
    }

    /// An interaction chains on any state: the sequence advances by exactly one in hexadecimal,
    /// the prior digest is the state's, and the anchors arrive verbatim.
    #[test]
    fn interactions_chain_on_the_state(sequence in 0_u64..1_000_000, anchors in 0_usize..3) {
        let request = salty_request(PASSCODE, 1, 1);
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request).map_err(fail)?;
        let state = state_of(&artifact, |value| {
            value["s"] = serde_json::json!(format!("{sequence:x}"));
        })?;

        let seals: Vec<Sad> = (0..anchors)
            .map(|index| {
                let mut seal = Sad::new();
                seal.insert("i", format!("seal-{index}")).map(|()| seal)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(fail)?;
        let interaction = interact_identifier(keeper.as_ref(), &state, seals.clone()).map_err(fail)?;
        prop_assert_eq!(interaction.event.kind(), EventKind::Interaction);
        let expected = format!("{:x}", u128::from(sequence) + 1);
        prop_assert_eq!(interaction.event.sad().get_text("s"), Some(expected.as_str()));
        prop_assert_eq!(interaction.event.sad().get_text("p"), state.digest.as_str().into());
        let rendered = SadValue::Array(seals.into_iter().map(SadValue::Map).collect());
        prop_assert_eq!(interaction.event.sad().get("a"), Some(&rendered));
        prop_assert_eq!(signature_count(&interaction.signatures), 1);
    }

    /// A rotation always signs over keys whose digests the state committed to, takes the state's
    /// next threshold as its signing threshold, and becomes delegated exactly when the state
    /// names a delegator.
    #[test]
    fn rotations_follow_the_state(next in 1_usize..4, delegated in any::<bool>()) {
        let request = salty_request(PASSCODE, 1, next);
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request).map_err(fail)?;
        let committed = artifact.event.sad().get("n").cloned();
        let threshold = artifact.event.sad().get_text("nt").map(str::to_owned);
        let state = state_of(&artifact, |value| {
            if delegated {
                value["di"] = serde_json::json!("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C");
            }
        })?;

        let rotation = rotate_identifier(
            keeper.as_mut(),
            &state,
            &RotateIdentifierRequest {
                next_count: next,
                next_threshold: Some(SigningThreshold::numeric(next as u128)),
                ..RotateIdentifierRequest::default()
            },
        )
        .map_err(fail)?;
        let expected_kind = if delegated {
            EventKind::DelegatedRotation
        } else {
            EventKind::Rotation
        };
        prop_assert_eq!(rotation.event.kind(), expected_kind);
        prop_assert_eq!(rotation.event.sad().get_text("s"), Some("1"));
        prop_assert_eq!(
            rotation.event.sad().get_text("kt").map(str::to_owned),
            threshold
        );
        // The rotated-to keys hash to exactly the committed digests.
        let Some(SadValue::Array(keys)) = rotation.event.sad().get("k") else {
            return Err(TestCaseError::fail("the rotation carries no keys"));
        };
        let digests: Vec<SadValue> = keys
            .iter()
            .filter_map(|key| match key {
                SadValue::Text(key) => keri_cesr::crypto::digest::Digest::derive(
                    keri_cesr::crypto::digest::DigestAlgorithm::Blake3_256,
                    key.as_bytes(),
                )
                .qb64()
                .ok()
                .map(SadValue::Text),
                _ => None,
            })
            .collect();
        prop_assert_eq!(committed, Some(SadValue::Array(digests)));
        // A salty keeper's current count never moves from its inception count — Roadmap 4.3's
        // pinned quirk — so the rotation signs with one key even when the event carries more.
        prop_assert_eq!(signature_count(&rotation.signatures), 1);
    }

    /// A refused request never reaches the keeper: the pre-checks run before any key derives.
    #[test]
    fn refused_requests_precede_derivation(threshold in 3_u128..10, current in 1_usize..3) {
        prop_assume!(threshold > current as u128);
        let mut request = salty_request(PASSCODE, current, 1);
        request.signing_threshold = Some(SigningThreshold::numeric(threshold));
        let refused = matches!(request.keeper_request(0), Err(IdentifierError::Event { .. }));
        prop_assert!(refused);
        let outcome = keeper_for(&salty_request(PASSCODE, current, 1))
            .and_then(|mut keeper| incept_identifier(keeper.as_mut(), &request).map_err(fail));
        prop_assert!(outcome.is_err());
    }

    /// The non-transferable conflicts are refused for every non-zero contradiction.
    #[test]
    fn non_transferable_conflicts_are_refused(next in 1_usize..4) {
        let mut request = salty_request(PASSCODE, 1, next);
        request.transferability = KeyTransferability::NonTransferable;
        let refused = matches!(
            request.keeper_request(0),
            Err(IdentifierError::NonTransferableNextKeys { .. })
        );
        prop_assert!(refused);
        let mut request = salty_request(PASSCODE, 1, 0);
        request.transferability = KeyTransferability::NonTransferable;
        request.next_threshold = Some(SigningThreshold::numeric(next as u128));
        let refused = matches!(
            request.keeper_request(0),
            Err(IdentifierError::NonTransferableNextThreshold)
        );
        prop_assert!(refused);
    }
}
