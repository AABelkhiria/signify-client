//! Invariants of the controller and agent state.
//!
//! Every case uses the ephemeral derivation cost. The production profile costs 64 MiB per key,
//! which a property test would multiply by its case count; the state machine under test does not
//! depend on the profile, and the cross-language vectors cover the production one exactly.

use keri_cesr::crypto::cipher::{Decrypter, Encrypter};
use keri_cesr::crypto::salt::SecurityTier;
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::event::kind::EventKind;
use keri_protocol::serialization::{SadValue, SerializedEvent};
use keria_types::api::KeyState;
use proptest::prelude::*;
use signify_keys::controller::{Agent, Controller, ControllerOptions};
use signify_keys::manager::DerivationCost;

/// The Base64 URL-safe alphabet a passcode draws from.
const ALPHABET: &str = "[A-Za-z0-9_-]{21}";

fn ephemeral(passcode: &str) -> Result<Controller, TestCaseError> {
    Controller::with_options(
        passcode,
        SecurityTier::Low,
        ControllerOptions {
            derivation_cost: DerivationCost::Ephemeral,
            ..ControllerOptions::default()
        },
    )
    .map_err(|error| TestCaseError::fail(error.to_string()))
}

fn agent_state(sequence_hex: &str, delegator: &str) -> Result<Agent, TestCaseError> {
    let state: KeyState = serde_json::from_value(serde_json::json!({
        "i": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
        "s": sequence_hex,
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
        "di": delegator
    }))
    .map_err(|error| TestCaseError::fail(error.to_string()))?;
    Agent::from_key_state(state).map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn rotations_follow_the_log_after_any_number_of_approvals(
        first in ALPHABET,
        second in ALPHABET,
        approvals in 0_u8..5,
    ) {
        prop_assume!(first != second);
        let mut controller = ephemeral(&first)?;
        let delegator = controller
            .prefix()
            .qb64()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        for _ in 0..approvals {
            controller
                .approve_delegation(&agent_state("0", &delegator)?)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
        }
        let before = controller.current_said();

        let rotation = controller
            .rotate_passcode(&second, &[])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let expected = format!("{:x}", u128::from(approvals) + 1);
        let prior = before.qb64().map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(rotation.rotation.sad().get_text("s"), Some(expected.as_str()));
        prop_assert_eq!(rotation.rotation.sad().get_text("p"), Some(prior.as_str()));
        prop_assert_eq!(controller.current_sequence_number(), u128::from(approvals) + 1);
        prop_assert_eq!(controller.current_event().raw(), rotation.rotation.raw());
    }
}

proptest! {
    /// The same passcode always derives the same controller, and different passcodes different
    /// ones — the pinned unit test's own property, over arbitrary passcodes.
    #[test]
    fn controllers_are_deterministic_and_distinct(first in ALPHABET, second in ALPHABET) {
        let left = ephemeral(&first)?;
        let again = ephemeral(&first)?;
        prop_assert_eq!(left.current_event().raw(), again.current_event().raw());
        prop_assert_eq!(left.current_keys(), again.current_keys());
        if first != second {
            let right = ephemeral(&second)?;
            prop_assert_ne!(
                left.prefix().qb64().ok(),
                right.prefix().qb64().ok()
            );
        }
    }

    /// The inception is self-consistent: one key, one digest, both thresholds one, sequence
    /// zero, a self-addressing prefix, and bytes that reparse to the same field map.
    #[test]
    fn every_inception_is_self_consistent(passcode in ALPHABET) {
        let controller = ephemeral(&passcode)?;
        let event = controller.current_event();
        let sad = event.sad();
        prop_assert_eq!(sad.get_text("t"), Some(EventKind::Inception.as_str()));
        prop_assert_eq!(sad.get_text("kt"), Some("1"));
        prop_assert_eq!(sad.get_text("nt"), Some("1"));
        prop_assert_eq!(sad.get_text("bt"), Some("0"));
        prop_assert_eq!(controller.current_sequence_number(), 0);
        prop_assert!(controller.prefix().is_digestive());
        prop_assert_eq!(
            controller.current_said().qb64().ok(),
            controller.prefix().qb64().ok()
        );
        let reparsed = SerializedEvent::parse(event.raw())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(reparsed.sad(), event.sad());
        // The event's key is the signer's own verifier.
        prop_assert_eq!(
            controller.current_keys().first().cloned(),
            controller.expose_signer().verifier().qb64().ok()
        );
    }

    /// Consecutive rotation indices chain: index n's committed next key is index n+1's current
    /// key.
    #[test]
    fn rotation_indices_chain_the_key_sequence(passcode in ALPHABET, index in 0_u32..8) {
        let options = |rotation_index| ControllerOptions {
            rotation_index,
            derivation_cost: DerivationCost::Ephemeral,
        };
        let current = Controller::with_options(&passcode, SecurityTier::Low, options(index))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let next = Controller::with_options(&passcode, SecurityTier::Low, options(index + 1))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let committed = current.next_digests().first().cloned();
        let arrived = next.current_keys().first().cloned().unwrap_or_default();
        let digest = keri_cesr::crypto::digest::Digest::derive(
            keri_cesr::crypto::digest::DigestAlgorithm::Blake3_256,
            arrived.as_bytes(),
        );
        prop_assert_eq!(committed, digest.qb64().ok());
    }

    /// Approving a delegation advances the log by exactly one, anchors the agent's coordinates,
    /// and signs the new event with the controller key; repeated approvals keep chaining.
    #[test]
    fn approvals_chain_interactions(passcode in ALPHABET, sn in 0_u128..1_000_000, repeats in 1_usize..4) {
        let mut controller = ephemeral(&passcode)?;
        let agent = agent_state(&format!("{sn:x}"), "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose")?;
        let mut prior = controller.current_said();
        for round in 1..=repeats {
            let signature = controller
                .approve_delegation(&agent)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let sad = controller.current_event().sad();
            prop_assert_eq!(sad.get_text("t"), Some(EventKind::Interaction.as_str()));
            prop_assert_eq!(controller.current_sequence_number(), round as u128);
            let prior_qb64 = prior.qb64().ok();
            prop_assert_eq!(sad.get_text("p"), prior_qb64.as_deref());
            let Some(SadValue::Array(anchors)) = sad.get("a") else {
                return Err(TestCaseError::fail("the interaction carries no anchors"));
            };
            let Some(SadValue::Map(anchor)) = anchors.first() else {
                return Err(TestCaseError::fail("the anchor is not a field map"));
            };
            let sequence_hex = format!("{sn:x}");
            prop_assert_eq!(anchor.get_text("s"), Some(sequence_hex.as_str()));
            prop_assert!(
                controller
                    .expose_signer()
                    .verifier()
                    .verify(signature.raw(), controller.current_event().raw())
                    .is_ok()
            );
            prior = controller.current_said();
        }
    }

    /// A passcode rotation always produces the same shape: a sequence-one rotation whose second
    /// key is the previously committed one, two verifying signatures, and a sealed salt the
    /// prior passcode's key opens to the stored salt.
    #[test]
    fn passcode_rotation_is_self_consistent(first in ALPHABET, second in ALPHABET) {
        prop_assume!(first != second);
        let mut controller = ephemeral(&first)?;
        let committed = controller.next_digests().first().cloned();
        let old_salt = controller
            .salt()
            .expose_qb64()
            .map_err(|error| TestCaseError::fail(error.to_string()))?
            .as_str()
            .to_owned();
        let prior_signer = controller
            .salt()
            .derive_signer_with_profile(
                "",
                KeyTransferability::NonTransferable,
                DerivationCost::Ephemeral.profile(SecurityTier::Low),
            )
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let rotation = controller
            .rotate_passcode(&second, &[])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let sad = rotation.rotation.sad();
        // A fresh controller is at its inception, so its first rotation is sequence one.
        prop_assert_eq!(sad.get_text("s"), Some("1"));
        let Some(SadValue::Array(keys)) = sad.get("k") else {
            return Err(TestCaseError::fail("the rotation carries no keys"));
        };
        prop_assert_eq!(keys.len(), 2);
        let Some(SadValue::Text(old_key)) = keys.get(1) else {
            return Err(TestCaseError::fail("the second key is not text"));
        };
        let digest = keri_cesr::crypto::digest::Digest::derive(
            keri_cesr::crypto::digest::DigestAlgorithm::Blake3_256,
            old_key.as_bytes(),
        );
        prop_assert_eq!(committed, digest.qb64().ok());
        prop_assert_eq!(rotation.signatures.len(), 2);
        for signature in &rotation.signatures {
            let position = usize::try_from(signature.index())
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let Some(SadValue::Text(key)) = keys.get(position) else {
                return Err(TestCaseError::fail("a signature indexes a missing key"));
            };
            let verifier = keri_cesr::crypto::verifier::VerificationKey::from_qb64(key)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert!(verifier.verify(signature.raw(), rotation.rotation.raw()).is_ok());
        }

        // The sealed salt opens under the NEW key to the NEW salt, as keripy does — so rotating
        // the passcode rotates the encryption. The reference seals the old salt under the old key,
        // producing a payload the new passcode cannot open at all.
        let new_salt = controller
            .salt()
            .expose_qb64()
            .map_err(|error| TestCaseError::fail(error.to_string()))?
            .as_str()
            .to_owned();
        prop_assert_ne!(&new_salt, &old_salt, "the controller's salt did not move");

        let new_signer = controller
            .salt()
            .derive_signer_with_profile(
                "",
                KeyTransferability::NonTransferable,
                DerivationCost::Ephemeral.profile(SecurityTier::Low),
            )
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let opened = Decrypter::from_signer(&new_signer)
            .decrypt_salt(&rotation.sealed_salt, SecurityTier::Low)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(
            opened.expose_qb64().map(|qb64| qb64.as_str().to_owned()).ok(),
            Some(new_salt)
        );

        // And the passcode being left behind no longer opens it.
        prop_assert!(
            Decrypter::from_signer(&prior_signer)
                .decrypt_salt(&rotation.sealed_salt, SecurityTier::Low)
                .is_err(),
            "the old passcode still opens the rotated payload"
        );
        prop_assert_eq!(controller.current_keys().len(), 2);
        // The rotation became the current event; the reference leaves it at zero.
        prop_assert_eq!(controller.current_sequence_number(), 1);
        prop_assert_eq!(controller.current_event().raw(), rotation.rotation.raw());
    }

    /// Sealed material round-trips through a rotation: whatever the prior key sealed, the **new**
    /// key opens afterwards, unchanged — and the prior key no longer does.
    #[test]
    fn re_encryption_preserves_what_it_seals(first in ALPHABET, second in ALPHABET, seed in any::<[u8; 32]>()) {
        prop_assume!(first != second);
        let mut controller = ephemeral(&first)?;
        let prior_signer = controller
            .salt()
            .derive_signer_with_profile(
                "",
                KeyTransferability::NonTransferable,
                DerivationCost::Ephemeral.profile(SecurityTier::Low),
            )
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let encrypter = Encrypter::from_verification_key(prior_signer.verifier())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let decrypter = Decrypter::from_signer(&prior_signer);

        let signer = keri_cesr::crypto::signer::Signer::from_seed(&seed, KeyTransferability::Transferable)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let public = signer
            .verifier()
            .qb64()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let sealed = encrypter
            .encrypt_signer(&signer)
            .map_err(|error| TestCaseError::fail(error.to_string()))?
            .qb64()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let record: keria_types::api::Hab = serde_json::from_value(serde_json::json!({
            "name": "aid",
            "prefix": public.clone(),
            "icp_dt": "2023-12-01T10:05:25.062609+00:00",
            "randy": { "prxs": [sealed], "nxts": [] },
            "state": {
                "i": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
                "s": "0", "p": "", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
                "f": "0", "dt": "2023-12-01T10:05:25.062609+00:00", "et": "icp",
                "kt": "1", "k": [public.clone()], "nt": "1",
                "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
                "bt": "0", "b": [], "c": [],
                "ee": {"s": "0", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", "br": [], "ba": []},
                "di": ""
            }
        }))
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let keria_types::api::Hab::Accepted(record) = record else {
            return Err(TestCaseError::fail("the record parsed as pending"));
        };

        let rotation = controller
            .rotate_passcode(&second, std::slice::from_ref(&record))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let Some((_, signify_keys::controller::ReEncryptedKeyState::Randy { signing_keys, .. })) =
            rotation.re_encrypted.first()
        else {
            return Err(TestCaseError::fail("the randy record was not re-encrypted"));
        };
        let Some(resealed) = signing_keys.first() else {
            return Err(TestCaseError::fail("no key was re-sealed"));
        };
        // The new passcode opens what the old one sealed, and the material is unchanged.
        let new_signer = controller
            .salt()
            .derive_signer_with_profile(
                "",
                KeyTransferability::NonTransferable,
                DerivationCost::Ephemeral.profile(SecurityTier::Low),
            )
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let reopened = Decrypter::from_signer(&new_signer)
            .decrypt_seed(resealed, KeyTransferability::Transferable)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(reopened.verifier().qb64().ok(), Some(public));

        // And the old one does not, which is what makes this a rotation rather than a copy.
        prop_assert!(
            decrypter
                .decrypt_seed(resealed, KeyTransferability::Transferable)
                .is_err(),
            "a re-sealed key still opens under the old passcode"
        );
    }

    /// An agent's parsed coordinates always agree with the state it was built from.
    #[test]
    fn agent_parsing_is_faithful(sn in 0_u64..1_000_000) {
        let hex = format!("{sn:x}");
        let agent = agent_state(&hex, "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose")?;
        prop_assert_eq!(agent.sequence_number(), u128::from(sn));
        prop_assert_eq!(agent.state().sequence_number.as_str(), hex.as_str());
        let anchor_qb64 = agent.anchor().qb64().ok();
        prop_assert_eq!(anchor_qb64.as_deref(), agent.state().delegator());
    }
}
