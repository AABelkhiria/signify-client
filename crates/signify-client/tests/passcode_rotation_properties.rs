//! Invariants of the passcode-rotation workflow.
//!
//! Whatever the old passcode sealed the new one opens, and nothing moves until the agent accepts.

use std::error::Error;

use keri_cesr::crypto::cipher::{Decrypter, Encrypter};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keria_types::api::{AcceptedHab, Hab};
use proptest::prelude::*;
use signify_keri::controller::{Controller, ControllerOptions};
use signify_keri::manager::DerivationCost;

const ALPHABET: &str = "[0-9a-zA-Z_-]{21}";

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

fn encryption(passcode: &str) -> Result<(Encrypter, Decrypter), TestCaseError> {
    let build = || -> Result<(Encrypter, Decrypter), Box<dyn Error>> {
        let salt = Salt::from_qb64(&format!("0AA{passcode}"), SecurityTier::Low)?;
        let signer = salt.derive_signer_with_profile(
            "",
            KeyTransferability::NonTransferable,
            DerivationCost::Ephemeral.profile(SecurityTier::Low),
        )?;
        Ok((
            Encrypter::from_verification_key(signer.verifier())?,
            Decrypter::from_signer(&signer),
        ))
    };
    build().map_err(|error| TestCaseError::fail(error.to_string()))
}

fn randy_record(seed: &[u8; 32], encrypter: &Encrypter) -> Result<(AcceptedHab, String), TestCaseError> {
    let build = || -> Result<(AcceptedHab, String), Box<dyn Error>> {
        let signer = Signer::from_seed(seed, KeyTransferability::Transferable)?;
        let public = signer.verifier().qb64()?;
        let sealed = encrypter.encrypt_signer(&signer)?.qb64()?;
        let record: Hab = serde_json::from_value(serde_json::json!({
            "name": "aid",
            "prefix": public,
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
        }))?;
        let Hab::Accepted(record) = record else {
            return Err("the record parsed as pending".into());
        };
        Ok((record, public))
    };
    build().map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #[test]
    fn the_new_passcode_opens_what_the_old_one_sealed(
        first in ALPHABET,
        second in ALPHABET,
        seed in any::<[u8; 32]>()
    ) {
        prop_assume!(first != second);
        let mut controller = ephemeral(&first)?;
        let (old_encrypter, old_decrypter) = encryption(&first)?;
        let (_, new_decrypter) = encryption(&second)?;
        let (record, public) = randy_record(&seed, &old_encrypter)?;

        let rotation = controller
            .rotate_passcode(&second, std::slice::from_ref(&record))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let Some((_, signify_keri::controller::ReEncryptedKeyState::Randy { signing_keys, .. })) =
            rotation.re_encrypted.first()
        else {
            return Err(TestCaseError::fail("the randy record was not re-encrypted"));
        };
        let Some(sealed) = signing_keys.first() else {
            return Err(TestCaseError::fail("no key was re-sealed"));
        };

        let reopened = new_decrypter
            .decrypt_seed(sealed, KeyTransferability::Transferable)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(reopened.verifier().qb64().ok(), Some(public));

        prop_assert!(
            old_decrypter.decrypt_seed(sealed, KeyTransferability::Transferable).is_err(),
            "the old passcode still opens the rotated key"
        );
    }

    #[test]
    fn the_sealed_salt_is_the_passcode_now_in_force(first in ALPHABET, second in ALPHABET) {
        prop_assume!(first != second);
        let mut controller = ephemeral(&first)?;
        let (_, old_decrypter) = encryption(&first)?;
        let (_, new_decrypter) = encryption(&second)?;

        let rotation = controller
            .rotate_passcode(&second, &[])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let opened = new_decrypter
            .decrypt_salt(&rotation.sealed_salt, SecurityTier::Low)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let text = opened
            .expose_qb64()
            .map_err(|error| TestCaseError::fail(error.to_string()))?
            .as_str()
            .to_owned();
        prop_assert_eq!(text, format!("0AA{second}"));
        prop_assert!(
            old_decrypter.decrypt_salt(&rotation.sealed_salt, SecurityTier::Low).is_err(),
            "the old passcode still opens the sealed salt"
        );
    }

    #[test]
    fn planning_alone_moves_nothing(first in ALPHABET, second in ALPHABET) {
        prop_assume!(first != second);
        let controller = ephemeral(&first)?;
        let before_keys = controller.current_keys().to_vec();
        let before_digests = controller.next_digests().to_vec();
        let before_event = controller.current_event().raw().to_vec();

        let planned = controller
            .plan_passcode_rotation(&second, &[])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(planned.artifacts().signatures.len(), 2);

        drop(planned);
        prop_assert_eq!(controller.current_keys(), before_keys.as_slice());
        prop_assert_eq!(controller.next_digests(), before_digests.as_slice());
        prop_assert_eq!(controller.current_event().raw(), before_event.as_slice());
    }

    #[test]
    fn rotating_twice_keeps_the_chain(first in ALPHABET, second in ALPHABET, third in ALPHABET) {
        prop_assume!(first != second && second != third && first != third);
        let mut controller = ephemeral(&first)?;

        let one = controller
            .rotate_passcode(&second, &[])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let two = controller
            .rotate_passcode(&third, &[])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let revealed = |rotation: &keri_protocol::event::KeyEvent| {
            rotation.sad().get("k").and_then(|keys| match keys {
                keri_protocol::serialization::SadValue::Array(keys) => match keys.get(1) {
                    Some(keri_protocol::serialization::SadValue::Text(key)) => Some(key.clone()),
                    _ => None,
                },
                _ => None,
            })
        };
        let committed = |rotation: &keri_protocol::event::KeyEvent| {
            rotation.sad().get("n").and_then(|digests| match digests {
                keri_protocol::serialization::SadValue::Array(digests) => match digests.first() {
                    Some(keri_protocol::serialization::SadValue::Text(digest)) => Some(digest.clone()),
                    _ => None,
                },
                _ => None,
            })
        };

        // Each rotation is the next event, naming the one before it.
        prop_assert_eq!(one.rotation.sad().get_text("s"), Some("1"));
        prop_assert_eq!(two.rotation.sad().get_text("s"), Some("2"));
        prop_assert_eq!(two.rotation.sad().get_text("p"), one.rotation.sad().get_text("d"));

        let Some(key) = revealed(&two.rotation) else {
            return Err(TestCaseError::fail("the second rotation reveals no old key"));
        };
        let digest = keri_cesr::crypto::digest::Digest::derive(
            keri_cesr::crypto::digest::DigestAlgorithm::Blake3_256,
            key.as_bytes(),
        );
        prop_assert_eq!(committed(&one.rotation), digest.qb64().ok());
    }

    #[test]
    fn a_mismatched_identifier_is_always_refused(
        first in ALPHABET,
        second in ALPHABET,
        seed in any::<[u8; 32]>(),
        other in any::<[u8; 32]>()
    ) {
        prop_assume!(first != second && seed != other);
        let mut controller = ephemeral(&first)?;
        let (encrypter, _) = encryption(&first)?;
        let (mut record, _) = randy_record(&seed, &encrypter)?;

        let impostor = Signer::from_seed(&other, KeyTransferability::Transferable)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let claimed = impostor
            .verifier()
            .qb64()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        record.state.signing_keys = vec![claimed];

        prop_assert!(
            controller.rotate_passcode(&second, std::slice::from_ref(&record)).is_err(),
            "an identifier whose stored key is not the one it reports was re-sealed anyway"
        );
    }
}
