#![no_main]

//! Fuzzes passcode rotation over hostile passcodes and identifier records.
//!
//! A rotation moves secrets between two locks, and everything about it is decided by two inputs a
//! caller supplies: the new passcode, and the records whose material is being moved. The property
//! that has to hold for every pair is the one the reference gets backwards — **what the old
//! passcode sealed, the new passcode opens, and the old one no longer does**.
//!
//! The target asserts that nothing panics for any passcode pair, that a successful rotation always
//! produces material only the new passcode opens, that the material itself is unchanged, that a
//! record whose stored key is not the key it reports is always refused, and that a rotation which
//! is planned but not applied leaves the controller untouched — which is what lets a client decline
//! a rotation its agent rejected.

use libfuzzer_sys::fuzz_target;
use signify_crypto::cipher::{Decrypter, Encrypter};
use signify_crypto::salt::{Salt, SecurityTier};
use signify_crypto::signer::Signer;
use signify_crypto::verifier::KeyTransferability;
use signify_keri::controller::{Controller, ControllerOptions, ReEncryptedKeyState};
use signify_keri::manager::DerivationCost;
use signify_types::api::{AcceptedHab, Hab};

/// A passcode is exactly twenty-one characters of the reference's own alphabet.
fn passcode(bytes: &[u8]) -> Option<String> {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    if bytes.is_empty() {
        return None;
    }
    let text: String = (0..21)
        .map(|index| {
            let byte = bytes.get(index % bytes.len()).copied().unwrap_or(0);
            char::from(ALPHABET[usize::from(byte) % ALPHABET.len()])
        })
        .collect();
    Some(text)
}

fn controller(text: &str) -> Option<Controller> {
    Controller::with_options(
        text,
        SecurityTier::Low,
        ControllerOptions {
            derivation_cost: DerivationCost::Ephemeral,
            ..ControllerOptions::default()
        },
    )
    .ok()
}

/// The encryption key one passcode derives, at the same cost the controller uses.
fn encryption(text: &str) -> Option<(Encrypter, Decrypter)> {
    let salt = Salt::from_qb64(&format!("0AA{text}"), SecurityTier::Low).ok()?;
    let signer = salt
        .derive_signer_with_profile(
            "",
            KeyTransferability::NonTransferable,
            DerivationCost::Ephemeral.profile(SecurityTier::Low),
        )
        .ok()?;
    Some((
        Encrypter::from_verification_key(signer.verifier()).ok()?,
        Decrypter::from_signer(&signer),
    ))
}

/// One randy identifier holding `seed`, reporting `claimed` as its signing key.
fn record(seed: &[u8; 32], claimed: Option<&str>, encrypter: &Encrypter) -> Option<(AcceptedHab, String)> {
    let signer = Signer::from_seed(seed, KeyTransferability::Transferable).ok()?;
    let public = signer.verifier().qb64().ok()?;
    let sealed = encrypter.encrypt_signer(&signer).ok()?.qb64().ok()?;
    let reported = claimed.unwrap_or(&public).to_owned();
    let record: Hab = serde_json::from_value(serde_json::json!({
        "name": "aid",
        "prefix": public,
        "icp_dt": "2023-12-01T10:05:25.062609+00:00",
        "randy": { "prxs": [sealed], "nxts": [] },
        "state": {
            "i": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
            "s": "0", "p": "", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
            "f": "0", "dt": "2023-12-01T10:05:25.062609+00:00", "et": "icp",
            "kt": "1", "k": [reported], "nt": "1",
            "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
            "bt": "0", "b": [], "c": [],
            "ee": {"s": "0", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", "br": [], "ba": []},
            "di": ""
        }
    }))
    .ok()?;
    match record {
        Hab::Accepted(record) => Some((record, public)),
        Hab::Pending(_) => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let Some(first) = passcode(parts.next().unwrap_or_default()) else {
        return;
    };
    let Some(second) = passcode(parts.next().unwrap_or_default()) else {
        return;
    };
    let mut seed = [0_u8; 32];
    for (slot, byte) in seed.iter_mut().zip(parts.next().unwrap_or_default()) {
        *slot = *byte;
    }
    let mismatch = parts.next().is_some_and(|flag| flag.first().is_some_and(|byte| byte % 2 == 0));

    let Some(mut controller) = controller(&first) else {
        return;
    };
    let Some((old_encrypter, old_decrypter)) = encryption(&first) else {
        return;
    };

    // -----------------------------------------------------------------------
    // A record whose stored key is not the key it reports is always refused.
    // -----------------------------------------------------------------------
    if mismatch {
        let claimed = "DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE";
        if let Some((record, public)) = record(&seed, Some(claimed), &old_encrypter)
            && public != claimed
        {
            assert!(
                controller
                    .rotate_passcode(&second, std::slice::from_ref(&record))
                    .is_err(),
                "an identifier whose stored key is not the one it reports was re-sealed"
            );
        }
        return;
    }

    let Some((record, public)) = record(&seed, None, &old_encrypter) else {
        return;
    };

    // -----------------------------------------------------------------------
    // Planning alone moves nothing.
    // -----------------------------------------------------------------------
    let before_keys = controller.current_keys().to_vec();
    if let Ok(planned) = controller.plan_passcode_rotation(&second, std::slice::from_ref(&record)) {
        assert_eq!(planned.artifacts().signatures.len(), 2);
        drop(planned);
        assert_eq!(
            controller.current_keys(),
            before_keys.as_slice(),
            "planning a rotation moved the controller"
        );
    }

    // -----------------------------------------------------------------------
    // And a rotation that happens moves the lock, not the material.
    // -----------------------------------------------------------------------
    let Ok(rotation) = controller.rotate_passcode(&second, std::slice::from_ref(&record)) else {
        return;
    };
    let Some((_, new_decrypter)) = encryption(&second) else {
        return;
    };

    // The controller's own salt is the new one, under the new key.
    if let Ok(opened) = new_decrypter.decrypt_salt(&rotation.sealed_salt, SecurityTier::Low)
        && let Ok(text) = opened.expose_qb64()
    {
        assert_eq!(text.as_str(), format!("0AA{second}"), "the sealed salt is not the new one");
    }
    if first != second {
        assert!(
            old_decrypter
                .decrypt_salt(&rotation.sealed_salt, SecurityTier::Low)
                .is_err(),
            "the old passcode still opens the sealed salt"
        );
    }

    // And the identifier's private key survives unchanged, readable only by the new passcode.
    if let Some((_, ReEncryptedKeyState::Randy { signing_keys, .. })) = rotation.re_encrypted.first()
        && let Some(sealed) = signing_keys.first()
    {
        let reopened = new_decrypter.decrypt_seed(sealed, KeyTransferability::Transferable);
        assert!(reopened.is_ok(), "the new passcode cannot open the rotated key");
        if let Ok(signer) = reopened {
            assert_eq!(
                signer.verifier().qb64().ok(),
                Some(public),
                "the rotated key is not the key that was stored"
            );
        }
        if first != second {
            assert!(
                old_decrypter
                    .decrypt_seed(sealed, KeyTransferability::Transferable)
                    .is_err(),
                "the old passcode still opens the rotated key"
            );
        }
    }
});
