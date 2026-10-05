#![no_main]

//! Fuzzes derivation-path construction, passcode parsing, and managed signing.
//!
//! Three boundaries here take input a caller or a stored record chooses: a derivation stem, which
//! comes back from a KERIA identifier record; a passcode, which comes from a person; and the list
//! of public keys a signing request names. The first input byte splits one corpus entry across all
//! of them.
//!
//! The target asserts that nothing panics, that every rejection is one of the expected typed
//! errors, that an accepted path is exactly the concatenation the reference builds, that the
//! empty-stem collapse is reported rather than hidden, and that a manager never signs with a key it
//! does not hold.

use libfuzzer_sys::fuzz_target;
use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use keri_cesr::crypto::verifier::KeyTransferability;
use signify_keri::manager::{
    DerivationPath, InceptionRequest, KeyIndices, KeyManager, MAX_KEYS_PER_SET, MAX_STEM_BYTES, ManagerError,
    RotationKey, SaltyKeyCreator, SignatureForm, Stem,
};

/// Returns whether a rejection is one of the variants this module is allowed to produce.
fn is_expected(error: &ManagerError) -> bool {
    matches!(
        error,
        ManagerError::DerivationPathTooLong { .. }
            | ManagerError::StemTooLong { .. }
            | ManagerError::TooManyKeys { .. }
            | ManagerError::IndexOverflow { .. }
            | ManagerError::UnsupportedAlgorithm { .. }
            | ManagerError::PasscodeTooShort { .. }
            | ManagerError::InvalidPasscode { .. }
            | ManagerError::NoCurrentKeys
            | ManagerError::MissingSalt
            | ManagerError::RandomKeysNeedEncryption
            | ManagerError::SeedDoesNotMatchIdentifier
            | ManagerError::AlreadyIncepted { .. }
            | ManagerError::NotIncepted { .. }
            | ManagerError::Abandoned { .. }
            | ManagerError::MissingPrivateKey { .. }
            | ManagerError::DecryptionUnavailable
            | ManagerError::SaltDecryptionUnavailable
            | ManagerError::NoSigningKeysRequested
            | ManagerError::PlacementCountMismatch { .. }
            | ManagerError::DestinationOccupied { .. }
            | ManagerError::Crypto { .. }
    )
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(body).into_owned();

    // A stem the client or a KERIA record chose.
    match Stem::new(text.clone()) {
        Ok(stem) => {
            assert!(stem.as_str().len() <= MAX_STEM_BYTES);
            let indices = KeyIndices::new(
                u32::from(selector),
                u32::from(selector).wrapping_mul(7),
                u32::from(selector).wrapping_mul(13),
            );
            match DerivationPath::new(&stem, indices) {
                Ok(path) => {
                    // The path is exactly what the reference concatenates, and nothing else.
                    let expected = if stem.is_empty() {
                        format!("{:x}", indices.prefix)
                    } else {
                        format!("{}{:x}{:x}", stem.as_str(), indices.rotation, indices.key)
                    };
                    assert_eq!(path.as_str(), expected);
                    // The collapse that defeats pre-rotation is reported, never silent.
                    assert_eq!(path.reuses_keys_across_rotations(), stem.is_empty());
                    if stem.is_empty() {
                        let elsewhere = DerivationPath::new(&stem, KeyIndices::new(indices.prefix, 0, 0))
                            .expect("an empty stem always builds a path");
                        assert_eq!(path, elsewhere);
                    }
                }
                Err(error) => assert!(is_expected(&error), "unexpected error: {error:?}"),
            }
        }
        Err(error) => {
            assert!(matches!(error, ManagerError::StemTooLong { .. }));
            assert!(text.len() > MAX_STEM_BYTES);
        }
    }

    // A rotation key is built from a prefix a peer supplied.
    let key = RotationKey::new(&text, u32::from(selector));
    assert!(key.as_str().len() >= text.len() + 33);
    assert!(key.as_str().starts_with(&text));

    // A passcode a person typed.
    match KeyManager::from_passcode(&text, None) {
        Ok(manager) => {
            assert!(text.chars().count() >= 21);
            assert!(manager.encryption_identifier().is_some());
        }
        Err(error) => assert!(is_expected(&error), "unexpected error: {error:?}"),
    }

    // A key count a caller chose, bounded before any derivation happens.
    let Ok(salt) = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low) else {
        return;
    };
    let count = usize::from(selector) * 64;
    let creator = SaltyKeyCreator::new(&salt, Stem::empty());
    if count > MAX_KEYS_PER_SET {
        assert!(matches!(
            creator.create(
                count,
                KeyTransferability::Transferable,
                KeyIndices::inception(0),
                KeyDerivationProfile::Temporary,
            ),
            Err(ManagerError::TooManyKeys { .. })
        ));
    }

    // A signing request naming keys the manager may or may not hold.
    let Ok(salt) = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low) else {
        return;
    };
    let Ok(mut manager) = KeyManager::builder().salt(salt).build() else {
        return;
    };
    let Ok(incepted) = manager.incept(InceptionRequest {
        profile: KeyDerivationProfile::Temporary,
        ..InceptionRequest::default()
    }) else {
        return;
    };

    match manager.sign(body, &[text.clone()], &SignatureForm::IndexedByPosition) {
        // The only key this manager holds is the one it incepted, so anything else must fail.
        Ok(_) => assert_eq!(text, incepted.prefix),
        Err(error) => assert!(is_expected(&error), "unexpected error: {error:?}"),
    }

    // An empty request is always refused, whatever the payload.
    assert!(matches!(
        manager.sign(body, &[], &SignatureForm::IndexedByPosition),
        Err(ManagerError::NoSigningKeysRequested)
    ));
});
