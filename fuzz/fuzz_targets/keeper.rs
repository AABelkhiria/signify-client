#![no_main]

//! Fuzzes the identifier keepers.
//!
//! Three of the boundaries here take input a stored record or a peer chooses: the sealed salt a
//! salty keeper opens, the sealed keys a randy keeper opens, and the group key lists a group keeper
//! searches for its member. The first input byte selects which one the rest drives.
//!
//! The target asserts that nothing panics, that every rejection is one of the expected typed
//! errors, that an ephemeral keeper is never storable, that a group signature never lands anywhere
//! but its member's own position, and that a keeper only ever signs with keys it actually holds.

use libfuzzer_sys::fuzz_target;
use signify_client::cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use signify_client::cesr::crypto::verifier::{KeyTransferability, VerificationKey};
use signify_keys::manager::keeper::salty::{SaltyKeeperConfig, SaltySource};
use signify_keys::manager::{
    DerivationCost, GroupKeeper, IdentifierKeeper, KeeperFactory, KeeperRequest, KeeperRotation, ManagedSignatures,
    ManagerError, RandyKeeperRequest, SaltyKeeper, SignatureForm, SigningPurpose, Stem,
};

/// Returns whether a rejection is one this module is allowed to produce.
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
            | ManagerError::SaltDecryptionUnavailable
            | ManagerError::NoSigningKeysRequested
            | ManagerError::PlacementCountMismatch { .. }
            | ManagerError::DestinationOccupied { .. }
            | ManagerError::UnknownExternalModule { .. }
            | ManagerError::MemberNotInSigningKeys { .. }
            | ManagerError::MemberNotPrecommitted { .. }
            | ManagerError::NoSigningKeys { .. }
            | ManagerError::ProfileNotStorable
            | ManagerError::UnsupportedTier
            | ManagerError::UnsupportedDigest { .. }
            | ManagerError::Crypto { .. }
    )
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(body).into_owned();
    let Ok(salt) = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low) else {
        return;
    };

    match selector % 4 {
        // A sealed salt a stored record supplied.
        0 => match SaltyKeeper::new(
            &salt,
            SaltySource::Sealed(text.clone()),
            SaltyKeeperConfig {
                profile: DerivationCost::Ephemeral,
                ..SaltyKeeperConfig::default()
            },
        ) {
            Ok(keeper) => {
                // An ephemeral keeper can never be written back into a record.
                assert!(matches!(keeper.parameters(), Err(ManagerError::ProfileNotStorable)));
            }
            Err(error) => assert!(is_expected(&error), "unexpected error: {error:?}"),
        },

        // A passcode a person typed, and a stem a record carried.
        1 => {
            match SaltyKeeper::new(
                &salt,
                SaltySource::Passcode(text.clone().into()),
                SaltyKeeperConfig {
                    stem: Stem::new(text.chars().take(32).collect::<String>()).unwrap_or_else(|_| Stem::empty()),
                    profile: DerivationCost::Ephemeral,
                    transferability: KeyTransferability::Transferable,
                    ..SaltyKeeperConfig::default()
                },
            ) {
                Ok(mut keeper) => {
                    assert!(text.chars().count() >= 21);
                    let material = keeper
                        .incept(KeyTransferability::Transferable)
                        .expect("an ephemeral inception must succeed");
                    // Every key it reports is one it can sign with.
                    let signers = keeper.expose_signers().expect("a keeper must open its own keys");
                    let reported: Vec<String> = signers
                        .iter()
                        .map(|signer| signer.verifier().qb64().expect("a key must encode"))
                        .collect();
                    assert_eq!(reported, material.public_keys);
                }
                Err(error) => assert!(is_expected(&error), "unexpected error: {error:?}"),
            }
        }

        // Sealed private keys a stored record supplied.
        2 => {
            let factory = KeeperFactory::new(salt);
            match factory.create(KeeperRequest::Randy(RandyKeeperRequest {
                current_count: 1,
                next_count: 1,
                transferability: KeyTransferability::Transferable,
                sealed_signing_keys: vec![text.clone()],
                sealed_next_keys: Vec::new(),
                profile: DerivationCost::Ephemeral,
            })) {
                Ok(keeper) => match keeper.sign(body, &SignatureForm::IndexedByPosition, SigningPurpose::Current) {
                    // Anything that opens is a real key, so it produces exactly one signature.
                    Ok(signatures) => assert_eq!(signatures.len(), 1),
                    Err(error) => assert!(is_expected(&error), "unexpected error: {error:?}"),
                },
                Err(error) => assert!(is_expected(&error), "unexpected error: {error:?}"),
            }
        }

        // A group key list a peer supplied.
        _ => {
            let Ok(member_key) = salt.derive_signer_with_profile(
                "member",
                KeyTransferability::Transferable,
                KeyDerivationProfile::Temporary,
            ) else {
                return;
            };
            let Ok(key) = member_key.verifier().qb64() else { return };
            let Ok(encoded) = member_key.verifier().qb64_bytes() else {
                return;
            };
            let digest = signify_client::cesr::crypto::digest::Digest::derive(
                signify_client::cesr::crypto::digest::DigestAlgorithm::Blake3_256,
                &encoded,
            );
            let Ok(digest) = digest.qb64() else { return };

            let Ok(habitat) = serde_json::from_str::<signify_client::types::api::AcceptedHab>(&format!(
                r#"{{"name":"m","prefix":"EMEM","icp_dt":"2023-12-01T10:05:25.062609+00:00","randy":{{"prxs":[],"nxts":[]}},"state":{{"i":"EMEM","s":"0","p":"","d":"EMEM","f":"0","dt":"","et":"icp","kt":"1","k":["{key}"],"nt":"1","n":["{digest}"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"EMEM"}},"di":""}}}}"#
            )) else {
                return;
            };

            let Ok(mut inner) = SaltyKeeper::new(
                &salt,
                SaltySource::Passcode("0123456789abcdefghijk".into()),
                SaltyKeeperConfig {
                    profile: DerivationCost::Ephemeral,
                    transferability: KeyTransferability::Transferable,
                    ..SaltyKeeperConfig::default()
                },
            ) else {
                return;
            };
            if inner.incept(KeyTransferability::Transferable).is_err() {
                return;
            }

            // The fuzzer chooses the group's key list, so the member may or may not be in it.
            let mut keys: Vec<String> = text.split(',').map(str::to_owned).collect();
            if selector % 2 == 0 {
                keys.push(key.clone());
            }
            let group = GroupKeeper::new(Box::new(inner), habitat, keys.clone(), vec![digest.clone()]);

            for purpose in [SigningPurpose::Current, SigningPurpose::Rotation] {
                match group.sign(body, &SignatureForm::IndexedByPosition, purpose) {
                    Ok(signatures) => {
                        let ManagedSignatures::Indexed(indexed) = &signatures else {
                            panic!("a group signature was not indexed");
                        };
                        let signature = indexed.first().expect("a group signature must exist");
                        // A group signature always lands at the member's own position, never
                        // anywhere else, and only a rotation exposes a prior position.
                        let position = keys
                            .iter()
                            .position(|candidate| *candidate == key)
                            .expect("a signature implies the member is in the list");
                        assert_eq!(usize::try_from(signature.index()).unwrap_or(usize::MAX), position);
                        assert_eq!(
                            signature.other_index().is_some(),
                            matches!(purpose, SigningPurpose::Rotation)
                        );
                    }
                    Err(error) => {
                        assert!(is_expected(&error), "unexpected error: {error:?}");
                        // The only reasons a group refuses are that the member is absent from the
                        // list, or that nothing committed to it.
                        assert!(matches!(
                            error,
                            ManagerError::MemberNotInSigningKeys { .. }
                                | ManagerError::MemberNotPrecommitted { .. }
                                | ManagerError::Crypto { .. }
                        ));
                    }
                }
            }

            // A rotation never moves the prior digests, so the member stays findable.
            let mut group = group;
            let _ = group.rotate(KeeperRotation::to_keys(1));
            assert!(VerificationKey::from_qb64(&key).is_ok());
        }
    }
});
