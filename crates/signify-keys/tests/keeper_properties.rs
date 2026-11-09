//! Invariants of the identifier keepers.
//!
//! Every salty case uses the ephemeral derivation profile. The production profile costs 64 MiB and
//! two Argon2 passes per key, which a property test would multiply by its case count; the path
//! arithmetic and the state machine under test do not depend on the profile, and the
//! cross-language vectors cover the production one exactly.

use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use keri_cesr::crypto::signer::SignaturePlacement;
use keri_cesr::crypto::verifier::{KeyTransferability, VerificationKey};
use keria_types::api::KeyManagerState;
use proptest::prelude::*;
use signify_keys::manager::keeper::salty::{SaltyKeeperConfig, SaltySource};
use signify_keys::manager::{
    DerivationCost, GroupKeeper, IdentifierKeeper, KeeperFactory, KeeperRequest, KeeperRotation, KeyAlgorithm,
    ManagedSignatures, ManagerError, RandyKeeperRequest, SaltyKeeper, SignatureForm, SigningPurpose, Stem,
};

fn salt() -> Result<Salt, ManagerError> {
    Ok(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?)
}

/// A cheap salty keeper; anything built this way is ephemeral and cannot be stored.
fn salty(config: SaltyKeeperConfig) -> Result<SaltyKeeper, ManagerError> {
    SaltyKeeper::new(
        &salt()?,
        SaltySource::Passcode("0123456789abcdefghijk".into()),
        SaltyKeeperConfig {
            profile: DerivationCost::Ephemeral,
            ..config
        },
    )
}

fn transferability(transferable: bool) -> KeyTransferability {
    if transferable {
        KeyTransferability::Transferable
    } else {
        KeyTransferability::NonTransferable
    }
}

proptest! {
    /// A salty keeper derives the same keys from the same inputs, every time.
    #[test]
    fn salty_derivation_is_deterministic(
        stem in "[a-z:]{0,12}",
        count in 1_usize..4,
        next_count in 0_usize..4,
        transferable in any::<bool>(),
        prefix_index in 0_u32..16,
    ) {
        let config = SaltyKeeperConfig {
            prefix_index,
            transferability: transferability(transferable),
            stem: Stem::new(stem)?,
            current_count: count,
            next_count,
            ..SaltyKeeperConfig::default()
        };
        let mut first = salty(config.clone())?;
        let mut second = salty(config)?;

        let left = first.incept(transferability(transferable))?;
        let right = second.incept(transferability(transferable))?;
        prop_assert_eq!(&left, &right);
        prop_assert_eq!(left.public_keys.len(), count);
        prop_assert_eq!(left.next_digests.len(), next_count);

        // Transferability shows in every derived key's code, and nowhere else.
        let expected = if transferable { 'D' } else { 'B' };
        for key in &left.public_keys {
            prop_assert_eq!(key.chars().next(), Some(expected));
        }
    }

    /// Inception always resets the key index, and each rotation advances it by one key set.
    #[test]
    fn the_key_index_advances_one_set_at_a_time(
        count in 1_usize..4,
        rounds in 1_usize..4,
        start in 0_u32..8,
    ) {
        let mut keeper = salty(SaltyKeeperConfig {
            key_index: start,
            transferability: KeyTransferability::Transferable,
            current_count: count,
            next_count: count,
            ..SaltyKeeperConfig::default()
        })?;

        keeper.incept(KeyTransferability::Transferable)?;
        prop_assert_eq!(keeper.key_index(), 0, "inception did not reset the key index");

        for round in 1..=rounds {
            keeper.rotate(KeeperRotation::to_keys(count))?;
            let expected = u32::try_from(round * count).unwrap_or(u32::MAX);
            prop_assert_eq!(keeper.key_index(), expected);
        }
    }

    /// What a keeper commits to is exactly what its next rotation signs with, round after round.
    #[test]
    fn a_rotation_signs_with_the_keys_it_committed_to(count in 1_usize..3, rounds in 1_usize..4) {
        let mut keeper = salty(SaltyKeeperConfig {
            transferability: KeyTransferability::Transferable,
            current_count: count,
            next_count: count,
            ..SaltyKeeperConfig::default()
        })?;

        let mut committed = keeper.incept(KeyTransferability::Transferable)?.next_digests;
        for _ in 0..rounds {
            let rotated = keeper.rotate(KeeperRotation::to_keys(count))?;
            let recomputed: Vec<String> = rotated
                .public_keys
                .iter()
                .map(|key| {
                    let verifier = VerificationKey::from_qb64(key)?;
                    let digest = keri_cesr::crypto::digest::Digest::derive(
                        keri_cesr::crypto::digest::DigestAlgorithm::Blake3_256,
                        &verifier.qb64_bytes()?,
                    );
                    digest.qb64()
                })
                .collect::<Result<_, _>>()
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(&committed, &recomputed);
            committed = rotated.next_digests;
        }
    }

    /// Every signature a keeper produces verifies against the key it reported.
    #[test]
    fn every_keeper_signature_verifies(
        count in 1_usize..3,
        payload in prop::collection::vec(any::<u8>(), 0..48),
    ) {
        let mut keeper = salty(SaltyKeeperConfig {
            transferability: KeyTransferability::Transferable,
            current_count: count,
            next_count: 1,
            ..SaltyKeeperConfig::default()
        })?;
        let material = keeper.incept(KeyTransferability::Transferable)?;

        for form in [SignatureForm::IndexedByPosition, SignatureForm::Unindexed] {
            let signatures = keeper.sign(&payload, &form, SigningPurpose::Current)?;
            prop_assert_eq!(signatures.len(), count);
            let raw: Vec<Vec<u8>> = match &signatures {
                ManagedSignatures::Indexed(indexed) => indexed.iter().map(|s| s.raw().to_vec()).collect(),
                ManagedSignatures::Unindexed(plain) => plain.iter().map(|s| s.raw().to_vec()).collect(),
            };
            for (position, signature) in raw.iter().enumerate() {
                let key = material
                    .public_keys
                    .get(position)
                    .ok_or_else(|| TestCaseError::fail("a signature has no key"))?;
                let verifier = VerificationKey::from_qb64(key)
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                prop_assert!(verifier.verify(signature, &payload).is_ok());
            }
        }
    }

    /// The purpose never changes what a non-group keeper does.
    #[test]
    fn the_purpose_is_a_group_concern(payload in prop::collection::vec(any::<u8>(), 0..32)) {
        let mut keeper = salty(SaltyKeeperConfig {
            transferability: KeyTransferability::Transferable,
            ..SaltyKeeperConfig::default()
        })?;
        keeper.incept(KeyTransferability::Transferable)?;

        let current = keeper.sign(&payload, &SignatureForm::IndexedByPosition, SigningPurpose::Current)?;
        let rotation = keeper.sign(&payload, &SignatureForm::IndexedByPosition, SigningPurpose::Rotation)?;
        prop_assert_eq!(current.qb64()?, rotation.qb64()?);
    }

    /// A randy keeper stores every key it holds and can always open them again.
    #[test]
    fn random_keys_survive_their_own_storage(count in 1_usize..3, next_count in 0_usize..3) {
        let factory = KeeperFactory::new(salt()?);
        let mut keeper = factory.create(KeeperRequest::Randy(RandyKeeperRequest {
            current_count: count,
            next_count,
            transferability: KeyTransferability::Transferable,
            profile: DerivationCost::Ephemeral,
            ..RandyKeeperRequest::default()
        }))?;

        let material = keeper.incept(KeyTransferability::Transferable)?;
        prop_assert_eq!(material.public_keys.len(), count);
        prop_assert_eq!(material.next_digests.len(), next_count);

        let KeyManagerState::Randy(state) = keeper.parameters()? else {
            return Err(TestCaseError::fail("a randy keeper reported another state"));
        };
        prop_assert_eq!(state.encrypted_signing_keys.len(), count);
        prop_assert_eq!(state.encrypted_next_keys.len(), next_count);

        // Reloading the stored record recovers the same keys.
        let reloaded = factory.create(KeeperRequest::Randy(RandyKeeperRequest {
            current_count: count,
            next_count,
            transferability: KeyTransferability::Transferable,
            sealed_signing_keys: state.encrypted_signing_keys,
            sealed_next_keys: state.encrypted_next_keys,
            profile: DerivationCost::Ephemeral,
        }))?;
        let recovered: Vec<String> = reloaded
            .expose_signers()?
            .iter()
            .map(|signer| signer.verifier().qb64())
            .collect::<Result<_, _>>()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(recovered, material.public_keys);
    }

    /// A group signature always lands at the member's position, and exposes a prior position only
    /// for a rotation.
    #[test]
    fn a_group_signature_lands_at_the_member_position(
        member in 0_usize..3,
        rotation in any::<bool>(),
    ) {
        let salt = salt()?;
        let mut keys = Vec::new();
        for index in 0..3 {
            let signer = salt.derive_signer_with_profile(
                &format!("member-{index}"),
                KeyTransferability::Transferable,
                KeyDerivationProfile::Temporary,
            )?;
            keys.push(
                signer
                    .verifier()
                    .qb64()
                    .map_err(|error| TestCaseError::fail(error.to_string()))?,
            );
        }
        let digests: Vec<String> = keys
            .iter()
            .map(|key| {
                let verifier = VerificationKey::from_qb64(key)?;
                keri_cesr::crypto::digest::Digest::derive(
                    keri_cesr::crypto::digest::DigestAlgorithm::Blake3_256,
                    &verifier.qb64_bytes()?,
                )
                .qb64()
            })
            .collect::<Result<_, _>>()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let key = keys.get(member).ok_or_else(|| TestCaseError::fail("no member key"))?;
        let digest = digests.get(member).ok_or_else(|| TestCaseError::fail("no member digest"))?;
        let mut inner = salty(SaltyKeeperConfig {
            transferability: KeyTransferability::Transferable,
            ..SaltyKeeperConfig::default()
        })?;
        inner.incept(KeyTransferability::Transferable)?;

        let habitat: keria_types::api::AcceptedHab = serde_json::from_str(&format!(
            r#"{{"name":"m","prefix":"EMEM","icp_dt":"2023-12-01T10:05:25.062609+00:00","randy":{{"prxs":[],"nxts":[]}},"state":{{"i":"EMEM","s":"0","p":"","d":"EMEM","f":"0","dt":"","et":"icp","kt":"1","k":["{key}"],"nt":"1","n":["{digest}"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"EMEM"}},"di":""}}}}"#
        ))
        .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let group = GroupKeeper::new(Box::new(inner), habitat, keys.clone(), digests.clone());
        prop_assert_eq!(group.algorithm(), KeyAlgorithm::Group);

        let purpose = if rotation { SigningPurpose::Rotation } else { SigningPurpose::Current };
        let signatures = group.sign(b"payload", &SignatureForm::IndexedByPosition, purpose)?;
        let ManagedSignatures::Indexed(indexed) = &signatures else {
            return Err(TestCaseError::fail("a group signature was not indexed"));
        };
        let signature = indexed.first().ok_or_else(|| TestCaseError::fail("no signature"))?;
        let position = u32::try_from(member).unwrap_or(0);
        prop_assert_eq!(signature.index(), position);
        prop_assert_eq!(signature.other_index(), rotation.then_some(position));
    }

    /// An explicit placement reaches a non-group keeper unchanged.
    #[test]
    fn a_placement_reaches_a_keeper_unchanged(index in 0_u32..64, prior in prop::option::of(0_u32..64)) {
        let mut keeper = salty(SaltyKeeperConfig {
            transferability: KeyTransferability::Transferable,
            ..SaltyKeeperConfig::default()
        })?;
        keeper.incept(KeyTransferability::Transferable)?;

        let placement = match prior {
            Some(prior) => SignaturePlacement::both_lists_with_prior(index, prior),
            None => SignaturePlacement::current_list(index),
        };
        let signatures = keeper.sign(
            b"payload",
            &SignatureForm::Indexed(vec![placement]),
            SigningPurpose::Current,
        )?;
        let ManagedSignatures::Indexed(indexed) = &signatures else {
            return Err(TestCaseError::fail("an indexed request produced unindexed signatures"));
        };
        let signature = indexed.first().ok_or_else(|| TestCaseError::fail("no signature"))?;
        prop_assert_eq!(signature.index(), index);
        prop_assert_eq!(signature.other_index(), prior);
    }

    /// A mismatched placement count is always refused, never silently truncated.
    #[test]
    fn a_mismatched_placement_count_is_refused(keys in 1_usize..4, placements in 0_usize..6) {
        let mut keeper = salty(SaltyKeeperConfig {
            transferability: KeyTransferability::Transferable,
            current_count: keys,
            ..SaltyKeeperConfig::default()
        })?;
        keeper.incept(KeyTransferability::Transferable)?;

        let form = SignatureForm::Indexed(
            (0..placements)
                .map(|position| SignaturePlacement::both_lists(u32::try_from(position).unwrap_or(0)))
                .collect(),
        );
        let outcome = keeper.sign(b"payload", &form, SigningPurpose::Current);
        prop_assert_eq!(outcome.is_ok(), placements == keys);
        if let Err(error) = outcome {
            let typed = matches!(error, ManagerError::PlacementCountMismatch { .. });
            prop_assert!(typed, "a mismatched placement count was refused for another reason");
        }
    }

    /// An ephemeral keeper can never be written into an identifier record.
    #[test]
    fn an_ephemeral_keeper_is_never_storable(count in 1_usize..3) {
        let keeper = salty(SaltyKeeperConfig {
            current_count: count,
            ..SaltyKeeperConfig::default()
        })?;
        let refused = matches!(keeper.parameters(), Err(ManagerError::ProfileNotStorable));
        prop_assert!(refused, "an ephemeral keeper was storable");
    }
}
