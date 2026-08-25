//! Invariants of key creation, storage, rotation, and signing.
//!
//! Every property uses the temporary Argon2 profile: the production profiles cost 64 MiB and up per
//! key, which a property test would multiply by its case count. The path arithmetic and the state
//! machine under test do not depend on the profile, and the cross-language vectors cover the
//! production one.

use proptest::prelude::*;
use signify_crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use signify_crypto::signer::{SignaturePlacement, Signer};
use signify_crypto::verifier::KeyTransferability;
use signify_keri::manager::{
    DerivationPath, InceptionRequest, KeyAlgorithm, KeyIndices, KeyManager, MAX_KEYS_PER_SET, MAX_STEM_BYTES,
    ManagedSignatures, ManagerError, RetiredKeyPolicy, RotationKey, RotationRequest, SaltyKeyCreator, SignatureForm,
    Stem,
};

/// The encryption seed the pinned unit test uses.
const CRYPT_SEED: [u8; 32] = [
    104, 44, 35, 124, 138, 112, 34, 18, 196, 51, 116, 50, 166, 225, 24, 25, 240, 102, 50, 44, 121, 196, 194, 49, 64,
    245, 64, 21, 46, 162, 26, 207,
];

fn salt() -> Result<Salt, ManagerError> {
    Ok(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?)
}

fn seed() -> Result<Signer, ManagerError> {
    Ok(Signer::from_seed(&CRYPT_SEED, KeyTransferability::NonTransferable)?)
}

fn temporary() -> InceptionRequest {
    InceptionRequest {
        profile: KeyDerivationProfile::Temporary,
        ..InceptionRequest::default()
    }
}

/// Stems that are safe to put in a derivation path.
fn stem() -> impl Strategy<Value = String> {
    "[a-z:]{0,24}"
}

proptest! {
    /// The same inputs always derive the same keys, which is what makes a salt enough to keep.
    #[test]
    fn derivation_is_deterministic(
        stem in stem(),
        prefix in 0_u32..64,
        rotation in 0_u32..64,
        key in 0_u32..64,
        count in 0_usize..3,
        transferable in any::<bool>(),
    ) {
        let salt = salt()?;
        let creator = SaltyKeyCreator::new(&salt, Stem::new(stem)?);
        let indices = KeyIndices::new(prefix, rotation, key);
        let transferability = if transferable {
            KeyTransferability::Transferable
        } else {
            KeyTransferability::NonTransferable
        };

        let first = creator.create(count, transferability, indices, KeyDerivationProfile::Temporary)?;
        let second = creator.create(count, transferability, indices, KeyDerivationProfile::Temporary)?;
        prop_assert_eq!(first.public_keys()?, second.public_keys()?);
        prop_assert_eq!(first.len(), count);

        // Transferability shows in the code of every derived public key, and nowhere else.
        let expected = if transferable { 'D' } else { 'B' };
        for public_key in first.public_keys()? {
            prop_assert_eq!(public_key.chars().next(), Some(expected));
        }
    }

    /// A non-empty stem puts both indices in the path, in the reference's own spelling.
    ///
    /// It does **not** separate them. The reference concatenates two variable-length hexadecimal
    /// numbers with no delimiter, so the mapping from position to path is not injective: equal
    /// indices always give equal paths, but equal paths do not imply equal indices. That is a
    /// reference defect rather than a port defect — see
    /// `distinct_positions_can_collide_onto_one_path` below, which pins the reference's own
    /// colliding pair — so the property states the direction that actually holds.
    #[test]
    fn a_stem_places_both_indices_in_the_references_own_spelling(
        stem in "[a-z]{1,8}",
        first in (0_u32..32, 0_u32..32),
        second in (0_u32..32, 0_u32..32),
    ) {
        let stem = Stem::new(stem)?;
        let left = DerivationPath::new(&stem, KeyIndices::new(0, first.0, first.1))?;
        let right = DerivationPath::new(&stem, KeyIndices::new(0, second.0, second.1))?;
        // Equal indices always derive equal paths; the converse is what does not hold.
        if first == second {
            prop_assert_eq!(&left, &right);
        }
        prop_assert!(!left.reuses_keys_across_rotations());
        // The path is the stem followed by the two indices in lowercase hexadecimal.
        prop_assert_eq!(
            left.as_str(),
            format!("{}{:x}{:x}", stem.as_str(), first.0, first.1)
        );
        // A collision is possible only where the two renderings concatenate to the same text,
        // which is exactly what the path equality says.
        prop_assert_eq!(
            left == right,
            format!("{:x}{:x}", first.0, first.1) == format!("{:x}{:x}", second.0, second.1)
        );
    }

    /// An empty stem collapses every position onto one path, which is the reference defect.
    #[test]
    fn an_empty_stem_collapses_every_position(
        prefix in 0_u32..64,
        rotation in 0_u32..64,
        key in 0_u32..64,
    ) {
        let stem = Stem::empty();
        let path = DerivationPath::new(&stem, KeyIndices::new(prefix, rotation, key))?;
        let base = DerivationPath::new(&stem, KeyIndices::new(prefix, 0, 0))?;
        prop_assert_eq!(&path, &base);
        prop_assert!(path.reuses_keys_across_rotations());
        prop_assert_eq!(path.as_str(), format!("{prefix:x}"));
    }

    /// An incepted identifier is always consistent with the state recorded for it.
    #[test]
    fn an_inception_records_a_consistent_state(
        stem in stem(),
        current in 1_usize..4,
        next in 0_usize..4,
        transferable in any::<bool>(),
    ) {
        let mut manager = KeyManager::builder().salt(salt()?).build()?;
        let incepted = manager.incept(InceptionRequest {
            current_keys: current,
            next_keys: next,
            stem: Stem::new(stem)?,
            transferability: if transferable {
                KeyTransferability::Transferable
            } else {
                KeyTransferability::NonTransferable
            },
            ..temporary()
        })?;

        prop_assert_eq!(incepted.verifiers.len(), current);
        prop_assert_eq!(incepted.next_digests.len(), next);

        let situation = manager
            .store()
            .situation(&incepted.prefix)
            .ok_or_else(|| TestCaseError::fail("the incepted identifier has no key sets"))?;
        // The prefix is the first current key, which is what makes it a basic prefix.
        prop_assert_eq!(situation.current.public_keys.first(), Some(&incepted.prefix));
        prop_assert_eq!(situation.current.public_keys.len(), current);
        prop_assert_eq!(situation.next.public_keys.len(), next);
        prop_assert_eq!(situation.current.rotation_index, 0);
        prop_assert_eq!(situation.current.key_index, 0);
        prop_assert_eq!(situation.next.rotation_index, 1);
        prop_assert_eq!(u32::try_from(current).unwrap_or(u32::MAX), situation.next.key_index);
        prop_assert!(situation.old.is_empty());

        // Both sets are recorded under their rotation keys.
        prop_assert_eq!(
            manager.store().key_set(&RotationKey::new(&incepted.prefix, 0)).map(<[String]>::len),
            Some(current)
        );
        prop_assert_eq!(manager.prefix_index(), 1);
    }

    /// A rotation always advances the indices by exactly the set it retires.
    #[test]
    fn a_rotation_advances_the_indices(stem in "[a-z]{1,8}", rounds in 1_usize..4, next in 1_usize..3) {
        let mut manager = KeyManager::builder().salt(salt()?).build()?;
        let incepted = manager.incept(InceptionRequest {
            next_keys: next,
            stem: Stem::new(stem)?,
            ..temporary()
        })?;

        for round in 0..rounds {
            let before = manager
                .store()
                .situation(&incepted.prefix)
                .cloned()
                .ok_or_else(|| TestCaseError::fail("the identifier has no key sets"))?;
            manager.rotate(RotationRequest {
                next_keys: next,
                profile: KeyDerivationProfile::Temporary,
                ..RotationRequest::new(&incepted.prefix)
            })?;
            let after = manager
                .store()
                .situation(&incepted.prefix)
                .ok_or_else(|| TestCaseError::fail("the identifier has no key sets"))?;

            // What was committed to is now current, and what was current is now retired.
            prop_assert_eq!(&after.current.public_keys, &before.next.public_keys);
            prop_assert_eq!(&after.old.public_keys, &before.current.public_keys);
            prop_assert_eq!(after.next.rotation_index, after.current.rotation_index + 1);
            prop_assert_eq!(
                after.next.key_index,
                after.current.key_index + u32::try_from(after.current.public_keys.len()).unwrap_or(0)
            );
            prop_assert_eq!(after.current.rotation_index, u32::try_from(round).unwrap_or(0) + 1);
        }
    }

    /// Every signature a manager produces verifies against the key it names.
    #[test]
    fn every_signature_verifies(stem in stem(), keys in 1_usize..3, payload in prop::collection::vec(any::<u8>(), 0..64)) {
        let mut manager = KeyManager::builder().salt(salt()?).build()?;
        let incepted = manager.incept(InceptionRequest {
            current_keys: keys,
            stem: Stem::new(stem)?,
            ..temporary()
        })?;
        let public_keys: Vec<String> = incepted
            .verifiers
            .iter()
            .map(signify_crypto::verifier::VerificationKey::qb64)
            .collect::<Result<_, _>>()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        for form in [SignatureForm::IndexedByPosition, SignatureForm::Unindexed] {
            let signatures = manager.sign(&payload, &public_keys, &form)?;
            prop_assert_eq!(signatures.len(), keys);
            match &signatures {
                ManagedSignatures::Indexed(indexed) => {
                    for (position, signature) in indexed.iter().enumerate() {
                        let verifier = incepted
                            .verifiers
                            .get(position)
                            .ok_or_else(|| TestCaseError::fail("a signature has no key"))?;
                        prop_assert!(verifier.verify(signature.raw(), &payload).is_ok());
                        prop_assert_eq!(signature.index(), u32::try_from(position).unwrap_or(0));
                    }
                }
                ManagedSignatures::Unindexed(unindexed) => {
                    for (position, signature) in unindexed.iter().enumerate() {
                        let verifier = incepted
                            .verifiers
                            .get(position)
                            .ok_or_else(|| TestCaseError::fail("a signature has no key"))?;
                        prop_assert!(verifier.verify(signature.raw(), &payload).is_ok());
                    }
                }
            }
        }
    }

    /// An explicit placement is carried into the signature exactly as given.
    #[test]
    fn a_placement_is_carried_verbatim(index in 0_u32..128, prior in prop::option::of(0_u32..128)) {
        let mut manager = KeyManager::builder().salt(salt()?).build()?;
        let incepted = manager.incept(temporary())?;
        let placement = match prior {
            Some(prior) => SignaturePlacement::both_lists_with_prior(index, prior),
            None => SignaturePlacement::current_list(index),
        };

        let signatures = manager.sign(
            b"payload",
            &[incepted.prefix],
            &SignatureForm::Indexed(vec![placement]),
        )?;
        let ManagedSignatures::Indexed(signatures) = &signatures else {
            return Err(TestCaseError::fail("an indexed request produced unindexed signatures"));
        };
        let signature = signatures
            .first()
            .ok_or_else(|| TestCaseError::fail("no signature was produced"))?;
        prop_assert_eq!(signature.index(), index);
        prop_assert_eq!(signature.other_index(), prior);
    }

    /// Saved state always restores into a manager that signs the same way.
    #[test]
    fn saved_state_signs_identically(stem in stem(), payload in prop::collection::vec(any::<u8>(), 0..32)) {
        let seed = seed()?;
        let mut manager = KeyManager::builder().salt(salt()?).build_encrypted(&seed)?;
        let incepted = manager.incept(InceptionRequest {
            stem: Stem::new(stem)?,
            ..temporary()
        })?;
        let keys = vec![incepted.prefix.clone()];
        let before = manager.sign(&payload, &keys, &SignatureForm::IndexedByPosition)?.qb64()?;

        let restored = KeyManager::restore(manager.store().clone(), Some(salt()?), &seed)?;
        let after = restored.sign(&payload, &keys, &SignatureForm::IndexedByPosition)?.qb64()?;
        prop_assert_eq!(before, after);
        prop_assert_eq!(restored.prefix_index(), manager.prefix_index());
        prop_assert_eq!(restored.algorithm(), manager.algorithm());
    }

    /// Retiring a key set erases exactly the private keys it retires, and only when asked.
    #[test]
    fn the_retirement_policy_decides_what_survives(keep in any::<bool>()) {
        let seed = seed()?;
        let mut manager = KeyManager::builder().salt(salt()?).build_encrypted(&seed)?;
        let incepted = manager.incept(InceptionRequest {
            stem: Stem::new("red")?,
            ..temporary()
        })?;
        let policy = if keep { RetiredKeyPolicy::Keep } else { RetiredKeyPolicy::Erase };

        // Two rotations, because the first retires the empty set.
        for _ in 0..2 {
            manager.rotate(RotationRequest {
                profile: KeyDerivationProfile::Temporary,
                retired_keys: policy,
                ..RotationRequest::new(&incepted.prefix)
            })?;
        }
        prop_assert_eq!(manager.store().sealed_key(&incepted.prefix).is_some(), keep);
    }

    /// A randy identifier stores one sealed key per key and derives nothing.
    #[test]
    fn random_keys_are_always_stored(current in 1_usize..3, next in 0_usize..3) {
        let seed = seed()?;
        let mut manager = KeyManager::builder()
            .algorithm(KeyAlgorithm::Randy)
            .build_encrypted(&seed)?;
        let incepted = manager.incept(InceptionRequest {
            current_keys: current,
            next_keys: next,
            algorithm: Some(KeyAlgorithm::Randy),
            ..temporary()
        })?;

        prop_assert_eq!(manager.store().sealed_key_count(), current + next);
        prop_assert!(manager.store().path(&incepted.prefix).is_none());
        let parameters = manager
            .store()
            .parameters(&incepted.prefix)
            .ok_or_else(|| TestCaseError::fail("the identifier has no parameters"))?;
        // A randy identifier records no salt and no tier, because it derives from neither.
        prop_assert_eq!(parameters.sealed_salt.as_ref(), None);
        prop_assert_eq!(parameters.tier, None);
    }

    /// Bounds are enforced before any derivation happens.
    #[test]
    fn bounds_are_enforced(excess in 1_usize..8) {
        let salt = salt()?;
        let creator = SaltyKeyCreator::new(&salt, Stem::empty());
        let refused = matches!(
            creator.create(
                MAX_KEYS_PER_SET + excess,
                KeyTransferability::Transferable,
                KeyIndices::inception(0),
                KeyDerivationProfile::Temporary,
            ),
            Err(ManagerError::TooManyKeys { .. })
        );
        prop_assert!(refused, "an oversized key set was derived");

        let long_stem = matches!(
            Stem::new("a".repeat(MAX_STEM_BYTES + excess)),
            Err(ManagerError::StemTooLong { .. })
        );
        prop_assert!(long_stem, "an oversized stem was accepted");
    }

    /// A rotation key orders rotations, whatever the index.
    #[test]
    fn rotation_keys_sort_in_rotation_order(first in 0_u32..1024, second in 0_u32..1024) {
        let left = RotationKey::new("EABC", first);
        let right = RotationKey::new("EABC", second);
        prop_assert_eq!(left < right, first < second);
        prop_assert_eq!(left.as_str().len(), "EABC".len() + 1 + 32);
    }

    /// A passcode is accepted exactly when it is long enough and inside the alphabet.
    #[test]
    fn a_passcode_is_accepted_only_when_usable(passcode in "[0-9a-zA-Z_*-]{0,30}") {
        let long_enough = passcode.chars().count() >= 21;
        let in_alphabet = passcode
            .chars()
            .take(21)
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));

        let outcome = KeyManager::from_passcode(&passcode, None);
        prop_assert_eq!(outcome.is_ok(), long_enough && in_alphabet, "{}", passcode);
        if let Err(error) = outcome {
            let typed = matches!(
                error,
                ManagerError::PasscodeTooShort { .. } | ManagerError::InvalidPasscode { .. }
            );
            prop_assert!(typed, "a passcode was refused for an unrelated reason");
        }
    }
}

// ---------------------------------------------------------------------------
// Named regressions.
// ---------------------------------------------------------------------------

/// Two distinct key positions derive **the same key**, which is a reference defect.
///
/// Found by `a_stem_places_both_indices_in_the_references_own_spelling` on 2026-08-25, during
/// Roadmap 6.11. The reference builds a salty derivation path as
/// `stem + ridx.toString(16) + (kidx + idx).toString(16)` — two variable-length hexadecimal numbers
/// concatenated with no delimiter — so rotation 1 with key 16 and rotation 17 with key 0 both spell
/// `"a110"` and therefore derive one key. That defeats pre-rotation at those positions exactly as
/// the empty-stem path does at every position, which `PORTING.md` §9 already pins for Roadmap 4.2.
///
/// The port reproduces it deliberately: diverging would derive different identifiers from identical
/// inputs. The public key below is the reference's own, produced by driving its compiled
/// `SaltyCreator` at both positions.
#[test]
fn distinct_positions_can_collide_onto_one_path() -> Result<(), Box<dyn std::error::Error>> {
    /// The key the reference derives at both positions, from salt `0AAwMTIzNDU2Nzg5YWJjZGVm`.
    const SHARED_KEY: &str = "DGInBhzbDTr1NiDZkTofi1664nAF8QgTBiXVrhr1Q-P5";

    let stem = Stem::new("a")?;
    let first = DerivationPath::new(&stem, KeyIndices::new(0, 1, 16))?;
    let second = DerivationPath::new(&stem, KeyIndices::new(0, 17, 0))?;
    assert_eq!(first.as_str(), "a110");
    assert_eq!(second.as_str(), "a110");
    assert_eq!(first, second);

    // And so the keys are the same, which is what makes it a defect rather than a curiosity.
    let salt = salt()?;
    let creator = SaltyKeyCreator::new(&salt, Stem::new("a")?);
    let one = creator.create(
        1,
        KeyTransferability::Transferable,
        KeyIndices::new(0, 1, 16),
        KeyDerivationProfile::Temporary,
    )?;
    let other = creator.create(
        1,
        KeyTransferability::Transferable,
        KeyIndices::new(0, 17, 0),
        KeyDerivationProfile::Temporary,
    )?;
    assert_eq!(one.public_keys()?, other.public_keys()?);
    assert_eq!(one.public_keys()?, vec![SHARED_KEY.to_owned()]);
    Ok(())
}
