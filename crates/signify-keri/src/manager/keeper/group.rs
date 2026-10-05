//! The group keeper: one multisig identifier that has no keys of its own.
//!
//! A group identifier is signed for by its members. This keeper holds no private key at all: it
//! works out where the local member sits in the group's key lists and hands the signature down to
//! that member's own keeper.
//!
//! # The two positions a rotation signature carries
//!
//! An indexed signature can name two places:
//!
//! - the **index**, which points at the signer's key in the event's current key list, proving the
//!   signature counts toward the current signing threshold;
//! - the **prior index**, which points at the entry in the *previous* establishment event's next-key
//!   digest list that committed to this key, proving the key was precommitted.
//!
//! Only a rotation needs the second. An inception or an interaction satisfies the current threshold
//! alone, and the event's own next-key list is a commitment for a *future* rotation rather than a
//! source of positions for this one. [`SigningPurpose`] selects between the two, which is the
//! reference's `rotated` flag.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::{KeyTransferability, VerificationKey};
use signify_types::api::{AcceptedHab, GroupState, KeyManagerState};

use super::super::algorithm::KeyAlgorithm;
use super::super::error::ManagerError;
use super::super::key_manager::{ManagedSignatures, SignatureForm};
use super::{IdentifierKeeper, KeeperRotation, KeyMaterial, SigningPurpose, first_keys, first_next_digests};

/// Signs for a multisig group by delegating to the local member's keeper.
pub struct GroupKeeper {
    member: Box<dyn IdentifierKeeper>,
    member_habitat: Box<AcceptedHab>,
    signing_keys: Vec<String>,
    next_digests: Vec<String>,
    prior_next_digests: Vec<String>,
}

impl core::fmt::Debug for GroupKeeper {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GroupKeeper")
            .field("member", &self.member_habitat.common.prefix)
            .field("signing_keys", &self.signing_keys.len())
            .field("next_digests", &self.next_digests.len())
            .finish_non_exhaustive()
    }
}

impl GroupKeeper {
    /// Creates a group keeper over a member keeper and the group's key lists.
    ///
    /// At inception there is no previous establishment event, so the prior next digests start as
    /// the same list as the proposed ones — which is what the reference does. A rotation replaces
    /// the proposed list while leaving the prior list where it is, because that list is what the
    /// prior index points into.
    ///
    /// The member's keeper is resolved once here rather than at every signature, as the reference
    /// does. The member habitat cannot change over this keeper's life, so the two are equivalent
    /// and this one does not have to hold the factory.
    #[must_use]
    pub fn new(
        member: Box<dyn IdentifierKeeper>,
        member_habitat: AcceptedHab,
        signing_keys: Vec<String>,
        next_digests: Vec<String>,
    ) -> Self {
        Self {
            member,
            member_habitat: Box::new(member_habitat),
            signing_keys,
            prior_next_digests: next_digests.clone(),
            next_digests,
        }
    }

    /// Creates a group keeper from the key states of its members.
    ///
    /// Each member contributes its first signing key and its first next-key digest, exactly as the
    /// reference's `states.map(state => state['k'][0])` does.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::NoSigningKeys`] when a member's key state carries no keys.
    pub fn from_states(
        member: Box<dyn IdentifierKeeper>,
        member_habitat: AcceptedHab,
        states: &[signify_types::api::KeyState],
        next_states: &[signify_types::api::KeyState],
    ) -> Result<Self, ManagerError> {
        Ok(Self::new(
            member,
            member_habitat,
            first_keys(states)?,
            first_next_digests(next_states)?,
        ))
    }

    /// Returns the group's current signing keys.
    #[must_use]
    pub fn signing_keys(&self) -> &[String] {
        &self.signing_keys
    }

    /// Returns the digests the group currently commits to.
    #[must_use]
    pub fn next_digests(&self) -> &[String] {
        &self.next_digests
    }

    /// Returns the local member's signing key.
    fn member_key(&self) -> Result<&String, ManagerError> {
        self.member_habitat
            .state
            .signing_keys
            .first()
            .ok_or_else(|| ManagerError::NoSigningKeys {
                prefix: self.member_habitat.common.prefix.clone(),
            })
    }

    /// Finds the prior next-digest position that committed to `key`.
    ///
    /// Each prior digest is re-derived over the key using that digest's own algorithm and compared,
    /// which is how a precommitment is recognized without knowing which algorithm was used.
    fn prior_next_index(&self, key: &str) -> Result<u32, ManagerError> {
        let verifier = VerificationKey::from_qb64(key)?;
        let encoded = verifier.qb64_bytes()?;

        for (position, committed) in self.prior_next_digests.iter().enumerate() {
            let parsed = Digest::from_qb64(committed)?;
            let algorithm = DigestAlgorithm::try_from(parsed.code()).map_err(|_| ManagerError::UnsupportedDigest {
                code: parsed.code().as_str().to_owned(),
            })?;
            if Digest::derive(algorithm, &encoded).qb64()? == *committed {
                return u32::try_from(position).map_err(|_| ManagerError::IndexOverflow { index: "signature" });
            }
        }
        Err(ManagerError::MemberNotPrecommitted { key: key.to_owned() })
    }
}

impl IdentifierKeeper for GroupKeeper {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Group
    }

    fn parameters(&self) -> Result<KeyManagerState, ManagerError> {
        Ok(KeyManagerState::Group(Box::new(GroupState {
            member: (*self.member_habitat).clone(),
            keys: self.signing_keys.clone(),
            next_key_digests: self.next_digests.clone(),
        })))
    }

    fn incept(&mut self, _transferability: KeyTransferability) -> Result<KeyMaterial, ManagerError> {
        // A group has no keys to create: its key lists are supplied by its members' key states.
        Ok(KeyMaterial {
            public_keys: self.signing_keys.clone(),
            next_digests: self.next_digests.clone(),
        })
    }

    fn rotate(&mut self, rotation: KeeperRotation<'_>) -> Result<KeyMaterial, ManagerError> {
        // The prior next digests deliberately stay where they are: they are what a rotation
        // signature's prior index points into, and they only move when the group's new
        // establishment event is accepted.
        if let Some(states) = rotation.states {
            self.signing_keys = first_keys(states)?;
        }
        if let Some(next_states) = rotation.next_states {
            self.next_digests = first_next_digests(next_states)?;
        }
        Ok(KeyMaterial {
            public_keys: self.signing_keys.clone(),
            next_digests: self.next_digests.clone(),
        })
    }

    fn sign(
        &self,
        serialization: &[u8],
        form: &SignatureForm,
        purpose: SigningPurpose,
    ) -> Result<ManagedSignatures, ManagerError> {
        let key = self.member_key()?;
        let index = self
            .signing_keys
            .iter()
            .position(|candidate| candidate == key)
            .ok_or_else(|| ManagerError::MemberNotInSigningKeys { key: key.clone() })?;
        let index = u32::try_from(index).map_err(|_| ManagerError::IndexOverflow { index: "signature" })?;

        let placement = match purpose {
            SigningPurpose::Rotation => SignaturePlacement::both_lists_with_prior(index, self.prior_next_index(key)?),
            SigningPurpose::Current => SignaturePlacement::current_list(index),
        };

        // The caller's placements are deliberately ignored: a group signature's positions come
        // from the group's own key lists, not from whoever asked for the signature. The reference
        // names those arguments `_indices` and `_ondices` for the same reason. Only the choice
        // between indexed and unindexed is carried through.
        let member_form = match form {
            SignatureForm::Unindexed => SignatureForm::Unindexed,
            SignatureForm::IndexedByPosition | SignatureForm::Indexed(_) => SignatureForm::Indexed(vec![placement]),
        };
        self.member.sign(serialization, &member_form, SigningPurpose::Current)
    }

    fn expose_signers(&self) -> Result<Vec<Signer>, ManagerError> {
        // A group has no keys of its own; the member's are what sign for it.
        self.member.expose_signers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::keeper::salty::{SaltyKeeper, SaltyKeeperConfig, SaltySource};
    use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
    use std::error::Error;

    /// Builds the member set the pinned `keeping.test.ts` builds: four keys derived at
    /// `member-{index}` with the temporary profile, and digests over the first three.
    fn group_fixture() -> Result<(Vec<String>, Vec<String>), Box<dyn Error>> {
        let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?;
        let mut keys = Vec::new();
        for index in 0..4 {
            let signer = salt.derive_signer_with_profile(
                &format!("member-{index}"),
                KeyTransferability::Transferable,
                KeyDerivationProfile::Temporary,
            )?;
            keys.push(signer.verifier().qb64()?);
        }
        let digests = keys
            .iter()
            .take(3)
            .map(|key| {
                let verifier = VerificationKey::from_qb64(key)?;
                Ok(Digest::derive(DigestAlgorithm::Blake3_256, &verifier.qb64_bytes()?).qb64()?)
            })
            .collect::<Result<Vec<String>, Box<dyn Error>>>()?;
        Ok((keys, digests))
    }

    /// A member habitat whose key state names one signing key.
    fn member_habitat(key: &str, next_digest: &str) -> Result<AcceptedHab, Box<dyn Error>> {
        let document = format!(
            r#"{{"name":"member","prefix":"EMEM","icp_dt":"2023-12-01T10:05:25.062609+00:00","randy":{{"prxs":[],"nxts":[]}},"state":{{"i":"EMEM","s":"0","p":"","d":"EMEM","f":"0","dt":"","et":"icp","kt":"1","k":["{key}"],"nt":"1","n":["{next_digest}"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"EMEM"}},"di":""}}}}"#
        );
        Ok(serde_json::from_str(&document)?)
    }

    fn member_keeper() -> Result<Box<dyn IdentifierKeeper>, Box<dyn Error>> {
        let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?;
        let sealing_key =
            salt.derive_signer_with_profile("", KeyTransferability::Transferable, KeyDerivationProfile::Temporary)?;
        let encrypter = keri_cesr::crypto::cipher::Encrypter::from_verification_key(sealing_key.verifier())?;
        let identifier_salt = Salt::from_raw(b"fedcba9876543210", SecurityTier::Low)?;
        let sealed = encrypter.encrypt_salt(&identifier_salt)?.qb64()?;

        let mut keeper = SaltyKeeper::new(
            &salt,
            SaltySource::Sealed(sealed),
            SaltyKeeperConfig {
                transferability: KeyTransferability::Transferable,
                profile: super::super::DerivationCost::Ephemeral,
                ..SaltyKeeperConfig::default()
            },
        )?;
        keeper.incept(KeyTransferability::Transferable)?;
        Ok(Box::new(keeper))
    }

    #[test]
    fn a_rotation_signature_exposes_the_prior_next_position() -> Result<(), Box<dyn Error>> {
        // The pinned test's first case: the member holds the key at position two.
        let (keys, digests) = group_fixture()?;
        let key = keys.get(2).ok_or("the fixture has too few keys")?;
        let digest = digests.get(2).ok_or("the fixture has too few digests")?;
        let group = GroupKeeper::new(
            member_keeper()?,
            member_habitat(key, digest)?,
            keys.iter().take(3).cloned().collect(),
            digests.clone(),
        );

        assert_eq!(group.algorithm(), KeyAlgorithm::Group);
        let signatures = group.sign(
            b"not a keri event",
            &SignatureForm::IndexedByPosition,
            SigningPurpose::Rotation,
        )?;
        let ManagedSignatures::Indexed(indexed) = &signatures else {
            return Err("a group signature was not indexed".into());
        };
        let signature = indexed.first().ok_or("no signature was produced")?;
        // The reference asserts the member keeper is called with index 2 and prior index 2.
        assert_eq!(signature.index(), 2);
        assert_eq!(signature.other_index(), Some(2));
        Ok(())
    }

    #[test]
    fn a_current_signature_exposes_no_prior_position() -> Result<(), Box<dyn Error>> {
        // The pinned test's second case: the member holds the key at position zero.
        let (keys, digests) = group_fixture()?;
        let key = keys.first().ok_or("the fixture has too few keys")?;
        let digest = digests.first().ok_or("the fixture has too few digests")?;
        let group = GroupKeeper::new(
            member_keeper()?,
            member_habitat(key, digest)?,
            keys.iter().take(3).cloned().collect(),
            digests.clone(),
        );

        let signatures = group.sign(
            b"not a keri event",
            &SignatureForm::IndexedByPosition,
            SigningPurpose::Current,
        )?;
        let ManagedSignatures::Indexed(indexed) = &signatures else {
            return Err("a group signature was not indexed".into());
        };
        let signature = indexed.first().ok_or("no signature was produced")?;
        // The reference asserts index 0 and an explicitly absent prior index.
        assert_eq!(signature.index(), 0);
        assert_eq!(signature.other_index(), None);
        Ok(())
    }

    #[test]
    fn a_member_outside_the_signing_keys_cannot_sign() -> Result<(), Box<dyn Error>> {
        let (keys, digests) = group_fixture()?;
        // The fourth key is deliberately not among the group's three signing keys.
        let key = keys.get(3).ok_or("the fixture has too few keys")?;
        let digest = digests.first().ok_or("the fixture has too few digests")?;
        let group = GroupKeeper::new(
            member_keeper()?,
            member_habitat(key, digest)?,
            keys.iter().take(3).cloned().collect(),
            digests.clone(),
        );

        assert!(matches!(
            group.sign(b"payload", &SignatureForm::IndexedByPosition, SigningPurpose::Current),
            Err(ManagerError::MemberNotInSigningKeys { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_member_that_was_never_precommitted_cannot_rotate() -> Result<(), Box<dyn Error>> {
        let (keys, digests) = group_fixture()?;
        let key = keys.first().ok_or("the fixture has too few keys")?;
        let digest = digests.first().ok_or("the fixture has too few digests")?;
        // A prior digest list that commits to nobody in the signing set.
        let unrelated = digests.last().cloned().ok_or("the fixture has too few digests")?;
        let group = GroupKeeper::new(
            member_keeper()?,
            member_habitat(key, digest)?,
            keys.iter().take(3).cloned().collect(),
            vec![unrelated],
        );

        // Signing for the current threshold still works; only the rotation position is missing.
        assert!(
            group
                .sign(b"payload", &SignatureForm::IndexedByPosition, SigningPurpose::Current)
                .is_ok()
        );
        assert!(matches!(
            group.sign(b"payload", &SignatureForm::IndexedByPosition, SigningPurpose::Rotation),
            Err(ManagerError::MemberNotPrecommitted { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_group_reports_its_key_lists_and_never_creates_keys() -> Result<(), Box<dyn Error>> {
        let (keys, digests) = group_fixture()?;
        let key = keys.first().ok_or("the fixture has too few keys")?;
        let digest = digests.first().ok_or("the fixture has too few digests")?;
        let mut group = GroupKeeper::new(
            member_keeper()?,
            member_habitat(key, digest)?,
            keys.iter().take(3).cloned().collect(),
            digests.clone(),
        );

        // Inception returns the lists it was given; a group creates nothing.
        let material = group.incept(KeyTransferability::Transferable)?;
        assert_eq!(material.public_keys, group.signing_keys());
        assert_eq!(material.next_digests, group.next_digests());

        let KeyManagerState::Group(state) = group.parameters()? else {
            return Err("a group keeper reported another state".into());
        };
        assert_eq!(Some(state.keys.as_slice()), keys.get(..3));
        assert_eq!(state.next_key_digests, digests);
        assert_eq!(state.member.common.prefix, "EMEM");
        Ok(())
    }

    #[test]
    fn a_rotation_moves_the_proposed_digests_and_not_the_prior_ones() -> Result<(), Box<dyn Error>> {
        let (keys, digests) = group_fixture()?;
        let key = keys.first().ok_or("the fixture has too few keys")?;
        let digest = digests.first().ok_or("the fixture has too few digests")?;
        let mut group = GroupKeeper::new(
            member_keeper()?,
            member_habitat(key, digest)?,
            keys.iter().take(3).cloned().collect(),
            digests.clone(),
        );

        let states: Vec<signify_types::api::KeyState> = keys
            .iter()
            .take(3)
            .map(|key| key_state(key, digest))
            .collect::<Result<_, Box<dyn Error>>>()?;
        let rotated = group.rotate(KeeperRotation {
            next_key_count: 3,
            transferability: KeyTransferability::Transferable,
            states: Some(&states),
            next_states: Some(&states),
        })?;
        assert_eq!(Some(rotated.public_keys.as_slice()), keys.get(..3));
        // Every member's key state names the same next digest here, so the proposed list changes.
        assert_eq!(rotated.next_digests, vec![digest.clone(); 3]);

        // The prior list is untouched, so the rotation position still resolves.
        let signatures = group.sign(b"payload", &SignatureForm::IndexedByPosition, SigningPurpose::Rotation)?;
        let ManagedSignatures::Indexed(indexed) = &signatures else {
            return Err("a group signature was not indexed".into());
        };
        assert_eq!(
            indexed
                .first()
                .and_then(keri_cesr::crypto::signature::IndexedSignature::other_index),
            Some(0)
        );
        Ok(())
    }

    fn key_state(key: &str, next_digest: &str) -> Result<signify_types::api::KeyState, Box<dyn Error>> {
        let document = format!(
            r#"{{"i":"EMEM","s":"0","p":"","d":"EMEM","f":"0","dt":"","et":"icp","kt":"1","k":["{key}"],"nt":"1","n":["{next_digest}"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"EMEM"}},"di":""}}"#
        );
        Ok(serde_json::from_str(&document)?)
    }

    #[test]
    fn a_group_never_prints_its_member_keys() -> Result<(), Box<dyn Error>> {
        let (keys, digests) = group_fixture()?;
        let key = keys.first().ok_or("the fixture has too few keys")?;
        let digest = digests.first().ok_or("the fixture has too few digests")?;
        let group = GroupKeeper::new(
            member_keeper()?,
            member_habitat(key, digest)?,
            keys.iter().take(3).cloned().collect(),
            digests.clone(),
        );
        let rendered = format!("{group:?}");
        assert!(rendered.contains("EMEM"));
        assert!(!rendered.contains(key.as_str()));
        Ok(())
    }
}
