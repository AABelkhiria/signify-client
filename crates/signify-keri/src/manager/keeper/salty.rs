//! The salty keeper: one identifier whose keys derive from a salt of its own.

use keri_cesr::crypto::cipher::{Ciphertext, Decrypter, Encrypter};
use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keria_types::api::{KeyManagerState, SaltyState};

use super::super::algorithm::KeyAlgorithm;
use super::super::creator::{KeyIndices, SaltyKeyCreator, Stem};
use super::super::error::ManagerError;
use super::super::key_manager::{ManagedSignatures, SignatureForm};
use super::{DerivationCost, IdentifierKeeper, KeeperRotation, KeyMaterial, SigningPurpose, public_keys, sign_with};

/// The stem a salty keeper uses when the caller names none.
///
/// The reference defaults to this rather than to the empty stem its key *manager* uses, which is
/// why the two derive different keys from one salt.
pub const DEFAULT_STEM: &str = "signify:aid";

/// Where a salty keeper's own salt comes from.
///
/// The keeper's salt is not the controller's passcode salt: that one only derives the key its salt
/// is sealed to. This enum replaces the reference's three-branch `if` over a `bran` argument, an
/// `sxlt` argument, and neither.
#[derive(Debug)]
pub enum SaltySource {
    /// Derive the salt from a passcode, as the reference's `bran` argument does.
    Passcode(String),
    /// Generate a fresh salt from operating-system entropy.
    Generated,
    /// Open a salt this keeper sealed earlier, which is how a stored identifier is reloaded.
    Sealed(String),
}

/// Holds one identifier whose keys derive deterministically from its own salt.
pub struct SaltyKeeper {
    salt: Salt,
    sealed_salt: String,
    stem: Stem,
    tier: SecurityTier,
    prefix_index: u32,
    key_index: u32,
    current_count: usize,
    next_count: usize,
    transferability: KeyTransferability,
    digest: DigestAlgorithm,
    profile: DerivationCost,
}

impl core::fmt::Debug for SaltyKeeper {
    /// Names the public indices and nothing that could reconstruct a key.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SaltyKeeper")
            .field("stem", &self.stem)
            .field("tier", &self.tier)
            .field("prefix_index", &self.prefix_index)
            .field("key_index", &self.key_index)
            .finish_non_exhaustive()
    }
}

/// Everything a salty keeper needs that is not its salt.
#[derive(Clone, Debug)]
pub struct SaltyKeeperConfig {
    /// Index this identifier takes among the ones one controller holds.
    pub prefix_index: u32,
    /// Index of this identifier's current key set among all its keys.
    pub key_index: u32,
    /// Tier the keys derive under.
    pub tier: SecurityTier,
    /// Whether the identifier may rotate.
    pub transferability: KeyTransferability,
    /// Stem every derivation path starts with.
    pub stem: Stem,
    /// How many keys sign.
    pub current_count: usize,
    /// How many keys are committed to.
    pub next_count: usize,
    /// Digest algorithm committing to the next keys.
    pub digest: DigestAlgorithm,
    /// Derivation cost; see [`DerivationCost`].
    pub profile: DerivationCost,
}

impl Default for SaltyKeeperConfig {
    fn default() -> Self {
        Self {
            prefix_index: 0,
            key_index: 0,
            tier: SecurityTier::Low,
            transferability: KeyTransferability::NonTransferable,
            stem: Stem::new(DEFAULT_STEM).unwrap_or_else(|_| Stem::empty()),
            current_count: 1,
            next_count: 1,
            digest: DigestAlgorithm::Blake3_256,
            profile: DerivationCost::Production,
        }
    }
}

impl SaltyKeeper {
    /// Creates a salty keeper over a salt from `source`, sealed to a key derived from
    /// `passcode_salt`.
    ///
    /// The encryption key comes from `passcode_salt` at the empty derivation path, exactly as the
    /// reference derives it, and so depends on `config.transferability` — two identifiers of
    /// different transferability under one passcode seal to different keys. That is upstream's
    /// arrangement and round-trips, because the transferability is recorded alongside the sealed
    /// salt.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::PasscodeTooShort`] or [`ManagerError::InvalidPasscode`] for an
    /// unusable passcode, and a layered [`ManagerError::Crypto`] for a derivation, sealing, or
    /// opening failure.
    pub fn new(passcode_salt: &Salt, source: SaltySource, config: SaltyKeeperConfig) -> Result<Self, ManagerError> {
        // The sealing key follows the same cost as the identifier's own keys: an ephemeral keeper
        // is ephemeral throughout, and a production one derives exactly what the reference does.
        let sealing_key = passcode_salt.derive_signer_with_profile(
            "",
            config.transferability,
            config.profile.profile(config.tier),
        )?;
        let encrypter = Encrypter::from_verification_key(sealing_key.verifier())?;
        let decrypter = Decrypter::from_signer(&sealing_key);

        let (salt, sealed_salt) = match source {
            SaltySource::Passcode(passcode) => {
                let salt = super::super::key_manager::salt_from_passcode(&passcode, config.tier)?;
                let sealed = encrypter.encrypt_salt(&salt)?.qb64()?;
                (salt, sealed)
            }
            SaltySource::Generated => {
                let salt = Salt::generate(config.tier)?;
                let sealed = encrypter.encrypt_salt(&salt)?.qb64()?;
                (salt, sealed)
            }
            SaltySource::Sealed(sealed) => {
                let salt = decrypter.decrypt_salt(&Ciphertext::from_qb64(&sealed)?, config.tier)?;
                (salt, sealed)
            }
        };

        Ok(Self {
            salt,
            sealed_salt,
            stem: config.stem,
            tier: config.tier,
            prefix_index: config.prefix_index,
            key_index: config.key_index,
            current_count: config.current_count,
            next_count: config.next_count,
            transferability: config.transferability,
            digest: config.digest,
            profile: config.profile,
        })
    }

    /// Returns the index of this identifier's current key set.
    #[must_use]
    pub const fn key_index(&self) -> u32 {
        self.key_index
    }

    /// Derives `count` keys at `key_index`.
    ///
    /// The rotation index is always zero: this keeper advances the *key* index instead, which is
    /// what makes its derivation differ from the key manager's.
    fn derive(&self, count: usize, key_index: u32) -> Result<Vec<Signer>, ManagerError> {
        let creator = SaltyKeyCreator::new(&self.salt, self.stem.clone());
        let keys = creator.create(
            count,
            self.transferability,
            KeyIndices::new(self.prefix_index, 0, key_index),
            self.profile.profile(self.tier),
        )?;
        Ok(keys.into_entries().into_iter().map(|(signer, _)| signer).collect())
    }

    /// Derives the digests committing to a set of keys.
    fn digests(&self, signers: &[Signer]) -> Result<Vec<String>, ManagerError> {
        signers
            .iter()
            .map(|signer| {
                let encoded = signer.verifier().qb64_bytes()?;
                Ok(Digest::derive(self.digest, &encoded).qb64()?)
            })
            .collect()
    }

    /// Returns the key index the next key set derives at.
    fn next_key_index(&self) -> Result<u32, ManagerError> {
        let stride = u32::try_from(self.current_count).map_err(|_| ManagerError::IndexOverflow { index: "key" })?;
        self.key_index
            .checked_add(stride)
            .ok_or(ManagerError::IndexOverflow { index: "key" })
    }
}

impl IdentifierKeeper for SaltyKeeper {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Salty
    }

    fn parameters(&self) -> Result<KeyManagerState, ManagerError> {
        // A record stores a tier, not a cost, so an ephemeral keeper has nothing to write.
        if self.profile != DerivationCost::Production {
            return Err(ManagerError::ProfileNotStorable);
        }
        Ok(KeyManagerState::Salty(SaltyState {
            tier: super::key_tier(self.tier)?,
            encrypted_salt: self.sealed_salt.clone(),
            key_pair_index: self.prefix_index,
            key_index: self.key_index,
            stem: self.stem.as_str().to_owned(),
            digest_code: self.digest.code().as_str().to_owned(),
            // The reference stores one derivation code per key; this port derives Ed25519 only, so
            // the lists carry the one code repeated, which is what upstream writes too.
            inception_codes: vec![ED25519_SEED_CODE.to_owned(); self.current_count],
            next_codes: vec![ED25519_SEED_CODE.to_owned(); self.next_count],
            transferable: matches!(self.transferability, KeyTransferability::Transferable),
        }))
    }

    fn incept(&mut self, transferability: KeyTransferability) -> Result<KeyMaterial, ManagerError> {
        self.transferability = transferability;
        self.key_index = 0;

        let current = self.derive(self.current_count, 0)?;
        let next = self.derive(self.next_count, self.next_key_index()?)?;
        Ok(KeyMaterial {
            public_keys: public_keys(&current)?,
            next_digests: self.digests(&next)?,
        })
    }

    fn rotate(&mut self, rotation: KeeperRotation<'_>) -> Result<KeyMaterial, ManagerError> {
        self.next_count = rotation.next_key_count;
        self.transferability = rotation.transferability;

        // The committed-to keys become current, one stride further along.
        let current = self.derive(self.next_count, self.next_key_index()?)?;
        self.key_index = self.next_key_index()?;
        let next = self.derive(self.next_count, self.next_key_index()?)?;

        Ok(KeyMaterial {
            public_keys: public_keys(&current)?,
            next_digests: self.digests(&next)?,
        })
    }

    fn sign(
        &self,
        serialization: &[u8],
        form: &SignatureForm,
        _purpose: SigningPurpose,
    ) -> Result<ManagedSignatures, ManagerError> {
        // The purpose is a group concern; a salty keeper signs with the keys it holds either way,
        // exactly as the reference's `_rotated` parameter is ignored here.
        let signers = self.derive(self.current_count, self.key_index)?;
        sign_with(&signers, serialization, form)
    }

    fn expose_signers(&self) -> Result<Vec<Signer>, ManagerError> {
        self.derive(self.current_count, self.key_index)
    }
}

/// The one seed derivation code this port supports.
const ED25519_SEED_CODE: &str = "A";

#[cfg(test)]
mod tests {
    use super::*;
    use keria_types::api::KeyTier;
    use std::error::Error;

    /// A cheap configuration; a keeper built this way is ephemeral and cannot be stored.
    fn ephemeral() -> SaltyKeeperConfig {
        SaltyKeeperConfig {
            profile: DerivationCost::Ephemeral,
            ..SaltyKeeperConfig::default()
        }
    }

    fn passcode_salt() -> Result<Salt, Box<dyn Error>> {
        Ok(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?)
    }

    fn keeper() -> Result<SaltyKeeper, Box<dyn Error>> {
        Ok(SaltyKeeper::new(
            &passcode_salt()?,
            SaltySource::Sealed(sealed_salt()?),
            SaltyKeeperConfig {
                transferability: KeyTransferability::Transferable,
                profile: DerivationCost::Ephemeral,
                ..SaltyKeeperConfig::default()
            },
        )?)
    }

    /// Seals a known salt to the key one configuration derives, so a keeper can be built
    /// deterministically without generating one.
    ///
    /// The sealing key follows the derivation cost, so a salt sealed for an ephemeral keeper does
    /// not open for a production one and the other way round.
    fn sealed_salt_for(cost: DerivationCost) -> Result<String, Box<dyn Error>> {
        let sealing_key = passcode_salt()?.derive_signer_with_profile(
            "",
            KeyTransferability::Transferable,
            cost.profile(SecurityTier::Low),
        )?;
        let encrypter = Encrypter::from_verification_key(sealing_key.verifier())?;
        let identifier_salt = Salt::from_raw(b"fedcba9876543210", SecurityTier::Low)?;
        Ok(encrypter.encrypt_salt(&identifier_salt)?.qb64()?)
    }

    /// The ephemeral sealed salt every cheap test uses.
    fn sealed_salt() -> Result<String, Box<dyn Error>> {
        sealed_salt_for(DerivationCost::Ephemeral)
    }

    #[test]
    fn an_ephemeral_keeper_cannot_be_stored() -> Result<(), Box<dyn Error>> {
        // An identifier record names a tier, not a profile, so a cheap keeper has nothing to write.
        let keeper = keeper()?;
        assert!(matches!(keeper.parameters(), Err(ManagerError::ProfileNotStorable)));

        // A production keeper stores normally. This is the one test that pays the real Argon2 cost.
        let storable = SaltyKeeper::new(
            &passcode_salt()?,
            SaltySource::Sealed(sealed_salt_for(DerivationCost::Production)?),
            SaltyKeeperConfig {
                transferability: KeyTransferability::Transferable,
                ..SaltyKeeperConfig::default()
            },
        )?;
        assert!(storable.parameters().is_ok());
        Ok(())
    }

    #[test]
    fn a_sealed_salt_round_trips_into_a_working_keeper() -> Result<(), Box<dyn Error>> {
        let mut keeper = SaltyKeeper::new(
            &passcode_salt()?,
            SaltySource::Sealed(sealed_salt_for(DerivationCost::Production)?),
            SaltyKeeperConfig {
                transferability: KeyTransferability::Transferable,
                ..SaltyKeeperConfig::default()
            },
        )?;
        assert_eq!(keeper.algorithm(), KeyAlgorithm::Salty);
        let material = keeper.incept(KeyTransferability::Transferable)?;
        assert_eq!(material.public_keys.len(), 1);
        assert_eq!(material.next_digests.len(), 1);

        // The keeper's parameters carry the sealed salt back, so it reloads to the same keys.
        let KeyManagerState::Salty(state) = keeper.parameters()? else {
            return Err("a salty keeper reported another state".into());
        };
        assert_eq!(state.stem, DEFAULT_STEM);
        assert_eq!(state.tier, KeyTier::Low);
        assert!(state.transferable);
        assert_eq!(state.inception_codes, ["A"]);
        assert_eq!(state.digest_code, "E");

        let mut reloaded = SaltyKeeper::new(
            &passcode_salt()?,
            SaltySource::Sealed(state.encrypted_salt.clone()),
            SaltyKeeperConfig {
                transferability: KeyTransferability::Transferable,
                ..SaltyKeeperConfig::default()
            },
        )?;
        assert_eq!(reloaded.incept(KeyTransferability::Transferable)?, material);
        Ok(())
    }

    #[test]
    fn the_key_index_advances_by_the_inception_count() -> Result<(), Box<dyn Error>> {
        let mut keeper = keeper()?;
        let incepted = keeper.incept(KeyTransferability::Transferable)?;
        assert_eq!(keeper.key_index(), 0);

        let rotated = keeper.rotate(KeeperRotation::to_keys(1))?;
        assert_eq!(keeper.key_index(), 1);
        // What was committed to is now signing.
        assert_eq!(
            incepted.next_digests,
            keeper_digests(&rotated.public_keys, DigestAlgorithm::Blake3_256)?
        );

        let again = keeper.rotate(KeeperRotation::to_keys(1))?;
        assert_eq!(keeper.key_index(), 2);
        assert_eq!(
            rotated.next_digests,
            keeper_digests(&again.public_keys, DigestAlgorithm::Blake3_256)?
        );
        Ok(())
    }

    /// Recomputes the digests a set of public keys would be committed to by.
    fn keeper_digests(public_keys: &[String], algorithm: DigestAlgorithm) -> Result<Vec<String>, Box<dyn Error>> {
        public_keys
            .iter()
            .map(|key| {
                let verifier = keri_cesr::crypto::verifier::VerificationKey::from_qb64(key)?;
                Ok(Digest::derive(algorithm, &verifier.qb64_bytes()?).qb64()?)
            })
            .collect()
    }

    #[test]
    fn signing_uses_the_current_key_set_whatever_the_purpose() -> Result<(), Box<dyn Error>> {
        let mut keeper = keeper()?;
        let incepted = keeper.incept(KeyTransferability::Transferable)?;

        for purpose in [SigningPurpose::Current, SigningPurpose::Rotation] {
            let signatures = keeper.sign(b"payload", &SignatureForm::IndexedByPosition, purpose)?;
            assert_eq!(signatures.len(), 1);
        }

        // Every signature verifies against the key the keeper reported.
        let signatures = keeper.sign(b"payload", &SignatureForm::IndexedByPosition, SigningPurpose::Current)?;
        let ManagedSignatures::Indexed(indexed) = &signatures else {
            return Err("an indexed request produced unindexed signatures".into());
        };
        let key = incepted.public_keys.first().ok_or("no key was established")?;
        let verifier = keri_cesr::crypto::verifier::VerificationKey::from_qb64(key)?;
        let signature = indexed.first().ok_or("no signature was produced")?;
        verifier.verify(signature.raw(), b"payload")?;
        Ok(())
    }

    #[test]
    fn a_current_only_placement_is_preserved() -> Result<(), Box<dyn Error>> {
        // The pinned `keeping.test.ts` case: `ondices: [undefined]` must stay current-only.
        let mut keeper = keeper()?;
        keeper.incept(KeyTransferability::Transferable)?;
        let signatures = keeper.sign(
            b"current-only-salty",
            &SignatureForm::Indexed(vec![keri_cesr::crypto::signer::SignaturePlacement::current_list(0)]),
            SigningPurpose::Current,
        )?;
        let ManagedSignatures::Indexed(indexed) = &signatures else {
            return Err("an indexed request produced unindexed signatures".into());
        };
        let signature = indexed.first().ok_or("no signature was produced")?;
        assert_eq!(signature.index(), 0);
        assert_eq!(signature.other_index(), None);
        Ok(())
    }

    #[test]
    fn a_passcode_source_derives_the_salt_from_it() -> Result<(), Box<dyn Error>> {
        let mut first = SaltyKeeper::new(
            &passcode_salt()?,
            SaltySource::Passcode("0123456789abcdefghijk".to_owned()),
            ephemeral(),
        )?;
        let mut second = SaltyKeeper::new(
            &passcode_salt()?,
            SaltySource::Passcode("0123456789abcdefghijk".to_owned()),
            ephemeral(),
        )?;
        // The same passcode always gives the same identifier keys.
        assert_eq!(
            first.incept(KeyTransferability::NonTransferable)?,
            second.incept(KeyTransferability::NonTransferable)?
        );

        // A different passcode does not.
        let mut other = SaltyKeeper::new(
            &passcode_salt()?,
            SaltySource::Passcode("abcdefghijk0123456789".to_owned()),
            ephemeral(),
        )?;
        assert_ne!(
            first.incept(KeyTransferability::NonTransferable)?,
            other.incept(KeyTransferability::NonTransferable)?
        );

        assert!(matches!(
            SaltyKeeper::new(
                &passcode_salt()?,
                SaltySource::Passcode("short".to_owned()),
                ephemeral()
            ),
            Err(ManagerError::PasscodeTooShort { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_generated_salt_differs_every_time() -> Result<(), Box<dyn Error>> {
        let mut first = SaltyKeeper::new(&passcode_salt()?, SaltySource::Generated, ephemeral())?;
        let mut second = SaltyKeeper::new(&passcode_salt()?, SaltySource::Generated, ephemeral())?;
        assert_ne!(
            first.incept(KeyTransferability::NonTransferable)?,
            second.incept(KeyTransferability::NonTransferable)?
        );
        Ok(())
    }

    #[test]
    fn a_keeper_never_prints_its_salt() -> Result<(), Box<dyn Error>> {
        let keeper = keeper()?;
        let rendered = format!("{keeper:?}");
        assert!(rendered.contains("signify:aid"));
        assert!(!rendered.contains("fedcba"));
        assert!(!rendered.contains("decrypter"));
        Ok(())
    }

    #[test]
    fn multiple_keys_derive_at_consecutive_positions() -> Result<(), Box<dyn Error>> {
        let mut keeper = SaltyKeeper::new(
            &passcode_salt()?,
            SaltySource::Sealed(sealed_salt()?),
            SaltyKeeperConfig {
                transferability: KeyTransferability::Transferable,
                current_count: 3,
                next_count: 2,
                profile: DerivationCost::Ephemeral,
                ..SaltyKeeperConfig::default()
            },
        )?;
        let material = keeper.incept(KeyTransferability::Transferable)?;
        assert_eq!(material.public_keys.len(), 3);
        assert_eq!(material.next_digests.len(), 2);

        // The next set starts one stride — the inception count — past the current one.
        keeper.rotate(KeeperRotation::to_keys(2))?;
        assert_eq!(keeper.key_index(), 3);
        Ok(())
    }
}
