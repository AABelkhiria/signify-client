//! The randy keeper: one identifier whose keys are random and therefore have to be kept.

use keri_cesr::crypto::cipher::{Ciphertext, Decrypter, Encrypter};
use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::salt::Salt;
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keria_types::api::{KeyManagerState, RandyState};

use super::super::algorithm::KeyAlgorithm;
use super::super::creator::RandyKeyCreator;
use super::super::error::ManagerError;
use super::super::key_manager::{ManagedSignatures, SignatureForm};
use super::{DerivationCost, IdentifierKeeper, KeeperRotation, KeyMaterial, SigningPurpose, public_keys, sign_with};

/// Holds one identifier whose keys were generated at random and are stored sealed.
///
/// A randy key cannot be derived again, so the sealed key *is* the key: losing the store loses the
/// identifier. Every private key here is sealed to a key derived from the controller's passcode
/// before it is stored, and opened only to sign.
pub struct RandyKeeper {
    encrypter: Encrypter,
    decrypter: Decrypter,
    sealed_signing_keys: Vec<String>,
    sealed_next_keys: Vec<String>,
    current_count: usize,
    next_count: usize,
    transferability: KeyTransferability,
    digest: DigestAlgorithm,
}

impl core::fmt::Debug for RandyKeeper {
    /// Names how many keys are held and nothing about them.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RandyKeeper")
            .field("signing_keys", &self.sealed_signing_keys.len())
            .field("next_keys", &self.sealed_next_keys.len())
            .finish_non_exhaustive()
    }
}

/// Everything a randy keeper needs besides its stored keys.
#[derive(Clone, Debug)]
pub struct RandyKeeperConfig {
    /// How many keys sign.
    pub current_count: usize,
    /// How many keys are committed to.
    pub next_count: usize,
    /// Whether the identifier may rotate.
    pub transferability: KeyTransferability,
    /// Digest algorithm committing to the next keys.
    pub digest: DigestAlgorithm,
    /// Derivation cost of the key the stored keys are sealed to; see [`DerivationCost`].
    pub profile: DerivationCost,
}

impl Default for RandyKeeperConfig {
    fn default() -> Self {
        Self {
            current_count: 1,
            next_count: 1,
            transferability: KeyTransferability::NonTransferable,
            digest: DigestAlgorithm::Blake3_256,
            profile: DerivationCost::Production,
        }
    }
}

impl RandyKeeper {
    /// Creates a randy keeper, optionally over keys it sealed earlier.
    ///
    /// # Errors
    ///
    /// Returns a layered [`ManagerError::Crypto`] when the sealing key cannot be derived.
    pub fn new(
        passcode_salt: &Salt,
        sealed_signing_keys: Vec<String>,
        sealed_next_keys: Vec<String>,
        config: &RandyKeeperConfig,
    ) -> Result<Self, ManagerError> {
        // The reference derives this key at the empty path with the salter's own tier, unlike the
        // salty keeper, which passes its identifier tier through.
        let sealing_key = passcode_salt.derive_signer_with_profile(
            "",
            config.transferability,
            config.profile.profile(passcode_salt.tier()),
        )?;
        Ok(Self {
            encrypter: Encrypter::from_verification_key(sealing_key.verifier())?,
            decrypter: Decrypter::from_signer(&sealing_key),
            sealed_signing_keys,
            sealed_next_keys,
            current_count: config.current_count,
            next_count: config.next_count,
            transferability: config.transferability,
            digest: config.digest,
        })
    }

    /// Seals a set of freshly generated keys for storage.
    fn seal(&self, signers: &[Signer]) -> Result<Vec<String>, ManagerError> {
        signers
            .iter()
            .map(|signer| Ok(self.encrypter.encrypt_signer(signer)?.qb64()?))
            .collect()
    }

    /// Opens a set of stored keys.
    fn open(&self, sealed: &[String]) -> Result<Vec<Signer>, ManagerError> {
        sealed
            .iter()
            .map(|ciphertext| {
                Ok(self
                    .decrypter
                    .decrypt_seed(&Ciphertext::from_qb64(ciphertext)?, self.transferability)?)
            })
            .collect()
    }

    /// Generates a set of keys.
    fn generate(&self, count: usize) -> Result<Vec<Signer>, ManagerError> {
        let keys = RandyKeyCreator::new().create(count, self.transferability)?;
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
}

impl IdentifierKeeper for RandyKeeper {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Randy
    }

    fn parameters(&self) -> Result<KeyManagerState, ManagerError> {
        // The reference's `params()` also returns `transferable`, which the KERIA schema's randy
        // record has no field for and therefore drops. Transferability is recovered from the
        // identifier's own prefix code instead, which is what the reference's loader does.
        Ok(KeyManagerState::Randy(RandyState {
            encrypted_signing_keys: self.sealed_signing_keys.clone(),
            encrypted_next_keys: self.sealed_next_keys.clone(),
        }))
    }

    fn incept(&mut self, transferability: KeyTransferability) -> Result<KeyMaterial, ManagerError> {
        self.transferability = transferability;

        let current = self.generate(self.current_count)?;
        self.sealed_signing_keys = self.seal(&current)?;
        let next = self.generate(self.next_count)?;
        self.sealed_next_keys = self.seal(&next)?;

        Ok(KeyMaterial {
            public_keys: public_keys(&current)?,
            next_digests: self.digests(&next)?,
        })
    }

    fn rotate(&mut self, rotation: KeeperRotation<'_>) -> Result<KeyMaterial, ManagerError> {
        self.next_count = rotation.next_key_count;
        self.transferability = rotation.transferability;

        // The keys committed to become the signing keys; nothing new is generated for them.
        self.sealed_signing_keys = self.sealed_next_keys.clone();
        let current = self.open(&self.sealed_signing_keys)?;
        self.current_count = current.len();

        let next = self.generate(self.next_count)?;
        self.sealed_next_keys = self.seal(&next)?;

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
        let signers = self.open(&self.sealed_signing_keys)?;
        sign_with(&signers, serialization, form)
    }

    fn expose_signers(&self) -> Result<Vec<Signer>, ManagerError> {
        self.open(&self.sealed_signing_keys)
    }
}

/// Recovers a randy keeper's transferability from the identifier's own prefix.
///
/// The reference does exactly this, because its stored randy record has no transferability field.
///
/// # Errors
///
/// Returns a layered [`ManagerError::Crypto`] when the prefix is not a usable identifier.
pub(crate) fn transferability_of(prefix: &str) -> Result<KeyTransferability, ManagerError> {
    let parsed =
        keri_protocol::prefix::IdentifierPrefix::from_qb64(prefix).map_err(|_| ManagerError::NoSigningKeys {
            prefix: prefix.to_owned(),
        })?;
    Ok(if parsed.is_transferable() {
        KeyTransferability::Transferable
    } else {
        KeyTransferability::NonTransferable
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{key_digest, salt};
    use std::error::Error;

    fn keeper() -> Result<RandyKeeper, Box<dyn Error>> {
        Ok(RandyKeeper::new(
            &salt()?,
            Vec::new(),
            Vec::new(),
            &RandyKeeperConfig {
                transferability: KeyTransferability::Transferable,
                ..RandyKeeperConfig::default()
            },
        )?)
    }

    #[test]
    fn a_rotation_promotes_the_keys_it_committed_to() -> Result<(), Box<dyn Error>> {
        let mut keeper = keeper()?;
        let incepted = keeper.incept(KeyTransferability::Transferable)?;
        let committed = keeper.sealed_next_keys.clone();

        let rotated = keeper.rotate(KeeperRotation::to_keys(1))?;
        // The keys that were committed to are now the signing keys, unchanged.
        assert_eq!(keeper.sealed_signing_keys, committed);
        assert_ne!(rotated.public_keys, incepted.public_keys);
        assert_ne!(keeper.sealed_next_keys, committed);

        // And the digests the inception published commit to exactly those keys.
        let digest = key_digest(rotated.public_keys.first().ok_or("no key was rotated to")?)?;
        assert_eq!(incepted.next_digests, [digest]);
        Ok(())
    }

    #[test]
    fn signing_without_keys_produces_nothing() -> Result<(), Box<dyn Error>> {
        // A keeper that has not incepted holds no keys at all.
        let keeper = keeper()?;
        let signatures = keeper.sign(b"payload", &SignatureForm::IndexedByPosition, SigningPurpose::Current)?;
        assert!(signatures.is_empty());
        assert!(keeper.expose_signers()?.is_empty());
        Ok(())
    }

    #[test]
    fn transferability_comes_from_the_prefix() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            transferability_of("DB-fH5uto5o5XHZjNN3_W3PdT4MIyTCmQWDzMxMZV2kI")?,
            KeyTransferability::Transferable
        );
        assert_eq!(
            transferability_of("BB-fH5uto5o5XHZjNN3_W3PdT4MIyTCmQWDzMxMZV2kI")?,
            KeyTransferability::NonTransferable
        );
        assert!(transferability_of("not a prefix").is_err());
        Ok(())
    }

    #[test]
    fn a_keeper_never_prints_its_keys() -> Result<(), Box<dyn Error>> {
        let mut keeper = keeper()?;
        let material = keeper.incept(KeyTransferability::Transferable)?;
        let rendered = format!("{keeper:?}");
        for key in &material.public_keys {
            assert!(!rendered.contains(key));
        }
        assert!(!rendered.contains("decrypter"));
        Ok(())
    }
}
