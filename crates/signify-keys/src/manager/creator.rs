//! Key creators: the two ways a set of signing keys comes into existence.
//!
//! A *salty* creator derives keys deterministically from a salt and a path, so only the salt has to
//! be kept. A *randy* creator generates them from operating-system entropy, so each private key has
//! to be stored encrypted or it is gone.
//!
//! # The derivation path
//!
//! The reference builds a salty path as
//!
//! ```text
//! stem == "" ? hex(pidx) : stem + hex(ridx) + hex(kidx + offset)
//! ```
//!
//! and that first branch is reproduced exactly, because changing it would derive different keys
//! from the same inputs. It is worth understanding what it does: **with an empty stem the path
//! ignores the rotation and key indices entirely**, so every key of every rotation of one prefix
//! derives from the same path and is therefore the same key. The pinned unit test shows it — an
//! identifier's current and next public keys come out identical — and it means pre-rotation
//! commits to the key already in use. [`DerivationPath::reuses_keys_across_rotations`] reports the
//! condition so a caller can refuse it; see `PORTING.md` §9.

use core::fmt;

use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;

use super::error::ManagerError;

/// Largest derivation stem this module accepts, in bytes.
///
/// A stem is chosen by the client — `signify:aid` and `signify:controller` upstream — or read back
/// from a KERIA identifier record. The bound is generous because the content is not otherwise
/// constrained; what matters is that the resulting path stays inside the crypto layer's own limit.
pub const MAX_STEM_BYTES: usize = 256;

/// Largest derivation path this module produces, in bytes.
///
/// This is `keri-cesr`'s own bound, restated because a path is assembled here.
pub const MAX_DERIVATION_PATH_BYTES: usize = keri_cesr::crypto::salt::MAX_DERIVATION_PATH_BYTES;

/// Largest number of keys one creator call produces.
///
/// Every key costs one Argon2 derivation at the configured memory cost — a gibibyte at the high
/// tier — so an unbounded count is a denial-of-service lever for whoever chooses it. No KERI
/// signing group approaches this.
pub const MAX_KEYS_PER_SET: usize = 1_024;

/// A validated derivation stem: the fixed part of every path a salty creator builds.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Stem {
    text: String,
}

impl Stem {
    /// Validates one stem.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::StemTooLong`] above [`MAX_STEM_BYTES`].
    pub fn new(text: impl Into<String>) -> Result<Self, ManagerError> {
        let text = text.into();
        if text.len() > MAX_STEM_BYTES {
            return Err(ManagerError::StemTooLong {
                maximum: MAX_STEM_BYTES,
                actual: text.len(),
            });
        }
        Ok(Self { text })
    }

    /// Returns the empty stem, which the reference uses by default.
    #[must_use]
    pub const fn empty() -> Self {
        Self { text: String::new() }
    }

    /// Returns the stem as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns whether this is the empty stem.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

impl fmt::Display for Stem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Where a key sits in one identifier's sequence of key sets.
///
/// All three are written into a derivation path as lowercase hexadecimal.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyIndices {
    /// Which identifier this is, counted across everything one manager holds.
    pub prefix: u32,
    /// Which rotation of that identifier, starting at zero for inception.
    pub rotation: u32,
    /// Which key overall, counted across every rotation of this identifier.
    pub key: u32,
}

impl KeyIndices {
    /// Creates a set of indices.
    #[must_use]
    pub const fn new(prefix: u32, rotation: u32, key: u32) -> Self {
        Self { prefix, rotation, key }
    }

    /// Returns the indices for the inception key set of one identifier.
    #[must_use]
    pub const fn inception(prefix: u32) -> Self {
        Self::new(prefix, 0, 0)
    }

    /// Returns the same indices with the key index advanced by `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::IndexOverflow`] when the key index would exceed `u32`.
    pub const fn advanced_by(self, offset: u32) -> Result<Self, ManagerError> {
        match self.key.checked_add(offset) {
            Some(key) => Ok(Self { key, ..self }),
            None => Err(ManagerError::IndexOverflow { index: "key" }),
        }
    }
}

/// One salty derivation path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DerivationPath {
    text: String,
    stem_was_empty: bool,
}

impl DerivationPath {
    /// Builds the path for one key, exactly as the reference builds it.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::DerivationPathTooLong`] above [`MAX_DERIVATION_PATH_BYTES`].
    pub fn new(stem: &Stem, indices: KeyIndices) -> Result<Self, ManagerError> {
        let text = if stem.is_empty() {
            // Reproduced deliberately: the rotation and key indices are dropped here, which is
            // what makes every key of every rotation the same one. See the module documentation.
            format!("{:x}", indices.prefix)
        } else {
            format!("{}{:x}{:x}", stem.as_str(), indices.rotation, indices.key)
        };
        if text.len() > MAX_DERIVATION_PATH_BYTES {
            return Err(ManagerError::DerivationPathTooLong {
                maximum: MAX_DERIVATION_PATH_BYTES,
                actual: text.len(),
            });
        }
        Ok(Self {
            text,
            stem_was_empty: stem.is_empty(),
        })
    }

    /// Returns the path as the derivation reads it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns whether this path derives the same key at every rotation.
    ///
    /// True exactly when the stem was empty, which drops the rotation and key indices and so
    /// defeats pre-rotation. A caller that cares refuses such a path before incepting.
    #[must_use]
    pub const fn reuses_keys_across_rotations(&self) -> bool {
        self.stem_was_empty
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// One derived key together with the path it came from.
#[derive(Debug)]
pub struct DerivedKey {
    /// The private signer.
    pub signer: Signer,
    /// The path it derives from, which is enough to derive it again.
    pub path: DerivationPath,
}

/// A set of freshly created keys.
///
/// The two variants are what keeps the reference's "if paths are provided, they must be the same
/// length as signers" check from being needed: a derived set carries one path per key by
/// construction, and a random set has no paths at all.
#[derive(Debug)]
pub enum CreatedKeys {
    /// Deterministically derived keys, each with its path.
    Derived(Vec<DerivedKey>),
    /// Randomly generated keys, which have no path and must be stored.
    Random(Vec<Signer>),
}

impl CreatedKeys {
    /// Returns how many keys were created.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Derived(keys) => keys.len(),
            Self::Random(signers) => signers.len(),
        }
    }

    /// Returns whether no keys were created.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns every signer in creation order.
    pub fn signers(&self) -> impl Iterator<Item = &Signer> {
        let derived = match self {
            Self::Derived(keys) => Some(keys.iter().map(|key| &key.signer)),
            Self::Random(_) => None,
        };
        let random = match self {
            Self::Derived(_) => None,
            Self::Random(signers) => Some(signers.iter()),
        };
        derived.into_iter().flatten().chain(random.into_iter().flatten())
    }

    /// Returns the qualified public key of every signer, in creation order.
    ///
    /// # Errors
    ///
    /// Returns a layered [`ManagerError::Crypto`] when a verification key cannot be encoded.
    pub fn public_keys(&self) -> Result<Vec<String>, ManagerError> {
        self.signers()
            .map(|signer| signer.verifier().qb64().map_err(ManagerError::from))
            .collect()
    }

    /// Splits the set into one entry per key, each with its path where there is one.
    #[must_use]
    pub fn into_entries(self) -> Vec<(Signer, Option<DerivationPath>)> {
        match self {
            Self::Derived(keys) => keys.into_iter().map(|key| (key.signer, Some(key.path))).collect(),
            Self::Random(signers) => signers.into_iter().map(|signer| (signer, None)).collect(),
        }
    }
}

/// Derives keys deterministically from a salt and a path.
#[derive(Debug)]
pub struct SaltyKeyCreator<'salt> {
    salt: &'salt Salt,
    stem: Stem,
}

impl<'salt> SaltyKeyCreator<'salt> {
    /// Creates a salty creator over a borrowed salt.
    ///
    /// The salt is borrowed rather than owned because it is secret: `Salt` is deliberately not
    /// `Clone`, and nothing here needs a copy.
    #[must_use]
    pub const fn new(salt: &'salt Salt, stem: Stem) -> Self {
        Self { salt, stem }
    }

    /// Returns the salt these keys derive from.
    #[must_use]
    pub const fn salt(&self) -> &'salt Salt {
        self.salt
    }

    /// Returns the stem every path starts with.
    #[must_use]
    pub const fn stem(&self) -> &Stem {
        &self.stem
    }

    /// Derives `count` keys starting at `indices`.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::TooManyKeys`] above [`MAX_KEYS_PER_SET`],
    /// [`ManagerError::IndexOverflow`] when the key index would exceed `u32`,
    /// [`ManagerError::DerivationPathTooLong`] for an over-long path, and a layered
    /// [`ManagerError::Crypto`] when derivation itself fails.
    pub fn create(
        &self,
        count: usize,
        transferability: KeyTransferability,
        indices: KeyIndices,
        profile: KeyDerivationProfile,
    ) -> Result<CreatedKeys, ManagerError> {
        if count > MAX_KEYS_PER_SET {
            return Err(ManagerError::TooManyKeys {
                maximum: MAX_KEYS_PER_SET,
                requested: count,
            });
        }
        let mut keys = Vec::with_capacity(count);
        for offset in 0..count {
            let offset = u32::try_from(offset).map_err(|_| ManagerError::IndexOverflow { index: "key" })?;
            let path = DerivationPath::new(&self.stem, indices.advanced_by(offset)?)?;
            let signer = self
                .salt
                .derive_signer_with_profile(path.as_str(), transferability, profile)?;
            keys.push(DerivedKey { signer, path });
        }
        Ok(CreatedKeys::Derived(keys))
    }
}

/// Generates keys from operating-system entropy.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RandyKeyCreator;

impl RandyKeyCreator {
    /// Creates a randy creator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Generates `count` keys.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::TooManyKeys`] above [`MAX_KEYS_PER_SET`] and a layered
    /// [`ManagerError::Crypto`] when the operating system cannot supply entropy.
    pub fn create(&self, count: usize, transferability: KeyTransferability) -> Result<CreatedKeys, ManagerError> {
        if count > MAX_KEYS_PER_SET {
            return Err(ManagerError::TooManyKeys {
                maximum: MAX_KEYS_PER_SET,
                requested: count,
            });
        }
        let mut signers = Vec::with_capacity(count);
        for _ in 0..count {
            signers.push(Signer::generate(transferability)?);
        }
        Ok(CreatedKeys::Random(signers))
    }
}

/// Either way of creating a set of keys.
///
/// The reference's `Creatory` takes any of the four algorithms and throws for two of them; this
/// enum has exactly the two that work, so the failure moves to the point where the algorithm is
/// chosen rather than the point where a key is needed.
///
/// ```
/// use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
/// use keri_cesr::crypto::verifier::KeyTransferability;
/// use signify_keys::manager::{KeyCreator, KeyIndices, SaltyKeyCreator, Stem};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?;
/// let creator = KeyCreator::Salty(SaltyKeyCreator::new(&salt, Stem::empty()));
/// let keys = creator.create(
///     1,
///     KeyTransferability::Transferable,
///     KeyIndices::inception(0),
///     KeyDerivationProfile::Temporary,
/// )?;
///
/// assert_eq!(keys.len(), 1);
/// assert_eq!(keys.public_keys()?, ["DB-fH5uto5o5XHZjNN3_W3PdT4MIyTCmQWDzMxMZV2kI"]);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub enum KeyCreator<'salt> {
    /// Deterministic derivation from a salt.
    Salty(SaltyKeyCreator<'salt>),
    /// Random generation.
    Randy(RandyKeyCreator),
}

impl KeyCreator<'_> {
    /// Returns the algorithm this creator implements.
    #[must_use]
    pub const fn algorithm(&self) -> super::algorithm::KeyAlgorithm {
        match self {
            Self::Salty(_) => super::algorithm::KeyAlgorithm::Salty,
            Self::Randy(_) => super::algorithm::KeyAlgorithm::Randy,
        }
    }

    /// Creates `count` keys.
    ///
    /// `indices` and `profile` are used only by the salty creator; random generation has no path
    /// and no cost profile.
    ///
    /// # Errors
    ///
    /// Returns whatever the selected creator returns.
    pub fn create(
        &self,
        count: usize,
        transferability: KeyTransferability,
        indices: KeyIndices,
        profile: KeyDerivationProfile,
    ) -> Result<CreatedKeys, ManagerError> {
        match self {
            Self::Salty(creator) => creator.create(count, transferability, indices, profile),
            Self::Randy(creator) => creator.create(count, transferability),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::salt::SecurityTier;
    use std::error::Error;

    fn salt() -> Result<Salt, Box<dyn Error>> {
        Ok(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?)
    }

    #[test]
    fn an_empty_stem_drops_the_rotation_and_key_indices() -> Result<(), Box<dyn Error>> {
        let stem = Stem::empty();
        let first = DerivationPath::new(&stem, KeyIndices::new(0, 0, 0))?;
        let later = DerivationPath::new(&stem, KeyIndices::new(0, 7, 9))?;
        assert_eq!(first.as_str(), "0");
        // The same path, so the same key, at every rotation: this is the reference behavior that
        // defeats pre-rotation.
        assert_eq!(first, later);
        assert!(first.reuses_keys_across_rotations());

        // A different prefix index does change it, because that is the only index in the path.
        assert_eq!(DerivationPath::new(&stem, KeyIndices::new(26, 0, 0))?.as_str(), "1a");
        Ok(())
    }

    #[test]
    fn a_stem_puts_every_index_in_the_path() -> Result<(), Box<dyn Error>> {
        let stem = Stem::new("signify:aid")?;
        assert_eq!(
            DerivationPath::new(&stem, KeyIndices::new(0, 0, 0))?.as_str(),
            "signify:aid00"
        );
        assert_eq!(
            DerivationPath::new(&stem, KeyIndices::new(3, 10, 27))?.as_str(),
            "signify:aida1b"
        );
        assert!(!DerivationPath::new(&stem, KeyIndices::new(0, 1, 1))?.reuses_keys_across_rotations());
        // The prefix index is deliberately absent once a stem is present, as upstream.
        assert_eq!(
            DerivationPath::new(&stem, KeyIndices::new(0, 1, 1))?,
            DerivationPath::new(&stem, KeyIndices::new(9, 1, 1))?
        );
        Ok(())
    }

    #[test]
    fn a_stem_and_a_path_are_bounded() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            Stem::new("a".repeat(MAX_STEM_BYTES + 1)),
            Err(ManagerError::StemTooLong { .. })
        ));
        assert_eq!(Stem::new("a".repeat(MAX_STEM_BYTES))?.as_str().len(), MAX_STEM_BYTES);
        assert!(Stem::empty().is_empty());
        assert_eq!(Stem::default(), Stem::empty());
        assert_eq!(Stem::new("red")?.to_string(), "red");
        Ok(())
    }

    #[test]
    fn the_key_index_is_checked() {
        assert!(matches!(
            KeyIndices::new(0, 0, u32::MAX).advanced_by(1),
            Err(ManagerError::IndexOverflow { index: "key" })
        ));
        assert!(matches!(KeyIndices::new(0, 0, 1).advanced_by(1), Ok(indices) if indices.key == 2));
        assert_eq!(KeyIndices::inception(4), KeyIndices::new(4, 0, 0));
        assert_eq!(KeyIndices::default(), KeyIndices::new(0, 0, 0));
    }

    #[test]
    fn a_salty_creator_reproduces_the_pinned_keys() -> Result<(), Box<dyn Error>> {
        let salt = salt()?;
        let creator = SaltyKeyCreator::new(&salt, Stem::empty());

        // The pinned `SaltyCreator` unit test: path "0" under the temporary profile.
        let keys = creator.create(
            1,
            KeyTransferability::NonTransferable,
            KeyIndices::inception(0),
            KeyDerivationProfile::Temporary,
        )?;
        assert_eq!(keys.public_keys()?, ["BB-fH5uto5o5XHZjNN3_W3PdT4MIyTCmQWDzMxMZV2kI"]);

        // The same path under the production profile is a different key.
        let keys = creator.create(
            1,
            KeyTransferability::Transferable,
            KeyIndices::inception(0),
            KeyDerivationProfile::Standard(SecurityTier::Low),
        )?;
        assert_eq!(keys.public_keys()?, ["DHHneREQ1eZyQNc5nEsQYx1FqFVL1OTXmvmatTE77Cfe"]);
        assert_eq!(creator.stem(), &Stem::empty());
        Ok(())
    }

    #[test]
    fn a_derived_set_carries_one_path_per_key() -> Result<(), Box<dyn Error>> {
        let salt = salt()?;
        let creator = SaltyKeyCreator::new(&salt, Stem::new("red")?);
        let keys = creator.create(
            3,
            KeyTransferability::Transferable,
            KeyIndices::new(0, 0, 0),
            KeyDerivationProfile::Temporary,
        )?;

        assert_eq!(keys.len(), 3);
        assert!(!keys.is_empty());
        assert_eq!(keys.signers().count(), 3);
        let entries = keys.into_entries();
        let paths: Vec<String> = entries
            .iter()
            .filter_map(|(_, path)| path.as_ref().map(|path| path.as_str().to_owned()))
            .collect();
        // The key index advances by one per key while the rotation index stays put.
        assert_eq!(paths, ["red00", "red01", "red02"]);
        Ok(())
    }

    #[test]
    fn a_randy_creator_generates_distinct_keys() -> Result<(), Box<dyn Error>> {
        let keys = RandyKeyCreator::new().create(4, KeyTransferability::Transferable)?;
        assert_eq!(keys.len(), 4);
        let public = keys.public_keys()?;
        let unique: std::collections::BTreeSet<&String> = public.iter().collect();
        assert_eq!(unique.len(), 4, "random keys repeated");
        // A random set has no paths, so nothing can regenerate it.
        assert!(keys.into_entries().iter().all(|(_, path)| path.is_none()));
        Ok(())
    }

    #[test]
    fn an_empty_set_is_allowed_and_a_huge_one_is_not() -> Result<(), Box<dyn Error>> {
        let salt = salt()?;
        let creator = SaltyKeyCreator::new(&salt, Stem::empty());
        let empty = creator.create(
            0,
            KeyTransferability::Transferable,
            KeyIndices::inception(0),
            KeyDerivationProfile::Temporary,
        )?;
        assert!(empty.is_empty());
        assert_eq!(empty.public_keys()?.len(), 0);

        for outcome in [
            creator.create(
                MAX_KEYS_PER_SET + 1,
                KeyTransferability::Transferable,
                KeyIndices::inception(0),
                KeyDerivationProfile::Temporary,
            ),
            RandyKeyCreator::new().create(MAX_KEYS_PER_SET + 1, KeyTransferability::Transferable),
        ] {
            assert!(matches!(outcome, Err(ManagerError::TooManyKeys { .. })));
        }
        Ok(())
    }

    #[test]
    fn the_creator_enum_dispatches_to_both_arms() -> Result<(), Box<dyn Error>> {
        let salt = salt()?;
        let salty = KeyCreator::Salty(SaltyKeyCreator::new(&salt, Stem::empty()));
        let randy = KeyCreator::Randy(RandyKeyCreator::new());
        assert_eq!(salty.algorithm(), super::super::KeyAlgorithm::Salty);
        assert_eq!(randy.algorithm(), super::super::KeyAlgorithm::Randy);

        for creator in [&salty, &randy] {
            let keys = creator.create(
                2,
                KeyTransferability::Transferable,
                KeyIndices::inception(0),
                KeyDerivationProfile::Temporary,
            )?;
            assert_eq!(keys.len(), 2);
        }
        Ok(())
    }
}
