//! The state a key manager keeps for the identifiers it holds.
//!
//! # Why this is a struct and not a trait
//!
//! The reference declares a `KeyStore` interface with fifteen methods and exactly one
//! implementation, an in-memory `Keeper`. A public trait should not be introduced ahead of a second
//! implementation, and storage need only be *injected* rather than ambient — which
//! [`KeyManager::restore`](super::KeyManager::restore) does by taking a store the caller assembled.
//!
//! # What is stored, and what is not
//!
//! A private key never enters this store in the clear. The reference hands the store a live signer
//! and an encrypter and lets the store do the sealing; here the manager seals first and the store
//! only ever holds ciphertext, so nothing but the manager touches key material.
//!
//! Under the salty algorithm without encryption there are no stored keys at all: the store keeps
//! the derivation path instead, and the key is derived again when it is needed.

use std::collections::BTreeMap;

use keri_cesr::crypto::salt::{KeyDerivationProfile, SecurityTier};

use super::algorithm::KeyAlgorithm;
use super::creator::{DerivationPath, Stem};

/// Manager-wide state: which identifier is next, and how keys are protected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagerGlobals {
    /// Qualified public key that private keys are encrypted to, if any.
    ///
    /// The reference calls this the `aeid`. `None` means keys are not stored at all and are
    /// derived again from the salt whenever they are needed.
    pub encryption_identifier: Option<String>,
    /// Index the next incepted identifier will take.
    pub prefix_index: u32,
    /// Algorithm new identifiers use unless one is named per inception.
    pub algorithm: KeyAlgorithm,
    /// The manager salt, sealed to the encryption identifier.
    ///
    /// Present only when there is an encryption identifier. Without one the salt is held in memory
    /// by the manager and never written here, which is what the reference does too.
    pub sealed_salt: Option<String>,
    /// Security tier new identifiers derive under.
    pub tier: SecurityTier,
}

/// What one identifier's keys were created from.
///
/// This is the reference's `PrePrm`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixParameters {
    /// Index this identifier took when it was incepted.
    pub prefix_index: u32,
    /// Algorithm its keys come from.
    pub algorithm: KeyAlgorithm,
    /// The salt its keys derive from, sealed to the encryption identifier.
    ///
    /// `None` for a randy identifier, which has no salt, and for a salty identifier held without
    /// encryption, whose salt is the manager's own.
    pub sealed_salt: Option<String>,
    /// Stem every derivation path starts with.
    pub stem: Stem,
    /// Tier its keys derive under, or `None` for a randy identifier.
    pub tier: Option<SecurityTier>,
}

/// One ordered set of public keys, and where it sits in the identifier's sequence.
///
/// This is the reference's `PubLot`, minus its `dt` field: that timestamp is written three times
/// and read nowhere, and a protocol crate does not read the clock. See the `keri-manager` fixture.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PublicKeyLot {
    /// Qualified public keys, in signing order.
    pub public_keys: Vec<String>,
    /// Which establishment event uses this set, counting inception as zero.
    pub rotation_index: u32,
    /// Index of the first key of this set among all the identifier's keys.
    pub key_index: u32,
}

impl PublicKeyLot {
    /// Returns whether this set holds no keys, which is how an abandoned identifier is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.public_keys.is_empty()
    }
}

/// The three key sets one identifier has: retired, current, and committed-to.
///
/// This is the reference's `PreSit`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrefixSituation {
    /// Keys retired by the last rotation.
    pub old: PublicKeyLot,
    /// Keys currently signing.
    pub current: PublicKeyLot,
    /// Keys the current establishment event commits to.
    pub next: PublicKeyLot,
}

/// Everything needed to derive one key again, for an identifier held without encryption.
///
/// This is the reference's `PubPath`. It carries no derivation code, because this port derives
/// Ed25519 only, and one profile rather than a tier and a `temp` flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredPath {
    /// The path itself.
    pub path: DerivationPath,
    /// The cost profile it was derived under.
    pub profile: KeyDerivationProfile,
}

/// The key a set of public keys is stored under: an identifier and a rotation index.
///
/// This is the reference's `riKey`, which writes the rotation index as hexadecimal padded to
/// thirty-two characters so that keys sort in rotation order.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RotationKey {
    text: String,
}

impl RotationKey {
    /// Builds the key for one rotation of one identifier.
    #[must_use]
    pub fn new(prefix: &str, rotation_index: u32) -> Self {
        Self {
            text: format!("{prefix}.{rotation_index:032x}"),
        }
    }

    /// Returns the key as stored.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// The state one key manager keeps.
///
/// A store assembled by hand is how saved state is restored; see
/// [`KeyManager::restore`](super::KeyManager::restore).
#[derive(Clone, Debug, Default)]
pub struct KeyStore {
    globals: Option<ManagerGlobals>,
    parameters: BTreeMap<String, PrefixParameters>,
    situations: BTreeMap<String, PrefixSituation>,
    sealed_keys: BTreeMap<String, String>,
    paths: BTreeMap<String, StoredPath>,
    aliases: BTreeMap<String, String>,
    key_sets: BTreeMap<String, Vec<String>>,
}

impl KeyStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the manager-wide state, if it has been set.
    #[must_use]
    pub const fn globals(&self) -> Option<&ManagerGlobals> {
        self.globals.as_ref()
    }

    /// Replaces the manager-wide state.
    pub fn set_globals(&mut self, globals: ManagerGlobals) {
        self.globals = Some(globals);
    }

    /// Returns what one identifier's keys were created from.
    #[must_use]
    pub fn parameters(&self, prefix: &str) -> Option<&PrefixParameters> {
        self.parameters.get(prefix)
    }

    /// Records parameters for an identifier that has none yet.
    ///
    /// Returns `false` and changes nothing when the identifier already has parameters, which is
    /// the reference's `put` semantics as distinct from its `pin`.
    pub fn insert_parameters(&mut self, prefix: &str, parameters: PrefixParameters) -> bool {
        insert_new(&mut self.parameters, prefix, parameters)
    }

    /// Replaces one identifier's parameters whether or not it had any.
    pub fn replace_parameters(&mut self, prefix: &str, parameters: PrefixParameters) {
        self.parameters.insert(prefix.to_owned(), parameters);
    }

    /// Forgets one identifier's parameters, reporting whether there were any.
    pub fn remove_parameters(&mut self, prefix: &str) -> bool {
        self.parameters.remove(prefix).is_some()
    }

    /// Returns one identifier's three key sets.
    #[must_use]
    pub fn situation(&self, prefix: &str) -> Option<&PrefixSituation> {
        self.situations.get(prefix)
    }

    /// Records key sets for an identifier that has none yet.
    ///
    /// Returns `false` and changes nothing when the identifier already has them.
    pub fn insert_situation(&mut self, prefix: &str, situation: PrefixSituation) -> bool {
        insert_new(&mut self.situations, prefix, situation)
    }

    /// Replaces one identifier's key sets whether or not it had any.
    pub fn replace_situation(&mut self, prefix: &str, situation: PrefixSituation) {
        self.situations.insert(prefix.to_owned(), situation);
    }

    /// Forgets one identifier's key sets, reporting whether there were any.
    pub fn remove_situation(&mut self, prefix: &str) -> bool {
        self.situations.remove(prefix).is_some()
    }

    /// Returns the sealed private key for one public key.
    #[must_use]
    pub fn sealed_key(&self, public_key: &str) -> Option<&str> {
        self.sealed_keys.get(public_key).map(String::as_str)
    }

    /// Records a sealed private key for a public key that has none yet.
    ///
    /// Returns `false` and changes nothing when one is already stored.
    pub fn insert_sealed_key(&mut self, public_key: &str, ciphertext: String) -> bool {
        insert_new(&mut self.sealed_keys, public_key, ciphertext)
    }

    /// Replaces the sealed private key for one public key.
    pub fn replace_sealed_key(&mut self, public_key: &str, ciphertext: String) {
        self.sealed_keys.insert(public_key.to_owned(), ciphertext);
    }

    /// Erases the sealed private key for one public key.
    pub fn remove_sealed_key(&mut self, public_key: &str) {
        self.sealed_keys.remove(public_key);
    }

    /// Returns how many sealed private keys are held.
    #[must_use]
    pub fn sealed_key_count(&self) -> usize {
        self.sealed_keys.len()
    }

    /// Returns the derivation path for one public key.
    #[must_use]
    pub fn path(&self, public_key: &str) -> Option<&StoredPath> {
        self.paths.get(public_key)
    }

    /// Records a derivation path for a public key that has none yet.
    ///
    /// Returns `false` and changes nothing when one is already stored.
    pub fn insert_path(&mut self, public_key: &str, path: StoredPath) -> bool {
        insert_new(&mut self.paths, public_key, path)
    }

    /// Returns what one identifier prefix currently resolves to.
    ///
    /// An identifier is incepted under the public key of its first signer and later reassigned to
    /// its real prefix, so this maps the one to the other.
    #[must_use]
    pub fn alias(&self, prefix: &str) -> Option<&str> {
        self.aliases.get(prefix).map(String::as_str)
    }

    /// Records an alias for a prefix that has none yet.
    ///
    /// Returns `false` and changes nothing when one is already recorded.
    pub fn insert_alias(&mut self, prefix: &str, target: String) -> bool {
        insert_new(&mut self.aliases, prefix, target)
    }

    /// Replaces the alias for one prefix.
    pub fn replace_alias(&mut self, prefix: &str, target: String) {
        self.aliases.insert(prefix.to_owned(), target);
    }

    /// Returns the public keys recorded for one rotation of one identifier.
    #[must_use]
    pub fn key_set(&self, key: &RotationKey) -> Option<&[String]> {
        self.key_sets.get(key.as_str()).map(Vec::as_slice)
    }

    /// Records public keys for a rotation that has none yet.
    ///
    /// Returns `false` and changes nothing when they are already recorded.
    pub fn insert_key_set(&mut self, key: &RotationKey, public_keys: Vec<String>) -> bool {
        insert_new(&mut self.key_sets, key.as_str(), public_keys)
    }
}

/// Inserts only when the key is absent, reporting whether it was.
fn insert_new<T>(map: &mut BTreeMap<String, T>, key: &str, value: T) -> bool {
    if map.contains_key(key) {
        return false;
    }
    map.insert(key.to_owned(), value);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    fn parameters() -> Result<PrefixParameters, Box<dyn Error>> {
        Ok(PrefixParameters {
            prefix_index: 0,
            algorithm: KeyAlgorithm::Salty,
            sealed_salt: None,
            stem: Stem::new("red")?,
            tier: Some(SecurityTier::Low),
        })
    }

    #[test]
    fn inserting_twice_leaves_the_first_value_and_replacing_does_not() -> Result<(), Box<dyn Error>> {
        let mut store = KeyStore::new();
        assert!(store.insert_parameters("EABC", parameters()?));
        assert!(!store.insert_parameters("EABC", {
            let mut other = parameters()?;
            other.prefix_index = 9;
            other
        }));
        assert_eq!(store.parameters("EABC").map(|value| value.prefix_index), Some(0));

        store.replace_parameters("EABC", {
            let mut other = parameters()?;
            other.prefix_index = 9;
            other
        });
        assert_eq!(store.parameters("EABC").map(|value| value.prefix_index), Some(9));
        assert!(store.remove_parameters("EABC"));
        assert!(!store.remove_parameters("EABC"));
        assert_eq!(store.parameters("EABC"), None);
        Ok(())
    }

    #[test]
    fn every_map_follows_the_same_insert_and_replace_rules() {
        let mut store = KeyStore::new();

        assert!(store.insert_situation("EABC", PrefixSituation::default()));
        assert!(!store.insert_situation("EABC", PrefixSituation::default()));
        assert!(store.situation("EABC").is_some());
        store.replace_situation("EABC", PrefixSituation::default());
        assert!(store.remove_situation("EABC"));
        assert!(!store.remove_situation("EABC"));

        assert!(store.insert_sealed_key("DABC", "0ABC".to_owned()));
        assert!(!store.insert_sealed_key("DABC", "0DEF".to_owned()));
        assert_eq!(store.sealed_key("DABC"), Some("0ABC"));
        store.replace_sealed_key("DABC", "0DEF".to_owned());
        assert_eq!(store.sealed_key("DABC"), Some("0DEF"));
        assert_eq!(store.sealed_key_count(), 1);
        store.remove_sealed_key("DABC");
        assert_eq!(store.sealed_key("DABC"), None);
        assert_eq!(store.sealed_key_count(), 0);

        assert!(store.insert_alias("EABC", "EDEF".to_owned()));
        assert!(!store.insert_alias("EABC", "EGHI".to_owned()));
        assert_eq!(store.alias("EABC"), Some("EDEF"));
        store.replace_alias("EABC", "EGHI".to_owned());
        assert_eq!(store.alias("EABC"), Some("EGHI"));

        let key = RotationKey::new("EABC", 0);
        assert!(store.insert_key_set(&key, vec!["DABC".to_owned()]));
        assert!(!store.insert_key_set(&key, vec!["DDEF".to_owned()]));
        assert_eq!(store.key_set(&key), Some(["DABC".to_owned()].as_slice()));
        assert_eq!(store.key_set(&RotationKey::new("EABC", 1)), None);
    }

    #[test]
    fn a_stored_path_carries_one_profile_rather_than_a_tier_and_a_flag() -> Result<(), Box<dyn Error>> {
        let mut store = KeyStore::new();
        let path = StoredPath {
            path: DerivationPath::new(&Stem::empty(), super::super::KeyIndices::inception(0))?,
            profile: KeyDerivationProfile::Temporary,
        };
        assert!(store.insert_path("DABC", path.clone()));
        assert!(!store.insert_path("DABC", path.clone()));
        assert_eq!(store.path("DABC"), Some(&path));
        assert_eq!(store.path("DDEF"), None);
        Ok(())
    }

    #[test]
    fn an_empty_lot_is_how_an_abandoned_identifier_is_recorded() {
        assert!(PublicKeyLot::default().is_empty());
        let lot = PublicKeyLot {
            public_keys: vec!["DABC".to_owned()],
            rotation_index: 1,
            key_index: 1,
        };
        assert!(!lot.is_empty());
    }

    #[test]
    fn globals_start_absent() {
        let mut store = KeyStore::new();
        assert!(store.globals().is_none());
        store.set_globals(ManagerGlobals {
            encryption_identifier: None,
            prefix_index: 0,
            algorithm: KeyAlgorithm::Salty,
            sealed_salt: None,
            tier: SecurityTier::Low,
        });
        assert_eq!(store.globals().map(|globals| globals.prefix_index), Some(0));
    }
}
