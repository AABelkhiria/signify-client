//! The key manager: inception, rotation, signing, and reassignment for managed identifiers.
//!
//! # Encryption is all or nothing
//!
//! The reference holds an encryption identifier, an encrypter, a decrypter, and a seed as four
//! independent fields, and then guards against the combinations that cannot work — "Unauthorized
//! decryption attempt. Aeid but no decrypter." appears twice. Here one optional value holds all of
//! them, derived from the seed signer the caller supplies, so a manager either can seal and open
//! private keys or does not claim to. The identifier *is* the seed's public key, so only
//! [`KeyManager::restore`] has anything to check: it compares the seed with the saved identifier.
//!
//! # Two ways a private key is recovered
//!
//! With encryption, every private key is sealed into the store and opened again when it is needed.
//! Without it — which only the salty algorithm allows — nothing is stored but the derivation path,
//! and the key is derived again. [`KeyManager::sign`] takes whichever route the manager is
//! configured for.

use keri_cesr::crypto::cipher::{Ciphertext, Decrypter, Encrypter};
use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::{KeyTransferability, VerificationKey};
use zeroize::Zeroizing;

use super::algorithm::{CreatorKind, KeyAlgorithm};
use super::creator::{CreatedKeys, KeyCreator, KeyIndices, RandyKeyCreator, SaltyKeyCreator, Stem};
use super::error::ManagerError;
use super::store::{
    KeyStore, ManagerGlobals, PrefixParameters, PrefixSituation, PublicKeyLot, RotationKey, StoredPath,
};

/// Characters of a passcode that become salt material.
///
/// The reference prefixes a salt code and one padding character to the first twenty-one characters
/// of the passcode, making a twenty-four-character qualified salt.
pub const PASSCODE_LENGTH: usize = 21;

/// The qualified-salt code a passcode is turned into.
const SALT_CODE: &str = "0A";

/// What a manager can do with private keys.
struct Encryption {
    identifier: String,
    encrypter: Encrypter,
    decrypter: Decrypter,
}

/// What to do with the private keys a rotation retires.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RetiredKeyPolicy {
    /// Erase them, so a compromised store cannot sign with a key the log has moved past.
    #[default]
    Erase,
    /// Keep them, which only an archive that must re-verify old signatures needs.
    Keep,
}

/// How a signing request wants its signatures placed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureForm {
    /// Indexed signatures placed at each key's position in the request.
    ///
    /// This is the reference's default: index and prior index both take the position.
    IndexedByPosition,
    /// Indexed signatures at explicit placements, one per key.
    Indexed(Vec<SignaturePlacement>),
    /// Unindexed signatures, which carry no position at all.
    Unindexed,
}

/// The signatures one request produced.
#[derive(Debug)]
pub enum ManagedSignatures {
    /// Indexed signatures, in request order.
    Indexed(Vec<IndexedSignature>),
    /// Unindexed signatures, in request order.
    Unindexed(Vec<UnindexedSignature>),
}

impl ManagedSignatures {
    /// Returns how many signatures were produced.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Indexed(signatures) => signatures.len(),
            Self::Unindexed(signatures) => signatures.len(),
        }
    }

    /// Returns whether no signatures were produced.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns every signature as qualified Base64, in request order.
    ///
    /// # Errors
    ///
    /// Returns a layered [`ManagerError::Crypto`] when a signature cannot be encoded.
    pub fn qb64(&self) -> Result<Vec<String>, ManagerError> {
        match self {
            Self::Indexed(signatures) => signatures
                .iter()
                .map(|signature| signature.qb64().map_err(ManagerError::from))
                .collect(),
            Self::Unindexed(signatures) => signatures
                .iter()
                .map(|signature| signature.qb64().map_err(ManagerError::from))
                .collect(),
        }
    }
}

/// What to create when incepting an identifier.
#[derive(Debug)]
pub struct InceptionRequest {
    /// How many keys sign the inception event. At least one, because the prefix comes from the
    /// first of them.
    pub current_keys: usize,
    /// How many keys the inception commits to. Zero abandons the identifier immediately.
    pub next_keys: usize,
    /// Algorithm to use, or the manager's own when absent.
    pub algorithm: Option<KeyAlgorithm>,
    /// Salt to derive from, or the manager's own when absent. Unused by the randy algorithm.
    pub salt: Option<Salt>,
    /// Stem every derivation path starts with.
    pub stem: Stem,
    /// Whether the identifier may rotate.
    pub transferability: KeyTransferability,
    /// Derivation cost. A standard profile's tier is recorded, and rotations derive under it.
    pub profile: KeyDerivationProfile,
    /// Digest algorithm committing to the next keys.
    pub digest: DigestAlgorithm,
}

impl Default for InceptionRequest {
    fn default() -> Self {
        Self {
            current_keys: 1,
            next_keys: 1,
            algorithm: None,
            salt: None,
            stem: Stem::empty(),
            transferability: KeyTransferability::Transferable,
            profile: KeyDerivationProfile::Standard(SecurityTier::Low),
            digest: DigestAlgorithm::Blake3_256,
        }
    }
}

/// What to create when rotating an identifier.
#[derive(Debug)]
pub struct RotationRequest {
    /// Identifier to rotate.
    pub prefix: String,
    /// How many keys the rotation commits to. Zero abandons the identifier.
    pub next_keys: usize,
    /// Whether the new keys may rotate again.
    pub transferability: KeyTransferability,
    /// Derivation cost for the new keys. An identifier's recorded tier overrides a standard profile.
    pub profile: KeyDerivationProfile,
    /// Digest algorithm committing to the new keys.
    pub digest: DigestAlgorithm,
    /// What to do with the keys this rotation retires.
    pub retired_keys: RetiredKeyPolicy,
}

impl RotationRequest {
    /// Creates a request to rotate one identifier with the reference's defaults.
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            next_keys: 1,
            transferability: KeyTransferability::Transferable,
            profile: KeyDerivationProfile::Standard(SecurityTier::Low),
            digest: DigestAlgorithm::Blake3_256,
            retired_keys: RetiredKeyPolicy::Erase,
        }
    }
}

/// The keys an inception established.
#[derive(Debug)]
pub struct InceptedKeys {
    /// The identifier prefix, which is the first current public key.
    pub prefix: String,
    /// Keys that sign the inception event, in order.
    pub verifiers: Vec<VerificationKey>,
    /// Digests committing to the next keys, in order.
    pub next_digests: Vec<Digest>,
}

/// The keys a rotation established.
#[derive(Debug)]
pub struct RotatedKeys {
    /// Keys that now sign, in order.
    pub verifiers: Vec<VerificationKey>,
    /// Digests committing to the next keys, in order.
    pub next_digests: Vec<Digest>,
}

/// Creates a key manager.
#[derive(Debug, Default)]
pub struct KeyManagerBuilder {
    store: Option<KeyStore>,
    prefix_index: u32,
    algorithm: Option<KeyAlgorithm>,
    salt: Option<Salt>,
    tier: Option<SecurityTier>,
}

impl KeyManagerBuilder {
    /// Restores a manager over state saved earlier.
    #[must_use]
    pub fn store(mut self, store: KeyStore) -> Self {
        self.store = Some(store);
        self
    }

    /// Sets the index the next incepted identifier takes.
    #[must_use]
    pub const fn prefix_index(mut self, index: u32) -> Self {
        self.prefix_index = index;
        self
    }

    /// Sets the algorithm new identifiers use by default.
    #[must_use]
    pub const fn algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Sets the salt new identifiers derive from.
    #[must_use]
    pub fn salt(mut self, salt: Salt) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Sets the tier recorded for new identifiers.
    #[must_use]
    pub const fn tier(mut self, tier: SecurityTier) -> Self {
        self.tier = Some(tier);
        self
    }

    /// Builds a manager that stores private keys sealed to `seed`'s public key.
    ///
    /// # Errors
    ///
    /// Returns a layered [`ManagerError::Crypto`] when the seed cannot be turned into an
    /// encryption key pair.
    pub fn build_encrypted(self, seed: &Signer) -> Result<KeyManager, ManagerError> {
        let encryption = Encryption {
            identifier: seed.verifier().qb64()?,
            encrypter: Encrypter::from_verification_key(seed.verifier())?,
            decrypter: Decrypter::from_signer(seed),
        };
        self.assemble(Some(encryption))
    }

    /// Builds a manager that stores no private keys and derives them again when needed.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::RandomKeysNeedEncryption`] when the default algorithm is randy,
    /// whose keys cannot be derived again and so would have to be held in the clear.
    pub fn build(self) -> Result<KeyManager, ManagerError> {
        self.assemble(None)
    }

    fn assemble(self, encryption: Option<Encryption>) -> Result<KeyManager, ManagerError> {
        let algorithm = self.algorithm.unwrap_or_default();
        if algorithm.needs_stored_keys() && encryption.is_none() {
            return Err(ManagerError::RandomKeysNeedEncryption);
        }

        let tier = self
            .tier
            .or_else(|| self.salt.as_ref().map(Salt::tier))
            .unwrap_or_default();
        let sealed_salt = match (&encryption, &self.salt) {
            (Some(encryption), Some(salt)) => Some(encryption.encrypter.encrypt_salt(salt)?.qb64()?),
            _ => None,
        };

        let mut store = self.store.unwrap_or_default();
        store.set_globals(ManagerGlobals {
            encryption_identifier: encryption.as_ref().map(|encryption| encryption.identifier.clone()),
            prefix_index: self.prefix_index,
            algorithm,
            sealed_salt,
            tier,
        });

        Ok(KeyManager {
            store,
            salt: self.salt,
            encryption,
        })
    }
}

/// How one new private key will be recovered.
enum RetainedKey {
    Sealed(String),
    Derivable(StoredPath),
}

/// Creates, stores, rotates, and signs with the keys of the identifiers one controller holds.
///
/// ```
/// use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
/// use signify_keys::manager::{InceptionRequest, KeyManager};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?;
/// let mut manager = KeyManager::builder().salt(salt).build()?;
///
/// let incepted = manager.incept(InceptionRequest {
///     profile: KeyDerivationProfile::Temporary,
///     ..InceptionRequest::default()
/// })?;
///
/// assert_eq!(incepted.prefix, "DB-fH5uto5o5XHZjNN3_W3PdT4MIyTCmQWDzMxMZV2kI");
/// assert_eq!(incepted.next_digests.len(), 1);
/// assert_eq!(manager.prefix_index(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct KeyManager {
    store: KeyStore,
    salt: Option<Salt>,
    encryption: Option<Encryption>,
}

impl core::fmt::Debug for Encryption {
    /// Names the encryption identifier, which is public, and nothing else.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Encryption")
            .field("identifier", &self.identifier)
            .finish_non_exhaustive()
    }
}

impl KeyManager {
    /// Starts building a manager.
    #[must_use]
    pub fn builder() -> KeyManagerBuilder {
        KeyManagerBuilder::default()
    }

    /// Builds a manager from a passcode, exactly as the reference's `openManager` does.
    ///
    /// The first [`PASSCODE_LENGTH`] characters become a qualified salt, which derives the seed
    /// that private keys are sealed to. Supplying a salt selects the salty algorithm; omitting one
    /// selects randy.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::PasscodeTooShort`] below [`PASSCODE_LENGTH`] characters,
    /// [`ManagerError::InvalidPasscode`] for a character outside the Base64 URL-safe alphabet, and
    /// a layered [`ManagerError::Crypto`] when derivation fails.
    pub fn from_passcode(passcode: &str, salt: Option<Salt>) -> Result<Self, ManagerError> {
        let passcode_salt = salt_from_passcode(passcode, SecurityTier::Low)?;
        let seed = passcode_salt.derive_signer("", KeyTransferability::NonTransferable)?;

        let algorithm = if salt.is_some() {
            KeyAlgorithm::Salty
        } else {
            KeyAlgorithm::Randy
        };
        let mut builder = Self::builder().algorithm(algorithm);
        if let Some(salt) = salt {
            builder = builder.salt(salt);
        }
        builder.build_encrypted(&seed)
    }

    /// Restores a manager over saved state, sealing private keys to `seed`'s public key.
    ///
    /// Without a `salt`, the one sealed in the store is opened.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::SeedDoesNotMatchIdentifier`] when the store's keys are sealed to
    /// another seed, a layered [`ManagerError::Crypto`] when its salt cannot be opened, and
    /// whatever [`KeyManagerBuilder::build_encrypted`] returns.
    pub fn restore(store: KeyStore, mut salt: Option<Salt>, seed: &Signer) -> Result<Self, ManagerError> {
        let globals = store.globals().cloned();
        let mut builder = Self::builder().store(store);
        if let Some(globals) = globals {
            if let Some(identifier) = &globals.encryption_identifier
                && *identifier != seed.verifier().qb64()?
            {
                return Err(ManagerError::SeedDoesNotMatchIdentifier);
            }
            if salt.is_none()
                && let Some(sealed) = &globals.sealed_salt
            {
                let decrypter = Decrypter::from_signer(seed);
                salt = Some(decrypter.decrypt_salt(&Ciphertext::from_qb64(sealed)?, globals.tier)?);
            }
            builder = builder
                .prefix_index(globals.prefix_index)
                .algorithm(globals.algorithm)
                .tier(globals.tier);
        }
        if let Some(salt) = salt {
            builder = builder.salt(salt);
        }
        builder.build_encrypted(seed)
    }

    /// Returns the state this manager keeps.
    #[must_use]
    pub const fn store(&self) -> &KeyStore {
        &self.store
    }

    /// Returns the index the next incepted identifier will take.
    #[must_use]
    pub fn prefix_index(&self) -> u32 {
        self.globals().map_or(0, |globals| globals.prefix_index)
    }

    /// Returns the algorithm new identifiers use by default.
    #[must_use]
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.globals()
            .map_or_else(KeyAlgorithm::default, |globals| globals.algorithm)
    }

    /// Returns the tier new identifiers derive under.
    #[must_use]
    pub fn tier(&self) -> SecurityTier {
        self.globals()
            .map_or_else(SecurityTier::default, |globals| globals.tier)
    }

    /// Returns the public key private keys are sealed to, if this manager seals any.
    #[must_use]
    pub fn encryption_identifier(&self) -> Option<&str> {
        self.encryption
            .as_ref()
            .map(|encryption| encryption.identifier.as_str())
    }

    /// Returns the salt this manager derives from, if it has one.
    #[must_use]
    pub const fn salt(&self) -> Option<&Salt> {
        self.salt.as_ref()
    }

    fn globals(&self) -> Option<&ManagerGlobals> {
        self.store.globals()
    }

    /// Establishes a new identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::NoCurrentKeys`] for an inception with no signing keys,
    /// [`ManagerError::MissingSalt`] when the salty algorithm has no salt,
    /// [`ManagerError::RandomKeysNeedEncryption`] for random keys with nothing to seal them,
    /// [`ManagerError::AlreadyIncepted`] when the derived prefix is already held,
    /// [`ManagerError::IndexOverflow`] when an index would wrap, and whatever key creation returns.
    pub fn incept(&mut self, request: InceptionRequest) -> Result<InceptedKeys, ManagerError> {
        if request.current_keys == 0 {
            return Err(ManagerError::NoCurrentKeys);
        }
        let algorithm = request.algorithm.unwrap_or_else(|| self.algorithm());
        let prefix_index = self.prefix_index();
        let next_key_index =
            u32::try_from(request.current_keys).map_err(|_| ManagerError::IndexOverflow { index: "key" })?;

        let salt = match algorithm.creator_kind()? {
            CreatorKind::Salty => Some(
                request
                    .salt
                    .as_ref()
                    .or(self.salt.as_ref())
                    .ok_or(ManagerError::MissingSalt)?,
            ),
            CreatorKind::Randy => None,
        };
        let creator = match salt {
            Some(salt) => KeyCreator::Salty(SaltyKeyCreator::new(salt, request.stem.clone())),
            None => KeyCreator::Randy(RandyKeyCreator::new()),
        };

        let current = creator.create(
            request.current_keys,
            request.transferability,
            KeyIndices::new(prefix_index, 0, 0),
            request.profile,
        )?;
        let next = creator.create(
            request.next_keys,
            request.transferability,
            KeyIndices::new(prefix_index, 1, next_key_index),
            request.profile,
        )?;

        let verifiers: Vec<VerificationKey> = current.signers().map(|signer| signer.verifier().clone()).collect();
        let next_digests = digests(&next, request.digest)?;
        let current_keys = current.public_keys()?;
        let next_keys = next.public_keys()?;
        let prefix = current_keys.first().ok_or(ManagerError::NoCurrentKeys)?.clone();

        let parameters = PrefixParameters {
            prefix_index,
            algorithm,
            sealed_salt: match (&self.encryption, salt) {
                (Some(encryption), Some(salt)) => Some(encryption.encrypter.encrypt_salt(salt)?.qb64()?),
                _ => None,
            },
            stem: request.stem,
            tier: salt.map(|salt| match request.profile {
                KeyDerivationProfile::Standard(tier) => tier,
                _ => salt.tier(),
            }),
        };
        let situation = PrefixSituation {
            old: PublicKeyLot::default(),
            current: PublicKeyLot {
                public_keys: current_keys.clone(),
                rotation_index: 0,
                key_index: 0,
            },
            next: PublicKeyLot {
                public_keys: next_keys.clone(),
                rotation_index: 1,
                key_index: next_key_index,
            },
        };

        if self.store.alias(&prefix).is_some()
            || self.store.parameters(&prefix).is_some()
            || self.store.situation(&prefix).is_some()
        {
            return Err(ManagerError::AlreadyIncepted { prefix });
        }

        // Everything that can fail comes first, so a failed inception leaves no trace.
        let retained_current = self.prepare(current, request.profile)?;
        let retained_next = self.prepare(next, request.profile)?;
        self.advance_prefix_index()?;

        self.store.insert_alias(&prefix, prefix.clone());
        self.store.insert_parameters(&prefix, parameters);
        self.store.insert_situation(&prefix, situation);
        self.retain(retained_current);
        self.retain(retained_next);
        self.store.insert_key_set(&RotationKey::new(&prefix, 0), current_keys);
        self.store.insert_key_set(&RotationKey::new(&prefix, 1), next_keys);

        Ok(InceptedKeys {
            prefix,
            verifiers,
            next_digests,
        })
    }

    /// Rotates an identifier to the keys it committed to, and commits to new ones.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::NotIncepted`] for an unknown identifier, [`ManagerError::Abandoned`]
    /// when it committed to no next keys, [`ManagerError::SaltDecryptionUnavailable`] when its salt
    /// is sealed and this manager cannot open it, and whatever key creation returns.
    pub fn rotate(&mut self, request: RotationRequest) -> Result<RotatedKeys, ManagerError> {
        let prefix = request.prefix;
        let parameters = self
            .store
            .parameters(&prefix)
            .cloned()
            .ok_or_else(|| ManagerError::NotIncepted { prefix: prefix.clone() })?;
        let mut situation = self
            .store
            .situation(&prefix)
            .cloned()
            .ok_or_else(|| ManagerError::NotIncepted { prefix: prefix.clone() })?;
        if situation.next.is_empty() {
            return Err(ManagerError::Abandoned { prefix });
        }

        let retired = situation.old.clone();
        situation.old = situation.current;
        situation.current = situation.next.clone();

        let verifiers = situation
            .current
            .public_keys
            .iter()
            .map(|public_key| verifier(public_key))
            .collect::<Result<Vec<_>, _>>()?;

        // The identifier's own salt when it has one, otherwise the manager's.
        let identifier_salt = self.open_identifier_salt(&parameters)?;
        let salt = match parameters.algorithm.creator_kind()? {
            CreatorKind::Salty => Some(
                identifier_salt
                    .as_ref()
                    .or(self.salt.as_ref())
                    .ok_or(ManagerError::MissingSalt)?,
            ),
            CreatorKind::Randy => None,
        };
        let creator = match salt {
            Some(salt) => KeyCreator::Salty(SaltyKeyCreator::new(salt, parameters.stem.clone())),
            None => KeyCreator::Randy(RandyKeyCreator::new()),
        };

        // The reference reads `ps.nxt` here, which by now aliases `ps.new`; both spellings give
        // the current set, so the key index advances past the keys that just became current.
        let rotation_index = situation
            .current
            .rotation_index
            .checked_add(1)
            .ok_or(ManagerError::IndexOverflow { index: "rotation" })?;
        let key_index = situation
            .current
            .key_index
            .checked_add(
                u32::try_from(situation.current.public_keys.len())
                    .map_err(|_| ManagerError::IndexOverflow { index: "key" })?,
            )
            .ok_or(ManagerError::IndexOverflow { index: "key" })?;

        let profile = match (request.profile, parameters.tier) {
            (KeyDerivationProfile::Standard(_), Some(tier)) => KeyDerivationProfile::Standard(tier),
            (profile, _) => profile,
        };
        let created = creator.create(
            request.next_keys,
            request.transferability,
            KeyIndices::new(parameters.prefix_index, rotation_index, key_index),
            profile,
        )?;
        let next_digests = digests(&created, request.digest)?;
        let next_keys = created.public_keys()?;
        let retained = self.prepare(created, profile)?;

        situation.next = PublicKeyLot {
            public_keys: next_keys.clone(),
            rotation_index,
            key_index,
        };
        // An empty stem reuses one key at every position, so a retired key can still be in use.
        let in_use =
            |key: &String| situation.current.public_keys.contains(key) || situation.next.public_keys.contains(key);
        let erased: Vec<String> = match request.retired_keys {
            RetiredKeyPolicy::Erase => retired.public_keys.into_iter().filter(|key| !in_use(key)).collect(),
            RetiredKeyPolicy::Keep => Vec::new(),
        };

        self.store.replace_situation(&prefix, situation);
        self.retain(retained);
        self.store
            .insert_key_set(&RotationKey::new(&prefix, rotation_index), next_keys);
        for public_key in &erased {
            self.store.remove_sealed_key(public_key);
        }

        Ok(RotatedKeys {
            verifiers,
            next_digests,
        })
    }

    /// Signs one serialization with the named managed keys.
    ///
    /// The reference offers this twice, once taking qualified public keys and once taking
    /// verification keys; both resolve to the same private keys and produce the same signatures,
    /// which its own unit test asserts, so there is one method here.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::NoSigningKeysRequested`] for an empty request,
    /// [`ManagerError::PlacementCountMismatch`] when explicit placements do not match the keys,
    /// [`ManagerError::MissingPrivateKey`] when a key is not held, and whatever signing returns.
    pub fn sign(
        &self,
        serialization: &[u8],
        public_keys: &[String],
        form: &SignatureForm,
    ) -> Result<ManagedSignatures, ManagerError> {
        if public_keys.is_empty() {
            return Err(ManagerError::NoSigningKeysRequested);
        }
        if let SignatureForm::Indexed(placements) = form
            && placements.len() != public_keys.len()
        {
            return Err(ManagerError::PlacementCountMismatch {
                placements: placements.len(),
                keys: public_keys.len(),
            });
        }

        let signers = public_keys
            .iter()
            .map(|public_key| self.signer(public_key))
            .collect::<Result<Vec<_>, _>>()?;

        match form {
            SignatureForm::Unindexed => {
                let signatures = signers
                    .iter()
                    .map(|signer| signer.sign_unindexed(serialization).map_err(ManagerError::from))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ManagedSignatures::Unindexed(signatures))
            }
            SignatureForm::IndexedByPosition => {
                let signatures = signers
                    .iter()
                    .enumerate()
                    .map(|(position, signer)| {
                        let index =
                            u32::try_from(position).map_err(|_| ManagerError::IndexOverflow { index: "signature" })?;
                        signer
                            .sign_indexed(serialization, SignaturePlacement::both_lists(index))
                            .map_err(ManagerError::from)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ManagedSignatures::Indexed(signatures))
            }
            SignatureForm::Indexed(placements) => {
                let signatures = signers
                    .iter()
                    .zip(placements)
                    .map(|(signer, placement)| {
                        signer
                            .sign_indexed(serialization, *placement)
                            .map_err(ManagerError::from)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ManagedSignatures::Indexed(signatures))
            }
        }
    }

    /// Reassigns everything held under one prefix to another.
    ///
    /// An identifier is incepted under its first public key and moved to its real prefix once that
    /// is derived, which is what this is for.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::NotIncepted`] when the source is unknown and
    /// [`ManagerError::DestinationOccupied`] when the destination is already held.
    pub fn reassign(&mut self, from: &str, to: &str) -> Result<(), ManagerError> {
        if from == to {
            return Ok(());
        }
        if self.store.alias(from).is_none() || self.store.parameters(from).is_none() {
            return Err(ManagerError::NotIncepted {
                prefix: from.to_owned(),
            });
        }
        if self.store.alias(to).is_some() || self.store.parameters(to).is_some() {
            return Err(ManagerError::DestinationOccupied { prefix: to.to_owned() });
        }

        let parameters = self
            .store
            .parameters(from)
            .cloned()
            .ok_or_else(|| ManagerError::NotIncepted {
                prefix: from.to_owned(),
            })?;
        let situation = self
            .store
            .situation(from)
            .cloned()
            .ok_or_else(|| ManagerError::NotIncepted {
                prefix: from.to_owned(),
            })?;

        self.store.insert_parameters(to, parameters);
        self.store.remove_parameters(from);
        self.store.insert_situation(to, situation);
        self.store.remove_situation(from);

        let mut rotation_index = 0_u32;
        while let Some(public_keys) = self
            .store
            .key_set(&RotationKey::new(from, rotation_index))
            .map(<[String]>::to_vec)
        {
            self.store
                .insert_key_set(&RotationKey::new(to, rotation_index), public_keys);
            rotation_index = match rotation_index.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }

        self.store.replace_alias(from, to.to_owned());
        self.store.insert_alias(to, to.to_owned());
        Ok(())
    }

    /// Recovers the private key for a managed public key, by opening it or by deriving it again.
    fn signer(&self, public_key: &str) -> Result<Signer, ManagerError> {
        let transferability = verifier(public_key)?.transferability();
        let missing = || ManagerError::MissingPrivateKey {
            public_key: public_key.to_owned(),
        };

        if let Some(encryption) = &self.encryption {
            let sealed = self.store.sealed_key(public_key).ok_or_else(missing)?;
            return Ok(encryption
                .decrypter
                .decrypt_seed(&Ciphertext::from_qb64(sealed)?, transferability)?);
        }

        let stored = self.store.path(public_key).cloned().ok_or_else(missing)?;
        let salt = self.salt.as_ref().ok_or(ManagerError::MissingSalt)?;
        Ok(salt.derive_signer_with_profile(stored.path.as_str(), transferability, stored.profile)?)
    }

    /// Opens the identifier's own sealed salt, if it has one.
    fn open_identifier_salt(&self, parameters: &PrefixParameters) -> Result<Option<Salt>, ManagerError> {
        let Some(sealed) = &parameters.sealed_salt else {
            return Ok(None);
        };
        let encryption = self
            .encryption
            .as_ref()
            .ok_or(ManagerError::SaltDecryptionUnavailable)?;
        let tier = parameters.tier.unwrap_or_else(|| self.tier());
        Ok(Some(
            encryption
                .decrypter
                .decrypt_salt(&Ciphertext::from_qb64(sealed)?, tier)?,
        ))
    }

    /// Works out what to store for new keys, without storing it yet.
    fn prepare(
        &self,
        keys: CreatedKeys,
        profile: KeyDerivationProfile,
    ) -> Result<Vec<(String, RetainedKey)>, ManagerError> {
        let mut prepared = Vec::new();
        for (signer, path) in keys.into_entries() {
            let public_key = signer.verifier().qb64()?;
            let retained = match (&self.encryption, path) {
                (Some(encryption), _) => RetainedKey::Sealed(encryption.encrypter.encrypt_signer(&signer)?.qb64()?),
                (None, Some(path)) => {
                    // The reference forgets the derivation code when a *rotation* stores a path,
                    // which leaves the rotated key unusable for signing; there is no separate code
                    // here to forget, and the profile is the one the key was actually derived
                    // under. See the `keri-manager` fixture.
                    RetainedKey::Derivable(StoredPath { path, profile })
                }
                (None, None) => return Err(ManagerError::RandomKeysNeedEncryption),
            };
            prepared.push((public_key, retained));
        }
        Ok(prepared)
    }

    /// Stores prepared keys, sealed or as the paths that recreate them.
    fn retain(&mut self, keys: Vec<(String, RetainedKey)>) {
        for (public_key, retained) in keys {
            match retained {
                RetainedKey::Sealed(ciphertext) => {
                    self.store.insert_sealed_key(&public_key, ciphertext);
                }
                RetainedKey::Derivable(path) => {
                    self.store.insert_path(&public_key, path);
                }
            }
        }
    }

    fn advance_prefix_index(&mut self) -> Result<(), ManagerError> {
        let mut globals = self
            .globals()
            .cloned()
            .ok_or(ManagerError::IndexOverflow { index: "prefix" })?;
        globals.prefix_index = globals
            .prefix_index
            .checked_add(1)
            .ok_or(ManagerError::IndexOverflow { index: "prefix" })?;
        self.store.set_globals(globals);
        Ok(())
    }
}

/// Turns the first [`PASSCODE_LENGTH`] characters of a passcode into a qualified salt.
///
/// The reference builds this as the salt code, one padding character, and the passcode prefix, and
/// does it in three places. A character outside the Base64 URL-safe alphabet cannot produce a salt
/// at all, so it is refused here rather than surfacing several calls later as a parse failure that
/// does not mention the passcode.
///
/// # Errors
///
/// Returns [`ManagerError::PasscodeTooShort`] below [`PASSCODE_LENGTH`] characters,
/// [`ManagerError::InvalidPasscode`] for a character outside the alphabet, and a layered
/// [`ManagerError::Crypto`] when the result is not a usable salt.
pub fn salt_from_passcode(passcode: &str, tier: SecurityTier) -> Result<Salt, ManagerError> {
    if passcode.chars().count() < PASSCODE_LENGTH {
        return Err(ManagerError::PasscodeTooShort {
            required: PASSCODE_LENGTH,
            actual: passcode.chars().count(),
        });
    }
    if let Some(offset) = passcode
        .chars()
        .take(PASSCODE_LENGTH)
        .position(|character| !is_base64_url_safe(character))
    {
        return Err(ManagerError::InvalidPasscode { offset });
    }
    // Sized up front: a buffer that grew would leave its earlier copies unwiped.
    let mut qualified = Zeroizing::new(String::with_capacity(SALT_CODE.len() + 1 + PASSCODE_LENGTH));
    qualified.push_str(SALT_CODE);
    qualified.push('A');
    qualified.extend(passcode.chars().take(PASSCODE_LENGTH));
    Ok(Salt::from_qb64(&qualified, tier)?)
}

/// Parses one managed public key.
fn verifier(public_key: &str) -> Result<VerificationKey, ManagerError> {
    Ok(VerificationKey::from_qb64(public_key)?)
}

/// Derives one digest per created key, committing to its public half.
fn digests(keys: &CreatedKeys, algorithm: DigestAlgorithm) -> Result<Vec<Digest>, ManagerError> {
    keys.signers()
        .map(|signer| {
            let encoded = signer.verifier().qb64_bytes()?;
            Ok(Digest::derive(algorithm, &encoded))
        })
        .collect()
}

/// Returns whether a character belongs to the Base64 URL-safe alphabet.
const fn is_base64_url_safe(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// The raw salt the pinned `manager.test.ts` uses throughout.
    const SALT_RAW: &[u8] = b"0123456789abcdef";
    /// The encryption seed the pinned test calls `cryptseed0`.
    const CRYPT_SEED: [u8; 32] = [
        104, 44, 35, 124, 138, 112, 34, 18, 196, 51, 116, 50, 166, 225, 24, 25, 240, 102, 50, 44, 121, 196, 194, 49,
        64, 245, 64, 21, 46, 162, 26, 207,
    ];
    /// The encryption identifier the pinned test asserts for that seed.
    const AEID: &str = "BCa7mK96FwxkU0TdF54Yqg3qBDXUWpOhQ_Mtr7E77yZB";
    /// The serialization the pinned test signs.
    const SERIALIZATION: &[u8] = b"{\"vs\":\"KERI10JSON0000fb_\",\"pre\":\"EvEnZMhz52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdoI\",\"sn\":\"0\",\"ilk\":\"icp\",\"sith\":\"1\",\"keys\":[\"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA\"],\"nxt\":\"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU\",\"toad\":\"0\",\"wits\":[],\"cnfg\":[]}-AABAApYcYd1cppVg7Inh2YCslWKhUwh59TrPpIoqWxN2A38NCbTljvmBPBjSGIFDBNOvVjHpdZlty3Hgk6ilF8pVpAQ";

    fn salt() -> Result<Salt, Box<dyn Error>> {
        Ok(Salt::from_raw(SALT_RAW, SecurityTier::Low)?)
    }

    fn crypt_seed() -> Result<Signer, Box<dyn Error>> {
        Ok(Signer::from_seed(&CRYPT_SEED, KeyTransferability::NonTransferable)?)
    }

    fn temporary() -> InceptionRequest {
        InceptionRequest {
            profile: KeyDerivationProfile::Temporary,
            ..InceptionRequest::default()
        }
    }

    #[test]
    fn encryption_decides_whether_a_key_is_sealed_or_left_as_a_path() -> Result<(), Box<dyn Error>> {
        // Without encryption nothing is stored but the derivation path.
        let mut plain = KeyManager::builder().salt(salt()?).build()?;
        let incepted = plain.incept(temporary())?;
        assert_eq!(plain.store().sealed_key_count(), 0);
        assert!(plain.store().path(&incepted.prefix).is_some());

        // With encryption the key is sealed instead. The current and next keys are the same key
        // here, so one sealed key covers both.
        let mut sealed = KeyManager::builder().salt(salt()?).build_encrypted(&crypt_seed()?)?;
        let incepted = sealed.incept(temporary())?;
        assert_eq!(sealed.store().sealed_key_count(), 1);
        assert!(sealed.store().path(&incepted.prefix).is_none());
        Ok(())
    }

    #[test]
    fn a_randy_identifier_records_its_algorithm_and_signs() -> Result<(), Box<dyn Error>> {
        let mut manager = KeyManager::builder()
            .algorithm(KeyAlgorithm::Randy)
            .build_encrypted(&crypt_seed()?)?;
        let incepted = manager.incept(InceptionRequest::default())?;
        let parameters = manager
            .store()
            .parameters(&incepted.prefix)
            .ok_or("the identifier has no parameters")?;
        assert_eq!(parameters.algorithm, KeyAlgorithm::Randy);

        let signatures = manager.sign(SERIALIZATION, &[incepted.prefix], &SignatureForm::IndexedByPosition)?;
        assert_eq!(signatures.len(), 1);
        Ok(())
    }

    #[test]
    fn rotating_to_zero_next_keys_abandons_the_identifier() -> Result<(), Box<dyn Error>> {
        let mut manager = KeyManager::builder().salt(salt()?).build()?;
        let live = manager.incept(InceptionRequest {
            stem: Stem::new("live")?,
            ..temporary()
        })?;
        let rotated = manager.rotate(RotationRequest {
            next_keys: 0,
            ..RotationRequest::new(&live.prefix)
        })?;
        assert_eq!(rotated.next_digests, [] as [Digest; 0]);
        assert!(matches!(
            manager.rotate(RotationRequest::new(&live.prefix)),
            Err(ManagerError::Abandoned { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_rotation_erases_only_the_keys_it_retires() -> Result<(), Box<dyn Error>> {
        let seed = crypt_seed()?;
        let mut manager = KeyManager::builder().salt(salt()?).build_encrypted(&seed)?;
        let incepted = manager.incept(InceptionRequest {
            stem: Stem::new("red")?,
            ..temporary()
        })?;
        let first = incepted.prefix.clone();
        let rotation = || RotationRequest {
            profile: KeyDerivationProfile::Temporary,
            ..RotationRequest::new(&first)
        };

        // The first rotation retires the empty set, so nothing is erased.
        manager.rotate(rotation())?;
        assert!(manager.store().sealed_key(&first).is_some());

        // The second retires the inception keys, which can then no longer sign.
        manager.rotate(rotation())?;
        assert!(matches!(
            manager.sign(
                SERIALIZATION,
                std::slice::from_ref(&first),
                &SignatureForm::IndexedByPosition
            ),
            Err(ManagerError::MissingPrivateKey { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_prefix_may_not_be_incepted_twice_and_reassignment_is_checked() -> Result<(), Box<dyn Error>> {
        let mut manager = KeyManager::builder().salt(salt()?).build()?;
        let incepted = manager.incept(InceptionRequest {
            stem: Stem::new("red")?,
            ..temporary()
        })?;

        // The same stem at the same indices derives the same prefix, which is already held.
        assert!(matches!(
            manager.incept(InceptionRequest {
                stem: Stem::new("red")?,
                ..temporary()
            }),
            Err(ManagerError::AlreadyIncepted { .. })
        ));

        // Reassigning to itself is a no-op, and an unknown source is an error.
        manager.reassign(&incepted.prefix, &incepted.prefix)?;
        assert!(manager.store().situation(&incepted.prefix).is_some());
        assert!(matches!(
            manager.reassign("DUNKNOWN", "DOTHER"),
            Err(ManagerError::NotIncepted { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_passcode_builds_the_manager_the_reference_opens() -> Result<(), Box<dyn Error>> {
        // The passcode the pinned `controller.test.ts` uses with `openManager`.
        let manager = KeyManager::from_passcode("0123456789abcdefghijk", None)?;
        assert_eq!(manager.algorithm(), KeyAlgorithm::Randy);
        assert!(manager.encryption_identifier().is_some());

        // Supplying a salt selects the salty algorithm instead.
        let manager = KeyManager::from_passcode("0123456789abcdefghijk", Some(salt()?))?;
        assert_eq!(manager.algorithm(), KeyAlgorithm::Salty);

        // A character outside the Base64 alphabet could never produce a salt.
        assert!(matches!(
            KeyManager::from_passcode("0123456789abcdefghij*", None),
            Err(ManagerError::InvalidPasscode { offset: 20 })
        ));
        Ok(())
    }

    #[test]
    fn signing_refuses_a_request_it_cannot_satisfy() -> Result<(), Box<dyn Error>> {
        let mut manager = KeyManager::builder().salt(salt()?).build()?;
        let incepted = manager.incept(temporary())?;
        let keys = vec![incepted.prefix.clone()];

        assert!(matches!(
            manager.sign(
                SERIALIZATION,
                &keys,
                &SignatureForm::Indexed(vec![
                    SignaturePlacement::both_lists(0),
                    SignaturePlacement::both_lists(1),
                ]),
            ),
            Err(ManagerError::PlacementCountMismatch { placements: 2, keys: 1 })
        ));
        assert!(matches!(
            manager.sign(
                SERIALIZATION,
                &["DHHneREQ1eZyQNc5nEsQYx1FqFVL1OTXmvmatTE77Cfe".to_owned()],
                &SignatureForm::IndexedByPosition,
            ),
            Err(ManagerError::MissingPrivateKey { .. })
        ));
        assert!(matches!(
            manager.sign(
                SERIALIZATION,
                &["not a key".to_owned()],
                &SignatureForm::IndexedByPosition
            ),
            Err(ManagerError::Crypto { .. })
        ));
        Ok(())
    }

    #[test]
    fn rotating_an_unknown_identifier_is_refused() {
        let Ok(mut manager) = KeyManager::builder().build() else {
            return;
        };
        assert!(matches!(
            manager.rotate(RotationRequest::new("DUNKNOWN")),
            Err(ManagerError::NotIncepted { .. })
        ));
    }

    #[test]
    fn a_salty_manager_without_a_salt_cannot_incept() -> Result<(), Box<dyn Error>> {
        let mut manager = KeyManager::builder().build()?;
        assert!(matches!(manager.incept(temporary()), Err(ManagerError::MissingSalt)));
        Ok(())
    }

    #[test]
    fn restoring_with_another_seed_is_refused() -> Result<(), Box<dyn Error>> {
        let mut manager = KeyManager::builder().salt(salt()?).build_encrypted(&crypt_seed()?)?;
        manager.incept(temporary())?;
        let other = Signer::from_seed(&[7; 32], KeyTransferability::NonTransferable)?;

        assert!(matches!(
            KeyManager::restore(manager.store().clone(), None, &other),
            Err(ManagerError::SeedDoesNotMatchIdentifier)
        ));
        Ok(())
    }

    #[test]
    fn restoring_without_a_salt_opens_the_sealed_one() -> Result<(), Box<dyn Error>> {
        let seed = crypt_seed()?;
        let mut manager = KeyManager::builder().salt(salt()?).build_encrypted(&seed)?;
        manager.incept(temporary())?;

        let mut restored = KeyManager::restore(manager.store().clone(), None, &seed)?;
        assert!(
            restored
                .store()
                .globals()
                .is_some_and(|globals| globals.sealed_salt.is_some())
        );
        assert_eq!(restored.prefix_index(), 1);
        assert_eq!(
            restored.incept(temporary())?.prefix,
            manager.incept(temporary())?.prefix
        );
        Ok(())
    }

    #[test]
    fn a_failed_inception_leaves_nothing_behind() -> Result<(), Box<dyn Error>> {
        let mut manager = KeyManager::builder().salt(salt()?).build()?;
        let refused = manager.incept(InceptionRequest {
            algorithm: Some(KeyAlgorithm::Randy),
            ..temporary()
        });

        assert!(matches!(refused, Err(ManagerError::RandomKeysNeedEncryption)));
        assert_eq!(manager.prefix_index(), 0);
        assert_eq!(
            format!("{:?}", manager.store()),
            format!("{:?}", KeyManager::builder().salt(salt()?).build()?.store())
        );
        Ok(())
    }

    #[test]
    fn an_empty_stem_keeps_its_one_key_through_rotations() -> Result<(), Box<dyn Error>> {
        let mut manager = KeyManager::builder().salt(salt()?).build_encrypted(&crypt_seed()?)?;
        let incepted = manager.incept(temporary())?;

        for _ in 0..3 {
            manager.rotate(RotationRequest {
                profile: KeyDerivationProfile::Temporary,
                ..RotationRequest::new(&incepted.prefix)
            })?;
        }
        assert!(manager.store().sealed_key(&incepted.prefix).is_some());
        Ok(())
    }

    #[test]
    fn a_rotation_derives_under_the_recorded_tier() -> Result<(), Box<dyn Error>> {
        let stem = Stem::new("tiered")?;
        let medium = KeyDerivationProfile::Standard(SecurityTier::Medium);
        let mut manager = KeyManager::builder().salt(salt()?).build()?;
        let incepted = manager.incept(InceptionRequest {
            stem: stem.clone(),
            profile: medium,
            ..InceptionRequest::default()
        })?;

        // The request asks for the low tier.
        manager.rotate(RotationRequest::new(&incepted.prefix))?;

        let expected = SaltyKeyCreator::new(&salt()?, stem).create(
            1,
            KeyTransferability::Transferable,
            KeyIndices::new(0, 2, 2),
            medium,
        )?;
        let situation = manager.store().situation(&incepted.prefix);
        assert_eq!(
            situation.map(|lot| lot.next.public_keys.clone()),
            Some(expected.public_keys()?)
        );
        Ok(())
    }

    #[test]
    fn a_manager_never_prints_its_secrets() -> Result<(), Box<dyn Error>> {
        let seed = crypt_seed()?;
        let manager = KeyManager::builder().salt(salt()?).build_encrypted(&seed)?;
        let rendered = format!("{manager:?}");
        // The encryption identifier is public; nothing else about the keys may appear.
        assert!(rendered.contains(AEID));
        assert!(!rendered.contains("0123456789abcdef"));
        assert!(!rendered.contains("decrypter"));
        Ok(())
    }
}
