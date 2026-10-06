//! Per-identifier key keepers: the strategy that holds one identifier's keys.
//!
//! A [`KeyManager`](super::KeyManager) holds every identifier a controller owns. A *keeper* holds
//! one, and knows how that one identifier's keys come into existence, how they rotate, and how they
//! sign. This ports the pinned reference's `src/keri/core/keeping.ts`.
//!
//! There are four strategies, and unlike Roadmap 4.2's creators all four are real here:
//!
//! - [`SaltyKeeper`] derives keys from a salt of its own, sealed to a key derived from the
//!   controller's passcode.
//! - [`RandyKeeper`] holds randomly generated keys, sealed the same way.
//! - [`GroupKeeper`] has no keys at all: it maps a group event's signing positions onto the local
//!   member identifier and delegates the signature to that member's keeper.
//! - An external keeper is supplied by the caller through [`ExternalKeeperModule`], for keys held
//!   in an HSM or a KMS.
//!
//! # Why this is a trait when the key store was not
//!
//! Roadmap 4.2 made `KeyStore` a struct because it had one implementation. This has four, one of
//! which the caller writes, so a trait is what the design actually needs rather than an abstraction
//! ahead of its second user.
//!
//! # Synchronous, unlike upstream
//!
//! Every method on the reference's `IdentifierManager` is `async`, but nothing in the three
//! implementations awaits anything: no key operation here performs I/O. `ARCHITECTURE.md` §4.4
//! forbids `signify-keri` from acquiring an async runtime, so the trait is synchronous. An external
//! module backed by a network HSM has to bridge that itself; an asynchronous external contract, if
//! one is ever needed, belongs with the client phases that own transport.
//!
//! # Derivation differs from the key manager's
//!
//! A salty keeper always derives at **rotation index zero** and advances the *key* index instead,
//! and its default stem is `signify:aid` rather than empty. `KeyManager` advances the rotation
//! index and defaults to an empty stem. The two therefore derive different keys from the same salt,
//! which is upstream's arrangement and is reproduced exactly.

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keria_types::api::{KeyManagerState, KeyState};

use super::algorithm::KeyAlgorithm;
use super::error::ManagerError;
use super::key_manager::{ManagedSignatures, SignatureForm};

pub mod factory;
pub mod group;
pub mod randy;
pub mod salty;

pub use factory::{ExternalKeeperModule, KeeperFactory, KeeperRequest, RandyKeeperRequest, SaltyKeeperRequest};
pub use group::GroupKeeper;
pub use randy::RandyKeeper;
pub use salty::{SaltyKeeper, SaltySource};

/// The keys one inception or rotation established.
///
/// This is the reference's `IdentifierManagerResult`, a bare `[string[], string[]]` whose two
/// halves are easy to transpose.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KeyMaterial {
    /// Qualified public keys that now sign, in signing order.
    pub public_keys: Vec<String>,
    /// Qualified digests committing to the next keys, in order.
    pub next_digests: Vec<String>,
}

/// What a signature is being produced for.
///
/// This replaces the reference's `rotated` boolean. It matters only to [`GroupKeeper`]: a rotation
/// signature must also prove that the key signing it was precommitted, which means exposing the
/// position of that commitment. Every other keeper ignores it, exactly as the reference's
/// `_rotated` parameter does.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SigningPurpose {
    /// A signature satisfying only the current signing threshold.
    #[default]
    Current,
    /// A rotation signature, which must also prove the key was committed to in advance.
    Rotation,
}

/// What to rotate to.
#[derive(Clone, Copy, Debug)]
pub struct KeeperRotation<'states> {
    /// How many keys the rotation commits to.
    pub next_key_count: usize,
    /// Whether the new keys may rotate again.
    pub transferability: KeyTransferability,
    /// Key states supplying the group's current signing keys. Used only by [`GroupKeeper`].
    pub states: Option<&'states [KeyState]>,
    /// Key states supplying the group's proposed next digests. Used only by [`GroupKeeper`].
    pub next_states: Option<&'states [KeyState]>,
}

impl Default for KeeperRotation<'_> {
    /// Rotates to one transferable key, which is the reference's default.
    fn default() -> Self {
        Self::to_keys(1)
    }
}

impl KeeperRotation<'_> {
    /// Creates a rotation to `next_key_count` transferable keys, which is the common case.
    #[must_use]
    pub const fn to_keys(next_key_count: usize) -> Self {
        Self {
            next_key_count,
            transferability: KeyTransferability::Transferable,
            states: None,
            next_states: None,
        }
    }
}

/// Holds one identifier's keys, and knows how to establish, rotate, and sign with them.
pub trait IdentifierKeeper {
    /// Returns which strategy this keeper implements.
    fn algorithm(&self) -> KeyAlgorithm;

    /// Returns the state a KERIA identifier record stores for this keeper.
    ///
    /// This is the reference's `params()`, typed as the record it is serialized into rather than as
    /// an open bag of unknown values.
    ///
    /// # Errors
    ///
    /// Returns a layered [`ManagerError::Crypto`] when stored material cannot be encoded.
    fn parameters(&self) -> Result<KeyManagerState, ManagerError>;

    /// Establishes this identifier's first keys.
    ///
    /// # Errors
    ///
    /// Returns whatever key creation or sealing returns.
    fn incept(&mut self, transferability: KeyTransferability) -> Result<KeyMaterial, ManagerError>;

    /// Rotates to the committed-to keys and commits to new ones.
    ///
    /// # Errors
    ///
    /// Returns whatever key creation, opening, or sealing returns.
    fn rotate(&mut self, rotation: KeeperRotation<'_>) -> Result<KeyMaterial, ManagerError>;

    /// Signs one serialization with the keys this keeper holds.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::MissingPrivateKey`] when a key cannot be recovered, and whatever
    /// signing returns.
    fn sign(
        &self,
        serialization: &[u8],
        form: &SignatureForm,
        purpose: SigningPurpose,
    ) -> Result<ManagedSignatures, ManagerError>;

    /// Returns the private signers this keeper currently holds.
    ///
    /// **This hands out secret material.** It exists because an authenticated KERIA request is
    /// signed with the identifier's own key rather than through this keeper (Roadmap 6.4), and
    /// `signify-http`'s request signer takes a `Signer`. The `expose_` prefix marks the deliberate
    /// export, matching `Salt::expose_qb64`. The reference publishes the same material as a public
    /// `signers` field on every keeper.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::MissingPrivateKey`] when a key cannot be recovered, and whatever
    /// derivation or opening returns.
    fn expose_signers(&self) -> Result<Vec<Signer>, ManagerError>;
}

/// Returns the qualified public keys of a set of signers, in order.
pub(crate) fn public_keys(signers: &[Signer]) -> Result<Vec<String>, ManagerError> {
    signers
        .iter()
        .map(|signer| signer.verifier().qb64().map_err(ManagerError::from))
        .collect()
}

/// Reads the group's key material out of a set of key states, taking the first key of each.
///
/// The reference does exactly this — `states.map(state => state['k'][0])` — so a member with more
/// than one key contributes only its first. Reproduced, and the empty case is a typed error rather
/// than an `undefined` that surfaces much later.
pub(crate) fn first_keys(states: &[KeyState]) -> Result<Vec<String>, ManagerError> {
    states
        .iter()
        .map(|state| {
            state
                .signing_keys
                .first()
                .cloned()
                .ok_or_else(|| ManagerError::NoSigningKeys {
                    prefix: state.identifier.clone(),
                })
        })
        .collect()
}

/// Reads the group's next digests out of a set of key states, taking the first digest of each.
pub(crate) fn first_next_digests(states: &[KeyState]) -> Result<Vec<String>, ManagerError> {
    states
        .iter()
        .map(|state| {
            state
                .next_key_digests
                .first()
                .cloned()
                .ok_or_else(|| ManagerError::NoSigningKeys {
                    prefix: state.identifier.clone(),
                })
        })
        .collect()
}

/// Signs one serialization with a set of signers, placing the signatures as the form asks.
pub(crate) fn sign_with(
    signers: &[Signer],
    serialization: &[u8],
    form: &SignatureForm,
) -> Result<ManagedSignatures, ManagerError> {
    if let SignatureForm::Indexed(placements) = form
        && placements.len() != signers.len()
    {
        return Err(ManagerError::PlacementCountMismatch {
            placements: placements.len(),
            keys: signers.len(),
        });
    }

    match form {
        SignatureForm::Unindexed => signers
            .iter()
            .map(|signer| signer.sign_unindexed(serialization).map_err(ManagerError::from))
            .collect::<Result<Vec<_>, _>>()
            .map(ManagedSignatures::Unindexed),
        SignatureForm::IndexedByPosition => signers
            .iter()
            .enumerate()
            .map(|(position, signer)| {
                let index = u32::try_from(position).map_err(|_| ManagerError::IndexOverflow { index: "signature" })?;
                signer
                    .sign_indexed(
                        serialization,
                        keri_cesr::crypto::signer::SignaturePlacement::both_lists(index),
                    )
                    .map_err(ManagerError::from)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(ManagedSignatures::Indexed),
        SignatureForm::Indexed(placements) => signers
            .iter()
            .zip(placements)
            .map(|(signer, placement)| {
                signer
                    .sign_indexed(serialization, *placement)
                    .map_err(ManagerError::from)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(ManagedSignatures::Indexed),
    }
}

/// How much a keeper's key derivation should cost.
///
/// The reference offers no choice: it hardcodes the production profile everywhere. This exists
/// because a property test or a throwaway identifier cannot afford sixty-four mebibytes per key,
/// and it is a two-value enum rather than a profile so a keeper can never be built under a tier
/// that disagrees with the one its record would store.
///
/// A keeper built as [`DerivationCost::Ephemeral`] is exactly that: an identifier record stores a
/// tier and not a cost, so such a keeper could not be reloaded to the same keys, and asking it for
/// its parameters is [`ManagerError::ProfileNotStorable`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DerivationCost {
    /// The production profile for the keeper's tier, which is what the reference always uses.
    #[default]
    Production,
    /// The deliberately cheap profile. A keeper built under it cannot be stored.
    Ephemeral,
}

impl DerivationCost {
    /// Resolves this cost against a tier.
    #[must_use]
    pub const fn profile(
        self,
        tier: keri_cesr::crypto::salt::SecurityTier,
    ) -> keri_cesr::crypto::salt::KeyDerivationProfile {
        match self {
            Self::Production => keri_cesr::crypto::salt::KeyDerivationProfile::Standard(tier),
            Self::Ephemeral => keri_cesr::crypto::salt::KeyDerivationProfile::Temporary,
        }
    }
}

/// Maps a derivation tier onto the wire tier a KERIA identifier record stores.
///
/// # Errors
///
/// Returns [`ManagerError::UnsupportedTier`] for a tier the record has no spelling for.
pub(crate) fn key_tier(tier: keri_cesr::crypto::salt::SecurityTier) -> Result<keria_types::api::KeyTier, ManagerError> {
    use keri_cesr::crypto::salt::SecurityTier;
    use keria_types::api::KeyTier;
    match tier {
        SecurityTier::Low => Ok(KeyTier::Low),
        SecurityTier::Medium => Ok(KeyTier::Medium),
        SecurityTier::High => Ok(KeyTier::High),
        _ => Err(ManagerError::UnsupportedTier),
    }
}

/// Maps a stored wire tier onto the derivation tier it names.
pub(crate) const fn security_tier(tier: keria_types::api::KeyTier) -> keri_cesr::crypto::salt::SecurityTier {
    use keri_cesr::crypto::salt::SecurityTier;
    use keria_types::api::KeyTier;
    match tier {
        KeyTier::Low => SecurityTier::Low,
        KeyTier::Medium => SecurityTier::Medium,
        KeyTier::High => SecurityTier::High,
    }
}
