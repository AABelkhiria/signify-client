//! Key creation, storage, rotation, and signing for the identifiers one controller manages.
//!
//! This ports the pinned reference's `src/keri/core/manager.ts`: the two key creators, the state a
//! manager keeps for each identifier it holds, and the manager itself.
//!
//! Two of the reference's four algorithms have a key creator here. The other two name a source
//! outside this module — a multisig group member, or an external key store — and the reference's
//! own factory throws for both.

pub mod algorithm;
pub mod creator;
pub mod error;
pub mod keeper;
pub mod key_manager;
pub mod store;

pub use algorithm::{CreatorKind, KeyAlgorithm};
pub use creator::{
    CreatedKeys, DerivationPath, DerivedKey, KeyCreator, KeyIndices, MAX_DERIVATION_PATH_BYTES, MAX_KEYS_PER_SET,
    MAX_STEM_BYTES, RandyKeyCreator, SaltyKeyCreator, Stem,
};
pub use error::ManagerError;
pub use keeper::{
    DerivationCost, ExternalKeeperModule, GroupKeeper, IdentifierKeeper, KeeperFactory, KeeperRequest, KeeperRotation,
    KeyMaterial, RandyKeeper, RandyKeeperRequest, SaltyKeeper, SaltyKeeperRequest, SaltySource, SigningPurpose,
};
pub use key_manager::salt_from_passcode;
pub use key_manager::{
    InceptedKeys, InceptionRequest, KeyManager, KeyManagerBuilder, ManagedSignatures, PASSCODE_LENGTH,
    RetiredKeyPolicy, RotatedKeys, RotationRequest, SignatureForm,
};
pub use store::{KeyStore, ManagerGlobals, PrefixParameters, PrefixSituation, PublicKeyLot, RotationKey, StoredPath};
