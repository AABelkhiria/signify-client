//! The keeper factory: builds the right keeper for an algorithm or for a stored identifier.

use std::collections::BTreeMap;

use keri_cesr::crypto::digest::DigestAlgorithm;
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::verifier::KeyTransferability;
use serde_json::{Map, Value};
use signify_types::api::{Hab, KeyManagerState, KeyState};

use super::super::algorithm::KeyAlgorithm;
use super::super::creator::Stem;
use super::super::error::ManagerError;
use super::group::GroupKeeper;
use super::randy::{RandyKeeper, RandyKeeperConfig, transferability_of};
use super::salty::{SaltyKeeper, SaltyKeeperConfig, SaltySource};
use super::{DerivationCost, IdentifierKeeper, first_keys, first_next_digests};

/// Supplies a keeper for keys this process does not hold.
///
/// An external module stands in for an HSM, a KMS, or anything else that signs without handing over
/// a key. The reference registers a constructor by a type name and calls it with the stored
/// parameters; this is the same contract, typed.
///
/// Implementations must be usable from any thread, because a keeper built from one may be moved
/// into whatever the client runs on.
pub trait ExternalKeeperModule: Send + Sync {
    /// Builds a keeper over externally held keys.
    ///
    /// # Errors
    ///
    /// Returns whatever the module needs to report; a module that cannot reach its key store
    /// should say so rather than produce a keeper that fails later.
    fn create(
        &self,
        key_pair_index: u32,
        parameters: &Map<String, Value>,
    ) -> Result<Box<dyn IdentifierKeeper>, ManagerError>;
}

/// What to build a salty keeper from.
#[derive(Debug)]
pub struct SaltyKeeperRequest {
    /// Index this identifier takes among the ones one controller holds.
    pub prefix_index: u32,
    /// Index of the current key set among all this identifier's keys.
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
    /// Where the identifier's own salt comes from.
    pub source: SaltySource,
    /// Derivation cost; see [`DerivationCost`].
    pub profile: DerivationCost,
}

impl Default for SaltyKeeperRequest {
    fn default() -> Self {
        let config = SaltyKeeperConfig::default();
        Self {
            prefix_index: config.prefix_index,
            key_index: config.key_index,
            tier: config.tier,
            transferability: config.transferability,
            stem: config.stem,
            current_count: config.current_count,
            next_count: config.next_count,
            digest: config.digest,
            source: SaltySource::Generated,
            profile: DerivationCost::Production,
        }
    }
}

/// What to build a randy keeper from.
#[derive(Clone, Debug)]
pub struct RandyKeeperRequest {
    /// How many keys sign.
    pub current_count: usize,
    /// How many keys are committed to.
    pub next_count: usize,
    /// Whether the identifier may rotate.
    pub transferability: KeyTransferability,
    /// Keys sealed earlier, if this identifier already exists.
    pub sealed_signing_keys: Vec<String>,
    /// Committed-to keys sealed earlier, if this identifier already exists.
    pub sealed_next_keys: Vec<String>,
    /// Derivation cost of the key its stored keys are sealed to; see [`DerivationCost`].
    pub profile: DerivationCost,
}

impl Default for RandyKeeperRequest {
    fn default() -> Self {
        Self {
            current_count: 1,
            next_count: 1,
            transferability: KeyTransferability::NonTransferable,
            sealed_signing_keys: Vec::new(),
            sealed_next_keys: Vec::new(),
            profile: DerivationCost::Production,
        }
    }
}

/// What to build a keeper for.
///
/// This replaces the reference's `new(algo, pidx, kargs)`, whose third argument is an untyped bag
/// read with string keys. Its `Unknown algo` failure is unrepresentable here.
#[derive(Debug)]
pub enum KeeperRequest<'states> {
    /// A new or reloaded salty identifier.
    Salty(SaltyKeeperRequest),
    /// A new or reloaded randy identifier.
    Randy(RandyKeeperRequest),
    /// A multisig group over a local member.
    Group {
        /// The local member identifier, whose keys sign for the group.
        member: Box<signify_types::api::AcceptedHab>,
        /// Key states supplying the group's current signing keys.
        states: &'states [KeyState],
        /// Key states supplying the group's proposed next digests.
        next_states: &'states [KeyState],
    },
    /// Keys held outside this process.
    Extern {
        /// Name the module was registered under.
        module_type: String,
        /// Index this identifier takes among the ones one controller holds.
        key_pair_index: u32,
        /// Module-specific parameters, passed through unread.
        parameters: Map<String, Value>,
    },
}

/// Builds keepers over one controller's passcode salt.
pub struct KeeperFactory {
    salt: Salt,
    modules: BTreeMap<String, Box<dyn ExternalKeeperModule>>,
}

impl core::fmt::Debug for KeeperFactory {
    /// Names the registered module types and nothing about the salt.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KeeperFactory")
            .field("modules", &self.modules.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl KeeperFactory {
    /// Creates a factory over the controller's passcode salt.
    ///
    /// Every keeper this builds seals its keys to a key derived from that salt, so the same salt
    /// must be supplied again to reload them.
    #[must_use]
    pub fn new(salt: Salt) -> Self {
        Self {
            salt,
            modules: BTreeMap::new(),
        }
    }

    /// Registers an external key-manager module under a name.
    #[must_use]
    pub fn with_module(mut self, module_type: impl Into<String>, module: Box<dyn ExternalKeeperModule>) -> Self {
        self.modules.insert(module_type.into(), module);
        self
    }

    /// Returns the names external modules are registered under, in order.
    pub fn module_types(&self) -> impl Iterator<Item = &str> {
        self.modules.keys().map(String::as_str)
    }

    /// Builds a keeper for a new or reloaded identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::UnknownExternalModule`] when no module is registered under the
    /// requested name, and whatever the selected keeper's constructor returns.
    pub fn create(&self, request: KeeperRequest<'_>) -> Result<Box<dyn IdentifierKeeper>, ManagerError> {
        match request {
            KeeperRequest::Salty(request) => Ok(Box::new(SaltyKeeper::new(
                &self.salt,
                request.source,
                SaltyKeeperConfig {
                    prefix_index: request.prefix_index,
                    key_index: request.key_index,
                    tier: request.tier,
                    transferability: request.transferability,
                    stem: request.stem,
                    current_count: request.current_count,
                    next_count: request.next_count,
                    digest: request.digest,
                    profile: request.profile,
                },
            )?)),
            KeeperRequest::Randy(request) => Ok(Box::new(RandyKeeper::new(
                &self.salt,
                request.sealed_signing_keys,
                request.sealed_next_keys,
                &RandyKeeperConfig {
                    current_count: request.current_count,
                    next_count: request.next_count,
                    transferability: request.transferability,
                    digest: DigestAlgorithm::Blake3_256,
                    profile: request.profile,
                },
            )?)),
            KeeperRequest::Group {
                member,
                states,
                next_states,
            } => {
                let member_keeper = self.keeper_for_state(&member.common.key_manager, &member.common.prefix)?;
                Ok(Box::new(GroupKeeper::new(
                    member_keeper,
                    *member,
                    first_keys(states)?,
                    first_next_digests(next_states)?,
                )))
            }
            KeeperRequest::Extern {
                module_type,
                key_pair_index,
                parameters,
            } => self.external(&module_type, key_pair_index, &parameters),
        }
    }

    /// Builds the keeper an existing identifier record describes.
    ///
    /// This is the reference's `get(aid)`. Its `No algo specified` failure is unrepresentable:
    /// Roadmap 4.1's identifier record names exactly one key manager or does not decode.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::UnknownExternalModule`] for an unregistered module and whatever the
    /// selected keeper's constructor returns.
    pub fn keeper_for(&self, hab: &Hab) -> Result<Box<dyn IdentifierKeeper>, ManagerError> {
        self.keeper_for_state(&hab.common().key_manager, &hab.common().prefix)
    }

    /// Builds the keeper one key-manager state describes.
    fn keeper_for_state(
        &self,
        state: &KeyManagerState,
        prefix: &str,
    ) -> Result<Box<dyn IdentifierKeeper>, ManagerError> {
        match state {
            KeyManagerState::Salty(salty) => {
                let tier = super::security_tier(salty.tier);
                Ok(Box::new(SaltyKeeper::new(
                    &self.salt,
                    SaltySource::Sealed(salty.encrypted_salt.clone()),
                    SaltyKeeperConfig {
                        prefix_index: salty.key_pair_index,
                        key_index: salty.key_index,
                        tier,
                        transferability: if salty.transferable {
                            KeyTransferability::Transferable
                        } else {
                            KeyTransferability::NonTransferable
                        },
                        stem: Stem::new(salty.stem.clone())?,
                        current_count: salty.inception_codes.len(),
                        next_count: salty.next_codes.len(),
                        digest: digest_of(&salty.digest_code)?,
                        // A stored record always names the production profile for its tier.
                        profile: DerivationCost::Production,
                    },
                )?))
            }
            KeyManagerState::Randy(randy) => Ok(Box::new(RandyKeeper::new(
                &self.salt,
                randy.encrypted_signing_keys.clone(),
                randy.encrypted_next_keys.clone(),
                &RandyKeeperConfig {
                    current_count: randy.encrypted_signing_keys.len(),
                    next_count: randy.encrypted_next_keys.len(),
                    // The stored randy record has no transferability field, so it comes from the
                    // identifier's own prefix code — which is what the reference does too.
                    transferability: transferability_of(prefix)?,
                    digest: DigestAlgorithm::Blake3_256,
                    profile: DerivationCost::Production,
                },
            )?)),
            KeyManagerState::Group(group) => {
                let member_keeper =
                    self.keeper_for_state(&group.member.common.key_manager, &group.member.common.prefix)?;
                Ok(Box::new(GroupKeeper::new(
                    member_keeper,
                    group.member.clone(),
                    group.keys.clone(),
                    group.next_key_digests.clone(),
                )))
            }
            KeyManagerState::Extern(external) => {
                self.external(&external.extern_type, external.key_pair_index, &external.additional)
            }
        }
    }

    /// Looks up and calls a registered external module.
    fn external(
        &self,
        module_type: &str,
        key_pair_index: u32,
        parameters: &Map<String, Value>,
    ) -> Result<Box<dyn IdentifierKeeper>, ManagerError> {
        self.modules
            .get(module_type)
            .ok_or_else(|| ManagerError::UnknownExternalModule {
                module_type: module_type.to_owned(),
            })?
            .create(key_pair_index, parameters)
    }
}

/// Maps a stored digest code onto the algorithm it names.
fn digest_of(code: &str) -> Result<DigestAlgorithm, ManagerError> {
    if code == DigestAlgorithm::Blake3_256.code().as_str() {
        Ok(DigestAlgorithm::Blake3_256)
    } else {
        Err(ManagerError::UnsupportedDigest { code: code.to_owned() })
    }
}

/// Keeps the algorithm table reachable from this module's documentation.
const _: KeyAlgorithm = KeyAlgorithm::Salty;

#[cfg(test)]
mod tests {
    use super::super::{KeeperRotation, KeyMaterial, SigningPurpose};
    use super::*;
    use crate::manager::key_manager::{ManagedSignatures, SignatureForm};
    use std::error::Error;

    fn factory() -> Result<KeeperFactory, Box<dyn Error>> {
        Ok(KeeperFactory::new(Salt::from_raw(
            b"0123456789abcdef",
            SecurityTier::Low,
        )?))
    }

    /// A module that stands in for an HSM, recording what it was handed.
    struct RecordingModule;

    struct RecordingKeeper {
        key_pair_index: u32,
        parameters: Map<String, Value>,
    }

    impl ExternalKeeperModule for RecordingModule {
        fn create(
            &self,
            key_pair_index: u32,
            parameters: &Map<String, Value>,
        ) -> Result<Box<dyn IdentifierKeeper>, ManagerError> {
            Ok(Box::new(RecordingKeeper {
                key_pair_index,
                parameters: parameters.clone(),
            }))
        }
    }

    impl IdentifierKeeper for RecordingKeeper {
        fn algorithm(&self) -> KeyAlgorithm {
            KeyAlgorithm::Extern
        }

        fn parameters(&self) -> Result<KeyManagerState, ManagerError> {
            Ok(KeyManagerState::Extern(signify_types::api::ExternState {
                extern_type: "recording".to_owned(),
                key_pair_index: self.key_pair_index,
                additional: self.parameters.clone(),
            }))
        }

        fn incept(&mut self, _transferability: KeyTransferability) -> Result<KeyMaterial, ManagerError> {
            Ok(KeyMaterial::default())
        }

        fn rotate(&mut self, _rotation: KeeperRotation<'_>) -> Result<KeyMaterial, ManagerError> {
            Ok(KeyMaterial::default())
        }

        fn sign(
            &self,
            _serialization: &[u8],
            _form: &SignatureForm,
            _purpose: SigningPurpose,
        ) -> Result<ManagedSignatures, ManagerError> {
            Ok(ManagedSignatures::Indexed(Vec::new()))
        }

        fn expose_signers(&self) -> Result<Vec<keri_cesr::crypto::signer::Signer>, ManagerError> {
            // Externally held keys never leave their store, which is the point of the module.
            Ok(Vec::new())
        }
    }

    #[test]
    fn a_salty_record_reloads_into_a_keeper_that_signs_the_same_way() -> Result<(), Box<dyn Error>> {
        let factory = factory()?;
        let mut keeper = factory.create(KeeperRequest::Salty(SaltyKeeperRequest {
            transferability: KeyTransferability::Transferable,
            ..SaltyKeeperRequest::default()
        }))?;
        let material = keeper.incept(KeyTransferability::Transferable)?;
        let state = keeper.parameters()?;

        let reloaded = factory.keeper_for(&pending_hab("EPRE", state))?;
        assert_eq!(reloaded.algorithm(), KeyAlgorithm::Salty);
        assert_eq!(
            super::super::public_keys(&reloaded.expose_signers()?)?,
            material.public_keys
        );
        Ok(())
    }

    #[test]
    fn a_randy_record_takes_its_transferability_from_the_prefix() -> Result<(), Box<dyn Error>> {
        let factory = factory()?;
        let mut keeper = factory.create(KeeperRequest::Randy(RandyKeeperRequest {
            current_count: 1,
            next_count: 1,
            transferability: KeyTransferability::Transferable,
            ..RandyKeeperRequest::default()
        }))?;
        let material = keeper.incept(KeyTransferability::Transferable)?;
        let state = keeper.parameters()?;

        // The prefix is the identifier's first key, and its code says transferable.
        let prefix = material.public_keys.first().ok_or("no key was established")?;
        let reloaded = factory.keeper_for(&pending_hab(prefix, state))?;
        assert_eq!(reloaded.algorithm(), KeyAlgorithm::Randy);
        assert_eq!(
            super::super::public_keys(&reloaded.expose_signers()?)?,
            material.public_keys
        );
        Ok(())
    }

    #[test]
    fn an_unregistered_external_module_is_refused() -> Result<(), Box<dyn Error>> {
        let factory = factory()?;
        assert!(matches!(
            factory.create(KeeperRequest::Extern {
                module_type: "mock".to_owned(),
                key_pair_index: 0,
                parameters: Map::new(),
            }),
            Err(ManagerError::UnknownExternalModule { .. })
        ));

        // And the same through a stored record, which is the reference's other entry point.
        let state = KeyManagerState::Extern(signify_types::api::ExternState {
            extern_type: "mock".to_owned(),
            key_pair_index: 3,
            additional: Map::new(),
        });
        assert!(matches!(
            factory.keeper_for(&pending_hab("EPRE", state)),
            Err(ManagerError::UnknownExternalModule { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_registered_external_module_receives_its_parameters() -> Result<(), Box<dyn Error>> {
        let factory = factory()?.with_module("mock", Box::new(RecordingModule));
        assert_eq!(factory.module_types().collect::<Vec<_>>(), ["mock"]);

        let mut parameters = Map::new();
        parameters.insert("slot".to_owned(), Value::from("7"));
        let keeper = factory.create(KeeperRequest::Extern {
            module_type: "mock".to_owned(),
            key_pair_index: 3,
            parameters: parameters.clone(),
        })?;
        assert_eq!(keeper.algorithm(), KeyAlgorithm::Extern);
        let KeyManagerState::Extern(state) = keeper.parameters()? else {
            return Err("an external keeper reported another state".into());
        };
        assert_eq!(state.key_pair_index, 3);
        assert_eq!(state.additional.get("slot"), Some(&Value::from("7")));

        // Externally held keys never leave the module.
        assert!(keeper.expose_signers()?.is_empty());
        Ok(())
    }

    #[test]
    fn an_external_record_reaches_its_module_with_the_stored_index() -> Result<(), Box<dyn Error>> {
        let factory = factory()?.with_module("mock", Box::new(RecordingModule));
        let state = KeyManagerState::Extern(signify_types::api::ExternState {
            extern_type: "mock".to_owned(),
            key_pair_index: 3,
            additional: {
                let mut fields = Map::new();
                fields.insert("param".to_owned(), Value::from("value"));
                fields
            },
        });
        let keeper = factory.keeper_for(&pending_hab("EPRE", state))?;
        let KeyManagerState::Extern(recorded) = keeper.parameters()? else {
            return Err("an external keeper reported another state".into());
        };
        assert_eq!(recorded.key_pair_index, 3);
        assert_eq!(recorded.additional.get("param"), Some(&Value::from("value")));
        Ok(())
    }

    #[test]
    fn a_group_record_builds_its_member_keeper_too() -> Result<(), Box<dyn Error>> {
        let factory = factory()?;
        // A group record embeds its member's record, so the member has to be storable and this
        // test pays the real derivation cost.
        let mut member = factory.create(KeeperRequest::Salty(SaltyKeeperRequest {
            transferability: KeyTransferability::Transferable,
            ..SaltyKeeperRequest::default()
        }))?;
        let member_material = member.incept(KeyTransferability::Transferable)?;
        let member_state = member.parameters()?;
        let member_key = member_material
            .public_keys
            .first()
            .cloned()
            .ok_or("the member established no keys")?;
        let member_digest = member_material
            .next_digests
            .first()
            .cloned()
            .ok_or("the member committed to no keys")?;

        let member_hab = accepted_hab("EMEM", member_state, &member_key, &member_digest)?;
        let group = KeyManagerState::Group(Box::new(signify_types::api::GroupState {
            member: member_hab,
            keys: vec![member_key.clone()],
            next_key_digests: vec![member_digest.clone()],
        }));

        let keeper = factory.keeper_for(&pending_hab("EGRP", group))?;
        assert_eq!(keeper.algorithm(), KeyAlgorithm::Group);
        // The group signs through the member it was built with.
        let signatures = keeper.sign(b"payload", &SignatureForm::IndexedByPosition, SigningPurpose::Current)?;
        assert_eq!(signatures.len(), 1);
        Ok(())
    }

    /// Builds the shared half of an identifier record around one key-manager state.
    fn common(prefix: &str, state: KeyManagerState) -> signify_types::api::HabCommon {
        signify_types::api::HabCommon {
            name: "identifier".to_owned(),
            prefix: prefix.to_owned(),
            inception_stamp: "2023-12-01T10:05:25.062609+00:00".to_owned(),
            transferable: None,
            witness_indexes: None,
            key_manager: state,
        }
    }

    /// Builds an identifier record that has not been incepted yet.
    fn pending_hab(prefix: &str, state: KeyManagerState) -> Hab {
        Hab::Pending(signify_types::api::PendingHab {
            common: common(prefix, state),
        })
    }

    /// Builds an incepted identifier record, which a group member has to be.
    fn accepted_hab(
        prefix: &str,
        state: KeyManagerState,
        key: &str,
        next_digest: &str,
    ) -> Result<signify_types::api::AcceptedHab, Box<dyn Error>> {
        let document = format!(
            r#"{{"i":"{prefix}","s":"0","p":"","d":"{prefix}","f":"0","dt":"","et":"icp","kt":"1","k":["{key}"],"nt":"1","n":["{next_digest}"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{prefix}"}},"di":""}}"#
        );
        Ok(signify_types::api::AcceptedHab {
            common: common(prefix, state),
            state: Box::new(serde_json::from_str(&document)?),
        })
    }
}
