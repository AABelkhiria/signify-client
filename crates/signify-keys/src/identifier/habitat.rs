//! The habitat registry: one key manager, many named local identifiers.
//!
//! A [`Habery`] is what the reference calls a `Habery`: it owns one
//! [`KeyManager`] and creates identifiers with it, pairing each
//! inception event with a caller-chosen name as a [`Habitat`]. The registry's own name is the
//! derivation stem every salty key derives under, which is why two registries with different
//! names derive different keys from the same salt.
//!
//! # The empty name collapses salty derivation
//!
//! The registry's name becomes the key manager's derivation stem, and the `keri-manager` fixture
//! records what an empty stem does: every key of every rotation derives from the same path, so
//! pre-rotation commits to the key already in use and protects nothing. The reference behaves
//! identically. Give a registry a non-empty name unless key reuse is genuinely intended.
//!
//! # Derivation cost
//!
//! The reference hardcodes the production Argon2 profile (`temp: false`), which costs 64 MiB of
//! memory per derived key at the low tier. That is the right default for a deployed client and the
//! wrong one for a test suite, so [`HaberyBuilder::derivation_cost`] accepts a [`DerivationCost`],
//! defaulting to production.

use keri_cesr::crypto::digest::DigestAlgorithm;
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;

use crate::identifier::error::IdentifierError;
use crate::manager::key_manager::salt_from_passcode;
use crate::manager::{DerivationCost, InceptionRequest, KeyAlgorithm, KeyManager, ManagerError, Stem};
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::{
    ConfigurationTrait, EventError, KeyEvent, check_distinct, check_next_threshold, check_signing_threshold,
    check_witness_threshold,
};
use keri_protocol::prefix::{IdentifierPrefix, PrefixDerivation};
use keri_protocol::serialization::Sad;
use keri_protocol::threshold::SigningThreshold;

/// One local identifier: a name and the inception event that created it.
///
/// This is the reference's `Hab`. The identifier prefix is not stored separately because the
/// event already carries it — the reference's `pre` getter reads the event's `i` field, and
/// [`Habitat::prefix`] reads the same value through [`KeyEvent::identifier`].
#[derive(Clone, Debug)]
pub struct Habitat {
    name: String,
    event: KeyEvent,
}

impl Habitat {
    /// Returns the name this habitat is registered under.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the inception event that created this identifier.
    ///
    /// This is the reference's `serder` field: the exact wire bytes, the identifier, and the SAID.
    #[must_use]
    pub const fn inception(&self) -> &KeyEvent {
        &self.event
    }

    /// Returns the identifier prefix; the reference's `pre` getter.
    #[must_use]
    pub const fn prefix(&self) -> &IdentifierPrefix {
        self.event.identifier()
    }
}

/// What to create when making a habitat.
///
/// This is the reference's `MakeHabArgs`, with its silent overrides made explicit: a
/// [`KeyTransferability::NonTransferable`] habitat commits to no next keys, carries a zero
/// next-key threshold, and derives a basic non-transferable prefix, and a request that explicitly
/// contradicts any of that is refused rather than silently rewritten.
///
/// The reference's `estOnly` and `DnD` booleans are the `configuration` list here, which can also
/// express [`ConfigurationTrait::NoBackers`] — a trait the reference's `incept` accepts but its
/// `makeHab` cannot set.
#[derive(Clone, Debug)]
pub struct HabitatRequest {
    /// How many keys sign the inception event; the reference's `icount`. At least one.
    pub current_keys: usize,
    /// How many keys the habitat commits to; the reference's `ncount`, defaulting to
    /// `current_keys`.
    pub next_keys: Option<usize>,
    /// Signing threshold; the reference's `isith`, defaulting to a simple majority of the current
    /// keys, but never zero.
    pub signing_threshold: Option<SigningThreshold>,
    /// Next-key threshold; the reference's `nsith`, defaulting to the signing threshold when that
    /// is explicit and otherwise to a simple majority of the next keys, but never zero.
    ///
    /// The never-zero default is the reference's own formula, and it means a transferable habitat
    /// with zero next keys is refused unless this is an explicit zero: the reference instead emits
    /// an event whose next-key threshold no key can ever satisfy, recorded in the `keri-habery`
    /// fixture.
    pub next_threshold: Option<SigningThreshold>,
    /// Whether the identifier may rotate; the reference's `transferable` boolean.
    pub transferability: KeyTransferability,
    /// Prefix derivation; the reference's `code`, defaulting to
    /// [`PrefixDerivation::Blake3_256`] for a transferable habitat and forced to
    /// [`PrefixDerivation::Ed25519NonTransferable`] for a non-transferable one.
    pub derivation: Option<PrefixDerivation>,
    /// Witnesses that receipt this identifier's events; the reference's `wits`.
    pub witnesses: Vec<IdentifierPrefix>,
    /// How many witness receipts an event needs; the reference's `toad`, defaulting to
    /// [`ample`](keri_protocol::event::witness::ample) of the witness count.
    pub witness_threshold: Option<u32>,
    /// Delegator of this identifier; the reference's `delpre`. Makes the inception delegated.
    pub delegator: Option<IdentifierPrefix>,
    /// Configuration traits; the reference's `estOnly` and `DnD` flags, in list form.
    pub configuration: Vec<ConfigurationTrait>,
    /// Seals anchored in the inception event; the reference's `data`.
    pub anchors: Vec<Sad>,
}

impl Default for HabitatRequest {
    /// The reference's defaults: one transferable key committing to one next key.
    fn default() -> Self {
        Self {
            current_keys: 1,
            next_keys: None,
            signing_threshold: None,
            next_threshold: None,
            transferability: KeyTransferability::Transferable,
            derivation: None,
            witnesses: Vec::new(),
            witness_threshold: None,
            delegator: None,
            configuration: Vec::new(),
            anchors: Vec::new(),
        }
    }
}

/// Creates a [`Habery`].
///
/// The three build methods are the three ways the reference's constructor can resolve its secret
/// material, made explicit so the impossible combinations cannot be written: the reference accepts
/// a passcode *and* a seed and silently ignores the passcode — without even checking its length —
/// and accepts an `aeid` that may or may not belong to the seed. Here a passcode is consumed by
/// [`Self::build_with_passcode`], a seed goes to [`Self::build_encrypted`], and the encryption
/// identifier is always the seed's own public key.
///
/// The reference's `HaberyArgs` also declares a `tier` argument its constructor never reads; it is
/// pinned as a quirk in the `keri-habery` fixture and has no equivalent here — a salt already
/// knows its tier.
#[derive(Debug)]
pub struct HaberyBuilder {
    name: String,
    salt: Option<Salt>,
    prefix_index: u32,
    cost: DerivationCost,
}

impl HaberyBuilder {
    /// Sets the salt identifiers derive from, selecting the salty algorithm.
    ///
    /// Without a salt the registry uses the randy algorithm, exactly as the reference chooses.
    #[must_use]
    pub fn salt(mut self, salt: Salt) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Sets the index the first created identifier takes; the reference's `pidx`.
    #[must_use]
    pub const fn prefix_index(mut self, index: u32) -> Self {
        self.prefix_index = index;
        self
    }

    /// Sets how much key derivation costs.
    ///
    /// The reference hardcodes the production profile; [`DerivationCost::Ephemeral`] exists for
    /// tests and throwaway identifiers that cannot afford 64 MiB of Argon2 per key.
    #[must_use]
    pub const fn derivation_cost(mut self, cost: DerivationCost) -> Self {
        self.cost = cost;
        self
    }

    /// Builds a registry whose manager stores no private keys and derives them again when needed.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::StemTooLong`] via
    /// [`IdentifierError::Manager`] for an oversized name, and
    /// [`ManagerError::RandomKeysNeedEncryption`]
    /// when no salt was supplied, because random keys cannot be derived again and would have to be
    /// held in the clear. The reference refuses the same combination.
    pub fn build(self) -> Result<Habery, IdentifierError> {
        self.assemble(None)
    }

    /// Builds a registry whose private keys are sealed to `seed`'s public key.
    ///
    /// This is the reference's `seed`/`aeid` pair collapsed into one value: the encryption
    /// identifier is always the seed's own public key, so a mismatched pair cannot be written.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::StemTooLong`] via
    /// [`IdentifierError::Manager`] for an oversized name, and a layered
    /// [`IdentifierError::Manager`] when the seed cannot become an encryption key pair.
    pub fn build_encrypted(self, seed: &Signer) -> Result<Habery, IdentifierError> {
        self.assemble(Some(seed))
    }

    /// Builds an encrypted registry from a passcode, exactly as the reference derives one.
    ///
    /// The first [`PASSCODE_LENGTH`](crate::manager::PASSCODE_LENGTH) characters become a
    /// qualified salt, which derives — at the low tier and production cost, as the reference does —
    /// the non-transferable seed that private keys are sealed to. The passcode is consumed here
    /// and never stored.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::PasscodeTooShort`]
    /// or [`ManagerError::InvalidPasscode`] via
    /// [`IdentifierError::Manager`] for an unusable passcode, and whatever
    /// [`Self::build_encrypted`] returns.
    pub fn build_with_passcode(self, passcode: &str) -> Result<Habery, IdentifierError> {
        let passcode_salt = salt_from_passcode(passcode, SecurityTier::Low).map_err(IdentifierError::from)?;
        let seed = passcode_salt
            .derive_signer("", KeyTransferability::NonTransferable)
            .map_err(ManagerError::from)
            .map_err(IdentifierError::from)?;
        self.build_encrypted(&seed)
    }

    fn assemble(self, seed: Option<&Signer>) -> Result<Habery, IdentifierError> {
        let stem = Stem::new(self.name)?;
        let algorithm = if self.salt.is_some() {
            KeyAlgorithm::Salty
        } else {
            KeyAlgorithm::Randy
        };
        let mut builder = KeyManager::builder()
            .algorithm(algorithm)
            .prefix_index(self.prefix_index);
        if let Some(salt) = self.salt {
            builder = builder.salt(salt);
        }
        let manager = match seed {
            Some(seed) => builder.build_encrypted(seed)?,
            None => builder.build()?,
        };
        Ok(Habery {
            stem,
            manager,
            habitats: Vec::new(),
            cost: self.cost,
        })
    }
}

/// A named collection of local identifiers sharing one key manager.
///
/// ```
/// use keri_cesr::crypto::salt::{Salt, SecurityTier};
/// use keri_protocol::event::kind::EventKind;
/// use signify_keys::identifier::{Habery, HabitatRequest};
/// use signify_keys::manager::DerivationCost;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?;
/// let mut habery = Habery::builder("signify")
///     .salt(salt)
///     .derivation_cost(DerivationCost::Ephemeral)
///     .build()?;
///
/// let habitat = habery.make_habitat("test", HabitatRequest::default())?;
/// assert_eq!(habitat.inception().kind(), EventKind::Inception);
/// assert_eq!(habitat.inception().sequence_number(), 0);
///
/// assert_eq!(habery.habitat_by_name("test").map(|habitat| habitat.name()), Some("test"));
/// assert_eq!(habery.habitats().len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Habery {
    stem: Stem,
    manager: KeyManager,
    habitats: Vec<Habitat>,
    cost: DerivationCost,
}

impl Habery {
    /// Starts building a registry with the given name.
    ///
    /// The name is also the derivation stem salty keys derive under; see the module documentation
    /// for what an empty name does.
    #[must_use]
    pub fn builder(name: impl Into<String>) -> HaberyBuilder {
        HaberyBuilder {
            name: name.into(),
            salt: None,
            prefix_index: 0,
            cost: DerivationCost::Production,
        }
    }

    /// Returns this registry's name, which is also its derivation stem.
    #[must_use]
    pub fn name(&self) -> &str {
        self.stem.as_str()
    }

    /// Returns the key manager this registry creates identifiers with; the reference's `mgr`.
    #[must_use]
    pub const fn manager(&self) -> &KeyManager {
        &self.manager
    }

    /// Returns every habitat, in creation order.
    #[must_use]
    pub fn habitats(&self) -> &[Habitat] {
        &self.habitats
    }

    /// Returns the habitat registered under `name`, if any; the reference's `habByName`.
    #[must_use]
    pub fn habitat_by_name(&self, name: &str) -> Option<&Habitat> {
        self.habitats.iter().find(|habitat| habitat.name == name)
    }

    /// Creates an identifier and registers its habitat under `name`; the reference's `makeHab`.
    ///
    /// The keys come from the registry's manager, derived under the registry's name as stem, and
    /// the returned habitat holds the complete serialized inception event. The manager files the
    /// created identifier under its first public key, exactly as the reference leaves it —
    /// `makeHab` never moves it to the event-derived prefix.
    ///
    /// # A named salty registry holds one habitat per transferability
    ///
    /// The salty derivation path under a non-empty stem is built from the rotation and key indices
    /// only — the prefix index is dropped — so a second habitat would re-derive the first one's
    /// keys, and the manager refuses with
    /// [`ManagerError::AlreadyIncepted`], exactly
    /// as the reference throws `Already incepted pre=…`. A habitat of the *other* transferability
    /// derives the same raw key under a different code, which the store treats as distinct, and a
    /// randy registry generates fresh keys every time, so both of those succeed. This is the
    /// pinned reference's own arrangement, recorded in the `keri-habery` fixture.
    ///
    /// Requests that fail validation are refused before any key is derived. A request that fails
    /// inside event construction afterwards — which none of the pre-checked paths can — would
    /// leave the derived keys in the manager, as the reference's own failures do.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::DuplicateHabitat`] when the name is taken — the reference
    /// silently overwrites instead, recorded in the `keri-habery` fixture — the
    /// [`IdentifierError::NonTransferableNextKeys`],
    /// [`IdentifierError::NonTransferableNextThreshold`],
    /// [`IdentifierError::NonTransferableDerivation`], and
    /// [`IdentifierError::NonTransferableContent`] conflicts the reference silently rewrites,
    /// [`IdentifierError::BasicDerivationNeedsOneKey`] for a basic prefix over several keys,
    /// threshold and witness failures from the same checks the inception builder runs, and layered
    /// [`IdentifierError::Manager`] and [`IdentifierError::Event`] failures.
    pub fn make_habitat(
        &mut self,
        name: impl Into<String>,
        request: HabitatRequest,
    ) -> Result<&Habitat, IdentifierError> {
        let name = name.into();
        if self.habitat_by_name(&name).is_some() {
            return Err(IdentifierError::DuplicateHabitat { name });
        }

        // The reference resolves `nsith` from `isith` before anything else, so an explicit
        // signing threshold carries over to the next keys unless a next threshold is given.
        let propagated_next_threshold = request
            .next_threshold
            .clone()
            .or_else(|| request.signing_threshold.clone());

        let (next_keys, next_threshold, derivation) = match request.transferability {
            KeyTransferability::Transferable => (
                request.next_keys.unwrap_or(request.current_keys),
                propagated_next_threshold,
                request.derivation.unwrap_or(PrefixDerivation::Blake3_256),
            ),
            KeyTransferability::NonTransferable => {
                // The reference silently rewrites all three; an explicit contradiction is refused.
                if let Some(requested) = request.next_keys
                    && requested != 0
                {
                    return Err(IdentifierError::NonTransferableNextKeys { requested });
                }
                if let Some(threshold) = &request.next_threshold
                    && threshold.numeric_value() != Some(0)
                {
                    return Err(IdentifierError::NonTransferableNextThreshold);
                }
                if let Some(derivation) = request.derivation
                    && derivation != PrefixDerivation::Ed25519NonTransferable
                {
                    return Err(IdentifierError::NonTransferableDerivation {
                        code: derivation.code().as_str(),
                    });
                }
                // The derivation itself rejects these, but only after every key is derived.
                if !request.witnesses.is_empty() {
                    return Err(IdentifierError::NonTransferableContent { label: "b" });
                }
                if !request.anchors.is_empty() {
                    return Err(IdentifierError::NonTransferableContent { label: "a" });
                }
                (
                    0,
                    Some(SigningThreshold::numeric(0)),
                    PrefixDerivation::Ed25519NonTransferable,
                )
            }
        };

        // The reference's defaults: a simple majority, but never zero, for both thresholds.
        let signing_threshold = match request.signing_threshold {
            Some(threshold) => threshold,
            None => majority(request.current_keys)?,
        };
        let next_threshold = match next_threshold {
            Some(threshold) => threshold,
            None => majority(next_keys)?,
        };

        // Everything checkable before key derivation is checked here, using the same checks the
        // inception builder will run, so an impossible request costs no Argon2 passes.
        check_signing_threshold(&signing_threshold, request.current_keys)?;
        check_next_threshold(&next_threshold, next_keys)?;
        check_distinct(&request.witnesses, "b")?;
        if let Some(threshold) = request.witness_threshold {
            check_witness_threshold(threshold, request.witnesses.len())?;
        }
        if request.delegator.is_some() && !derivation.is_digestive() {
            return Err(IdentifierError::from(EventError::DelegatedPrefixMustBeDigestive {
                code: derivation.code().as_str(),
            }));
        }
        if !derivation.is_digestive() && request.current_keys != 1 {
            return Err(IdentifierError::BasicDerivationNeedsOneKey {
                keys: request.current_keys,
            });
        }

        let incepted = self.manager.incept(InceptionRequest {
            current_keys: request.current_keys,
            next_keys,
            algorithm: None,
            salt: None,
            stem: self.stem.clone(),
            transferability: request.transferability,
            profile: self.cost.profile(self.manager.tier()),
            digest: DigestAlgorithm::Blake3_256,
        })?;

        let mut builder = InceptionBuilder::new(incepted.verifiers)
            .signing_threshold(signing_threshold)
            .next_key_digests(incepted.next_digests)
            .next_threshold(next_threshold)
            .witnesses(request.witnesses)
            .configuration(request.configuration)
            .anchors(request.anchors)
            .prefix_derivation(derivation);
        if let Some(threshold) = request.witness_threshold {
            builder = builder.witness_threshold(threshold);
        }
        if let Some(delegator) = request.delegator {
            builder = builder.delegator(delegator);
        }
        let event = builder.build()?;

        self.habitats.push(Habitat { name, event });
        self.habitats.last().ok_or(IdentifierError::ValueOutOfRange {
            context: "habitat list",
        })
    }
}

/// The reference's default threshold: a simple majority, but never zero.
fn majority(count: usize) -> Result<SigningThreshold, IdentifierError> {
    let count = u128::try_from(count).map_err(|_| IdentifierError::ValueOutOfRange { context: "key count" })?;
    Ok(SigningThreshold::numeric(count.div_ceil(2).max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    use keri_protocol::event::kind::EventKind;
    use keri_protocol::serialization::SadValue;

    /// The raw salt the pinned `habery.test.ts` builds its salter from.
    const SALT_RAW: &[u8] = b"0123456789abcdef";
    /// The passcode the pinned `habery.test.ts` uses.
    const PASSCODE: &str = "0123456789abcdefghijk";

    /// Checks that a refusal is the expected non-transferable conflict.
    type ConflictCheck = fn(&IdentifierError) -> bool;

    fn salt() -> Result<Salt, Box<dyn Error>> {
        Ok(Salt::from_raw(SALT_RAW, SecurityTier::Low)?)
    }

    /// A cheap salty registry for tests that do not pin production key material.
    fn ephemeral(name: &str) -> Result<Habery, Box<dyn Error>> {
        Ok(Habery::builder(name)
            .salt(salt()?)
            .derivation_cost(DerivationCost::Ephemeral)
            .build()?)
    }

    fn text_field(habitat: &Habitat, label: &str) -> Option<String> {
        habitat.inception().sad().get_text(label).map(str::to_owned)
    }

    fn list_field(habitat: &Habitat, label: &str) -> Result<Vec<String>, Box<dyn Error>> {
        match habitat.inception().sad().get(label) {
            Some(SadValue::Array(items)) => items
                .iter()
                .map(|item| match item {
                    SadValue::Text(text) => Ok(text.clone()),
                    other => Err(format!("field {label:?} holds a non-text value: {other:?}").into()),
                })
                .collect(),
            other => Err(format!("field {label:?} is not a list: {other:?}").into()),
        }
    }

    #[test]
    fn a_salty_registry_reports_its_name_and_algorithm() -> Result<(), Box<dyn Error>> {
        let habery = ephemeral("signify")?;
        assert_eq!(habery.name(), "signify");
        assert_eq!(habery.manager().algorithm(), KeyAlgorithm::Salty);
        // A salt alone encrypts nothing.
        assert!(habery.manager().encryption_identifier().is_none());
        Ok(())
    }

    #[test]
    fn a_non_transferable_habitat_accepts_its_explicit_values() -> Result<(), Box<dyn Error>> {
        // An explicit zero next threshold and an explicit basic derivation agree with the forced
        // values and are accepted.
        let mut habery = ephemeral("signify")?;
        habery.make_habitat(
            "witness",
            HabitatRequest {
                transferability: KeyTransferability::NonTransferable,
                next_keys: Some(0),
                next_threshold: Some(SigningThreshold::numeric(0)),
                derivation: Some(PrefixDerivation::Ed25519NonTransferable),
                ..HabitatRequest::default()
            },
        )?;

        // The same registry does accept a habitat of the other transferability: the raw key is the
        // same, but its code differs, which the store treats as a distinct public key.
        habery.make_habitat("controller", HabitatRequest::default())?;
        Ok(())
    }

    #[test]
    fn an_unnamed_registry_holds_several_distinct_habitats() -> Result<(), Box<dyn Error>> {
        // An empty-name registry keeps the prefix index in the path, so it can hold several
        // habitats — at the price of the derivation collapse its own test pins.
        let mut unnamed = ephemeral("")?;
        let first = unnamed
            .make_habitat("first", HabitatRequest::default())?
            .prefix()
            .qb64()?;
        let second = unnamed
            .make_habitat("second", HabitatRequest::default())?
            .prefix()
            .qb64()?;
        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn non_transferable_conflicts_are_refused_before_any_key_derives() -> Result<(), Box<dyn Error>> {
        let mut habery = ephemeral("signify")?;
        let witness = ephemeral("other")?
            .make_habitat(
                "w",
                HabitatRequest {
                    transferability: KeyTransferability::NonTransferable,
                    ..HabitatRequest::default()
                },
            )?
            .prefix()
            .clone();

        let mut anchor = Sad::new();
        anchor.insert("i", SadValue::text("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"))?;

        let cases: Vec<(HabitatRequest, ConflictCheck)> = vec![
            (
                HabitatRequest {
                    transferability: KeyTransferability::NonTransferable,
                    next_keys: Some(1),
                    ..HabitatRequest::default()
                },
                |error| matches!(error, IdentifierError::NonTransferableNextKeys { requested: 1 }),
            ),
            (
                HabitatRequest {
                    transferability: KeyTransferability::NonTransferable,
                    next_threshold: Some(SigningThreshold::numeric(1)),
                    ..HabitatRequest::default()
                },
                |error| matches!(error, IdentifierError::NonTransferableNextThreshold),
            ),
            (
                HabitatRequest {
                    transferability: KeyTransferability::NonTransferable,
                    derivation: Some(PrefixDerivation::Blake3_256),
                    ..HabitatRequest::default()
                },
                |error| matches!(error, IdentifierError::NonTransferableDerivation { .. }),
            ),
            (
                HabitatRequest {
                    transferability: KeyTransferability::NonTransferable,
                    witnesses: vec![witness],
                    ..HabitatRequest::default()
                },
                |error| matches!(error, IdentifierError::NonTransferableContent { label: "b" }),
            ),
            (
                HabitatRequest {
                    transferability: KeyTransferability::NonTransferable,
                    anchors: vec![anchor],
                    ..HabitatRequest::default()
                },
                |error| matches!(error, IdentifierError::NonTransferableContent { label: "a" }),
            ),
        ];
        for (request, expected) in cases {
            match habery.make_habitat("refused", request) {
                Err(error) if expected(&error) => {}
                other => return Err(format!("expected a non-transferable conflict, got {other:?}").into()),
            }
        }
        // Every refusal happened before the manager derived anything.
        assert_eq!(habery.manager().prefix_index(), 0);
        assert!(habery.habitats().is_empty());
        Ok(())
    }

    #[test]
    fn witnesses_and_their_threshold_follow_the_reference() -> Result<(), Box<dyn Error>> {
        let witness = ephemeral("other")?
            .make_habitat(
                "w",
                HabitatRequest {
                    transferability: KeyTransferability::NonTransferable,
                    ..HabitatRequest::default()
                },
            )?
            .prefix()
            .clone();

        let mut habery = ephemeral("signify")?;
        let habitat = habery.make_habitat(
            "witnessed",
            HabitatRequest {
                witnesses: vec![witness.clone()],
                ..HabitatRequest::default()
            },
        )?;
        assert_eq!(text_field(habitat, "bt").as_deref(), Some("1"));
        assert_eq!(list_field(habitat, "b")?, [witness.qb64()?]);

        // An impossible witness threshold is refused before any key derives.
        assert!(matches!(
            habery.make_habitat(
                "refused",
                HabitatRequest {
                    witnesses: vec![witness.clone()],
                    witness_threshold: Some(2),
                    ..HabitatRequest::default()
                },
            ),
            Err(IdentifierError::Event { .. })
        ));
        assert!(matches!(
            habery.make_habitat(
                "refused",
                HabitatRequest {
                    witnesses: vec![witness.clone(), witness],
                    ..HabitatRequest::default()
                },
            ),
            Err(IdentifierError::Event { .. })
        ));
        assert_eq!(habery.manager().prefix_index(), 1);
        Ok(())
    }

    #[test]
    fn a_delegated_habitat_writes_the_delegator_last() -> Result<(), Box<dyn Error>> {
        let delegator = IdentifierPrefix::from_qb64("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C")?;
        let mut habery = ephemeral("signify")?;
        let habitat = habery.make_habitat(
            "delegated",
            HabitatRequest {
                delegator: Some(delegator.clone()),
                ..HabitatRequest::default()
            },
        )?;
        assert_eq!(habitat.inception().kind(), EventKind::DelegatedInception);
        let labels: Vec<&str> = habitat.inception().sad().entries().map(|(label, _)| label).collect();
        assert_eq!(labels.last(), Some(&"di"));
        assert_eq!(text_field(habitat, "di"), Some(delegator.qb64()?));

        // A delegated identifier cannot use a basic derivation, and the conflict is caught before
        // any key derives.
        assert!(matches!(
            habery.make_habitat(
                "refused",
                HabitatRequest {
                    delegator: Some(delegator),
                    derivation: Some(PrefixDerivation::Ed25519),
                    ..HabitatRequest::default()
                },
            ),
            Err(IdentifierError::Event { .. })
        ));
        assert_eq!(habery.manager().prefix_index(), 1);
        Ok(())
    }

    #[test]
    fn configuration_and_anchors_are_carried_in_order() -> Result<(), Box<dyn Error>> {
        let mut anchor = Sad::new();
        anchor.insert("i", SadValue::text("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"))?;

        let mut habery = ephemeral("signify")?;
        let habitat = habery.make_habitat(
            "configured",
            HabitatRequest {
                configuration: vec![ConfigurationTrait::EstablishmentOnly, ConfigurationTrait::DoNotDelegate],
                anchors: vec![anchor.clone()],
                ..HabitatRequest::default()
            },
        )?;
        assert_eq!(list_field(habitat, "c")?, ["EO", "DND"]);
        assert_eq!(
            habitat.inception().sad().get("a"),
            Some(&SadValue::Array(vec![SadValue::Map(anchor)]))
        );
        Ok(())
    }

    #[test]
    fn zero_next_keys_need_an_explicit_zero_threshold() -> Result<(), Box<dyn Error>> {
        let mut habery = ephemeral("signify")?;

        // The reference's default formula never yields zero, so it derives a threshold of one over
        // zero digests and emits an event no rotation can ever satisfy; Rust refuses instead. See
        // the `keri-habery` fixture.
        assert!(matches!(
            habery.make_habitat(
                "refused",
                HabitatRequest {
                    next_keys: Some(0),
                    ..HabitatRequest::default()
                },
            ),
            Err(IdentifierError::Event { .. })
        ));
        assert_eq!(habery.manager().prefix_index(), 0);

        // An explicit zero abandons the identifier cleanly.
        let habitat = habery.make_habitat(
            "abandoned",
            HabitatRequest {
                next_keys: Some(0),
                next_threshold: Some(SigningThreshold::numeric(0)),
                ..HabitatRequest::default()
            },
        )?;
        assert_eq!(text_field(habitat, "nt").as_deref(), Some("0"));
        assert_eq!(list_field(habitat, "n")?, [] as [String; 0]);
        Ok(())
    }

    #[test]
    fn a_basic_derivation_needs_one_key() -> Result<(), Box<dyn Error>> {
        let mut habery = ephemeral("signify")?;
        assert!(matches!(
            habery.make_habitat(
                "refused",
                HabitatRequest {
                    current_keys: 2,
                    derivation: Some(PrefixDerivation::Ed25519),
                    ..HabitatRequest::default()
                },
            ),
            Err(IdentifierError::BasicDerivationNeedsOneKey { keys: 2 })
        ));
        assert_eq!(habery.manager().prefix_index(), 0);

        // With one key an explicit basic derivation makes the key itself the identifier.
        let habitat = habery.make_habitat(
            "basic",
            HabitatRequest {
                derivation: Some(PrefixDerivation::Ed25519),
                ..HabitatRequest::default()
            },
        )?;
        assert_eq!(
            Some(habitat.prefix().qb64()?),
            list_field(habitat, "k")?.first().cloned()
        );
        Ok(())
    }

    #[test]
    fn a_zero_signing_threshold_is_refused_before_any_key_derives() -> Result<(), Box<dyn Error>> {
        let mut habery = ephemeral("signify")?;
        for request in [
            HabitatRequest {
                signing_threshold: Some(SigningThreshold::numeric(0)),
                ..HabitatRequest::default()
            },
            HabitatRequest {
                signing_threshold: Some(SigningThreshold::numeric(2)),
                ..HabitatRequest::default()
            },
        ] {
            assert!(matches!(
                habery.make_habitat("refused", request),
                Err(IdentifierError::Event { .. })
            ));
        }
        assert_eq!(habery.manager().prefix_index(), 0);
        Ok(())
    }

    #[test]
    fn an_empty_name_collapses_salty_derivation() -> Result<(), Box<dyn Error>> {
        let mut habery = ephemeral("")?;
        let habitat = habery.make_habitat("collapsed", HabitatRequest::default())?;
        let current_key = list_field(habitat, "k")?
            .first()
            .cloned()
            .ok_or("the habitat has no signing key")?;

        // With an empty stem the derivation path drops the rotation index, so the committed next
        // key is the key already in use — the reference behavior the `keri-manager` fixture pins.
        let situation = habery
            .manager()
            .store()
            .situation(&current_key)
            .ok_or("the manager holds no key sets for the habitat")?;
        assert_eq!(situation.current.public_keys, situation.next.public_keys);
        Ok(())
    }

    #[test]
    fn a_passcode_only_registry_uses_random_keys() -> Result<(), Box<dyn Error>> {
        let mut habery = Habery::builder("signify").build_with_passcode(PASSCODE)?;
        assert_eq!(habery.manager().algorithm(), KeyAlgorithm::Randy);
        assert!(habery.manager().encryption_identifier().is_some());

        let first = habery.make_habitat("one", HabitatRequest::default())?.prefix().qb64()?;
        let second = habery.make_habitat("two", HabitatRequest::default())?.prefix().qb64()?;
        assert_ne!(first, second);
        assert!(first.starts_with('E'));
        Ok(())
    }

    #[test]
    fn builder_failures_are_typed() -> Result<(), Box<dyn Error>> {
        // No salt and no encryption: random keys would have to be held in the clear.
        assert!(matches!(
            Habery::builder("signify").build(),
            Err(IdentifierError::Manager { .. })
        ));
        // The reference's own passcode length check, plus the alphabet check it lacks.
        assert!(matches!(
            Habery::builder("signify").build_with_passcode("too-short"),
            Err(IdentifierError::Manager { .. })
        ));
        assert!(matches!(
            Habery::builder("signify").build_with_passcode("0123456789abcdefghij*"),
            Err(IdentifierError::Manager { .. })
        ));
        // An oversized name cannot become a derivation stem.
        assert!(matches!(
            Habery::builder("x".repeat(crate::manager::MAX_STEM_BYTES + 1))
                .salt(salt()?)
                .build(),
            Err(IdentifierError::Manager { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_registry_starts_at_the_requested_prefix_index() -> Result<(), Box<dyn Error>> {
        let mut habery = Habery::builder("signify")
            .salt(salt()?)
            .prefix_index(4)
            .derivation_cost(DerivationCost::Ephemeral)
            .build()?;
        assert_eq!(habery.manager().prefix_index(), 4);
        habery.make_habitat("offset", HabitatRequest::default())?;
        assert_eq!(habery.manager().prefix_index(), 5);
        Ok(())
    }

    #[test]
    fn a_registry_never_prints_its_salt() -> Result<(), Box<dyn Error>> {
        let habery = ephemeral("signify")?;
        let rendered = format!("{habery:?}");
        assert!(!rendered.contains("0123456789abcdef"));
        Ok(())
    }
}
