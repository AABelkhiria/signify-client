//! The client's own signing identity, derived from a passcode.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;

use crate::controller::agent::Agent;
use crate::controller::error::ControllerError;
use crate::manager::key_manager::salt_from_passcode;
use crate::manager::{DerivationCost, KeyIndices, ManagerError, SaltyKeyCreator, Stem};
use keri_protocol::event::EventError;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::interaction::InteractionBuilder;
use keri_protocol::prefix::{IdentifierPrefix, PrefixDerivation};
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadError, SadValue, SerializedEvent};
use keri_protocol::threshold::SigningThreshold;

/// The derivation stem every controller key derives under; the reference's `signify:controller`.
pub const CONTROLLER_STEM: &str = "signify:controller";

/// Optional construction parameters, with the reference's defaults.
#[derive(Clone, Copy, Debug, Default)]
pub struct ControllerOptions {
    /// The rotation index keys derive at; the reference's `ridx`, default zero.
    ///
    /// The reference exposes `ridx` as a mutable public field and its client assigns it after
    /// construction *without re-deriving any key*, so the field and the keys can disagree. Here
    /// the index is fixed at construction and always agrees with the derived keys; that silent
    /// inconsistency is unrepresentable.
    pub rotation_index: u32,
    /// How much key derivation costs; the reference hardcodes the production profile.
    pub derivation_cost: DerivationCost,
}

/// The current establishment or interaction event, with the fields the controller reads cached.
#[derive(Clone, Debug)]
pub(crate) struct CurrentEvent {
    event: SerializedEvent,
    prefix: IdentifierPrefix,
    said: Said,
    sequence_number: u128,
}

impl CurrentEvent {
    /// Validates that an event carries everything the controller must read from it.
    pub(crate) fn from_serialized(event: SerializedEvent) -> Result<Self, ControllerError> {
        let prefix = match event.identifier_prefix() {
            Some(prefix) => IdentifierPrefix::from_qb64(prefix)?,
            None => return Err(ControllerError::RestoredEventIncomplete { label: "i" }),
        };
        let said = match event.said() {
            Some(said) => Said::from_qb64(said)?,
            None => return Err(ControllerError::RestoredEventIncomplete { label: "d" }),
        };
        let sequence_number = event
            .sequence_number()?
            .ok_or(ControllerError::RestoredEventIncomplete { label: "s" })?
            .value();
        Ok(Self {
            event,
            prefix,
            said,
            sequence_number,
        })
    }
}

/// The key material one passcode derives for a controller.
struct DerivedKeys {
    salt: Salt,
    signer: Signer,
    next_signer: Signer,
    next_digest: Digest,
}

impl DerivedKeys {
    /// Derives the current and next key at `rotation_index` and `rotation_index + 1`.
    fn derive(passcode: &str, tier: SecurityTier, options: ControllerOptions) -> Result<Self, ControllerError> {
        let salt = salt_from_passcode(passcode, tier)?;
        let stem = Stem::new(CONTROLLER_STEM)?;
        let profile = options.derivation_cost.profile(tier);
        let next_index = options
            .rotation_index
            .checked_add(1)
            .ok_or(ControllerError::SequenceNumberOverflow)?;

        let creator = SaltyKeyCreator::new(&salt, stem);
        let signer = single_signer(&creator, options.rotation_index, profile)?;
        let next_signer = single_signer(&creator, next_index, profile)?;
        let next_digest = Digest::derive(DigestAlgorithm::Blake3_256, &next_signer.verifier().qb64_bytes()?);
        Ok(Self {
            salt,
            signer,
            next_signer,
            next_digest,
        })
    }

    /// Builds the controller's inception event, exactly as the reference's constructor does.
    fn inception(&self) -> Result<SerializedEvent, ControllerError> {
        let event = InceptionBuilder::new(vec![self.signer.verifier().clone()])
            .signing_threshold(SigningThreshold::numeric(1))
            .next_key_digests(vec![self.next_digest])
            .next_threshold(SigningThreshold::numeric(1))
            .witness_threshold(0)
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()?;
        Ok(event.into_serialized())
    }
}

/// The client's controller: the account identity that signs every request to KERIA.
///
/// This is the reference's `Controller`. It derives one signing key and one committed next key
/// from the passcode under [`CONTROLLER_STEM`], holds the current event — the local inception, a
/// restored establishment event, or the delegation-approval interaction — and builds the artifacts
/// the client submits. It performs no I/O; Roadmap 6.4 owns the requests these artifacts travel
/// in.
///
/// The reference also carries two members that are not ported: a `verfers` getter that calls a
/// property as a function and therefore throws on every use, and a `derive` method nothing calls,
/// which reads a different state shape than the constructor and throws on its own `undefined`
/// branch. Both are pinned in `PORTING.md` §9.
///
/// ```
/// use keri_cesr::crypto::salt::SecurityTier;
/// use signify_keys::controller::{Controller, ControllerOptions};
/// use signify_keys::manager::DerivationCost;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let controller = Controller::with_options(
///     "0123456789abcdefghijk",
///     SecurityTier::Low,
///     ControllerOptions {
///         derivation_cost: DerivationCost::Ephemeral,
///         ..ControllerOptions::default()
///     },
/// )?;
/// assert_eq!(controller.current_event().sad().get_text("s"), Some("0"));
/// assert_eq!(controller.current_keys().len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Controller {
    pub(crate) salt: Salt,
    pub(crate) tier: SecurityTier,
    pub(crate) rotation_index: u32,
    pub(crate) cost: DerivationCost,
    pub(crate) signer: Signer,
    pub(crate) next_signer: Signer,
    pub(crate) keys: Vec<String>,
    pub(crate) next_digests: Vec<String>,
    pub(crate) current: CurrentEvent,
}

impl Controller {
    /// Derives a controller from a passcode and builds its inception event.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::PasscodeTooShort`]
    /// or [`ManagerError::InvalidPasscode`] via
    /// [`ControllerError::Manager`] for an unusable passcode — the reference instead slices
    /// whatever it is given and fails much later — and layered derivation or event failures.
    pub fn new(passcode: &str, tier: SecurityTier) -> Result<Self, ControllerError> {
        Self::with_options(passcode, tier, ControllerOptions::default())
    }

    /// Derives a controller with explicit options.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::new`] returns.
    pub fn with_options(
        passcode: &str,
        tier: SecurityTier,
        options: ControllerOptions,
    ) -> Result<Self, ControllerError> {
        let derived = DerivedKeys::derive(passcode, tier, options)?;
        let current = CurrentEvent::from_serialized(derived.inception()?)?;
        Self::assemble(derived, tier, options, current)
    }

    /// Restores a controller against a stored establishment event.
    ///
    /// The reference's rule is kept: an event at sequence number zero is *not* adopted — the
    /// controller rebuilds its own inception from the derived keys, which for a well-formed state
    /// is the same event. A later establishment event is adopted as found; the reference performs
    /// no check that it belongs to the derived keys, and neither does this, which `PORTING.md` §9
    /// records.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RestoredEventIncomplete`] when the event lacks an identifier,
    /// SAID, or sequence number, and whatever [`Self::new`] returns.
    pub fn restore(
        passcode: &str,
        tier: SecurityTier,
        options: ControllerOptions,
        event: SerializedEvent,
    ) -> Result<Self, ControllerError> {
        let derived = DerivedKeys::derive(passcode, tier, options)?;
        let restored = CurrentEvent::from_serialized(event)?;
        let current = if restored.sequence_number == 0 {
            CurrentEvent::from_serialized(derived.inception()?)?
        } else {
            restored
        };
        Self::assemble(derived, tier, options, current)
    }

    /// Assembles the controller from its derived keys and current event.
    fn assemble(
        derived: DerivedKeys,
        tier: SecurityTier,
        options: ControllerOptions,
        current: CurrentEvent,
    ) -> Result<Self, ControllerError> {
        let keys = vec![derived.signer.verifier().qb64()?];
        let next_digests = vec![derived.next_digest.qb64()?];
        Ok(Self {
            salt: derived.salt,
            tier,
            rotation_index: options.rotation_index,
            cost: options.derivation_cost,
            signer: derived.signer,
            next_signer: derived.next_signer,
            keys,
            next_digests,
            current,
        })
    }

    /// Returns the controller's identifier prefix; the reference's `pre`.
    #[must_use]
    pub const fn prefix(&self) -> &IdentifierPrefix {
        &self.current.prefix
    }

    /// Returns the current event: the inception, a restored establishment event, or the
    /// delegation-approval interaction; the reference's `serder`.
    #[must_use]
    pub const fn current_event(&self) -> &SerializedEvent {
        &self.current.event
    }

    /// Returns the SAID of the current event.
    #[must_use]
    pub const fn current_said(&self) -> Said {
        self.current.said
    }

    /// Returns the sequence number of the current event.
    #[must_use]
    pub const fn current_sequence_number(&self) -> u128 {
        self.current.sequence_number
    }

    /// Returns the current signing keys as qualified Base64, in order.
    #[must_use]
    pub fn current_keys(&self) -> &[String] {
        &self.keys
    }

    /// Returns the digests committing to the next keys as qualified Base64, in order.
    #[must_use]
    pub fn next_digests(&self) -> &[String] {
        &self.next_digests
    }

    /// Returns the rotation index the keys were derived at.
    #[must_use]
    pub const fn rotation_index(&self) -> u32 {
        self.rotation_index
    }

    /// Returns the security tier the keys derive under.
    #[must_use]
    pub const fn tier(&self) -> SecurityTier {
        self.tier
    }

    /// Returns the passcode-derived salt; the reference's `salter`, which the client hands to the
    /// keeper factory.
    #[must_use]
    pub const fn salt(&self) -> &Salt {
        &self.salt
    }

    /// Returns the current signing key.
    ///
    /// This is the one deliberate secret export, mirroring the keeper's `expose_signers`: the
    /// client must build a request signer from it. The reference publishes the same signer as a
    /// public field.
    #[must_use]
    pub const fn expose_signer(&self) -> &Signer {
        &self.signer
    }

    /// Re-derives this controller's signing key as an owned value.
    ///
    /// [`Self::expose_signer`] lends the key the controller holds, which is enough to sign an
    /// event in place. An HTTP authenticator instead needs to *own* one for the life of a
    /// connection, and Roadmap 2.5 deliberately made [`Signer`] non-cloneable so a secret cannot be
    /// duplicated by accident. Re-deriving is the way to get a second one, and it goes through the
    /// same salt, stem, and rotation index the controller itself used, so the two always agree.
    ///
    /// This costs one key derivation, at whatever profile the controller was built with.
    ///
    /// # Errors
    ///
    /// Returns layered [`ControllerError::Crypto`] or [`ControllerError::Manager`] failures when
    /// the key cannot be derived.
    pub fn derive_signing_key(&self) -> Result<Signer, ControllerError> {
        let stem = Stem::new(CONTROLLER_STEM)?;
        let creator = SaltyKeyCreator::new(&self.salt, stem);
        single_signer(&creator, self.rotation_index, self.cost.profile(self.tier))
    }

    /// Signs the current event; the reference's `event` getter.
    ///
    /// # Errors
    ///
    /// Returns a layered [`ControllerError::Crypto`] when signing fails.
    pub fn signed_event(&self) -> Result<(&SerializedEvent, IndexedSignature), ControllerError> {
        let signature = self
            .signer
            .sign_indexed(self.current.event.raw(), SignaturePlacement::both_lists(0))?;
        Ok((&self.current.event, signature))
    }

    /// Anchors the agent's inception in an interaction event and signs it; the reference's
    /// `approveDelegation`.
    ///
    /// The interaction becomes the controller's current event, exactly as the reference mutates
    /// its `serder`, so a repeated call chains a further interaction on top of the first.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::SequenceNumberOverflow`] when the log cannot advance, and
    /// layered event or signing failures.
    pub fn approve_delegation(&mut self, agent: &Agent) -> Result<IndexedSignature, ControllerError> {
        let mut anchor = Sad::new();
        anchor
            .insert("i", SadValue::Text(agent.prefix().qb64()?))
            .map_err(sad_error)?;
        anchor
            .insert("s", SadValue::text(format!("{:x}", agent.sequence_number())))
            .map_err(sad_error)?;
        anchor
            .insert("d", SadValue::Text(agent.said().qb64()?))
            .map_err(sad_error)?;

        let sequence_number = self
            .current
            .sequence_number
            .checked_add(1)
            .ok_or(ControllerError::SequenceNumberOverflow)?;
        let event = InteractionBuilder::new(self.current.prefix.clone(), self.current.said, sequence_number)
            .anchors(vec![anchor])
            .build()?;

        self.current = CurrentEvent::from_serialized(event.into_serialized())?;
        let signature = self
            .signer
            .sign_indexed(self.current.event.raw(), SignaturePlacement::both_lists(0))?;
        Ok(signature)
    }
}

/// Derives exactly one controller key at the given rotation index.
pub(crate) fn single_signer(
    creator: &SaltyKeyCreator<'_>,
    rotation_index: u32,
    profile: KeyDerivationProfile,
) -> Result<Signer, ControllerError> {
    let created = creator.create(
        1,
        KeyTransferability::Transferable,
        KeyIndices::new(0, rotation_index, 0),
        profile,
    )?;
    created
        .into_entries()
        .into_iter()
        .next()
        .map(|(signer, _)| signer)
        .ok_or_else(|| ControllerError::from(ManagerError::NoCurrentKeys))
}

fn sad_error(source: SadError) -> EventError {
    EventError::Sad {
        source: Box::new(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    use crate::manager::ManagerError;
    use keri_protocol::event::kind::EventKind;

    /// The passcode the pinned `controller.test.ts` uses.
    const PASSCODE: &str = "0123456789abcdefghijk";

    fn ephemeral(passcode: &str) -> Result<Controller, Box<dyn Error>> {
        Ok(Controller::with_options(
            passcode,
            SecurityTier::Low,
            ControllerOptions {
                derivation_cost: DerivationCost::Ephemeral,
                ..ControllerOptions::default()
            },
        )?)
    }

    fn mock_agent(sequence_number_hex: &str) -> Result<crate::controller::Agent, Box<dyn Error>> {
        let state: keria_types::api::KeyState = serde_json::from_value(serde_json::json!({
            "i": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
            "s": sequence_number_hex,
            "p": "",
            "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
            "f": "0",
            "dt": "2023-12-01T10:05:25.062609+00:00",
            "et": "dip",
            "kt": "1",
            "k": ["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE"],
            "nt": "1",
            "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
            "bt": "0",
            "b": [],
            "c": [],
            "ee": {"s": "0", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", "br": [], "ba": []},
            "di": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"
        }))?;
        Ok(crate::controller::Agent::from_key_state(state)?)
    }

    #[test]
    fn the_pinned_controller_prefixes_are_reproduced() -> Result<(), Box<dyn Error>> {
        // The two pinned `controller.test.ts` cases, at the production Argon2 cost the reference
        // hardcodes.
        let controller = Controller::new(PASSCODE, SecurityTier::Low)?;
        assert_eq!(
            controller.prefix().qb64()?,
            "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"
        );
        let controller = Controller::new("abcdefghijk0123456789", SecurityTier::Low)?;
        assert_eq!(
            controller.prefix().qb64()?,
            "EIIY2SgE_bqKLl2MlnREUawJ79jTuucvWwh-S6zsSUFo"
        );
        Ok(())
    }

    #[test]
    fn the_inception_matches_the_reference_shape() -> Result<(), Box<dyn Error>> {
        let controller = ephemeral(PASSCODE)?;
        let sad = controller.current_event().sad();
        assert_eq!(sad.get_text("t"), Some(EventKind::Inception.as_str()));
        assert_eq!(sad.get_text("s"), Some("0"));
        assert_eq!(sad.get_text("kt"), Some("1"));
        assert_eq!(sad.get_text("nt"), Some("1"));
        assert_eq!(sad.get_text("bt"), Some("0"));
        assert_eq!(controller.current_keys().len(), 1);
        assert_eq!(controller.next_digests().len(), 1);
        assert!(controller.prefix().is_digestive());
        assert_eq!(controller.current_said().qb64()?, controller.prefix().qb64()?);
        assert_eq!(controller.current_sequence_number(), 0);
        assert_eq!(controller.tier(), SecurityTier::Low);
        assert_eq!(controller.rotation_index(), 0);
        // The event's key is the controller's key, and its digest commits to the next signer.
        assert_eq!(
            sad.get("k"),
            Some(&SadValue::Array(vec![SadValue::text(
                controller.current_keys().first().map_or("", String::as_str)
            )]))
        );
        Ok(())
    }

    #[test]
    fn a_rotation_index_moves_the_whole_key_chain() -> Result<(), Box<dyn Error>> {
        let base = ephemeral(PASSCODE)?;
        let advanced = Controller::with_options(
            PASSCODE,
            SecurityTier::Low,
            ControllerOptions {
                rotation_index: 1,
                derivation_cost: DerivationCost::Ephemeral,
            },
        )?;
        assert_ne!(base.prefix().qb64()?, advanced.prefix().qb64()?);
        // The advanced controller's current key is the base one's committed next key.
        let base_next = Digest::from_qb64(base.next_digests().first().map_or("", String::as_str))?;
        let advanced_key = advanced.current_keys().first().cloned().unwrap_or_default();
        let advanced_digest = Digest::derive(DigestAlgorithm::Blake3_256, advanced_key.as_bytes());
        assert_eq!(base_next.qb64()?, advanced_digest.qb64()?);
        assert_eq!(advanced.rotation_index(), 1);
        Ok(())
    }

    #[test]
    fn restore_rebuilds_the_inception_at_sequence_zero() -> Result<(), Box<dyn Error>> {
        let controller = ephemeral(PASSCODE)?;
        let inception_raw = controller.current_event().raw().to_vec();

        // The reference's rule: an establishment event at sequence zero is not adopted.
        let restored = Controller::restore(
            PASSCODE,
            SecurityTier::Low,
            ControllerOptions {
                derivation_cost: DerivationCost::Ephemeral,
                ..ControllerOptions::default()
            },
            SerializedEvent::parse(&inception_raw)?,
        )?;
        assert_eq!(restored.current_event().raw(), inception_raw.as_slice());
        Ok(())
    }

    #[test]
    fn restore_adopts_a_later_establishment_event_unchecked() -> Result<(), Box<dyn Error>> {
        // Any event past sequence zero is adopted as found — even one that belongs to different
        // keys, because the reference performs no ownership check.
        let mut other = ephemeral("abcdefghijk0123456789")?;
        other.approve_delegation(&mock_agent("0")?)?;
        let foreign = SerializedEvent::parse(other.current_event().raw())?;
        let foreign_raw = foreign.raw().to_vec();

        let restored = Controller::restore(
            PASSCODE,
            SecurityTier::Low,
            ControllerOptions {
                derivation_cost: DerivationCost::Ephemeral,
                ..ControllerOptions::default()
            },
            foreign,
        )?;
        assert_eq!(restored.current_event().raw(), foreign_raw.as_slice());
        assert_eq!(restored.prefix().qb64()?, other.prefix().qb64()?);
        // The derived keys are still the passcode's own.
        assert_ne!(restored.current_keys(), other.current_keys());
        Ok(())
    }

    #[test]
    fn restore_refuses_an_event_missing_what_it_must_read() -> Result<(), Box<dyn Error>> {
        let mut sad = Sad::new();
        sad.insert("v", SadValue::text("KERI10JSON000000_"))?;
        sad.insert("t", SadValue::text("icp"))?;
        sad.insert("d", SadValue::text("EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY"))?;
        let event = SerializedEvent::from_sad(sad)?;
        assert!(matches!(
            Controller::restore(
                PASSCODE,
                SecurityTier::Low,
                ControllerOptions {
                    derivation_cost: DerivationCost::Ephemeral,
                    ..ControllerOptions::default()
                },
                event,
            ),
            Err(ControllerError::RestoredEventIncomplete { label: "i" })
        ));
        Ok(())
    }

    #[test]
    fn approving_a_delegation_anchors_the_agent_and_advances_the_log() -> Result<(), Box<dyn Error>> {
        let mut controller = ephemeral(PASSCODE)?;
        let inception_said = controller.current_said();
        let agent = mock_agent("a")?;

        let signature = controller.approve_delegation(&agent)?;
        let sad = controller.current_event().sad();
        assert_eq!(sad.get_text("t"), Some(EventKind::Interaction.as_str()));
        assert_eq!(sad.get_text("s"), Some("1"));
        assert_eq!(sad.get_text("p"), Some(inception_said.qb64()?.as_str()));
        assert_eq!(controller.current_sequence_number(), 1);

        // The anchor names the agent's inception: its prefix, hexadecimal sequence number, SAID.
        let Some(SadValue::Array(anchors)) = sad.get("a") else {
            return Err("the interaction carries no anchors".into());
        };
        let Some(SadValue::Map(anchor)) = anchors.first() else {
            return Err("the anchor is not a field map".into());
        };
        assert_eq!(anchor.get_text("i"), Some(agent.prefix().qb64()?.as_str()));
        assert_eq!(anchor.get_text("s"), Some("a"));
        assert_eq!(anchor.get_text("d"), Some(agent.said().qb64()?.as_str()));

        // The signature is the controller key's, at position zero, over the interaction bytes.
        assert_eq!(signature.index(), 0);
        assert!(
            controller
                .expose_signer()
                .verifier()
                .verify(signature.raw(), controller.current_event().raw())
                .is_ok()
        );

        // A second approval chains a further interaction, exactly as the reference mutates.
        controller.approve_delegation(&agent)?;
        assert_eq!(controller.current_sequence_number(), 2);
        Ok(())
    }

    #[test]
    fn the_signed_event_verifies_against_the_controller_key() -> Result<(), Box<dyn Error>> {
        let controller = ephemeral(PASSCODE)?;
        let (event, signature) = controller.signed_event()?;
        assert_eq!(event.raw(), controller.current_event().raw());
        assert_eq!(signature.index(), 0);
        assert!(
            controller
                .expose_signer()
                .verifier()
                .verify(signature.raw(), event.raw())
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn an_unusable_passcode_is_refused_before_any_derivation() {
        assert!(matches!(
            Controller::new("too-short", SecurityTier::Low),
            Err(ControllerError::Manager { source })
                if matches!(*source, ManagerError::PasscodeTooShort { .. })
        ));
        assert!(matches!(
            Controller::new("0123456789abcdefghij*", SecurityTier::Low),
            Err(ControllerError::Manager { source })
                if matches!(*source, ManagerError::InvalidPasscode { .. })
        ));
    }

    #[test]
    fn a_controller_never_prints_its_secrets() -> Result<(), Box<dyn Error>> {
        let controller = ephemeral(PASSCODE)?;
        let rendered = format!("{controller:?}");
        assert!(!rendered.contains(PASSCODE));
        assert!(!rendered.contains("0AA0123456789abcdefghijk"));
        Ok(())
    }
}
