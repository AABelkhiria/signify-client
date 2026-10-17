//! Identifier artifacts: the events, signatures, and reply messages a managed identifier submits.
//!
//! This ports the pure half of the reference's `src/keri/app/aiding.ts`: everything `create`,
//! `createInteract`, `rotate`, `addEndRole`, and `addLocScheme` construct *before* their HTTP call.
//! Each function here takes the identifier's keeper — an [`IdentifierKeeper`] — and, where the
//! reference reads the stored identifier, its [`KeyState`]. Building the keeper from a stored
//! record (`KeeperFactory::keeper_for`), serializing the request body, and the endpoints themselves
//! are `signify-client`'s identifier endpoint family.
//!
//! The one clock the reference reads — a reply's default timestamp — is a required
//! [`Timestamp`] here, continuing the event builders' rule that a protocol crate never reads the
//! clock.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::salt::SecurityTier;
use keri_cesr::crypto::verifier::{KeyTransferability, VerificationKey};
use keri_cesr::number::CesrNumber;
use keria_types::api::{AcceptedHab, KeyState, Role, Threshold};
use serde_json::{Map, Value};

use crate::identifier::error::IdentifierError;
use crate::manager::key_manager::{ManagedSignatures, SignatureForm};
use crate::manager::{
    DerivationCost, IdentifierKeeper, KeeperRequest, KeeperRotation, KeyMaterial, ManagerError, RandyKeeperRequest,
    SaltyKeeperRequest, SaltySource, SigningPurpose,
};
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::interaction::InteractionBuilder;
use keri_protocol::event::reply::{ReplyBuilder, ReplyMessage};
use keri_protocol::event::rotation::{RotationBuilder, RotationKind};
use keri_protocol::event::{
    EventError, KeyEvent, Timestamp, check_distinct, check_next_threshold, check_signing_threshold,
    check_witness_threshold,
};
use keri_protocol::prefix::{IdentifierPrefix, PrefixDerivation, PrefixError};
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadError};
use keri_protocol::threshold::SigningThreshold;

/// The route an end-role authorization reply travels under.
pub const END_ROLE_ROUTE: &str = "/end/role/add";
/// The route a location-scheme authorization reply travels under.
pub const LOCATION_SCHEME_ROUTE: &str = "/loc/scheme";
/// The scheme a location authorization defaults to; the reference's `'http'`.
pub const DEFAULT_LOCATION_SCHEME: &str = "http";

/// One key event with the signatures its keeper produced over it.
#[derive(Debug)]
pub struct IdentifierArtifact {
    /// The serialized event: exact wire bytes, identifier, and SAID.
    pub event: KeyEvent,
    /// The keeper's signatures over the event bytes, in signing order.
    pub signatures: ManagedSignatures,
}

/// One reply message with the signatures its keeper produced over it.
#[derive(Debug)]
pub struct SignedReply {
    /// The serialized reply: exact wire bytes and SAID.
    pub reply: ReplyMessage,
    /// The keeper's signatures over the reply bytes, in signing order.
    pub signatures: ManagedSignatures,
}

/// Where a new identifier's keys come from; the algorithm half of the reference's
/// `CreateIdentiferArgs`.
///
/// Each variant carries exactly the arguments its algorithm reads, so the reference's untyped
/// bag — where a randy creation silently ignores `count`-less salty arguments and vice versa —
/// becomes four shapes that cannot mix.
#[derive(Debug)]
pub enum CreateAlgorithm {
    /// Keys derived from a salt of the identifier's own.
    Salty {
        /// Passcode the identifier's salt derives from; the reference's `bran`. Absent, the salt
        /// is generated from operating-system entropy.
        passcode: Option<String>,
        /// Security tier the keys derive under; the reference's `tier`.
        tier: SecurityTier,
        /// How many keys sign; the reference's `count`.
        current_count: usize,
        /// How many keys are committed to; the reference's `ncount`.
        next_count: usize,
        /// Derivation cost; the reference hardcodes the production profile.
        cost: DerivationCost,
    },
    /// Randomly generated keys, sealed to the controller's passcode key.
    Randy {
        /// How many keys sign.
        current_count: usize,
        /// How many keys are committed to.
        next_count: usize,
        /// Derivation cost of the sealing key.
        cost: DerivationCost,
    },
    /// A multisig group over a local member.
    Group {
        /// The local member identifier; the reference's `mhab`.
        member: Box<AcceptedHab>,
        /// Key states supplying the group's current signing keys; the reference's `states`.
        states: Vec<KeyState>,
        /// Key states supplying the group's proposed next digests; the reference's `rstates`.
        next_states: Vec<KeyState>,
    },
    /// Keys held outside this process.
    Extern {
        /// Name the module was registered under; the reference's `extern_type`.
        module_type: String,
        /// Module-specific parameters, passed through unread; the reference's `extern`.
        parameters: Map<String, Value>,
    },
}

impl CreateAlgorithm {
    /// A one-key salty identifier at the reference's defaults.
    #[must_use]
    pub fn salty(passcode: Option<String>) -> Self {
        Self::Salty {
            passcode,
            tier: SecurityTier::Low,
            current_count: 1,
            next_count: 1,
            cost: DerivationCost::Production,
        }
    }

    /// A one-key randy identifier at the reference's defaults.
    #[must_use]
    pub const fn randy() -> Self {
        Self::Randy {
            current_count: 1,
            next_count: 1,
            cost: DerivationCost::Production,
        }
    }

    /// How many keys will sign, when the algorithm can know before its keeper runs.
    fn current_count(&self) -> Option<usize> {
        match self {
            Self::Salty { current_count, .. } | Self::Randy { current_count, .. } => Some(*current_count),
            Self::Group { states, .. } => Some(states.len()),
            Self::Extern { .. } => None,
        }
    }

    /// How many keys will be committed to, when the algorithm can know before its keeper runs.
    fn next_count(&self) -> Option<usize> {
        match self {
            Self::Salty { next_count, .. } | Self::Randy { next_count, .. } => Some(*next_count),
            Self::Group { next_states, .. } => Some(next_states.len()),
            Self::Extern { .. } => None,
        }
    }
}

/// What to create; the reference's `CreateIdentiferArgs` with its silent rewrites made explicit.
///
/// A [`KeyTransferability::NonTransferable`] identifier commits to no next keys, carries a zero
/// next-key threshold, and derives a basic non-transferable prefix; a request that explicitly
/// contradicts any of that is refused rather than silently rewritten, exactly as the habitat
/// registry does. The reference's unused `pre`, `keys`, and `ndigs` arguments have no equivalent —
/// `create` extracts and never reads them — and `prxs`/`nxts` belong to reloading an existing
/// identifier, which is `KeeperFactory::keeper_for`.
#[derive(Debug)]
pub struct CreateIdentifierRequest {
    /// Where the keys come from; the reference's `algo` plus its algorithm-specific arguments.
    pub algorithm: CreateAlgorithm,
    /// Whether the identifier may rotate; the reference's `transferable`.
    pub transferability: KeyTransferability,
    /// Signing threshold; the reference's `isith`, defaulting to one — not the majority formula
    /// the habitat registry uses.
    pub signing_threshold: Option<SigningThreshold>,
    /// Next-key threshold; the reference's `nsith`, defaulting to one.
    pub next_threshold: Option<SigningThreshold>,
    /// Witnesses; the reference's `wits`.
    pub witnesses: Vec<IdentifierPrefix>,
    /// Witness threshold; the reference's `toad`, which it always passes and defaults to zero —
    /// so a witnessed identifier must set this explicitly or be refused, as upstream is.
    pub witness_threshold: u32,
    /// Delegator; the reference's `delpre`. Makes the inception delegated.
    pub delegator: Option<IdentifierPrefix>,
    /// Prefix derivation; the reference's `dcode`, defaulting to
    /// [`PrefixDerivation::Blake3_256`] and forced to
    /// [`PrefixDerivation::Ed25519NonTransferable`] for a non-transferable identifier.
    pub derivation: Option<PrefixDerivation>,
    /// A seal anchored in the inception event; the reference's `data`, which it wraps in a
    /// single-element list — even when handed a list, which is pinned and not reproducible here.
    pub anchor: Option<Sad>,
    /// Proxy identifier the creation is routed through; carried into the request body by
    /// `signify-client`, unread here.
    pub proxy: Option<String>,
}

impl CreateIdentifierRequest {
    /// A request with the reference's defaults around the given algorithm.
    #[must_use]
    pub fn new(algorithm: CreateAlgorithm) -> Self {
        Self {
            algorithm,
            transferability: KeyTransferability::Transferable,
            signing_threshold: None,
            next_threshold: None,
            witnesses: Vec::new(),
            witness_threshold: 0,
            delegator: None,
            derivation: None,
            anchor: None,
            proxy: None,
        }
    }

    /// Maps this request onto the keeper the reference's `manager.new(algo, pidx, xargs)` builds.
    ///
    /// This owns the `xargs` translation: the passcode becomes
    /// [`SaltySource::Passcode`], the counts and tier reach the keeper unchanged, a group borrows
    /// its member and states, and a non-transferable identifier's next-key count is forced to
    /// zero exactly as the reference forces `ncount`.
    ///
    /// # Errors
    ///
    /// Returns the same conflict refusals as [`incept_identifier`] reports before deriving.
    pub fn keeper_request(&self, prefix_index: u32) -> Result<KeeperRequest<'_>, IdentifierError> {
        let resolved = self.resolve()?;
        Ok(match &self.algorithm {
            CreateAlgorithm::Salty {
                passcode,
                tier,
                current_count,
                cost,
                ..
            } => KeeperRequest::Salty(SaltyKeeperRequest {
                prefix_index,
                key_index: 0,
                tier: *tier,
                transferability: self.transferability,
                current_count: *current_count,
                next_count: resolved.next_count.unwrap_or(0),
                source: match passcode {
                    Some(passcode) => SaltySource::Passcode(passcode.clone()),
                    None => SaltySource::Generated,
                },
                profile: *cost,
                ..SaltyKeeperRequest::default()
            }),
            CreateAlgorithm::Randy {
                current_count, cost, ..
            } => KeeperRequest::Randy(RandyKeeperRequest {
                current_count: *current_count,
                next_count: resolved.next_count.unwrap_or(0),
                transferability: self.transferability,
                profile: *cost,
                ..RandyKeeperRequest::default()
            }),
            CreateAlgorithm::Group {
                member,
                states,
                next_states,
            } => KeeperRequest::Group {
                member: member.clone(),
                states,
                next_states,
            },
            CreateAlgorithm::Extern {
                module_type,
                parameters,
            } => KeeperRequest::Extern {
                module_type: module_type.clone(),
                key_pair_index: prefix_index,
                parameters: parameters.clone(),
            },
        })
    }

    /// The member identifiers a group creation names; the request body's `smids`.
    #[must_use]
    pub fn member_identifiers(&self) -> Option<Vec<String>> {
        match &self.algorithm {
            CreateAlgorithm::Group { states, .. } => {
                Some(states.iter().map(|state| state.identifier.clone()).collect())
            }
            _ => None,
        }
    }

    /// The rotation member identifiers a group creation names; the request body's `rmids`.
    #[must_use]
    pub fn rotation_member_identifiers(&self) -> Option<Vec<String>> {
        match &self.algorithm {
            CreateAlgorithm::Group { next_states, .. } => {
                Some(next_states.iter().map(|state| state.identifier.clone()).collect())
            }
            _ => None,
        }
    }

    /// Resolves the thresholds, derivation, and next-key count, refusing explicit conflicts.
    fn resolve(&self) -> Result<ResolvedCreate, IdentifierError> {
        let (next_count, next_threshold, derivation) = match self.transferability {
            KeyTransferability::Transferable => (
                self.algorithm.next_count(),
                self.next_threshold
                    .clone()
                    .unwrap_or_else(|| SigningThreshold::numeric(1)),
                self.derivation.unwrap_or(PrefixDerivation::Blake3_256),
            ),
            KeyTransferability::NonTransferable => {
                // The reference silently rewrites `ncount`, `nsith`, and `dcode`; an explicit
                // contradiction is refused, following the habitat registry.
                if let Some(requested) = self.algorithm.next_count()
                    && requested != 0
                {
                    return Err(IdentifierError::NonTransferableNextKeys { requested });
                }
                if let Some(threshold) = &self.next_threshold
                    && threshold.numeric_value() != Some(0)
                {
                    return Err(IdentifierError::NonTransferableNextThreshold);
                }
                if let Some(derivation) = self.derivation
                    && derivation != PrefixDerivation::Ed25519NonTransferable
                {
                    return Err(IdentifierError::NonTransferableDerivation {
                        code: derivation.code().as_str(),
                    });
                }
                if !self.witnesses.is_empty() {
                    return Err(IdentifierError::NonTransferableContent { label: "b" });
                }
                if self.anchor.is_some() {
                    return Err(IdentifierError::NonTransferableContent { label: "a" });
                }
                (
                    Some(0),
                    SigningThreshold::numeric(0),
                    PrefixDerivation::Ed25519NonTransferable,
                )
            }
        };

        let signing_threshold = self
            .signing_threshold
            .clone()
            .unwrap_or_else(|| SigningThreshold::numeric(1));

        // Everything checkable before a key derives is checked here, with the builder's own
        // validation, so an impossible request costs no derivation.
        if let Some(count) = self.algorithm.current_count() {
            check_signing_threshold(&signing_threshold, count)?;
            if !derivation.is_digestive() && count != 1 {
                return Err(IdentifierError::BasicDerivationNeedsOneKey { keys: count });
            }
        }
        if let Some(count) = next_count {
            check_next_threshold(&next_threshold, count)?;
        }
        check_distinct(&self.witnesses, "b")?;
        check_witness_threshold(self.witness_threshold, self.witnesses.len())?;
        if self.delegator.is_some() && !derivation.is_digestive() {
            return Err(IdentifierError::from(
                keri_protocol::event::EventError::DelegatedPrefixMustBeDigestive {
                    code: derivation.code().as_str(),
                },
            ));
        }

        Ok(ResolvedCreate {
            signing_threshold,
            next_threshold,
            next_count,
            derivation,
        })
    }
}

/// The request's resolved event parameters.
struct ResolvedCreate {
    signing_threshold: SigningThreshold,
    next_threshold: SigningThreshold,
    next_count: Option<usize>,
    derivation: PrefixDerivation,
}

/// What to rotate to; the reference's `RotateIdentifierArgs`.
#[derive(Debug)]
pub struct RotateIdentifierRequest {
    /// Whether the new keys may rotate again; the reference's `transferable`.
    pub transferability: KeyTransferability,
    /// How many keys the rotation commits to; the reference's `ncount`/`ncodes`, whose codes
    /// collapse to a count because only Ed25519 is derived.
    pub next_count: usize,
    /// Next-key threshold; the reference's `nsith`, defaulting to the state's own next threshold
    /// — which also becomes the rotation's signing threshold.
    pub next_threshold: Option<SigningThreshold>,
    /// Witness threshold; the reference's `toad`, computed from the surviving witnesses when
    /// absent.
    pub witness_threshold: Option<u32>,
    /// Witnesses removed; the reference's `cuts`.
    pub witness_cuts: Vec<IdentifierPrefix>,
    /// Witnesses added; the reference's `adds`.
    pub witness_adds: Vec<IdentifierPrefix>,
    /// A seal anchored in the rotation event; the reference's `data`, wrapped as in creation.
    pub anchor: Option<Sad>,
    /// Key states supplying a group's current signing keys; the reference's `states`.
    pub states: Vec<KeyState>,
    /// Key states supplying a group's proposed next digests; the reference's `rstates`.
    pub next_states: Vec<KeyState>,
}

impl Default for RotateIdentifierRequest {
    /// The reference's defaults: rotate to one transferable key.
    fn default() -> Self {
        Self {
            transferability: KeyTransferability::Transferable,
            next_count: 1,
            next_threshold: None,
            witness_threshold: None,
            witness_cuts: Vec::new(),
            witness_adds: Vec::new(),
            anchor: None,
            states: Vec::new(),
            next_states: Vec::new(),
        }
    }
}

impl RotateIdentifierRequest {
    /// The member identifiers a group rotation names; the request body's `smids`.
    ///
    /// Unlike creation, the reference always writes these — an empty list when no states were
    /// given — so this is a list rather than an option.
    #[must_use]
    pub fn member_identifiers(&self) -> Vec<String> {
        self.states.iter().map(|state| state.identifier.clone()).collect()
    }

    /// The rotation member identifiers a group rotation names; the request body's `rmids`.
    #[must_use]
    pub fn rotation_member_identifiers(&self) -> Vec<String> {
        self.next_states.iter().map(|state| state.identifier.clone()).collect()
    }
}

/// Builds and signs an inception event over freshly established keys; the artifact half of the
/// reference's `create`.
///
/// The keeper is built separately — from [`CreateIdentifierRequest::keeper_request`] through
/// `KeeperFactory::create` — so tests can drive this with any keeper and cost profile. The
/// configuration list is always empty and the threshold encoding textual, exactly as the
/// reference passes `cnfg: []` and `intive: false`.
///
/// ```
/// use keri_cesr::crypto::salt::{Salt, SecurityTier};
/// use signify_keys::identifier::{CreateAlgorithm, CreateIdentifierRequest, incept_identifier};
/// use signify_keys::manager::{DerivationCost, KeeperFactory};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
///     passcode: Some("0123456789abcdefghijk".to_owned()),
///     tier: SecurityTier::Low,
///     current_count: 1,
///     next_count: 1,
///     cost: DerivationCost::Ephemeral,
/// });
/// let factory = KeeperFactory::new(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?);
/// let mut keeper = factory.create(request.keeper_request(0)?)?;
///
/// let artifact = incept_identifier(keeper.as_mut(), &request)?;
/// assert!(artifact.event.raw().starts_with(br#"{"v":"KERI10JSON"#));
/// assert_eq!(artifact.signatures.len(), 1);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns the conflict refusals of [`CreateIdentifierRequest::keeper_request`], threshold and
/// witness failures from the inception builder's own checks, and layered keeper, event, and
/// signing failures.
pub fn incept_identifier(
    keeper: &mut dyn IdentifierKeeper,
    request: &CreateIdentifierRequest,
) -> Result<IdentifierArtifact, IdentifierError> {
    let resolved = request.resolve()?;
    let material = keeper.incept(request.transferability)?;
    let (keys, digests) = parse_material(&material)?;

    let mut builder = InceptionBuilder::new(keys)
        .signing_threshold(resolved.signing_threshold)
        .next_key_digests(digests)
        .next_threshold(resolved.next_threshold)
        .witnesses(request.witnesses.clone())
        .witness_threshold(request.witness_threshold)
        .anchors(request.anchor.iter().cloned().collect())
        .prefix_derivation(resolved.derivation);
    if let Some(delegator) = &request.delegator {
        builder = builder.delegator(delegator.clone());
    }
    let event = builder.build()?;

    let signatures = keeper.sign(event.raw(), &SignatureForm::IndexedByPosition, SigningPurpose::Current)?;
    Ok(IdentifierArtifact { event, signatures })
}

/// Builds and signs an interaction event on a stored identifier; the reference's
/// `createInteract`.
///
/// The reference wraps a non-list `data` argument in a list; here the anchors are the list. A
/// call with no data at all makes the reference anchor `[null]` — a seal that seals nothing,
/// whose SAID commits to it — which a field-map anchor cannot express and is pinned rather than
/// reproduced; an empty list anchors `[]`.
///
/// # Errors
///
/// Returns [`IdentifierError::ValueOutOfRange`] when the sequence number cannot advance, layered
/// parse failures for the state's fields, and layered event and signing failures.
pub fn interact_identifier(
    keeper: &dyn IdentifierKeeper,
    state: &KeyState,
    anchors: Vec<Sad>,
) -> Result<IdentifierArtifact, IdentifierError> {
    let prefix = IdentifierPrefix::from_qb64(&state.identifier)?;
    let prior = Said::from_qb64(&state.digest)?;
    let sequence_number = next_sequence_number(state)?;

    let event = InteractionBuilder::new(prefix, prior, sequence_number)
        .anchors(anchors)
        .build()?;
    let signatures = keeper.sign(event.raw(), &SignatureForm::IndexedByPosition, SigningPurpose::Current)?;
    Ok(IdentifierArtifact { event, signatures })
}

/// Builds and signs a rotation event on a stored identifier; the artifact half of the reference's
/// `rotate`.
///
/// The state's own next threshold becomes the rotation's signing threshold, its digest the prior,
/// its witnesses the surviving witness list, and a non-empty delegator makes the event a
/// delegated rotation — all exactly as the reference reads them. The signatures carry
/// [`SigningPurpose::Rotation`], the reference's `rotated = true`, so a group keeper exposes the
/// prior commitment position.
///
/// # Errors
///
/// Returns [`IdentifierError::ValueOutOfRange`] when the sequence number cannot advance, layered
/// parse failures for the state's fields, and layered keeper, event, and signing failures.
pub fn rotate_identifier(
    keeper: &mut dyn IdentifierKeeper,
    state: &KeyState,
    request: &RotateIdentifierRequest,
) -> Result<IdentifierArtifact, IdentifierError> {
    let prefix = IdentifierPrefix::from_qb64(&state.identifier)?;
    let prior = Said::from_qb64(&state.digest)?;
    let sequence_number = next_sequence_number(state)?;
    let witnesses = state
        .witnesses
        .iter()
        .map(|witness| IdentifierPrefix::from_qb64(witness))
        .collect::<Result<Vec<_>, _>>()?;

    let signing_threshold = signing_threshold_of(&state.next_threshold)?;
    let next_threshold = match &request.next_threshold {
        Some(threshold) => threshold.clone(),
        None => signing_threshold.clone(),
    };

    let material = keeper.rotate(KeeperRotation {
        next_key_count: request.next_count,
        transferability: request.transferability,
        states: (!request.states.is_empty()).then_some(request.states.as_slice()),
        next_states: (!request.next_states.is_empty()).then_some(request.next_states.as_slice()),
    })?;
    let (keys, digests) = parse_material(&material)?;

    let kind = if state.delegator().is_some() {
        RotationKind::Delegated
    } else {
        RotationKind::Rotation
    };
    let mut builder = RotationBuilder::new(prefix, prior, sequence_number, keys)
        .kind(kind)
        .signing_threshold(signing_threshold)
        .next_threshold(next_threshold)
        .next_key_digests(digests)
        .witnesses(witnesses)
        .witness_cuts(request.witness_cuts.clone())
        .witness_adds(request.witness_adds.clone())
        .anchors(request.anchor.iter().cloned().collect());
    if let Some(threshold) = request.witness_threshold {
        builder = builder.witness_threshold(threshold);
    }
    let event = builder.build()?;

    let signatures = keeper.sign(event.raw(), &SignatureForm::IndexedByPosition, SigningPurpose::Rotation)?;
    Ok(IdentifierArtifact { event, signatures })
}

/// Builds the `/end/role/add` reply authorizing an endpoint provider; the reference's
/// `makeEndRole`.
///
/// # Errors
///
/// Returns layered event failures when the reply cannot be built.
pub fn end_role_reply(
    controller: &IdentifierPrefix,
    role: &Role,
    endpoint: Option<&IdentifierPrefix>,
    stamp: Timestamp,
) -> Result<ReplyMessage, IdentifierError> {
    let mut attributes = Sad::new();
    attributes
        .insert("cid", controller.qb64().map_err(prefix_error)?)
        .map_err(sad_error)?;
    attributes.insert("role", role.as_str().to_owned()).map_err(sad_error)?;
    if let Some(endpoint) = endpoint {
        attributes
            .insert("eid", endpoint.qb64().map_err(prefix_error)?)
            .map_err(sad_error)?;
    }
    Ok(ReplyBuilder::new(END_ROLE_ROUTE, stamp)
        .attributes(attributes)
        .build()?)
}

/// Builds the `/loc/scheme` reply authorizing an endpoint location; the pure half of the
/// reference's `addLocScheme`.
///
/// The endpoint defaults to the identifier itself and the scheme to
/// [`DEFAULT_LOCATION_SCHEME`], exactly as upstream defaults them. The URL is carried as text —
/// the reference performs no validation, and the reply's meaning belongs to its consumer.
///
/// # Errors
///
/// Returns layered event failures when the reply cannot be built.
pub fn location_scheme_reply(
    controller: &IdentifierPrefix,
    url: &str,
    scheme: Option<&str>,
    endpoint: Option<&IdentifierPrefix>,
    stamp: Timestamp,
) -> Result<ReplyMessage, IdentifierError> {
    let endpoint = match endpoint {
        Some(endpoint) => endpoint,
        None => controller,
    };
    let mut attributes = Sad::new();
    attributes
        .insert("eid", endpoint.qb64().map_err(prefix_error)?)
        .map_err(sad_error)?;
    attributes.insert("url", url.to_owned()).map_err(sad_error)?;
    attributes
        .insert("scheme", scheme.unwrap_or(DEFAULT_LOCATION_SCHEME).to_owned())
        .map_err(sad_error)?;
    Ok(ReplyBuilder::new(LOCATION_SCHEME_ROUTE, stamp)
        .attributes(attributes)
        .build()?)
}

/// Signs a reply with an identifier's keeper, as `addEndRole` and `addLocScheme` do.
///
/// # Errors
///
/// Returns layered keeper and signing failures.
pub fn sign_reply(keeper: &dyn IdentifierKeeper, reply: &ReplyMessage) -> Result<SignedReply, IdentifierError> {
    let signatures = keeper.sign(reply.raw(), &SignatureForm::IndexedByPosition, SigningPurpose::Current)?;
    Ok(SignedReply {
        reply: reply.clone(),
        signatures,
    })
}

/// Parses the keeper's key material into the builder's semantic types.
fn parse_material(material: &KeyMaterial) -> Result<(Vec<VerificationKey>, Vec<Digest>), IdentifierError> {
    let keys = material
        .public_keys
        .iter()
        .map(|key| VerificationKey::from_qb64(key).map_err(ManagerError::from))
        .collect::<Result<Vec<_>, _>>()?;
    let digests = material
        .next_digests
        .iter()
        .map(|digest| Digest::from_qb64(digest).map_err(ManagerError::from))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((keys, digests))
}

/// Advances a state's hexadecimal sequence number by one.
fn next_sequence_number(state: &KeyState) -> Result<u128, IdentifierError> {
    CesrNumber::from_hex(&state.sequence_number)?
        .value()
        .checked_add(1)
        .ok_or(IdentifierError::ValueOutOfRange {
            context: "sequence number",
        })
}

/// Converts a key state's threshold into the event builders' exact representation.
fn signing_threshold_of(threshold: &Threshold) -> Result<SigningThreshold, IdentifierError> {
    let rendered;
    let sith = match threshold {
        Threshold::Simple(text) => text.as_str(),
        Threshold::Clause(weights) => {
            rendered = serde_json::to_string(weights).unwrap_or_default();
            rendered.as_str()
        }
        Threshold::Clauses(clauses) => {
            rendered = serde_json::to_string(clauses).unwrap_or_default();
            rendered.as_str()
        }
    };
    Ok(SigningThreshold::from_sith(sith)?)
}

/// Keeps the digest table reachable from this module's documentation.
const _: DigestAlgorithm = DigestAlgorithm::Blake3_256;

fn sad_error(source: SadError) -> EventError {
    EventError::Sad {
        source: Box::new(source),
    }
}

fn prefix_error(source: PrefixError) -> EventError {
    EventError::Prefix {
        source: Box::new(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    use keri_cesr::crypto::salt::Salt;

    use crate::manager::KeeperFactory;
    use crate::manager::keeper::GroupKeeper;
    use keri_protocol::event::kind::EventKind;
    use keri_protocol::serialization::SadValue;

    const PASSCODE: &str = "0123456789abcdefghijk";

    /// A deterministic, cheap salty request.
    fn salty_request() -> CreateIdentifierRequest {
        CreateIdentifierRequest::new(CreateAlgorithm::Salty {
            passcode: Some(PASSCODE.to_owned()),
            tier: SecurityTier::Low,
            current_count: 1,
            next_count: 1,
            cost: DerivationCost::Ephemeral,
        })
    }

    fn keeper_for(request: &CreateIdentifierRequest) -> Result<Box<dyn IdentifierKeeper>, Box<dyn Error>> {
        let factory = KeeperFactory::new(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)?);
        Ok(factory.create(request.keeper_request(0)?)?)
    }

    fn text_field(artifact: &IdentifierArtifact, label: &str) -> Option<String> {
        artifact.event.sad().get_text(label).map(str::to_owned)
    }

    fn list_len(artifact: &IdentifierArtifact, label: &str) -> usize {
        match artifact.event.sad().get(label) {
            Some(SadValue::Array(items)) => items.len(),
            _ => usize::MAX,
        }
    }

    /// A key state whose identifier fields come from a freshly incepted artifact.
    fn state_after(
        artifact: &IdentifierArtifact,
        extra: impl FnOnce(&mut serde_json::Value),
    ) -> Result<KeyState, Box<dyn Error>> {
        let event: serde_json::Value = serde_json::from_slice(artifact.event.raw())?;
        let mut state = serde_json::json!({
            "i": event.get("i").cloned().ok_or("no identifier")?,
            "s": "0",
            "p": "",
            "d": event.get("d").cloned().ok_or("no digest")?,
            "f": "0",
            "dt": "2023-12-01T10:05:25.062609+00:00",
            "et": "icp",
            "kt": event.get("kt").cloned().ok_or("no threshold")?,
            "k": event.get("k").cloned().ok_or("no keys")?,
            "nt": event.get("nt").cloned().ok_or("no next threshold")?,
            "n": event.get("n").cloned().ok_or("no digests")?,
            "bt": "0",
            "b": [],
            "c": [],
            "ee": {"s": "0", "d": event.get("d").cloned().ok_or("no digest")?, "br": [], "ba": []},
            "di": ""
        });
        extra(&mut state);
        Ok(serde_json::from_value(state)?)
    }

    type Placements = Vec<(u32, Option<u32>)>;

    fn indexed(signatures: &ManagedSignatures) -> Result<Placements, Box<dyn Error>> {
        match signatures {
            ManagedSignatures::Indexed(signatures) => Ok(signatures
                .iter()
                .map(|signature| (signature.index(), signature.other_index()))
                .collect()),
            ManagedSignatures::Unindexed(_) => Err("expected indexed signatures".into()),
        }
    }

    #[test]
    fn a_default_creation_matches_the_reference_shape() -> Result<(), Box<dyn Error>> {
        let request = salty_request();
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;

        assert_eq!(artifact.event.kind(), EventKind::Inception);
        assert_eq!(text_field(&artifact, "kt").as_deref(), Some("1"));
        assert_eq!(text_field(&artifact, "nt").as_deref(), Some("1"));
        assert_eq!(text_field(&artifact, "bt").as_deref(), Some("0"));
        assert_eq!(list_len(&artifact, "k"), 1);
        assert_eq!(list_len(&artifact, "n"), 1);
        assert_eq!(list_len(&artifact, "b"), 0);
        assert_eq!(list_len(&artifact, "c"), 0);
        assert_eq!(list_len(&artifact, "a"), 0);
        assert!(artifact.event.identifier().is_digestive());
        assert_eq!(indexed(&artifact.signatures)?, [(0, Some(0))]);
        Ok(())
    }

    #[test]
    fn a_multisig_creation_carries_its_thresholds() -> Result<(), Box<dyn Error>> {
        let mut request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
            passcode: Some(PASSCODE.to_owned()),
            tier: SecurityTier::Low,
            current_count: 3,
            next_count: 2,
            cost: DerivationCost::Ephemeral,
        });
        request.signing_threshold = Some(SigningThreshold::numeric(2));
        request.next_threshold = Some(SigningThreshold::numeric(2));
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        assert_eq!(text_field(&artifact, "kt").as_deref(), Some("2"));
        assert_eq!(text_field(&artifact, "nt").as_deref(), Some("2"));
        assert_eq!(list_len(&artifact, "k"), 3);
        assert_eq!(list_len(&artifact, "n"), 2);
        assert_eq!(
            indexed(&artifact.signatures)?,
            [(0, Some(0)), (1, Some(1)), (2, Some(2))]
        );
        Ok(())
    }

    #[test]
    fn a_non_transferable_creation_commits_to_nothing() -> Result<(), Box<dyn Error>> {
        let mut request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
            passcode: Some(PASSCODE.to_owned()),
            tier: SecurityTier::Low,
            current_count: 1,
            next_count: 0,
            cost: DerivationCost::Ephemeral,
        });
        request.transferability = KeyTransferability::NonTransferable;
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        assert!(artifact.event.identifier().qb64()?.starts_with('B'));
        assert_eq!(text_field(&artifact, "nt").as_deref(), Some("0"));
        assert_eq!(list_len(&artifact, "n"), 0);
        Ok(())
    }

    #[test]
    fn non_transferable_conflicts_are_refused() -> Result<(), Box<dyn Error>> {
        let base = |next_count| CreateIdentifierRequest {
            transferability: KeyTransferability::NonTransferable,
            ..CreateIdentifierRequest::new(CreateAlgorithm::Salty {
                passcode: Some(PASSCODE.to_owned()),
                tier: SecurityTier::Low,
                current_count: 1,
                next_count,
                cost: DerivationCost::Ephemeral,
            })
        };
        assert!(matches!(
            base(1).keeper_request(0),
            Err(IdentifierError::NonTransferableNextKeys { requested: 1 })
        ));
        let mut with_threshold = base(0);
        with_threshold.next_threshold = Some(SigningThreshold::numeric(1));
        assert!(matches!(
            with_threshold.keeper_request(0),
            Err(IdentifierError::NonTransferableNextThreshold)
        ));
        let mut with_derivation = base(0);
        with_derivation.derivation = Some(PrefixDerivation::Blake3_256);
        assert!(matches!(
            with_derivation.keeper_request(0),
            Err(IdentifierError::NonTransferableDerivation { .. })
        ));
        let mut with_witness = base(0);
        with_witness.witnesses = vec![IdentifierPrefix::from_qb64(
            "BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ",
        )?];
        with_witness.witness_threshold = 1;
        assert!(matches!(
            with_witness.keeper_request(0),
            Err(IdentifierError::NonTransferableContent { label: "b" })
        ));
        Ok(())
    }

    #[test]
    fn a_witnessed_creation_needs_an_explicit_threshold() -> Result<(), Box<dyn Error>> {
        // The reference always passes `toad ?? 0`, so a witnessed identifier without an explicit
        // threshold is refused there too.
        let mut request = salty_request();
        request.witnesses = vec![IdentifierPrefix::from_qb64(
            "BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ",
        )?];
        assert!(matches!(request.keeper_request(0), Err(IdentifierError::Event { .. })));

        request.witness_threshold = 1;
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        assert_eq!(text_field(&artifact, "bt").as_deref(), Some("1"));
        assert_eq!(list_len(&artifact, "b"), 1);
        Ok(())
    }

    #[test]
    fn a_delegated_creation_writes_the_delegator() -> Result<(), Box<dyn Error>> {
        let mut request = salty_request();
        request.delegator = Some(IdentifierPrefix::from_qb64(
            "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C",
        )?);
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        assert_eq!(artifact.event.kind(), EventKind::DelegatedInception);
        assert_eq!(
            text_field(&artifact, "di").as_deref(),
            Some("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C")
        );
        Ok(())
    }

    #[test]
    fn an_anchored_creation_carries_its_seal() -> Result<(), Box<dyn Error>> {
        let mut seal = Sad::new();
        seal.insert("i", SadValue::text("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"))?;
        let mut request = salty_request();
        request.anchor = Some(seal.clone());
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        assert_eq!(
            artifact.event.sad().get("a"),
            Some(&SadValue::Array(vec![SadValue::Map(seal)]))
        );
        Ok(())
    }

    #[test]
    fn a_group_creation_signs_current_only_at_the_member_position() -> Result<(), Box<dyn Error>> {
        // A group keeper over an ephemeral member, exactly as the pinned unit test mocks its
        // member: the group's keys come from the states, and the signature must land at the
        // member's position without a prior index.
        let member_request = salty_request();
        let mut member_keeper = keeper_for(&member_request)?;
        let member_material = member_keeper.incept(KeyTransferability::Transferable)?;
        let member_key = member_material.public_keys.first().cloned().ok_or("no member key")?;
        let member_artifact = incept_identifier(keeper_for(&member_request)?.as_mut(), &member_request)?;
        let member_state = state_after(&member_artifact, |_| ())?;
        let member_hab = AcceptedHab {
            common: keria_types::api::HabCommon {
                name: "member".to_owned(),
                prefix: member_key.clone(),
                inception_stamp: "2023-12-01T10:05:25.062609+00:00".to_owned(),
                transferable: None,
                witness_indexes: None,
                key_manager: keria_types::api::KeyManagerState::Randy(keria_types::api::RandyState {
                    encrypted_signing_keys: Vec::new(),
                    encrypted_next_keys: Vec::new(),
                }),
            },
            state: Box::new(member_state.clone()),
        };
        let other_state = state_after(&member_artifact, |value| {
            value["i"] = serde_json::json!("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C");
            value["k"] = serde_json::json!(["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"]);
        })?;

        let states = vec![other_state.clone(), member_state.clone()];
        let next_states = vec![other_state, member_state.clone()];
        let mut group_keeper = GroupKeeper::new(
            member_keeper,
            member_hab.clone(),
            states
                .iter()
                .map(|state| state.signing_keys.first().cloned().unwrap_or_default())
                .collect(),
            next_states
                .iter()
                .map(|state| state.next_key_digests.first().cloned().unwrap_or_default())
                .collect(),
        );

        let request = CreateIdentifierRequest::new(CreateAlgorithm::Group {
            member: Box::new(member_hab),
            states: states.clone(),
            next_states,
        });
        let artifact = incept_identifier(&mut group_keeper, &request)?;
        assert_eq!(list_len(&artifact, "k"), 2);
        // The member is second in the states, so its signature lands at position one, and an
        // inception signature never carries a prior index.
        assert_eq!(indexed(&artifact.signatures)?, [(1, None)]);
        assert_eq!(
            request.member_identifiers().map(|identifiers| identifiers.len()),
            Some(2)
        );
        assert_eq!(
            request
                .rotation_member_identifiers()
                .map(|identifiers| identifiers.len()),
            Some(2)
        );
        Ok(())
    }

    #[test]
    fn an_interaction_advances_the_hexadecimal_sequence() -> Result<(), Box<dyn Error>> {
        let request = salty_request();
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        let state = state_after(&artifact, |value| {
            value["s"] = serde_json::json!("a");
        })?;

        let mut anchor = Sad::new();
        anchor.insert("i", SadValue::text("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"))?;
        anchor.insert("s", SadValue::integer(0)?)?;
        let interaction = interact_identifier(keeper.as_ref(), &state, vec![anchor.clone()])?;
        assert_eq!(interaction.event.kind(), EventKind::Interaction);
        assert_eq!(interaction.event.sad().get_text("s"), Some("b"));
        assert_eq!(
            interaction.event.sad().get_text("p"),
            artifact.event.sad().get_text("d")
        );
        assert_eq!(
            interaction.event.sad().get("a"),
            Some(&SadValue::Array(vec![SadValue::Map(anchor)]))
        );
        assert_eq!(indexed(&interaction.signatures)?, [(0, Some(0))]);
        Ok(())
    }

    #[test]
    fn a_rotation_reads_the_state_it_is_given() -> Result<(), Box<dyn Error>> {
        let request = salty_request();
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        let committed = artifact.event.sad().get("n").cloned();
        let state = state_after(&artifact, |_| ())?;

        let rotation = rotate_identifier(keeper.as_mut(), &state, &RotateIdentifierRequest::default())?;
        assert_eq!(rotation.event.kind(), EventKind::Rotation);
        assert_eq!(rotation.event.sad().get_text("s"), Some("1"));
        assert_eq!(rotation.event.sad().get_text("p"), artifact.event.sad().get_text("d"));
        // The prior next threshold becomes the signing threshold.
        assert_eq!(rotation.event.sad().get_text("kt"), Some("1"));
        // The rotated-to keys are exactly the committed digests' keys.
        let Some(SadValue::Array(keys)) = rotation.event.sad().get("k") else {
            return Err("the rotation carries no keys".into());
        };
        let digests: Vec<SadValue> = keys
            .iter()
            .filter_map(|key| match key {
                SadValue::Text(key) => Digest::derive(DigestAlgorithm::Blake3_256, key.as_bytes())
                    .qb64()
                    .ok()
                    .map(SadValue::Text),
                _ => None,
            })
            .collect();
        assert_eq!(committed, Some(SadValue::Array(digests)));
        Ok(())
    }

    #[test]
    fn a_rotation_signs_with_the_inception_count() -> Result<(), Box<dyn Error>> {
        // Property-test regression, permanent: a salty keeper's current count never moves from its
        // inception count — the `keri-keeping` fixture's pinned quirk — so a rotation to two keys
        // writes both into the event but signs with one.
        let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
            passcode: Some(PASSCODE.to_owned()),
            tier: SecurityTier::Low,
            current_count: 1,
            next_count: 2,
            cost: DerivationCost::Ephemeral,
        });
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        let state = state_after(&artifact, |_| ())?;
        let rotation = rotate_identifier(
            keeper.as_mut(),
            &state,
            &RotateIdentifierRequest {
                next_count: 2,
                next_threshold: Some(SigningThreshold::numeric(2)),
                ..RotateIdentifierRequest::default()
            },
        )?;
        assert_eq!(list_len(&rotation, "k"), 2);
        assert_eq!(rotation.signatures.len(), 1);
        Ok(())
    }

    #[test]
    fn a_delegated_state_rotates_with_a_delegated_event() -> Result<(), Box<dyn Error>> {
        let request = salty_request();
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        let state = state_after(&artifact, |value| {
            value["di"] = serde_json::json!("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C");
        })?;
        let rotation = rotate_identifier(keeper.as_mut(), &state, &RotateIdentifierRequest::default())?;
        assert_eq!(rotation.event.kind(), EventKind::DelegatedRotation);
        Ok(())
    }

    #[test]
    fn a_weighted_next_threshold_carries_into_the_rotation() -> Result<(), Box<dyn Error>> {
        let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
            passcode: Some(PASSCODE.to_owned()),
            tier: SecurityTier::Low,
            current_count: 2,
            next_count: 2,
            cost: DerivationCost::Ephemeral,
        });
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        let state = state_after(&artifact, |value| {
            value["nt"] = serde_json::json!(["1/2", "1/2"]);
        })?;
        let rotation = rotate_identifier(
            keeper.as_mut(),
            &state,
            &RotateIdentifierRequest {
                next_count: 2,
                next_threshold: Some(SigningThreshold::numeric(1)),
                ..RotateIdentifierRequest::default()
            },
        )?;
        // The stored next threshold becomes the signing threshold, in its weighted spelling.
        assert_eq!(
            rotation.event.sad().get("kt"),
            Some(&SadValue::Array(vec![SadValue::text("1/2"), SadValue::text("1/2")]))
        );
        assert_eq!(rotation.event.sad().get_text("nt"), Some("1"));
        Ok(())
    }

    #[test]
    fn a_sequence_number_cannot_overflow() -> Result<(), Box<dyn Error>> {
        let request = salty_request();
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        let state = state_after(&artifact, |value| {
            value["s"] = serde_json::json!("f".repeat(32));
        })?;
        assert!(matches!(
            interact_identifier(keeper.as_ref(), &state, Vec::new()),
            Err(IdentifierError::ValueOutOfRange { .. })
        ));
        let bad_hex = state_after(&artifact, |value| {
            value["s"] = serde_json::json!("not hex");
        })?;
        assert!(matches!(
            interact_identifier(keeper.as_ref(), &bad_hex, Vec::new()),
            Err(IdentifierError::Cesr { .. })
        ));
        Ok(())
    }

    #[test]
    fn replies_match_the_reference_routes_and_field_order() -> Result<(), Box<dyn Error>> {
        let controller = IdentifierPrefix::from_qb64("EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C")?;
        let endpoint = IdentifierPrefix::from_qb64("BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ")?;
        let stamp = Timestamp::parse("2021-06-27T21:26:21.233257+00:00")?;

        let end_role = end_role_reply(&controller, &Role::Agent, Some(&endpoint), stamp.clone())?;
        assert_eq!(end_role.route(), Some(END_ROLE_ROUTE));
        let Some(SadValue::Map(attributes)) = end_role.sad().get("a") else {
            return Err("the reply carries no attributes".into());
        };
        let labels: Vec<&str> = attributes.entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["cid", "role", "eid"]);
        assert_eq!(attributes.get_text("role"), Some("agent"));

        // Without an endpoint the field is omitted entirely, as the reference omits it.
        let bare = end_role_reply(&controller, &Role::Agent, None, stamp.clone())?;
        let Some(SadValue::Map(attributes)) = bare.sad().get("a") else {
            return Err("the reply carries no attributes".into());
        };
        assert!(!attributes.contains("eid"));

        let location = location_scheme_reply(&controller, "http://test.com", None, None, stamp.clone())?;
        assert_eq!(location.route(), Some(LOCATION_SCHEME_ROUTE));
        let Some(SadValue::Map(attributes)) = location.sad().get("a") else {
            return Err("the reply carries no attributes".into());
        };
        let labels: Vec<&str> = attributes.entries().map(|(label, _)| label).collect();
        assert_eq!(labels, ["eid", "url", "scheme"]);
        assert_eq!(attributes.get_text("eid"), Some(controller.qb64()?.as_str()));
        assert_eq!(attributes.get_text("scheme"), Some(DEFAULT_LOCATION_SCHEME));
        Ok(())
    }

    #[test]
    fn a_reply_is_signed_by_the_identifier_keeper() -> Result<(), Box<dyn Error>> {
        let request = salty_request();
        let mut keeper = keeper_for(&request)?;
        let artifact = incept_identifier(keeper.as_mut(), &request)?;
        let controller = artifact.event.identifier().clone();
        let stamp = Timestamp::parse("2021-06-27T21:26:21.233257+00:00")?;

        let reply = end_role_reply(&controller, &Role::Agent, None, stamp)?;
        let signed = sign_reply(keeper.as_ref(), &reply)?;
        assert_eq!(indexed(&signed.signatures)?, [(0, Some(0))]);
        assert_eq!(signed.reply.raw(), reply.raw());
        Ok(())
    }
}
