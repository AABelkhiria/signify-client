//! The client lifecycle: boot an agent, read its state, connect to it, and send signed requests.
//!
//! This ports `SignifyClient` from the pinned `src/keri/app/clienting.ts`, minus the endpoint
//! accessors (Roadmap 9.5) and the passcode rotation (Roadmap 8.9). The order is fixed by the
//! protocol:
//!
//! ```text
//! boot     POST {boot}/boot            unsigned — no agent exists yet to sign to
//!   ↓
//! state    GET  {admin}/agent/{caid}   unsigned — reads the agent and controller state
//!   ↓
//! connect  rebuilds the controller against that state, checks the agent's commitment,
//!          approves the delegation, and derives the signing material
//!   ↓
//! fetch    signed — everything an endpoint family will ever send
//! ```
//!
//! # Connecting is a type change, not a flag
//!
//! The reference's `fetch` throws `client need to call connect first` when its authenticator is
//! still null. Here [`SignifyClient::connect`] consumes the client and returns a
//! [`ConnectedClient`], so there is no `fetch` to call before connecting and no null to check.
//! Everything that genuinely works before connecting — booting, reading state — stays on the
//! unconnected type.
//!
//! # Three calls are deliberately unsigned
//!
//! [`SignifyClient::boot`] cannot be signed: the agent it is creating does not exist yet. But
//! [`ConnectedClient::approve_delegation`], [`ConnectedClient::save_old_passcode`], and
//! [`ConnectedClient::delete_passcode`] bypass the signed path upstream too, calling the global
//! `fetch` directly — so a passcode reaches the agent over an unsigned request. That is
//! reproduced, because changing it would produce requests KERIA does not expect, and each method
//! says so in its own documentation. See `fixtures/client-lifecycle/`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use keri_cesr::crypto::salt::SecurityTier;
use keri_cesr::crypto::verifier::VerificationKey;
use keria_types::api::{AcceptedHab, KeyState};
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::request::{BaseUrl, MediaType, ResourcePath};
use signify_http::retry::Clock;
use signify_http::signature::authentication::{RequestSigner, ResponseVerifier};
use signify_http::signature::input::{RequestTarget, SIGNIFY_RESOURCE_HEADER_NAME};
use signify_http::signature::transport::{Freshness, ResponseAuthenticator, SigningTransport};
use signify_http::transport::{Method, Request, RequestUrl, Response, StatusCode, Transport};
use signify_keri::controller::{Agent, Controller, ControllerOptions, PasscodeRotation, ReEncryptedKeyState};
use signify_keri::manager::{KeeperFactory, salt_from_passcode};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

use crate::config::{ClientConfig, Passcode};
use crate::endpoint::challenges::Challenges;
use crate::endpoint::config::Config;
use crate::endpoint::contacts::Contacts;
use crate::endpoint::credentials::Credentials;
use crate::endpoint::escrows::Escrows;
use crate::endpoint::exchanges::Exchanges;
use crate::endpoint::groups::Groups;
use crate::endpoint::identifiers::Identifiers;
use crate::endpoint::ipex::Ipex;
use crate::endpoint::key_events::KeyEvents;
use crate::endpoint::key_states::KeyStates;
use crate::endpoint::notifications::Notifications;
use crate::endpoint::oobis::Oobis;
use crate::endpoint::operations::Operations;
use crate::endpoint::registries::Registries;
use crate::endpoint::schemas::Schemas;
use crate::error::ClientError;
use crate::operation::Poller;

/// Path segment the agent resource lives under.
pub const AGENT_SEGMENT: &str = "agent";
/// Path segment the boot interface lives under.
pub const BOOT_SEGMENT: &str = "boot";
/// Path segment a stored passcode lives under.
pub const SALT_SEGMENT: &str = "salt";
/// Query parameter the delegation approval carries; the reference's `?type=ixn`.
pub const APPROVAL_TYPE_PARAMETER: &str = "type";
/// Value of that parameter.
pub const APPROVAL_TYPE_INTERACTION: &str = "ixn";

/// Value the boot body's `pidx` field always carries.
///
/// The reference hardcodes `pidx: 1` while its own client field is zero, and nothing reads the
/// value back. It is a constant here rather than a field, so the two cannot disagree.
pub const BOOT_PREFIX_INDEX: i64 = 1;

/// The agent and controller state a KERIA agent reports.
///
/// This is the reference's `State`, whose four fields are `any`, `any`, and two numbers. Both
/// halves are typed here: the agent's state is Roadmap 4.1's [`KeyState`] and the controller's
/// establishment event is a parsed [`SerializedEvent`].
#[derive(Clone, Debug)]
pub struct AgentState {
    agent: KeyState,
    controller_event: SerializedEvent,
    rotation_index: u32,
    prefix_index: u32,
}

impl AgentState {
    /// Returns the agent's key state.
    #[must_use]
    pub const fn agent(&self) -> &KeyState {
        &self.agent
    }

    /// Returns the controller's latest establishment event, as the agent has it.
    #[must_use]
    pub const fn controller_event(&self) -> &SerializedEvent {
        &self.controller_event
    }

    /// Returns the rotation index the controller's keys derive at; the reference's `ridx`.
    #[must_use]
    pub const fn rotation_index(&self) -> u32 {
        self.rotation_index
    }

    /// Returns the prefix index; the reference's `pidx`.
    #[must_use]
    pub const fn prefix_index(&self) -> u32 {
        self.prefix_index
    }

    /// Parses one agent-resource response body.
    fn parse(body: &[u8]) -> Result<Self, ClientError> {
        let document = Sad::from_json_bytes(body).map_err(|source| ClientError::Serialization {
            source: Box::new(source.into()),
        })?;
        let agent = document
            .get("agent")
            .and_then(SadValue::as_map)
            .ok_or(ClientError::IncompleteAgentState { missing: "agent" })?;
        let controller = document
            .get("controller")
            .and_then(SadValue::as_map)
            .ok_or(ClientError::IncompleteAgentState { missing: "controller" })?;
        let establishment =
            controller
                .get("ee")
                .and_then(SadValue::as_map)
                .ok_or(ClientError::IncompleteAgentState {
                    missing: "controller establishment event",
                })?;

        let agent_state: KeyState =
            serde_json::from_slice(&agent.to_json_bytes().map_err(|source| ClientError::Serialization {
                source: Box::new(source.into()),
            })?)
            .map_err(|_| ClientError::IncompleteAgentState { missing: "agent state" })?;
        let controller_event =
            SerializedEvent::parse(
                &establishment
                    .to_json_bytes()
                    .map_err(|source| ClientError::Serialization {
                        source: Box::new(source.into()),
                    })?,
            )?;

        Ok(Self {
            agent: agent_state,
            controller_event,
            rotation_index: read_index(&document, "ridx"),
            prefix_index: read_index(&document, "pidx"),
        })
    }
}

/// Reads one optional non-negative index, defaulting to zero as the reference does.
fn read_index(document: &Sad, label: &str) -> u32 {
    match document.get(label) {
        Some(SadValue::Integer(value)) => u32::try_from(*value).unwrap_or_default(),
        _ => 0,
    }
}

/// A client that has not connected yet.
///
/// It can boot an agent and read that agent's state. Everything else needs
/// [`Self::connect`], which returns the type that can do it.
#[derive(Debug)]
pub struct SignifyClient {
    config: ClientConfig,
    controller: Controller,
    transport: Arc<dyn Transport>,
    clock: Arc<dyn Clock>,
}

impl SignifyClient {
    /// Derives the controller and prepares a client against `transport`.
    ///
    /// The transport is the *unsigned* one; connecting wraps it in the signing stack.
    ///
    /// # Errors
    ///
    /// Returns layered [`ClientError::Controller`] failures when the passcode cannot derive a
    /// controller.
    pub fn new(
        config: ClientConfig,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ClientError> {
        let controller = Controller::with_options(
            config.passcode().expose(),
            config.tier(),
            ControllerOptions {
                rotation_index: 0,
                derivation_cost: config.derivation_cost(),
            },
        )?;
        Ok(Self {
            config,
            controller,
            transport,
            clock,
        })
    }

    /// Returns the configuration this client was built with.
    #[must_use]
    pub const fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Returns the controller derived from the passcode.
    #[must_use]
    pub const fn controller(&self) -> &Controller {
        &self.controller
    }

    /// Boots a KERIA agent for this controller.
    ///
    /// The request is **unsigned**, and cannot be otherwise: the agent whose key would verify it
    /// is what this call creates. It carries the controller's inception event, the signature over
    /// it, the derivation stem, a fixed prefix index, and the security tier.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, and layered request, transport,
    /// and controller failures.
    pub async fn boot(&self) -> Result<Response, ClientError> {
        let body = self.boot_body()?;
        let path = ResourcePath::builder().segment(BOOT_SEGMENT).build()?;
        let request = Request::builder(Method::Post, self.config.boot_url().join(&path)?)
            .header(content_type()?, json_value()?)
            .body(body)
            .build()?;
        let response = self.transport.execute(request).await?;
        require_success(&response)?;
        Ok(response)
    }

    /// Builds the exact JSON body the boot request carries.
    ///
    /// Exposed because a caller may want to inspect what would be sent, and because it is the one
    /// part of booting that is pure.
    ///
    /// # Errors
    ///
    /// Returns layered [`ClientError::Controller`] and [`ClientError::Serialization`] failures.
    pub fn boot_body(&self) -> Result<Vec<u8>, ClientError> {
        let (event, signature) = self.controller.signed_event()?;
        let mut body = Sad::new();
        body.insert("icp", SadValue::Map(event.sad().clone()))
            .map_err(sad_error)?;
        body.insert("sig", SadValue::Text(signature.qb64().map_err(ClientError::from)?))
            .map_err(sad_error)?;
        body.insert("stem", SadValue::text(signify_keri::controller::CONTROLLER_STEM))
            .map_err(sad_error)?;
        body.insert("pidx", SadValue::integer(BOOT_PREFIX_INDEX).map_err(sad_error)?)
            .map_err(sad_error)?;
        body.insert("tier", SadValue::text(tier_text(self.config.tier())))
            .map_err(sad_error)?;
        body.to_json_bytes().map_err(sad_error)
    }

    /// Reads the agent and controller state.
    ///
    /// The request is unsigned; the reference sends it before any signing material exists.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::AgentNotFound`] for a 404 — the reference's own special case —
    /// [`ClientError::Status`] for any other non-success answer, which the reference instead
    /// parses as if it were state, and [`ClientError::IncompleteAgentState`] for a body missing
    /// either half.
    pub async fn state(&self) -> Result<AgentState, ClientError> {
        // A rotated controller keeps the prefix its first passcode incepted, which the current
        // passcode no longer derives; the caller names it through the configuration.
        let controller = self
            .config
            .controller_prefix()
            .unwrap_or_else(|| self.controller.prefix())
            .qb64()
            .map_err(prefix_error)?;
        let path = ResourcePath::builder()
            .segment(AGENT_SEGMENT)
            .segment(&controller)
            .build()?;
        let request = Request::builder(Method::Get, self.config.admin_url().join(&path)?).build()?;
        let response = self.transport.execute(request).await?;
        if response.status().as_u16() == 404 {
            return Err(ClientError::AgentNotFound { controller });
        }
        require_success(&response)?;
        AgentState::parse(response.body())
    }

    /// Connects: reads the state, rebuilds the controller against it, validates the agent, and
    /// approves the delegation when the controller is still at sequence zero.
    ///
    /// A controller that has rotated its passcode is reported by its agent with the rotation as its
    /// latest establishment event and no rotation index, so it is restored at that event and derives
    /// its keys at index zero from the passcode configured here — the key that rotation put first.
    /// Its prefix is still the one its **first** passcode incepted, which the current passcode no
    /// longer derives, so a client reconnecting after a rotation must be configured with it:
    /// [`ClientConfig::with_controller_prefix`]. The connected client's configuration always
    /// carries the prefix, so it can be persisted from there.
    ///
    /// Two checks the reference does not make: the reported controller must be the configured one,
    /// and the passcode must derive the first signing key of its latest establishment event. Without
    /// the second, a stale passcode — the one a rotation replaced — connects without complaint and
    /// fails on its first signed request.
    ///
    /// The client is consumed, so a caller cannot hold an unconnected handle that looks usable.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::state`] returns,
    /// [`ClientError::ControllerPrefixMismatch`] when the agent reports a controller other than the
    /// configured one, [`ClientError::ControllerKeyMismatch`] when the passcode does not derive
    /// that controller's current signing key,
    /// [`ClientError::AgentNotDelegatedToController`] when the agent's inception anchors a
    /// different controller, and layered controller, manager, and authentication failures.
    pub async fn connect(self) -> Result<ConnectedClient, ClientError> {
        let state = self.state().await?;
        let agent = Agent::from_key_state(state.agent().clone())?;

        // The controller is rebuilt with the returned rotation index rather than mutated after
        // the fact, so its keys always agree with the index they were derived at.
        let controller = Controller::restore(
            self.config.passcode().expose(),
            self.config.tier(),
            ControllerOptions {
                rotation_index: state.rotation_index(),
                derivation_cost: self.config.derivation_cost(),
            },
            state.controller_event().clone(),
        )?;

        let expected = controller.prefix().qb64().map_err(prefix_error)?;
        if let Some(configured) = self.config.controller_prefix() {
            let configured = configured.qb64().map_err(prefix_error)?;
            if configured != expected {
                return Err(ClientError::ControllerPrefixMismatch {
                    configured,
                    reported: expected,
                });
            }
        }

        // `restore` adopts a later establishment event as reported, so the event's keys and this
        // passcode's keys can disagree; refuse here rather than on the first signed request.
        let established = state
            .controller_event()
            .sad()
            .get("k")
            .and_then(|keys| match keys {
                SadValue::Array(keys) => keys.first(),
                _ => None,
            })
            .and_then(|key| match key {
                SadValue::Text(key) => Some(key.clone()),
                _ => None,
            })
            .ok_or(ClientError::IncompleteAgentState {
                missing: "controller keys",
            })?;
        let derived = controller
            .expose_signer()
            .verifier()
            .qb64()
            .map_err(ClientError::from)?;
        if established != derived {
            return Err(ClientError::ControllerKeyMismatch {
                controller: expected,
                established,
                derived,
            });
        }

        let anchored = agent.anchor().qb64().map_err(prefix_error)?;
        if anchored != expected {
            return Err(ClientError::AgentNotDelegatedToController {
                expected,
                actual: anchored,
            });
        }

        let config = self.config.with_controller_prefix(controller.prefix().clone());
        let mut connected = ConnectedClient::assemble(
            config,
            controller,
            agent,
            self.transport,
            self.clock,
            state.prefix_index(),
        )?;
        if connected.controller.current_sequence_number() == 0 {
            connected.approve_delegation().await?;
        }
        Ok(connected)
    }
}

/// A client that has connected, and can therefore send signed requests.
#[derive(Debug)]
pub struct ConnectedClient {
    config: ClientConfig,
    controller: Controller,
    agent: Agent,
    keepers: KeeperFactory,
    unsigned: Arc<dyn Transport>,
    signing: SigningTransport,
    authenticator: ResponseAuthenticator,
    clock: Arc<dyn Clock>,
    resource: HeaderValue,
    prefix_index: AtomicU32,
}

impl ConnectedClient {
    /// Builds the signing material and the key manager from a validated controller and agent.
    fn assemble(
        config: ClientConfig,
        controller: Controller,
        agent: Agent,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
        prefix_index: u32,
    ) -> Result<Self, ClientError> {
        let resource = HeaderValue::new(controller.prefix().qb64().map_err(prefix_error)?)?;
        let signer = RequestSigner::new(controller.derive_signing_key()?);
        let signing =
            SigningTransport::new(Arc::clone(&transport), signer, resource.clone())?.with_clock(Arc::clone(&clock));
        let verifier = ResponseVerifier::new(agent_key(&agent));
        let agent_resource = HeaderValue::new(agent.prefix().qb64().map_err(prefix_error)?)?;
        let authenticator = ResponseAuthenticator::new(verifier, agent_resource, Arc::clone(&clock));
        // The keeper factory needs an owned salt, and a `Salt` is deliberately not cloneable
        // (Roadmap 2.5), so it is re-derived through the one function that owns that derivation.
        let keepers = KeeperFactory::new(salt_from_passcode(config.passcode().expose(), config.tier())?);

        Ok(Self {
            config,
            controller,
            agent,
            keepers,
            unsigned: transport,
            signing,
            authenticator,
            clock,
            resource,
            prefix_index: AtomicU32::new(prefix_index),
        })
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Returns the controller this client speaks for.
    #[must_use]
    pub const fn controller(&self) -> &Controller {
        &self.controller
    }

    /// Returns the agent it is connected to.
    #[must_use]
    pub const fn agent(&self) -> &Agent {
        &self.agent
    }

    /// Returns the keeper factory every identifier's keys come from.
    #[must_use]
    pub const fn keepers(&self) -> &KeeperFactory {
        &self.keepers
    }

    /// Returns the prefix index the next creation will derive under.
    ///
    /// It starts at whatever the agent reported and advances with every creation, as the
    /// reference's `pidx` does.
    #[must_use]
    pub fn prefix_index(&self) -> u32 {
        self.prefix_index.load(Ordering::SeqCst)
    }

    /// Reserves the prefix index one creation will derive under, advancing the counter.
    ///
    /// The reference increments its shared `pidx` *after* signing, so two concurrent creations
    /// would read the same value and derive the same identifier's keys. Reserving first makes that
    /// collision unrepresentable; the cost is that a creation which fails after reserving consumes
    /// an index the reference would have reused, which leaves a gap and nothing else.
    pub(crate) fn reserve_prefix_index(&self) -> u32 {
        self.prefix_index.fetch_add(1, Ordering::SeqCst)
    }

    /// Returns the clock this client measures and waits with.
    ///
    /// Crate-private: a client has exactly one clock, and reusing it is what lets Roadmap 7.2's
    /// polling be driven deterministically by the same `TestClock` a request signature already is.
    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Returns the `Signify-Resource` value every request is stamped with.
    #[must_use]
    pub const fn resource(&self) -> &HeaderValue {
        &self.resource
    }

    /// Returns the operations endpoint family.
    ///
    /// A KERIA agent answers most write requests with a long-running operation rather than a
    /// result, so this is the family every other one leans on. The reference exposes sixteen such
    /// accessors; each arrives here with its own roadmap item rather than being stubbed ahead of
    /// it.
    #[must_use]
    pub const fn operations(&self) -> Operations<'_> {
        Operations::new(self)
    }

    /// Returns the identifier endpoint family.
    #[must_use]
    pub const fn identifiers(&self) -> Identifiers<'_> {
        Identifiers::new(self)
    }

    /// Returns the key-events endpoint family: the log behind an identifier's state.
    #[must_use]
    pub const fn key_events(&self) -> KeyEvents<'_> {
        KeyEvents::new(self)
    }

    /// Returns the key-states endpoint family: what the agent believes about other identifiers.
    #[must_use]
    pub const fn key_states(&self) -> KeyStates<'_> {
        KeyStates::new(self)
    }

    /// Returns the registries endpoint family: the credential registries an identifier owns.
    #[must_use]
    pub const fn registries(&self) -> Registries<'_> {
        Registries::new(self)
    }

    /// Returns the schemas endpoint family: the credential schemas the agent holds.
    #[must_use]
    pub const fn schemas(&self) -> Schemas<'_> {
        Schemas::new(self)
    }

    /// Returns the credentials endpoint family: the ACDCs the agent holds, and their status.
    #[must_use]
    pub const fn credentials(&self) -> Credentials<'_> {
        Credentials::new(self)
    }

    /// Returns the IPEX endpoint family: disclosing a credential to somebody else.
    #[must_use]
    pub const fn ipex(&self) -> Ipex<'_> {
        Ipex::new(self)
    }

    /// Returns the notifications endpoint family: what the agent wants the controller to know.
    #[must_use]
    pub const fn notifications(&self) -> Notifications<'_> {
        Notifications::new(self)
    }

    /// Returns the OOBI endpoint family: how identifiers that have never met learn about each
    /// other.
    #[must_use]
    pub const fn oobis(&self) -> Oobis<'_> {
        Oobis::new(self)
    }

    /// Returns the challenges endpoint family: proving somebody controls what they claim.
    #[must_use]
    pub const fn challenges(&self) -> Challenges<'_> {
        Challenges::new(self)
    }

    /// Returns the contacts endpoint family: who this client knows.
    #[must_use]
    pub const fn contacts(&self) -> Contacts<'_> {
        Contacts::new(self)
    }

    /// Returns the escrows endpoint family: what the agent received and could not yet accept.
    #[must_use]
    pub const fn escrows(&self) -> Escrows<'_> {
        Escrows::new(self)
    }

    /// Returns the exchange endpoint family: peer-to-peer messages and their delivery.
    #[must_use]
    pub const fn exchanges(&self) -> Exchanges<'_> {
        Exchanges::new(self)
    }

    /// Returns the groups endpoint family: the round of messages a multisig group decides through.
    #[must_use]
    pub const fn groups(&self) -> Groups<'_> {
        Groups::new(self)
    }

    /// Returns the delegation endpoint family: a delegator's approval of a pending delegate.
    #[must_use]
    pub const fn delegations(&self) -> crate::endpoint::delegations::Delegations<'_> {
        crate::endpoint::delegations::Delegations::new(self)
    }

    /// Returns the multisig workflows: bringing a group identifier into existence, and running it.
    ///
    /// A workflow rather than an endpoint family, like [`Self::poller`] — it composes several
    /// families in an order the reference only ever writes in its own tests.
    #[must_use]
    pub const fn multisig(&self) -> crate::multisig::Multisig<'_> {
        crate::multisig::Multisig::new(self)
    }

    /// Returns the IPEX disclosure workflow.
    #[must_use]
    pub const fn presentation(&self) -> crate::presentation::Presentation<'_> {
        crate::presentation::Presentation::new(self)
    }

    /// Returns a poller for long-running agent operations.
    ///
    /// A KERIA agent answers most writes with an operation rather than a result, so this is where
    /// most workflows end. It is bounded where the reference's own loop is not; see
    /// [`operation`](crate::operation).
    #[must_use]
    pub fn poller(&self) -> Poller<'_> {
        Poller::new(self)
    }

    /// Returns the configuration endpoint family: what the *agent* was set up with.
    ///
    /// Named for whose configuration it reads, because [`Self::config`] already returns this
    /// client's own — the reference has only one of the two, so its `client.config()` is
    /// unambiguous where this would not be.
    #[must_use]
    pub const fn agent_config(&self) -> Config<'_> {
        Config::new(self)
    }

    /// Signs a request for an **external** resource with one managed identifier's own key.
    ///
    /// This is the reference's `createSignedRequest`, and it is the one signing path that does not
    /// use the controller's key: the identifier is looked up by alias, its keeper's first signer
    /// signs, and the identifier's own prefix — not the controller's — is stamped as
    /// `Signify-Resource`. The signature covers the *external* URL's path.
    ///
    /// The request is taken by value and a new one returned, where the reference mutates the
    /// caller's own options object in place.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Identifiers::get`] returns, [`ClientError::Manager`] when the record's
    /// keeper cannot be rebuilt, [`ClientError::NoSigningKey`] when that keeper holds none, and
    /// [`ClientError::Signing`] when the request cannot be signed.
    pub async fn sign_external_request(&self, alias: &str, request: Request) -> Result<Request, ClientError> {
        let record = self.identifiers().get(alias).await?;
        let keeper = self
            .keepers
            .keeper_for(&keria_types::api::Hab::Accepted(record.clone()))?;
        let signer = keeper
            .expose_signers()?
            .into_iter()
            .next()
            .ok_or_else(|| ClientError::NoSigningKey {
                alias: alias.to_owned(),
            })?;
        let resource = HeaderValue::new(record.common.prefix.clone())?;
        // The signing itself is Roadmap 5.5's, which exposed `sign_request` for exactly this call.
        // The inner transport is never used: nothing is sent from here.
        let signing = SigningTransport::new(Arc::clone(&self.unsigned), RequestSigner::new(signer), resource)?
            .with_clock(Arc::clone(&self.clock));
        Ok(signing.sign_request(&request)?)
    }

    /// Sets how old a response signature may be.
    ///
    /// The reference checks freshness nowhere at all, which Roadmap 5.5 recorded; the default
    /// window closes that, and [`Freshness::Ignore`] reproduces the reference exactly.
    #[must_use]
    pub fn with_freshness(mut self, freshness: Freshness) -> Self {
        self.authenticator = self.authenticator.with_freshness(freshness);
        self
    }

    /// Sends one signed request and authenticates the response.
    ///
    /// This is the pipeline every endpoint family will use: stamp the resource and the timestamp,
    /// sign at the request's final form, send, refuse a non-success status, then check the
    /// response came from the expected agent and really said what it says.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, layered
    /// [`ClientError::Signing`] and [`ClientError::Transport`] failures, and
    /// [`ClientError::ResponseAuthentication`] when the response does not authenticate.
    pub async fn fetch(&self, request: ClientRequest) -> Result<Response, ClientError> {
        let path = request.path;
        let url = self.config.admin_url().join(&path)?;
        let mut builder = Request::builder(request.method, url).header(content_type()?, json_value()?);
        for (name, value) in request.headers.iter() {
            builder = builder.header(name.clone(), value.clone());
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let built = builder.build()?;

        // The reference strips the query before signing and verifying alike, so the same target
        // serves both halves; Roadmap 3.10 pinned that.
        let target = RequestTarget::new(built.method().as_str(), built.url().path()).map_err(|source| {
            ClientError::Authentication {
                source: Box::new(source.into()),
            }
        })?;

        // `SigningTransport` signs the request it is handed, so signing happens inside whatever
        // the transport beneath it does — the order ADR `0023` requires.
        let response = self.signing.execute(built).await?;
        require_success(&response)?;
        self.authenticator.authenticate(&target, response.headers())?;
        Ok(response)
    }

    /// Approves the delegation of this controller to the agent.
    ///
    /// **Unsigned.** The reference bypasses its own signed path here and calls the global `fetch`
    /// directly, so the `PUT` anchoring the agent carries no HTTP signature; Roadmap 5.1 recorded
    /// the same defect from the other side. Reproduced, because a signed request is not what KERIA
    /// expects at this endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer and layered controller, request,
    /// and transport failures.
    pub async fn approve_delegation(&mut self) -> Result<Response, ClientError> {
        let signature = self.controller.approve_delegation(&self.agent)?;
        let mut body = Sad::new();
        body.insert("ixn", SadValue::Map(self.controller.current_event().sad().clone()))
            .map_err(sad_error)?;
        body.insert(
            "sigs",
            SadValue::Array(vec![SadValue::Text(signature.qb64().map_err(ClientError::from)?)]),
        )
        .map_err(sad_error)?;

        let path = ResourcePath::builder()
            .segment(AGENT_SEGMENT)
            .segment(&self.controller.prefix().qb64().map_err(prefix_error)?)
            .parameter(APPROVAL_TYPE_PARAMETER, APPROVAL_TYPE_INTERACTION)
            .build()?;
        let request = Request::builder(Method::Put, self.config.admin_url().join(&path)?)
            .header(content_type()?, json_value()?)
            .body(body.to_json_bytes().map_err(sad_error)?)
            .build()?;
        let response = self.unsigned.execute(request).await?;
        require_success(&response)?;
        Ok(response)
    }

    /// Rotates this client to a new passcode; the reference's `SignifyClient.rotate`.
    ///
    /// `identifiers` are the managed identifiers whose stored key material moves with the
    /// passcode. Each one's material is opened with the old passcode's key, checked against the
    /// key state the agent reports for it, and sealed again under the **new** passcode's key —
    /// which the reference does not do, and which is the whole point of rotating. See
    /// [`signify_keri::controller::rotation`] and ADR `0033`.
    ///
    /// **Nothing moves locally until the agent accepts.** The rotation is computed first, sent
    /// second, and adopted third: if the request fails, this client is exactly as it was and the
    /// caller may retry. The reference advances its controller before it sends, so a failed
    /// rotation there leaves a client signing with a key the agent has never seen.
    ///
    /// **Persist the controller prefix with the new passcode.** The controller keeps the prefix its
    /// first passcode incepted, and the new passcode derives a different one, so a client started
    /// later from the new passcode alone asks for an agent that does not exist. The prefix is in
    /// this client's configuration after the rotation — `self.config().controller_prefix()` — and
    /// a later client passes it to [`ClientConfig::with_controller_prefix`]. The reference has no
    /// way to reconnect at all.
    ///
    /// An identifier left out of `identifiers` keeps material sealed to the old passcode, which
    /// the new one cannot open. The list is the caller's — the agent is the only party that knows
    /// the whole set, and the reference passes whatever its caller passes — so this method cannot
    /// check it; pass every managed identifier.
    ///
    /// The rotation is built at the sequence number after the controller's current event — the
    /// reference always writes one, which an agent whose log holds the connection's delegation
    /// approval refuses with `500` — and a rotation the agent accepts becomes the controller's
    /// current event, so the next one chains on it. ADR `0034`.
    ///
    /// **Signed with the key the rotation introduces.** The reference bypasses its signed path and
    /// sends the `PUT` unsigned. A KERIA agent applies the rotation *first* and checks the request's
    /// signature *afterwards*, against the controller's keys as they now stand: upstream KERIA
    /// refuses an unsigned request there with `403` after it has already rotated, leaving the agent
    /// one event ahead of a client that believes the rotation failed. Signing with the new key
    /// satisfies both that check and a deployment that verifies only signed requests. On success
    /// this client signs every later request with the new key too.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Controller`] when an identifier's stored keys do not match its
    /// reported key state or its key manager is one this cannot re-seal,
    /// [`ClientError::InvalidPasscodeLength`] for a passcode that is not twenty-one characters,
    /// [`ClientError::Status`] for a non-success answer, and layered request and transport
    /// failures. On every one of them this client is unchanged.
    pub async fn rotate_passcode(
        &mut self,
        new_passcode: &Passcode,
        identifiers: &[AcceptedHab],
    ) -> Result<Response, ClientError> {
        let planned = self
            .controller
            .plan_passcode_rotation(new_passcode.expose(), identifiers)?;

        let body = rotation_body(planned.artifacts())?;
        let path = ResourcePath::builder()
            .segment(AGENT_SEGMENT)
            .segment(&self.controller.prefix().qb64().map_err(prefix_error)?)
            .build()?;
        let request = Request::builder(Method::Put, self.config.admin_url().join(&path)?)
            .header(content_type()?, json_value()?)
            .body(body)
            .build()?;

        // The agent verifies this request against the controller's keys after applying the
        // rotation it carries, so it is signed with the key the rotation introduces. The same
        // transport signs everything this client sends once the rotation is accepted.
        let rotated = SigningTransport::new(
            Arc::clone(&self.unsigned),
            RequestSigner::new(planned.derive_signing_key()?),
            self.resource.clone(),
        )?
        .with_clock(Arc::clone(&self.clock));
        let response = rotated.execute(request).await?;
        require_success(&response)?;

        // Accepted. Now the client's own secrets move: the controller onto its new chain and its
        // new place in the log, the request signer onto the new key, and the keeper factory and
        // configuration onto the new passcode — without which this client would go on trying to
        // open its identifiers with a key that no longer seals them.
        let keepers = KeeperFactory::new(salt_from_passcode(new_passcode.expose(), self.config.tier())?);
        self.controller.apply_passcode_rotation(planned);
        self.signing = rotated;
        self.keepers = keepers;
        self.config = self
            .config
            .clone()
            .with_passcode(new_passcode.clone())
            .with_controller_prefix(self.controller.prefix().clone());
        Ok(response)
    }

    /// Stores a superseded passcode with the agent.
    ///
    /// **Unsigned**, as upstream: the passcode travels over a request carrying no HTTP signature.
    /// A caller should weigh that against whatever the transport itself provides.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer and layered request and transport
    /// failures.
    pub async fn save_old_passcode(&self, passcode: &crate::config::Passcode) -> Result<Response, ClientError> {
        let mut body = Sad::new();
        body.insert("salt", SadValue::text(passcode.expose()))
            .map_err(sad_error)?;
        let request = Request::builder(Method::Put, self.salt_url()?)
            .header(content_type()?, json_value()?)
            .body(body.to_json_bytes().map_err(sad_error)?)
            .build()?;
        let response = self.unsigned.execute(request).await?;
        require_success(&response)?;
        Ok(response)
    }

    /// Deletes a stored passcode from the agent.
    ///
    /// **Unsigned**, as upstream.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer and layered request and transport
    /// failures.
    pub async fn delete_passcode(&self) -> Result<Response, ClientError> {
        let request = Request::builder(Method::Delete, self.salt_url()?)
            .header(content_type()?, json_value()?)
            .build()?;
        let response = self.unsigned.execute(request).await?;
        require_success(&response)?;
        Ok(response)
    }

    /// Builds the stored-passcode URL both passcode methods use.
    fn salt_url(&self) -> Result<RequestUrl, ClientError> {
        let path = ResourcePath::builder()
            .segment(SALT_SEGMENT)
            .segment(&self.controller.prefix().qb64().map_err(prefix_error)?)
            .build()?;
        Ok(self.config.admin_url().join(&path)?)
    }
}

/// One request an endpoint family asks the client to send.
///
/// The reference's `fetch(path, method, data, extraHeaders)` takes a raw string path and an `any`
/// body. Here the path is Roadmap 5.3's [`ResourcePath`], which encodes every dynamic component
/// exactly once, and the body is already-serialized bytes — this crate never decides a document's
/// shape.
#[derive(Clone, Debug)]
pub struct ClientRequest {
    method: Method,
    path: ResourcePath,
    headers: Headers,
    body: Option<Vec<u8>>,
}

impl ClientRequest {
    /// Starts a request for one method and path.
    #[must_use]
    pub fn new(method: Method, path: ResourcePath) -> Self {
        Self {
            method,
            path,
            headers: Headers::new(),
            body: None,
        }
    }

    /// Adds one header the signature will not cover.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Header`] for an unusable name or value.
    pub fn header(mut self, name: &str, value: &str) -> Result<Self, ClientError> {
        self.headers.insert(HeaderName::new(name)?, HeaderValue::new(value)?)?;
        Ok(self)
    }

    /// Sets the already-serialized request body.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Returns the method.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Returns the path.
    #[must_use]
    pub const fn path(&self) -> &ResourcePath {
        &self.path
    }
}

/// Refuses a non-success status, keeping a bounded body for diagnosis.
fn require_success(response: &Response) -> Result<(), ClientError> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(ClientError::status(response.status().as_u16(), response.body()))
    }
}

fn content_type() -> Result<HeaderName, ClientError> {
    Ok(HeaderName::new("content-type")?)
}

fn json_value() -> Result<HeaderValue, ClientError> {
    Ok(MediaType::json().header_value()?)
}

fn sad_error(source: signify_keri::serialization::SadError) -> ClientError {
    ClientError::Serialization {
        source: Box::new(source.into()),
    }
}

fn prefix_error(source: signify_keri::prefix::PrefixError) -> ClientError {
    ClientError::Controller {
        source: Box::new(source.into()),
    }
}

/// Returns the agent's verification key.
fn agent_key(agent: &Agent) -> VerificationKey {
    agent.verifier().clone()
}

/// Renders a security tier as the wire text the boot body carries.
///
/// The three spellings are the reference's `Tier` enum, which a KERIA agent stores verbatim.
/// [`SecurityTier`] is `#[non_exhaustive]`, so a tier added later renders as the interactive
/// profile rather than failing to compile here; the fixture asserts all three current ones.
const fn tier_text(tier: SecurityTier) -> &'static str {
    match tier {
        SecurityTier::Medium => "med",
        SecurityTier::High => "high",
        SecurityTier::Low | _ => "low",
    }
}

/// Keeps the identifier prefix type reachable from this module's documentation.
const _: Option<IdentifierPrefix> = None;
/// Keeps the status type reachable from this module's documentation.
const _: Option<StatusCode> = None;
/// Keeps the resource header name reachable from this module's documentation.
const _: &str = SIGNIFY_RESOURCE_HEADER_NAME;
/// Keeps the base URL type reachable from this module's documentation.
const _: Option<BaseUrl> = None;

/// Writes the rotation payload the agent expects: the reference's `{rot, sigs, sxlt, keys}`.
fn rotation_body(rotation: &PasscodeRotation) -> Result<Vec<u8>, ClientError> {
    let mut body = Sad::new();
    body.insert("rot", SadValue::Map(rotation.rotation.sad().clone()))
        .map_err(sad_error)?;
    body.insert(
        "sigs",
        SadValue::Array(
            rotation
                .signatures
                .iter()
                .map(|signature| Ok(SadValue::Text(signature.qb64()?)))
                .collect::<Result<Vec<_>, ClientError>>()?,
        ),
    )
    .map_err(sad_error)?;
    body.insert("sxlt", SadValue::text(rotation.sealed_salt.qb64()?))
        .map_err(sad_error)?;

    let mut keys = Sad::new();
    for (prefix, state) in &rotation.re_encrypted {
        let mut entry = Sad::new();
        match state {
            ReEncryptedKeyState::Salty { sealed_salt } => {
                entry
                    .insert("sxlt", SadValue::text(sealed_salt.qb64()?))
                    .map_err(sad_error)?;
            }
            ReEncryptedKeyState::Randy {
                signing_keys,
                next_keys,
            } => {
                entry.insert("prxs", sealed_array(signing_keys)?).map_err(sad_error)?;
                entry.insert("nxts", sealed_array(next_keys)?).map_err(sad_error)?;
            }
        }
        keys.insert(prefix.clone(), SadValue::Map(entry)).map_err(sad_error)?;
    }
    body.insert("keys", SadValue::Map(keys)).map_err(sad_error)?;

    body.to_json_bytes().map_err(sad_error)
}

/// Renders a list of sealed values as the wire's array of qualified ciphertexts.
fn sealed_array(sealed: &[keri_cesr::crypto::cipher::Ciphertext]) -> Result<SadValue, ClientError> {
    Ok(SadValue::Array(
        sealed
            .iter()
            .map(|value| Ok(SadValue::Text(value.qb64()?)))
            .collect::<Result<Vec<_>, ClientError>>()?,
    ))
}
