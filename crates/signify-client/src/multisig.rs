//! Bringing a multisig group into existence, and running it afterwards.
//!
//! A group identifier is not created by one party. Each member independently builds the *same*
//! event from the *same* inputs, signs it with its own key, and tells the others; the agent
//! collects the signatures and the event happens once enough have arrived. That is true of all
//! three rounds a group runs, and both halves of each are here:
//!
//! | round | who starts | who joins |
//! |---|---|---|
//! | inception | [`Multisig::propose_inception`] | [`Multisig::accept_inception`] |
//! | rotation | [`Multisig::propose_rotation`] | [`Multisig::accept_rotation`] |
//! | interaction | [`Multisig::propose_interaction`] | [`Multisig::accept_interaction`] |
//! | delegation approval | [`Multisig::propose_delegation_approval`] | [`Multisig::accept_delegation_approval`] |
//! | registry | [`Multisig::propose_registry`] | [`Multisig::accept_registry`] |
//! | issuance | [`Multisig::propose_issuance`] | [`Multisig::accept_issuance`] |
//! | revocation | [`Multisig::propose_revocation`] | [`Multisig::accept_revocation`] |
//! | disclosure | [`Multisig::propose_disclosure`] | [`Multisig::accept_disclosure`] |
//! | admittance | [`Multisig::propose_admittance`] | [`Multisig::accept_admittance`] |
//! | agent end roles | [`Multisig::propose_agent_end_roles`] | [`Multisig::accept_end_role`] |
//!
//! An inception creates the identifier, a rotation changes who controls it, and an interaction
//! anchors seals in its log without changing anything about its keys. A **delegation approval** is
//! an interaction that goes to a different address: the group is a delegator, and the seals it
//! anchors bring delegated identifiers — themselves often groups — into existence.
//!
//! # The joining half always checks
//!
//! Each of the three joining methods ends up signing something another member composed, and each
//! one checks before it does. An inception reads every field of the event from the proposal, so
//! there is nothing to disagree about. A rotation rebuilds and then **compares the digest it built
//! with the digest it was shown**, refusing to sign a different event. An interaction reads the
//! seals from the proposal and compares the same way.
//!
//! **The reference compares nothing, anywhere.** Its joining members rebuild a rotation from their
//! own key states and sign whatever comes out; where two members' states differ they sign different
//! events, the group never rotates, and nothing says so. The `client-multisig-events` fixture
//! drives exactly that.
//!
//! # A delegation approval anchors every seal it was shown
//!
//! The reference's `delegateMultisig` reads `ixn.a[0]` — the first seal and no other — where its
//! own plain interaction round reads the same field whole. A delegator group anchoring two
//! delegations in one event therefore has the second silently dropped by every member but the
//! initiator. And the one check it does perform fires *after* the approval is posted, comparing the
//! first seal of what it built against the whole anchor it was given: a two-seal approval reaches
//! the delegator's log, then throws, and the peers are never told. Here the seals are checked
//! before anything is written and all of them are anchored.
//!
//! # A joining member reads the proposal
//!
//! The registry, issuance, and revocation rounds are where the reference stops reading altogether.
//! `createRegistryMultisig` and `issueCredentialMultisig` **wait for a notification, discard its
//! SAID, and then build from their own arguments** — no `getRequest`, no comparison, nothing read.
//! So two members handed a different nonce create different registries, and two handed different
//! attributes issue different credentials, and in both cases the group simply never reaches its
//! threshold. Here the nonce and the credential are read out of the proposal, and what this member
//! derives is compared with what it was shown.
//!
//! # A group's IPEX rounds read their timestamp out of the proposal
//!
//! The last two rounds send an IPEX message rather than a key or registry event: the group grants a
//! credential to somebody outside it, or acknowledges one it was granted. The message is built
//! under the group's alias and announced under the member's, and the announcement carries it whole
//! in [`EXCHANGE_SLOT`] with the group's establishment seal over the member's signature.
//!
//! The announcement also names the members in `smids` and `rmids`, as every event round's does.
//! The reference's `grantMultisig` and `admitMultisig` write `{ gid }` alone and hand the peers to
//! the helper as an argument; a joining member here has no such argument, and the group's record
//! cannot supply one — its `keys` are signing keys, not identifiers. So the members travel in the
//! proposal, and a proposal that names none (the reference's) is answered by asking the agent for
//! its listing of them, exactly as `multisigIssue` and `multisigRevoke` do.
//!
//! An IPEX message's SAID covers **its timestamp**, so two members stamping their own clocks build
//! two different messages. The reference's helpers take the stamp as an argument and its holder test
//! reads a module-level `TIME` constant, so both members agree only because one process handed them
//! the same value; `assert.equal(admitResult1.admitSaid, admitResult2.admitSaid)` passes there and
//! would fail in any real deployment. Here [`Multisig::accept_admittance`] takes no timestamp at
//! all — it reads the stamp, the recipient, the text, and the grant being acknowledged out of the
//! proposal, and compares the SAID it derives with the one it was shown.
//!
//! # A group reaches its members' agents only once it authorizes them
//!
//! A group identifier has no agent endpoint until its members authorize one, so until then nothing
//! addressed to the group gets past the sender's own agent. The reference's `addEndRoleMultisig`
//! authorizes **every signing member's agent** — one end-role reply per agent, each announced on
//! [`REPLY_ROUTE`] with the reply in [`REPLY_SLOT`] under the group's establishment seal — and so
//! does [`Multisig::propose_agent_end_roles`]. A joining member of the reference waits for as many
//! notifications as there are signing members, **discards them**, and builds its replies from its
//! own timestamp argument, so two members stamping differently sign different replies, and a group
//! whose threshold needs more than one member authorizes nobody. [`Multisig::accept_end_role`]
//! takes no timestamp: it reads the stamp, the role, and the endpoint out of the proposal and
//! compares the reply it derives with the one it was shown.
//!
//! The two halves are not tied to a leader. A member may propose every agent and also accept every
//! proposal it is shown, which is what a notification-driven wallet does: each member proposes once
//! its own group operation completes, with its own stamp, and accepts each `/multisig/rpy`
//! notification as it arrives. Replies proposed by different members carry different stamps and so
//! different SAIDs, and each reaches the group's threshold through the members accepting it.
//!
//! The agent keeps a reply short of the threshold in escrow for one hour **measured from the
//! reply's own stamp**, not from when it arrived, so every member must sign within an hour of the
//! stamp the proposer chose. A stamp in the past shortens that window; one more than an hour old
//! can never complete.
//!
//! # The route names the embed
//!
//! Every announcement here carries the embed slot its route names, because the two travel together
//! in one value. Upstream they do not: of the three sends that carry a rotation, only the
//! initiator's uses `/multisig/rot` — both joining members send the same `rot` embed under
//! [`INTERACTION_ROUTE`] while their peers wait on [`ROTATION_ROUTE`].
//!
//! # There is no upstream file
//!
//! The reference writes this orchestration only in its own tests. The inception round lives in the
//! helpers `startMultisigIncept` and `acceptMultisigIncept` in
//! `test-integration/utils/multisig-utils.ts`; the other two are written inline in the body of
//! `test-integration/multisig.test.ts` and are not even functions. So there is no exported API to
//! port and no unit test to reproduce. It is a Rust-only module, and the fixtures run the
//! reference's own code — the helpers by transpiling that one file in memory, the two later rounds
//! by driving the same primitives in the same order. See `fixtures/client-multisig-inception/` and
//! `fixtures/client-multisig-events/`.
//!
//! # What this composes
//!
//! Nothing here is new protocol. The inception is an identifier artifact submitted through the
//! identifier endpoint; the proposal is an exchange message signed by the member's keeper, attached
//! with CESR attachment framing and sent through the exchange submission; the proposal a joining
//! member reads is the group listing classified by the route table. This module is the order those
//! go in, and the four places the reference gets that order wrong.
//!
//! # A proposal is addressed to a peer
//!
//! `startMultisigIncept` passes its whole participant list as the recipient list, and the local
//! member is the first of it — so through the exchange submission's delivery loop, the message is
//! addressed to its own sender and delivered back to itself along with everybody else. The
//! accepting helper already filters itself out; here both do.
//!
//! # A joining member relays what it read
//!
//! `acceptMultisigIncept` reads the proposal's rotation members, derives the group's next keys from
//! them, and then relays `rmids: smids` — the *signing* set — so a third member joining from its
//! message is told the wrong one. Here the set that was read is the set that is relayed.
//!
//! # The witness threshold is not re-parsed
//!
//! The reference rebuilds the accepted inception with `toad: parseInt(icp.bt)`, and `bt` is written
//! in hexadecimal. Below ten the two agree. `"a"` parses to `NaN` and throws. `"10"` is sixteen and
//! parses to **ten**, which throws nothing: the joining member builds a different event, derives a
//! different group identifier, and the two members wait for each other forever. The fixture records
//! both, driven. Here the proposal's own decoded event supplies the threshold, so there is no
//! string to read in the wrong base.
//!
//! # One thing this port does that the reference does not
//!
//! It reads the member record **twice**: once here to build the group, and once inside
//! [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send), which resolves its own sender
//! from the alias rather than taking a record the caller is already holding. That is what keeps a
//! message's `i` field and the key that signed it one identifier, and it is why a proposal makes
//! six requests here where the reference — passing the hab it already has — makes five. The group's
//! keys come from the participants' key states either way, so nothing rests on it.

use keri_acdc::credential::Credential;
use keri_cesr::sequence::SequenceNumber;
use keri_protocol::attachment::{SignatureSeal, SignedMessageBuilder};
use keri_protocol::event::Timestamp;
use keri_protocol::event::exchange::ExchangeEmbed;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadError, SadValue};
use keri_protocol::threshold::SigningThreshold;
use keria_types::api::{
    AcceptedHab, ExchangeEmbed as ApiEmbed, ExchangeRecord, GroupMember, Hab, KeyEvent, KeyState,
    MultisigExchangeResource, RegistryInceptionRecord, ReplyRecord, Role, Threshold,
};
use signify_keys::acdc::ipex::{self, Disclosure, IpexEnvelope, IpexMessage, IpexRoute};
use signify_keys::acdc::revocation::RevocationEvent;
use signify_keys::identifier::{
    CreateAlgorithm, CreateIdentifierRequest, END_ROLE_ROUTE, IdentifierArtifact, RotateIdentifierRequest, SignedReply,
    end_role_reply,
};

use crate::client::ConnectedClient;
use crate::endpoint::body::{sad_error, text_array};
use crate::endpoint::credentials::{IssuedCredential, RevokedCredential};
use crate::endpoint::decode_json;
use crate::endpoint::delegations::DELEGATION_SEGMENT;
use crate::endpoint::exchanges::{
    ClassifiedExchange, ExchangeDraft, GROUP_LABEL, MultisigProposal, MultisigRoute, REGISTRY_TOPIC,
    ROTATION_MEMBERS_LABEL, SIGNING_MEMBERS_LABEL, SentExchange,
};
use crate::endpoint::identifiers::{EVENTS_SEGMENT, Submission};
use crate::endpoint::ipex::SubmittedIpexMessage;
use crate::endpoint::registries::{CreateRegistryRequest, CreatedRegistry, RegistryBacking};
use crate::error::ClientError;

/// The route a group inception is proposed on.
pub const INCEPTION_ROUTE: &str = "/multisig/icp";

/// The embed slot a group inception proposal carries.
pub const INCEPTION_SLOT: &str = "icp";

/// The route a group rotation is proposed on.
pub const ROTATION_ROUTE: &str = "/multisig/rot";

/// The embed slot a group rotation proposal carries.
pub const ROTATION_SLOT: &str = "rot";

/// The route a group interaction is proposed on.
///
/// **Upstream announces rotations here too.** Only the initiator of a rotation sends
/// [`ROTATION_ROUTE`]; both joining members send a `rot` embed under this route while their peers
/// wait on that one. Nothing here does that: the route names the embed.
pub const INTERACTION_ROUTE: &str = "/multisig/ixn";

/// The embed slot a group interaction proposal carries.
pub const INTERACTION_SLOT: &str = "ixn";

/// What a group inception commits to.
///
/// Every member must build the same event, so every field here is part of the group's identifier:
/// change one and the members derive different groups and never converge. That is why the joining
/// half takes none of them — it reads them all from the proposal.
#[derive(Debug)]
pub struct GroupInceptionRequest<'a> {
    /// Local alias the group will be stored under; the reference's `groupName`.
    ///
    /// It is also the notification topic the proposal is filed under, which is the reference's own
    /// choice: `startMultisigIncept` passes this as the topic, so peers see the *sender's* local
    /// alias for a group none of them has named yet.
    pub group_name: &'a str,
    /// Local alias of this member's own identifier; the reference's `localMemberName`.
    pub local_member: &'a str,
    /// Every member of the group, this one included; the reference's `participants`.
    pub participants: &'a [IdentifierPrefix],
    /// How many members must sign; the reference's `isith`.
    pub signing_threshold: Option<SigningThreshold>,
    /// How many must sign the next rotation; the reference's `nsith`.
    pub next_threshold: Option<SigningThreshold>,
    /// Witnesses the group will use; the reference's `wits`.
    pub witnesses: &'a [IdentifierPrefix],
    /// How many witness receipts the group requires; the reference's `toad`.
    pub witness_threshold: u32,
    /// Delegator, when the group is delegated; the reference's `delpre`.
    pub delegator: Option<&'a IdentifierPrefix>,
    /// When the proposal message is stamped.
    ///
    /// Required, as everywhere in this port: the reference reads the clock, and a message's `dt` is
    /// inside its SAID and every signature over it.
    pub timestamp: Timestamp,
}

/// One member's half of a group inception: what it created and what it told its peers.
#[derive(Debug)]
pub struct GroupInception {
    group: IdentifierPrefix,
    creation: Submission<IdentifierArtifact>,
    proposal: SentExchange,
    signing_members: Vec<IdentifierPrefix>,
    rotation_members: Vec<IdentifierPrefix>,
}

impl GroupInception {
    /// Returns the group identifier every member must derive.
    ///
    /// Two members that disagree about this have not joined the same group — which is exactly what
    /// the reference's base-ten witness threshold produces.
    #[must_use]
    pub const fn group(&self) -> &IdentifierPrefix {
        &self.group
    }

    /// Returns the creation the agent was asked to perform, with its long-running operation.
    #[must_use]
    pub const fn creation(&self) -> &Submission<IdentifierArtifact> {
        &self.creation
    }

    /// Returns the agent's answer to the proposal message.
    #[must_use]
    pub const fn proposal(&self) -> &SentExchange {
        &self.proposal
    }

    /// Returns the members that will sign for the group.
    #[must_use]
    pub fn signing_members(&self) -> &[IdentifierPrefix] {
        &self.signing_members
    }

    /// Returns the members that will hold rotation authority.
    ///
    /// For a proposal this is the signing set; for an acceptance it is whatever the proposal said,
    /// where the reference substitutes the signing set on the way out.
    #[must_use]
    pub fn rotation_members(&self) -> &[IdentifierPrefix] {
        &self.rotation_members
    }
}

/// What a group rotation commits to.
///
/// As with an inception every field here is inside the event's digest, so two members that differ
/// about one of them produce different rotations: [`Multisig::accept_rotation`] takes the same
/// request and refuses a rotation that is not the one it was shown.
#[derive(Debug)]
pub struct GroupRotationRequest<'a> {
    /// Local alias of the group; also the notification topic, as the reference passes it.
    pub group_name: &'a str,
    /// Local alias of this member's own identifier.
    pub local_member: &'a str,
    /// Key states supplying the group's new signing keys; the reference's `states`.
    pub signing_states: &'a [KeyState],
    /// Key states supplying the group's new next digests; the reference's `rstates`.
    ///
    /// Separate from `signing_states`, and never defaulted to it. The reference's two rotation
    /// call sites disagree about which one reaches `rmids`, which is the same conflation the
    /// `client-multisig-inception` fixture recorded in the accepting half of an inception.
    pub rotation_states: &'a [KeyState],
    /// Signing threshold; the reference's `isith`, defaulting to the state's own next threshold.
    pub signing_threshold: Option<SigningThreshold>,
    /// Next-key threshold; the reference's `nsith`, defaulting to the signing threshold.
    pub next_threshold: Option<SigningThreshold>,
    /// Witness threshold; the reference's `toad`, computed from the surviving witnesses when absent.
    pub witness_threshold: Option<u32>,
    /// Witnesses removed; the reference's `cuts`.
    pub witness_cuts: &'a [IdentifierPrefix],
    /// Witnesses added; the reference's `adds`.
    pub witness_adds: &'a [IdentifierPrefix],
    /// A seal anchored in the rotation; the reference's `data`.
    pub anchor: Option<Sad>,
    /// When the proposal message is stamped.
    pub timestamp: Timestamp,
}

/// What a group interaction anchors.
///
/// An interaction changes nothing about who controls the group; it commits the group's log to the
/// seals it carries. The joining half reads those seals out of the proposal rather than taking
/// them, because anchoring different data would produce a different event.
#[derive(Debug)]
pub struct GroupInteractionRequest<'a> {
    /// Local alias of the group; also the notification topic.
    pub group_name: &'a str,
    /// Local alias of this member's own identifier.
    pub local_member: &'a str,
    /// Every member of the group, this one included.
    pub members: &'a [IdentifierPrefix],
    /// The seals the interaction anchors; the reference's `data`.
    pub anchors: Vec<Sad>,
    /// When the proposal message is stamped.
    pub timestamp: Timestamp,
}

/// What a group's delegation approval commits to.
///
/// The group named here is the **delegator**: it is anchoring seals of identifiers that named it,
/// and each of its members must anchor the same ones.
#[derive(Debug)]
pub struct GroupDelegationRequest<'a> {
    /// Local alias of the delegator group; also the notification topic.
    pub group_name: &'a str,
    /// Local alias of this member's own identifier.
    pub local_member: &'a str,
    /// Every member of the delegator group, this one included.
    pub members: &'a [IdentifierPrefix],
    /// The seals to anchor; [`InceptionSeal::to_sad`] builds one.
    ///
    /// [`InceptionSeal::to_sad`]: crate::endpoint::delegations::InceptionSeal::to_sad
    ///
    /// More than one is permitted, because the event format permits it and the endpoint accepts it.
    /// The reference's helper cannot send more than one: its own assertion compares the first seal
    /// of what it built against the whole anchor it was given, and fails — after the approval has
    /// been posted.
    pub seals: &'a [Sad],
    /// When the announcement is stamped.
    pub timestamp: Timestamp,
}

/// What a group's registry creation commits to.
///
/// The registry identifier is a digest over its inception, and the **nonce** is inside that digest
/// — so every member must supply the same one or they create different registries. The reference
/// makes that the caller's problem twice over: its joining half waits for a notification, discards
/// the SAID, and then creates a registry from its own arguments without ever reading the proposal.
#[derive(Debug)]
pub struct GroupRegistryRequest<'a> {
    /// Local alias of the group that will own the registry.
    pub group_name: &'a str,
    /// Local alias of this member's own identifier.
    pub local_member: &'a str,
    /// Every member of the group, this one included.
    pub members: &'a [IdentifierPrefix],
    /// Alias the registry is stored under; the reference's `registryName`.
    pub registry: &'a str,
    /// Nonce the registry identifier derives from.
    ///
    /// Required here, where the reference's endpoint draws one from the operating system when it
    /// is absent — which for a group means every member deriving a different registry.
    pub nonce: &'a str,
    /// Who witnesses the registry's events.
    pub backing: RegistryBacking,
    /// When the announcement is stamped.
    pub timestamp: Timestamp,
}

/// What a group's credential issuance commits to.
#[derive(Debug)]
pub struct GroupIssuanceRequest<'a> {
    /// Local alias of the issuing group.
    pub group_name: &'a str,
    /// Local alias of this member's own identifier.
    pub local_member: &'a str,
    /// Every member of the group, this one included.
    pub members: &'a [IdentifierPrefix],
    /// The credential to issue; every field of it is inside its SAID.
    pub credential: Credential,
    /// When the announcement is stamped.
    pub timestamp: Timestamp,
}

/// What a group's credential revocation commits to.
#[derive(Debug)]
pub struct GroupRevocationRequest<'a> {
    /// Local alias of the issuing group.
    pub group_name: &'a str,
    /// Local alias of this member's own identifier.
    pub local_member: &'a str,
    /// Every member of the group, this one included.
    pub members: &'a [IdentifierPrefix],
    /// The revocation event to record.
    pub revocation: RevocationEvent,
    /// When the announcement is stamped.
    pub timestamp: Timestamp,
}

/// One member's half of a group rotation or interaction.
///
/// The same shape as [`GroupInception`] minus the group identifier, which an existing group already
/// has: what this member submitted, and what it told its peers.
#[derive(Debug)]
pub struct GroupEvent {
    submission: Submission<IdentifierArtifact>,
    announcement: SentExchange,
    signing_members: Vec<IdentifierPrefix>,
    rotation_members: Vec<IdentifierPrefix>,
}

impl GroupEvent {
    /// Returns the event the agent was asked to perform, with its long-running operation.
    #[must_use]
    pub const fn submission(&self) -> &Submission<IdentifierArtifact> {
        &self.submission
    }

    /// Returns the agent's answer to the announcement.
    #[must_use]
    pub const fn announcement(&self) -> &SentExchange {
        &self.announcement
    }

    /// Returns the members that will sign for the group.
    #[must_use]
    pub fn signing_members(&self) -> &[IdentifierPrefix] {
        &self.signing_members
    }

    /// Returns the members that will hold rotation authority, as named rather than as substituted.
    #[must_use]
    pub fn rotation_members(&self) -> &[IdentifierPrefix] {
        &self.rotation_members
    }
}

/// Multisig group workflows.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through — the shape every endpoint family and the operation poller share.
#[derive(Debug)]
pub struct Multisig<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Multisig<'client> {
    /// Binds these workflows to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Proposes a group inception to its other members.
    ///
    /// The local member's identifier supplies the key that signs; the participants' key states
    /// supply the group's keys. The event is created through the agent — which is what starts the
    /// long-running operation that completes when enough members have signed — and then proposed to
    /// the other members over `/multisig/icp`.
    ///
    /// **The proposal is addressed to a peer and delivered to the peers.** The local member is
    /// removed from the delivery list, which the reference does when *accepting* and not when
    /// proposing.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::LocalMemberNotAParticipant`] when the local member is not among the
    /// participants, [`ClientError::LonelyGroup`] when it is the only one, and whatever
    /// [`Identifiers::create`](crate::endpoint::identifiers::Identifiers::create),
    /// [`KeyStates::get`](crate::endpoint::key_states::KeyStates::get), and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn propose_inception(&self, request: &GroupInceptionRequest<'_>) -> Result<GroupInception, ClientError> {
        let member = self.local_member(request.local_member).await?;
        let recipients = peers(&member, request.participants)?;
        let states = self.key_states(request.participants).await?;

        let creation = CreateIdentifierRequest {
            signing_threshold: request.signing_threshold.clone(),
            next_threshold: request.next_threshold.clone(),
            witnesses: request.witnesses.to_vec(),
            witness_threshold: request.witness_threshold,
            delegator: request.delegator.cloned(),
            ..CreateIdentifierRequest::new(CreateAlgorithm::Group {
                member: Box::new(member.clone()),
                // The reference passes the participants' states for both, so a proposal always
                // names one set; a member that wants two states them when it accepts.
                states: states.clone(),
                next_states: states.clone(),
            })
        };

        let members: Vec<IdentifierPrefix> = request.participants.to_vec();
        self.submit(&Proposed {
            group_name: request.group_name,
            local_member: request.local_member,
            creation: &creation,
            // The reference names one set for both, which is what a proposal commits to.
            signing: &members,
            rotation: &members,
            recipients: &recipients,
            timestamp: request.timestamp.clone(),
        })
        .await
    }

    /// Joins a group inception another member proposed.
    ///
    /// Every field of the event is read from the proposal rather than taken from the caller: the
    /// group identifier is a digest over them, so a member that supplied its own would derive a
    /// different group. That includes the witness threshold, which the reference re-parses out of
    /// the event's hexadecimal `bt` with a base-ten `parseInt`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotAnInceptionProposal`] when the message under `proposal` is not a
    /// group inception, [`ClientError::LocalMemberNotAParticipant`] when the local member is not
    /// among the members it names, [`ClientError::LonelyGroup`] when it is the only one, and
    /// whatever [`Groups::requests`](crate::endpoint::groups::Groups::requests),
    /// [`Identifiers::create`](crate::endpoint::identifiers::Identifiers::create), and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn accept_inception(
        &self,
        group_name: &str,
        local_member: &str,
        proposal: &Said,
        timestamp: Timestamp,
    ) -> Result<GroupInception, ClientError> {
        let member = self.local_member(local_member).await?;
        let proposed = self.read_proposal(proposal, MultisigRoute::Inception).await?;

        let signing = proposed.attributes.signing_members.clone().unwrap_or_default();
        // The reference's `exn.a.rmids ?? smids`, kept as what it read rather than replaced on the
        // way out.
        let rotation = proposed
            .attributes
            .rotation_members
            .clone()
            .unwrap_or_else(|| signing.clone());
        let recipients = peers(&member, &signing)?;

        let inception = inception_event(&proposed)?;
        let states = self.key_states(&signing).await?;
        let next_states = self.key_states(&rotation).await?;

        let creation = CreateIdentifierRequest {
            signing_threshold: Some(inception.signing_threshold.clone()),
            next_threshold: Some(inception.next_threshold.clone()),
            witnesses: inception.witnesses.clone(),
            // Read in the base the protocol writes it in, not with a base-ten `parseInt`.
            witness_threshold: inception.witness_threshold,
            delegator: inception.delegator.clone(),
            ..CreateIdentifierRequest::new(CreateAlgorithm::Group {
                member: Box::new(member.clone()),
                states,
                next_states,
            })
        };

        self.submit(&Proposed {
            group_name,
            local_member,
            creation: &creation,
            signing: &signing,
            rotation: &rotation,
            recipients: &recipients,
            timestamp,
        })
        .await
    }

    /// Proposes a rotation of the group's keys to its other members.
    ///
    /// The group's new keys come from the members' own key states, which each member queries for
    /// itself — so this is where a group most easily fails to converge, and the accepting half is
    /// built to avoid it: [`Self::accept_rotation`] signs the event *this* member proposed rather
    /// than rebuilding its own.
    ///
    /// The announcement goes out on [`ROTATION_ROUTE`], which is the route the reference's own
    /// members wait on and the route only its *initiator* sends.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::LocalMemberNotAParticipant`] when the local member is not among the
    /// signing states, [`ClientError::LonelyGroup`] when it is the only one, and whatever
    /// [`Identifiers::rotate`](crate::endpoint::identifiers::Identifiers::rotate) and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn propose_rotation(&self, request: &GroupRotationRequest<'_>) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(request.local_member).await?;
        let signing = prefixes_of(request.signing_states)?;
        let rotation = prefixes_of(request.rotation_states)?;
        let recipients = peers(&member, &signing)?;

        let rotate = RotateIdentifierRequest {
            signing_threshold: request.signing_threshold.clone(),
            next_threshold: request.next_threshold.clone(),
            witness_threshold: request.witness_threshold,
            witness_cuts: request.witness_cuts.to_vec(),
            witness_adds: request.witness_adds.to_vec(),
            anchor: request.anchor.clone(),
            states: request.signing_states.to_vec(),
            next_states: request.rotation_states.to_vec(),
            ..RotateIdentifierRequest::default()
        };
        let submission = self.client.identifiers().rotate(request.group_name, &rotate).await?;

        self.announce(
            submission,
            &Announcement {
                group_name: request.group_name,
                local_member: request.local_member,
                route: ROTATION_ROUTE,
                slot: ROTATION_SLOT,
                signing: &signing,
                rotation: &rotation,
                recipients: &recipients,
                timestamp: request.timestamp.clone(),
            },
        )
        .await
    }

    /// Joins a rotation another member proposed, after checking it is the same rotation.
    ///
    /// This member rebuilds the rotation from the key states it queried — which is what the
    /// reference does — and then **compares what it built with what it was shown**, refusing to
    /// sign a different event. The reference compares nothing: `multisig.test.ts` has its joining
    /// members call `rotate` again and sign whatever comes out, so two members whose key states
    /// differ sign different rotations and the group silently never rotates. The fixture drives
    /// exactly that, with no error raised on either side.
    ///
    /// The check is a digest comparison rather than a byte comparison, and that is not a
    /// weakening: an event's SAID is a digest over the event, so two events with the same SAID are
    /// the same event. It is also the only check available — a decoded record cannot reproduce the
    /// bytes it arrived as.
    ///
    /// The announcement goes out on [`ROTATION_ROUTE`], where the reference's joining members send
    /// [`INTERACTION_ROUTE`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotARotationProposal`] when the message under `proposal` is not a
    /// group rotation, [`ClientError::ProposalMismatch`] when the rotation this member builds is
    /// not the one it was shown (nothing is sent), and whatever
    /// [`Groups::requests`](crate::endpoint::groups::Groups::requests),
    /// [`Identifiers::rotate`](crate::endpoint::identifiers::Identifiers::rotate), and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn accept_rotation(
        &self,
        request: &GroupRotationRequest<'_>,
        proposal: &Said,
    ) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(request.local_member).await?;
        let proposed = self.read_proposal(proposal, MultisigRoute::Rotation).await?;
        let ApiEmbed::Rotation(embed) = &proposed.proposed.message else {
            return Err(ClientError::NotARotationProposal {
                found: "an embed that is not a rotation",
            });
        };
        let proposed_digest = rotation_digest(&embed.rot)?;

        // The member lists come from the proposal, not from the caller: they are inside the event
        // the group is agreeing on, so taking them from anywhere else is how members diverge.
        let signing = proposed.attributes.signing_members.clone().unwrap_or_default();
        let rotation = proposed
            .attributes
            .rotation_members
            .clone()
            .unwrap_or_else(|| signing.clone());
        let recipients = peers(&member, &signing)?;

        let rotate = RotateIdentifierRequest {
            signing_threshold: request.signing_threshold.clone(),
            next_threshold: request.next_threshold.clone(),
            witness_threshold: request.witness_threshold,
            witness_cuts: request.witness_cuts.to_vec(),
            witness_adds: request.witness_adds.to_vec(),
            anchor: request.anchor.clone(),
            states: request.signing_states.to_vec(),
            next_states: request.rotation_states.to_vec(),
            ..RotateIdentifierRequest::default()
        };
        let identifiers = self.client.identifiers();
        let (artifact, body) = identifiers.build_rotation(request.group_name, &rotate, None).await?;

        let built = artifact.event.said().qb64()?;
        if built != proposed_digest {
            return Err(ClientError::ProposalMismatch {
                proposed: proposed_digest,
                built,
            });
        }
        let submission = identifiers
            .submit_event(request.group_name, EVENTS_SEGMENT, artifact, &body)
            .await?;

        self.announce(
            submission,
            &Announcement {
                group_name: request.group_name,
                local_member: request.local_member,
                route: ROTATION_ROUTE,
                slot: ROTATION_SLOT,
                signing: &signing,
                rotation: &rotation,
                recipients: &recipients,
                timestamp: request.timestamp.clone(),
            },
        )
        .await
    }

    /// Proposes an interaction anchoring `anchors` in the group's log.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::LocalMemberNotAParticipant`] when the local member is not among the
    /// members, [`ClientError::LonelyGroup`] when it is the only one, and whatever
    /// [`Identifiers::interact`](crate::endpoint::identifiers::Identifiers::interact) and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn propose_interaction(&self, request: &GroupInteractionRequest<'_>) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(request.local_member).await?;
        let recipients = peers(&member, request.members)?;
        let submission = self
            .client
            .identifiers()
            .interact(request.group_name, request.anchors.clone())
            .await?;

        self.announce(
            submission,
            &Announcement {
                group_name: request.group_name,
                local_member: request.local_member,
                route: INTERACTION_ROUTE,
                slot: INTERACTION_SLOT,
                signing: request.members,
                rotation: request.members,
                recipients: &recipients,
                timestamp: request.timestamp.clone(),
            },
        )
        .await
    }

    /// Joins an interaction another member proposed, anchoring the seals it named.
    ///
    /// The seals are read out of the proposal's embedded event, which is what the reference does
    /// here and the one half of these two rounds it gets right — anchoring anything else would
    /// produce a different event. What this adds is the check: the event this member builds is
    /// compared with the one it was shown, and a disagreement is refused rather than signed.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotAnInteractionProposal`] when the message under `proposal` is not a
    /// group interaction, [`ClientError::ProposalMismatch`] when the event this member builds is
    /// not the event it was shown (nothing is sent), and whatever
    /// [`Groups::requests`](crate::endpoint::groups::Groups::requests),
    /// [`Identifiers::interact`](crate::endpoint::identifiers::Identifiers::interact), and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn accept_interaction(
        &self,
        group_name: &str,
        local_member: &str,
        proposal: &Said,
        timestamp: Timestamp,
    ) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(local_member).await?;
        let (proposed, embeds) = self
            .read_proposal_and_embeds(proposal, MultisigRoute::Interaction)
            .await?;
        let ApiEmbed::Interaction(embed) = &proposed.proposed.message else {
            return Err(ClientError::NotAnInteractionProposal {
                found: "an embed that is not an interaction",
            });
        };

        let anchors = anchors_of(&embeds)?;
        let signing = proposed.attributes.signing_members.clone().unwrap_or_default();
        let rotation = proposed
            .attributes
            .rotation_members
            .clone()
            .unwrap_or_else(|| signing.clone());
        let recipients = peers(&member, &signing)?;

        let identifiers = self.client.identifiers();
        let (artifact, body) = identifiers.build_interaction(group_name, anchors).await?;

        // What was built against what was shown. The reference compares nothing anywhere.
        let proposed_digest = digest_of(&embed.ixn)?;
        let built = artifact.event.said().qb64()?;
        if built != proposed_digest {
            return Err(ClientError::ProposalMismatch {
                proposed: proposed_digest,
                built,
            });
        }
        let submission = identifiers
            .submit_event(group_name, EVENTS_SEGMENT, artifact, &body)
            .await?;

        self.announce(
            submission,
            &Announcement {
                group_name,
                local_member,
                route: INTERACTION_ROUTE,
                slot: INTERACTION_SLOT,
                signing: &signing,
                rotation: &rotation,
                recipients: &recipients,
                timestamp,
            },
        )
        .await
    }

    /// Proposes a delegation approval to the group's other members.
    ///
    /// The group is the **delegator**: each of its members anchors the same seals in the group's
    /// log and tells the others, and the delegation completes when enough have signed. The event is
    /// an interaction, posted to the delegation family's `delegation` address rather than to
    /// `events` — which is what tells the agent it completes a pending delegated inception — and
    /// announced on [`INTERACTION_ROUTE`], which is what it embeds.
    ///
    /// **The seals are checked before anything is written.** The reference's `delegateMultisig`
    /// posts the approval first and asserts afterwards, comparing `serder.sad.a[0]` against the
    /// whole anchor it was given — so a two-seal approval is anchored in the delegator's log, then
    /// fails its own assertion, and the peers are never told.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoDelegationSeals`] for an empty seal list,
    /// [`ClientError::LocalMemberNotAParticipant`] when the local member is not among the members,
    /// [`ClientError::LonelyGroup`] when it is the only one, and whatever
    /// [`Delegations::approve`](crate::endpoint::delegations::Delegations::approve) and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn propose_delegation_approval(
        &self,
        request: &GroupDelegationRequest<'_>,
    ) -> Result<GroupEvent, ClientError> {
        if request.seals.is_empty() {
            return Err(ClientError::NoDelegationSeals);
        }
        let member = self.local_member(request.local_member).await?;
        let recipients = peers(&member, request.members)?;
        let submission = self
            .client
            .delegations()
            .approve(request.group_name, request.seals)
            .await?;

        self.announce(
            submission,
            &Announcement {
                group_name: request.group_name,
                local_member: request.local_member,
                route: INTERACTION_ROUTE,
                slot: INTERACTION_SLOT,
                signing: request.members,
                rotation: request.members,
                recipients: &recipients,
                timestamp: request.timestamp.clone(),
            },
        )
        .await
    }

    /// Joins a delegation approval another member proposed, anchoring **every** seal it named.
    ///
    /// The reference reads `ixn.a[0]` — the first seal and no other — where its own plain
    /// interaction round reads the same field whole. So a delegator group anchoring two delegations
    /// in one event has the second silently dropped by every member but the initiator, the members
    /// sign different events, and the group never reaches its threshold. Driven, with no error on
    /// either side.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotAnInteractionProposal`] when the message under `proposal` is not a
    /// group interaction, [`ClientError::NoDelegationSeals`] when it anchors nothing,
    /// [`ClientError::ProposalMismatch`] when the event this member builds is not the event it was
    /// shown (nothing is sent), and whatever
    /// [`Groups::requests`](crate::endpoint::groups::Groups::requests),
    /// [`Delegations::approve`](crate::endpoint::delegations::Delegations::approve), and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn accept_delegation_approval(
        &self,
        group_name: &str,
        local_member: &str,
        proposal: &Said,
        timestamp: Timestamp,
    ) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(local_member).await?;
        let (proposed, embeds) = self
            .read_proposal_and_embeds(proposal, MultisigRoute::Interaction)
            .await?;
        let ApiEmbed::Interaction(embed) = &proposed.proposed.message else {
            return Err(ClientError::NotAnInteractionProposal {
                found: "an embed that is not an interaction",
            });
        };

        // Every seal, not the first one.
        let seals = anchors_of(&embeds)?;
        if seals.is_empty() {
            return Err(ClientError::NoDelegationSeals);
        }
        let signing = proposed.attributes.signing_members.clone().unwrap_or_default();
        let rotation = proposed
            .attributes
            .rotation_members
            .clone()
            .unwrap_or_else(|| signing.clone());
        let recipients = peers(&member, &signing)?;

        let identifiers = self.client.identifiers();
        let (artifact, body) = identifiers.build_interaction(group_name, seals).await?;

        // What was built against what was shown, before anything is sent.
        let proposed_digest = digest_of(&embed.ixn)?;
        let built = artifact.event.said().qb64()?;
        if built != proposed_digest {
            return Err(ClientError::ProposalMismatch {
                proposed: proposed_digest,
                built,
            });
        }
        let submission = identifiers
            .submit_event(group_name, DELEGATION_SEGMENT, artifact, &body)
            .await?;

        self.announce(
            submission,
            &Announcement {
                group_name,
                local_member,
                route: INTERACTION_ROUTE,
                slot: INTERACTION_SLOT,
                signing: &signing,
                rotation: &rotation,
                recipients: &recipients,
                timestamp,
            },
        )
        .await
    }

    /// Proposes a credential registry for the group to own.
    ///
    /// A registry identifier is a digest over its own inception, and the **nonce is inside that
    /// digest** — so every member must supply the same one or the group creates several registries
    /// and agrees on none. The nonce is required here for that reason; the endpoint beneath draws
    /// one from the operating system when it is absent, which is right for a single signer and
    /// wrong for a group.
    ///
    /// The announcement carries two embeds — the registry inception and the key event anchoring it
    /// — on [`REGISTRY_ROUTE`], under the reference's own `registry` topic.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::LocalMemberNotAParticipant`] when the local member is not among the
    /// members, [`ClientError::LonelyGroup`] when it is the only one, and whatever
    /// [`Registries::create`](crate::endpoint::registries::Registries::create) and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn propose_registry(&self, request: &GroupRegistryRequest<'_>) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(request.local_member).await?;
        let recipients = peers(&member, request.members)?;

        let created = self
            .client
            .registries()
            .create(&CreateRegistryRequest {
                identifier: request.group_name.to_owned(),
                registry: request.registry.to_owned(),
                backing: request.backing.clone(),
                nonce: Some(request.nonce.to_owned()),
            })
            .await?;

        let (submission, embeds) = registry_announcement(created)?;
        self.send_announcement(
            submission,
            &Announcement {
                group_name: request.group_name,
                local_member: request.local_member,
                route: REGISTRY_ROUTE,
                slot: REGISTRY_SLOT,
                signing: request.members,
                rotation: request.members,
                recipients: &recipients,
                timestamp: request.timestamp.clone(),
            },
            REGISTRY_TOPIC,
            embeds,
        )
        .await
    }

    /// Joins a registry creation another member proposed, taking the nonce from the proposal.
    ///
    /// **The reference does not read the proposal at all.** `createRegistryMultisig` waits for a
    /// `/multisig/vcp` notification, *discards its SAID*, and then creates a registry from its own
    /// arguments — so a member handed a different nonce derives a different registry and nothing
    /// says so. Here the registry inception is read out of the message, its nonce is what this
    /// member uses, and the registry it derives is compared with the one it was shown.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotARegistryProposal`] when the message under `proposal` is not a
    /// registry inception, [`ClientError::ProposalMismatch`] when this member derives a different
    /// registry (nothing is sent), and whatever
    /// [`Groups::requests`](crate::endpoint::groups::Groups::requests),
    /// [`Registries::create`](crate::endpoint::registries::Registries::create), and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn accept_registry(
        &self,
        group_name: &str,
        local_member: &str,
        registry: &str,
        proposal: &Said,
        timestamp: Timestamp,
    ) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(local_member).await?;
        let proposed = self.read_proposal(proposal, MultisigRoute::RegistryInception).await?;
        let ApiEmbed::RegistryInception(embed) = &proposed.proposed.message else {
            return Err(ClientError::NotARegistryProposal {
                found: "an embed that is not a registry inception",
            });
        };

        let members = self.members_of(&proposed, group_name).await?;
        let recipients = peers(&member, &members)?;

        let registries = self.client.registries();
        let (artifacts, body) = registries
            .build_registry(&CreateRegistryRequest {
                identifier: group_name.to_owned(),
                registry: registry.to_owned(),
                backing: backing_of(&embed.vcp),
                // The nonce that decides the identifier, read from what was proposed.
                nonce: Some(embed.vcp.nonce.clone()),
            })
            .await?;

        let built = artifacts.inception.identifier().qb64()?;
        if built != embed.vcp.registry {
            return Err(ClientError::ProposalMismatch {
                proposed: embed.vcp.registry.clone(),
                built,
            });
        }

        let created = registries.submit_registry(group_name, artifacts, &body).await?;
        let (submission, embeds) = registry_announcement(created)?;
        self.send_announcement(
            submission,
            &Announcement {
                group_name,
                local_member,
                route: REGISTRY_ROUTE,
                slot: REGISTRY_SLOT,
                signing: &members,
                rotation: &members,
                recipients: &recipients,
                timestamp,
            },
            REGISTRY_TOPIC,
            embeds,
        )
        .await
    }

    /// Proposes a credential for the group to issue.
    ///
    /// Three embeds travel: the credential, the transaction event recording its issuance, and the
    /// key event anchoring that. Only the last is signed — the other two are authorized by the
    /// anchor, which is why they carry no attachment.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::LocalMemberNotAParticipant`] when the local member is not among the
    /// members, [`ClientError::LonelyGroup`] when it is the only one, and whatever
    /// [`Credentials::issue`](crate::endpoint::credentials::Credentials::issue) and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn propose_issuance(&self, request: &GroupIssuanceRequest<'_>) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(request.local_member).await?;
        let recipients = peers(&member, request.members)?;

        let issued = self
            .client
            .credentials()
            .issue(request.group_name, request.credential.clone())
            .await?;
        let (submission, embeds) = issuance_announcement(issued)?;
        self.send_announcement(
            submission,
            &Announcement {
                group_name: request.group_name,
                local_member: request.local_member,
                route: ISSUANCE_ROUTE,
                slot: ISSUANCE_SLOT,
                signing: request.members,
                rotation: request.members,
                recipients: &recipients,
                timestamp: request.timestamp.clone(),
            },
            request.group_name,
            embeds,
        )
        .await
    }

    /// Joins an issuance another member proposed, issuing the credential it was shown.
    ///
    /// **The reference does not read the proposal here either.** `issueCredentialMultisig` waits
    /// for a `/multisig/iss` notification, discards its SAID, and issues from its own
    /// `CredentialData` — so two members handed different attributes issue different credentials.
    /// Here the credential is read out of the message and the SAID this member derives is compared
    /// with the one it was shown.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotAnIssuanceProposal`] when the message under `proposal` is not a
    /// credential issuance, [`ClientError::ProposalMismatch`] when this member derives a different
    /// credential (nothing is sent), and whatever
    /// [`Groups::requests`](crate::endpoint::groups::Groups::requests),
    /// [`Credentials::issue`](crate::endpoint::credentials::Credentials::issue), and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn accept_issuance(
        &self,
        group_name: &str,
        local_member: &str,
        credential: Credential,
        proposal: &Said,
        timestamp: Timestamp,
    ) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(local_member).await?;
        let proposed = self.read_proposal(proposal, MultisigRoute::Issuance).await?;
        let ApiEmbed::Issuance(embed) = &proposed.proposed.message else {
            return Err(ClientError::NotAnIssuanceProposal {
                found: "an embed that is not a credential issuance",
            });
        };

        let members = self.members_of(&proposed, group_name).await?;
        let recipients = peers(&member, &members)?;

        let credentials = self.client.credentials();
        let (artifacts, body) = credentials.build_issuance(group_name, credential).await?;

        let built = artifacts.credential.said().qb64()?;
        if built != embed.acdc.digest {
            return Err(ClientError::ProposalMismatch {
                proposed: embed.acdc.digest.clone(),
                built,
            });
        }

        let issued = credentials.submit_issuance(group_name, artifacts, &body).await?;
        let (submission, embeds) = issuance_announcement(issued)?;
        self.send_announcement(
            submission,
            &Announcement {
                group_name,
                local_member,
                route: ISSUANCE_ROUTE,
                slot: ISSUANCE_SLOT,
                signing: &members,
                rotation: &members,
                recipients: &recipients,
                timestamp,
            },
            group_name,
            embeds,
        )
        .await
    }

    /// Proposes revoking a credential the group issued.
    ///
    /// The revocation travels in [`REVOCATION_SLOT`], which is the slot its route names. **The
    /// reference sends it in `iss` instead** — the issuance slot — so a member narrowing through
    /// its own `assertMultisigRev` finds no `rev` at all.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::LocalMemberNotAParticipant`] when the local member is not among the
    /// members, [`ClientError::LonelyGroup`] when it is the only one, and whatever
    /// [`Credentials::revoke`](crate::endpoint::credentials::Credentials::revoke) and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn propose_revocation(&self, request: &GroupRevocationRequest<'_>) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(request.local_member).await?;
        let recipients = peers(&member, request.members)?;

        let revoked = self
            .client
            .credentials()
            .revoke(request.group_name, request.revocation.clone())
            .await?;
        let (submission, embeds) = revocation_announcement(revoked)?;
        self.send_announcement(
            submission,
            &Announcement {
                group_name: request.group_name,
                local_member: request.local_member,
                route: REVOCATION_ROUTE,
                slot: REVOCATION_SLOT,
                signing: request.members,
                rotation: request.members,
                recipients: &recipients,
                timestamp: request.timestamp.clone(),
            },
            request.group_name,
            embeds,
        )
        .await
    }

    /// Joins a revocation another member proposed, revoking the credential it was shown.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotARevocationProposal`] when the message under `proposal` is not a
    /// credential revocation, [`ClientError::ProposalMismatch`] when this member derives a
    /// different revocation (nothing is sent), and whatever
    /// [`Groups::requests`](crate::endpoint::groups::Groups::requests),
    /// [`Credentials::revoke`](crate::endpoint::credentials::Credentials::revoke), and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn accept_revocation(
        &self,
        group_name: &str,
        local_member: &str,
        revocation: RevocationEvent,
        proposal: &Said,
        timestamp: Timestamp,
    ) -> Result<GroupEvent, ClientError> {
        let member = self.local_member(local_member).await?;
        let proposed = self.read_proposal(proposal, MultisigRoute::Revocation).await?;
        let ApiEmbed::Revocation(embed) = &proposed.proposed.message else {
            return Err(ClientError::NotARevocationProposal {
                found: "an embed that is not a credential revocation",
            });
        };

        let members = self.members_of(&proposed, group_name).await?;
        let recipients = peers(&member, &members)?;

        let credentials = self.client.credentials();
        let (artifacts, body) = credentials.build_revocation(group_name, revocation).await?;

        let built = artifacts.revocation.said().qb64()?;
        if built != embed.rev.digest() {
            return Err(ClientError::ProposalMismatch {
                proposed: embed.rev.digest().to_owned(),
                built,
            });
        }

        let revoked = credentials.submit_revocation(group_name, artifacts, &body).await?;
        let (submission, embeds) = revocation_announcement(revoked)?;
        self.send_announcement(
            submission,
            &Announcement {
                group_name,
                local_member,
                route: REVOCATION_ROUTE,
                slot: REVOCATION_SLOT,
                signing: &members,
                rotation: &members,
                recipients: &recipients,
                timestamp,
            },
            group_name,
            embeds,
        )
        .await
    }

    /// The members a proposal is agreed by.
    ///
    /// A proposal this port sent names them in `smids`. One the reference sent names only the
    /// group — it writes `{ gid }` and nothing else on every route but inception, rotation, and
    /// interaction — so when the message names nobody the members are read from the agent's own
    /// listing of them, which is also where the reference reads them: `multisigIssue` and
    /// `multisigRevoke` in `test-integration/multisig.test.ts` call `identifiers().members` and
    /// take `signing[].aid`.
    ///
    /// The group's *record* is not a source. Its `keys` are the members' current signing keys,
    /// not their identifiers, and reading them as prefixes finds nobody — which is how a joining
    /// member once answered every grant with [`ClientError::LocalMemberNotAParticipant`].
    async fn members_of(
        &self,
        proposed: &MultisigProposal,
        group_name: &str,
    ) -> Result<Vec<IdentifierPrefix>, ClientError> {
        let named = proposed.attributes.signing_members.clone().unwrap_or_default();
        if named.is_empty() {
            self.recorded_members(group_name).await
        } else {
            Ok(named)
        }
    }

    /// The members the agent lists for a group, in its signing order.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoRecordedMembers`] when the agent lists no signing member,
    /// [`ClientError::Identifier`] when a listed member is not a qualified prefix, and whatever
    /// [`Identifiers::members`](crate::endpoint::identifiers::Identifiers::members) returns.
    async fn recorded_members(&self, group_name: &str) -> Result<Vec<IdentifierPrefix>, ClientError> {
        let listing = self.client.identifiers().members(group_name).await?;
        signing_prefixes(group_name, &listing)
    }

    /// Announces an event this member submitted to the peers that must match it.
    ///
    /// The route and the embed slot arrive together and always agree, which is the whole of what
    /// this port does differently from the reference's rotation round.
    async fn announce(
        &self,
        submission: Submission<IdentifierArtifact>,
        announcement: &Announcement<'_>,
    ) -> Result<GroupEvent, ClientError> {
        let embed = signed_embed(announcement.slot, submission.artifact())?;
        self.send_announcement(submission, announcement, announcement.group_name, vec![embed])
            .await
    }

    /// Writes the attribute block, addresses the message, and sends it.
    ///
    /// `topic` is a separate argument because a registry proposal is filed under `registry` and
    /// every other round under the group's own alias — the reference's own inconsistency, kept.
    async fn send_announcement(
        &self,
        submission: Submission<IdentifierArtifact>,
        announcement: &Announcement<'_>,
        topic: &str,
        embeds: Vec<ExchangeEmbed>,
    ) -> Result<GroupEvent, ClientError> {
        let Announcement {
            group_name: _,
            local_member,
            route,
            slot: _,
            signing,
            rotation,
            recipients,
            timestamp,
        } = announcement;
        let group = submission.artifact().event.identifier().clone();

        let payload = group_payload(&group.qb64()?, signing, rotation)?;

        let addressee = recipients.first().ok_or(ClientError::LonelyGroup)?.clone();
        let draft = ExchangeDraft::new(*route, addressee, (*timestamp).clone())
            .payload(payload)
            .embeds(embeds);

        let announced = self
            .client
            .exchanges()
            .send(local_member, topic, &draft, recipients)
            .await?;

        Ok(GroupEvent {
            submission,
            announcement: announced,
            signing_members: signing.to_vec(),
            rotation_members: rotation.to_vec(),
        })
    }

    /// Creates the group event and proposes it — the half both workflows share.
    async fn submit(&self, proposal: &Proposed<'_>) -> Result<GroupInception, ClientError> {
        let Proposed {
            group_name,
            local_member,
            creation,
            signing,
            rotation,
            recipients,
            timestamp,
        } = proposal;
        let submission = self.client.identifiers().create(group_name, creation).await?;
        let group = submission.artifact().event.identifier().clone();

        let embed = signed_embed(INCEPTION_SLOT, submission.artifact())?;

        let payload = group_payload(&group.qb64()?, signing, rotation)?;

        let addressee = recipients.first().ok_or(ClientError::LonelyGroup)?.clone();
        let draft = ExchangeDraft::new(INCEPTION_ROUTE, addressee, timestamp.clone())
            .payload(payload)
            .embeds(vec![embed]);

        // The topic is the group's local alias, which is what the reference passes.
        let proposal = self
            .client
            .exchanges()
            .send(local_member, group_name, &draft, recipients)
            .await?;

        Ok(GroupInception {
            group,
            creation: submission,
            proposal,
            signing_members: signing.to_vec(),
            rotation_members: rotation.to_vec(),
        })
    }

    /// Reads the local member's identifier record, which must be a fully accepted one.
    async fn local_member(&self, alias: &str) -> Result<AcceptedHab, ClientError> {
        match self.client.identifiers().get_any(alias).await? {
            Hab::Accepted(record) => Ok(record),
            Hab::Pending(_) => Err(ClientError::IdentifierNotAccepted { name: alias.to_owned() }),
        }
    }

    /// Reads one key state per member, in order.
    ///
    /// The reference takes `states[0]` without checking there is one; an agent that knows nothing
    /// about a participant hands it `undefined`, which reaches the group's key list.
    async fn key_states(&self, members: &[IdentifierPrefix]) -> Result<Vec<KeyState>, ClientError> {
        let mut states = Vec::with_capacity(members.len());
        for member in members {
            let answered = self.client.key_states().get(member).await?;
            let state = answered
                .into_iter()
                .next()
                .ok_or_else(|| ClientError::UnknownGroupMember {
                    member: member.qb64().unwrap_or_default(),
                })?;
            states.push(state);
        }
        Ok(states)
    }

    /// Reads one group request and requires it to be a proposal on `expected`.
    ///
    /// The route decides which error a mismatch raises, so a caller learns which round it was
    /// handed rather than that it was handed the wrong one.
    async fn read_proposal(&self, said: &Said, expected: MultisigRoute) -> Result<MultisigProposal, ClientError> {
        let (proposal, _) = self.read_proposal_and_embeds(said, expected).await?;
        Ok(proposal)
    }

    /// [`Self::read_proposal`], together with the proposal's embed block as it was written.
    ///
    /// The typed proposal is what the round reasons about; the embed block is what a member
    /// re-anchors. The second is kept as a [`Sad`] because the agent's JSON decode sorts object
    /// keys, and a seal re-anchored in a different field order is a different event — one the
    /// proposer never built and the digest comparison would rightly refuse.
    async fn read_proposal_and_embeds(
        &self,
        said: &Said,
        expected: MultisigRoute,
    ) -> Result<(MultisigProposal, Sad), ClientError> {
        let wrong = |found: &'static str| match expected {
            MultisigRoute::Rotation => ClientError::NotARotationProposal { found },
            MultisigRoute::Interaction => ClientError::NotAnInteractionProposal { found },
            MultisigRoute::Reply => ClientError::NotAnEndRoleProposal { found },
            _ => ClientError::NotAnInceptionProposal { found },
        };
        let body = self.client.groups().requests_body(said).await?;
        let listing: Vec<MultisigExchangeResource> = decode_json(&body)?;
        let first = listing.first().ok_or_else(|| wrong("an empty listing"))?;
        let classified = ClassifiedExchange::try_from(first)?;
        let proposal = classified
            .as_multisig()
            .ok_or_else(|| wrong("a message on another route"))?;
        if proposal.route != expected {
            return Err(wrong(proposal.route.as_str()));
        }
        let embeds = first_embed_block(&body).ok_or_else(|| wrong("a message embedding nothing"))?;
        Ok((proposal.clone(), embeds))
    }
}

/// The `e` block of a request listing's first message, in the field order the agent wrote.
///
/// `Sad` parses objects, so the listing — a JSON array — is read as the one field of an object
/// wrapped around it.
fn first_embed_block(listing: &[u8]) -> Option<Sad> {
    let mut wrapped = Vec::with_capacity(listing.len().saturating_add(7));
    wrapped.extend_from_slice(br#"{"l":"#);
    wrapped.extend_from_slice(listing);
    wrapped.push(b'}');
    let wrapped = Sad::from_json_bytes(&wrapped).ok()?;
    let SadValue::Array(entries) = wrapped.get("l")? else {
        return None;
    };
    let SadValue::Map(first) = entries.first()? else {
        return None;
    };
    let SadValue::Map(exchange) = first.get("exn")? else {
        return None;
    };
    match exchange.get("e")? {
        SadValue::Map(embeds) => Some(embeds.clone()),
        _ => None,
    }
}

/// What both halves hand to [`Multisig::submit`]: an event to create and who to tell about it.
///
/// The two halves differ only in where these come from — the caller's request when proposing, the
/// message when joining — so the second half of the workflow is written once.
struct Proposed<'a> {
    group_name: &'a str,
    local_member: &'a str,
    creation: &'a CreateIdentifierRequest,
    signing: &'a [IdentifierPrefix],
    rotation: &'a [IdentifierPrefix],
    recipients: &'a [IdentifierPrefix],
    timestamp: Timestamp,
}

/// The route a group registry inception is proposed on.
pub const REGISTRY_ROUTE: &str = "/multisig/vcp";

/// The embed slot a group registry proposal carries its registry inception in.
pub const REGISTRY_SLOT: &str = "vcp";

/// The route a group credential issuance is proposed on.
pub const ISSUANCE_ROUTE: &str = "/multisig/iss";

/// The embed slot a group issuance proposal carries the credential in.
///
/// Not `iss`, which the route is named for: an issuance embed carries three messages and the
/// credential's slot is what the shared embed union is discriminated by.
pub const ISSUANCE_SLOT: &str = "acdc";

/// The embed slot a group issuance proposal carries the transaction event in.
pub const TRANSACTION_SLOT: &str = "iss";

/// The route a group credential revocation is proposed on.
pub const REVOCATION_ROUTE: &str = "/multisig/rev";

/// The embed slot a group revocation proposal carries the revocation in.
///
/// **The reference sends its revocation under [`TRANSACTION_SLOT`] instead**, so its own
/// `assertMultisigRev` would find no `rev` at all.
pub const REVOCATION_SLOT: &str = "rev";

/// The embed slot every transaction-event proposal carries its anchoring key event in.
pub const ANCHOR_SLOT: &str = "anc";

/// The submission and embeds a registry proposal announces.
///
/// The registry inception travels **unsigned** — what authorizes it is the signature on the key
/// event that anchors it, which is the second embed and the one an operation completes on.
fn registry_announcement(
    created: CreatedRegistry,
) -> Result<(Submission<IdentifierArtifact>, Vec<ExchangeEmbed>), ClientError> {
    let response = created.response_body().to_vec();
    let inception = ExchangeEmbed::new(REGISTRY_SLOT, created.inception.serialized())?;
    let anchor = IdentifierArtifact {
        event: created.anchor,
        signatures: created.signatures,
    };
    let embeds = vec![inception, signed_embed(ANCHOR_SLOT, &anchor)?];
    Ok((Submission::from_parts(anchor, response), embeds))
}

/// The submission and embeds an issuance proposal announces: three messages, one signature.
fn issuance_announcement(
    issued: IssuedCredential,
) -> Result<(Submission<IdentifierArtifact>, Vec<ExchangeEmbed>), ClientError> {
    let response = issued.response_body().to_vec();
    let artifacts = issued.artifacts;
    let embeds = vec![
        ExchangeEmbed::new(ISSUANCE_SLOT, artifacts.credential.serialized())?,
        ExchangeEmbed::new(TRANSACTION_SLOT, artifacts.issuance.serialized())?,
        signed_embed(ANCHOR_SLOT, &artifacts.anchor)?,
    ];
    Ok((Submission::from_parts(artifacts.anchor, response), embeds))
}

/// The submission and embeds a revocation proposal announces.
fn revocation_announcement(
    revoked: RevokedCredential,
) -> Result<(Submission<IdentifierArtifact>, Vec<ExchangeEmbed>), ClientError> {
    let response = revoked.response_body().to_vec();
    let artifacts = revoked.artifacts;
    let embeds = vec![
        // The slot the route names. The reference sends this under `iss`.
        ExchangeEmbed::new(REVOCATION_SLOT, artifacts.revocation.serialized())?,
        signed_embed(ANCHOR_SLOT, &artifacts.anchor)?,
    ];
    Ok((Submission::from_parts(artifacts.anchor, response), embeds))
}

/// The signing members of an agent's group listing, in the order the agent lists them.
///
/// The listing is `GET /identifiers/{name}/members`, whose `signing[].aid` are the members'
/// identifiers — where the group *record*'s `keys` are their current signing keys, which look like
/// prefixes and are not. The local member stays in the list; [`delivery_list`] takes it out and
/// says so when it is missing.
///
/// # Errors
///
/// Returns [`ClientError::NoRecordedMembers`] when the listing names no signing member, and
/// [`ClientError::Identifier`] when one of them is not a qualified prefix.
fn signing_prefixes(group_name: &str, listing: &GroupMember) -> Result<Vec<IdentifierPrefix>, ClientError> {
    if listing.signing.is_empty() {
        return Err(ClientError::NoRecordedMembers {
            group: group_name.to_owned(),
        });
    }
    listing
        .signing
        .iter()
        .map(|member| Ok(IdentifierPrefix::from_qb64(&member.aid)?))
        .collect()
}

/// The attribute block every announcement here carries: the group, then who signs, then who may
/// rotate — `gid`, `smids`, `rmids`, in the reference's own order.
///
/// The reference writes the two member lists on inception, rotation, and interaction and the
/// group alone everywhere else. Here every round writes all three, so a joining member reads its
/// peers from the message it was shown rather than looking them up; a message that names nobody
/// is still read, see [`Multisig::members_of`].
fn group_payload(group: &str, signing: &[IdentifierPrefix], rotation: &[IdentifierPrefix]) -> Result<Sad, ClientError> {
    let mut payload = Sad::new();
    payload.insert(GROUP_LABEL, group.to_owned()).map_err(sad_error)?;
    payload
        .insert(SIGNING_MEMBERS_LABEL, text_array(qb64_all(signing)?))
        .map_err(sad_error)?;
    payload
        .insert(ROTATION_MEMBERS_LABEL, text_array(qb64_all(rotation)?))
        .map_err(sad_error)?;
    Ok(payload)
}

/// How a proposed registry is witnessed, read from the inception it proposes.
fn backing_of(inception: &RegistryInceptionRecord) -> RegistryBacking {
    if inception.backers.is_empty() {
        RegistryBacking::None
    } else {
        RegistryBacking::Backers {
            // Carried as text, because the reference validates none of them: its own vector commits
            // the string `'a backer'`.
            backers: inception.backers.clone(),
            // Written in hexadecimal, as every threshold on the wire is.
            threshold: u32::from_str_radix(&inception.backer_threshold, 16).unwrap_or(0),
        }
    }
}

/// One embed slot carrying an event with the signatures that authorize it.
///
/// Every announcement this module sends transposes a signed event this way; the multi-event rounds
/// — a registry inception and its anchor, a credential and its issuance and its anchor — carry
/// several, and the unsigned ones travel with no attachment because the anchor's signature is what
/// authorizes them.
fn signed_embed(slot: &str, artifact: &IdentifierArtifact) -> Result<ExchangeEmbed, ClientError> {
    let attachment = SignedMessageBuilder::new(artifact.event.serialized())
        .controller_signatures(indexed(&artifact.signatures)?)
        .build()
        .map_err(|source| ClientError::Attachment {
            source: Box::new(source),
        })?
        .attachments()
        .to_vec();
    Ok(ExchangeEmbed::new(slot, artifact.event.serialized())?.with_attachment(attachment)?)
}

/// What [`Multisig::announce`] needs beyond the submission itself.
///
/// The route and the embed slot travel together here, so a message announcing a rotation on the
/// interaction route — which is what both of the reference's joining members send — cannot be
/// built by mistake.
struct Announcement<'a> {
    group_name: &'a str,
    local_member: &'a str,
    route: &'static str,
    slot: &'static str,
    signing: &'a [IdentifierPrefix],
    rotation: &'a [IdentifierPrefix],
    recipients: &'a [IdentifierPrefix],
    timestamp: Timestamp,
}

/// The identifiers a list of key states names, in order.
fn prefixes_of(states: &[KeyState]) -> Result<Vec<IdentifierPrefix>, ClientError> {
    states
        .iter()
        .map(|state| Ok(IdentifierPrefix::from_qb64(&state.identifier)?))
        .collect()
}

/// The seals the interaction in an embed block anchors, read out of its `a` field as written.
///
/// The schema types that field `unknown` and the reference wraps a non-array in one, so a seal
/// list is what arrives and a single seal is what a caller may have sent. Both are read here; a
/// seal that is not an object is refused rather than dropped. The seals come from the block's own
/// bytes rather than from the typed decode, so each keeps the field order its proposer wrote — the
/// order its digest, and so the rebuilt event's, depends on.
fn anchors_of(embeds: &Sad) -> Result<Vec<Sad>, ClientError> {
    let Some(SadValue::Map(interaction)) = embeds.get("ixn") else {
        return Err(ClientError::NotAnInteractionProposal {
            found: "an embed that is not an interaction",
        });
    };
    let seals: Vec<&SadValue> = match interaction.get("a") {
        Some(SadValue::Array(seals)) => seals.iter().collect(),
        Some(single) => vec![single],
        None => Vec::new(),
    };
    seals
        .into_iter()
        .map(|seal| match seal {
            SadValue::Map(seal) => Ok(seal.clone()),
            _ => Err(sad_error(SadError::NotAnObject)),
        })
        .collect()
}

/// The digest an embedded rotation carries as its own SAID.
fn rotation_digest(event: &KeyEvent) -> Result<String, ClientError> {
    match event {
        KeyEvent::Rotation(record) => Ok(record.digest.clone()),
        KeyEvent::DelegatedRotation(record) => Ok(record.digest.clone()),
        _ => Err(ClientError::NotARotationProposal {
            found: "an embed that is not a rotation",
        }),
    }
}

/// The digest an embedded event carries as its own SAID.
fn digest_of(event: &KeyEvent) -> Result<String, ClientError> {
    match event {
        KeyEvent::Interaction(record) => Ok(record.digest.clone()),
        _ => Err(ClientError::NotAnInteractionProposal {
            found: "an embed that is not an interaction",
        }),
    }
}

/// The delivery list for a proposal: every participant but this member, in the order given.
///
/// The first of them is the addressee, so this decides both who the message names and who it
/// reaches. The reference filters the local member when *accepting* and not when proposing, so an
/// initiator there delivers its own proposal back to itself and — through the exchange submission's
/// delivery loop — addresses it to itself as well.
///
/// Public because a caller may reasonably want to know who a proposal will reach before sending
/// one, and because it is the whole of the difference described above.
///
/// ```
/// use signify_client::multisig::delivery_list;
/// use signify_client::protocol::prefix::IdentifierPrefix;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let members = ["ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK", "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p"]
///     .iter()
///     .map(|member| IdentifierPrefix::from_qb64(member))
///     .collect::<Result<Vec<_>, _>>()?;
/// let (local, peer) = (&members[0], &members[1]);
///
/// // The proposer's own message goes to the other member, and is addressed to it.
/// let peers = delivery_list(local, &members)?;
/// assert_eq!(peers, [peer.clone()]);
/// assert_eq!(peers.first(), Some(peer));
///
/// // A group of one has nobody to tell, where the reference sends to itself.
/// assert!(delivery_list(local, &[local.clone()]).is_err());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`ClientError::LocalMemberNotAParticipant`] when `local` is not among `participants`,
/// and [`ClientError::LonelyGroup`] when it is the only one — a group of one has nobody to tell.
pub fn delivery_list(
    local: &IdentifierPrefix,
    participants: &[IdentifierPrefix],
) -> Result<Vec<IdentifierPrefix>, ClientError> {
    if !participants.contains(local) {
        return Err(ClientError::LocalMemberNotAParticipant {
            member: local.qb64().unwrap_or_default(),
        });
    }
    let peers: Vec<IdentifierPrefix> = participants
        .iter()
        .filter(|participant| *participant != local)
        .cloned()
        .collect();
    if peers.is_empty() {
        return Err(ClientError::LonelyGroup);
    }
    Ok(peers)
}

/// [`delivery_list`] for a member record, whose prefix is text until it is read.
fn peers(member: &AcceptedHab, participants: &[IdentifierPrefix]) -> Result<Vec<IdentifierPrefix>, ClientError> {
    delivery_list(&IdentifierPrefix::from_qb64(&member.common.prefix)?, participants)
}

/// Encodes a member list for the wire.
fn qb64_all(members: &[IdentifierPrefix]) -> Result<Vec<String>, ClientError> {
    members
        .iter()
        .map(|member| Ok(member.qb64()?))
        .collect::<Result<Vec<String>, ClientError>>()
}

/// Demands the indexed signatures a group proposal must attach.
fn indexed(
    signatures: &signify_keys::manager::ManagedSignatures,
) -> Result<Vec<keri_cesr::crypto::signature::IndexedSignature>, ClientError> {
    match signatures {
        signify_keys::manager::ManagedSignatures::Indexed(indexed) if !indexed.is_empty() => Ok(indexed.clone()),
        _ => Err(ClientError::UnsignedGroupRequest),
    }
}

/// Reads the inception event out of a classified proposal.
fn inception_event(proposal: &MultisigProposal) -> Result<ProposedInception, ClientError> {
    let ApiEmbed::Inception(embed) = &proposal.proposed.message else {
        return Err(ClientError::NotAnInceptionProposal {
            found: "an embed that is not an inception",
        });
    };
    ProposedInception::read(&embed.icp)
}

/// The values a proposed inception commits to.
///
/// The group identifier is a digest over all of them, which is why a joining member takes every one
/// from the message rather than from its caller. The two inception ilks differ only in the trailing
/// delegator, so both read the same way here.
#[derive(Debug)]
struct ProposedInception {
    signing_threshold: SigningThreshold,
    next_threshold: SigningThreshold,
    witnesses: Vec<IdentifierPrefix>,
    witness_threshold: u32,
    delegator: Option<IdentifierPrefix>,
}

impl ProposedInception {
    /// Reads one inception or delegated inception.
    fn read(event: &KeyEvent) -> Result<Self, ClientError> {
        let (signing, next, witnesses, threshold, delegator) = match event {
            KeyEvent::Inception(record) => (
                &record.signing_threshold,
                &record.next_threshold,
                &record.witnesses,
                &record.witness_threshold,
                None,
            ),
            KeyEvent::DelegatedInception(record) => (
                &record.signing_threshold,
                &record.next_threshold,
                &record.witnesses,
                &record.witness_threshold,
                Some(record.delegator.as_str()),
            ),
            _ => {
                return Err(ClientError::NotAnInceptionProposal {
                    found: "an embed that is not an inception",
                });
            }
        };
        Ok(Self {
            signing_threshold: threshold_from(signing)?,
            next_threshold: threshold_from(next)?,
            witnesses: witnesses
                .iter()
                .map(|witness| Ok(IdentifierPrefix::from_qb64(witness)?))
                .collect::<Result<Vec<IdentifierPrefix>, ClientError>>()?,
            witness_threshold: witness_threshold(threshold)?,
            delegator: delegator
                .filter(|text| !text.is_empty())
                .map(IdentifierPrefix::from_qb64)
                .transpose()?,
        })
    }
}

/// Reads a witness threshold in the base the protocol writes it in.
///
/// **This is the divergence with the most consequence in this item.** The reference rebuilds the
/// accepted inception with `toad: parseInt(icp.bt)`, which is base ten. Below ten the two agree.
/// `"a"` parses to `NaN` and throws — loudly, at least. `"10"` is sixteen and parses to **ten**,
/// which throws nothing: the joining member builds a different event, derives a different group
/// identifier, and the two members wait for each other forever. The fixture records both, driven.
fn witness_threshold(text: &str) -> Result<u32, ClientError> {
    u32::from_str_radix(text, 16).map_err(|_| ClientError::UnrepresentableNumber)
}

/// Parses one threshold as the reference's own `sith` form spells it.
fn threshold_from(threshold: &Threshold) -> Result<SigningThreshold, ClientError> {
    let sith = match threshold {
        Threshold::Simple(text) => text.clone(),
        Threshold::Clause(weights) => serde_json::to_string(weights).map_err(|_| ClientError::UnrepresentableNumber)?,
        Threshold::Clauses(clauses) => {
            serde_json::to_string(clauses).map_err(|_| ClientError::UnrepresentableNumber)?
        }
    };
    SigningThreshold::from_sith(&sith).map_err(|_| ClientError::UnrepresentableNumber)
}

/// The route a group end-role authorization is proposed on.
pub const REPLY_ROUTE: &str = "/multisig/rpy";

/// The embed slot carrying the end-role reply.
pub const REPLY_SLOT: &str = "rpy";

/// One group member's agent, as the group's members listing names it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberAgent {
    /// The member.
    pub member: IdentifierPrefix,
    /// The agent that member authorizes, which the group will authorize too.
    pub agent: IdentifierPrefix,
}

/// Reads each signing member's agent out of a group's members listing, in the listing's order.
///
/// The reference takes `Object.keys(signing.ends.agent)[0]` — the first agent a member authorizes,
/// in the order the agent wrote them. Here the listing is decoded into an ordered map, so a member
/// authorizing several agents yields the lowest prefix. The two agree: the agent builds the listing
/// from a database cursor that walks agents in byte order, so the first written is the lowest. A
/// member has one agent in every deployment observed.
///
/// # Errors
///
/// Returns [`ClientError::MemberHasNoAgent`] when a signing member authorizes no agent — where the
/// reference throws part way through its loop, after authorizing the members before it — and
/// [`ClientError::Identifier`] when a member or an agent is not a qualified prefix.
pub fn member_agents(listing: &GroupMember) -> Result<Vec<MemberAgent>, ClientError> {
    listing
        .signing
        .iter()
        .map(|record| {
            let agent = record
                .ends
                .agent
                .as_ref()
                .and_then(|agents| agents.keys().next())
                .ok_or_else(|| ClientError::MemberHasNoAgent {
                    member: record.aid.clone(),
                })?;
            Ok(MemberAgent {
                member: IdentifierPrefix::from_qb64(&record.aid)?,
                agent: IdentifierPrefix::from_qb64(agent)?,
            })
        })
        .collect()
}

/// The end role a proposal asks the group to authorize, read out of its embedded reply.
#[derive(Clone, Debug, PartialEq)]
pub struct ProposedEndRole {
    /// The role, wire label `a.role`.
    pub role: Role,
    /// The endpoint authorized for it, wire label `a.eid`.
    pub endpoint: IdentifierPrefix,
    /// The reply's own timestamp, wire label `dt`: every member must sign the same one.
    pub stamp: Timestamp,
    /// The reply's SAID, which the rebuilt reply must reproduce.
    pub said: Said,
}

/// Reads what a proposed end-role reply authorizes, requiring it to be for `group`.
///
/// Everything that decides the reply's SAID — the route, the controller, the role, the endpoint,
/// and the stamp — is read and checked, so a joining member can rebuild the same reply rather than
/// one from its own arguments.
///
/// # Errors
///
/// Returns [`ClientError::NotAnEndRoleProposal`] when the reply is on another route, names another
/// controller, or carries no usable role or endpoint, [`ClientError::Timestamp`] when its stamp is
/// not a KERI timestamp, [`ClientError::Identifier`] when a prefix is not qualified, and
/// [`ClientError::Said`] when the reply's digest is not one.
pub fn proposed_end_role(group: &IdentifierPrefix, reply: &ReplyRecord) -> Result<ProposedEndRole, ClientError> {
    if reply.route != END_ROLE_ROUTE {
        return Err(ClientError::NotAnEndRoleProposal {
            found: "a reply on another route",
        });
    }
    let attribute = |label: &str| reply.attributes.get(label).and_then(serde_json::Value::as_str);
    let controller = attribute("cid").ok_or(ClientError::NotAnEndRoleProposal {
        found: "a reply naming no controller",
    })?;
    if IdentifierPrefix::from_qb64(controller)? != *group {
        return Err(ClientError::NotAnEndRoleProposal {
            found: "a reply for another controller",
        });
    }
    let role = attribute("role")
        .filter(|role| !role.is_empty())
        .ok_or(ClientError::NotAnEndRoleProposal {
            found: "a reply naming no role",
        })?;
    let endpoint = attribute("eid").ok_or(ClientError::NotAnEndRoleProposal {
        found: "a reply naming no endpoint",
    })?;
    Ok(ProposedEndRole {
        role: Role::from(role),
        endpoint: IdentifierPrefix::from_qb64(endpoint)?,
        stamp: reply.stamp.parse::<Timestamp>()?,
        said: Said::from_qb64(&reply.digest)?,
    })
}

/// What a group's agent end-role round commits to.
#[derive(Debug)]
pub struct GroupEndRoleRequest<'a> {
    /// Local alias of the group.
    pub group_name: &'a str,
    /// Local alias of this member's own identifier.
    pub local_member: &'a str,
    /// The stamp every reply carries, and so every member signs.
    ///
    /// It decides the replies' SAIDs, so proposing again with the same stamp resubmits the same
    /// replies — the agent records each once and notifies nobody twice — where a fresh stamp
    /// starts a second set that the first does not count toward. It also starts the agent's
    /// one-hour escrow clock: the other members must sign within an hour of it.
    pub timestamp: Timestamp,
}

/// One member's half of one end-role authorization: the reply it submitted and the announcement.
#[derive(Debug)]
pub struct GroupReply {
    submission: Submission<SignedReply>,
    announcement: SentExchange,
    signing_members: Vec<IdentifierPrefix>,
    end_role: ProposedEndRole,
}

impl GroupReply {
    /// Returns what the reply authorizes: the role, the endpoint, the stamp, and the SAID.
    ///
    /// A caller keeping one pending operation per agent correlates them by the endpoint here.
    #[must_use]
    pub const fn end_role(&self) -> &ProposedEndRole {
        &self.end_role
    }

    /// Returns the signed reply the agent was asked to record, with its long-running operation.
    #[must_use]
    pub const fn submission(&self) -> &Submission<SignedReply> {
        &self.submission
    }

    /// Returns the agent's answer to the announcement.
    #[must_use]
    pub const fn announcement(&self) -> &SentExchange {
        &self.announcement
    }

    /// Returns the members that sign for the group.
    #[must_use]
    pub fn signing_members(&self) -> &[IdentifierPrefix] {
        &self.signing_members
    }

    /// Returns the SAID of the reply, which every member's is.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.end_role.said
    }
}

impl Multisig<'_> {
    /// Proposes authorizing every signing member's agent as the group's agent.
    ///
    /// One end-role reply per member's agent, each announced to the other members on
    /// [`REPLY_ROUTE`]. Until this round completes, nothing addressed to the group reaches any
    /// member's agent but the sender's. The replies come back in the members listing's order, each
    /// naming the agent it authorizes under [`GroupReply::end_role`].
    ///
    /// The replies are submitted and announced one agent at a time, so a failure part way through
    /// leaves the agents before it proposed and the error carries nothing about them. Proposing
    /// again with the same [`GroupEndRoleRequest::timestamp`] resubmits those replies unchanged and
    /// continues; a fresh stamp starts the round over.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoRecordedMembers`] when the agent lists no signing member,
    /// [`ClientError::MemberHasNoAgent`] when one authorizes no agent — before anything is
    /// submitted — [`ClientError::LocalMemberNotAParticipant`] and [`ClientError::LonelyGroup`] for
    /// an unusable membership, and whatever
    /// [`Identifiers::add_end_role`](crate::endpoint::identifiers::Identifiers::add_end_role) and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn propose_agent_end_roles(
        &self,
        request: &GroupEndRoleRequest<'_>,
    ) -> Result<Vec<GroupReply>, ClientError> {
        let member = self.local_member(request.local_member).await?;
        let listing = self.client.identifiers().members(request.group_name).await?;
        let members = signing_prefixes(request.group_name, &listing)?;
        let recipients = peers(&member, &members)?;
        // Read whole before anything is submitted, so a member without an agent refuses the round
        // rather than leaving it half done.
        let agents = member_agents(&listing)?;

        let mut replies = Vec::with_capacity(agents.len());
        for agent in &agents {
            let submission = self
                .client
                .identifiers()
                .add_end_role(
                    request.group_name,
                    &Role::Agent,
                    Some(&agent.agent),
                    request.timestamp.clone(),
                )
                .await?;
            let end_role = ProposedEndRole {
                role: Role::Agent,
                endpoint: agent.agent.clone(),
                stamp: request.timestamp.clone(),
                said: submission.artifact().reply.said(),
            };
            replies.push(
                self.announce_reply(
                    request.group_name,
                    request.local_member,
                    submission,
                    &members,
                    &recipients,
                    end_role,
                )
                .await?,
            );
        }
        Ok(replies)
    }

    /// Joins one end-role authorization another member proposed.
    ///
    /// The stamp, the role, and the endpoint are read out of the proposal's reply, and the reply this
    /// member builds is compared with the one it was shown. A proposing member sends one proposal per
    /// agent, so a joining member accepts each — one call per `/multisig/rpy` notification, with the
    /// SAID the notification names.
    ///
    /// The comparison proves the proposal is the reply it claims to be, not that this member wants
    /// it: whatever role and endpoint the proposal names are signed. The agent refuses a role it
    /// does not know, but a known role other than `agent` is authorized as proposed. A caller with
    /// a policy reads the proposal first, through
    /// [`Groups::requests`](crate::endpoint::groups::Groups::requests) and [`proposed_end_role`].
    ///
    /// The announcement is stamped with the reply's stamp rather than the clock, so accepting the
    /// same proposal twice sends the same announcement twice, which the agent records once.
    ///
    /// **Upstream the reference's helper reads nothing.** `addEndRoleMultisig` waits for as many
    /// `/multisig/rpy` notifications as there are signing members, discards them, and builds from
    /// its own `timestamp` argument; two members stamping differently sign different replies and
    /// nothing says so. A wallet built on the reference does read the stamp, the role, and the
    /// endpoint out of the proposal, as this does, without comparing what it rebuilds.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotAnEndRoleProposal`] when the message under `proposal` is not a
    /// proposed end-role reply for this group, [`ClientError::ProposalMismatch`] when this member
    /// derives a different reply, and whatever
    /// [`Groups::requests`](crate::endpoint::groups::Groups::requests),
    /// [`Identifiers::add_end_role`](crate::endpoint::identifiers::Identifiers::add_end_role), and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn accept_end_role(
        &self,
        group_name: &str,
        local_member: &str,
        proposal: &Said,
    ) -> Result<GroupReply, ClientError> {
        let member = self.local_member(local_member).await?;
        let proposed = self.read_proposal(proposal, MultisigRoute::Reply).await?;
        let ApiEmbed::Reply(embed) = &proposed.proposed.message else {
            return Err(ClientError::NotAnEndRoleProposal {
                found: "an embed that is not a reply",
            });
        };
        let group = self.client.identifiers().get(group_name).await?;
        let group_prefix = IdentifierPrefix::from_qb64(&group.common.prefix)?;
        let end_role = proposed_end_role(&group_prefix, &embed.rpy)?;

        // Rebuilt and compared before anything is signed or sent: a reply is pure, so a proposal
        // this member would not sign costs nothing but the reads above.
        let rebuilt = end_role_reply(
            &group_prefix,
            &end_role.role,
            Some(&end_role.endpoint),
            end_role.stamp.clone(),
        )?;
        if rebuilt.said() != end_role.said {
            return Err(ClientError::ProposalMismatch {
                proposed: end_role.said.qb64()?,
                built: rebuilt.said().qb64()?,
            });
        }

        let members = self.members_of(&proposed, group_name).await?;
        let recipients = peers(&member, &members)?;

        let submission = self
            .client
            .identifiers()
            .add_end_role(
                group_name,
                &end_role.role,
                Some(&end_role.endpoint),
                end_role.stamp.clone(),
            )
            .await?;

        self.announce_reply(group_name, local_member, submission, &members, &recipients, end_role)
            .await
    }

    /// Announces one signed end-role reply to the group's other members.
    ///
    /// The reply is sealed to the group's latest establishment event as the agent reports it now,
    /// where the reference seals to the state its caller passed in — stale once the group rotates.
    /// The seal has to match: a receiving agent merges signatures only under one seal, its own
    /// latest establishment event, and drops a reply sealed to an older one.
    async fn announce_reply(
        &self,
        group_name: &str,
        local_member: &str,
        submission: Submission<SignedReply>,
        members: &[IdentifierPrefix],
        recipients: &[IdentifierPrefix],
        end_role: ProposedEndRole,
    ) -> Result<GroupReply, ClientError> {
        let record = self.client.identifiers().get(group_name).await?;
        let establishment = &record.state.latest_establishment_event;
        let reply = &submission.artifact().reply;

        let attachment = SignedMessageBuilder::new(reply.serialized())
            .controller_signatures(indexed(&submission.artifact().signatures)?)
            .seal(SignatureSeal::Event {
                identifier: IdentifierPrefix::from_qb64(&record.common.prefix)?,
                sequence_number: SequenceNumber::from_hex(&establishment.sequence_number)?,
                said: Said::from_qb64(&establishment.digest)?,
            })
            .build()
            .map_err(|source| ClientError::Attachment {
                source: Box::new(source),
            })?
            .attachments()
            .to_vec();
        let embed = ExchangeEmbed::new(REPLY_SLOT, reply.serialized())?.with_attachment(attachment)?;

        let payload = group_payload(&record.common.prefix, members, members)?;
        let addressee = recipients.first().ok_or(ClientError::LonelyGroup)?.clone();
        let draft = ExchangeDraft::new(REPLY_ROUTE, addressee, end_role.stamp.clone())
            .payload(payload)
            .embeds(vec![embed]);
        // The topic is the group's local alias, which is what the reference passes.
        let announcement = self
            .client
            .exchanges()
            .send(local_member, group_name, &draft, recipients)
            .await?;

        Ok(GroupReply {
            submission,
            announcement,
            signing_members: members.to_vec(),
            end_role,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
    const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
    const THIRD: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";

    fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
        Ok(IdentifierPrefix::from_qb64(text)?)
    }

    /// A grant a group is acknowledging.
    const GRANT: &str = "EL7y8q-Cc2MO8s4aiJX5MC05m2BTIYvoX5lgUhFo5ZYF";

    /// One proposed IPEX step, as the embedded `exn` of a `/multisig/exn` proposal.
    fn embedded_step(route: &str, prior: &str, stamp: &str) -> Result<ExchangeRecord, Box<dyn Error>> {
        let document = format!(
            r#"{{"v":"KERI10JSON000100_","t":"exn","d":"EADMIT","i":"EGRP","rp":"{PEER}","p":"{prior}","dt":"{stamp}","r":"{route}","q":{{}},"a":{{"m":"a note"}},"e":{{}}}}"#
        );
        Ok(serde_json::from_str(&document)?)
    }

    #[test]
    fn a_joining_member_reads_the_stamp_out_of_the_proposal() -> Result<(), Box<dyn Error>> {
        let stamp = "2023-11-14T22:13:20.123000+00:00";
        let proposed = embedded_step(IpexRoute::Admit.as_str(), GRANT, stamp)?;
        let step = proposed_step(&proposed, IpexRoute::Admit)?;

        // Everything that decides the message's SAID comes from the proposal, not from an
        // argument — which is the whole of what the reference's shared `timestamp` parameter
        // leaves to its caller.
        assert_eq!(step.timestamp.to_string(), stamp);
        assert_eq!(step.recipient.qb64()?, PEER);
        assert_eq!(step.message, "a note");
        assert_eq!(step.prior.map(|said| said.qb64()).transpose()?, Some(GRANT.to_owned()));
        Ok(())
    }

    #[test]
    fn a_proposal_on_another_step_is_refused() -> Result<(), Box<dyn Error>> {
        let proposed = embedded_step(IpexRoute::Grant.as_str(), "", "2023-11-14T22:13:20.123000+00:00")?;
        let refused = matches!(
            proposed_step(&proposed, IpexRoute::Admit),
            Err(ClientError::WrongDisclosureStep { .. })
        );
        assert!(refused, "a grant was accepted as a proposed admit");
        Ok(())
    }

    #[test]
    fn a_proposal_addressed_to_nobody_is_refused() -> Result<(), Box<dyn Error>> {
        let document = r#"{"v":"KERI10JSON000100_","t":"exn","d":"EADMIT","i":"EGRP","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"/ipex/admit","q":{},"a":{"m":""},"e":{}}"#;
        let proposed: ExchangeRecord = serde_json::from_str(document)?;
        let refused = matches!(
            proposed_step(&proposed, IpexRoute::Admit),
            Err(ClientError::WrongDisclosureStep { .. })
        );
        assert!(refused, "a step addressed to nobody was accepted");
        Ok(())
    }

    #[test]
    fn a_proposed_step_with_no_prior_answers_nothing() -> Result<(), Box<dyn Error>> {
        let proposed = embedded_step(IpexRoute::Grant.as_str(), "", "2023-11-14T22:13:20.123000+00:00")?;
        let step = proposed_step(&proposed, IpexRoute::Grant)?;
        // An issuer's grant opens the exchange, so it names no predecessor — and the empty string
        // reads as "answers nothing" rather than as a SAID.
        assert!(step.prior.is_none());
        Ok(())
    }

    #[test]
    fn the_exchange_route_and_slot_are_the_ones_the_reference_sends() {
        assert_eq!(EXCHANGE_ROUTE, "/multisig/exn");
        assert_eq!(EXCHANGE_SLOT, "exn");
        assert_eq!(EXCHANGE_ROUTE, MultisigRoute::Exchange.as_str());
    }

    /// One inception event, used where a test needs an embed that is not an interaction.
    const INCEPTION_EVENT: &str = r#"{"v":"KERI10JSON000_","t":"icp","d":"EICP","i":"EGRP","s":"0","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":"0","b":[],"c":[],"a":[]}"#;

    /// One registry inception, exactly as an embed carries it.
    fn registry_inception(backers: &str, threshold: &str) -> Result<RegistryInceptionRecord, Box<dyn Error>> {
        let document = format!(
            r#"{{"v":"KERI10JSON000_","t":"vcp","d":"EVCP","i":"EVCP","ii":"EGRP","s":"0","c":[],"bt":"{threshold}","b":{backers},"n":"AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s"}}"#
        );
        Ok(serde_json::from_str(&document)?)
    }

    /// One interaction event anchoring `anchors`, exactly as an embed carries it.
    fn interaction(anchors: &str) -> Result<KeyEvent, Box<dyn Error>> {
        let document = format!(
            r#"{{"v":"KERI10JSON000_","t":"ixn","d":"EIXNDIGEST","i":"EGRP","s":"1","p":"EICP","a":{anchors}}}"#
        );
        Ok(serde_json::from_str(&document)?)
    }

    /// The embed block of an interaction proposal anchoring `anchors`, in the order it was written.
    fn interaction_embeds(anchors: &str) -> Result<Sad, Box<dyn Error>> {
        let block = format!(
            r#"{{"ixn":{{"v":"KERI10JSON000_","t":"ixn","d":"EIXNDIGEST","i":"EGRP","s":"1","p":"EICP","a":{anchors}}}}}"#
        );
        Ok(Sad::from_json_bytes(block.as_bytes())?)
    }

    /// One key state naming `prefix_text`, of the shape `/states` answers with.
    fn state(prefix_text: &str) -> Result<KeyState, Box<dyn Error>> {
        let document = format!(
            r#"{{"vn":[1,0],"i":"{prefix_text}","s":"0","p":"","d":"{prefix_text}","f":"0","dt":"2023-08-21T22:30:46.473545+00:00","et":"icp","kt":"1","k":["DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9"],"nt":"1","n":["EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{prefix_text}","br":[],"ba":[]}},"di":""}}"#
        );
        Ok(serde_json::from_str(&document)?)
    }

    fn record(prefix_text: &str) -> Result<AcceptedHab, Box<dyn Error>> {
        let document = format!(
            r#"{{"name":"member1","prefix":"{prefix_text}","transferable":true,"windexes":[],"icp_dt":"2023-08-21T22:30:46.473545+00:00","salty":{{"sxlt":"1AAH","pidx":0,"kidx":0,"stem":"signify:aid","tier":"low","dcode":"E","icodes":["A"],"ncodes":["A"],"transferable":true}},"state":{{"vn":[1,0],"i":"{prefix_text}","s":"0","p":"","d":"{prefix_text}","f":"0","dt":"2023-08-21T22:30:46.473545+00:00","et":"icp","kt":"1","k":["DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9"],"nt":"1","n":["EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{prefix_text}","br":[],"ba":[]}},"di":""}}}}"#
        );
        Ok(serde_json::from_str(&document)?)
    }

    #[test]
    fn the_route_constants_are_the_references_own() {
        assert_eq!(INCEPTION_ROUTE, "/multisig/icp");
        assert_eq!(INCEPTION_SLOT, "icp");
        assert_eq!(ROTATION_ROUTE, "/multisig/rot");
        assert_eq!(ROTATION_SLOT, "rot");
        assert_eq!(INTERACTION_ROUTE, "/multisig/ixn");
        assert_eq!(INTERACTION_SLOT, "ixn");
        assert_eq!(REPLY_ROUTE, "/multisig/rpy");
        assert_eq!(REPLY_SLOT, "rpy");
        // And each is the route the route table names.
        assert_eq!(MultisigRoute::Inception.as_str(), INCEPTION_ROUTE);
        assert_eq!(MultisigRoute::Rotation.as_str(), ROTATION_ROUTE);
        assert_eq!(MultisigRoute::Interaction.as_str(), INTERACTION_ROUTE);
        assert_eq!(MultisigRoute::Reply.as_str(), REPLY_ROUTE);
    }

    /// Every route this module announces on names the slot it embeds.
    ///
    /// The reference's two joining members send a `rot` embed under `/multisig/ixn`; here the two
    /// arrive together in one value, so the pair cannot come apart.
    #[test]
    fn each_route_this_module_sends_names_its_own_embed() {
        for (route, slot) in [
            (INCEPTION_ROUTE, INCEPTION_SLOT),
            (ROTATION_ROUTE, ROTATION_SLOT),
            (INTERACTION_ROUTE, INTERACTION_SLOT),
            (REPLY_ROUTE, REPLY_SLOT),
        ] {
            assert_eq!(route.rsplit('/').next(), Some(slot), "{route} does not name {slot}");
        }
    }

    #[test]
    fn a_key_state_list_reads_its_identifiers_in_order() -> Result<(), Box<dyn Error>> {
        let states = [state(PEER)?, state(LOCAL)?, state(THIRD)?];
        assert_eq!(prefixes_of(&states)?, [prefix(PEER)?, prefix(LOCAL)?, prefix(THIRD)?]);
        // An empty list is empty rather than an error: whether a group may have no members is
        // the caller's question, and `peers` answers it.
        assert_eq!(prefixes_of(&[])?, [] as [IdentifierPrefix; 0]);
        Ok(())
    }

    #[test]
    fn a_key_state_that_is_not_a_prefix_is_refused() -> Result<(), Box<dyn Error>> {
        let mut broken = state(LOCAL)?;
        broken.identifier = "not-a-prefix".to_owned();
        let refused = matches!(prefixes_of(&[broken]), Err(ClientError::Identifier { .. }));
        assert!(refused, "a key state naming no identifier was accepted");
        Ok(())
    }

    #[test]
    fn an_interaction_reads_the_seals_it_was_shown() -> Result<(), Box<dyn Error>> {
        // The reference's own scenario anchors one seal, written as a bare object; `createInteract`
        // wraps a non-array, so both shapes reach the event and both are read here.
        let one = interaction_embeds(r#"[{"i":"EBgew7O4","s":"0","d":"EBgew7O4"}]"#)?;
        let anchors = anchors_of(&one)?;
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors.first().and_then(|seal| seal.get_text("i")), Some("EBgew7O4"));

        let bare = interaction_embeds(r#"{"i":"EBgew7O4","s":"0","d":"EBgew7O4"}"#)?;
        assert_eq!(anchors_of(&bare)?.len(), 1);

        let two = interaction_embeds(r#"[{"i":"EBgew7O4"},{"i":"EMQQpnSk"}]"#)?;
        assert_eq!(anchors_of(&two)?.len(), 2);
        Ok(())
    }

    #[test]
    fn a_seal_keeps_the_field_order_its_proposer_wrote() -> Result<(), Box<dyn Error>> {
        // KERIpy and signify-ts write a seal `i, s, d`; a decode through `serde_json::Value` would
        // hand back `d, i, s`, and a seal re-anchored in that order is a different event.
        let conventional = br#"{"i":"EBgew7O4","s":"0","d":"EBgew7O4"}"#;
        let embeds = interaction_embeds(r#"[{"i":"EBgew7O4","s":"0","d":"EBgew7O4"}]"#)?;
        let seals = anchors_of(&embeds)?;
        let written = seals.first().ok_or("no seal")?.to_json_bytes()?;
        assert_eq!(written, conventional);
        Ok(())
    }

    #[test]
    fn a_seal_that_is_not_an_object_is_refused_rather_than_dropped() -> Result<(), Box<dyn Error>> {
        let embeds = interaction_embeds(r#"["not a seal"]"#)?;
        let refused = anchors_of(&embeds).is_err();
        assert!(refused, "a seal that is not an object was accepted");
        Ok(())
    }

    #[test]
    fn an_embed_that_is_not_an_interaction_is_not_read_as_one() -> Result<(), Box<dyn Error>> {
        let embeds = Sad::from_json_bytes(format!(r#"{{"icp":{INCEPTION_EVENT}}}"#).as_bytes())?;
        let refused = matches!(anchors_of(&embeds), Err(ClientError::NotAnInteractionProposal { .. }));
        assert!(refused, "an inception was read for seals");
        let inception: KeyEvent = serde_json::from_str(INCEPTION_EVENT)?;
        let no_digest = matches!(digest_of(&inception), Err(ClientError::NotAnInteractionProposal { .. }));
        assert!(no_digest, "an inception answered for an interaction's digest");
        Ok(())
    }

    #[test]
    fn the_transaction_routes_and_slots_are_the_references_own() {
        assert_eq!(REGISTRY_ROUTE, "/multisig/vcp");
        assert_eq!(REGISTRY_SLOT, "vcp");
        assert_eq!(ISSUANCE_ROUTE, "/multisig/iss");
        assert_eq!(REVOCATION_ROUTE, "/multisig/rev");
        assert_eq!(REVOCATION_SLOT, "rev");
        assert_eq!(ANCHOR_SLOT, "anc");
        // And each is the route the route table names.
        assert_eq!(MultisigRoute::RegistryInception.as_str(), REGISTRY_ROUTE);
        assert_eq!(MultisigRoute::Issuance.as_str(), ISSUANCE_ROUTE);
        assert_eq!(MultisigRoute::Revocation.as_str(), REVOCATION_ROUTE);
    }

    /// An issuance is the one round whose route and embed slot are *not* the same word.
    #[test]
    fn an_issuance_is_named_for_its_transaction_and_embedded_by_its_credential() {
        // The route ends in `iss` and the embed's discriminating slot is `acdc`, because the shared
        // embed union is told apart by field names and an issuance carries three messages.
        assert_eq!(ISSUANCE_ROUTE.rsplit('/').next(), Some(TRANSACTION_SLOT));
        assert_eq!(ISSUANCE_SLOT, "acdc");
        assert_ne!(ISSUANCE_SLOT, TRANSACTION_SLOT);
        // The other two rounds are named for what they embed.
        assert_eq!(REGISTRY_ROUTE.rsplit('/').next(), Some(REGISTRY_SLOT));
        assert_eq!(REVOCATION_ROUTE.rsplit('/').next(), Some(REVOCATION_SLOT));
    }

    /// The reference sends a revocation under the issuance slot; this port does not.
    #[test]
    fn a_revocation_travels_in_the_slot_its_route_names() {
        assert_eq!(REVOCATION_SLOT, "rev");
        assert_ne!(REVOCATION_SLOT, TRANSACTION_SLOT);
        // `multisigRevoke` builds `{ iss: [rev, ''], anc: [...] }`, so a reader narrowing through
        // the reference's own `assertMultisigRev` finds no `rev` at all.
        assert_eq!(TRANSACTION_SLOT, "iss");
    }

    #[test]
    fn a_registry_backing_is_read_from_what_was_proposed() -> Result<(), Box<dyn Error>> {
        let unbacked = registry_inception("[]", "0")?;
        assert!(matches!(backing_of(&unbacked), RegistryBacking::None));

        let backed = registry_inception(r#"["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"]"#, "1")?;
        let RegistryBacking::Backers { backers, threshold } = backing_of(&backed) else {
            return Err("a backed registry read as unbacked".into());
        };
        assert_eq!(backers.len(), 1);
        assert_eq!(threshold, 1);
        Ok(())
    }

    #[test]
    fn a_backer_threshold_is_read_in_hexadecimal() -> Result<(), Box<dyn Error>> {
        // The same base every threshold on the wire is written in — the multisig inception's
        // finding, applied where it also applies.
        let backed = registry_inception(r#"["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"]"#, "a")?;
        let RegistryBacking::Backers { threshold, .. } = backing_of(&backed) else {
            return Err("a backed registry read as unbacked".into());
        };
        assert_eq!(threshold, 10, "the backer threshold was read in base ten");
        Ok(())
    }

    /// The agent's listing of a group's members, as `GET /identifiers/{name}/members` answers it.
    fn listing(signing: &[&str]) -> Result<GroupMember, Box<dyn Error>> {
        let entries: Vec<String> = signing
            .iter()
            .map(|aid| format!(r#"{{"aid":"{aid}","ends":{{}}}}"#))
            .collect();
        let document = format!(r#"{{"signing":[{}],"rotation":[]}}"#, entries.join(","));
        Ok(serde_json::from_str(&document)?)
    }

    #[test]
    fn signing_members_are_read_from_the_listing_in_order() -> Result<(), Box<dyn Error>> {
        // The listing's `aid` fields are the members' identifiers, in the agent's order, and the
        // local member stays in — `peers` is what takes it out.
        let members = signing_prefixes("board", &listing(&[LOCAL, PEER, THIRD])?)?;
        assert_eq!(members, [prefix(LOCAL)?, prefix(PEER)?, prefix(THIRD)?]);
        assert_eq!(peers(&record(PEER)?, &members)?, [prefix(LOCAL)?, prefix(THIRD)?]);
        Ok(())
    }

    #[test]
    fn a_groups_keys_are_not_its_members() -> Result<(), Box<dyn Error>> {
        // The defect this replaces: the group record's `keys` parse as prefixes and name nobody.
        let key = "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9";
        let as_prefix = prefix(key)?;
        assert_ne!(as_prefix, prefix(LOCAL)?);
        assert!(matches!(
            peers(&record(LOCAL)?, &[as_prefix]),
            Err(ClientError::LocalMemberNotAParticipant { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_listing_with_no_signing_member_is_refused() -> Result<(), Box<dyn Error>> {
        let refused = matches!(
            signing_prefixes("board", &listing(&[])?),
            Err(ClientError::NoRecordedMembers { group }) if group == "board"
        );
        assert!(refused, "an empty listing answered as a group");
        Ok(())
    }

    #[test]
    fn a_listing_naming_a_non_prefix_is_refused() -> Result<(), Box<dyn Error>> {
        let refused = matches!(
            signing_prefixes("board", &listing(&[LOCAL, "not-a-prefix"])?),
            Err(ClientError::Identifier { .. })
        );
        assert!(refused, "a malformed member was accepted");
        Ok(())
    }

    #[test]
    fn an_announcement_names_the_group_and_both_member_lists() -> Result<(), Box<dyn Error>> {
        // Every round's block, the IPEX rounds included — where the reference's grant and admit
        // helpers write `{ gid }` alone.
        let members = [prefix(LOCAL)?, prefix(PEER)?];
        let rendered = String::from_utf8(group_payload("EGRP", &members, &members)?.to_json_bytes()?)?;
        assert_eq!(
            rendered,
            format!(r#"{{"gid":"EGRP","smids":["{LOCAL}","{PEER}"],"rmids":["{LOCAL}","{PEER}"]}}"#)
        );
        Ok(())
    }

    #[test]
    fn a_delegation_approval_anchors_every_seal_it_was_shown() -> Result<(), Box<dyn Error>> {
        // The reference reads `ixn.a[0]`; this reads the list. Two seals in, two seals out.
        let two =
            interaction_embeds(r#"[{"i":"EBgew7O4","s":"0","d":"EBgew7O4"},{"i":"EMQQpnSk","s":"0","d":"EMQQpnSk"}]"#)?;
        let seals = anchors_of(&two)?;
        assert_eq!(seals.len(), 2);
        assert_eq!(seals.first().and_then(|seal| seal.get_text("i")), Some("EBgew7O4"));
        assert_eq!(seals.get(1).and_then(|seal| seal.get_text("i")), Some("EMQQpnSk"));
        // Which is what makes the two members' events the same one: taking only the first would
        // change the digest, and nothing upstream compares them.
        assert_ne!(seals.len(), 1, "the second delegation was dropped");
        Ok(())
    }

    #[test]
    fn a_delegation_approval_that_anchors_nothing_is_refused() -> Result<(), Box<dyn Error>> {
        // An interaction anchoring an empty list is a valid event and a meaningless approval.
        let empty = interaction_embeds("[]")?;
        assert_eq!(anchors_of(&empty)?, [] as [Sad; 0]);
        Ok(())
    }

    #[test]
    fn an_interactions_digest_is_the_one_it_carries() -> Result<(), Box<dyn Error>> {
        let event = interaction("[]")?;
        assert_eq!(digest_of(&event)?, "EIXNDIGEST");
        Ok(())
    }

    #[test]
    fn a_proposal_is_delivered_to_the_peers_and_not_to_the_sender() -> Result<(), Box<dyn Error>> {
        // The reference delivers the initiator's proposal back to the initiator, and — through
        // the exchange submission's delivery loop — addresses it to itself as well.
        let member = record(LOCAL)?;
        let participants = [prefix(LOCAL)?, prefix(PEER)?, prefix(THIRD)?];
        let peers = peers(&member, &participants)?;
        assert_eq!(peers, [prefix(PEER)?, prefix(THIRD)?]);
        assert!(!peers.contains(&prefix(LOCAL)?));
        Ok(())
    }

    #[test]
    fn the_order_of_the_remaining_peers_is_the_participants_own() -> Result<(), Box<dyn Error>> {
        // The addressee is the first peer, so the order decides who the message names.
        let member = record(PEER)?;
        let participants = [prefix(LOCAL)?, prefix(PEER)?, prefix(THIRD)?];
        assert_eq!(peers(&member, &participants)?, [prefix(LOCAL)?, prefix(THIRD)?]);
        Ok(())
    }

    #[test]
    fn a_member_that_is_not_a_participant_is_refused() -> Result<(), Box<dyn Error>> {
        let member = record(THIRD)?;
        let participants = [prefix(LOCAL)?, prefix(PEER)?];
        assert!(matches!(
            peers(&member, &participants),
            Err(ClientError::LocalMemberNotAParticipant { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_group_of_one_is_refused() -> Result<(), Box<dyn Error>> {
        // Nobody to propose to, and no signature but this member's — which is an identifier, not a
        // group. The reference sends a proposal addressed to and delivered to itself alone.
        let member = record(LOCAL)?;
        assert!(matches!(
            peers(&member, &[prefix(LOCAL)?]),
            Err(ClientError::LonelyGroup)
        ));
        assert!(matches!(
            peers(&member, &[]),
            Err(ClientError::LocalMemberNotAParticipant { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_witness_threshold_is_read_in_hexadecimal() -> Result<(), Box<dyn Error>> {
        // The whole of the reference's silent divergence, in one table. Below ten the two bases
        // agree; from ten they do not, and `parseInt` reports no error for the two-digit case.
        for (written, means) in [
            ("0", 0_u32),
            ("2", 2),
            ("9", 9),
            ("a", 10),
            ("f", 15),
            ("10", 16),
            ("ff", 255),
        ] {
            assert_eq!(witness_threshold(written)?, means, "{written}");
        }
        // `parseInt` agrees only below ten.
        assert_eq!(witness_threshold("9")?, "9".parse::<u32>()?);
        assert_ne!(witness_threshold("10")?, 10);
        assert_eq!(witness_threshold("10")?, 16);
        assert!("a".parse::<u32>().is_err());
        Ok(())
    }

    #[test]
    fn a_threshold_that_is_not_a_number_is_refused() {
        for text in ["", "g", "-1", "0x10", " 2", "2 ", "10000000000"] {
            assert!(
                witness_threshold(text).is_err(),
                "{text:?} was accepted as a witness threshold"
            );
        }
    }

    #[test]
    fn the_payload_writes_the_three_labels_in_the_references_order() -> Result<(), Box<dyn Error>> {
        let payload = group_payload("EGRP", &[prefix(LOCAL)?], &[prefix(PEER)?])?;
        let rendered = String::from_utf8(payload.to_json_bytes()?)?;
        assert!(rendered.starts_with(r#"{"gid":"EGRP","smids":["#), "{rendered}");
        assert!(rendered.contains(r#""rmids":["#));
        // The rotation set is what was read, not the signing set substituted for it.
        assert!(rendered.contains(PEER));
        assert!(!rendered.contains(&format!(r#""rmids":["{LOCAL}"]"#)));
        Ok(())
    }

    #[test]
    fn a_member_list_encodes_in_order() -> Result<(), Box<dyn Error>> {
        assert_eq!(qb64_all(&[])?, Vec::<String>::new());
        assert_eq!(
            qb64_all(&[prefix(LOCAL)?, prefix(PEER)?])?,
            [LOCAL.to_owned(), PEER.to_owned()]
        );
        Ok(())
    }

    #[test]
    fn an_unsigned_creation_cannot_be_proposed() {
        use signify_keys::manager::ManagedSignatures;
        // A group proposal carries its member's signature; without one there is nothing to relay.
        assert!(matches!(
            indexed(&ManagedSignatures::Indexed(Vec::new())),
            Err(ClientError::UnsignedGroupRequest)
        ));
        assert!(matches!(
            indexed(&ManagedSignatures::Unindexed(Vec::new())),
            Err(ClientError::UnsignedGroupRequest)
        ));
    }
}

/// Route a group proposes another exchange message on; the reference's `/multisig/exn`.
pub const EXCHANGE_ROUTE: &str = "/multisig/exn";

/// Slot the proposed message travels in.
pub const EXCHANGE_SLOT: &str = "exn";

/// What a group's disclosure commits to.
#[derive(Debug)]
pub struct GroupDisclosureRequest<'a> {
    /// Local alias of the disclosing group.
    pub group_name: &'a str,
    /// Local alias of this member's own identifier.
    pub local_member: &'a str,
    /// Every member of the group, this one included.
    pub members: &'a [IdentifierPrefix],
    /// Who the credential is being disclosed to.
    pub recipient: IdentifierPrefix,
    /// The credential, its issuance, and the key event anchoring it.
    pub disclosure: Disclosure,
    /// Human-readable text carried in the grant's `m` field.
    pub message: String,
    /// When the grant is stamped — and, because the joining members read it back out of the
    /// proposal, what makes their grants identical to this one.
    pub timestamp: Timestamp,
}

/// What a group's acknowledgement of a disclosure commits to.
#[derive(Debug)]
pub struct GroupAdmittanceRequest<'a> {
    /// Local alias of the admitting group.
    pub group_name: &'a str,
    /// Local alias of this member's own identifier.
    pub local_member: &'a str,
    /// Every member of the group, this one included.
    pub members: &'a [IdentifierPrefix],
    /// Who disclosed the credential.
    pub discloser: IdentifierPrefix,
    /// The grant being acknowledged.
    pub grant: Said,
    /// Human-readable text carried in the admit's `m` field.
    pub message: String,
    /// When the admit is stamped.
    pub timestamp: Timestamp,
}

/// What one member did in a group's IPEX round.
#[derive(Debug)]
pub struct GroupDisclosure {
    submitted: SubmittedIpexMessage,
    announcement: SentExchange,
    said: Said,
}

impl GroupDisclosure {
    /// Returns the agent's answer to the IPEX submission.
    #[must_use]
    pub const fn submitted(&self) -> &SubmittedIpexMessage {
        &self.submitted
    }

    /// Returns the agent's answer to the announcement.
    #[must_use]
    pub const fn announcement(&self) -> &SentExchange {
        &self.announcement
    }

    /// Returns the SAID of the message this member built.
    ///
    /// Every member's is the same, which is the whole point of the round: the agent collects
    /// signatures on one message. The reference's own holder test asserts exactly this equality —
    /// and it holds there only because both members read one module-level `TIME` constant.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }
}

impl Multisig<'_> {
    /// Proposes disclosing a credential to somebody outside the group.
    ///
    /// The group grants the credential and each member tells the others, so the agent can collect
    /// enough signatures on one grant. The message is built under the *group's* alias and announced
    /// under this member's own, which is the same split every other round here uses.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::LocalMemberNotAParticipant`] when the local member is not among the
    /// members, [`ClientError::LonelyGroup`] when it is the only one, [`ClientError::Ipex`] when the
    /// grant cannot be built, and whatever
    /// [`Ipex::submit`](crate::endpoint::ipex::Ipex::submit) and
    /// [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send) return.
    pub async fn propose_disclosure(
        &self,
        request: &GroupDisclosureRequest<'_>,
    ) -> Result<GroupDisclosure, ClientError> {
        let member = self.local_member(request.local_member).await?;
        let recipients = peers(&member, request.members)?;

        let grant = self
            .build_grant(
                request.group_name,
                &request.recipient,
                &request.disclosure,
                &request.message,
                &request.timestamp,
            )
            .await?;
        self.run_ipex_round(
            request.group_name,
            request.local_member,
            request.members,
            &recipients,
            grant,
            &request.recipient,
        )
        .await
    }

    /// Joins a disclosure another member proposed, granting the credential it was shown.
    ///
    /// Everything that decides the grant's SAID is read out of the proposal — the recipient, the
    /// text, and **the timestamp** — and the grant this member builds is compared with the one it
    /// was shown. The credential itself is the caller's, because a grant embeds it rather than
    /// naming it, and this member must hold it to disclose it.
    ///
    /// **Upstream nothing is read.** `grantMultisig` waits for a `/multisig/exn` notification,
    /// discards its SAID, and builds from its own arguments; the two members agree only because the
    /// test process hands both the same `timestamp`. Two members stamping their own clocks build
    /// two different grants, the group never reaches its threshold, and nothing says so.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotAnExchangeProposal`] when the message under `proposal` is not a
    /// proposed exchange, [`ClientError::WrongDisclosureStep`] when the message it carries is not a
    /// grant, [`ClientError::ProposalMismatch`] when this member derives a different grant, and
    /// whatever [`Groups::requests`](crate::endpoint::groups::Groups::requests) returns.
    pub async fn accept_disclosure(
        &self,
        group_name: &str,
        local_member: &str,
        proposal: &Said,
        disclosure: &Disclosure,
    ) -> Result<GroupDisclosure, ClientError> {
        let member = self.local_member(local_member).await?;
        let (proposed, embedded) = self.read_exchange_proposal(proposal).await?;
        let step = proposed_step(&embedded, IpexRoute::Grant)?;

        let members = self.members_of(&proposed, group_name).await?;
        let recipients = peers(&member, &members)?;

        let grant = self
            .build_grant(group_name, &step.recipient, disclosure, &step.message, &step.timestamp)
            .await?;
        require_same(&embedded.digest, &grant)?;

        self.run_ipex_round(group_name, local_member, &members, &recipients, grant, &step.recipient)
            .await
    }

    /// Proposes acknowledging a disclosure the group received.
    ///
    /// # Errors
    ///
    /// Returns the failures [`Self::propose_disclosure`] returns, for the admit rather than the
    /// grant.
    pub async fn propose_admittance(
        &self,
        request: &GroupAdmittanceRequest<'_>,
    ) -> Result<GroupDisclosure, ClientError> {
        let member = self.local_member(request.local_member).await?;
        let recipients = peers(&member, request.members)?;

        let admit = self
            .build_admit(
                request.group_name,
                &request.discloser,
                request.grant,
                &request.message,
                &request.timestamp,
            )
            .await?;
        self.run_ipex_round(
            request.group_name,
            request.local_member,
            request.members,
            &recipients,
            admit,
            &request.discloser,
        )
        .await
    }

    /// Joins an acknowledgement another member proposed.
    ///
    /// As with [`Self::accept_disclosure`], the grant being acknowledged, the recipient, the text,
    /// and the timestamp are all read out of the proposal, and the admit this member builds is
    /// compared with the one it was shown. This method takes **no timestamp**, because taking one
    /// would let a caller build something the group cannot sign.
    ///
    /// # Errors
    ///
    /// Returns the failures [`Self::accept_disclosure`] returns, for the admit rather than the
    /// grant.
    pub async fn accept_admittance(
        &self,
        group_name: &str,
        local_member: &str,
        proposal: &Said,
    ) -> Result<GroupDisclosure, ClientError> {
        let member = self.local_member(local_member).await?;
        let (proposed, embedded) = self.read_exchange_proposal(proposal).await?;
        let step = proposed_step(&embedded, IpexRoute::Admit)?;
        let granted = step.prior.ok_or(ClientError::WrongDisclosureStep {
            expected: IpexRoute::Admit.as_str(),
            found: "an admit chained to nothing",
        })?;

        let members = self.members_of(&proposed, group_name).await?;
        let recipients = peers(&member, &members)?;

        let admit = self
            .build_admit(group_name, &step.recipient, granted, &step.message, &step.timestamp)
            .await?;
        require_same(&embedded.digest, &admit)?;

        self.run_ipex_round(group_name, local_member, &members, &recipients, admit, &step.recipient)
            .await
    }

    /// Builds and signs one grant under the group's own alias.
    async fn build_grant(
        &self,
        group_name: &str,
        recipient: &IdentifierPrefix,
        disclosure: &Disclosure,
        message: &str,
        timestamp: &Timestamp,
    ) -> Result<IpexMessage, ClientError> {
        let (keeper, group) = self.group_signer(group_name).await?;
        let envelope = IpexEnvelope::new(group, recipient.clone(), message, timestamp.clone())?;
        Ok(ipex::grant(keeper.as_ref(), &envelope, disclosure, None)?)
    }

    /// Builds and signs one admit under the group's own alias.
    async fn build_admit(
        &self,
        group_name: &str,
        recipient: &IdentifierPrefix,
        grant: Said,
        message: &str,
        timestamp: &Timestamp,
    ) -> Result<IpexMessage, ClientError> {
        let (keeper, group) = self.group_signer(group_name).await?;
        let envelope = IpexEnvelope::new(group, recipient.clone(), message, timestamp.clone())?;
        Ok(ipex::admit(keeper.as_ref(), &envelope, grant)?)
    }

    /// Reads the group's keeper and prefix.
    async fn group_signer(
        &self,
        group_name: &str,
    ) -> Result<
        (
            Box<dyn signify_keys::manager::keeper::IdentifierKeeper>,
            IdentifierPrefix,
        ),
        ClientError,
    > {
        let record = self.client.identifiers().get(group_name).await?;
        let group = IdentifierPrefix::from_qb64(&record.common.prefix)?;
        let keeper = self.client.keepers().keeper_for(&Hab::Accepted(record))?;
        Ok((keeper, group))
    }

    /// Submits the message to its recipient, then announces it to the group's other members.
    ///
    /// `members` is the whole group, this member included; `recipients` are its peers. The
    /// announcement names the members in `smids` and `rmids` as every event round's does, where the
    /// reference's `grantMultisig` and `admitMultisig` write `{ gid }` alone — a deliberate
    /// divergence, so that a joining member reads its peers from the proposal rather than from a
    /// lookup.
    async fn run_ipex_round(
        &self,
        group_name: &str,
        local_member: &str,
        members: &[IdentifierPrefix],
        recipients: &[IdentifierPrefix],
        message: IpexMessage,
        addressee: &IdentifierPrefix,
    ) -> Result<GroupDisclosure, ClientError> {
        let said = message.said();
        let embed = self.transposed_embed(group_name, &message).await?;

        let submitted = self
            .client
            .ipex()
            .submit(group_name, &message, std::slice::from_ref(addressee))
            .await?;

        let group = self.client.identifiers().get(group_name).await?;
        let payload = group_payload(&group.common.prefix, members, members)?;

        let peer = recipients.first().ok_or(ClientError::LonelyGroup)?.clone();
        let draft = ExchangeDraft::new(EXCHANGE_ROUTE, peer, message_stamp(&message)?)
            .payload(payload)
            .embeds(vec![embed]);
        let announcement = self
            .client
            .exchanges()
            .send(
                local_member,
                crate::endpoint::exchanges::MULTISIG_TOPIC,
                &draft,
                recipients,
            )
            .await?;

        Ok(GroupDisclosure {
            submitted,
            announcement,
            said,
        })
    }

    /// Builds the `exn` embed: the message, its signatures under the group's establishment seal,
    /// and whatever its own embeds attached.
    async fn transposed_embed(&self, group_name: &str, message: &IpexMessage) -> Result<ExchangeEmbed, ClientError> {
        let record = self.client.identifiers().get(group_name).await?;
        let establishment = &record.state.latest_establishment_event;

        let mut attachment = SignedMessageBuilder::new(message.exchange().serialized())
            .controller_signatures(indexed(message.signatures())?)
            .seal(SignatureSeal::Event {
                identifier: IdentifierPrefix::from_qb64(&record.common.prefix)?,
                sequence_number: SequenceNumber::from_hex(&establishment.sequence_number)?,
                said: Said::from_qb64(&establishment.digest)?,
            })
            .build()
            .map_err(|source| ClientError::Attachment {
                source: Box::new(source),
            })?
            .attachments()
            .to_vec();
        attachment.extend_from_slice(message.attachments());

        Ok(ExchangeEmbed::new(EXCHANGE_SLOT, message.exchange().serialized())?.with_attachment(attachment)?)
    }

    /// Reads one group request and requires it to be a proposed exchange message.
    async fn read_exchange_proposal(&self, said: &Said) -> Result<(MultisigProposal, ExchangeRecord), ClientError> {
        let listing = self.client.groups().requests(said).await?;
        let first = listing.first().ok_or(ClientError::NotAnExchangeProposal {
            found: "an empty listing",
        })?;
        let classified = ClassifiedExchange::try_from(first)?;
        let proposal = classified
            .as_multisig()
            .ok_or(ClientError::NotAnExchangeProposal {
                found: "a message on another route",
            })?
            .clone();
        if proposal.route != MultisigRoute::Exchange {
            return Err(ClientError::NotAnExchangeProposal {
                found: proposal.route.as_str(),
            });
        }
        let ApiEmbed::Exchange(embed) = &proposal.proposed.message else {
            return Err(ClientError::NotAnExchangeProposal {
                found: "an embed that is not an exchange message",
            });
        };
        let embedded = embed.exn.clone();
        Ok((proposal, embedded))
    }
}

/// Everything a joining member must read out of a proposed IPEX step to rebuild it.
struct ProposedStep {
    recipient: IdentifierPrefix,
    message: String,
    timestamp: Timestamp,
    prior: Option<Said>,
}

/// Reads a proposed IPEX step, requiring it to be on `expected`.
fn proposed_step(embedded: &ExchangeRecord, expected: IpexRoute) -> Result<ProposedStep, ClientError> {
    if embedded.route != expected.as_str() {
        return Err(ClientError::WrongDisclosureStep {
            expected: expected.as_str(),
            found: match IpexRoute::ALL.iter().find(|route| route.as_str() == embedded.route) {
                Some(route) => route.as_str(),
                None => "a message on another route",
            },
        });
    }
    let addressed = embedded.recipient.as_deref().ok_or(ClientError::WrongDisclosureStep {
        expected: expected.as_str(),
        found: "a step addressed to nobody",
    })?;
    let message = embedded
        .attributes
        .get(ipex::MESSAGE_LABEL)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let prior = if embedded.prior.is_empty() {
        None
    } else {
        Some(Said::from_qb64(&embedded.prior)?)
    };

    Ok(ProposedStep {
        recipient: IdentifierPrefix::from_qb64(addressed)?,
        message,
        timestamp: embedded.stamp.parse()?,
        prior,
    })
}

/// Requires the message this member built to be the one it was shown.
fn require_same(proposed: &str, built: &IpexMessage) -> Result<(), ClientError> {
    let derived = built.said().qb64()?;
    if derived == proposed {
        Ok(())
    } else {
        Err(ClientError::ProposalMismatch {
            proposed: proposed.to_owned(),
            built: derived,
        })
    }
}

/// Reads a built message's own timestamp back, so the announcement carries the same one.
fn message_stamp(message: &IpexMessage) -> Result<Timestamp, ClientError> {
    let text = message
        .exchange()
        .sad()
        .get_text("dt")
        .ok_or(ClientError::WrongDisclosureStep {
            expected: "a stamped message",
            found: "one with no timestamp",
        })?;
    Ok(text.parse()?)
}
