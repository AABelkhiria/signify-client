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
//!
//! An inception creates the identifier, a rotation changes who controls it, and an interaction
//! anchors seals in its log without changing anything about its keys.
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
//! events, the group never rotates, and nothing says so. Roadmap 8.4's fixture drives exactly that.
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
//! port and no unit test to reproduce. `PORTING.md` §4.5 records it as a Rust-only module, and the
//! fixtures run the reference's own code — the helpers by transpiling that one file in memory, the
//! two later rounds by driving the same primitives in the same order. See
//! `fixtures/client-multisig-inception/` and `fixtures/client-multisig-events/`.
//!
//! # What this composes
//!
//! Nothing here is new protocol. The inception is Roadmap 4.6's artifact submitted through 6.6's
//! endpoint; the proposal is 3.8's exchange message signed by 4.3's keeper, attached with 3.7's
//! framing and sent through 7.7's submission; the proposal a joining member reads is 8.2's listing
//! classified by 8.1. This module is the order those go in, and the four places the reference gets
//! that order wrong.
//!
//! # A proposal is addressed to a peer
//!
//! `startMultisigIncept` passes its whole participant list as the recipient list, and the local
//! member is the first of it — so through the loop Roadmap 7.7 recorded, the message is addressed
//! to its own sender and delivered back to itself along with everybody else. The accepting helper
//! already filters itself out; here both do.
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
//! It reads the member record **twice**: once here to build the group, and once inside Roadmap
//! 7.7's [`Exchanges::send`](crate::endpoint::exchanges::Exchanges::send), which resolves its own
//! sender from the alias rather than taking a record the caller is already holding. That is what
//! keeps a message's `i` field and the key that signed it one identifier, and it is why a proposal
//! makes six requests here where the reference — passing the hab it already has — makes five. The
//! group's keys come from the participants' key states either way, so nothing rests on it.

use signify_keri::attachment::SignedMessageBuilder;
use signify_keri::event::Timestamp;
use signify_keri::event::exchange::ExchangeEmbed;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, IdentifierArtifact, RotateIdentifierRequest};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::Sad;
use signify_keri::threshold::SigningThreshold;
use signify_types::api::{AcceptedHab, ExchangeEmbed as ApiEmbed, Hab, KeyEvent, KeyState, Threshold};

use crate::client::ConnectedClient;
use crate::endpoint::body::{sad_error, text_array};
use crate::endpoint::exchanges::{
    ClassifiedExchange, ExchangeDraft, GROUP_LABEL, MultisigProposal, MultisigRoute, ROTATION_MEMBERS_LABEL,
    SIGNING_MEMBERS_LABEL, SentExchange,
};
use crate::endpoint::identifiers::Submission;
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
/// about one of them produce different rotations. Unlike an inception, the joining half takes
/// **none** of them: [`Multisig::accept_rotation`] signs the event it was shown rather than
/// rebuilding one, which is why there is no accepting counterpart to this type.
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
    /// call sites disagree about which one reaches `rmids`, which is the same conflation Roadmap
    /// 8.3 recorded in the accepting half of an inception.
    pub rotation_states: &'a [KeyState],
    /// Next-key threshold; the reference's `nsith`, defaulting to the state's own.
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
/// speaks through — the shape Roadmap 6.5 settled for a family and 7.2 reused for a workflow.
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
    /// bytes it arrived as, which `PORTING.md` §10 records.
    ///
    /// The announcement goes out on [`ROTATION_ROUTE`], where the reference's joining members send
    /// [`INTERACTION_ROUTE`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotARotationProposal`] when the message under `proposal` is not a
    /// group rotation, [`ClientError::ProposalMismatch`] when the rotation this member builds is
    /// not the one it was shown, and whatever
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

        let built = submission.artifact().event.said().qb64()?;
        if built != proposed_digest {
            return Err(ClientError::ProposalMismatch {
                proposed: proposed_digest,
                built,
            });
        }

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
    /// not the event it was shown, and whatever
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
        let proposed = self.read_proposal(proposal, MultisigRoute::Interaction).await?;
        let ApiEmbed::Interaction(embed) = &proposed.proposed.message else {
            return Err(ClientError::NotAnInteractionProposal {
                found: "an embed that is not an interaction",
            });
        };

        let anchors = anchors_of(&embed.ixn)?;
        let signing = proposed.attributes.signing_members.clone().unwrap_or_default();
        let rotation = proposed
            .attributes
            .rotation_members
            .clone()
            .unwrap_or_else(|| signing.clone());
        let recipients = peers(&member, &signing)?;

        let submission = self.client.identifiers().interact(group_name, anchors).await?;

        // What was built against what was shown. The reference compares nothing anywhere.
        let proposed_digest = digest_of(&embed.ixn)?;
        let built = submission.artifact().event.said().qb64()?;
        if built != proposed_digest {
            return Err(ClientError::ProposalMismatch {
                proposed: proposed_digest,
                built,
            });
        }

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

    /// Announces an event this member submitted to the peers that must match it.
    ///
    /// The route and the embed slot arrive together and always agree, which is the whole of what
    /// this port does differently from the reference's rotation round.
    async fn announce(
        &self,
        submission: Submission<IdentifierArtifact>,
        announcement: &Announcement<'_>,
    ) -> Result<GroupEvent, ClientError> {
        let Announcement {
            group_name,
            local_member,
            route,
            slot,
            signing,
            rotation,
            recipients,
            timestamp,
        } = announcement;
        let group = submission.artifact().event.identifier().clone();

        let attachment = SignedMessageBuilder::new(submission.artifact().event.serialized())
            .controller_signatures(indexed(&submission.artifact().signatures)?)
            .build()
            .map_err(|source| ClientError::Attachment {
                source: Box::new(source),
            })?
            .attachments()
            .to_vec();
        let embed = ExchangeEmbed::new(*slot, submission.artifact().event.serialized())?.with_attachment(attachment)?;

        let mut payload = Sad::new();
        payload.insert(GROUP_LABEL, group.qb64()?).map_err(sad_error)?;
        payload
            .insert(SIGNING_MEMBERS_LABEL, text_array(qb64_all(signing)?))
            .map_err(sad_error)?;
        payload
            .insert(ROTATION_MEMBERS_LABEL, text_array(qb64_all(rotation)?))
            .map_err(sad_error)?;

        let addressee = recipients.first().ok_or(ClientError::LonelyGroup)?.clone();
        let draft = ExchangeDraft::new(*route, addressee, (*timestamp).clone())
            .payload(payload)
            .embeds(vec![embed]);

        let announced = self
            .client
            .exchanges()
            .send(local_member, group_name, &draft, recipients)
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

        let attachment = SignedMessageBuilder::new(submission.artifact().event.serialized())
            .controller_signatures(indexed(&submission.artifact().signatures)?)
            .build()
            .map_err(|source| ClientError::Attachment {
                source: Box::new(source),
            })?
            .attachments()
            .to_vec();
        let embed = ExchangeEmbed::new(INCEPTION_SLOT, submission.artifact().event.serialized())?
            .with_attachment(attachment)?;

        let mut payload = Sad::new();
        payload.insert(GROUP_LABEL, group.qb64()?).map_err(sad_error)?;
        payload
            .insert(SIGNING_MEMBERS_LABEL, text_array(qb64_all(signing)?))
            .map_err(sad_error)?;
        payload
            .insert(ROTATION_MEMBERS_LABEL, text_array(qb64_all(rotation)?))
            .map_err(sad_error)?;

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
        let wrong = |found: &'static str| match expected {
            MultisigRoute::Rotation => ClientError::NotARotationProposal { found },
            MultisigRoute::Interaction => ClientError::NotAnInteractionProposal { found },
            _ => ClientError::NotAnInceptionProposal { found },
        };
        let listing = self.client.groups().requests(said).await?;
        let first = listing.first().ok_or_else(|| wrong("an empty listing"))?;
        let classified = ClassifiedExchange::try_from(first)?;
        let proposal = classified
            .as_multisig()
            .ok_or_else(|| wrong("a message on another route"))?;
        if proposal.route == expected {
            Ok(proposal.clone())
        } else {
            Err(wrong(proposal.route.as_str()))
        }
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

/// The seals an interaction event anchors, read out of its `a` field.
///
/// The schema types that field `unknown` and the reference wraps a non-array in one, so a seal
/// list is what arrives and a single seal is what a caller may have sent. Both are read here; a
/// seal that is not an object is refused rather than dropped.
fn anchors_of(event: &KeyEvent) -> Result<Vec<Sad>, ClientError> {
    let KeyEvent::Interaction(record) = event else {
        return Err(ClientError::NotAnInteractionProposal {
            found: "an embed that is not an interaction",
        });
    };
    let seals = match &record.anchors {
        serde_json::Value::Array(seals) => seals.clone(),
        single => vec![single.clone()],
    };
    seals
        .iter()
        .map(|anchor| {
            let bytes = serde_json::to_vec(anchor).map_err(|_| ClientError::UnrepresentableNumber)?;
            Sad::from_json_bytes(&bytes).map_err(sad_error)
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
/// initiator there delivers its own proposal back to itself and — through Roadmap 7.7's loop —
/// addresses it to itself as well.
///
/// Public because a caller may reasonably want to know who a proposal will reach before sending
/// one, and because it is the whole of the difference described above.
///
/// ```
/// use signify_client::multisig::delivery_list;
/// use signify_keri::prefix::IdentifierPrefix;
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
    signatures: &signify_keri::manager::ManagedSignatures,
) -> Result<Vec<signify_crypto::signature::IndexedSignature>, ClientError> {
    match signatures {
        signify_keri::manager::ManagedSignatures::Indexed(indexed) if !indexed.is_empty() => Ok(indexed.clone()),
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

    /// One inception event, used where a test needs an embed that is not an interaction.
    const INCEPTION_EVENT: &str = r#"{"v":"KERI10JSON000_","t":"icp","d":"EICP","i":"EGRP","s":"0","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":"0","b":[],"c":[],"a":[]}"#;

    /// One interaction event anchoring `anchors`, exactly as an embed carries it.
    fn interaction(anchors: &str) -> Result<KeyEvent, Box<dyn Error>> {
        let document = format!(
            r#"{{"v":"KERI10JSON000_","t":"ixn","d":"EIXNDIGEST","i":"EGRP","s":"1","p":"EICP","a":{anchors}}}"#
        );
        Ok(serde_json::from_str(&document)?)
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
        // And each is the route Roadmap 8.1's table names.
        assert_eq!(MultisigRoute::Inception.as_str(), INCEPTION_ROUTE);
        assert_eq!(MultisigRoute::Rotation.as_str(), ROTATION_ROUTE);
        assert_eq!(MultisigRoute::Interaction.as_str(), INTERACTION_ROUTE);
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
        assert!(prefixes_of(&[])?.is_empty());
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
        let one = interaction(r#"[{"i":"EBgew7O4","s":"0","d":"EBgew7O4"}]"#)?;
        let anchors = anchors_of(&one)?;
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors.first().and_then(|seal| seal.get_text("i")), Some("EBgew7O4"));

        let bare = interaction(r#"{"i":"EBgew7O4","s":"0","d":"EBgew7O4"}"#)?;
        assert_eq!(anchors_of(&bare)?.len(), 1);

        let two = interaction(r#"[{"i":"EBgew7O4"},{"i":"EMQQpnSk"}]"#)?;
        assert_eq!(anchors_of(&two)?.len(), 2);
        Ok(())
    }

    #[test]
    fn a_seal_that_is_not_an_object_is_refused_rather_than_dropped() -> Result<(), Box<dyn Error>> {
        let event = interaction(r#"["not a seal"]"#)?;
        let refused = anchors_of(&event).is_err();
        assert!(refused, "a seal that is not an object was accepted");
        Ok(())
    }

    #[test]
    fn an_embed_that_is_not_an_interaction_is_not_read_as_one() -> Result<(), Box<dyn Error>> {
        let inception: KeyEvent = serde_json::from_str(INCEPTION_EVENT)?;
        let refused = matches!(
            anchors_of(&inception),
            Err(ClientError::NotAnInteractionProposal { .. })
        );
        assert!(refused, "an inception was read for seals");
        let no_digest = matches!(digest_of(&inception), Err(ClientError::NotAnInteractionProposal { .. }));
        assert!(no_digest, "an inception answered for an interaction's digest");
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
        // Roadmap 7.7's loop — addresses it to itself as well.
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
        let mut payload = Sad::new();
        payload.insert(GROUP_LABEL, "EGRP".to_owned())?;
        payload.insert(SIGNING_MEMBERS_LABEL, text_array(vec![LOCAL.to_owned()]))?;
        payload.insert(ROTATION_MEMBERS_LABEL, text_array(vec![PEER.to_owned()]))?;
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
        use signify_keri::manager::ManagedSignatures;
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
