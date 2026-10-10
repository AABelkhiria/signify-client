//! What a client lifecycle can fail at.
//!
//! The reference throws strings — `bran must be 21 characters`, `agent does not exist for
//! controller …`, `commitment to controller AID missing in agent inception event`, `client need to
//! call connect first`. Each becomes a variant here, except the last, which the type system makes
//! unreachable.

use core::fmt;
use std::error::Error;

use keri_cesr::CesrError;
use keri_cesr::crypto::CryptoError;
use keria_types::api::ApiError;
use signify_acdc::credential::CredentialError;
use signify_acdc::error::{AnchorError, IpexError, IpexSigningError, TransactionError};
use signify_http::header::HeaderError;
use signify_http::request::RequestError;
use signify_http::response::ResponseError;
use signify_http::signature::authentication::AuthenticationError;
use signify_http::signature::transport::{ResponseAuthenticationError, SigningError};
use signify_http::transport::TransportError;
use signify_keri::attachment::AttachmentError;
use signify_keri::controller::ControllerError;
use signify_keri::event::{EventError, TimestampError};
use signify_keri::identifier::IdentifierError;
use signify_keri::manager::ManagerError;
use signify_keri::prefix::PrefixError;
use signify_keri::registry::RegistryError;
use signify_keri::said::SaidError;
use signify_keri::serialization::SerializationError;

/// Largest response body detail kept in an error message, in bytes.
const MAX_DETAIL_BYTES: usize = 256;

/// Stable client-lifecycle failures.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// A passcode is not exactly [`PASSCODE_LENGTH`](crate::config::PASSCODE_LENGTH) characters.
    InvalidPasscodeLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// A passcode holds a character outside the URL-safe Base64 alphabet.
    PasscodeNotBase64 {
        /// Zero-based position of the first offending character.
        position: usize,
    },
    /// The agent resource does not exist; the reference's `agent does not exist for controller …`.
    AgentNotFound {
        /// The controller prefix the agent was looked up for.
        controller: String,
    },
    /// The agent's inception event does not anchor this controller.
    ///
    /// The reference's `commitment to controller AID missing in agent inception event`. An agent
    /// that fails this is either not ours or has been substituted, so nothing else is attempted.
    AgentNotDelegatedToController {
        /// The controller this client derived.
        expected: String,
        /// The controller the agent's inception anchors.
        actual: String,
    },
    /// The agent reported a controller other than the one this client was configured for.
    ///
    /// The state was fetched by the configured prefix, so this means the agent answered for a
    /// different controller than it was asked about.
    ControllerPrefixMismatch {
        /// The prefix this client was configured with.
        configured: String,
        /// The prefix of the controller event the agent reported.
        reported: String,
    },
    /// The passcode does not derive the signing key of the controller the agent reports.
    ///
    /// Either the passcode is not the one in force — an old passcode after a rotation, or a
    /// mistyped one — or the configured controller prefix names somebody else's controller. The
    /// reference adopts the reported event unchecked and fails only on the first signed request.
    ControllerKeyMismatch {
        /// The controller the agent reports.
        controller: String,
        /// The first signing key of its latest establishment event.
        established: String,
        /// The key this passcode derives.
        derived: String,
    },
    /// The agent state response did not carry an agent, or did not carry a controller.
    IncompleteAgentState {
        /// Which half was missing.
        missing: &'static str,
    },
    /// A request returned a non-success status.
    ///
    /// The reference builds one message out of the method, path, status, status text, and body;
    /// here the parts stay separate and the body is bounded.
    Status {
        /// The status returned.
        status: u16,
        /// The bounded body, for diagnosis.
        detail: String,
    },
    /// A response could not be decoded as the document it should have been.
    Decode {
        /// Underlying failure.
        source: Box<ResponseError>,
    },
    /// Building a request failed.
    Request {
        /// Underlying failure.
        source: Box<RequestError>,
    },
    /// A header name or value was unusable.
    Header {
        /// Underlying failure.
        source: Box<HeaderError>,
    },
    /// The transport failed.
    Transport {
        /// Underlying failure.
        source: Box<TransportError>,
    },
    /// Signing a request failed.
    Signing {
        /// Underlying failure.
        source: Box<SigningError>,
    },
    /// Preparing the signing or verifying material failed.
    Authentication {
        /// Underlying failure.
        source: Box<AuthenticationError>,
    },
    /// A response did not authenticate.
    ResponseAuthentication {
        /// Underlying failure.
        source: Box<ResponseAuthenticationError>,
    },
    /// The controller could not be derived or advanced.
    Controller {
        /// Underlying failure.
        source: Box<ControllerError>,
    },
    /// The key manager could not be built.
    Manager {
        /// Underlying failure.
        source: Box<ManagerError>,
    },
    /// A serialized event could not be read or written.
    Serialization {
        /// Underlying failure.
        source: Box<SerializationError>,
    },
    /// A cryptographic value could not be encoded.
    Crypto {
        /// Underlying failure.
        source: Box<CryptoError>,
    },
    /// A qualified value could not be encoded.
    Cesr {
        /// Underlying failure.
        source: Box<CesrError>,
    },
    /// A KERIA document did not decode as the type it should have been.
    Api {
        /// Underlying failure.
        source: Box<ApiError>,
    },
    /// An operation was asked for its result before it had finished.
    ///
    /// The reference has no such state: its `throwIfFailed` returns a still-running operation
    /// unchanged, and only `wait` notices.
    OperationPending {
        /// The operation's name, which is also its path segment.
        name: String,
    },
    /// An operation finished unsuccessfully.
    ///
    /// The reference interpolates all four of these into one thrown string; here they stay apart,
    /// and the message is bounded because it is remote text.
    OperationFailed {
        /// The operation's name.
        name: String,
        /// The agent's status code, following HTTP conventions.
        code: i64,
        /// The agent's message, bounded.
        message: String,
        /// The agent's structured detail, rendered as JSON when present.
        details: Option<String>,
    },
    /// An identifier artifact could not be built or signed.
    Identifier {
        /// Underlying failure.
        source: Box<IdentifierError>,
    },
    /// An identifier record carried no key state where one was required.
    ///
    /// The reference's `No key state for identifier <name>`, which a multisig group still
    /// collecting member signatures produces.
    IdentifierNotAccepted {
        /// The alias or prefix the record was looked up by.
        name: String,
    },
    /// A self-addressing identifier could not be encoded.
    Said {
        /// Underlying failure.
        source: Box<SaidError>,
    },
    /// A registry event could not be built.
    Registry {
        /// Underlying failure.
        source: Box<RegistryError>,
    },
    /// An exchange message could not be built.
    Exchange {
        /// Underlying failure.
        source: Box<EventError>,
    },
    /// A signed message's CESR attachment could not be framed.
    Attachment {
        /// Underlying failure.
        source: Box<AttachmentError>,
    },
    /// A credential names an issuer that is not the identifier being used to anchor it.
    ///
    /// The reference never compares the two: the credential's issuer is `args.i ?? hab.prefix` and
    /// the anchor is signed by whichever identifier the caller named, so a credential can claim an
    /// issuer whose key event log contains no anchor for it. No verifier can resolve such a
    /// credential, so it is refused here before anything is signed.
    CredentialIssuerMismatch {
        /// The issuer the credential names.
        credential: String,
        /// The identifier whose keeper would sign the anchor.
        anchoring: String,
    },
    /// A credential transaction event could not be built or anchored.
    Transaction {
        /// Underlying failure.
        source: Box<TransactionError>,
    },
    /// A credential or registry identifier could not be encoded.
    Credential {
        /// Underlying failure.
        source: Box<CredentialError>,
    },
    /// A registry, issuance, or revocation was asked for under an identifier that may carry only
    /// establishment events.
    ///
    /// Such an identifier anchors only in a rotation event, which neither the reference nor this
    /// port builds. The reference throws `establishment only not implemented` — for a registry,
    /// after building the whole inception; here nothing is derived and nothing is sent.
    EstablishmentOnlyIssuer {
        /// The identifier prefix that refused it.
        identifier: String,
    },
    /// An IPEX message was submitted with no recipient at all.
    ///
    /// The reference sends `"rec":[]`, asking the agent to deliver the message to nobody and
    /// reporting nothing; here it is a caller mistake rather than a request.
    NoIpexRecipients {
        /// The route of the message that would have been sent.
        route: &'static str,
    },
    /// A timestamp read back off the wire is not a KERI timestamp.
    ///
    /// A joining member reads the stamp out of the proposal it is joining, because the stamp is
    /// inside the SAID it must reproduce; an agent that returns a malformed one is a failure here
    /// rather than a message nobody can sign.
    Timestamp {
        /// Underlying failure.
        source: Box<TimestampError>,
    },
    /// A group request was read expecting a proposed exchange message and was something else.
    NotAnExchangeProposal {
        /// What was found instead.
        found: &'static str,
    },
    /// A group request was read expecting a proposed end-role authorization and was something else.
    ///
    /// Includes a reply on another route, one for a different group, and one whose role or
    /// endpoint is missing or is not usable — none of which a member can rebuild and sign.
    NotAnEndRoleProposal {
        /// What was found instead.
        found: &'static str,
    },
    /// A group member authorizes no agent, so there is no agent for the group to authorize.
    ///
    /// The reference throws `signing.ends.agent is null or undefined` part way through its loop,
    /// after the members before it were already authorized.
    MemberHasNoAgent {
        /// The member's prefix.
        member: String,
    },
    /// An IPEX message could not be built or signed.
    Ipex {
        /// Underlying failure.
        source: Box<IpexError>,
    },
    /// A disclosure step was answered as though it were a different step.
    ///
    /// Answering a grant with an agree, or an apply with an admit, produces a message chained to
    /// something its recipient is not waiting for. Upstream every step takes a bare SAID, so any
    /// step can be handed to any answer.
    WrongDisclosureStep {
        /// The step the method answers.
        expected: &'static str,
        /// The step it was handed.
        found: &'static str,
    },
    /// A notification announced a message but named none.
    ///
    /// The reference's waiter ends `?.a.d ?? ''`, so this case reaches its callers as the empty
    /// string and is built into an answer chained to nothing.
    UnaddressedNotification {
        /// Identifier of the notification.
        notification: String,
    },
    /// A notification named a message that is not an IPEX step.
    NotADisclosureStep {
        /// The route the message carried.
        route: String,
    },
    /// A notification's route is not the route the message it names carries.
    DisclosureRouteMismatch {
        /// The route the notification claimed.
        notified: String,
        /// The route the message actually carries.
        carried: &'static str,
    },
    /// A credential could not be re-serialized to the bytes its SAID names.
    ///
    /// The SAID of an event is a digest over its exact encoding, so an event whose field order did
    /// not survive the agent's JSON can no longer be disclosed under the name it arrived with.
    NonCanonicalCredential {
        /// Which of the three parts of a disclosure failed.
        part: &'static str,
    },
    /// An apply's attribute block is not the shape a request must have.
    MalformedDisclosureRequest {
        /// What the block was required to be or to name.
        what: &'static str,
    },
    /// A key-state listing named no identifier at all.
    ///
    /// The reference sends `/states?` with nothing after the question mark, which asks for
    /// nothing; here it is a caller mistake rather than a request.
    EmptyKeyStateListing,
    /// An identifier's keeper holds no signing key.
    NoSigningKey {
        /// The alias the identifier was looked up by.
        alias: String,
    },
    /// Polling gave up before the operation finished.
    ///
    /// The reference has no such state: its `Operations.wait` is a `while (true)` with no deadline
    /// and no attempt cap, so an operation the agent never finishes is polled forever. Roadmap 7.2
    /// bounds it and reports which bound was reached.
    PollingStopped {
        /// The operation that was being waited on.
        name: String,
        /// Which bound stopped it.
        limit: crate::operation::PollingLimit,
        /// How many times the agent was asked.
        attempts: u32,
        /// How long the poll ran before giving up.
        elapsed: core::time::Duration,
    },
    /// A challenge strength is not an entropy size BIP39 defines.
    ///
    /// The reference stringifies whatever number it is given into the query, so a fraction, a
    /// negative, or `NaN` reaches the agent as a request no mnemonic generator can satisfy.
    InvalidChallengeStrength {
        /// The value that was asked for.
        bits: u32,
    },
    /// An exchange message's route promises an embed the message does not carry.
    ///
    /// The reference's thirteen `assert*` functions compare the route and stop, so a message on
    /// `/multisig/icp` carrying no `icp` block is handed to the caller typed as though it did.
    /// Here the route selects a shape and the shape is decoded, so the two cannot disagree.
    ExchangeEmbedMismatch {
        /// The route the message carried.
        route: &'static str,
        /// The embed slot that route requires.
        expected: &'static str,
        /// The slot the message actually carried, or `nothing` when it carried no embed at all.
        found: &'static str,
    },
    /// A multisig proposal's attribute block is missing a label its route requires.
    ///
    /// The reference declares `gid` on all eight multisig routes and `smids` on the three that
    /// name members, and checks neither. A label that is present but is not a list of qualified
    /// prefixes reports the same way an absent one does, so a malformed member list can never read
    /// as an unset one.
    MissingGroupAttribute {
        /// The route the message carried.
        route: &'static str,
        /// The wire label that was missing or unusable.
        label: &'static str,
    },
    /// A group inception named the local member nowhere among its participants.
    ///
    /// The reference never compares them: it passes the member's habitat to `create` and the
    /// participant list to `send`, so a member can propose a group it is not in — and then hold a
    /// key the group's own event does not name.
    LocalMemberNotAParticipant {
        /// The local member's prefix.
        member: String,
    },
    /// A group inception named only the local member.
    ///
    /// There is nobody to propose to and no signature but this one, which is an identifier rather
    /// than a group. The reference sends the proposal to itself.
    LonelyGroup,
    /// The agent lists no signing member for a group.
    ///
    /// A proposal that names no members is answered by asking the agent who they are, and an
    /// empty answer leaves nobody to sign. The reference reads `members.signing.map(…)` and would
    /// send the proposal to an empty list.
    NoRecordedMembers {
        /// The group's local alias.
        group: String,
    },
    /// A group inception named a member the agent knows no key state for.
    ///
    /// The reference reads `states[0]` without checking there is one, so an unknown participant
    /// reaches the group's key list as `undefined`.
    UnknownGroupMember {
        /// The member whose key state was missing.
        member: String,
    },
    /// A message read as a group inception proposal is not one.
    NotAnInceptionProposal {
        /// What was found in its place.
        found: &'static str,
    },
    /// A delegation approval was asked to anchor nothing.
    ///
    /// The reference declares its anchor optional and wraps a non-array in one, so `approve(name)`
    /// with no anchor sends `"a": [null]` — an approval of nothing, which is the only body its own
    /// unit test publishes for this endpoint; see `PORTING.md` §9.
    NoDelegationSeals,
    /// An event that is not a delegated inception was offered as one awaiting approval.
    NotADelegatedInception {
        /// The ilk that was found in its place.
        found: &'static str,
    },
    /// A group registry proposal was expected and something else arrived.
    NotARegistryProposal {
        /// What was found in its place.
        found: &'static str,
    },
    /// A group credential issuance proposal was expected and something else arrived.
    NotAnIssuanceProposal {
        /// What was found in its place.
        found: &'static str,
    },
    /// A group credential revocation proposal was expected and something else arrived.
    NotARevocationProposal {
        /// What was found in its place.
        found: &'static str,
    },
    /// An identifier a group workflow was asked to act for is not a group.
    NotAGroupIdentifier {
        /// The identifier that was named.
        identifier: String,
    },
    /// A group rotation proposal was expected and something else arrived.
    NotARotationProposal {
        /// What was found in its place.
        found: &'static str,
    },
    /// A group interaction proposal was expected and something else arrived.
    NotAnInteractionProposal {
        /// What was found in its place.
        found: &'static str,
    },
    /// A member built an event that is not the event it was asked to sign.
    ///
    /// Every member of a group builds the same event independently, so a disagreement about one
    /// field of it produces a different digest and the group never converges. The reference
    /// compares nothing anywhere — `multisig.test.ts` has its joining member rebuild a rotation
    /// from its own key states and sign whatever comes out — so this failure has no upstream
    /// counterpart; see `PORTING.md` §9.
    ProposalMismatch {
        /// The digest the proposal carried.
        proposed: String,
        /// The digest this member built.
        built: String,
    },
    /// A group request was proposed with no signature at all.
    ///
    /// The reference's `Groups.sendRequest` declares `sigs: string[]` and sends whatever it is
    /// given; its own unit test sends `[]`, which asks the agent to relay to every group member a
    /// proposal nobody signed.
    UnsignedGroupRequest,
    /// A group join named no signing member.
    ///
    /// The reference sends empty member lists unchallenged, which asks the agent to rotate a group
    /// into having no signers. An empty **rotation**-member list is allowed, because a
    /// single-signature rotation writes one and Roadmap 6.6 reproduces it.
    EmptyGroupMembers,
    /// An exchange message was submitted with no recipient at all.
    ///
    /// The reference's `sendFromEvents` sends `"rec":[]` unchallenged — its own unit test does
    /// exactly that — while `send` throws, and only because its loop cannot run. Here both refuse
    /// it: asking the agent to deliver a message to nobody is a caller mistake, which is the same
    /// reasoning Roadmap 6.12 applied to an IPEX submission.
    NoExchangeRecipients,
    /// An exchange message was submitted under no topic at all.
    ///
    /// The topic is what the agent files the recipient's notification under, so an empty one asks
    /// for a notification nobody can find. The reference sends it unchallenged.
    EmptyExchangeTopic,
    /// A challenge verification named no words at all.
    ///
    /// The reference sends `{"words":[]}`, asking the agent to confirm that an identifier signed
    /// nothing; here it is a caller mistake rather than a request.
    EmptyChallengeWords,
    /// A module's own stored parameter is a number this port cannot write exactly.
    ///
    /// Roadmap 3.2 narrowed the number space deliberately so byte parity is provable; a
    /// fractional or out-of-range value is refused rather than rounded.
    UnrepresentableNumber,
    /// Operating-system randomness was unavailable.
    Randomness,
}

impl ClientError {
    /// Builds a status failure, bounding the body kept for diagnosis.
    #[must_use]
    pub(crate) fn status(status: u16, body: &[u8]) -> Self {
        let text = String::from_utf8_lossy(body);
        let detail = text
            .char_indices()
            .take_while(|(index, character)| index.saturating_add(character.len_utf8()) <= MAX_DETAIL_BYTES)
            .map(|(_, character)| character)
            .collect();
        Self::Status { status, detail }
    }
}

impl fmt::Display for ClientError {
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per variant is the clearest form for a Display over a large error enum, \
                  and it is what keeps the match exhaustive: every alternative either needs a \
                  catch-all, which would let a new variant render as something generic, or \
                  scatters the wording across several functions"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPasscodeLength { expected, actual } => write!(
                formatter,
                "a passcode must be exactly {expected} characters, not {actual}"
            ),
            Self::PasscodeNotBase64 { position } => write!(
                formatter,
                "a passcode character at position {position} is outside the URL-safe Base64 alphabet"
            ),
            Self::AgentNotFound { controller } => {
                write!(formatter, "no agent exists for controller {controller}")
            }
            Self::AgentNotDelegatedToController { expected, actual } => write!(
                formatter,
                "the agent's inception anchors {actual}, not this controller {expected}"
            ),
            Self::ControllerPrefixMismatch { configured, reported } => write!(
                formatter,
                "the agent reported controller {reported}, not the configured controller {configured}"
            ),
            Self::ControllerKeyMismatch {
                controller,
                established,
                derived,
            } => write!(
                formatter,
                "the passcode derives {derived}, but controller {controller} signs with {established}"
            ),
            Self::IncompleteAgentState { missing } => {
                write!(formatter, "the agent state carried no {missing}")
            }
            Self::Status { status, detail } => write!(formatter, "the agent answered {status}: {detail}"),
            Self::Decode { source } => write!(formatter, "response decoding failed: {source}"),
            Self::Request { source } => write!(formatter, "request construction failed: {source}"),
            Self::Header { source } => write!(formatter, "header construction failed: {source}"),
            Self::Transport { source } => write!(formatter, "transport failed: {source}"),
            Self::Signing { source } => write!(formatter, "request signing failed: {source}"),
            Self::Authentication { source } => write!(formatter, "authentication setup failed: {source}"),
            Self::ResponseAuthentication { source } => {
                write!(formatter, "response authentication failed: {source}")
            }
            Self::Controller { source } => write!(formatter, "controller derivation failed: {source}"),
            Self::Manager { source } => write!(formatter, "key manager construction failed: {source}"),
            Self::Serialization { source } => write!(formatter, "serialization failed: {source}"),
            Self::Crypto { source } => write!(formatter, "cryptographic encoding failed: {source}"),
            Self::Cesr { source } => write!(formatter, "qualified encoding failed: {source}"),
            Self::Api { source } => write!(formatter, "document decoding failed: {source}"),
            Self::OperationPending { name } => write!(formatter, "operation {name:?} is still running"),
            Self::OperationFailed {
                name,
                code,
                message,
                details,
            } => match details {
                Some(details) => write!(
                    formatter,
                    "operation {name:?} failed [code {code}]: {message} ({details})"
                ),
                None => write!(formatter, "operation {name:?} failed [code {code}]: {message}"),
            },
            Self::Identifier { source } => write!(formatter, "identifier artifact construction failed: {source}"),
            Self::IdentifierNotAccepted { name } => {
                write!(formatter, "the identifier {name:?} has no key state yet")
            }
            Self::Said { source } => write!(formatter, "self-addressing identifier encoding failed: {source}"),
            Self::Registry { source } => write!(formatter, "registry event construction failed: {source}"),
            Self::EstablishmentOnlyIssuer { identifier } => write!(
                formatter,
                "the identifier {identifier} may carry only establishment events, so it cannot anchor an interaction event"
            ),
            Self::CredentialIssuerMismatch { credential, anchoring } => write!(
                formatter,
                "the credential names issuer {credential}, which is not the identifier {anchoring} anchoring it"
            ),
            Self::Transaction { source } => write!(formatter, "transaction event construction failed: {source}"),
            Self::Credential { source } => write!(formatter, "credential encoding failed: {source}"),
            Self::Timestamp { source } => write!(formatter, "a timestamp could not be read: {source}"),
            Self::NotAnEndRoleProposal { found } => {
                write!(
                    formatter,
                    "a group end-role proposal was expected, but {found} was found"
                )
            }
            Self::MemberHasNoAgent { member } => {
                write!(formatter, "the group member {member} authorizes no agent")
            }
            Self::NotAnExchangeProposal { found } => {
                write!(
                    formatter,
                    "a proposed exchange message was expected, and {found} was found"
                )
            }
            Self::Ipex { source } => write!(formatter, "IPEX message construction failed: {source}"),
            Self::WrongDisclosureStep { expected, found } => {
                write!(formatter, "a disclosure {expected} cannot answer a {found}")
            }
            Self::UnaddressedNotification { notification } => write!(
                formatter,
                "notification {notification} announces a message but names none"
            ),
            Self::NotADisclosureStep { route } => {
                write!(
                    formatter,
                    "a notification named a message on {route}, which is not an IPEX step"
                )
            }
            Self::DisclosureRouteMismatch { notified, carried } => write!(
                formatter,
                "a notification on {notified} named a message carrying {carried}"
            ),
            Self::NonCanonicalCredential { part } => {
                write!(formatter, "{part} does not re-serialize to the bytes its SAID names")
            }
            Self::MalformedDisclosureRequest { what } => {
                write!(formatter, "a disclosure request must carry {what}")
            }
            Self::NoIpexRecipients { route } => write!(
                formatter,
                "an IPEX {route} message must name at least one recipient to be delivered to"
            ),
            Self::Exchange { source } => write!(formatter, "exchange message construction failed: {source}"),
            Self::Attachment { source } => write!(formatter, "attachment framing failed: {source}"),
            Self::ExchangeEmbedMismatch { route, expected, found } => write!(
                formatter,
                "an exchange on {route} must embed {expected}, but it embeds {found}"
            ),
            Self::MissingGroupAttribute { route, label } => {
                write!(formatter, "a multisig proposal on {route} must name a usable {label}")
            }
            Self::LocalMemberNotAParticipant { member } => write!(
                formatter,
                "the local member {member} is not among the group's participants"
            ),
            Self::LonelyGroup => formatter.write_str("a multisig group must name a member besides the local one"),
            Self::NoRecordedMembers { group } => {
                write!(formatter, "the agent lists no signing member for the group {group}")
            }
            Self::UnknownGroupMember { member } => {
                write!(formatter, "the agent knows no key state for the group member {member}")
            }
            Self::NotAnInceptionProposal { found } => {
                write!(
                    formatter,
                    "a group inception proposal was expected, but {found} was found"
                )
            }
            Self::NoDelegationSeals => formatter.write_str("a delegation approval must anchor at least one seal"),
            Self::NotADelegatedInception { found } => {
                write!(
                    formatter,
                    "a delegated inception was expected, but a {found} event was found"
                )
            }
            Self::NotARegistryProposal { found } => {
                write!(
                    formatter,
                    "a group registry proposal was expected, but {found} was found"
                )
            }
            Self::NotAnIssuanceProposal { found } => {
                write!(
                    formatter,
                    "a group credential issuance was expected, but {found} was found"
                )
            }
            Self::NotARevocationProposal { found } => {
                write!(
                    formatter,
                    "a group credential revocation was expected, but {found} was found"
                )
            }
            Self::NotAGroupIdentifier { identifier } => {
                write!(formatter, "the identifier {identifier} is not a multisig group")
            }
            Self::NotARotationProposal { found } => {
                write!(
                    formatter,
                    "a group rotation proposal was expected, but {found} was found"
                )
            }
            Self::NotAnInteractionProposal { found } => {
                write!(
                    formatter,
                    "a group interaction proposal was expected, but {found} was found"
                )
            }
            Self::ProposalMismatch { proposed, built } => {
                write!(
                    formatter,
                    "this member built the event {built} where the proposal it read carries {proposed}"
                )
            }
            Self::UnsignedGroupRequest => {
                formatter.write_str("a group request must carry at least one signature to be relayed")
            }
            Self::EmptyGroupMembers => formatter.write_str("a group join must name at least one signing member"),
            Self::NoExchangeRecipients => {
                formatter.write_str("an exchange message must name at least one recipient to be delivered to")
            }
            Self::EmptyExchangeTopic => formatter.write_str("an exchange message must be submitted under a topic"),
            Self::EmptyKeyStateListing => formatter.write_str("a key-state listing must name at least one identifier"),
            Self::NoSigningKey { alias } => {
                write!(formatter, "the identifier {alias:?} holds no signing key")
            }
            Self::PollingStopped {
                name,
                limit,
                attempts,
                elapsed,
            } => write!(
                formatter,
                "the operation {name:?} was still running after {attempts} attempts over {elapsed:?}: {limit}"
            ),
            Self::InvalidChallengeStrength { bits } => write!(
                formatter,
                "a challenge strength of {bits} bits is not one BIP39 defines ({declared:?})",
                declared = crate::endpoint::challenges::ChallengeStrength::DECLARED
            ),
            Self::EmptyChallengeWords => formatter.write_str("a challenge verification named no words"),
            Self::UnrepresentableNumber => {
                formatter.write_str("a stored parameter is a number that cannot be written exactly")
            }
            Self::Randomness => formatter.write_str("operating-system randomness is unavailable"),
        }
    }
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode { source } => Some(source),
            Self::Request { source } => Some(source),
            Self::Header { source } => Some(source),
            Self::Transport { source } => Some(source),
            Self::Signing { source } => Some(source),
            Self::Authentication { source } => Some(source),
            Self::ResponseAuthentication { source } => Some(source),
            Self::Controller { source } => Some(source),
            Self::Manager { source } => Some(source),
            Self::Serialization { source } => Some(source),
            Self::Crypto { source } => Some(source),
            Self::Cesr { source } => Some(source),
            Self::Api { source } => Some(source),
            Self::Identifier { source } => Some(source),
            Self::Said { source } => Some(source),
            Self::Registry { source } => Some(source),
            Self::Exchange { source } => Some(source),
            Self::Attachment { source } => Some(source),
            Self::Transaction { source } => Some(source),
            Self::Credential { source } => Some(source),
            Self::Ipex { source } => Some(source),
            Self::Timestamp { source } => Some(source),
            Self::InvalidPasscodeLength { .. }
            | Self::PasscodeNotBase64 { .. }
            | Self::AgentNotFound { .. }
            | Self::AgentNotDelegatedToController { .. }
            | Self::ControllerPrefixMismatch { .. }
            | Self::ControllerKeyMismatch { .. }
            | Self::IncompleteAgentState { .. }
            | Self::Status { .. }
            | Self::OperationPending { .. }
            | Self::OperationFailed { .. }
            | Self::IdentifierNotAccepted { .. }
            | Self::EstablishmentOnlyIssuer { .. }
            | Self::CredentialIssuerMismatch { .. }
            | Self::NoIpexRecipients { .. }
            | Self::NotAnExchangeProposal { .. }
            | Self::NotAnEndRoleProposal { .. }
            | Self::MemberHasNoAgent { .. }
            | Self::WrongDisclosureStep { .. }
            | Self::UnaddressedNotification { .. }
            | Self::NotADisclosureStep { .. }
            | Self::DisclosureRouteMismatch { .. }
            | Self::NonCanonicalCredential { .. }
            | Self::MalformedDisclosureRequest { .. }
            | Self::ExchangeEmbedMismatch { .. }
            | Self::MissingGroupAttribute { .. }
            | Self::NoDelegationSeals
            | Self::NotADelegatedInception { .. }
            | Self::NotARegistryProposal { .. }
            | Self::NotAnIssuanceProposal { .. }
            | Self::NotARevocationProposal { .. }
            | Self::NotAGroupIdentifier { .. }
            | Self::NotARotationProposal { .. }
            | Self::NotAnInteractionProposal { .. }
            | Self::ProposalMismatch { .. }
            | Self::LocalMemberNotAParticipant { .. }
            | Self::LonelyGroup
            | Self::NoRecordedMembers { .. }
            | Self::UnknownGroupMember { .. }
            | Self::NotAnInceptionProposal { .. }
            | Self::UnsignedGroupRequest
            | Self::EmptyGroupMembers
            | Self::NoExchangeRecipients
            | Self::EmptyExchangeTopic
            | Self::EmptyKeyStateListing
            | Self::NoSigningKey { .. }
            | Self::PollingStopped { .. }
            | Self::InvalidChallengeStrength { .. }
            | Self::EmptyChallengeWords
            | Self::UnrepresentableNumber
            | Self::Randomness => None,
        }
    }
}

macro_rules! layered {
    ($source:ty, $variant:ident) => {
        impl From<$source> for ClientError {
            fn from(source: $source) -> Self {
                Self::$variant {
                    source: Box::new(source),
                }
            }
        }
    };
}

layered!(ResponseError, Decode);
layered!(RequestError, Request);
layered!(HeaderError, Header);
layered!(TransportError, Transport);
layered!(SigningError, Signing);
layered!(AuthenticationError, Authentication);
layered!(ResponseAuthenticationError, ResponseAuthentication);
layered!(ControllerError, Controller);
layered!(ManagerError, Manager);
layered!(SerializationError, Serialization);
layered!(CryptoError, Crypto);
layered!(CesrError, Cesr);
layered!(IdentifierError, Identifier);
layered!(RegistryError, Registry);
layered!(EventError, Exchange);
layered!(AttachmentError, Attachment);
layered!(SaidError, Said);
layered!(TransactionError, Transaction);
layered!(CredentialError, Credential);
layered!(IpexError, Ipex);

impl From<AnchorError> for ClientError {
    fn from(error: AnchorError) -> Self {
        match error {
            AnchorError::Transaction { source } => Self::Transaction { source },
            AnchorError::Identifier { source } => Self::Identifier { source },
        }
    }
}

impl From<IpexSigningError> for ClientError {
    fn from(error: IpexSigningError) -> Self {
        match error {
            IpexSigningError::Ipex { source } => Self::Ipex { source },
            IpexSigningError::Manager { source } => Self::Manager { source },
        }
    }
}
layered!(TimestampError, Timestamp);

impl From<PrefixError> for ClientError {
    /// A prefix read out of an identifier record is that record's failure, not the controller's.
    fn from(source: PrefixError) -> Self {
        Self::Identifier {
            source: Box::new(source.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a status failure's two fields, or an error naming the wrong variant.
    fn status_parts(error: &ClientError) -> Result<(u16, &str), String> {
        match error {
            ClientError::Status { status, detail } => Ok((*status, detail.as_str())),
            other => Err(format!("the wrong variant was built: {other}")),
        }
    }

    #[test]
    fn a_status_failure_bounds_the_body_it_keeps() -> Result<(), String> {
        let error = ClientError::status(500, &b"x".repeat(MAX_DETAIL_BYTES * 4));
        let (status, detail) = status_parts(&error)?;
        assert_eq!(status, 500);
        assert_eq!(detail.len(), MAX_DETAIL_BYTES);
        assert!(error.to_string().contains("500"));
        Ok(())
    }

    #[test]
    fn a_status_body_is_never_split_through_a_character() -> Result<(), String> {
        // Four-byte characters, so a naive byte truncation would produce invalid UTF-8.
        let body = "\u{1f510}".repeat(200);
        let error = ClientError::status(400, body.as_bytes());
        let (_, detail) = status_parts(&error)?;
        assert!(detail.len() <= MAX_DETAIL_BYTES);
        assert!(detail.chars().all(|character| character == '\u{1f510}'));
        Ok(())
    }

    #[test]
    fn every_failure_describes_itself() {
        let failures = [
            ClientError::InvalidPasscodeLength {
                expected: 21,
                actual: 5,
            },
            ClientError::PasscodeNotBase64 { position: 3 },
            ClientError::AgentNotFound {
                controller: "ECTRL".to_owned(),
            },
            ClientError::AgentNotDelegatedToController {
                expected: "ECTRL".to_owned(),
                actual: "EOTHER".to_owned(),
            },
            ClientError::IncompleteAgentState { missing: "agent" },
            ClientError::status(404, b"missing"),
            ClientError::IdentifierNotAccepted {
                name: "group1".to_owned(),
            },
            ClientError::EstablishmentOnlyIssuer {
                identifier: "EISS".to_owned(),
            },
            ClientError::CredentialIssuerMismatch {
                credential: "EISSUER".to_owned(),
                anchoring: "EANCHOR".to_owned(),
            },
            ClientError::NoIpexRecipients { route: "/ipex/grant" },
            ClientError::EmptyKeyStateListing,
            ClientError::NoSigningKey {
                alias: "aid1".to_owned(),
            },
            ClientError::UnrepresentableNumber,
            ClientError::Randomness,
        ];
        for failure in &failures {
            assert_ne!(failure.to_string(), "");
            assert!(failure.source().is_none());
        }
    }
}
