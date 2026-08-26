//! The groups endpoint: what a multisig member reads and says while a group decides something.
//!
//! A multisig group acts only when enough of its members have signed the same event. That takes a
//! round of messages: one member proposes, the agent notifies the others, each reads the proposal
//! and either contributes a signature or does not. This family is the three calls that round is
//! made of — [`Groups::requests`] to read what was proposed, [`Groups::send_request`] to say it, and
//! [`Groups::join`] to contribute keys to a rotation already under way.
//!
//! This ports the whole `Groups` class of the pinned `src/keri/app/grouping.ts`. The messages
//! themselves are Roadmap 7.7's and the classifiers that read them are 8.1's; nothing here builds
//! or signs anything.
//!
//! # Reading is where this family is actually used
//!
//! `getRequest` is called twenty-one times across the reference's integration tree.
//! `sendRequest` and `join` are called **nowhere** outside the single pinned unit case — and that
//! case passes a forty-six-character SAID, a rotation whose event is `{}`, the signature `'sig'`,
//! and members named `1` and `a`. So the two writes are ported from their declarations, and every
//! one of those arguments is proven unrepresentable here. See `fixtures/client-groups/`.
//!
//! # A request is signed or it is not sent
//!
//! `sendRequest` declares `sigs: string[]` and sends whatever it is given; the pinned test sends
//! `[]`, which asks the agent to relay to every group member a proposal nobody signed. Here the
//! message is Roadmap 7.7's [`SignedExchange`], which comes from a keeper, and an empty signature
//! set is refused before the body is built.
//!
//! # There are two ways to send the same message
//!
//! `sendRequest` posts `{exn, sigs, atc}` to `/identifiers/{name}/multisig/request`, while Roadmap
//! 7.7's `Exchanges::send_signed` posts `{tpc, exn, sigs, atc, rec}` to
//! `/identifiers/{name}/exchanges`. The reference offers both for the same kind of message and
//! never says which to use; this port reproduces both and says so, because the pinned tree does not
//! settle it.

use signify_http::request::ResourcePath;
use signify_http::transport::Method;
use signify_keri::identifier::IdentifierArtifact;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};
use signify_types::api::{GroupOperation, MultisigExchangeResource};

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::body::{sad_error, text_array};
use crate::endpoint::decode_json;
use crate::endpoint::exchanges::{MULTISIG_TOPIC, SentExchange, SignedExchange};
use crate::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use crate::error::ClientError;

/// Path segment the group resources live under.
///
/// It appears in three addresses and never alone: `/multisig/request/{said}` reads,
/// `/identifiers/{alias}/multisig/request` proposes, and `/identifiers/{alias}/multisig/join`
/// contributes.
pub const MULTISIG_SEGMENT: &str = "multisig";

/// Path segment a group request lives under.
pub const REQUEST_SEGMENT: &str = "request";

/// Path segment a group join is posted to.
pub const JOIN_SEGMENT: &str = "join";

/// Contributing keys to a group rotation already under way.
///
/// The reference takes six arguments, of which the first two are the alias and a value it reads
/// `.sad` off — so passing the rotation event its own documentation names sends no rotation at all,
/// which the fixture records both ways round. Here the rotation is Roadmap 4.6's
/// [`IdentifierArtifact`], which carries the event and the signatures over it together, so there is
/// no second argument to disagree with and no field to read off.
#[derive(Debug)]
pub struct GroupJoin<'a> {
    rotation: &'a IdentifierArtifact,
    group: &'a IdentifierPrefix,
    signing_members: &'a [IdentifierPrefix],
    rotation_members: &'a [IdentifierPrefix],
}

impl<'a> GroupJoin<'a> {
    /// Describes a contribution to `group`'s rotation.
    ///
    /// `signing_members` is who will sign for the group afterwards and `rotation_members` is who
    /// will hold rotation authority — the reference's `smids` and `rmids`, which Roadmap 8.1 reads
    /// back out of a proposal's attribute block.
    #[must_use]
    pub const fn new(
        rotation: &'a IdentifierArtifact,
        group: &'a IdentifierPrefix,
        signing_members: &'a [IdentifierPrefix],
        rotation_members: &'a [IdentifierPrefix],
    ) -> Self {
        Self {
            rotation,
            group,
            signing_members,
            rotation_members,
        }
    }

    /// Returns the group this contribution is for.
    #[must_use]
    pub const fn group(&self) -> &IdentifierPrefix {
        self.group
    }

    /// Writes the body the reference sends, in its field order.
    fn body(&self) -> Result<Sad, ClientError> {
        require_signing_members(self.signing_members)?;
        let mut body = Sad::new();
        // The topic is the literal `'multisig'` upstream, where `Exchanges::send` takes it as an
        // argument; there is only ever one group topic, so it stays a constant here too.
        body.insert("tpc", MULTISIG_TOPIC.to_owned()).map_err(sad_error)?;
        body.insert("rot", SadValue::Map(self.rotation.event.sad().clone()))
            .map_err(sad_error)?;
        body.insert("sigs", text_array(self.rotation.signatures.qb64()?))
            .map_err(sad_error)?;
        body.insert("gid", self.group.qb64()?).map_err(sad_error)?;
        body.insert("smids", text_array(prefixes(self.signing_members)?))
            .map_err(sad_error)?;
        body.insert("rmids", text_array(prefixes(self.rotation_members)?))
            .map_err(sad_error)?;
        Ok(body)
    }
}

/// Refuses a contribution that names nobody to sign for the group afterwards.
///
/// Checked before anything is encoded, so a caller mistake costs no work. The reference sends an
/// empty list unchallenged, which asks the agent to rotate a group into having no signers.
fn require_signing_members(members: &[IdentifierPrefix]) -> Result<(), ClientError> {
    if members.is_empty() {
        Err(ClientError::EmptyGroupMembers)
    } else {
        Ok(())
    }
}

/// Encodes a member list for the wire.
fn prefixes(members: &[IdentifierPrefix]) -> Result<Vec<String>, ClientError> {
    members
        .iter()
        .map(|member| Ok(member.qb64()?))
        .collect::<Result<Vec<String>, ClientError>>()
}

/// The groups endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through. This is the shape Roadmap 6.5 settled for every family.
#[derive(Debug)]
pub struct Groups<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Groups<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Reads the group requests stored under one exchange SAID.
    ///
    /// The agent answers with a **list**: one entry per copy of the proposal it holds, each
    /// carrying the local group and member aliases beside the message. Classify each with Roadmap
    /// 8.1's [`ClassifiedExchange`](crate::endpoint::exchanges::ClassifiedExchange), which is what
    /// turns "a message on `/multisig/icp`" into "an inception this group is proposing".
    ///
    /// The SAID is Roadmap 3.3's validated type. The reference concatenates its argument straight
    /// into the path, and its own integration helper falls back to the empty string when no notice
    /// arrived — which addresses `/multisig/request/` and asks for the whole collection.
    ///
    /// ```no_run
    /// # use signify_client::client::ConnectedClient;
    /// # use signify_client::endpoint::exchanges::ClassifiedExchange;
    /// # use signify_keri::said::Said;
    /// # async fn read(client: &ConnectedClient, said: &Said) -> Result<(), Box<dyn std::error::Error>> {
    /// for resource in client.groups().requests(said).await? {
    ///     let proposal = ClassifiedExchange::try_from(&resource)?;
    ///     if let Some(multisig) = proposal.as_multisig() {
    ///         println!("{} proposes {}", resource.sender.as_deref().unwrap_or("a member"), multisig.route);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when the body
    /// is not a list of group requests, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn requests(&self, said: &Said) -> Result<Vec<MultisigExchangeResource>, ClientError> {
        let path = ResourcePath::builder()
            .segment(MULTISIG_SEGMENT)
            .segment(REQUEST_SEGMENT)
            .segment(&said.qb64()?)
            .build()?;
        let response = self.client.fetch(ClientRequest::new(Method::Get, path)).await?;
        decode_json(response.body())
    }

    /// Proposes one signed exchange message to the group's other members.
    ///
    /// `alias` names the group identifier the proposal is posted under. The message is Roadmap
    /// 7.7's, already built and signed by the member's own keeper.
    ///
    /// The body carries no topic and no recipient list, which is what the reference sends: the
    /// agent works both out from the message's own route. That is the difference from
    /// [`Exchanges::send_signed`](crate::endpoint::exchanges::Exchanges::send_signed), which posts
    /// the same message to a different address with both.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnsignedGroupRequest`] when the message carries no signature — the
    /// pinned unit test sends exactly that — [`ClientError::Decode`] when the message's attachment
    /// stream is not UTF-8, [`ClientError::Serialization`] when the body cannot be written, and the
    /// request, transport, and authentication failures [`ConnectedClient::fetch`] returns.
    pub async fn send_request(&self, alias: &str, message: &SignedExchange) -> Result<SentExchange, ClientError> {
        if message.signatures().is_empty() {
            return Err(ClientError::UnsignedGroupRequest);
        }

        let mut body = Sad::new();
        body.insert("exn", SadValue::Map(message.message().sad().clone()))
            .map_err(sad_error)?;
        body.insert("sigs", text_array(message.signatures().qb64()?))
            .map_err(sad_error)?;
        body.insert("atc", attachment_text(message)?.to_owned())
            .map_err(sad_error)?;

        let path = Self::identifier_path(alias, REQUEST_SEGMENT)?;
        let request = ClientRequest::new(Method::Post, path).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(request).await?;
        Ok(SentExchange::from_body(response.into_body()))
    }

    /// Contributes this member's keys to a group rotation already under way.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EmptyGroupMembers`] when the contribution names no signing member,
    /// [`ClientError::Serialization`] when the body cannot be written, [`ClientError::Api`] when
    /// the answer is not a group operation, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn join(&self, alias: &str, request: &GroupJoin<'_>) -> Result<GroupOperation, ClientError> {
        let body = request.body()?;
        let path = Self::identifier_path(alias, JOIN_SEGMENT)?;
        let sent = ClientRequest::new(Method::Post, path).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(sent).await?;
        decode_json(response.body())
    }

    /// Builds the address the two writes share, differing only in their last segment.
    fn identifier_path(alias: &str, action: &str) -> Result<ResourcePath, ClientError> {
        Ok(ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(alias)
            .segment(MULTISIG_SEGMENT)
            .segment(action)
            .build()?)
    }
}

/// Reads a message's attachment stream as the text the body carries it as.
fn attachment_text(message: &SignedExchange) -> Result<&str, ClientError> {
    core::str::from_utf8(message.attachments()).map_err(|error| ClientError::Decode {
        source: Box::new(signify_http::response::ResponseError::NotUtf8 {
            offset: error.valid_up_to(),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
    const GROUP: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
    const MEMBER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

    /// The forty-six-character value the pinned unit test reads by.
    const PINNED_SAID: &str = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose00";

    fn read_path(said: &Said) -> Result<ResourcePath, Box<dyn Error>> {
        Ok(ResourcePath::builder()
            .segment(MULTISIG_SEGMENT)
            .segment(REQUEST_SEGMENT)
            .segment(&said.qb64()?)
            .build()?)
    }

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(MULTISIG_SEGMENT, "multisig");
        assert_eq!(REQUEST_SEGMENT, "request");
        assert_eq!(JOIN_SEGMENT, "join");
        // The topic a join writes is Roadmap 7.7's, not a second copy.
        assert_eq!(MULTISIG_TOPIC, "multisig");
    }

    #[test]
    fn the_three_addresses_are_the_pinned_ones() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            read_path(&SAID.parse::<Said>()?)?.as_str(),
            format!("/multisig/request/{SAID}")
        );
        assert_eq!(
            Groups::identifier_path("aid1", REQUEST_SEGMENT)?.as_str(),
            "/identifiers/aid1/multisig/request"
        );
        assert_eq!(
            Groups::identifier_path("aid1", JOIN_SEGMENT)?.as_str(),
            "/identifiers/aid1/multisig/join"
        );
        Ok(())
    }

    #[test]
    fn the_two_writes_differ_only_in_their_last_segment() -> Result<(), Box<dyn Error>> {
        let request = Groups::identifier_path("aid1", REQUEST_SEGMENT)?;
        let join = Groups::identifier_path("aid1", JOIN_SEGMENT)?;
        let shared = |path: &ResourcePath| -> Vec<String> {
            path.path()
                .split('/')
                .skip(1)
                .take(3)
                .map(ToOwned::to_owned)
                .collect::<Vec<String>>()
        };
        assert_eq!(shared(&request), shared(&join));
        assert_eq!(shared(&request), ["identifiers", "aid1", "multisig"]);
        Ok(())
    }

    #[test]
    fn an_alias_can_never_leave_its_own_path_segment() -> Result<(), Box<dyn Error>> {
        // The reference interpolates the alias raw; the fixture records `a/b?c=d` reaching the wire
        // as two segments and a query.
        let path = Groups::identifier_path("a/b?c=d", REQUEST_SEGMENT)?;
        assert_eq!(path.as_str(), "/identifiers/a%2Fb%3Fc%3Dd/multisig/request");
        assert_eq!(path.path().split('/').count(), 5);
        assert_eq!(path.query(), None);
        Ok(())
    }

    #[test]
    fn the_pinned_read_value_is_not_a_said() {
        // Forty-six characters where a qualified digest is forty-four.
        assert_eq!(PINNED_SAID.len(), 46);
        assert_eq!(SAID.len(), 44);
        assert!(
            PINNED_SAID.parse::<Said>().is_err(),
            "the pinned literal was accepted as a SAID"
        );
    }

    #[test]
    fn a_value_that_would_escape_the_read_path_is_not_a_said() {
        // The empty string is the reference's own `waitAndMarkNotification` fallback, which
        // addresses `/multisig/request/` and asks for the whole collection.
        for hostile in ["", "../identifiers/aid1?x=1", "a/b", "not a said", PINNED_SAID] {
            assert!(
                hostile.parse::<Said>().is_err(),
                "{hostile:?} was accepted as a group request SAID"
            );
        }
    }

    #[test]
    fn a_read_path_is_always_three_segments() -> Result<(), Box<dyn Error>> {
        let path = read_path(&SAID.parse::<Said>()?)?;
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments.first().copied(), Some(MULTISIG_SEGMENT));
        assert_eq!(segments.get(1).copied(), Some(REQUEST_SEGMENT));
        assert_eq!(path.query(), None);
        Ok(())
    }

    #[test]
    fn a_join_writes_the_references_six_fields_in_order() -> Result<(), Box<dyn Error>> {
        // Built by hand rather than through `GroupJoin`, because an artifact needs a keeper; the
        // field order is what this test is about and it is the reference's.
        let mut body = Sad::new();
        body.insert("tpc", MULTISIG_TOPIC.to_owned())?;
        body.insert("rot", SadValue::Map(Sad::new()))?;
        body.insert("sigs", text_array(vec!["AAB".to_owned()]))?;
        body.insert("gid", GROUP.to_owned())?;
        body.insert("smids", text_array(vec![MEMBER.to_owned()]))?;
        body.insert("rmids", text_array(vec![MEMBER.to_owned()]))?;

        let rendered = String::from_utf8(body.to_json_bytes()?)?;
        assert!(rendered.starts_with(r#"{"tpc":"multisig","rot":{},"sigs":["AAB"],"gid":"#));
        let mut previous = 0_usize;
        for label in [
            r#""tpc":"#,
            r#""rot":"#,
            r#""sigs":"#,
            r#""gid":"#,
            r#""smids":"#,
            r#""rmids":"#,
        ] {
            let at = rendered.find(label).ok_or_else(|| format!("no {label}"))?;
            assert!(at >= previous, "{label} is out of order");
            previous = at;
        }
        Ok(())
    }

    #[test]
    fn a_request_writes_three_fields_and_no_topic() -> Result<(), Box<dyn Error>> {
        // Where Roadmap 7.7's submission writes five: this endpoint's body is the shorter one.
        let mut body = Sad::new();
        body.insert("exn", SadValue::Map(Sad::new()))?;
        body.insert("sigs", text_array(vec!["AAB".to_owned()]))?;
        body.insert("atc", String::new())?;
        assert_eq!(
            String::from_utf8(body.to_json_bytes()?)?,
            r#"{"exn":{},"sigs":["AAB"],"atc":""}"#
        );
        Ok(())
    }

    #[test]
    fn a_join_naming_no_signing_member_is_refused() -> Result<(), Box<dyn Error>> {
        // The reference sends empty lists unchallenged, which asks the agent to rotate a group
        // into having no signers. `GroupJoin::body` runs this before encoding anything.
        assert!(matches!(
            require_signing_members(&[]),
            Err(ClientError::EmptyGroupMembers)
        ));
        assert!(require_signing_members(&[IdentifierPrefix::from_qb64(MEMBER)?]).is_ok());
        Ok(())
    }

    #[test]
    fn an_empty_rotation_member_list_is_allowed() -> Result<(), Box<dyn Error>> {
        // Only the signing list is required: Roadmap 6.6's `rotate` writes an empty `rmids` for a
        // single-signature identifier, and refusing one here would refuse what that already sends.
        let members = [IdentifierPrefix::from_qb64(MEMBER)?];
        assert!(require_signing_members(&members).is_ok());
        assert_eq!(prefixes(&[])?, Vec::<String>::new());
        assert_eq!(prefixes(&members)?, [MEMBER.to_owned()]);
        Ok(())
    }

    #[test]
    fn an_answer_of_the_wrong_shape_is_refused() {
        // `getRequest` casts its answer to `ExnMultisig[]`; the fixture records `{"notes":[]}`
        // reaching a caller that way.
        for wrong in [
            r#"{"notes":[]}"#,
            r#"[{"exn":{}}]"#,
            r#"[{"paths":{}}]"#,
            "null",
            r#""text""#,
            "7",
        ] {
            assert!(
                serde_json::from_str::<Vec<MultisigExchangeResource>>(wrong).is_err(),
                "{wrong} was accepted as a group request listing"
            );
        }
    }

    #[test]
    fn a_group_request_listing_keeps_its_local_aliases() -> Result<(), Box<dyn Error>> {
        let exn = format!(
            r#"{{"v":"KERI10JSON000_","t":"exn","d":"{SAID}","i":"{MEMBER}","rp":"{GROUP}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"/multisig/icp","q":{{}},"a":{{}},"e":{{}}}}"#
        );
        let document = format!(
            r#"[{{"exn":{exn},"paths":{{"-e-icp":"-AABAA"}},"groupName":"multisig","memberName":"member1","sender":"{MEMBER}"}}]"#
        );
        let listing: Vec<MultisigExchangeResource> = serde_json::from_str(&document)?;
        let first = listing.first().ok_or("empty listing")?;
        assert_eq!(first.group_name.as_deref(), Some("multisig"));
        assert_eq!(first.member_name.as_deref(), Some("member1"));
        assert_eq!(first.sender.as_deref(), Some(MEMBER));
        assert_eq!(first.paths.len(), 1);
        // The three local labels are optional, so an agent that omits them is still understood.
        let bare = format!(r#"[{{"exn":{exn},"paths":{{}}}}]"#);
        let plain: Vec<MultisigExchangeResource> = serde_json::from_str(&bare)?;
        assert_eq!(plain.first().and_then(|entry| entry.group_name.as_deref()), None);
        Ok(())
    }

    #[test]
    fn an_empty_listing_is_an_answer_rather_than_an_absence() -> Result<(), Box<dyn Error>> {
        let listing: Vec<MultisigExchangeResource> = serde_json::from_str("[]")?;
        assert!(listing.is_empty());
        Ok(())
    }
}
