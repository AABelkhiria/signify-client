//! Classifying an exchange message by its route, and checking that it carries what the route says.
//!
//! The pinned `src/keri/app/exchanging.ts` declares thirteen resource variants, thirteen `is*`
//! guards, and thirteen `assert*` assertions over them. Every one of the twenty-six is a single
//! route comparison — `msg.exn.r === ROUTE` — and the variant it narrows to is a **compile-time
//! claim about a run-time value that nothing looks at**.
//!
//! So `assertMultisigIcp` accepts a message on `/multisig/icp` carrying no `icp` block at all,
//! returns it typed as though it did, and the caller's `exn.e.icp` is `undefined` while the
//! compiler insists it is an inception. The fixture records exactly that, executed.
//!
//! [`ClassifiedExchange`] makes the claim a check: the route selects a shape and the shape is
//! decoded, so a route and a payload that disagree are a typed refusal rather than a wrong type.
//!
//! # What replaces twenty-six functions
//!
//! One enum and two `TryFrom` impls. A guard is `matches!`; an assertion is `?`. Nothing here is
//! generated per route, so a route and its payload cannot drift apart the way two hand-written
//! functions can — and the thirteen guards, **none of which has a caller anywhere in the pinned
//! tree**, need no equivalent at all.
//!
//! # An unnamed route is a message, not a mistake
//!
//! The route space is open: this crate's own [`Challenges::respond`](crate::endpoint::challenges)
//! sends `/challenge/response`, which is not one of the thirteen. Such a message classifies as
//! [`ClassifiedExchange::Other`] rather than failing. Only a **named** route whose payload
//! disagrees is refused.
//!
//! See `fixtures/client-exchange-routes/`.

use serde_json::{Map, Value};

use signify_acdc::ipex::IpexRoute;
use signify_keri::prefix::IdentifierPrefix;
use signify_types::api::MultisigExchangeResource;
use signify_types::api::{AcdcRecord, ExchangeEmbed, ExchangeEmbeds, ExchangeRecord, ExchangeResource};

use super::route::{ExchangeRoute, MultisigRoute};
use crate::error::ClientError;

/// Wire label carrying the group identifier a proposal coordinates.
pub const GROUP_LABEL: &str = "gid";

/// Wire label carrying the members that will sign.
pub const SIGNING_MEMBERS_LABEL: &str = "smids";

/// Wire label carrying the members that will hold rotation authority.
pub const ROTATION_MEMBERS_LABEL: &str = "rmids";

/// Wire label carrying a registry's stated usage.
pub const USAGE_LABEL: &str = "usage";

/// The `a` block a multisig proposal carries.
///
/// The reference declares a different `a` shape per route, but the differences are only which
/// fields are present: `gid` on all eight, `smids` and `rmids` on the three that name members, and
/// `usage` on the registry proposal. One value with the route deciding what is required is the same
/// thing said once.
///
/// **The generated schema names none of these labels** — `gid`, `smids`, and `rmids` appear zero
/// times in it — so the shape comes from the reference's hand-written types, checked against what
/// `test-integration/multisig.test.ts` actually sends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupAttributes {
    /// The group identifier being coordinated; wire label `gid`.
    pub group: IdentifierPrefix,
    /// Members that will sign, present on inception, rotation, and interaction; wire label `smids`.
    pub signing_members: Option<Vec<IdentifierPrefix>>,
    /// Members that will hold rotation authority; wire label `rmids`.
    ///
    /// The reference declares it optional and every real call site sends it.
    pub rotation_members: Option<Vec<IdentifierPrefix>>,
    /// What a proposed registry is for; wire label `usage`.
    pub usage: Option<String>,
    /// Every other label the block carried.
    ///
    /// The reference's types declare an index signature, so an `a` block may carry anything beyond
    /// the four labels above; nothing is dropped.
    pub additional: Map<String, Value>,
}

impl GroupAttributes {
    /// Reads the block a message on `route` carries.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::MissingGroupAttribute`] when a label the route requires is absent or
    /// is not the shape it must be, and [`ClientError::Identifier`] when an identifier in it is not
    /// a qualified prefix.
    fn parse(route: MultisigRoute, block: &Value) -> Result<Self, ClientError> {
        let fields = block.as_object().ok_or_else(|| ClientError::MissingGroupAttribute {
            route: route.as_str(),
            label: GROUP_LABEL,
        })?;

        let group = text(fields, GROUP_LABEL)
            .ok_or(ClientError::MissingGroupAttribute {
                route: route.as_str(),
                label: GROUP_LABEL,
            })
            .and_then(|value| Ok(IdentifierPrefix::from_qb64(value)?))?;

        let signing_members = prefixes(route, fields, SIGNING_MEMBERS_LABEL)?;
        if route.names_members() && signing_members.is_none() {
            // The reference declares `smids` required on exactly these three routes and never
            // checks; a caller there reads `undefined` as a list.
            return Err(ClientError::MissingGroupAttribute {
                route: route.as_str(),
                label: SIGNING_MEMBERS_LABEL,
            });
        }

        let mut additional = fields.clone();
        for label in [GROUP_LABEL, SIGNING_MEMBERS_LABEL, ROTATION_MEMBERS_LABEL, USAGE_LABEL] {
            additional.remove(label);
        }

        Ok(Self {
            group,
            signing_members,
            rotation_members: prefixes(route, fields, ROTATION_MEMBERS_LABEL)?,
            usage: text(fields, USAGE_LABEL).map(ToOwned::to_owned),
            additional,
        })
    }
}

/// Reads one text field, or `None` when it is absent or is not text.
fn text<'a>(fields: &'a Map<String, Value>, label: &str) -> Option<&'a str> {
    fields.get(label).and_then(Value::as_str)
}

/// Reads one list of qualified prefixes, or `None` when the label is absent.
///
/// A label that is present but is not a list of prefixes is a failure rather than an absence, so a
/// malformed member list can never read as an unset one.
fn prefixes(
    route: MultisigRoute,
    fields: &Map<String, Value>,
    label: &'static str,
) -> Result<Option<Vec<IdentifierPrefix>>, ClientError> {
    let Some(value) = fields.get(label) else {
        return Ok(None);
    };
    let unusable = || ClientError::MissingGroupAttribute {
        route: route.as_str(),
        label,
    };
    value
        .as_array()
        .ok_or_else(unusable)?
        .iter()
        .map(|item| {
            let text = item.as_str().ok_or_else(unusable)?;
            Ok(IdentifierPrefix::from_qb64(text)?)
        })
        .collect::<Result<Vec<IdentifierPrefix>, ClientError>>()
        .map(Some)
}

/// One multisig coordination step, with the message it proposes.
#[derive(Clone, Debug, PartialEq)]
pub struct MultisigProposal {
    /// Which step this is.
    pub route: MultisigRoute,
    /// The group and the members it names.
    pub attributes: GroupAttributes,
    /// The message being proposed, with the embed block's own SAID.
    ///
    /// This is Roadmap 4.1's [`ExchangeEmbeds`], whose eight variants correspond one-to-one with
    /// the eight multisig routes — which is why the route and the embed can be checked against
    /// each other at all.
    pub proposed: ExchangeEmbeds,
}

/// What an IPEX step embeds.
///
/// The reference declares these shapes by hand in `exchanging.ts`; **the generated schema models
/// none of them**, because its `ExnEmbeds` union is the multisig one.
#[derive(Clone, Debug, PartialEq)]
pub enum IpexPayload {
    /// Apply, agree, and admit embed nothing at all.
    Empty,
    /// An offer embeds the credential being offered, and nothing else.
    Offer(Box<OfferedCredential>),
    /// A grant embeds the credential, its issuance, and the anchoring key event.
    ///
    /// Those are the same three fields a multisig issuance proposal carries, so one shape serves
    /// both routes; the inner value is always [`ExchangeEmbed::Issuance`].
    Grant(Box<ExchangeEmbeds>),
}

/// The embed block of an IPEX offer: a credential with no provenance beside it.
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct OfferedCredential {
    /// SAID of the embed block itself, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// The credential being offered.
    pub acdc: Box<AcdcRecord>,
}

/// One IPEX disclosure step, with what it embeds.
#[derive(Clone, Debug, PartialEq)]
pub struct IpexStep {
    /// Which step of the conversation this is.
    pub route: IpexRoute,
    /// What the step embeds.
    pub payload: IpexPayload,
}

/// An exchange message, classified by its route.
///
/// This replaces the reference's thirteen `is*` guards and thirteen `assert*` assertions: a guard
/// is `matches!` on this enum, and an assertion is the `?` on the [`TryFrom`] that produced it.
///
/// ```
/// use signify_client::endpoint::exchanges::{ClassifiedExchange, MultisigRoute};
/// use signify_types::api::ExchangeResource;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // A route the table does not name is a message, not a failure: this crate sends one.
/// let answer = r#"{"exn":{"v":"KERI10JSON000100_","t":"exn","d":"EEXN","i":"EMEM","rp":"EPEER",
///   "p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"/challenge/response","q":{},
///   "a":{"words":["shell"]},"e":{}},"pathed":{}}"#;
/// let resource: ExchangeResource = serde_json::from_str(&answer.replace('\n', ""))?;
/// let classified = ClassifiedExchange::try_from(&resource)?;
/// assert!(matches!(classified, ClassifiedExchange::Other { .. }));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub enum ClassifiedExchange {
    /// One of the eight multisig coordination steps.
    Multisig(Box<MultisigProposal>),
    /// One of the five IPEX disclosure steps.
    Ipex(Box<IpexStep>),
    /// A message on a route this table does not name.
    ///
    /// Not a failure. `/challenge/response` reaches here, and so would any route a future KERIA
    /// introduces; the message itself is still whatever the agent sent.
    Other {
        /// The route the message carried.
        route: String,
    },
}

impl ClassifiedExchange {
    /// Returns the route this message carries, when the table names it.
    #[must_use]
    pub fn route(&self) -> Option<ExchangeRoute> {
        match self {
            Self::Multisig(proposal) => Some(ExchangeRoute::Multisig(proposal.route)),
            Self::Ipex(step) => Some(ExchangeRoute::Ipex(step.route)),
            Self::Other { .. } => None,
        }
    }

    /// Returns the multisig proposal this message is, if it is one.
    ///
    /// This is the whole of what the reference's `isMultisig*` guards offer, for all eight routes
    /// at once — combine it with a `==` on [`MultisigProposal::route`] for one.
    #[must_use]
    pub fn as_multisig(&self) -> Option<&MultisigProposal> {
        match self {
            Self::Multisig(proposal) => Some(proposal),
            Self::Ipex(_) | Self::Other { .. } => None,
        }
    }

    /// Returns the IPEX step this message is, if it is one.
    #[must_use]
    pub fn as_ipex(&self) -> Option<&IpexStep> {
        match self {
            Self::Ipex(step) => Some(step),
            Self::Multisig(_) | Self::Other { .. } => None,
        }
    }

    /// Classifies one exchange message.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::ExchangeEmbedMismatch`] when a named route carries an embed it cannot
    /// carry — or none at all — [`ClientError::MissingGroupAttribute`] when a multisig proposal's
    /// `a` block is missing a label the route requires, [`ClientError::Identifier`] when an
    /// identifier in that block is not a qualified prefix, and [`ClientError::Api`] when an embed
    /// does not decode.
    pub fn classify(message: &ExchangeRecord) -> Result<Self, ClientError> {
        let Some(route) = ExchangeRoute::parse(&message.route) else {
            return Ok(Self::Other {
                route: message.route.clone(),
            });
        };
        match route {
            ExchangeRoute::Multisig(route) => Ok(Self::Multisig(Box::new(MultisigProposal {
                route,
                attributes: GroupAttributes::parse(route, &message.attributes)?,
                proposed: multisig_embed(route, message)?,
            }))),
            ExchangeRoute::Ipex(route) => Ok(Self::Ipex(Box::new(IpexStep {
                route,
                payload: ipex_payload(route, message)?,
            }))),
        }
    }
}

impl TryFrom<&ExchangeRecord> for ClassifiedExchange {
    type Error = ClientError;

    fn try_from(message: &ExchangeRecord) -> Result<Self, Self::Error> {
        Self::classify(message)
    }
}

impl TryFrom<&ExchangeResource> for ClassifiedExchange {
    type Error = ClientError;

    fn try_from(resource: &ExchangeResource) -> Result<Self, Self::Error> {
        Self::classify(&resource.exn)
    }
}

impl TryFrom<&MultisigExchangeResource> for ClassifiedExchange {
    type Error = ClientError;

    /// The group form classifies identically to the plain one.
    ///
    /// Upstream this needs a second overload per function and eight extra `*Group` variants, and
    /// the five IPEX assertions have none — so `assertIpexGrant` on a group request returns an
    /// unnarrowed value. Here the wrapper differs and the message inside it does not.
    fn try_from(resource: &MultisigExchangeResource) -> Result<Self, Self::Error> {
        Self::classify(&resource.exn)
    }
}

/// Reads the embed a multisig proposal must carry, refusing one the route cannot hold.
fn multisig_embed(route: MultisigRoute, message: &ExchangeRecord) -> Result<ExchangeEmbeds, ClientError> {
    let embeds = decode_embeds(route.as_str(), expected_slot(route), message)?;
    if slot_of(&embeds.message) == expected_slot(route) {
        Ok(embeds)
    } else {
        Err(ClientError::ExchangeEmbedMismatch {
            route: route.as_str(),
            expected: expected_slot(route),
            found: slot_of(&embeds.message),
        })
    }
}

/// Reads what an IPEX step embeds.
fn ipex_payload(route: IpexRoute, message: &ExchangeRecord) -> Result<IpexPayload, ClientError> {
    match route {
        // Apply, agree, and admit declare `e: object` and embed nothing; Roadmap 6.12 already
        // recorded that neither attachment is ever non-empty.
        IpexRoute::Apply | IpexRoute::Agree | IpexRoute::Admit => Ok(IpexPayload::Empty),
        IpexRoute::Offer => {
            let block = embed_block(route.as_str(), "acdc", message)?;
            Ok(IpexPayload::Offer(Box::new(decode_block(block)?)))
        }
        IpexRoute::Grant => {
            let embeds = decode_embeds(route.as_str(), "acdc", message)?;
            if matches!(embeds.message, ExchangeEmbed::Issuance(_)) {
                Ok(IpexPayload::Grant(Box::new(embeds)))
            } else {
                Err(ClientError::ExchangeEmbedMismatch {
                    route: route.as_str(),
                    expected: "acdc",
                    found: slot_of(&embeds.message),
                })
            }
        }
    }
}

/// Returns the `e` block of a message that must have one.
fn embed_block<'a>(
    route: &'static str,
    expected: &'static str,
    message: &'a ExchangeRecord,
) -> Result<&'a Map<String, Value>, ClientError> {
    message
        .embeds
        .as_ref()
        .filter(|block| !block.is_empty())
        .ok_or(ClientError::ExchangeEmbedMismatch {
            route,
            expected,
            found: "nothing",
        })
}

/// Decodes the `e` block of a message that must carry one of Roadmap 4.1's embeds.
fn decode_embeds(
    route: &'static str,
    expected: &'static str,
    message: &ExchangeRecord,
) -> Result<ExchangeEmbeds, ClientError> {
    let block = embed_block(route, expected, message)?;
    decode_block(block)
}

/// Decodes one embed block into a typed shape.
///
/// The block arrives already parsed, so this is a re-interpretation rather than a second parse —
/// which is what keeps a malformed embed a typed failure instead of a panic.
fn decode_block<T: serde::de::DeserializeOwned>(block: &Map<String, Value>) -> Result<T, ClientError> {
    serde_json::from_value(Value::Object(block.clone())).map_err(|source| ClientError::Api {
        source: Box::new(signify_types::api::ApiError::Json {
            source: Box::new(source),
        }),
    })
}

/// Returns the wire label the embed occupies, which is how the union is discriminated.
const fn slot_of(embed: &ExchangeEmbed) -> &'static str {
    match embed {
        ExchangeEmbed::Inception(_) => "icp",
        ExchangeEmbed::Rotation(_) => "rot",
        ExchangeEmbed::Interaction(_) => "ixn",
        ExchangeEmbed::RegistryInception(_) => "vcp",
        ExchangeEmbed::Issuance(_) => "acdc",
        ExchangeEmbed::Revocation(_) => "rev",
        ExchangeEmbed::Reply(_) => "rpy",
        ExchangeEmbed::Exchange(_) => "exn",
    }
}

/// Returns the embed slot a multisig route must carry.
///
/// This is the correspondence that makes the check possible: Roadmap 4.1's eight embed variants and
/// the reference's eight multisig routes are the same eight things.
const fn expected_slot(route: MultisigRoute) -> &'static str {
    match route {
        MultisigRoute::Inception => "icp",
        MultisigRoute::Rotation => "rot",
        MultisigRoute::Interaction => "ixn",
        MultisigRoute::Reply => "rpy",
        MultisigRoute::RegistryInception => "vcp",
        MultisigRoute::Issuance => "acdc",
        MultisigRoute::Exchange => "exn",
        MultisigRoute::Revocation => "rev",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const GROUP: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
    const MEMBER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
    const SECOND: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";

    /// One message on `route`, with the given attribute and embed blocks.
    fn message(route: &str, attributes: &str, embeds: &str) -> Result<ExchangeRecord, Box<dyn Error>> {
        let document = format!(
            r#"{{"v":"KERI10JSON000100_","t":"exn","d":"EEXN","i":"{MEMBER}","rp":"{SECOND}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{attributes},"e":{embeds}}}"#
        );
        Ok(serde_json::from_str(&document)?)
    }

    /// An inception the `icp` slot accepts.
    const INCEPTION: &str = r#"{"v":"KERI10JSON000_","t":"icp","d":"EICP","i":"EGRP","s":"0","kt":"2","k":["DAA","DBB"],"nt":"2","n":["EAA","EBB"],"bt":"0","b":[],"c":[],"a":[]}"#;
    /// An interaction the `ixn` slot accepts.
    const INTERACTION: &str = r#"{"v":"KERI10JSON000_","t":"ixn","d":"EIXN","i":"EGRP","s":"1","p":"EICP","a":[]}"#;

    fn group_block() -> String {
        format!(
            r#"{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":["{MEMBER}"],"{ROTATION_MEMBERS_LABEL}":["{MEMBER}"]}}"#
        )
    }

    #[test]
    fn the_wire_labels_are_the_references_own() {
        assert_eq!(GROUP_LABEL, "gid");
        assert_eq!(SIGNING_MEMBERS_LABEL, "smids");
        assert_eq!(ROTATION_MEMBERS_LABEL, "rmids");
        assert_eq!(USAGE_LABEL, "usage");
    }

    #[test]
    fn an_inception_proposal_classifies_with_its_members() -> Result<(), Box<dyn Error>> {
        let embeds = format!(r#"{{"d":"EEMB","icp":{INCEPTION}}}"#);
        let classified = ClassifiedExchange::classify(&message("/multisig/icp", &group_block(), &embeds)?)?;

        let proposal = classified.as_multisig().ok_or("not a multisig proposal")?;
        assert_eq!(proposal.route, MultisigRoute::Inception);
        assert_eq!(proposal.attributes.group, IdentifierPrefix::from_qb64(GROUP)?);
        assert_eq!(
            proposal.attributes.signing_members,
            Some(vec![IdentifierPrefix::from_qb64(MEMBER)?])
        );
        assert_eq!(proposal.proposed.digest, "EEMB");
        assert!(matches!(proposal.proposed.message, ExchangeEmbed::Inception(_)));
        assert_eq!(
            classified.route(),
            Some(ExchangeRoute::Multisig(MultisigRoute::Inception))
        );
        Ok(())
    }

    #[test]
    fn a_route_that_promises_an_embed_it_does_not_carry_is_refused() -> Result<(), Box<dyn Error>> {
        // The reference's `assertMultisigIcp` accepts exactly this and hands the caller a value
        // whose `exn.e.icp` is `undefined` while typed as an inception.
        let outcome = ClassifiedExchange::classify(&message("/multisig/icp", &group_block(), "{}")?);
        assert!(
            matches!(
                outcome,
                Err(ClientError::ExchangeEmbedMismatch {
                    route: "/multisig/icp",
                    expected: "icp",
                    found: "nothing"
                })
            ),
            "{outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn a_route_carrying_another_routes_embed_is_refused() -> Result<(), Box<dyn Error>> {
        // An interaction proposed on the inception route: both are valid messages, and the pair is
        // not.
        let embeds = format!(r#"{{"d":"EEMB","ixn":{INTERACTION}}}"#);
        let outcome = ClassifiedExchange::classify(&message("/multisig/icp", &group_block(), &embeds)?);
        assert!(
            matches!(
                outcome,
                Err(ClientError::ExchangeEmbedMismatch {
                    route: "/multisig/icp",
                    expected: "icp",
                    found: "ixn"
                })
            ),
            "{outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn a_step_that_names_members_must_name_them() -> Result<(), Box<dyn Error>> {
        let embeds = format!(r#"{{"d":"EEMB","icp":{INCEPTION}}}"#);
        let bare = format!(r#"{{"{GROUP_LABEL}":"{GROUP}"}}"#);
        let outcome = ClassifiedExchange::classify(&message("/multisig/icp", &bare, &embeds)?);
        assert!(
            matches!(
                outcome,
                Err(ClientError::MissingGroupAttribute {
                    route: "/multisig/icp",
                    label: "smids"
                })
            ),
            "{outcome:?}"
        );

        // A step that does not name members is content with the group alone.
        let reply = r#"{"v":"KERI10JSON000_","t":"rpy","d":"ERPY","dt":"2023-11-14T22:13:20.123000+00:00","r":"/end/role/add","a":{}}"#;
        let classified = ClassifiedExchange::classify(&message(
            "/multisig/rpy",
            &bare,
            &format!(r#"{{"d":"E","rpy":{reply}}}"#),
        )?)?;
        let proposal = classified.as_multisig().ok_or("not a proposal")?;
        assert_eq!(proposal.route, MultisigRoute::Reply);
        assert_eq!(proposal.attributes.signing_members, None);
        Ok(())
    }

    #[test]
    fn a_proposal_with_no_group_is_refused() -> Result<(), Box<dyn Error>> {
        let embeds = format!(r#"{{"d":"EEMB","icp":{INCEPTION}}}"#);
        for block in ["{}", r#"{"smids":[]}"#, "[]", "null", r#""text""#] {
            let outcome = ClassifiedExchange::classify(&message("/multisig/icp", block, &embeds)?);
            assert!(
                matches!(outcome, Err(ClientError::MissingGroupAttribute { label: "gid", .. })),
                "{block} was accepted: {outcome:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_member_list_that_is_not_a_list_of_prefixes_is_refused() -> Result<(), Box<dyn Error>> {
        let embeds = format!(r#"{{"d":"EEMB","icp":{INCEPTION}}}"#);
        for members in [r#""not-a-list""#, "[7]", r#"["not a prefix"]"#, "{}"] {
            let block = format!(r#"{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":{members}}}"#);
            assert!(
                ClassifiedExchange::classify(&message("/multisig/icp", &block, &embeds)?).is_err(),
                "{members} was accepted as a member list"
            );
        }
        Ok(())
    }

    #[test]
    fn an_unrecognised_label_is_kept_rather_than_dropped() -> Result<(), Box<dyn Error>> {
        // The reference's variants declare an index signature, so the block is open.
        let embeds = format!(r#"{{"d":"EEMB","icp":{INCEPTION}}}"#);
        let block = format!(
            r#"{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":["{MEMBER}"],"anything":{{"nested":true}}}}"#
        );
        let classified = ClassifiedExchange::classify(&message("/multisig/icp", &block, &embeds)?)?;
        let proposal = classified.as_multisig().ok_or("not a proposal")?;
        assert_eq!(proposal.attributes.additional.len(), 1);
        assert!(proposal.attributes.additional.contains_key("anything"));
        // And the four declared labels are not duplicated into it.
        for label in [GROUP_LABEL, SIGNING_MEMBERS_LABEL, ROTATION_MEMBERS_LABEL, USAGE_LABEL] {
            assert!(!proposal.attributes.additional.contains_key(label));
        }
        Ok(())
    }

    #[test]
    fn a_registry_proposal_keeps_its_usage() -> Result<(), Box<dyn Error>> {
        let registry = r#"{"v":"KERI10JSON000_","t":"vcp","d":"EVCP","i":"EREG","ii":"EGRP","s":"0","c":["NB"],"bt":"0","b":[],"n":"AAAA"}"#;
        let anchor = r#"{"v":"KERI10JSON000_","t":"ixn","d":"EIXN","i":"EGRP","s":"1","p":"EICP","a":[]}"#;
        let block = format!(r#"{{"{GROUP_LABEL}":"{GROUP}","{USAGE_LABEL}":"Issue vLEIs"}}"#);
        let embeds = format!(r#"{{"d":"EEMB","vcp":{registry},"anc":{anchor}}}"#);

        let classified = ClassifiedExchange::classify(&message("/multisig/vcp", &block, &embeds)?)?;
        let proposal = classified.as_multisig().ok_or("not a proposal")?;
        assert_eq!(proposal.route, MultisigRoute::RegistryInception);
        assert_eq!(proposal.attributes.usage.as_deref(), Some("Issue vLEIs"));
        assert!(matches!(proposal.proposed.message, ExchangeEmbed::RegistryInception(_)));
        Ok(())
    }

    #[test]
    fn the_three_empty_ipex_steps_embed_nothing() -> Result<(), Box<dyn Error>> {
        for (route, expected) in [
            ("/ipex/apply", IpexRoute::Apply),
            ("/ipex/agree", IpexRoute::Agree),
            ("/ipex/admit", IpexRoute::Admit),
        ] {
            let classified = ClassifiedExchange::classify(&message(route, "{}", "{}")?)?;
            let step = classified.as_ipex().ok_or("not an IPEX step")?;
            assert_eq!(step.route, expected);
            assert_eq!(step.payload, IpexPayload::Empty);
            // And they carry no group attributes at all, which is why none is required.
            assert!(classified.as_multisig().is_none());
        }
        Ok(())
    }

    #[test]
    fn an_ipex_step_needs_no_group_attributes() -> Result<(), Box<dyn Error>> {
        // The five IPEX variants declare no `a` constraint, so an empty block is ordinary.
        let classified = ClassifiedExchange::classify(&message("/ipex/admit", r#"{"i":"EX","m":""}"#, "{}")?)?;
        assert!(classified.as_ipex().is_some());
        Ok(())
    }

    #[test]
    fn an_unnamed_route_classifies_rather_than_failing() -> Result<(), Box<dyn Error>> {
        // This crate's own `Challenges::respond` sends this route.
        let classified =
            ClassifiedExchange::classify(&message("/challenge/response", r#"{"words":["shell","gloom"]}"#, "{}")?)?;
        assert_eq!(
            classified,
            ClassifiedExchange::Other {
                route: "/challenge/response".to_owned()
            }
        );
        assert_eq!(classified.route(), None);
        assert!(classified.as_multisig().is_none());
        assert!(classified.as_ipex().is_none());
        Ok(())
    }

    #[test]
    fn an_unnamed_route_is_never_checked_for_a_payload() -> Result<(), Box<dyn Error>> {
        // Whatever an unnamed route carries, there is no promise to break.
        for embeds in ["{}", r#"{"d":"E","icp":7}"#, r#"{"anything":"at all"}"#] {
            let classified = ClassifiedExchange::classify(&message("/some/future/route", "{}", embeds)?)?;
            assert!(matches!(classified, ClassifiedExchange::Other { .. }));
        }
        Ok(())
    }

    #[test]
    fn a_guard_is_a_match_rather_than_a_function() -> Result<(), Box<dyn Error>> {
        // The whole of what thirteen `is*` functions offer, none of which the pinned tree calls.
        let embeds = format!(r#"{{"d":"EEMB","icp":{INCEPTION}}}"#);
        let classified = ClassifiedExchange::classify(&message("/multisig/icp", &group_block(), &embeds)?)?;
        assert!(matches!(
            classified.as_multisig().map(|proposal| proposal.route),
            Some(MultisigRoute::Inception)
        ));
        assert!(!matches!(
            classified.as_multisig().map(|proposal| proposal.route),
            Some(MultisigRoute::Rotation)
        ));
        Ok(())
    }

    #[test]
    fn a_group_request_classifies_as_the_plain_form_does() -> Result<(), Box<dyn Error>> {
        // Upstream this needs a second overload per function and eight extra `*Group` variants.
        let embeds = format!(r#"{{"d":"EEMB","icp":{INCEPTION}}}"#);
        let exn = message("/multisig/icp", &group_block(), &embeds)?;
        let plain = ExchangeResource {
            exn: exn.clone(),
            pathed: Map::new(),
        };
        let grouped = MultisigExchangeResource {
            exn,
            paths: Map::new(),
            group_name: Some("group".to_owned()),
            member_name: Some("member1".to_owned()),
            sender: Some(MEMBER.to_owned()),
        };
        assert_eq!(
            ClassifiedExchange::try_from(&plain)?,
            ClassifiedExchange::try_from(&grouped)?
        );
        Ok(())
    }

    #[test]
    fn every_multisig_route_expects_a_distinct_slot() {
        // The correspondence that makes the check possible: eight routes, eight embed variants.
        let slots: Vec<&str> = MultisigRoute::ALL.into_iter().map(expected_slot).collect();
        let unique: std::collections::BTreeSet<&str> = slots.iter().copied().collect();
        assert_eq!(unique.len(), 8, "two routes expect one slot: {slots:?}");
        // An issuance proposal is discriminated by its credential, which is also a grant's slot.
        assert_eq!(expected_slot(MultisigRoute::Issuance), "acdc");
    }
}
