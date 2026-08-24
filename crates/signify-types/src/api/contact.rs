//! Contacts, endpoint roles, challenges, notifications, and agent configuration.

use core::fmt;
use core::str::FromStr;
use std::collections::BTreeMap;
use std::convert::Infallible;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// A role one identifier authorizes another to play.
///
/// The schema is inconsistent about this: an OOBI's role is a nine-value enum while an end role's
/// is a bare string. KERI's role registry is extensible, so [`Role::Other`] carries anything else
/// rather than failing — the alternative would be a client that cannot read a contact because a
/// newer agent knows one more role than it does. The nine named variants are the ones the schema
/// declares, in declaration order.
///
/// ```
/// use signify_types::api::Role;
///
/// assert_eq!(Role::Witness.as_str(), "witness");
/// assert_eq!(Role::from("mailbox"), Role::Mailbox);
/// assert_eq!(Role::from("notary").as_str(), "notary");
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Role {
    /// The identifier's own controller.
    Controller,
    /// A witness.
    Witness,
    /// A registrar.
    Registrar,
    /// A watcher.
    Watcher,
    /// A judge.
    Judge,
    /// A juror.
    Juror,
    /// A peer.
    Peer,
    /// A mailbox.
    Mailbox,
    /// A KERIA agent.
    Agent,
    /// A role this crate does not name, kept exactly as received.
    Other(String),
}

impl Role {
    /// Every role the schema declares, in declaration order.
    pub const DECLARED: [Self; 9] = [
        Self::Controller,
        Self::Witness,
        Self::Registrar,
        Self::Watcher,
        Self::Judge,
        Self::Juror,
        Self::Peer,
        Self::Mailbox,
        Self::Agent,
    ];

    /// Returns the exact wire text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Controller => "controller",
            Self::Witness => "witness",
            Self::Registrar => "registrar",
            Self::Watcher => "watcher",
            Self::Judge => "judge",
            Self::Juror => "juror",
            Self::Peer => "peer",
            Self::Mailbox => "mailbox",
            Self::Agent => "agent",
            Self::Other(role) => role,
        }
    }

    /// Returns whether this role is one the schema declares.
    #[must_use]
    pub const fn is_declared(&self) -> bool {
        !matches!(self, Self::Other(_))
    }
}

impl From<&str> for Role {
    fn from(role: &str) -> Self {
        match role {
            "controller" => Self::Controller,
            "witness" => Self::Witness,
            "registrar" => Self::Registrar,
            "watcher" => Self::Watcher,
            "judge" => Self::Judge,
            "juror" => Self::Juror,
            "peer" => Self::Peer,
            "mailbox" => Self::Mailbox,
            "agent" => Self::Agent,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl From<String> for Role {
    fn from(role: String) -> Self {
        match Self::from(role.as_str()) {
            // Reuse the allocation the caller already made for an unnamed role.
            Self::Other(_) => Self::Other(role),
            named => named,
        }
    }
}

impl FromStr for Role {
    type Err = Infallible;

    fn from_str(role: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(role))
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for Role {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Role {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// The endpoints authorized for one role, keyed by endpoint identifier and then by URL scheme.
pub type RoleEndpoints = BTreeMap<String, BTreeMap<String, String>>;

/// The endpoints a contact has authorized, one entry per declared role.
///
/// Every field is required and nullable: KERIA writes `null` for a role with no endpoints rather
/// than omitting it, and that spelling is preserved. Unlike [`Role`], this record cannot grow a
/// tenth role without a schema change, which is why it is a struct rather than a map.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemberEnds {
    /// Agent endpoints.
    pub agent: Option<RoleEndpoints>,
    /// Controller endpoints.
    pub controller: Option<RoleEndpoints>,
    /// Witness endpoints.
    pub witness: Option<RoleEndpoints>,
    /// Registrar endpoints.
    pub registrar: Option<RoleEndpoints>,
    /// Watcher endpoints.
    pub watcher: Option<RoleEndpoints>,
    /// Judge endpoints.
    pub judge: Option<RoleEndpoints>,
    /// Juror endpoints.
    pub juror: Option<RoleEndpoints>,
    /// Peer endpoints.
    pub peer: Option<RoleEndpoints>,
    /// Mailbox endpoints.
    pub mailbox: Option<RoleEndpoints>,
}

impl MemberEnds {
    /// Returns the endpoints authorized for one role, if the schema names it and any are present.
    #[must_use]
    pub const fn role(&self, role: &Role) -> Option<&RoleEndpoints> {
        match role {
            Role::Agent => self.agent.as_ref(),
            Role::Controller => self.controller.as_ref(),
            Role::Witness => self.witness.as_ref(),
            Role::Registrar => self.registrar.as_ref(),
            Role::Watcher => self.watcher.as_ref(),
            Role::Judge => self.judge.as_ref(),
            Role::Juror => self.juror.as_ref(),
            Role::Peer => self.peer.as_ref(),
            Role::Mailbox => self.mailbox.as_ref(),
            Role::Other(_) => None,
        }
    }
}

/// A well-known URL a contact has published.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WellKnown {
    /// The URL.
    pub url: String,
    /// When it was recorded, wire label `dt`.
    #[serde(rename = "dt")]
    pub stamp: String,
}

/// A challenge exchanged to prove control of an identifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Challenge {
    /// The challenge words.
    pub words: Vec<String>,
    /// When the challenge was answered, wire label `dt`.
    #[serde(rename = "dt", default, skip_serializing_if = "Option::is_none")]
    pub stamp: Option<String>,
    /// SAID of the exchange message that answered it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub said: Option<String>,
    /// Whether the answer verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
}

/// One entry in the client's contact list.
///
/// The schema declares an open index signature, so any field KERIA adds is captured in
/// [`Contact::additional`] and survives a round trip.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Contact {
    /// Identifier prefix, wire label `id`.
    pub id: String,
    /// Local alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// The OOBI the contact was resolved from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oobi: Option<String>,
    /// Endpoints the contact has authorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ends: Option<MemberEnds>,
    /// Challenges exchanged with the contact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenges: Option<Vec<Challenge>>,
    /// Well-known URLs the contact has published, wire label `wellKnowns`.
    #[serde(rename = "wellKnowns", default, skip_serializing_if = "Option::is_none")]
    pub well_knowns: Option<Vec<WellKnown>>,
    /// Every field the schema does not name, preserved as received.
    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

/// One identifier and the endpoints it has authorized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AidRecord {
    /// Identifier prefix.
    pub aid: String,
    /// Endpoints it has authorized.
    pub ends: MemberEnds,
}

/// The members of a multisig group, by the authority they hold.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupMember {
    /// Members holding current signing authority.
    pub signing: Vec<AidRecord>,
    /// Members holding next-key authority.
    pub rotation: Vec<AidRecord>,
}

/// The payload of a notification.
///
/// The schema declares three optional fields and an open index signature.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct NotificationData {
    /// Route the notification concerns, wire label `r`.
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// SAID of the message it concerns, wire label `d`.
    #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Human-readable message, wire label `m`.
    #[serde(rename = "m", default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Every field the schema does not name, preserved as received.
    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

/// One notification KERIA is holding for the client.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Notification {
    /// Notification identifier, wire label `i`.
    #[serde(rename = "i")]
    pub id: String,
    /// When it was raised, wire label `dt`.
    #[serde(rename = "dt")]
    pub stamp: String,
    /// Whether the client has already read it, wire label `r`.
    #[serde(rename = "r")]
    pub read: bool,
    /// The payload, wire label `a`.
    #[serde(rename = "a")]
    pub attributes: NotificationData,
}

/// The OOBIs published for one role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Oobi {
    /// The role these OOBIs are for.
    pub role: Role,
    /// The OOBI URLs.
    pub oobis: Vec<String>,
}

/// One authorization of an endpoint role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndRole {
    /// Identifier prefix granting the role, wire label `cid`.
    pub cid: String,
    /// The role.
    ///
    /// The schema types this a bare string while typing an OOBI's role as an enum; both are [`Role`]
    /// here, which reads an unnamed role rather than refusing it.
    pub role: Role,
    /// Identifier prefix receiving the role, wire label `eid`.
    pub eid: String,
}

/// The agent's own configuration.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentConfig {
    /// Introduction OOBIs the agent resolves at startup, wire label `iurls`.
    #[serde(rename = "iurls", default, skip_serializing_if = "Option::is_none")]
    pub introduction_urls: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// A captured number too large for `i64`/`u64` does **not** survive its first re-encoding.
    ///
    /// Discovered by Roadmap 6.10's fuzz run. An undeclared field holding
    /// `133333333303333333333333` lands here as an `f64`, and `serde_json` writes a shortest form
    /// that reparses one unit in the last place away. From the *second* encoding onward it is a
    /// fixed point, which is the invariant the fuzz target asserts.
    ///
    /// This qualifies the round-trip guarantee for every record with a captured open field —
    /// [`Contact`], `ExternState`, `NotificationData`, `AcdcAttributes`, and `Schema.properties`.
    /// It is pinned rather than fixed because fixing it means `serde_json`'s `arbitrary_precision`,
    /// which changes number handling across the workspace and collides with ADR `0008`'s
    /// deliberately narrowed number space. `PORTING.md` §10 owns the decision.
    #[test]
    fn a_large_captured_number_loses_a_unit_in_the_last_place() -> Result<(), Box<dyn Error>> {
        let body = r#"{"id":"E","extra":133333333303333333333333}"#;
        let once: Contact = serde_json::from_str(body)?;
        let first = serde_json::to_string(&once)?;
        assert_eq!(first, r#"{"id":"E","extra":1.3333333330333333e+23}"#);

        let twice: Contact = serde_json::from_str(&first)?;
        let second = serde_json::to_string(&twice)?;
        assert_eq!(second, r#"{"id":"E","extra":1.3333333330333332e+23}"#);
        assert_ne!(once, twice, "the first re-encoding unexpectedly round-tripped");

        // Stable from here on, which is what makes a *stored* record safe to re-read.
        let thrice: Contact = serde_json::from_str(&second)?;
        assert_eq!(twice, thrice);
        assert_eq!(second, serde_json::to_string(&thrice)?);

        // A number inside the exact integer range is unaffected.
        let exact: Contact = serde_json::from_str(r#"{"id":"E","extra":9007199254740991}"#)?;
        let encoded = serde_json::to_string(&exact)?;
        assert_eq!(encoded, r#"{"id":"E","extra":9007199254740991}"#);
        assert_eq!(exact, serde_json::from_str::<Contact>(&encoded)?);
        Ok(())
    }

    #[test]
    fn a_declared_role_round_trips_and_an_unnamed_one_survives() -> Result<(), Box<dyn Error>> {
        for role in Role::DECLARED {
            let text = role.as_str().to_owned();
            assert_eq!(serde_json::to_string(&role)?, format!(r#""{text}""#));
            assert_eq!(serde_json::from_str::<Role>(&format!(r#""{text}""#))?, role);
            assert_eq!(role.to_string(), text);
            assert!(role.is_declared());
            assert_eq!(text.parse::<Role>()?, role);
        }

        // KERI's role registry is extensible, so an unknown role is read rather than refused.
        let unnamed: Role = serde_json::from_str(r#""notary""#)?;
        assert_eq!(unnamed, Role::Other("notary".to_owned()));
        assert!(!unnamed.is_declared());
        assert_eq!(serde_json::to_string(&unnamed)?, r#""notary""#);
        assert_eq!(Role::from("notary".to_owned()), unnamed);
        assert_eq!(Role::from("witness".to_owned()), Role::Witness);

        // A role must still be a string.
        assert!(serde_json::from_str::<Role>("1").is_err());
        Ok(())
    }

    #[test]
    fn member_ends_keeps_every_declared_role_and_its_nulls() -> Result<(), Box<dyn Error>> {
        let document = r#"{"agent":{"EAGT":{"http":"http://agent:3902/"}},"controller":null,"witness":null,"registrar":null,"watcher":null,"judge":null,"juror":null,"peer":null,"mailbox":null}"#;
        let ends: MemberEnds = serde_json::from_str(document)?;
        assert_eq!(
            ends.role(&Role::Agent)
                .and_then(|role| role.get("EAGT"))
                .map(BTreeMap::len),
            Some(1)
        );
        assert_eq!(ends.role(&Role::Witness), None);
        assert_eq!(ends.role(&Role::Other("notary".to_owned())), None);
        // The nulls are written back, because the schema requires every field to be present.
        assert_eq!(serde_json::to_string(&ends)?, document);
        assert_eq!(MemberEnds::default().agent, None);
        Ok(())
    }

    #[test]
    fn a_contact_preserves_the_fields_the_schema_does_not_name() -> Result<(), Box<dyn Error>> {
        let document = r#"{"id":"ECON","alias":"alice","oobi":"http://witness:5642/oobi/ECON","challenges":[{"words":["a","b"],"dt":"2023-08-19T21:04:57.948863+00:00","said":"EANS","authenticated":true}],"wellKnowns":[{"url":"https://example.test","dt":"2023-08-19T21:04:57.948863+00:00"}],"company":"Example"}"#;
        let contact: Contact = serde_json::from_str(document)?;
        assert_eq!(contact.alias.as_deref(), Some("alice"));
        assert_eq!(contact.challenges.as_ref().map(Vec::len), Some(1));
        assert_eq!(contact.well_knowns.as_ref().map(Vec::len), Some(1));
        assert_eq!(
            contact.additional.get("company").and_then(Value::as_str),
            Some("Example")
        );
        assert_eq!(serde_json::to_string(&contact)?, document);

        // Only `id` is required.
        let minimal: Contact = serde_json::from_str(r#"{"id":"ECON"}"#)?;
        assert_eq!(minimal.ends, None);
        assert_eq!(serde_json::to_string(&minimal)?, r#"{"id":"ECON"}"#);
        assert!(serde_json::from_str::<Contact>("{}").is_err());
        Ok(())
    }

    #[test]
    fn the_remaining_contact_records_round_trip() -> Result<(), Box<dyn Error>> {
        let ends = r#"{"agent":null,"controller":null,"witness":null,"registrar":null,"watcher":null,"judge":null,"juror":null,"peer":null,"mailbox":null}"#;
        let members = format!(r#"{{"signing":[{{"aid":"EMEM","ends":{ends}}}],"rotation":[]}}"#);
        let group: GroupMember = serde_json::from_str(&members)?;
        assert_eq!(group.signing.len(), 1);
        assert_eq!(group.signing.first().map(|record| record.aid.as_str()), Some("EMEM"));
        assert_eq!(serde_json::to_string(&group)?, members);

        let notification = r#"{"i":"0AB","dt":"2023-08-19T21:04:57.948863+00:00","r":false,"a":{"r":"/multisig/icp","d":"EEXN","m":"","extra":1}}"#;
        let decoded: Notification = serde_json::from_str(notification)?;
        assert!(!decoded.read);
        assert_eq!(decoded.attributes.route.as_deref(), Some("/multisig/icp"));
        assert_eq!(decoded.attributes.additional.len(), 1);
        assert_eq!(serde_json::to_string(&decoded)?, notification);
        assert_eq!(NotificationData::default().additional.len(), 0);

        let oobi = r#"{"role":"agent","oobis":["http://agent:3902/oobi/EAGT/agent/EAG2"]}"#;
        let decoded: Oobi = serde_json::from_str(oobi)?;
        assert_eq!(decoded.role, Role::Agent);
        assert_eq!(serde_json::to_string(&decoded)?, oobi);

        let end_role = r#"{"cid":"ECID","role":"agent","eid":"EEID"}"#;
        let decoded: EndRole = serde_json::from_str(end_role)?;
        assert_eq!(decoded.role, Role::Agent);
        assert_eq!(serde_json::to_string(&decoded)?, end_role);

        let config = r#"{"iurls":["http://witness:5642/oobi"]}"#;
        let decoded: AgentConfig = serde_json::from_str(config)?;
        assert_eq!(decoded.introduction_urls.as_ref().map(Vec::len), Some(1));
        assert_eq!(serde_json::to_string(&decoded)?, config);
        assert_eq!(serde_json::to_string(&AgentConfig::default())?, "{}");
        Ok(())
    }

    #[test]
    fn a_challenge_needs_only_its_words() -> Result<(), Box<dyn Error>> {
        let challenge: Challenge = serde_json::from_str(r#"{"words":["a"]}"#)?;
        assert_eq!(challenge.authenticated, None);
        assert_eq!(serde_json::to_string(&challenge)?, r#"{"words":["a"]}"#);
        assert!(serde_json::from_str::<Challenge>("{}").is_err());
        assert!(serde_json::from_str::<Challenge>(r#"{"words":"a"}"#).is_err());
        Ok(())
    }
}
