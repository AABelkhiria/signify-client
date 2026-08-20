//! Exchange resources and the messages a multisig exchange embeds.
//!
//! An exchange message can carry other messages inside its `e` block, each with the CESR
//! attachments that authorize it transposed alongside. KERIA returns those blocks typed by what
//! they carry: a group inception, a rotation, an interaction, a registry inception, an issuance, a
//! revocation, a reply, or another exchange.
//!
//! The schema types each embedded slot as a union of key-event shapes — the `icp` slot admits an
//! inception or a delegated inception and nothing else — which the bare `KeyEvent` enum is wider
//! than. Each slot therefore checks the ilk it decoded, so a rotation arriving in the `icp` slot is
//! a typed failure rather than a message a caller reads as an inception.
//!
//! Routes and route-specific payload shapes are not modelled here: the typed route table is Roadmap
//! 8.1, which owns the multisig and IPEX route constants and the guards upstream writes by hand.

use serde::de;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use super::credential::IssuanceEvent;
use super::error::ApiError;
use super::message::{AcdcRecord, ExchangeRecord, KeyEvent, RegistryInceptionRecord, ReplyRecord, RevocationRecord};

/// Ilks an inception slot accepts.
const INCEPTION_ILKS: &[&str] = &["icp", "dip"];
/// Ilks a rotation slot accepts.
const ROTATION_ILKS: &[&str] = &["rot", "drt"];
/// Ilks an interaction slot accepts.
const INTERACTION_ILKS: &[&str] = &["ixn"];

/// Refuses a message whose ilk the slot it arrived in cannot hold.
fn require_kind(event: KeyEvent, label: &'static str, expected: &'static [&'static str]) -> Result<KeyEvent, ApiError> {
    if expected.contains(&event.kind()) {
        Ok(event)
    } else {
        Err(ApiError::UnexpectedEventKind {
            label,
            found: event.kind(),
            expected,
        })
    }
}

/// Decodes an inception or delegated inception, refusing any other ilk.
fn deserialize_inception<'de, D: Deserializer<'de>>(deserializer: D) -> Result<KeyEvent, D::Error> {
    require_kind(KeyEvent::deserialize(deserializer)?, "icp", INCEPTION_ILKS).map_err(de::Error::custom)
}

/// Decodes a rotation or delegated rotation, refusing any other ilk.
fn deserialize_rotation<'de, D: Deserializer<'de>>(deserializer: D) -> Result<KeyEvent, D::Error> {
    require_kind(KeyEvent::deserialize(deserializer)?, "rot", ROTATION_ILKS).map_err(de::Error::custom)
}

/// Decodes an interaction, refusing any other ilk.
fn deserialize_interaction<'de, D: Deserializer<'de>>(deserializer: D) -> Result<KeyEvent, D::Error> {
    require_kind(KeyEvent::deserialize(deserializer)?, "ixn", INTERACTION_ILKS).map_err(de::Error::custom)
}

/// An exchange message together with the pathed attachments received with it.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExchangeResource {
    /// The exchange message.
    pub exn: ExchangeRecord,
    /// Attachments keyed by the path they were transposed under.
    pub pathed: Map<String, Value>,
}

/// A multisig group inception proposed inside an exchange message.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MultisigInceptionEmbed {
    /// The proposed inception or delegated inception.
    #[serde(deserialize_with = "deserialize_inception")]
    pub icp: KeyEvent,
}

/// A multisig group rotation proposed inside an exchange message.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MultisigRotationEmbed {
    /// The proposed rotation or delegated rotation.
    #[serde(deserialize_with = "deserialize_rotation")]
    pub rot: KeyEvent,
}

/// A multisig group interaction proposed inside an exchange message.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MultisigInteractionEmbed {
    /// The proposed interaction.
    #[serde(deserialize_with = "deserialize_interaction")]
    pub ixn: KeyEvent,
}

/// A registry inception proposed inside an exchange message.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MultisigRegistryInceptionEmbed {
    /// The proposed registry inception.
    pub vcp: RegistryInceptionRecord,
    /// The key event anchoring it, wire label `anc`.
    pub anc: KeyEvent,
}

/// A credential issuance proposed inside an exchange message.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MultisigIssuanceEmbed {
    /// The credential being issued.
    pub acdc: AcdcRecord,
    /// The TEL issuance event.
    pub iss: IssuanceEvent,
    /// The key event anchoring it, wire label `anc`.
    pub anc: KeyEvent,
}

/// A credential revocation proposed inside an exchange message.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MultisigRevocationEmbed {
    /// The TEL revocation event.
    pub rev: RevocationRecord,
    /// The key event anchoring it, wire label `anc`.
    pub anc: KeyEvent,
}

/// A reply proposed inside an exchange message.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MultisigReplyEmbed {
    /// The proposed reply.
    pub rpy: ReplyRecord,
}

/// Another exchange message embedded inside one.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MultisigExchangeEmbed {
    /// The embedded exchange message.
    pub exn: ExchangeRecord,
}

/// Which kind of message an exchange embeds.
///
/// The variants are told apart by the field names they carry, which is how the schema's union is
/// discriminated: the slot name *is* the tag.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ExchangeEmbed {
    /// A group inception.
    Inception(MultisigInceptionEmbed),
    /// A group rotation.
    Rotation(MultisigRotationEmbed),
    /// A group interaction.
    Interaction(MultisigInteractionEmbed),
    /// A registry inception and its anchor.
    RegistryInception(Box<MultisigRegistryInceptionEmbed>),
    /// A credential issuance and its anchor.
    Issuance(Box<MultisigIssuanceEmbed>),
    /// A credential revocation and its anchor.
    Revocation(Box<MultisigRevocationEmbed>),
    /// A reply.
    Reply(Box<MultisigReplyEmbed>),
    /// Another exchange message.
    Exchange(Box<MultisigExchangeEmbed>),
}

/// The embed block of an exchange message: its own SAID plus the message it carries.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExchangeEmbeds {
    /// SAID of the embed block itself, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// The embedded message.
    #[serde(flatten)]
    pub message: ExchangeEmbed,
}

/// An exchange message a multisig group is collecting signatures for.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MultisigExchangeResource {
    /// The exchange message.
    pub exn: ExchangeRecord,
    /// Attachments keyed by the path they were transposed under.
    pub paths: Map<String, Value>,
    /// Local alias of the group, wire label `groupName`.
    #[serde(rename = "groupName", default, skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    /// Local alias of the member sending it, wire label `memberName`.
    #[serde(rename = "memberName", default, skip_serializing_if = "Option::is_none")]
    pub member_name: Option<String>,
    /// Identifier prefix of the sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const INCEPTION: &str = r#"{"v":"KERI10JSON000_","t":"icp","d":"EICP","i":"EGRP","s":"0","kt":"2","k":["DAA","DBB"],"nt":"2","n":["EAA","EBB"],"bt":"0","b":[],"c":[],"a":[]}"#;
    const INTERACTION: &str = r#"{"v":"KERI10JSON000_","t":"ixn","d":"EIXN","i":"EGRP","s":"1","p":"EICP","a":[]}"#;
    const EXCHANGE: &str = r#"{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"EMEM","rp":"EPEER","p":"","dt":"2023-08-19T21:04:57.948863+00:00","r":"/multisig/icp","q":{},"a":{},"e":{}}"#;

    #[test]
    fn an_embed_slot_refuses_a_message_it_cannot_hold() {
        // The `icp` slot admits an inception or a delegated inception, and nothing else.
        let wrong = format!(r#"{{"icp":{INTERACTION}}}"#);
        let error = serde_json::from_str::<MultisigInceptionEmbed>(&wrong)
            .map(|_| ())
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(error.contains("ixn"), "{error}");

        let wrong = format!(r#"{{"rot":{INCEPTION}}}"#);
        assert!(serde_json::from_str::<MultisigRotationEmbed>(&wrong).is_err());

        let wrong = format!(r#"{{"ixn":{INCEPTION}}}"#);
        assert!(serde_json::from_str::<MultisigInteractionEmbed>(&wrong).is_err());
    }

    #[test]
    fn an_embed_slot_accepts_both_ilks_the_schema_names() -> Result<(), Box<dyn Error>> {
        let delegated = INCEPTION
            .replace(r#""t":"icp""#, r#""t":"dip""#)
            .replace(r#""a":[]}"#, r#""a":[],"di":"EDEL"}"#);
        let document = format!(r#"{{"icp":{delegated}}}"#);
        let embed: MultisigInceptionEmbed = serde_json::from_str(&document)?;
        assert_eq!(embed.icp.kind(), "dip");
        assert_eq!(serde_json::to_string(&embed)?, document);

        let document = format!(r#"{{"icp":{INCEPTION}}}"#);
        let embed: MultisigInceptionEmbed = serde_json::from_str(&document)?;
        assert_eq!(embed.icp.kind(), "icp");
        assert_eq!(serde_json::to_string(&embed)?, document);
        Ok(())
    }

    #[test]
    fn the_embed_block_chooses_its_variant_by_slot_name() -> Result<(), Box<dyn Error>> {
        let document = format!(r#"{{"d":"EEMB","icp":{INCEPTION}}}"#);
        let embeds: ExchangeEmbeds = serde_json::from_str(&document)?;
        assert_eq!(embeds.digest, "EEMB");
        assert!(matches!(embeds.message, ExchangeEmbed::Inception(_)));
        assert_eq!(serde_json::to_string(&embeds)?, document);

        let document = format!(r#"{{"d":"EEMB","ixn":{INTERACTION}}}"#);
        let embeds: ExchangeEmbeds = serde_json::from_str(&document)?;
        assert!(matches!(embeds.message, ExchangeEmbed::Interaction(_)));
        assert_eq!(serde_json::to_string(&embeds)?, document);

        let document = format!(r#"{{"d":"EEMB","exn":{EXCHANGE}}}"#);
        let embeds: ExchangeEmbeds = serde_json::from_str(&document)?;
        assert!(matches!(embeds.message, ExchangeEmbed::Exchange(_)));
        assert_eq!(serde_json::to_string(&embeds)?, document);

        // A block naming no slot the schema knows about matches no variant.
        assert!(serde_json::from_str::<ExchangeEmbeds>(r#"{"d":"EEMB","rct":{}}"#).is_err());
        Ok(())
    }

    #[test]
    fn a_credential_embed_carries_its_anchor() -> Result<(), Box<dyn Error>> {
        let acdc = r#"{"v":"ACDC10JSON000_","d":"ECRED","i":"EISS","ri":"EREG","s":"ESCH"}"#;
        let iss = r#"{"v":"KERI10JSON0000ed_","t":"iss","d":"EISSEV","i":"ECRED","s":"0","ri":"EREG","dt":"2023-08-19T21:04:57.948863+00:00"}"#;
        let document = format!(r#"{{"d":"EEMB","acdc":{acdc},"iss":{iss},"anc":{INTERACTION}}}"#);
        let embeds: ExchangeEmbeds = serde_json::from_str(&document)?;
        let ExchangeEmbed::Issuance(embed) = &embeds.message else {
            return Err("an issuance block decoded as something else".into());
        };
        assert_eq!(embed.acdc.digest, "ECRED");
        assert_eq!(embed.anc.kind(), "ixn");
        assert_eq!(serde_json::to_string(&embeds)?, document);

        let rev = r#"{"v":"KERI10JSON000_","t":"rev","d":"EREV","i":"ECRED","s":"1","ri":"EREG","p":"EISSEV","dt":"2023-08-19T21:04:57.948863+00:00"}"#;
        let document = format!(r#"{{"d":"EEMB","rev":{rev},"anc":{INTERACTION}}}"#);
        let embeds: ExchangeEmbeds = serde_json::from_str(&document)?;
        assert!(matches!(embeds.message, ExchangeEmbed::Revocation(_)));
        assert_eq!(serde_json::to_string(&embeds)?, document);
        Ok(())
    }

    #[test]
    fn the_exchange_resources_round_trip() -> Result<(), Box<dyn Error>> {
        let document = format!(r#"{{"exn":{EXCHANGE},"pathed":{{"acdc":"-IAB"}}}}"#);
        let resource: ExchangeResource = serde_json::from_str(&document)?;
        assert_eq!(resource.exn.route, "/multisig/icp");
        assert_eq!(resource.pathed.len(), 1);
        assert_eq!(serde_json::to_string(&resource)?, document);

        let document = format!(
            r#"{{"exn":{EXCHANGE},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"EMEM"}}"#
        );
        let resource: MultisigExchangeResource = serde_json::from_str(&document)?;
        assert_eq!(resource.group_name.as_deref(), Some("multisig"));
        assert_eq!(resource.sender.as_deref(), Some("EMEM"));
        assert_eq!(serde_json::to_string(&resource)?, document);

        let minimal = format!(r#"{{"exn":{EXCHANGE},"paths":{{}}}}"#);
        let resource: MultisigExchangeResource = serde_json::from_str(&minimal)?;
        assert_eq!(resource.member_name, None);
        assert_eq!(serde_json::to_string(&resource)?, minimal);
        Ok(())
    }

    #[test]
    fn a_registry_or_reply_embed_round_trips() -> Result<(), Box<dyn Error>> {
        let vcp = r#"{"v":"KERI10JSON000_","t":"vcp","d":"EVCP","i":"EREG","ii":"EISS","s":"0","c":["NB"],"bt":"0","b":[],"n":"AKl"}"#;
        let document = format!(r#"{{"d":"EEMB","vcp":{vcp},"anc":{INTERACTION}}}"#);
        let embeds: ExchangeEmbeds = serde_json::from_str(&document)?;
        assert!(matches!(embeds.message, ExchangeEmbed::RegistryInception(_)));
        assert_eq!(serde_json::to_string(&embeds)?, document);

        let rpy = r#"{"v":"KERI10JSON000_","t":"rpy","d":"ERPY","dt":"2023-08-19T21:04:57.948863+00:00","r":"/end/role/add","a":{}}"#;
        let document = format!(r#"{{"d":"EEMB","rpy":{rpy}}}"#);
        let embeds: ExchangeEmbeds = serde_json::from_str(&document)?;
        assert!(matches!(embeds.message, ExchangeEmbed::Reply(_)));
        assert_eq!(serde_json::to_string(&embeds)?, document);
        Ok(())
    }
}
