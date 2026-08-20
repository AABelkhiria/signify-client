//! Credentials, credential status, and registries.

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::message::{AcdcRecord, Anchor, KeyEvent, Schema, Seal};

/// An object the schema declares as having no properties at all.
///
/// The schema writes this `Record<string, never>`, and uses it for the revocation anchor of a
/// credential whose registry has no backers. Decoding refuses a document that carries anything,
/// because a value there would mean the credential is backed after all.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyObject {}

/// Whether a credential issuance is backed by a registry backer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum IssuanceKind {
    /// Unbacked issuance, ilk `iss`.
    #[serde(rename = "iss")]
    Unbacked,
    /// Backed issuance, ilk `bis`.
    #[serde(rename = "bis")]
    Backed,
}

/// The TEL issuance event a credential was issued by.
///
/// The schema declares this shape twice: once as `IssEvent`, whose `t` is a two-value enum, and
/// once as `ISS_V_1`, whose `t` is a bare string. One record covers both and takes the stricter
/// spelling, so a `t` outside `iss` and `bis` is refused wherever the event appears.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssuanceEvent {
    /// Version string, wire label `v`.
    #[serde(rename = "v")]
    pub version: String,
    /// Event kind, wire label `t`.
    #[serde(rename = "t")]
    pub kind: IssuanceKind,
    /// Event SAID, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Credential SAID, wire label `i`.
    #[serde(rename = "i")]
    pub credential: String,
    /// Sequence number in the credential's TEL, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Registry identifier, wire label `ri`.
    #[serde(rename = "ri")]
    pub registry: String,
    /// Timestamp, wire label `dt`.
    #[serde(rename = "dt")]
    pub stamp: String,
}

/// Status of a credential in a registry with no backers.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum UnbackedCredentialStatus {
    /// Issued, ilk `iss`.
    #[serde(rename = "iss")]
    Issued,
    /// Revoked, ilk `rev`.
    #[serde(rename = "rev")]
    Revoked,
}

/// Status of a credential in a registry with backers.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum BackedCredentialStatus {
    /// Backed issuance, ilk `bis`.
    #[serde(rename = "bis")]
    Issued,
    /// Backed revocation, ilk `brv`.
    #[serde(rename = "brv")]
    Revoked,
}

/// Where a backed credential's registry stood when its status changed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationAnchor {
    /// Registry identifier, wire label `i`.
    #[serde(rename = "i")]
    pub registry: String,
    /// Registry sequence number, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Registry event digest, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
}

/// The status of a credential whose registry has no backers.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UnbackedCredentialState {
    /// Protocol version as `[major, minor]`, wire label `vn`.
    #[serde(rename = "vn")]
    pub version: Vec<u32>,
    /// Credential SAID, wire label `i`.
    #[serde(rename = "i")]
    pub credential: String,
    /// Sequence number in the credential's TEL, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Digest of the TEL event that set this status, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Registry identifier, wire label `ri`.
    #[serde(rename = "ri")]
    pub registry: String,
    /// The seal anchoring the TEL event in the issuer's key event log, wire label `a`.
    #[serde(rename = "a")]
    pub anchor: Seal,
    /// Timestamp, wire label `dt`.
    #[serde(rename = "dt")]
    pub stamp: String,
    /// Whether the credential is issued or revoked, wire label `et`.
    #[serde(rename = "et")]
    pub status: UnbackedCredentialStatus,
    /// Always empty for an unbacked credential, wire label `ra`.
    #[serde(rename = "ra")]
    pub registry_anchor: EmptyObject,
}

/// The status of a credential whose registry has backers.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BackedCredentialState {
    /// Protocol version as `[major, minor]`, wire label `vn`.
    #[serde(rename = "vn")]
    pub version: Vec<u32>,
    /// Credential SAID, wire label `i`.
    #[serde(rename = "i")]
    pub credential: String,
    /// Sequence number in the credential's TEL, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Digest of the TEL event that set this status, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Registry identifier, wire label `ri`.
    #[serde(rename = "ri")]
    pub registry: String,
    /// The seal anchoring the TEL event in the issuer's key event log, wire label `a`.
    #[serde(rename = "a")]
    pub anchor: Seal,
    /// Timestamp, wire label `dt`.
    #[serde(rename = "dt")]
    pub stamp: String,
    /// Whether the credential is issued or revoked, wire label `et`.
    #[serde(rename = "et")]
    pub status: BackedCredentialStatus,
    /// Where the registry stood when the status changed, wire label `ra`.
    #[serde(rename = "ra")]
    pub registry_anchor: RevocationAnchor,
}

/// The status of one credential.
///
/// The `et` field chooses the variant: `iss` and `rev` describe a registry with no backers, whose
/// `ra` is therefore empty, while `bis` and `brv` describe a backed one, whose `ra` names where the
/// registry stood.
#[derive(Clone, Debug, PartialEq)]
pub enum CredentialState {
    /// A credential in a registry with no backers.
    Unbacked(UnbackedCredentialState),
    /// A credential in a registry with backers.
    Backed(BackedCredentialState),
}

/// Every `et` value [`CredentialState`] accepts, in the schema's order.
pub const CREDENTIAL_STATUS_KINDS: &[&str] = &["iss", "rev", "bis", "brv"];

impl CredentialState {
    /// Returns the `et` value this status carries.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        match self {
            Self::Unbacked(state) => match state.status {
                UnbackedCredentialStatus::Issued => "iss",
                UnbackedCredentialStatus::Revoked => "rev",
            },
            Self::Backed(state) => match state.status {
                BackedCredentialStatus::Issued => "bis",
                BackedCredentialStatus::Revoked => "brv",
            },
        }
    }

    /// Returns whether the credential is currently revoked.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        match self {
            Self::Unbacked(state) => matches!(state.status, UnbackedCredentialStatus::Revoked),
            Self::Backed(state) => matches!(state.status, BackedCredentialStatus::Revoked),
        }
    }

    /// Returns the credential SAID this status describes.
    #[must_use]
    pub fn credential(&self) -> &str {
        match self {
            Self::Unbacked(state) => &state.credential,
            Self::Backed(state) => &state.credential,
        }
    }
}

impl Serialize for CredentialState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unbacked(state) => state.serialize(serializer),
            Self::Backed(state) => state.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for CredentialState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let document = Value::deserialize(deserializer)?;
        let kind = document
            .get("et")
            .and_then(Value::as_str)
            .ok_or_else(|| de::Error::missing_field("et"))?
            .to_owned();
        let state = match kind.as_str() {
            "iss" | "rev" => serde_json::from_value(document).map(Self::Unbacked),
            "bis" | "brv" => serde_json::from_value(document).map(Self::Backed),
            other => return Err(de::Error::unknown_variant(other, CREDENTIAL_STATUS_KINDS)),
        };
        state.map_err(de::Error::custom)
    }
}

/// A credential together with everything KERIA knows about it.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Credential {
    /// The credential itself.
    pub sad: AcdcRecord,
    /// CESR attachments received with the credential, wire label `atc`.
    pub atc: String,
    /// The TEL issuance event.
    pub iss: IssuanceEvent,
    /// CESR attachments received with the issuance event, wire label `issatc`.
    pub issatc: String,
    /// Issuer identifier prefix, wire label `pre`.
    pub pre: String,
    /// The schema the credential claims to satisfy.
    pub schema: Schema,
    /// Credentials this one chains to.
    pub chains: Vec<Map<String, Value>>,
    /// Current status.
    pub status: CredentialState,
    /// The event anchoring the issuance in the issuer's key event log.
    pub anchor: Anchor,
    /// That anchoring event itself, wire label `anc`.
    pub anc: KeyEvent,
    /// CESR attachments received with the anchoring event, wire label `ancatc`.
    pub ancatc: Vec<String>,
}

/// Whether a registry event created a registry or rotated its backers.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum RegistryEventKind {
    /// Registry inception, ilk `vcp`.
    #[serde(rename = "vcp")]
    Inception,
    /// Backer rotation, ilk `vrt`.
    #[serde(rename = "vrt")]
    BackerRotation,
}

/// The current state of a credential registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryState {
    /// Protocol version as `[major, minor]`, wire label `vn`.
    #[serde(rename = "vn")]
    pub version: Vec<u32>,
    /// Registry identifier, wire label `i`.
    #[serde(rename = "i")]
    pub registry: String,
    /// Sequence number of the latest registry event, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Digest of the latest registry event, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Issuer identifier prefix, wire label `ii`.
    #[serde(rename = "ii")]
    pub issuer: String,
    /// Timestamp, wire label `dt`.
    #[serde(rename = "dt")]
    pub stamp: String,
    /// Kind of the latest registry event, wire label `et`.
    #[serde(rename = "et")]
    pub kind: RegistryEventKind,
    /// Backer threshold, wire label `bt`.
    #[serde(rename = "bt")]
    pub backer_threshold: String,
    /// Backer identifier prefixes, wire label `b`.
    #[serde(rename = "b")]
    pub backers: Vec<String>,
    /// Configuration traits, wire label `c`.
    #[serde(rename = "c")]
    pub configuration: Vec<String>,
}

/// A credential registry as KERIA lists it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Registry {
    /// Local alias the client gave this registry.
    pub name: String,
    /// Registry identifier, wire label `regk`.
    pub regk: String,
    /// Identifier prefix that owns it, wire label `pre`.
    pub pre: String,
    /// Current registry state.
    pub state: RegistryState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const UNBACKED: &str = r#"{"vn":[1,0],"i":"ECRED","s":"0","d":"EAB","ri":"EREG","a":{"s":"1","d":"EANC"},"dt":"2023-08-19T21:04:57.948863+00:00","et":"iss","ra":{}}"#;
    const BACKED: &str = r#"{"vn":[1,0],"i":"ECRED","s":"1","d":"EAB","ri":"EREG","a":{"s":"2","d":"EANC"},"dt":"2023-08-19T21:04:57.948863+00:00","et":"brv","ra":{"i":"EREG","s":"1","d":"EREGEV"}}"#;

    #[test]
    fn the_status_field_chooses_the_registry_shape() -> Result<(), Box<dyn Error>> {
        let state: CredentialState = serde_json::from_str(UNBACKED)?;
        assert!(matches!(state, CredentialState::Unbacked(_)));
        assert_eq!(state.status(), "iss");
        assert!(!state.is_revoked());
        assert_eq!(state.credential(), "ECRED");
        assert_eq!(serde_json::to_string(&state)?, UNBACKED);

        let state: CredentialState = serde_json::from_str(BACKED)?;
        assert!(matches!(state, CredentialState::Backed(_)));
        assert_eq!(state.status(), "brv");
        assert!(state.is_revoked());
        assert_eq!(serde_json::to_string(&state)?, BACKED);
        Ok(())
    }

    #[test]
    fn a_status_outside_the_four_declared_values_is_refused() {
        for kind in ["vcp", "icp", "ISS", ""] {
            let document = UNBACKED.replace(r#""et":"iss""#, &format!(r#""et":"{kind}""#));
            assert!(
                serde_json::from_str::<CredentialState>(&document).is_err(),
                "status {kind:?} was accepted"
            );
        }
        assert!(serde_json::from_str::<CredentialState>(r#"{"vn":[1,0]}"#).is_err());
    }

    #[test]
    fn an_unbacked_status_cannot_carry_a_registry_anchor() {
        // `ra` is `Record<string, never>` on this arm: a value there would contradict the `et`.
        let document = UNBACKED.replace(r#""ra":{}"#, r#""ra":{"i":"EREG","s":"1","d":"EREGEV"}"#);
        assert!(serde_json::from_str::<CredentialState>(&document).is_err());
        assert!(serde_json::from_str::<EmptyObject>(r#"{"a":1}"#).is_err());
    }

    #[test]
    fn a_backed_status_requires_its_registry_anchor() {
        let document = BACKED.replace(r#""ra":{"i":"EREG","s":"1","d":"EREGEV"}"#, r#""ra":{}"#);
        assert!(serde_json::from_str::<CredentialState>(&document).is_err());
    }

    #[test]
    fn an_issuance_event_takes_the_stricter_of_the_two_schema_spellings() -> Result<(), Box<dyn Error>> {
        let document = r#"{"v":"KERI10JSON0000ed_","t":"iss","d":"EAB","i":"ECRED","s":"0","ri":"EREG","dt":"2023-08-19T21:04:57.948863+00:00"}"#;
        let event: IssuanceEvent = serde_json::from_str(document)?;
        assert_eq!(event.kind, IssuanceKind::Unbacked);
        assert_eq!(event.credential, "ECRED");
        assert_eq!(serde_json::to_string(&event)?, document);

        let backed = document.replace(r#""t":"iss""#, r#""t":"bis""#);
        let event: IssuanceEvent = serde_json::from_str(&backed)?;
        assert_eq!(event.kind, IssuanceKind::Backed);

        // `ISS_V_1` types `t` as a bare string; this record does not.
        for kind in ["rev", "icp", ""] {
            let wrong = document.replace(r#""t":"iss""#, &format!(r#""t":"{kind}""#));
            assert!(
                serde_json::from_str::<IssuanceEvent>(&wrong).is_err(),
                "ilk {kind:?} was accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn a_registry_round_trips_with_its_state() -> Result<(), Box<dyn Error>> {
        let document = r#"{"name":"vLEI","regk":"EREG","pre":"EISS","state":{"vn":[1,0],"i":"EREG","s":"0","d":"EAB","ii":"EISS","dt":"2023-08-19T21:04:57.948863+00:00","et":"vcp","bt":"0","b":[],"c":["NB"]}}"#;
        let registry: Registry = serde_json::from_str(document)?;
        assert_eq!(registry.state.kind, RegistryEventKind::Inception);
        assert_eq!(registry.state.configuration, ["NB"]);
        assert_eq!(serde_json::to_string(&registry)?, document);

        let rotated = document.replace(r#""et":"vcp""#, r#""et":"vrt""#);
        let registry: Registry = serde_json::from_str(&rotated)?;
        assert_eq!(registry.state.kind, RegistryEventKind::BackerRotation);

        let wrong = document.replace(r#""et":"vcp""#, r#""et":"iss""#);
        assert!(serde_json::from_str::<Registry>(&wrong).is_err());
        Ok(())
    }

    #[test]
    fn a_credential_carries_every_artifact_keria_knows_about_it() -> Result<(), Box<dyn Error>> {
        let sad = r#"{"v":"ACDC10JSON000_","d":"ECRED","i":"EISS","ri":"EREG","s":"ESCH","a":{"d":"EATT","i":"EHOLD","LEI":"254900OP"}}"#;
        let iss = r#"{"v":"KERI10JSON0000ed_","t":"iss","d":"EISSEV","i":"ECRED","s":"0","ri":"EREG","dt":"2023-08-19T21:04:57.948863+00:00"}"#;
        let schema = r#"{"$id":"ESCH","$schema":"http://json-schema.org/draft-07/schema#","title":"t","description":"d","type":"object","credentialType":"c","version":"1.0.0","properties":{},"additionalProperties":false,"required":[]}"#;
        let anc = r#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EANC","i":"EISS","s":"1","p":"EPP","a":[]}"#;
        let document = format!(
            r#"{{"sad":{sad},"atc":"-AAB","iss":{iss},"issatc":"-AAC","pre":"EISS","schema":{schema},"chains":[],"status":{UNBACKED},"anchor":{{"pre":"EISS","sn":1,"d":"EANC"}},"anc":{anc},"ancatc":["-AAD"]}}"#
        );
        let credential: Credential = serde_json::from_str(&document)?;
        assert_eq!(credential.sad.digest, "ECRED");
        assert_eq!(credential.iss.kind, IssuanceKind::Unbacked);
        assert_eq!(credential.anc.kind(), "ixn");
        assert_eq!(credential.ancatc, ["-AAD"]);
        assert!(!credential.status.is_revoked());
        // The credential's attribute block is open, and an open block re-encodes in sorted key
        // order rather than the order received, so the documents are compared rather than the
        // bytes. Everything outside such a block is byte-exact, which the other tests assert.
        assert_eq!(
            serde_json::from_str::<Value>(&serde_json::to_string(&credential)?)?,
            serde_json::from_str::<Value>(&document)?
        );
        Ok(())
    }
}
