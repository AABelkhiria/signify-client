//! Key state as KERIA reports it, and the agent/controller pair returned when a client connects.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::message::{KeyEvent, Threshold};

/// The establishment-event summary a key state carries.
///
/// Upstream calls this `StateEERecord` in the schema and re-exports it as `EstablishmentState`;
/// the second name is used here. `br` and `ba` are typed `unknown[]` by the schema, so the witness
/// prefixes they carry stay as received rather than being narrowed to something the schema does not
/// promise.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EstablishmentState {
    /// Sequence number of the latest establishment event, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Digest of the latest establishment event, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// Witnesses the event cut, wire label `br`.
    #[serde(rename = "br", default, skip_serializing_if = "Option::is_none")]
    pub witnesses_removed: Option<Vec<Value>>,
    /// Witnesses the event added, wire label `ba`.
    #[serde(rename = "ba", default, skip_serializing_if = "Option::is_none")]
    pub witnesses_added: Option<Vec<Value>>,
}

/// The current key state of one identifier.
///
/// Upstream calls this `KeyStateRecord` in the schema and re-exports it as `KeyState`; the second
/// name is used here.
///
/// The sequence number, first-seen ordinal, and witness threshold stay as text. KERI writes them as
/// lowercase hexadecimal, but the pinned upstream tests declare key states whose `s`, `f`, `bt`, and
/// `kt` are the empty string, so narrowing them to an integer here would refuse a document the
/// reference accepts. Parsing them is `signify-cesr::number`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct KeyState {
    /// Protocol version as `[major, minor]`, wire label `vn`.
    #[serde(rename = "vn", default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Vec<u32>>,
    /// Identifier prefix, wire label `i`.
    #[serde(rename = "i")]
    pub identifier: String,
    /// Sequence number of the latest event, wire label `s`.
    #[serde(rename = "s")]
    pub sequence_number: String,
    /// Prior event digest, wire label `p`.
    #[serde(rename = "p")]
    pub prior: String,
    /// Digest of the latest event, wire label `d`.
    #[serde(rename = "d")]
    pub digest: String,
    /// First-seen ordinal of the latest event, wire label `f`.
    #[serde(rename = "f")]
    pub first_seen: String,
    /// Timestamp of the latest event, wire label `dt`.
    #[serde(rename = "dt")]
    pub stamp: String,
    /// Ilk of the latest establishment event, wire label `et`.
    ///
    /// The schema types this as a bare string rather than an ilk enum, and it is not the `t` of the
    /// document being decoded, so it is not narrowed here.
    #[serde(rename = "et")]
    pub establishment_kind: String,
    /// Current signing threshold, wire label `kt`.
    #[serde(rename = "kt")]
    pub signing_threshold: Threshold,
    /// Current signing keys, wire label `k`.
    #[serde(rename = "k")]
    pub signing_keys: Vec<String>,
    /// Next signing threshold, wire label `nt`.
    #[serde(rename = "nt")]
    pub next_threshold: Threshold,
    /// Digests committing to the next signing keys, wire label `n`.
    #[serde(rename = "n")]
    pub next_key_digests: Vec<String>,
    /// Witness threshold, wire label `bt`.
    #[serde(rename = "bt")]
    pub witness_threshold: String,
    /// Witness identifier prefixes, wire label `b`.
    #[serde(rename = "b")]
    pub witnesses: Vec<String>,
    /// Configuration traits, wire label `c`.
    #[serde(rename = "c")]
    pub configuration: Vec<String>,
    /// Latest establishment event summary, wire label `ee`.
    #[serde(rename = "ee")]
    pub latest_establishment_event: EstablishmentState,
    /// Delegator identifier prefix, wire label `di`; empty when the identifier is not delegated.
    #[serde(rename = "di")]
    pub delegator: String,
}

impl KeyState {
    /// Returns the delegator prefix, or `None` when this identifier is not delegated.
    ///
    /// KERIA writes an empty string rather than omitting the field, which is easy to mistake for a
    /// prefix.
    #[must_use]
    pub fn delegator(&self) -> Option<&str> {
        (!self.delegator.is_empty()).then_some(self.delegator.as_str())
    }
}

/// The controller half of a connected agent's state.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Controller {
    /// Controller key state.
    pub state: KeyState,
    /// The establishment event that produced it.
    ///
    /// The schema admits an inception, rotation, delegated inception, or delegated rotation here
    /// but not an interaction. That constraint is not enforced: an interaction reaching this field
    /// would be a KERIA defect, and refusing it would leave a client unable to read the rest of its
    /// own agent state. Callers that care check [`KeyEvent::is_establishment`].
    pub ee: KeyEvent,
}

/// What KERIA returns for the agent resource once a client is connected.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AgentResourceResult {
    /// Key state of the agent identifier.
    pub agent: KeyState,
    /// State of the controller the agent acts for.
    pub controller: Controller,
    /// Current key-pair index.
    pub pidx: u32,
    /// Current rotation index, or `null` before the first rotation.
    pub ridx: Option<u32>,
    /// Encrypted salt material, or `null` when the agent holds none.
    ///
    /// This is ciphertext, not a secret in the clear, so it is an ordinary field. It is still not
    /// something to log.
    pub sxlt: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// The `agent` block of the pinned `test/app/test-utils.ts` `mockConnect` document.
    const AGENT_STATE: &str = r#"{"vn":[1,0],"i":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","s":"0","p":"","d":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","f":"0","dt":"2023-08-19T21:04:57.948863+00:00","et":"dip","kt":"1","k":["DMZh_y-H5C3cSbZZST-fqnsmdNTReZxIh0t2xSTOJQ8a"],"nt":"1","n":["EM9M2EQNCBK0MyAhVYBvR98Q0tefpvHgE-lHLs82XgqC"],"bt":"0","b":[],"c":[],"ee":{"s":"0","d":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","br":[],"ba":[]},"di":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"}"#;

    #[test]
    fn the_pinned_agent_key_state_round_trips_in_schema_order() -> Result<(), Box<dyn Error>> {
        let state: KeyState = serde_json::from_str(AGENT_STATE)?;
        assert_eq!(state.version, Some(vec![1, 0]));
        assert_eq!(state.establishment_kind, "dip");
        assert_eq!(state.signing_threshold, Threshold::Simple("1".to_owned()));
        assert_eq!(state.signing_keys.len(), 1);
        assert_eq!(state.delegator(), Some("ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"));
        assert_eq!(serde_json::to_string(&state)?, AGENT_STATE);
        Ok(())
    }

    #[test]
    fn an_undelegated_identifier_reports_no_delegator() -> Result<(), Box<dyn Error>> {
        let document = AGENT_STATE.replace(r#""di":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose""#, r#""di":"""#);
        let state: KeyState = serde_json::from_str(&document)?;
        assert_eq!(state.delegator(), None);
        assert_eq!(state.delegator, "");
        Ok(())
    }

    #[test]
    fn the_empty_numeric_fields_of_the_pinned_registry_test_are_accepted() -> Result<(), Box<dyn Error>> {
        // `test/app/registry.test.ts` declares this literal as a `KeyState`, and its `s`, `f`,
        // `bt`, `kt`, and `nt` are all empty. Narrowing them to integers would refuse it.
        let document = r#"{"s":"0","d":"a digest","i":"","p":"","f":"","dt":"","et":"","kt":"","k":[],"nt":"","n":[],"bt":"","b":[],"c":[],"ee":{"s":"","d":"","br":[],"ba":[]},"di":""}"#;
        let state: KeyState = serde_json::from_str(document)?;
        assert_eq!(state.version, None);
        assert_eq!(state.first_seen, "");
        assert_eq!(state.witness_threshold, "");
        assert_eq!(state.signing_threshold, Threshold::Simple(String::new()));
        // `vn` was absent, so it stays absent rather than being written back as null.
        assert!(!serde_json::to_string(&state)?.contains("vn"));
        Ok(())
    }

    #[test]
    fn a_key_state_missing_a_required_field_is_refused() {
        for removed in [r#""i":"","#, r#""k":[],"#, r#""ee":{"s":"","d":""},"#] {
            let document = r#"{"s":"0","d":"a digest","i":"","p":"","f":"","dt":"","et":"","kt":"","k":[],"nt":"","n":[],"bt":"","b":[],"c":[],"ee":{"s":"","d":""},"di":""}"#
                .replace(removed, "");
            assert!(
                serde_json::from_str::<KeyState>(&document).is_err(),
                "a key state without {removed} was accepted"
            );
        }
        // A sequence number sent as a JSON number rather than KERI's hexadecimal text.
        let numeric = r#"{"s":0,"d":"a","i":"","p":"","f":"","dt":"","et":"","kt":"","k":[],"nt":"","n":[],"bt":"","b":[],"c":[],"ee":{"s":"","d":""},"di":""}"#;
        assert!(serde_json::from_str::<KeyState>(numeric).is_err());
    }

    #[test]
    fn an_establishment_state_omits_the_lists_it_did_not_carry() -> Result<(), Box<dyn Error>> {
        let state: EstablishmentState = serde_json::from_str(r#"{"s":"0","d":"EAB"}"#)?;
        assert_eq!(state.witnesses_removed, None);
        assert_eq!(serde_json::to_string(&state)?, r#"{"s":"0","d":"EAB"}"#);
        Ok(())
    }

    #[test]
    fn the_agent_resource_keeps_its_nullable_fields_distinct() -> Result<(), Box<dyn Error>> {
        let establishment = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"ELI7","i":"ELI7","s":"0","kt":"1","k":["DAbW"],"nt":"1","n":["EIFG"],"bt":"0","b":[],"c":[],"a":[]}"#;
        let document = format!(
            r#"{{"agent":{AGENT_STATE},"controller":{{"state":{AGENT_STATE},"ee":{establishment}}},"pidx":0,"ridx":0,"sxlt":null}}"#
        );
        let result: AgentResourceResult = serde_json::from_str(&document)?;
        assert_eq!(result.pidx, 0);
        assert_eq!(result.ridx, Some(0));
        assert_eq!(result.sxlt, None);
        assert!(result.controller.ee.is_establishment());
        // `null` is a value here, not an absence, so it is written back.
        assert_eq!(serde_json::to_string(&result)?, document);
        Ok(())
    }
}
