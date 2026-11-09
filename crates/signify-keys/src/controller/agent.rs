//! The KERIA agent's identity, validated from its key state.

use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::number::CesrNumber;
use keria_types::api::{KeyState, Threshold, ThresholdWeight};

use crate::controller::error::ControllerError;
use keri_protocol::event::kind::EventKind;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::threshold::SigningThreshold;

/// The KERIA agent: a custodial identity delegated to the client's controller.
///
/// This is the reference's `Agent`. It validates the key state KERIA reports for its agent — an
/// untrusted network input — and keeps the typed pieces the client needs: the agent's prefix, the
/// controller it anchors to, its current verification key, and where its log stands.
///
/// # Invariants
///
/// A value of this type only exists for a state whose latest establishment event is a delegated
/// inception carrying exactly one signing key, exactly one next-key digest, both thresholds
/// exactly one, and a delegator. Everything else is refused at construction.
///
/// ```
/// use signify_keys::controller::Agent;
/// use keria_types::api::KeyState;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let state: KeyState = serde_json::from_str(
///     r#"{"i":"EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY","s":"0","p":"",
///         "d":"EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY","f":"0",
///         "dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1",
///         "k":["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE"],"nt":"1",
///         "n":["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],"bt":"0","b":[],
///         "c":[],"ee":{"s":"0","d":"EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
///         "br":[],"ba":[]},"di":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"}"#,
/// )?;
/// let agent = Agent::from_key_state(state)?;
/// assert_eq!(
///     agent.anchor().qb64()?,
///     "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose",
/// );
/// assert_eq!(agent.sequence_number(), 0);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Agent {
    prefix: IdentifierPrefix,
    anchor: IdentifierPrefix,
    verifier: VerificationKey,
    sequence_number: u128,
    said: Said,
    state: KeyState,
}

impl Agent {
    /// Validates an agent's key state, exactly as the reference's constructor does.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::AgentKeyCount`] and [`ControllerError::AgentNextDigestCount`]
    /// unless exactly one of each is present, [`ControllerError::AgentThresholdNotOne`] for any
    /// threshold other than one, [`ControllerError::AgentNotDelegated`] when the latest
    /// establishment event is not a delegated inception, and
    /// [`ControllerError::MissingDelegatorAnchor`] when no delegator is named; layered parse
    /// failures cover malformed keys, digests, thresholds, and numbers.
    pub fn from_key_state(state: KeyState) -> Result<Self, ControllerError> {
        // The reference validates the key material first, then reads the log position, then
        // checks the establishment kind and anchor; the order decides which failure a
        // multiply-invalid state reports.
        let verifier = match state.signing_keys.as_slice() {
            [only] => VerificationKey::from_qb64(only)?,
            keys => return Err(ControllerError::AgentKeyCount { count: keys.len() }),
        };
        match state.next_key_digests.as_slice() {
            [only] => {
                // The reference parses the digest and then discards it; the validation is what
                // matters, so it is kept without the value.
                keri_cesr::crypto::digest::Digest::from_qb64(only)?;
            }
            digests => {
                return Err(ControllerError::AgentNextDigestCount { count: digests.len() });
            }
        }
        check_threshold_is_one(&state.signing_threshold, "kt")?;
        check_threshold_is_one(&state.next_threshold, "nt")?;

        let sequence_number = CesrNumber::from_hex(&state.sequence_number)?.value();
        let said = Said::from_qb64(&state.digest)?;

        if state.establishment_kind != EventKind::DelegatedInception.as_str() {
            return Err(ControllerError::AgentNotDelegated {
                kind: state.establishment_kind.clone(),
            });
        }
        let prefix = IdentifierPrefix::from_qb64(&state.identifier)?;
        let anchor = match state.delegator() {
            Some(delegator) => IdentifierPrefix::from_qb64(delegator)?,
            None => return Err(ControllerError::MissingDelegatorAnchor),
        };

        Ok(Self {
            prefix,
            anchor,
            verifier,
            sequence_number,
            said,
            state,
        })
    }

    /// Returns the agent's identifier prefix; the reference's `pre`.
    #[must_use]
    pub const fn prefix(&self) -> &IdentifierPrefix {
        &self.prefix
    }

    /// Returns the controller identifier the agent is delegated to; the reference's `anchor`.
    #[must_use]
    pub const fn anchor(&self) -> &IdentifierPrefix {
        &self.anchor
    }

    /// Returns the agent's current verification key, which authenticates its responses.
    #[must_use]
    pub const fn verifier(&self) -> &VerificationKey {
        &self.verifier
    }

    /// Returns the sequence number of the agent's latest event.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the SAID of the agent's latest event.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the complete key state this agent was validated from.
    #[must_use]
    pub const fn state(&self) -> &KeyState {
        &self.state
    }
}

/// Rejects a threshold that is not exactly the number one.
///
/// A weighted threshold has no numeric value at all, which the reference reports as
/// `invalid threshold undefined`; its weights are still parsed first, as the reference's
/// `Tholder` does, so a malformed weight is reported as such.
fn check_threshold_is_one(threshold: &Threshold, label: &'static str) -> Result<(), ControllerError> {
    let value = match threshold {
        Threshold::Simple(text) => SigningThreshold::from_sith(text)?.numeric_value(),
        Threshold::Clause(weights) => {
            SigningThreshold::from_sith(&weighted_sith(std::slice::from_ref(weights))?)?;
            None
        }
        Threshold::Clauses(clauses) => {
            SigningThreshold::from_sith(&weighted_sith(clauses)?)?;
            None
        }
    };
    if value == Some(1) {
        Ok(())
    } else {
        Err(ControllerError::AgentThresholdNotOne { label, value })
    }
}

/// Renders weighted clauses back into the JSON `sith` spelling the threshold parser accepts.
fn weighted_sith(clauses: &[Vec<ThresholdWeight>]) -> Result<String, ControllerError> {
    let rendered = if let [only] = clauses {
        serde_json::to_string(only)
    } else {
        serde_json::to_string(clauses)
    };
    // Serializing weights cannot fail, but the contract stays fallible.
    rendered.map_err(|_| ControllerError::AgentThresholdNotOne {
        label: "sith",
        value: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::agent_state_value;
    use std::error::Error;

    fn state_with(mutate: impl FnOnce(&mut serde_json::Value)) -> Result<KeyState, Box<dyn Error>> {
        let mut value = agent_state_value("0");
        mutate(&mut value);
        Ok(serde_json::from_value(value)?)
    }

    #[test]
    fn a_valid_delegated_state_becomes_an_agent() -> Result<(), Box<dyn Error>> {
        let agent = Agent::from_key_state(state_with(|_| ())?)?;
        assert_eq!(agent.prefix().qb64()?, "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY");
        assert_eq!(agent.anchor().qb64()?, "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose");
        assert_eq!(agent.verifier().qb64()?, "DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE");
        assert_eq!(agent.sequence_number(), 0);
        assert_eq!(agent.said().qb64()?, "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY");
        assert_eq!(agent.state().establishment_kind, "dip");
        Ok(())
    }

    #[test]
    fn the_sequence_number_is_hexadecimal() -> Result<(), Box<dyn Error>> {
        let agent = Agent::from_key_state(state_with(|value| {
            value["s"] = serde_json::json!("a");
        })?)?;
        assert_eq!(agent.sequence_number(), 10);
        Ok(())
    }

    #[test]
    fn the_next_threshold_and_a_malformed_weight_are_refused_too() -> Result<(), Box<dyn Error>> {
        let next_zero = state_with(|value| {
            value["nt"] = serde_json::json!("0");
        })?;
        assert!(matches!(
            Agent::from_key_state(next_zero),
            Err(ControllerError::AgentThresholdNotOne {
                label: "nt",
                value: Some(0)
            })
        ));
        // A malformed weight is a parse failure, not a threshold-value failure.
        let malformed = state_with(|value| {
            value["kt"] = serde_json::json!(["2/1", "1/2"]);
        })?;
        assert!(matches!(
            Agent::from_key_state(malformed),
            Err(ControllerError::Threshold { .. })
        ));
        Ok(())
    }

    #[test]
    fn only_a_delegated_inception_is_accepted() -> Result<(), Box<dyn Error>> {
        for kind in ["icp", "rot", "drt", ""] {
            let state = state_with(|value| {
                value["et"] = serde_json::json!(kind);
            })?;
            match Agent::from_key_state(state) {
                Err(ControllerError::AgentNotDelegated { kind: reported }) => {
                    assert_eq!(reported, kind);
                }
                other => return Err(format!("expected AgentNotDelegated for {kind:?}, got {other:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn malformed_material_is_a_layered_error() -> Result<(), Box<dyn Error>> {
        let bad_key = state_with(|value| {
            value["k"] = serde_json::json!(["not a key"]);
        })?;
        assert!(matches!(
            Agent::from_key_state(bad_key),
            Err(ControllerError::Crypto { .. })
        ));
        let bad_digest = state_with(|value| {
            value["n"] = serde_json::json!(["not a digest"]);
        })?;
        assert!(matches!(
            Agent::from_key_state(bad_digest),
            Err(ControllerError::Crypto { .. })
        ));
        let bad_sequence = state_with(|value| {
            value["s"] = serde_json::json!("not hex");
        })?;
        assert!(matches!(
            Agent::from_key_state(bad_sequence),
            Err(ControllerError::Cesr { .. })
        ));
        let bad_prefix = state_with(|value| {
            value["i"] = serde_json::json!("junk");
        })?;
        assert!(matches!(
            Agent::from_key_state(bad_prefix),
            Err(ControllerError::Prefix { .. })
        ));
        Ok(())
    }

    #[test]
    fn validation_order_matches_the_reference() -> Result<(), Box<dyn Error>> {
        // A state that is wrong in several ways reports the key count first, because the
        // reference's `event()` runs before its establishment-kind check.
        let several = state_with(|value| {
            value["k"] = serde_json::json!([]);
            value["et"] = serde_json::json!("icp");
            value["di"] = serde_json::json!("");
        })?;
        assert!(matches!(
            Agent::from_key_state(several),
            Err(ControllerError::AgentKeyCount { count: 0 })
        ));
        // With the key material valid, the kind check runs before the anchor check.
        let kind_first = state_with(|value| {
            value["et"] = serde_json::json!("icp");
            value["di"] = serde_json::json!("");
        })?;
        assert!(matches!(
            Agent::from_key_state(kind_first),
            Err(ControllerError::AgentNotDelegated { .. })
        ));
        Ok(())
    }
}
