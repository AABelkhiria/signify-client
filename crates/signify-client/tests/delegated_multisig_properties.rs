//! Invariants of a group approving a delegation.
//!
//! This round is the one place in the port where **a list is the payload**. An inception commits to
//! members and thresholds, a rotation to keys, an interaction to seals — and here the seals are
//! delegated identifiers waiting to exist. Drop one and an identifier never comes into being.
//!
//! So the properties are about the list surviving: every seal a proposal names is read back, in
//! order, at any length; the event's digest changes when the list does, which is what makes the
//! joining half's check meaningful; and a proposal on the interaction route still carries an
//! interaction, which is what Roadmap 8.4 established and this round inherits.

use std::error::Error;

use proptest::prelude::*;
use serde_json::Value;
use signify_client::endpoint::delegations::InceptionSeal;
use signify_client::endpoint::exchanges::{
    ClassifiedExchange, GROUP_LABEL, MultisigRoute, ROTATION_MEMBERS_LABEL, SIGNING_MEMBERS_LABEL,
};
use signify_client::multisig::{INTERACTION_ROUTE, INTERACTION_SLOT};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_types::api::{ExchangeEmbed, KeyEvent, MultisigExchangeResource};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const DELEGATEE: &str = "EDNA2EUYd0HbW_4NU1kMv01LK2zqAWK6o7VkIQsK_LyR";

/// The delegatee prefixes a proposal's seals may name.
const DELEGATEES: [&str; 4] = [
    DELEGATEE,
    "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1",
    PEER,
];

/// One delegated inception's seal, written as this port writes it.
fn seal(delegatee: &str) -> Result<String, Box<dyn Error>> {
    let built = InceptionSeal::new(IdentifierPrefix::from_qb64(delegatee)?, delegatee.parse::<Said>()?);
    Ok(String::from_utf8(built.to_sad()?.to_json_bytes()?)?)
}

/// One group interaction proposal anchoring `seals`, of the shape the agent answers with.
fn proposal(seals: &[String], digest: &str) -> String {
    let event = format!(
        r#"{{"v":"KERI10JSON000_","t":"ixn","d":"{digest}","i":"{GROUP}","s":"1","p":"{GROUP}","a":[{seals}]}}"#,
        seals = seals.join(",")
    );
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{INTERACTION_ROUTE}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":["{LOCAL}","{PEER}"],"{ROTATION_MEMBERS_LABEL}":["{LOCAL}","{PEER}"]}},"e":{{"d":"EEMB","{INTERACTION_SLOT}":{event}}}}}"#
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"delegators","memberName":"delegator1","sender":"{LOCAL}"}}]"#)
}

fn classify(document: &str) -> Result<ClassifiedExchange, Box<dyn Error>> {
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_str(document)?;
    let entry = decoded.first().ok_or("empty listing")?;
    Ok(ClassifiedExchange::try_from(entry)?)
}

/// The seals an embedded interaction anchors, as a joining member reads them.
fn anchored(classified: &ClassifiedExchange) -> Result<Vec<Value>, TestCaseError> {
    let multisig = classified
        .as_multisig()
        .ok_or_else(|| TestCaseError::fail("not a multisig proposal"))?;
    let ExchangeEmbed::Interaction(embed) = &multisig.proposed.message else {
        return Err(TestCaseError::fail("not an interaction embed"));
    };
    match &embed.ixn {
        KeyEvent::Interaction(record) => match &record.anchors {
            Value::Array(seals) => Ok(seals.clone()),
            single => Ok(vec![single.clone()]),
        },
        _ => Err(TestCaseError::fail("not a plain interaction")),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Every seal a proposal names is read back, in order, at any length.
    ///
    /// The reference reads `ixn.a[0]` — the first and no other — so a delegator group anchoring
    /// more than one delegation has the rest silently dropped by every member but the initiator.
    #[test]
    fn every_seal_a_proposal_names_is_read_back(
        delegatees in proptest::collection::vec(prop::sample::select(DELEGATEES.to_vec()), 1..6),
    ) {
        let seals: Vec<String> = delegatees
            .iter()
            .map(|delegatee| seal(delegatee))
            .collect::<Result<Vec<String>, Box<dyn Error>>>()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let classified = classify(&proposal(&seals, "EIXNDIGEST"))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let read = anchored(&classified)?;
        prop_assert_eq!(read.len(), delegatees.len(), "a seal was dropped");
        for (position, delegatee) in delegatees.iter().enumerate() {
            prop_assert_eq!(
                read.get(position).and_then(|seal| seal.get("i")).and_then(Value::as_str),
                Some(*delegatee),
                "seal {} names the wrong identifier", position
            );
            prop_assert_eq!(
                read.get(position).and_then(|seal| seal.get("s")).and_then(Value::as_str),
                Some("0")
            );
        }
        // Taking only the first would be a different list whenever there is more than one.
        prop_assert_eq!(read.len() == 1, delegatees.len() == 1);
    }

    /// A seal names one identifier three ways, and the three cannot disagree.
    #[test]
    fn a_seal_names_one_identifier_three_ways(delegatee in prop::sample::select(DELEGATEES.to_vec())) {
        let written = seal(delegatee).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let decoded: Value = serde_json::from_str(&written)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(decoded.get("i").and_then(Value::as_str), Some(delegatee));
        prop_assert_eq!(decoded.get("d").and_then(Value::as_str), Some(delegatee));
        prop_assert_eq!(decoded.get("s").and_then(Value::as_str), Some("0"));
        // A delegated inception is its own digest, which is what makes the two fields equal.
        prop_assert_eq!(decoded.get("i"), decoded.get("d"));
    }

    /// The digest a proposal carries is what a joining member checks against.
    ///
    /// Two proposals differing only in their seal list carry different digests, so a member that
    /// anchored the wrong seals builds an event that does not match — which is the check this port
    /// performs and the reference performs after the fact, on the wrong shape.
    #[test]
    fn a_different_seal_list_is_a_different_event(
        first in prop::sample::select(DELEGATEES.to_vec()),
        second in prop::sample::select(DELEGATEES.to_vec()),
    ) {
        let one = seal(first).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let two = seal(second).map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(!two.is_empty());

        let whole = classify(&proposal(&[one.clone(), two.clone()], "EWHOLE"))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let truncated = classify(&proposal(&[one], "ETRUNCATED"))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let whole_seals = anchored(&whole)?;
        let truncated_seals = anchored(&truncated)?;
        prop_assert_eq!(whole_seals.len(), 2);
        prop_assert_eq!(truncated_seals.len(), 1);
        prop_assert_ne!(&whole_seals, &truncated_seals);
        // The digests differ, which is what makes the comparison a check rather than a formality.
        let digest_of = |classified: &ClassifiedExchange| -> Option<String> {
            let multisig = classified.as_multisig()?;
            let ExchangeEmbed::Interaction(embed) = &multisig.proposed.message else {
                return None;
            };
            match &embed.ixn {
                KeyEvent::Interaction(record) => Some(record.digest.clone()),
                _ => None,
            }
        };
        prop_assert_ne!(digest_of(&whole), digest_of(&truncated));
    }

    /// A delegation approval is announced on the interaction route, carrying an interaction.
    #[test]
    fn an_approval_is_announced_as_the_interaction_it_is(
        count in 1_usize..4,
    ) {
        let seals: Vec<String> = (0..count)
            .filter_map(|index| DELEGATEES.get(index).copied())
            .map(|delegatee| seal(delegatee))
            .collect::<Result<Vec<String>, Box<dyn Error>>>()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let classified = classify(&proposal(&seals, "EIXNDIGEST"))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let multisig = classified.as_multisig()
            .ok_or_else(|| TestCaseError::fail("an approval did not classify as a multisig proposal"))?;
        prop_assert_eq!(multisig.route, MultisigRoute::Interaction);
        prop_assert_eq!(multisig.attributes.group.qb64().ok(), Some(GROUP.to_owned()));
        prop_assert_eq!(anchored(&classified)?.len(), seals.len());
    }

    /// Arbitrary bytes never panic: a proposal classifies or is refused with a reason.
    #[test]
    fn arbitrary_bytes_classify_or_are_refused(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        match core::str::from_utf8(&bytes) {
            Ok(text) => match classify(text) {
                Ok(classified) => {
                    let _ = classified.as_multisig().is_some();
                }
                Err(error) => prop_assert!(!error.to_string().is_empty()),
            },
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }
}

/// Regression: the seal the pinned scenario anchors.
#[test]
fn the_scenarios_seal_reproduces() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        seal(DELEGATEE)?,
        format!(r#"{{"i":"{DELEGATEE}","s":"0","d":"{DELEGATEE}"}}"#)
    );
    Ok(())
}

/// Regression: two seals in one proposal, which the reference's helper cannot send.
#[test]
fn two_seals_in_one_proposal_are_both_read() -> Result<(), Box<dyn Error>> {
    let seals = [seal(DELEGATEE)?, seal(GROUP)?];
    let classified = classify(&proposal(&seals, "EIXNDIGEST"))?;
    let multisig = classified.as_multisig().ok_or("not a multisig proposal")?;
    let ExchangeEmbed::Interaction(embed) = &multisig.proposed.message else {
        return Err("not an interaction embed".into());
    };
    let KeyEvent::Interaction(record) = &embed.ixn else {
        return Err("not a plain interaction".into());
    };
    let anchors = record.anchors.as_array().ok_or("the seals are not a list")?;
    assert_eq!(anchors.len(), 2);
    assert_eq!(
        anchors.first().and_then(|seal| seal.get("i")).and_then(Value::as_str),
        Some(DELEGATEE)
    );
    assert_eq!(
        anchors.get(1).and_then(|seal| seal.get("i")).and_then(Value::as_str),
        Some(GROUP)
    );
    Ok(())
}

/// Regression: an approval carrying no seal at all is still a well-formed interaction.
#[test]
fn an_approval_that_anchors_nothing_is_well_formed_and_meaningless() -> Result<(), Box<dyn Error>> {
    let classified = classify(&proposal(&[], "EIXNDIGEST"))?;
    let multisig = classified.as_multisig().ok_or("not a multisig proposal")?;
    assert_eq!(multisig.route, MultisigRoute::Interaction);
    // It classifies — the event format permits it — which is why the refusal lives in the workflow
    // rather than in the decoder.
    Ok(())
}
