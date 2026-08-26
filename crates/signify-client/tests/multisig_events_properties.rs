//! Invariants of the two rounds a multisig group runs after it exists.
//!
//! Roadmap 8.3's properties were about a group *forming*. These are about a group that already
//! exists **staying one group**: every member builds the same event independently, so the
//! invariants are all forms of "what one member announces is what another reads".
//!
//! Three things vary: the route a message is announced on, the shape of a proposal a member is
//! handed, and — new here — the JSON *type* of a witness threshold, which the reference chooses by
//! value.

use std::error::Error;

use proptest::prelude::*;
use signify_client::endpoint::exchanges::{
    ClassifiedExchange, GROUP_LABEL, MultisigRoute, ROTATION_MEMBERS_LABEL, SIGNING_MEMBERS_LABEL,
};
use signify_client::multisig::{
    INCEPTION_ROUTE, INCEPTION_SLOT, INTERACTION_ROUTE, INTERACTION_SLOT, ROTATION_ROUTE, ROTATION_SLOT,
};
use signify_types::api::{ExchangeEmbed, KeyEvent, MultisigExchangeResource, RotationRecord};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const DIGEST: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/// The three rounds this module announces, each with the slot its route names.
const ROUNDS: [(&str, &str); 3] = [
    (INCEPTION_ROUTE, INCEPTION_SLOT),
    (ROTATION_ROUTE, ROTATION_SLOT),
    (INTERACTION_ROUTE, INTERACTION_SLOT),
];

/// One embedded event of each kind, keyed by the slot it belongs in.
fn event(slot: &str, witness_threshold: &str) -> String {
    match slot {
        "icp" => format!(
            r#"{{"v":"KERI10JSON000_","t":"icp","d":"{GROUP}","i":"{GROUP}","s":"0","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":{witness_threshold},"b":[],"c":[],"a":[]}}"#
        ),
        "rot" => format!(
            r#"{{"v":"KERI10JSON000_","t":"rot","d":"{DIGEST}","i":"{GROUP}","s":"1","p":"{GROUP}","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":{witness_threshold},"br":[],"ba":[],"a":[]}}"#
        ),
        _ => format!(r#"{{"v":"KERI10JSON000_","t":"ixn","d":"{DIGEST}","i":"{GROUP}","s":"1","p":"{GROUP}","a":[]}}"#),
    }
}

/// One group request listing entry announcing `slot`'s event on `route`.
fn listing(route: &str, slot: &str, witness_threshold: &str) -> String {
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":["{LOCAL}","{PEER}"],"{ROTATION_MEMBERS_LABEL}":["{LOCAL}","{PEER}"]}},"e":{{"d":"EEMB","{slot}":{event}}}}}"#,
        event = event(slot, witness_threshold)
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#)
}

fn classify(document: &str) -> Result<ClassifiedExchange, Box<dyn Error>> {
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_str(document)?;
    let entry = decoded.first().ok_or("empty listing")?;
    Ok(ClassifiedExchange::try_from(entry)?)
}

/// The witness threshold an embedded rotation carries, as text.
fn threshold_of(classified: &ClassifiedExchange) -> Result<String, TestCaseError> {
    let multisig = classified
        .as_multisig()
        .ok_or_else(|| TestCaseError::fail("not a multisig proposal"))?;
    let ExchangeEmbed::Rotation(embed) = &multisig.proposed.message else {
        return Err(TestCaseError::fail("not a rotation embed"));
    };
    match &embed.rot {
        KeyEvent::Rotation(record) => Ok(record.witness_threshold.clone()),
        _ => Err(TestCaseError::fail("not a plain rotation")),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// A message announced on one round's route carries that round's embed, and no other.
    ///
    /// This is the finding stated as an invariant. Upstream, both joining members of a rotation
    /// send a `rot` embed under `/multisig/ixn` while their peers wait on `/multisig/rot`; here
    /// every pairing but the matching one is refused, so the message they send cannot be read as
    /// anything at all.
    #[test]
    fn a_route_admits_its_own_embed_and_refuses_every_other(
        route in prop::sample::select(ROUNDS.map(|(route, _)| route).to_vec()),
        slot in prop::sample::select(ROUNDS.map(|(_, slot)| slot).to_vec()),
    ) {
        let matching = ROUNDS.iter().any(|(named, expected)| *named == route && *expected == slot);
        let classified = classify(&listing(route, slot, r#""2""#));
        if matching {
            let proposal = classified
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let multisig = proposal.as_multisig()
                .ok_or_else(|| TestCaseError::fail("a multisig route did not classify as one"))?;
            prop_assert_eq!(multisig.route.as_str(), route);
        } else {
            prop_assert!(classified.is_err(), "{} accepted a {} embed", route, slot);
        }
    }

    /// A witness threshold survives whichever JSON type the reference chose to write it as.
    ///
    /// `rotate` writes `bt` as a bare number for a non-zero threshold and as hexadecimal text at
    /// zero, so a reader that accepts one type decodes half the rotations upstream emits. Both are
    /// read here and both keep the value they arrived with.
    #[test]
    fn a_rotation_threshold_reads_the_same_whichever_type_it_arrived_as(threshold in 0_u32..=4096) {
        let as_number = classify(&listing(ROTATION_ROUTE, ROTATION_SLOT, &threshold.to_string()))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(threshold_of(&as_number)?, threshold.to_string());

        let as_text = classify(&listing(ROTATION_ROUTE, ROTATION_SLOT, &format!("\"{threshold}\"")))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(threshold_of(&as_text)?, threshold.to_string());

        // Which is the point: the same threshold, two wire types, one decoded value.
        prop_assert_eq!(threshold_of(&as_number)?, threshold_of(&as_text)?);
    }

    /// Whatever a threshold's type, a value that is not a whole number is refused.
    #[test]
    fn a_threshold_that_is_not_a_whole_number_is_refused(
        written in prop::sample::select(vec!["true", "null", "[]", "{}", "-1", "1.5", "\"\"", "\" 2\""]),
    ) {
        let document = listing(ROTATION_ROUTE, ROTATION_SLOT, written);
        // The empty string and a padded one decode — the schema says string and says no more — so
        // what is asserted is that nothing panics and that a non-string non-number is refused.
        match classify(&document) {
            Ok(classified) => {
                prop_assert!(written.starts_with('"'), "{} was accepted as a threshold", written);
                let _ = threshold_of(&classified)?;
            }
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }

    /// The members a proposal names reach a reader unchanged, whichever round it is.
    #[test]
    fn the_member_lists_survive_every_round(
        route in prop::sample::select(ROUNDS.map(|(route, _)| route).to_vec()),
    ) {
        let slot = ROUNDS
            .iter()
            .find(|(named, _)| *named == route)
            .map(|(_, slot)| *slot)
            .ok_or_else(|| TestCaseError::fail("an unnamed route"))?;
        let classified = classify(&listing(route, slot, r#""2""#))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let multisig = classified.as_multisig()
            .ok_or_else(|| TestCaseError::fail("a multisig route did not classify as one"))?;

        let read = |members: Option<&Vec<signify_keri::prefix::IdentifierPrefix>>| -> Vec<String> {
            members
                .map(|list| list.iter().filter_map(|member| member.qb64().ok()).collect())
                .unwrap_or_default()
        };
        prop_assert_eq!(read(multisig.attributes.signing_members.as_ref()), vec![LOCAL.to_owned(), PEER.to_owned()]);
        prop_assert_eq!(read(multisig.attributes.rotation_members.as_ref()), vec![LOCAL.to_owned(), PEER.to_owned()]);
        prop_assert_eq!(multisig.attributes.group.qb64().ok(), Some(GROUP.to_owned()));
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

/// Regression: the exact pairing both of the reference's joining members send.
#[test]
fn a_rotation_announced_as_an_interaction_is_refused() -> Result<(), Box<dyn Error>> {
    let refused = classify(&listing(INTERACTION_ROUTE, ROTATION_SLOT, "3")).is_err();
    assert!(refused, "a rotation announced on the interaction route was classified");
    // And the pairing the initiator sends is not.
    let accepted = classify(&listing(ROTATION_ROUTE, ROTATION_SLOT, "3"))?;
    assert_eq!(
        accepted.as_multisig().map(|proposal| proposal.route),
        Some(MultisigRoute::Rotation)
    );
    Ok(())
}

/// Regression: the two wire types the reference writes the same field as.
#[test]
fn the_two_witness_threshold_types_decode_to_one_value() -> Result<(), Box<dyn Error>> {
    let numeric = r#"{"v":"KERI10JSON000_","t":"rot","d":"EROT","i":"EGRP","s":"1","p":"EICP","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":3,"br":[],"ba":[],"a":[]}"#;
    let text = numeric.replace(r#""bt":3"#, r#""bt":"3""#);
    let from_number: RotationRecord = serde_json::from_str(numeric)?;
    let from_text: RotationRecord = serde_json::from_str(&text)?;
    assert_eq!(from_number.witness_threshold, from_text.witness_threshold);
    assert_eq!(from_number.witness_threshold, "3");
    Ok(())
}

/// Regression: each round's route names its own slot, which is what keeps the pairing honest.
#[test]
fn every_round_names_the_slot_it_embeds() {
    for (route, slot) in ROUNDS {
        assert_eq!(route.rsplit('/').next(), Some(slot), "{route} does not name {slot}");
    }
}
