//! Invariants of the two rounds a multisig group runs after it exists.
//!
//! What one member announces is what another reads, including a witness threshold's JSON type.

mod support;

use std::error::Error;

use crate::support::classify;
use keria_types::api::{ExchangeEmbed, KeyEvent, MultisigExchangeResource};
use proptest::prelude::*;
use signify_client::endpoint::exchanges::{
    ClassifiedExchange, ExchangeRoute, GROUP_LABEL, MultisigRoute, ROTATION_MEMBERS_LABEL, SIGNING_MEMBERS_LABEL,
};
use signify_client::error::ClientError;
use signify_client::multisig::{
    INCEPTION_ROUTE, INCEPTION_SLOT, INTERACTION_ROUTE, INTERACTION_SLOT, ROTATION_ROUTE, ROTATION_SLOT,
};
use signify_keys::acdc::ipex::IpexRoute;

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const DIGEST: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/// The route table, spelled out rather than read from the type under test.
const ROUTE_TABLE: [(&str, ExchangeRoute); 13] = [
    ("/multisig/icp", ExchangeRoute::Multisig(MultisigRoute::Inception)),
    ("/multisig/rot", ExchangeRoute::Multisig(MultisigRoute::Rotation)),
    ("/multisig/ixn", ExchangeRoute::Multisig(MultisigRoute::Interaction)),
    ("/multisig/rpy", ExchangeRoute::Multisig(MultisigRoute::Reply)),
    (
        "/multisig/vcp",
        ExchangeRoute::Multisig(MultisigRoute::RegistryInception),
    ),
    ("/multisig/iss", ExchangeRoute::Multisig(MultisigRoute::Issuance)),
    ("/multisig/exn", ExchangeRoute::Multisig(MultisigRoute::Exchange)),
    ("/multisig/rev", ExchangeRoute::Multisig(MultisigRoute::Revocation)),
    ("/ipex/grant", ExchangeRoute::Ipex(IpexRoute::Grant)),
    ("/ipex/offer", ExchangeRoute::Ipex(IpexRoute::Offer)),
    ("/ipex/apply", ExchangeRoute::Ipex(IpexRoute::Apply)),
    ("/ipex/agree", ExchangeRoute::Ipex(IpexRoute::Agree)),
    ("/ipex/admit", ExchangeRoute::Ipex(IpexRoute::Admit)),
];

const ROUNDS: [(&str, &str); 3] = [
    (INCEPTION_ROUTE, INCEPTION_SLOT),
    (ROTATION_ROUTE, ROTATION_SLOT),
    (INTERACTION_ROUTE, INTERACTION_SLOT),
];

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

fn listing(route: &str, slot: &str, witness_threshold: &str) -> String {
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":["{LOCAL}","{PEER}"],"{ROTATION_MEMBERS_LABEL}":["{LOCAL}","{PEER}"]}},"e":{{"d":"EEMB","{slot}":{event}}}}}"#,
        event = event(slot, witness_threshold)
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#)
}

fn classify_typed(document: &str) -> Result<Result<ClassifiedExchange, ClientError>, TestCaseError> {
    let decoded: Vec<MultisigExchangeResource> =
        serde_json::from_str(document).map_err(|error| TestCaseError::fail(error.to_string()))?;
    let entry = decoded.first().ok_or_else(|| TestCaseError::fail("empty listing"))?;
    Ok(ClassifiedExchange::try_from(entry))
}

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

    #[test]
    fn a_rotation_threshold_reads_the_same_whichever_type_it_arrived_as(threshold in 0_u32..=4096) {
        let as_number = classify(&listing(ROTATION_ROUTE, ROTATION_SLOT, &threshold.to_string()))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(threshold_of(&as_number)?, threshold.to_string());

        let as_text = classify(&listing(ROTATION_ROUTE, ROTATION_SLOT, &format!("\"{threshold}\"")))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(threshold_of(&as_text)?, threshold.to_string());

        prop_assert_eq!(threshold_of(&as_number)?, threshold_of(&as_text)?);
    }

    #[test]
    fn a_threshold_that_is_neither_text_nor_a_whole_number_is_refused(
        written in prop_oneof![
            prop::sample::select(vec!["true", "null", "[]", "{}", "-1", "1.5", "1e3", "\"\"", "\" 2\""])
                .prop_map(str::to_owned),
            (0_u32..=4096).prop_map(|number| number.to_string()),
            "[0-9a-f]{1,4}".prop_map(|text| format!("\"{text}\"")),
        ],
    ) {
        let parsed: serde_json::Value = serde_json::from_str(&written)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let expected = match &parsed {
            serde_json::Value::Number(number) => number.as_u64().map(|whole| whole.to_string()),
            serde_json::Value::String(text) => Some(text.clone()),
            _ => None,
        };
        match (classify_typed(&listing(ROTATION_ROUTE, ROTATION_SLOT, &written))?, expected) {
            (Ok(classified), Some(expected)) => prop_assert_eq!(threshold_of(&classified)?, expected),
            (Err(ClientError::Api { .. }), None) => {}
            (outcome, expected) => {
                return Err(TestCaseError::fail(format!("{written} read as {outcome:?}, expected {expected:?}")));
            }
        }
    }

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

        let read = |members: Option<&Vec<keri_protocol::prefix::IdentifierPrefix>>| -> Vec<String> {
            members
                .map(|list| list.iter().filter_map(|member| member.qb64().ok()).collect())
                .unwrap_or_default()
        };
        prop_assert_eq!(read(multisig.attributes.signing_members.as_ref()), vec![LOCAL.to_owned(), PEER.to_owned()]);
        prop_assert_eq!(read(multisig.attributes.rotation_members.as_ref()), vec![LOCAL.to_owned(), PEER.to_owned()]);
        prop_assert_eq!(multisig.attributes.group.qb64().ok(), Some(GROUP.to_owned()));
    }

    #[test]
    fn a_listing_classifies_as_the_route_it_carries(
        route in prop_oneof![
            prop::sample::select(ROUTE_TABLE.map(|(text, _)| text).to_vec()).prop_map(str::to_owned),
            "/[a-z]{1,8}/[a-z]{1,8}",
        ],
        slot in prop::sample::select(vec!["icp", "rot", "ixn", "rpy", "vcp", "acdc", "rev", "exn"]),
        grouped in any::<bool>(),
    ) {
        let mut document = listing(&route, slot, r#""2""#);
        if !grouped {
            document = document.replace(&format!(r#""{GROUP_LABEL}":"{GROUP}","#), "");
        }
        let input: serde_json::Value = serde_json::from_str(&document)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let carried = input
            .pointer("/0/exn/r")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| TestCaseError::fail("the listing carries no route"))?;
        let named = ROUTE_TABLE.iter().find(|(text, _)| *text == carried).map(|(_, route)| *route);

        match (classify_typed(&document)?, named) {
            (Ok(classified), Some(expected)) => prop_assert_eq!(classified.route(), Some(expected)),
            (Ok(ClassifiedExchange::Other { route: other }), None) => prop_assert_eq!(other.as_str(), carried),
            (
                Err(
                    ClientError::ExchangeEmbedMismatch { .. }
                    | ClientError::MissingGroupAttribute { .. }
                    | ClientError::Api { .. },
                ),
                Some(_),
            ) => {
                // A table route with the embed it names and the group label always classifies.
                let own = ROUNDS.iter().any(|(named, expected)| *named == carried && *expected == slot);
                prop_assert!(!(own && grouped), "{} with its own {} embed was refused", carried, slot);
            }
            (outcome, _) => return Err(TestCaseError::fail(format!("{carried} with {slot} read as {outcome:?}"))),
        }
    }
}

#[test]
fn a_rotation_announced_as_an_interaction_is_refused() -> Result<(), Box<dyn Error>> {
    let refused = classify(&listing(INTERACTION_ROUTE, ROTATION_SLOT, "3")).is_err();
    assert!(refused, "a rotation announced on the interaction route was classified");
    let accepted = classify(&listing(ROTATION_ROUTE, ROTATION_SLOT, "3"))?;
    assert_eq!(
        accepted.as_multisig().map(|proposal| proposal.route),
        Some(MultisigRoute::Rotation)
    );
    Ok(())
}

#[test]
fn every_round_names_the_slot_it_embeds() {
    for (route, slot) in ROUNDS {
        assert_eq!(route.rsplit('/').next(), Some(slot), "{route} does not name {slot}");
    }
}
