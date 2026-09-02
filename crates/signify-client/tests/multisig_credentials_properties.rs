//! Invariants of a group's registry, issuance, and revocation rounds.
//!
//! The value that decides an identifier survives the round trip: a registry's nonce, a credential's SAID.

use std::error::Error;

use proptest::prelude::*;
use serde_json::Value;
use signify_client::endpoint::exchanges::{ClassifiedExchange, GROUP_LABEL, MultisigRoute};
use signify_client::multisig::{
    ANCHOR_SLOT, ISSUANCE_ROUTE, ISSUANCE_SLOT, REGISTRY_ROUTE, REGISTRY_SLOT, REVOCATION_ROUTE, REVOCATION_SLOT,
    TRANSACTION_SLOT,
};
use signify_types::api::{ExchangeEmbed, MultisigExchangeResource};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const REGISTRY: &str = "EJBglnT4bORqW6oF87S050gj5i1qBQSHwTj3bLPyMpbX";
const CREDENTIAL: &str = "ECk3MhIQkFtytQZCiAKKEAA94Y9oL8OtDTINpzsI8JSg";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

const ROUNDS: [(&str, &str); 3] = [
    (REGISTRY_ROUTE, REGISTRY_SLOT),
    (ISSUANCE_ROUTE, ISSUANCE_SLOT),
    (REVOCATION_ROUTE, REVOCATION_SLOT),
];

fn embeds(slot: &str, nonce: &str, attributes: &str) -> String {
    let anchor = format!(
        r#""{ANCHOR_SLOT}":{{"v":"KERI10JSON000_","t":"ixn","d":"EANC","i":"{GROUP}","s":"1","p":"{GROUP}","a":[]}}"#
    );
    match slot {
        "vcp" => format!(
            r#""{REGISTRY_SLOT}":{{"v":"KERI10JSON000_","t":"vcp","d":"{REGISTRY}","i":"{REGISTRY}","ii":"{GROUP}","s":"0","c":[],"bt":"0","b":[],"n":"{nonce}"}},{anchor}"#
        ),
        "acdc" => format!(
            r#""{ISSUANCE_SLOT}":{{"v":"ACDC10JSON000_","d":"{CREDENTIAL}","i":"{GROUP}","ri":"{REGISTRY}","s":"{SCHEMA}","a":{attributes}}},"{TRANSACTION_SLOT}":{{"v":"KERI10JSON000_","t":"iss","d":"EISS","i":"{CREDENTIAL}","s":"0","ri":"{REGISTRY}","dt":"2023-11-14T22:13:20.123000+00:00"}},{anchor}"#
        ),
        _ => format!(
            r#""{REVOCATION_SLOT}":{{"v":"KERI10JSON000_","t":"rev","d":"EREV","i":"{CREDENTIAL}","s":"1","ri":"{REGISTRY}","p":"EISS","dt":"2023-11-14T22:13:20.123000+00:00"}},{anchor}"#
        ),
    }
}

fn proposal(route: &str, slot: &str, nonce: &str, attributes: &str) -> String {
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}"}},"e":{{"d":"EEMB",{embeds}}}}}"#,
        embeds = embeds(slot, nonce, attributes)
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#)
}

fn classify(document: &str) -> Result<ClassifiedExchange, Box<dyn Error>> {
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_str(document)?;
    let entry = decoded.first().ok_or("empty listing")?;
    Ok(ClassifiedExchange::try_from(entry)?)
}

fn nonce_of(classified: &ClassifiedExchange) -> Result<String, TestCaseError> {
    let multisig = classified
        .as_multisig()
        .ok_or_else(|| TestCaseError::fail("not a multisig proposal"))?;
    let ExchangeEmbed::RegistryInception(embed) = &multisig.proposed.message else {
        return Err(TestCaseError::fail("not a registry embed"));
    };
    Ok(embed.vcp.nonce.clone())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn a_registrys_nonce_survives_the_round_trip(nonce in "[A-Za-z0-9_-]{43}") {
        let classified = classify(&proposal(REGISTRY_ROUTE, REGISTRY_SLOT, &nonce, "{}"))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(nonce_of(&classified)?, nonce);
        let multisig = classified.as_multisig()
            .ok_or_else(|| TestCaseError::fail("a registry proposal did not classify as one"))?;
        prop_assert_eq!(multisig.route, MultisigRoute::RegistryInception);
        prop_assert_eq!(multisig.attributes.group.qb64().ok(), Some(GROUP.to_owned()));
    }

    #[test]
    fn a_transaction_route_admits_its_own_embed(
        route in prop::sample::select(ROUNDS.map(|(route, _)| route).to_vec()),
        slot in prop::sample::select(ROUNDS.map(|(_, slot)| slot).to_vec()),
    ) {
        let matching = ROUNDS.iter().any(|(named, expected)| *named == route && *expected == slot);
        let classified = classify(&proposal(route, slot, "AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s", "{}"));
        if matching {
            let proposal = classified.map_err(|error| TestCaseError::fail(error.to_string()))?;
            let multisig = proposal.as_multisig()
                .ok_or_else(|| TestCaseError::fail("a multisig route did not classify as one"))?;
            prop_assert_eq!(multisig.route.as_str(), route);
        } else {
            prop_assert!(classified.is_err(), "{} accepted a {} embed", route, slot);
        }
    }

    #[test]
    fn a_revocation_under_the_issuance_label_is_refused(route in prop::sample::select(vec![REVOCATION_ROUTE, ISSUANCE_ROUTE])) {
        let misfiled = format!(
            r#"[{{"exn":{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}"}},"e":{{"d":"EEMB","{TRANSACTION_SLOT}":{{"v":"KERI10JSON000_","t":"rev","d":"EREV","i":"{CREDENTIAL}","s":"1","ri":"{REGISTRY}","p":"EISS","dt":"2023-11-14T22:13:20.123000+00:00"}},"{ANCHOR_SLOT}":{{"v":"KERI10JSON000_","t":"ixn","d":"EANC","i":"{GROUP}","s":"1","p":"{GROUP}","a":[]}}}}}},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#
        );
        prop_assert!(classify(&misfiled).is_err(), "{} accepted a revocation labelled as an issuance", route);
    }

    #[test]
    fn a_credentials_attributes_survive_the_round_trip(lei in "[A-Z0-9]{20}") {
        let attributes = format!(r#"{{"i":"{PEER}","LEI":"{lei}","dt":"2023-11-14T22:13:20.123000+00:00"}}"#);
        let classified = classify(&proposal(ISSUANCE_ROUTE, ISSUANCE_SLOT, "", &attributes))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let multisig = classified.as_multisig()
            .ok_or_else(|| TestCaseError::fail("an issuance did not classify as one"))?;
        let ExchangeEmbed::Issuance(embed) = &multisig.proposed.message else {
            return Err(TestCaseError::fail("not an issuance embed"));
        };
        let read = serde_json::to_value(&embed.acdc.attributes)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(read.get("LEI").and_then(Value::as_str), Some(lei.as_str()));
        prop_assert_eq!(embed.acdc.digest.as_str(), CREDENTIAL);
        prop_assert_eq!(embed.acdc.schema.as_str(), SCHEMA);
        prop_assert_eq!(embed.iss.digest.as_str(), "EISS");
    }

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

#[test]
fn an_issuance_is_named_for_its_transaction_and_discriminated_by_its_credential() {
    assert_eq!(ISSUANCE_ROUTE.rsplit('/').next(), Some(TRANSACTION_SLOT));
    assert_eq!(ISSUANCE_SLOT, "acdc");
    assert_ne!(ISSUANCE_SLOT, TRANSACTION_SLOT);
    assert_eq!(REGISTRY_ROUTE.rsplit('/').next(), Some(REGISTRY_SLOT));
    assert_eq!(REVOCATION_ROUTE.rsplit('/').next(), Some(REVOCATION_SLOT));
}

#[test]
fn the_scenarios_registry_reproduces() -> Result<(), Box<dyn Error>> {
    let classified = classify(&proposal(
        REGISTRY_ROUTE,
        REGISTRY_SLOT,
        "AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s",
        "{}",
    ))?;
    let multisig = classified.as_multisig().ok_or("not a multisig proposal")?;
    let ExchangeEmbed::RegistryInception(embed) = &multisig.proposed.message else {
        return Err("not a registry embed".into());
    };
    assert_eq!(embed.vcp.nonce, "AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s");
    assert_eq!(embed.vcp.registry, REGISTRY);
    assert_eq!(embed.vcp.issuer, GROUP);
    Ok(())
}

#[test]
fn a_transaction_proposal_names_only_the_group() -> Result<(), Box<dyn Error>> {
    let classified = classify(&proposal(REGISTRY_ROUTE, REGISTRY_SLOT, "AHSND", "{}"))?;
    let multisig = classified.as_multisig().ok_or("not a multisig proposal")?;
    assert_eq!(multisig.attributes.group.qb64()?, GROUP);
    assert!(multisig.attributes.signing_members.is_none());
    assert!(multisig.attributes.rotation_members.is_none());
    Ok(())
}
