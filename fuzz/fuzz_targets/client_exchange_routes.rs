#![no_main]

//! Fuzzes the exchange route table and the message classifiers over hostile messages.
//!
//! Everything this target sees came from **another controller**, relayed by the agent. A multisig
//! proposal is somebody asking a member to sign a key event; an IPEX grant is somebody handing over
//! a credential. Nothing here verifies either — that is what the member's own keeper does next —
//! so the job of classification is narrower and sharper: **decide what a message is, and never be
//! wrong about it**.
//!
//! The reference decides by comparing one string, and then hands back a value typed as though the
//! payload had been checked. So the invariants fuzzed are the ones that difference creates.
//!
//! A classification is **sound**: a message that classifies as a route carries exactly the embed
//! that route names, and one that carries another route's embed — or none — is refused.
//!
//! A classification is **total on the route**: any route text either names one of the thirteen or
//! classifies as `Other` carrying that text verbatim. There is no third outcome and no panic, which
//! is what lets a caller handle an agent that invents a route.
//!
//! A classification is **honest about the group**: `gid` is a validated prefix or the message is
//! refused, and a member list that is present but malformed never reads as an absent one — the
//! failure mode that would let a proposal claim fewer signers than it named.
//!
//! And nothing an attribute block carries is dropped: the four labels this port reads are extracted
//! and everything else survives, because the reference's own variants declare an index signature.

use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};
use signify_client::endpoint::exchanges::{
    ClassifiedExchange, ExchangeRoute, GROUP_LABEL, IpexPayload, MultisigRoute, ROTATION_MEMBERS_LABEL,
    SIGNING_MEMBERS_LABEL, USAGE_LABEL,
};
use keria_types::api::{ExchangeEmbed, ExchangeRecord, ExchangeResource, MultisigExchangeResource};

/// The four labels this port reads out of an attribute block.
const DECLARED_LABELS: [&str; 4] = [GROUP_LABEL, SIGNING_MEMBERS_LABEL, ROTATION_MEMBERS_LABEL, USAGE_LABEL];

/// Returns the embed slot a classified proposal actually carried.
fn slot_of(embed: &ExchangeEmbed) -> &'static str {
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

/// Returns the embed slot a route promises.
fn promised_slot(route: MultisigRoute) -> &'static str {
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

/// Checks every invariant a classified message must satisfy.
fn check(record: &ExchangeRecord) {
    let Ok(classified) = ClassifiedExchange::classify(record) else {
        // A refusal is always allowed; what is never allowed is a wrong acceptance.
        return;
    };

    match &classified {
        ClassifiedExchange::Multisig(proposal) => {
            // Soundness: the embed is the one the route names.
            assert_eq!(
                slot_of(&proposal.proposed.message),
                promised_slot(proposal.route),
                "a proposal on {} carried a {} embed",
                proposal.route.as_str(),
                slot_of(&proposal.proposed.message)
            );
            assert_eq!(
                classified.route(),
                Some(ExchangeRoute::Multisig(proposal.route)),
                "a proposal disagreed with itself about its route"
            );
            assert_eq!(proposal.route.as_str(), record.route, "a proposal rewrote its route");

            // The three member-bearing steps always name their signers.
            if proposal.route.names_members() {
                assert!(
                    proposal.attributes.signing_members.is_some(),
                    "{} classified without naming its members",
                    proposal.route.as_str()
                );
            }
            // Nothing this port reads is duplicated into what it kept.
            for label in DECLARED_LABELS {
                assert!(
                    !proposal.attributes.additional.contains_key(label),
                    "{label} survived into the additional block"
                );
            }
        }
        ClassifiedExchange::Ipex(step) => {
            assert_eq!(
                classified.route(),
                Some(ExchangeRoute::Ipex(step.route)),
                "an IPEX step disagreed with itself about its route"
            );
            assert_eq!(step.route.as_str(), record.route, "an IPEX step rewrote its route");
            // Apply, agree, and admit embed nothing; the other two always embed something.
            let empty = matches!(step.payload, IpexPayload::Empty);
            assert_eq!(
                empty,
                matches!(
                    step.route,
                    signify_acdc::ipex::IpexRoute::Apply
                        | signify_acdc::ipex::IpexRoute::Agree
                        | signify_acdc::ipex::IpexRoute::Admit
                ),
                "{} embedded the wrong amount",
                step.route.as_str()
            );
        }
        ClassifiedExchange::Other { route } => {
            // Totality: an unnamed route keeps its text and claims nothing.
            assert_eq!(route, &record.route, "an unnamed route was rewritten");
            assert!(
                ExchangeRoute::parse(route).is_none(),
                "{route} is in the table and still classified as unnamed"
            );
            assert_eq!(classified.route(), None);
            assert!(classified.as_multisig().is_none());
            assert!(classified.as_ipex().is_none());
        }
    }

    // A named route never classifies as unnamed, whatever the payload is: only the payload can be
    // wrong, and that is a refusal rather than a downgrade.
    if ExchangeRoute::parse(&record.route).is_some() {
        assert!(
            !matches!(classified, ClassifiedExchange::Other { .. }),
            "{} classified as unnamed",
            record.route
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let route = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let attributes = parts.next().unwrap_or_default();
    let embeds = parts.next().unwrap_or_default();
    let document = parts.next().unwrap_or_default();

    // -----------------------------------------------------------------------
    // The table: a lookup is total and never rewrites what it was given.
    // -----------------------------------------------------------------------
    match ExchangeRoute::parse(&route) {
        Some(found) => {
            assert_eq!(found.as_str(), route, "a lookup rewrote its own route");
            assert_eq!(route.parse::<ExchangeRoute>().ok(), Some(found));
        }
        None => assert!(route.parse::<ExchangeRoute>().is_err()),
    }

    // -----------------------------------------------------------------------
    // A message assembled from the fuzzed blocks.
    // -----------------------------------------------------------------------
    let attribute_block: Value = serde_json::from_slice(attributes).unwrap_or(Value::Object(Map::new()));
    let embed_block: Value = serde_json::from_slice(embeds).unwrap_or(Value::Object(Map::new()));
    let assembled = serde_json::json!({
        "v": "KERI10JSON000100_",
        "t": "exn",
        "d": "EEXN",
        "i": "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p",
        "rp": "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1",
        "p": "",
        "dt": "2023-11-14T22:13:20.123000+00:00",
        "r": route,
        "q": {},
        "a": attribute_block,
        "e": embed_block,
    });
    if let Ok(record) = serde_json::from_value::<ExchangeRecord>(assembled) {
        check(&record);
    }

    // -----------------------------------------------------------------------
    // A whole document, as an agent would send it, through both containers.
    // -----------------------------------------------------------------------
    if let Ok(resource) = serde_json::from_slice::<ExchangeResource>(document) {
        check(&resource.exn);
        let plain = ClassifiedExchange::try_from(&resource);
        // The group form differs only in its wrapper, so it must classify identically.
        let grouped = MultisigExchangeResource {
            exn: resource.exn.clone(),
            paths: resource.pathed.clone(),
            group_name: None,
            member_name: None,
            sender: None,
        };
        match (plain, ClassifiedExchange::try_from(&grouped)) {
            (Ok(one), Ok(other)) => assert_eq!(one, other, "the two containers classified differently"),
            (Err(_), Err(_)) => {}
            (one, other) => panic!("the two containers disagreed: {one:?} against {other:?}"),
        }
    }

    if let Ok(resource) = serde_json::from_slice::<MultisigExchangeResource>(document) {
        check(&resource.exn);
    }
});
