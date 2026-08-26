//! Invariants of the exchange route table and the message classifiers.
//!
//! The reference's thirteen guards and thirteen assertions have one invariant between them — the
//! route matched — and the variant they narrow to asserts a second one that nothing checks. These
//! properties state both, and the second is the one that has content: **a classified message
//! carries what its route promised**.
//!
//! The other properties are about the seam. A route the table does not name must classify rather
//! than fail, because this crate itself sends one; a group request must classify exactly as the
//! plain form does, because upstream that costs a second overload on every function; and nothing —
//! no route text, no attribute block, no embed — may make classification panic.

use std::collections::BTreeSet;
use std::error::Error;

use proptest::prelude::*;
use serde_json::{Map, Value, json};
use signify_acdc::ipex::IpexRoute;
use signify_client::endpoint::exchanges::{
    ClassifiedExchange, ExchangeRoute, GROUP_LABEL, IpexPayload, MultisigRoute, ROTATION_MEMBERS_LABEL,
    SIGNING_MEMBERS_LABEL, USAGE_LABEL,
};
use signify_client::error::ClientError;
use signify_types::api::{ExchangeEmbed, ExchangeRecord, ExchangeResource, MultisigExchangeResource};

const MEMBER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SECOND: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const GROUP: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

const ANCHOR: &str = r#"{"v":"KERI10JSON000_","t":"ixn","d":"EANC","i":"EGRP","s":"2","p":"EIXN","a":[]}"#;
const ACDC: &str = r#"{"v":"ACDC10JSON000_","d":"ECRED","i":"EISSUER","ri":"EREG","s":"ESCHEMA","a":{"d":"EATTR","i":"EHOLDER","dt":"2023-11-14T22:13:20.123000+00:00"}}"#;
const ISSUANCE: &str = r#"{"v":"KERI10JSON000_","t":"iss","d":"EISS","i":"ECRED","s":"0","ri":"EREG","dt":"2023-11-14T22:13:20.123000+00:00"}"#;

/// One message on `route`, with the given attribute and embed blocks.
fn message(route: &str, attributes: &str, embeds: &str) -> Result<ExchangeRecord, Box<dyn Error>> {
    let document = format!(
        r#"{{"v":"KERI10JSON000100_","t":"exn","d":"EEXN","i":"{MEMBER}","rp":"{SECOND}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{attributes},"e":{embeds}}}"#
    );
    Ok(serde_json::from_str(&document)?)
}

/// The attribute block every real proposal sends.
fn group_block() -> String {
    format!(
        r#"{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":["{MEMBER}"],"{ROTATION_MEMBERS_LABEL}":["{SECOND}"]}}"#
    )
}

/// A well-formed embed for one multisig route.
fn embed_for(route: MultisigRoute) -> String {
    let inner = match route {
        MultisigRoute::Inception => r#""icp":{"v":"KERI10JSON000_","t":"icp","d":"EICP","i":"EGRP","s":"0","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":"0","b":[],"c":[],"a":[]}"#.to_owned(),
        MultisigRoute::Rotation => r#""rot":{"v":"KERI10JSON000_","t":"rot","d":"EROT","i":"EGRP","s":"1","p":"EICP","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":"0","br":[],"ba":[],"a":[]}"#.to_owned(),
        MultisigRoute::Interaction => r#""ixn":{"v":"KERI10JSON000_","t":"ixn","d":"EIXN","i":"EGRP","s":"1","p":"EICP","a":[]}"#.to_owned(),
        MultisigRoute::Reply => r#""rpy":{"v":"KERI10JSON000_","t":"rpy","d":"ERPY","dt":"2023-11-14T22:13:20.123000+00:00","r":"/end/role/add","a":{}}"#.to_owned(),
        MultisigRoute::RegistryInception => format!(
            r#""vcp":{},"anc":{ANCHOR}"#,
            r#"{"v":"KERI10JSON000_","t":"vcp","d":"EVCP","i":"EREG","ii":"EGRP","s":"0","c":["NB"],"bt":"0","b":[],"n":"AAAA"}"#
        ),
        MultisigRoute::Issuance => format!(r#""acdc":{ACDC},"iss":{ISSUANCE},"anc":{ANCHOR}"#),
        MultisigRoute::Exchange => r#""exn":{"v":"KERI10JSON000_","t":"exn","d":"EINNER","i":"EMEM","rp":"EPEER","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"/ipex/grant","q":{},"a":{},"e":{}}"#.to_owned(),
        MultisigRoute::Revocation => format!(
            r#""rev":{},"anc":{ANCHOR}"#,
            r#"{"v":"KERI10JSON000_","t":"rev","d":"EREV","i":"ECRED","s":"1","ri":"EREG","p":"EISS","dt":"2023-11-14T22:13:20.123000+00:00"}"#
        ),
    };
    format!(r#"{{"d":"EEMB",{inner}}}"#)
}

/// Which embed variant a route's well-formed message produces.
fn slot_matches(route: MultisigRoute, embed: &ExchangeEmbed) -> bool {
    match route {
        MultisigRoute::Inception => matches!(embed, ExchangeEmbed::Inception(_)),
        MultisigRoute::Rotation => matches!(embed, ExchangeEmbed::Rotation(_)),
        MultisigRoute::Interaction => matches!(embed, ExchangeEmbed::Interaction(_)),
        MultisigRoute::Reply => matches!(embed, ExchangeEmbed::Reply(_)),
        MultisigRoute::RegistryInception => matches!(embed, ExchangeEmbed::RegistryInception(_)),
        MultisigRoute::Issuance => matches!(embed, ExchangeEmbed::Issuance(_)),
        MultisigRoute::Exchange => matches!(embed, ExchangeEmbed::Exchange(_)),
        MultisigRoute::Revocation => matches!(embed, ExchangeEmbed::Revocation(_)),
    }
}

fn multisig_routes() -> impl Strategy<Value = MultisigRoute> {
    prop::sample::select(MultisigRoute::ALL.to_vec())
}

fn ipex_routes() -> impl Strategy<Value = IpexRoute> {
    prop::sample::select(IpexRoute::ALL.to_vec())
}

/// Route texts the table does not name, including the one this crate sends.
fn unnamed_routes() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/challenge/response".to_owned()),
        Just(String::new()),
        Just("/multisig".to_owned()),
        Just("/multisig/dip".to_owned()),
        Just("/ipex/spurn".to_owned()),
        Just("/MULTISIG/ICP".to_owned()),
        "/[a-z]{1,8}(/[a-z]{1,8}){0,2}",
        "[\\PC]{0,32}",
    ]
    .prop_filter("the table must not name it", |text| {
        ExchangeRoute::parse(text).is_none()
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Every route round-trips through the exact text a message carries.
    #[test]
    fn every_route_round_trips(index in 0_usize..ExchangeRoute::ALL.len()) {
        let route = ExchangeRoute::ALL.get(index).copied()
            .ok_or_else(|| TestCaseError::fail("the table shrank"))?;
        prop_assert_eq!(ExchangeRoute::parse(route.as_str()), Some(route));
        prop_assert_eq!(route.to_string(), route.as_str());
    }

    /// A well-formed message on a named route classifies, and carries the embed the route promised.
    ///
    /// This is the invariant the reference's assertions claim and never check.
    #[test]
    fn a_named_route_carries_what_it_promised(route in multisig_routes()) {
        let record = message(route.as_str(), &group_block(), &embed_for(route))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let classified = ClassifiedExchange::classify(&record)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let proposal = classified.as_multisig()
            .ok_or_else(|| TestCaseError::fail("a multisig route did not classify as one"))?;
        prop_assert_eq!(proposal.route, route);
        prop_assert!(slot_matches(route, &proposal.proposed.message));
        prop_assert_eq!(classified.route(), Some(ExchangeRoute::Multisig(route)));
    }

    /// A named route whose embed belongs to another named route is always refused.
    #[test]
    fn a_mismatched_embed_is_always_refused(
        declared in multisig_routes(),
        carried in multisig_routes(),
    ) {
        prop_assume!(declared != carried);
        // The issuance and registry embeds share the anchor field but not the slot, so every
        // distinct pair really is a mismatch.
        let record = message(declared.as_str(), &group_block(), &embed_for(carried))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let outcome = ClassifiedExchange::classify(&record);
        prop_assert!(
            matches!(outcome, Err(ClientError::ExchangeEmbedMismatch { .. })),
            "{} carrying {} was accepted",
            declared.as_str(),
            carried.as_str()
        );
    }

    /// A named route carrying no embed at all is always refused — where every upstream assertion
    /// accepts it.
    #[test]
    fn a_named_route_with_no_embed_is_always_refused(route in multisig_routes()) {
        let record = message(route.as_str(), &group_block(), "{}")
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let refused = matches!(
            ClassifiedExchange::classify(&record),
            Err(ClientError::ExchangeEmbedMismatch { found: "nothing", .. })
        );
        prop_assert!(refused, "{} with no embed was accepted", route.as_str());
    }

    /// A route the table does not name always classifies, and keeps its route verbatim.
    #[test]
    fn an_unnamed_route_always_classifies(route in unnamed_routes(), embeds in prop_oneof![
        Just("{}".to_owned()),
        Just(r#"{"d":"E","icp":7}"#.to_owned()),
        Just(r#"{"anything":"at all"}"#.to_owned()),
    ]) {
        let record = message(&route.replace('"', "'").replace('\\', ""), "{}", &embeds)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let classified = ClassifiedExchange::classify(&record)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        match classified {
            ClassifiedExchange::Other { route: carried } => {
                prop_assert_eq!(carried, record.route);
            }
            other => prop_assert!(false, "{:?} claimed a route", other),
        }
    }

    /// A classified message claims a route exactly when the table names one.
    #[test]
    fn a_classification_claims_a_route_exactly_when_the_table_names_it(
        named in multisig_routes(),
        unnamed in unnamed_routes(),
    ) {
        let known = ClassifiedExchange::classify(
            &message(named.as_str(), &group_block(), &embed_for(named))
                .map_err(|error| TestCaseError::fail(error.to_string()))?,
        )
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(known.route().is_some());

        let other = ClassifiedExchange::classify(
            &message(&unnamed.replace('"', "'").replace('\\', ""), "{}", "{}")
                .map_err(|error| TestCaseError::fail(error.to_string()))?,
        )
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(other.route(), None);
        prop_assert!(other.as_multisig().is_none());
        prop_assert!(other.as_ipex().is_none());
    }

    /// The group form and the plain form always classify identically.
    ///
    /// Upstream this needs a second overload on all twenty-six functions and eight extra variants,
    /// and the five IPEX assertions have none.
    #[test]
    fn a_group_request_classifies_as_the_plain_form_does(route in multisig_routes()) {
        let exn = message(route.as_str(), &group_block(), &embed_for(route))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let plain = ExchangeResource { exn: exn.clone(), pathed: Map::new() };
        let grouped = MultisigExchangeResource {
            exn,
            paths: Map::new(),
            group_name: Some("group".to_owned()),
            member_name: Some("member1".to_owned()),
            sender: Some(MEMBER.to_owned()),
        };
        let from_plain = ClassifiedExchange::try_from(&plain)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let from_group = ClassifiedExchange::try_from(&grouped)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(from_plain, from_group);
    }

    /// The three empty IPEX steps embed nothing, and the two that embed always do.
    #[test]
    fn an_ipex_step_embeds_what_its_route_says(route in ipex_routes()) {
        let embeds = match route {
            IpexRoute::Apply | IpexRoute::Agree | IpexRoute::Admit => "{}".to_owned(),
            IpexRoute::Offer => format!(r#"{{"d":"EEMB","acdc":{ACDC}}}"#),
            IpexRoute::Grant => format!(r#"{{"d":"EEMB","acdc":{ACDC},"iss":{ISSUANCE},"anc":{ANCHOR}}}"#),
        };
        let record = message(route.as_str(), "{}", &embeds)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let classified = ClassifiedExchange::classify(&record)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let step = classified.as_ipex()
            .ok_or_else(|| TestCaseError::fail("an IPEX route did not classify as one"))?;
        prop_assert_eq!(step.route, route);
        match route {
            IpexRoute::Apply | IpexRoute::Agree | IpexRoute::Admit => {
                prop_assert_eq!(&step.payload, &IpexPayload::Empty);
            }
            IpexRoute::Offer => prop_assert!(matches!(step.payload, IpexPayload::Offer(_))),
            IpexRoute::Grant => prop_assert!(matches!(step.payload, IpexPayload::Grant(_))),
        }
    }

    /// A proposal's extra labels survive, and never collide with the four the port reads.
    #[test]
    fn an_attribute_block_keeps_what_it_was_not_asked_about(
        label in "[a-z]{1,10}",
        route in multisig_routes(),
    ) {
        prop_assume!(![GROUP_LABEL, SIGNING_MEMBERS_LABEL, ROTATION_MEMBERS_LABEL, USAGE_LABEL].contains(&label.as_str()));
        let block = json!({
            GROUP_LABEL: GROUP,
            SIGNING_MEMBERS_LABEL: [MEMBER],
            label.as_str(): { "kept": true },
        })
        .to_string();
        let record = message(route.as_str(), &block, &embed_for(route))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let classified = ClassifiedExchange::classify(&record)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let proposal = classified.as_multisig()
            .ok_or_else(|| TestCaseError::fail("did not classify"))?;
        prop_assert_eq!(proposal.attributes.additional.len(), 1);
        prop_assert!(proposal.attributes.additional.contains_key(&label));
        for declared in [GROUP_LABEL, SIGNING_MEMBERS_LABEL, ROTATION_MEMBERS_LABEL, USAGE_LABEL] {
            prop_assert!(!proposal.attributes.additional.contains_key(declared));
        }
    }

    /// Arbitrary route text never panics: a message either classifies or is refused with a reason.
    #[test]
    fn arbitrary_route_text_never_panics(route in "[\\PC]{0,64}") {
        let escaped = serde_json::to_string(&route)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let document = format!(
            r#"{{"v":"KERI10JSON000100_","t":"exn","d":"EEXN","i":"{MEMBER}","rp":"{SECOND}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":{escaped},"q":{{}},"a":{{}},"e":{{}}}}"#
        );
        let Ok(record) = serde_json::from_str::<ExchangeRecord>(&document) else { return Ok(()) };
        match ClassifiedExchange::classify(&record) {
            Ok(classified) => {
                // Anything that classifies either names a route in the table or reports the text.
                if let Some(named) = classified.route() {
                    prop_assert_eq!(named.as_str(), record.route);
                } else {
                    let unnamed = matches!(classified, ClassifiedExchange::Other { .. });
                    prop_assert!(unnamed, "a routeless classification is not Other");
                }
            }
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }

    /// Arbitrary bytes never panic anywhere in the classifier.
    #[test]
    fn arbitrary_bytes_decode_or_are_refused(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(resource) = serde_json::from_slice::<ExchangeResource>(&bytes) {
            match ClassifiedExchange::try_from(&resource) {
                Ok(classified) => prop_assert!(classified.route().is_some() || classified.as_multisig().is_none()),
                Err(error) => prop_assert!(!error.to_string().is_empty()),
            }
        }
    }
}

/// Regression: the thirteen routes are exactly the reference's, and all distinct.
#[test]
fn the_table_is_thirteen_distinct_routes() {
    let texts: BTreeSet<&str> = ExchangeRoute::ALL.iter().map(|route| route.as_str()).collect();
    assert_eq!(texts.len(), 13);
    assert_eq!(MultisigRoute::ALL.len(), 8);
    assert_eq!(IpexRoute::ALL.len(), 5);
}

/// Regression: a revocation proposal must carry the anchor the schema declares.
///
/// The reference's hand-written `MultisigRevExchange` declares `e: { rev, d? }` and omits the `anc`
/// its own generated schema requires, so a caller who narrows through `assertMultisigRev` cannot
/// reach it. Roadmap 4.1 modelled the schema; this port keeps the field.
#[test]
fn a_revocation_proposal_keeps_the_anchor_the_variant_hides() -> Result<(), Box<dyn Error>> {
    let classified = ClassifiedExchange::classify(&message(
        "/multisig/rev",
        &group_block(),
        &embed_for(MultisigRoute::Revocation),
    )?)?;
    let proposal = classified.as_multisig().ok_or("did not classify")?;
    let ExchangeEmbed::Revocation(revocation) = &proposal.proposed.message else {
        return Err("not a revocation embed".into());
    };
    assert_eq!(revocation.rev.digest, "EREV");
    assert_eq!(revocation.anc.digest(), "EANC");
    Ok(())
}

/// Regression: `/challenge/response` — the route this crate itself sends — is not in the table and
/// classifies as an ordinary message.
#[test]
fn the_route_this_crate_sends_is_not_in_the_table() -> Result<(), Box<dyn Error>> {
    assert!(ExchangeRoute::parse("/challenge/response").is_none());
    let classified =
        ClassifiedExchange::classify(&message("/challenge/response", r#"{"words":["shell","gloom"]}"#, "{}")?)?;
    assert_eq!(
        classified,
        ClassifiedExchange::Other {
            route: "/challenge/response".to_owned()
        }
    );
    Ok(())
}

/// Regression: a grant and an issuance carry the same three fields, so one shape decodes both — and
/// each still classifies under its own route.
#[test]
fn a_grant_and_an_issuance_share_one_embed_shape() -> Result<(), Box<dyn Error>> {
    let embeds = embed_for(MultisigRoute::Issuance);

    let proposal = ClassifiedExchange::classify(&message("/multisig/iss", &group_block(), &embeds)?)?;
    assert_eq!(
        proposal.as_multisig().map(|record| record.route),
        Some(MultisigRoute::Issuance)
    );

    let grant = ClassifiedExchange::classify(&message("/ipex/grant", "{}", &embeds)?)?;
    let step = grant.as_ipex().ok_or("not an IPEX step")?;
    assert_eq!(step.route, IpexRoute::Grant);
    assert!(matches!(step.payload, IpexPayload::Grant(_)));
    Ok(())
}

/// Regression: an offer's embed is a credential alone, which is not one of Roadmap 4.1's eight.
#[test]
fn an_offer_embeds_a_credential_and_nothing_else() -> Result<(), Box<dyn Error>> {
    let embeds = format!(r#"{{"d":"EEMB","acdc":{ACDC}}}"#);
    let classified = ClassifiedExchange::classify(&message("/ipex/offer", "{}", &embeds)?)?;
    let step = classified.as_ipex().ok_or("not an IPEX step")?;
    let IpexPayload::Offer(offer) = &step.payload else {
        return Err("not an offer payload".into());
    };
    assert_eq!(offer.digest, "EEMB");
    assert_eq!(offer.acdc.digest, "ECRED");

    // The schema's own embed union has no acdc-only member, so this shape is modelled here.
    let block: Value = serde_json::from_str(&embeds)?;
    assert!(serde_json::from_value::<signify_types::api::ExchangeEmbeds>(block).is_err());
    Ok(())
}

/// Regression: a proposal that names no group is refused, however the block is malformed.
#[test]
fn a_proposal_without_a_group_is_refused() -> Result<(), Box<dyn Error>> {
    for block in ["{}", r#"{"gid":7}"#, r#"{"gid":"not a prefix"}"#, "[]", "null"] {
        let outcome =
            ClassifiedExchange::classify(&message("/multisig/icp", block, &embed_for(MultisigRoute::Inception))?);
        assert!(outcome.is_err(), "{block} was accepted");
    }
    Ok(())
}
