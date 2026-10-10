//! Exact route-table and classifier vectors recorded from the pinned reference's own `exchanging.ts`.
//!
//! Thirteen guards and thirteen assertions, executed and declared, and the narrowing that is only a claim.

use std::error::Error;

use keria_types::api::{ExchangeEmbed, ExchangeRecord, ExchangeResource, MultisigExchangeResource};
use serde::Deserialize;
use serde_json::{Map, Value};
use signify_client::endpoint::challenges::CHALLENGE_RESPONSE_ROUTE;
use signify_client::endpoint::exchanges::{
    ClassifiedExchange, ExchangeRoute, GROUP_LABEL, IpexPayload, MultisigRoute, ROTATION_MEMBERS_LABEL,
    SIGNING_MEMBERS_LABEL, USAGE_LABEL,
};
use signify_client::error::ClientError;
use signify_keys::acdc::ipex::IpexRoute;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-exchange-routes/v1.json");

const MEMBER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SECOND: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const GROUP: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

// --- Fixture model ---
#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    declarations: Declarations,
    route_table: Vec<RouteEntry>,
    variant_shapes: Vec<VariantShape>,
    observed_attributes: Map<String, Value>,
    send_call_sites: usize,
    executed: Vec<Executed>,
    hostile: Vec<Hostile>,
    shape_findings: Value,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    route_constants: Vec<RouteConstant>,
    assert_route: String,
    exn_message_alias: String,
    exchange_resource_v1_alias: String,
    anchor_event_alias: String,
    with_group_metadata_alias: String,
    schema_exn_embeds: String,
    schema_multisig_revoke_embeds: String,
    schema_multisig_issue_embeds: String,
    schema_exn_multisig: String,
    schema_exchange_resource: String,
    attribute_labels_in_schema: AttributeScan,
}

#[derive(Debug, Deserialize)]
struct AttributeScan {
    in_generated_schema: SchemaCounts,
    note: String,
}

#[derive(Debug, Deserialize)]
struct SchemaCounts {
    gid: usize,
    smids: usize,
    rmids: usize,
}

#[derive(Debug, Deserialize)]
struct RouteConstant {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct RouteEntry {
    constant: String,
    value: String,
    variant: String,
    group: Option<String>,
    guard: String,
    assertion: String,
    slot: Option<String>,
    variant_declaration: String,
    group_declaration: Option<String>,
    guard_body: String,
    assertion_body: String,
    guard_consumers: Consumers,
    assertion_consumers: Consumers,
}

#[derive(Debug, Deserialize)]
struct Consumers {
    declared_in: usize,
    consumer_total: usize,
    scanned_files: usize,
}

#[derive(Debug, Deserialize)]
struct VariantShape {
    route: String,
    variant: String,
    embed_block: Option<String>,
    attribute_block: Option<String>,
    has_group_variant: bool,
}

#[derive(Debug, Deserialize)]
struct Executed {
    route: String,
    guard: String,
    assertion: String,
    guard_on_own_route: Verdict,
    guard_on_other_route: Verdict,
    assertion_on_own_route: Verdict,
    assertion_on_other_route: Verdict,
    guard_on_empty_payload: Verdict,
    assertion_on_empty_payload: Verdict,
    declared_slot_present_when_empty: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct Verdict {
    outcome: String,
    #[serde(default, rename = "verdict")]
    value: Option<Value>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    kind: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Hostile {
    name: String,
    guard: Verdict,
    assertion: Verdict,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

fn entry<'a>(fixture: &'a Fixture, route: &str) -> Result<&'a Executed, Box<dyn Error>> {
    fixture
        .executed
        .iter()
        .find(|record| record.route == route)
        .ok_or_else(|| format!("no recorded execution for {route}").into())
}

fn shape<'a>(fixture: &'a Fixture, variant: &str) -> Result<&'a VariantShape, Box<dyn Error>> {
    fixture
        .variant_shapes
        .iter()
        .find(|record| record.variant == variant)
        .ok_or_else(|| format!("no recorded shape for {variant}").into())
}

fn message(route: &str, attributes: &str, embeds: &str) -> Result<ExchangeRecord, Box<dyn Error>> {
    let document = format!(
        r#"{{"v":"KERI10JSON000100_","t":"exn","d":"EEXN","i":"{MEMBER}","rp":"{SECOND}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{attributes},"e":{embeds}}}"#
    );
    Ok(serde_json::from_str(&document)?)
}

fn group_block() -> String {
    format!(
        r#"{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":["{MEMBER}","{SECOND}"],"{ROTATION_MEMBERS_LABEL}":["{MEMBER}","{SECOND}"]}}"#
    )
}

fn embed_for(route: MultisigRoute) -> String {
    let inner = match route {
        MultisigRoute::Inception => {
            r#""icp":{"v":"KERI10JSON000_","t":"icp","d":"EICP","i":"EGRP","s":"0","kt":"2","k":["DAA","DBB"],"nt":"2","n":["EAA","EBB"],"bt":"0","b":[],"c":[],"a":[]}"#.to_owned()
        }
        MultisigRoute::Rotation => {
            r#""rot":{"v":"KERI10JSON000_","t":"rot","d":"EROT","i":"EGRP","s":"1","p":"EICP","kt":"2","k":["DAA","DBB"],"nt":"2","n":["EAA","EBB"],"bt":"0","br":[],"ba":[],"a":[]}"#.to_owned()
        }
        MultisigRoute::Interaction => {
            r#""ixn":{"v":"KERI10JSON000_","t":"ixn","d":"EIXN","i":"EGRP","s":"1","p":"EICP","a":[]}"#.to_owned()
        }
        MultisigRoute::Reply => {
            r#""rpy":{"v":"KERI10JSON000_","t":"rpy","d":"ERPY","dt":"2023-11-14T22:13:20.123000+00:00","r":"/end/role/add","a":{}}"#.to_owned()
        }
        MultisigRoute::RegistryInception => format!(
            r#""vcp":{},"anc":{}"#,
            r#"{"v":"KERI10JSON000_","t":"vcp","d":"EVCP","i":"EREG","ii":"EGRP","s":"0","c":["NB"],"bt":"0","b":[],"n":"AAAA"}"#,
            ANCHOR
        ),
        MultisigRoute::Issuance => format!(r#""acdc":{ACDC},"iss":{ISSUANCE},"anc":{ANCHOR}"#),
        MultisigRoute::Exchange => {
            r#""exn":{"v":"KERI10JSON000_","t":"exn","d":"EINNER","i":"EMEM","rp":"EPEER","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"/ipex/grant","q":{},"a":{},"e":{}}"#.to_owned()
        }
        MultisigRoute::Revocation => format!(
            r#""rev":{},"anc":{}"#,
            r#"{"v":"KERI10JSON000_","t":"rev","d":"EREV","i":"ECRED","s":"1","ri":"EREG","p":"EISS","dt":"2023-11-14T22:13:20.123000+00:00"}"#,
            ANCHOR
        ),
    };
    format!(r#"{{"d":"EEMB",{inner}}}"#)
}

const ANCHOR: &str = r#"{"v":"KERI10JSON000_","t":"ixn","d":"EANC","i":"EGRP","s":"2","p":"EIXN","a":[]}"#;
const ACDC: &str = r#"{"v":"ACDC10JSON000_","d":"ECRED","i":"EISSUER","ri":"EREG","s":"ESCHEMA","a":{"d":"EATTR","i":"EHOLDER","dt":"2023-11-14T22:13:20.123000+00:00"}}"#;
const ISSUANCE: &str = r#"{"v":"KERI10JSON000_","t":"iss","d":"EISS","i":"ECRED","s":"0","ri":"EREG","dt":"2023-11-14T22:13:20.123000+00:00"}"#;

// --- Manifest and provenance ---
#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert_ne!(fixture.generated_on, "");
    assert!(fixture.sources.iter().any(|source| source.ends_with("exchanging.ts")));
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("keria-api-schema.ts"))
    );
    assert!(fixture.provenance.note.contains("type system"));

    assert_eq!(fixture.route_table.len(), 13);
    assert_eq!(fixture.variant_shapes.len(), 13);
    assert_eq!(fixture.executed.len(), 13);
    assert_eq!(fixture.hostile.len(), 6);
    assert!(fixture.send_call_sites >= 30);
    Ok(())
}

#[test]
fn the_thirteen_constants_are_this_ports_route_table() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.declarations.route_constants.len(), 13);

    let recorded: Vec<&str> = fixture
        .declarations
        .route_constants
        .iter()
        .map(|constant| constant.value.as_str())
        .collect();
    let ported: Vec<&str> = ExchangeRoute::ALL.iter().map(|route| route.as_str()).collect();
    assert_eq!(recorded, ported);

    for constant in &fixture.declarations.route_constants {
        assert!(constant.name.ends_with("_ROUTE"), "{}", constant.name);
        let parsed = constant.value.parse::<ExchangeRoute>()?;
        assert_eq!(parsed.as_str(), constant.value);
    }
    Ok(())
}

#[test]
fn the_five_ipex_routes_are_roadmap_6_3s() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded: Vec<&str> = fixture
        .declarations
        .route_constants
        .iter()
        .filter(|constant| constant.name.starts_with("IPEX_"))
        .map(|constant| constant.value.as_str())
        .collect();
    assert_eq!(recorded.len(), 5);
    for text in &recorded {
        let route = text.parse::<ExchangeRoute>()?;
        assert!(matches!(route, ExchangeRoute::Ipex(_)), "{text} is not an IPEX route");
    }
    for route in IpexRoute::ALL {
        assert!(recorded.contains(&route.as_str()), "{} is missing", route.as_str());
    }
    Ok(())
}

// --- The declared half: what the variants say, and what nothing checks ---
#[test]
fn every_guard_and_assertion_is_one_route_comparison() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for record in &fixture.route_table {
        assert!(
            record
                .guard_body
                .contains(&format!("msg.exn.r === {}", record.constant)),
            "{} is no longer one comparison: {}",
            record.guard,
            record.guard_body
        );
        assert!(
            record
                .assertion_body
                .contains(&format!("assertRoute(msg, {}", record.constant)),
            "{} no longer delegates: {}",
            record.assertion,
            record.assertion_body
        );
        for slot in ["exn.e", "exn.a"] {
            assert!(!record.guard_body.contains(slot));
            assert!(!record.assertion_body.contains(slot));
        }
    }
    let helper = &fixture.declarations.assert_route;
    assert!(helper.contains("msg.exn?.r !== route"));
    assert!(helper.contains("Expected ${label} but got route: ${msg.exn?.r}"));
    Ok(())
}

#[test]
fn the_thirteen_guards_have_no_consumers_and_six_assertions_have_none_either() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let mut dead = Vec::new();
    for record in &fixture.route_table {
        assert_eq!(record.guard_consumers.scanned_files, 117);
        assert_eq!(
            record.guard_consumers.consumer_total, 0,
            "{} gained a consumer",
            record.guard
        );
        assert!(record.guard_consumers.declared_in >= 1);
        if record.assertion_consumers.consumer_total == 0 {
            dead.push(record.assertion.as_str());
        }
    }
    assert_eq!(dead.len(), 6);
    assert_eq!(fixture.route_table.len() + dead.len(), 19);

    let used: usize = fixture
        .route_table
        .iter()
        .map(|record| record.assertion_consumers.consumer_total)
        .sum();
    assert_eq!(used, 19, "the assertion call sites changed");

    for record in &fixture.route_table {
        let suffix = record.assertion.trim_start_matches("assert");
        assert_eq!(record.guard, format!("is{suffix}"));
        assert_eq!(record.variant, format!("{suffix}Exchange"));
        assert!(record.variant_declaration.contains(&record.constant));
        assert_eq!(
            record.slot.is_some(),
            !matches!(record.value.as_str(), "/ipex/apply" | "/ipex/agree" | "/ipex/admit")
        );
    }
    Ok(())
}

#[test]
fn every_variant_declares_the_slot_this_port_requires() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for route in MultisigRoute::ALL {
        let recorded = fixture
            .variant_shapes
            .iter()
            .find(|record| record.route == route.as_str())
            .ok_or("no recorded shape")?;
        let block = recorded.embed_block.as_deref().ok_or("no recorded embed block")?;
        let slot = match route {
            MultisigRoute::Inception => "icp:",
            MultisigRoute::Rotation => "rot:",
            MultisigRoute::Interaction => "ixn:",
            MultisigRoute::Reply => "rpy:",
            MultisigRoute::RegistryInception => "vcp:",
            MultisigRoute::Issuance => "acdc:",
            MultisigRoute::Exchange => "exn:",
            MultisigRoute::Revocation => "rev:",
        };
        assert!(
            block.starts_with(slot),
            "{} declares {block:?}, which does not start with {slot}",
            route.as_str()
        );
    }
    Ok(())
}

#[test]
fn only_the_three_member_bearing_routes_declare_members() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for route in MultisigRoute::ALL {
        let recorded = fixture
            .variant_shapes
            .iter()
            .find(|record| record.route == route.as_str())
            .ok_or("no recorded shape")?;
        let block = recorded.attribute_block.as_deref().ok_or("no attribute block")?;
        assert!(block.contains(GROUP_LABEL), "{} declares no gid", route.as_str());
        assert_eq!(
            block.contains(SIGNING_MEMBERS_LABEL),
            route.names_members(),
            "{} disagrees with this port about smids",
            route.as_str()
        );
        assert_eq!(block.contains(ROTATION_MEMBERS_LABEL), route.names_members());
    }
    let registry = shape(&fixture, "MultisigVcpExchange")?;
    assert!(
        registry
            .attribute_block
            .as_deref()
            .is_some_and(|block| block.contains(USAGE_LABEL))
    );
    Ok(())
}

#[test]
fn the_five_ipex_variants_declare_no_attribute_block() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for variant in [
        "IpexGrantExchange",
        "IpexOfferExchange",
        "IpexApplyExchange",
        "IpexAgreeExchange",
        "IpexAdmitExchange",
    ] {
        assert_eq!(shape(&fixture, variant)?.attribute_block, None, "{variant}");
    }
    let classified = ClassifiedExchange::classify(&message("/ipex/admit", "{}", "{}")?)?;
    assert!(classified.as_ipex().is_some());
    Ok(())
}

#[test]
fn only_multisig_routes_have_a_group_variant() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let with_group: Vec<&str> = fixture
        .variant_shapes
        .iter()
        .filter(|record| record.has_group_variant)
        .map(|record| record.route.as_str())
        .collect();
    assert_eq!(with_group.len(), 8);
    assert!(with_group.iter().all(|route| route.starts_with("/multisig/")));

    for record in &fixture.route_table {
        assert_eq!(record.group.is_some(), record.value.starts_with("/multisig/"));
        assert_eq!(record.group_declaration.is_some(), record.group.is_some());
    }
    assert!(fixture.declarations.with_group_metadata_alias.contains("groupName"));
    assert!(fixture.declarations.exn_message_alias.contains("ExnMultisig"));
    assert!(
        fixture
            .declarations
            .exchange_resource_v1_alias
            .contains("ExchangeResource")
    );
    Ok(())
}

#[test]
fn the_generated_schema_names_no_group_attribute() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let counts = &fixture.declarations.attribute_labels_in_schema.in_generated_schema;
    assert_eq!((counts.gid, counts.smids, counts.rmids), (0, 0, 0));
    assert_ne!(fixture.declarations.attribute_labels_in_schema.note, "");
    assert!(fixture.declarations.schema_exchange_resource.contains("pathed"));
    assert!(fixture.declarations.schema_exn_multisig.contains("paths"));
    Ok(())
}

#[test]
fn the_hand_written_revocation_variant_hides_the_anchor_its_schema_declares() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let revocation = shape(&fixture, "MultisigRevExchange")?;
    let block = revocation.embed_block.as_deref().ok_or("no embed block")?;
    assert!(block.contains("rev:"));
    assert!(!block.contains("anc:"), "the variant now declares its anchor: {block}");
    assert!(fixture.declarations.schema_multisig_revoke_embeds.contains("anc:"));

    let with_anchor = message("/multisig/rev", &group_block(), &embed_for(MultisigRoute::Revocation))?;
    let classified = ClassifiedExchange::classify(&with_anchor)?;
    assert!(matches!(
        classified.as_multisig().map(|proposal| proposal.route),
        Some(MultisigRoute::Revocation)
    ));

    let without = format!(
        r#"{{"d":"EEMB","rev":{}}}"#,
        r#"{"v":"KERI10JSON000_","t":"rev","d":"EREV","i":"ECRED","s":"1","ri":"EREG","p":"EISS","dt":"2023-11-14T22:13:20.123000+00:00"}"#
    );
    assert!(
        ClassifiedExchange::classify(&message("/multisig/rev", &group_block(), &without)?).is_err(),
        "a revocation with no anchor was accepted"
    );
    Ok(())
}

#[test]
fn a_grant_and_an_issuance_declare_the_same_embed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let grant = shape(&fixture, "IpexGrantExchange")?.embed_block.clone();
    let issuance = shape(&fixture, "MultisigIssExchange")?.embed_block.clone();
    assert_eq!(grant, issuance, "the two embed blocks diverged");
    assert!(fixture.declarations.schema_multisig_issue_embeds.contains("acdc"));

    let embeds = embed_for(MultisigRoute::Issuance);
    let proposal = ClassifiedExchange::classify(&message("/multisig/iss", &group_block(), &embeds)?)?;
    assert!(matches!(
        proposal.as_multisig().map(|record| record.route),
        Some(MultisigRoute::Issuance)
    ));
    let grant_message = ClassifiedExchange::classify(&message("/ipex/grant", "{}", &embeds)?)?;
    let step = grant_message.as_ipex().ok_or("not an IPEX step")?;
    assert_eq!(step.route, IpexRoute::Grant);
    assert!(matches!(step.payload, IpexPayload::Grant(_)));
    Ok(())
}

#[test]
fn the_schema_models_no_ipex_embed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let union = &fixture.declarations.schema_exn_embeds;
    for member in [
        "MultisigInceptEmbeds",
        "MultisigRotateEmbeds",
        "MultisigInteractEmbeds",
        "MultisigRegistryInceptEmbeds",
        "MultisigIssueEmbeds",
        "MultisigRevokeEmbeds",
        "MultisigRpyEmbeds",
        "MultisigExnEmbeds",
    ] {
        assert!(union.contains(member), "the union no longer names {member}");
    }
    assert_eq!(union.matches("Embeds']").count(), 8, "the union changed size: {union}");
    Ok(())
}

// --- The executed half: what the guards and assertions actually did ---
#[test]
fn every_guard_agreed_with_its_own_route_and_refused_another() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for record in &fixture.executed {
        assert_eq!(record.guard_on_own_route.outcome, "returned");
        assert_eq!(record.guard_on_own_route.value, Some(Value::Bool(true)));
        assert_eq!(record.guard_on_other_route.value, Some(Value::Bool(false)));
        assert_eq!(record.assertion_on_own_route.outcome, "returned");
        assert_eq!(record.assertion_on_other_route.outcome, "threw");

        let error = record.assertion_on_other_route.error.as_deref().ok_or("no error")?;
        assert!(error.starts_with("Expected "), "{error}");
        assert!(error.contains(" but got route: /multisig/"), "{error}");

        let route = record.route.parse::<ExchangeRoute>()?;
        assert_eq!(route.as_str(), record.route);
        assert_eq!(record.guard, format!("is{}", &record.assertion["assert".len()..]));
    }
    Ok(())
}

#[test]
fn a_route_that_promises_a_payload_it_does_not_carry_is_accepted_upstream_and_refused_here()
-> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for route in MultisigRoute::ALL {
        let record = entry(&fixture, route.as_str())?;
        assert_eq!(
            record.guard_on_empty_payload.value,
            Some(Value::Bool(true)),
            "{} refused an empty payload",
            record.guard
        );
        assert_eq!(
            record.assertion_on_empty_payload.outcome, "returned",
            "{} refused an empty payload",
            record.assertion
        );
        assert_eq!(record.declared_slot_present_when_empty, Some(false));

        let outcome = ClassifiedExchange::classify(&message(route.as_str(), &group_block(), "{}")?);
        assert!(
            matches!(
                outcome,
                Err(ClientError::ExchangeEmbedMismatch { found: "nothing", .. })
            ),
            "{}: {outcome:?}",
            route.as_str()
        );
    }
    Ok(())
}

#[test]
fn every_multisig_route_classifies_the_message_it_promises() -> Result<(), Box<dyn Error>> {
    for route in MultisigRoute::ALL {
        let classified = ClassifiedExchange::classify(&message(route.as_str(), &group_block(), &embed_for(route))?)?;
        let proposal = classified
            .as_multisig()
            .ok_or_else(|| format!("{} did not classify", route.as_str()))?;
        assert_eq!(proposal.route, route);
        assert_eq!(proposal.proposed.digest, "EEMB");
        let expected = match route {
            MultisigRoute::Inception => matches!(proposal.proposed.message, ExchangeEmbed::Inception(_)),
            MultisigRoute::Rotation => matches!(proposal.proposed.message, ExchangeEmbed::Rotation(_)),
            MultisigRoute::Interaction => matches!(proposal.proposed.message, ExchangeEmbed::Interaction(_)),
            MultisigRoute::Reply => matches!(proposal.proposed.message, ExchangeEmbed::Reply(_)),
            MultisigRoute::RegistryInception => {
                matches!(proposal.proposed.message, ExchangeEmbed::RegistryInception(_))
            }
            MultisigRoute::Issuance => matches!(proposal.proposed.message, ExchangeEmbed::Issuance(_)),
            MultisigRoute::Exchange => matches!(proposal.proposed.message, ExchangeEmbed::Exchange(_)),
            MultisigRoute::Revocation => matches!(proposal.proposed.message, ExchangeEmbed::Revocation(_)),
        };
        assert!(expected, "{} carried the wrong embed", route.as_str());
    }
    Ok(())
}

#[test]
fn a_guard_and_its_assertion_fail_differently_on_a_message_with_no_exn() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = fixture
        .hostile
        .iter()
        .find(|record| record.name == "no_exn_at_all")
        .ok_or("no recorded case")?;

    assert_eq!(record.guard.outcome, "threw");
    assert_eq!(record.guard.kind.as_deref(), Some("TypeError"));
    assert_eq!(record.assertion.kind.as_deref(), Some("Error"));
    assert!(
        record
            .assertion
            .error
            .as_deref()
            .is_some_and(|error| error.contains("but got route: undefined"))
    );

    for wrong in ["{}", r#"{"exn":null}"#, r#"{"pathed":{}}"#] {
        assert!(
            serde_json::from_str::<ExchangeResource>(wrong).is_err(),
            "{wrong} decoded as an exchange resource"
        );
    }
    Ok(())
}

#[test]
fn the_recorded_hostile_shapes_are_each_accounted_for() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let names: Vec<&str> = fixture.hostile.iter().map(|record| record.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "no_exn_at_all",
            "exn_is_null",
            "exn_has_no_route",
            "route_is_a_number",
            "route_carries_the_label_text",
            "an_unknown_route",
        ]
    );
    for record in &fixture.hostile {
        assert_eq!(record.assertion.outcome, "threw", "{}", record.name);
    }

    let confusing = fixture
        .hostile
        .iter()
        .find(|record| record.name == "route_carries_the_label_text")
        .ok_or("no recorded case")?;
    assert_eq!(
        confusing.assertion.error.as_deref(),
        Some("Expected Multisig ICP message but got route: Multisig ICP message")
    );
    Ok(())
}

#[test]
fn an_unnamed_route_is_a_message_here_and_a_failure_upstream() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = fixture
        .hostile
        .iter()
        .find(|record| record.name == "an_unknown_route")
        .ok_or("no recorded case")?;
    assert_eq!(record.guard.value, Some(Value::Bool(false)));
    assert_eq!(record.assertion.outcome, "threw");
    assert!(
        record
            .assertion
            .error
            .as_deref()
            .is_some_and(|error| error.contains(CHALLENGE_RESPONSE_ROUTE))
    );

    let classified = ClassifiedExchange::classify(&message(
        CHALLENGE_RESPONSE_ROUTE,
        r#"{"words":["shell","gloom"]}"#,
        "{}",
    )?)?;
    assert_eq!(
        classified,
        ClassifiedExchange::Other {
            route: CHALLENGE_RESPONSE_ROUTE.to_owned()
        }
    );
    assert!(CHALLENGE_RESPONSE_ROUTE.parse::<ExchangeRoute>().is_err());
    Ok(())
}

// --- What the integration tests actually send ---
#[test]
fn every_attribute_block_the_reference_sends_is_one_this_port_accepts() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let mut checked = 0_usize;
    for (route_text, observed) in &fixture.observed_attributes {
        let Some(ExchangeRoute::Multisig(route)) = ExchangeRoute::parse(route_text) else {
            continue;
        };
        let sets = observed
            .get("label_sets")
            .and_then(Value::as_array)
            .ok_or("no recorded label sets")?;
        for set in sets {
            let labels: Vec<&str> = set.as_str().ok_or("a label set is not text")?.split(',').collect();
            assert_eq!(
                labels.contains(&SIGNING_MEMBERS_LABEL),
                route.names_members(),
                "{route_text} sends {labels:?}"
            );
            assert!(labels.contains(&GROUP_LABEL), "{route_text} sends no group");

            let mut block = Map::new();
            for label in &labels {
                let value = match *label {
                    GROUP_LABEL => Value::String(GROUP.to_owned()),
                    SIGNING_MEMBERS_LABEL | ROTATION_MEMBERS_LABEL => {
                        Value::Array(vec![Value::String(MEMBER.to_owned())])
                    }
                    other => Value::String(other.to_owned()),
                };
                block.insert((*label).to_owned(), value);
            }
            let rendered = serde_json::to_string(&Value::Object(block))?;
            let classified = ClassifiedExchange::classify(&message(route_text, &rendered, &embed_for(route))?)?;
            let proposal = classified.as_multisig().ok_or("did not classify")?;
            assert_eq!(proposal.route, route);
            assert_eq!(
                proposal.attributes.signing_members.is_some(),
                labels.contains(&SIGNING_MEMBERS_LABEL)
            );
            assert_eq!(proposal.attributes.usage.is_some(), labels.contains(&USAGE_LABEL));
            checked = checked.saturating_add(1);
        }
    }
    assert_eq!(checked, 9);
    Ok(())
}

#[test]
fn the_fourteenth_route_the_reference_sends_is_not_in_the_table() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let observed = fixture
        .observed_attributes
        .get(CHALLENGE_RESPONSE_ROUTE)
        .ok_or("the reference no longer sends a challenge response")?;
    assert_eq!(
        observed.get("label_sets").and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
    assert_eq!(
        observed
            .get("label_sets")
            .and_then(Value::as_array)
            .and_then(|sets| sets.first())
            .and_then(Value::as_str),
        Some("words")
    );
    assert!(ExchangeRoute::parse(CHALLENGE_RESPONSE_ROUTE).is_none());
    Ok(())
}

// --- The divergences ---
#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (section, expected) in [(&fixture.reference_quirks, 6), (&fixture.shape_findings, 4)] {
        let entries = section.as_object().ok_or("a findings section is not an object")?;
        assert_eq!(entries.len(), expected);
        for (name, finding) in entries {
            let record = finding.as_object().ok_or("a finding is not an object")?;
            for label in ["note", "rust_decision"] {
                assert!(
                    record
                        .get(label)
                        .and_then(Value::as_str)
                        .is_some_and(|text| !text.is_empty()),
                    "finding {name} records no {label}"
                );
            }
        }
    }
    assert!(fixture.declarations.anchor_event_alias.contains("IXN_V_1"));
    Ok(())
}

#[test]
fn a_group_request_and_a_plain_one_classify_alike() -> Result<(), Box<dyn Error>> {
    let exn = message("/multisig/icp", &group_block(), &embed_for(MultisigRoute::Inception))?;
    let plain = ExchangeResource {
        exn: exn.clone(),
        pathed: Map::new(),
    };
    let grouped = MultisigExchangeResource {
        exn,
        paths: Map::new(),
        group_name: Some("group".to_owned()),
        member_name: Some("member1".to_owned()),
        sender: Some(MEMBER.to_owned()),
    };
    assert_eq!(
        ClassifiedExchange::try_from(&plain)?,
        ClassifiedExchange::try_from(&grouped)?
    );
    Ok(())
}
