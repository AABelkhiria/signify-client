//! Exact vectors for the three rounds a multisig group runs over a credential registry.
//!
//! Registry creation, issuance, and revocation, and eight rounds confirming no member ever reads a proposal.

use std::error::Error;

use serde::Deserialize;
use serde_json::Value;
use signify_client::endpoint::exchanges::{ClassifiedExchange, MultisigRoute, REGISTRY_TOPIC};
use signify_client::multisig::{
    ANCHOR_SLOT, ISSUANCE_ROUTE, ISSUANCE_SLOT, REGISTRY_ROUTE, REGISTRY_SLOT, REVOCATION_ROUTE, REVOCATION_SLOT,
    TRANSACTION_SLOT,
};
use signify_types::api::MultisigExchangeResource;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-multisig-credentials/v1.json");

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

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
    key_states: serde_json::Map<String, Value>,
    identifier_record: Value,
    group_record: Value,
    calls: Vec<Call>,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    fixed_clock_ms: u64,
    local_member_prefix: String,
    peer_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    create_registry_multisig: String,
    issue_credential_multisig: String,
    multisig_revoke: String,
    notification_waits: Vec<NotificationWait>,
    proposal_reads: Vec<ProposalRead>,
    send_calls: Vec<SendCall>,
    issue_credential_result: Vec<Member>,
    revoke_credential_result: Vec<Member>,
    registry_uses: Scan,
    issuance_uses: Scan,
    scanned_files: usize,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct NotificationWait {
    file: String,
    enclosing: String,
    route: String,
    binds: Option<String>,
    discarded: bool,
}

#[derive(Debug, Deserialize)]
struct ProposalRead {
    file: String,
    enclosing: String,
}

#[derive(Debug, Deserialize)]
struct SendCall {
    file: String,
    route: String,
    topic: String,
    embed_slots: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Member {
    name: String,
    #[serde(rename = "type")]
    declared: String,
}

#[derive(Debug, Deserialize)]
struct Scan {
    needle: String,
    total: usize,
    files: Vec<ScanHit>,
    scanned_files: usize,
}

#[derive(Debug, Deserialize)]
struct ScanHit {
    file: String,
    count: usize,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    requests: Vec<RecordedRequest>,
    result: Value,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    group: String,
    registry: String,
    nonce: String,
    schema: String,
    credential: String,
    registry_paths: Vec<String>,
    issuance_paths: Vec<String>,
    registry_route: String,
    registry_topic: String,
    issuance_route: String,
    issuance_topic: String,
    note: String,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

fn call<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Call, Box<dyn Error>> {
    fixture
        .calls
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| format!("no recorded call {name}").into())
}

fn body(fixture: &Fixture, name: &str, ending: &str) -> Result<Value, Box<dyn Error>> {
    let request = call(fixture, name)?
        .requests
        .iter()
        .find(|entry| entry.path.ends_with(ending))
        .ok_or_else(|| format!("call {name} sent nothing to a path ending {ending}"))?;
    Ok(serde_json::from_str(request.body.as_deref().ok_or("no body")?)?)
}

fn quirk<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Value, Box<dyn Error>> {
    fixture
        .reference_quirks
        .get(name)
        .ok_or_else(|| format!("no recorded divergence {name}").into())
}

// --- Manifest and declarations ---
#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert!(!fixture.generated_on.is_empty());
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("multisig-vlei-issuance.test.ts"))
    );
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("credentialing.ts"))
    );
    assert_eq!(fixture.provenance.bran, "0123456789abcdefghijk");
    assert_eq!(fixture.provenance.fixed_clock_ms, 1_700_000_000_123);
    assert_eq!(fixture.provenance.local_member_prefix, LOCAL);
    assert_eq!(fixture.provenance.peer_prefix, PEER);
    assert!(fixture.provenance.note.contains("transpiled in memory"));
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 8);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert!(!entry.requests.is_empty(), "call {} sent nothing", entry.name);
        assert_eq!(entry.error, None, "call {} failed upstream", entry.name);
        assert!(!entry.result.is_null(), "call {} answered nothing", entry.name);
    }
    assert_eq!(
        fixture.identifier_record.pointer("/salty/sxlt").and_then(Value::as_str),
        Some("<SXLT>")
    );
    assert_eq!(
        fixture
            .group_record
            .pointer("/group/mhab/salty/sxlt")
            .and_then(Value::as_str),
        Some("<SXLT>")
    );
    assert_eq!(fixture.key_states.len(), 2);
    assert!(fixture.declarations.notes.is_object());
    Ok(())
}

#[test]
fn the_three_helpers_are_the_ones_the_scenarios_call() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(fixture.declarations.create_registry_multisig.contains("registries()"));
    assert!(fixture.declarations.issue_credential_multisig.contains("credentials()"));
    assert!(fixture.declarations.multisig_revoke.contains("/multisig/rev"));
    assert_eq!(fixture.declarations.scanned_files, 117);

    for scan in [&fixture.declarations.registry_uses, &fixture.declarations.issuance_uses] {
        assert!(scan.total >= 1, "{} is used nowhere", scan.needle);
        assert_eq!(scan.scanned_files, 117);
        assert_eq!(scan.files.iter().map(|hit| hit.count).sum::<usize>(), scan.total);
        assert!(
            scan.files.iter().all(|hit| hit.file.starts_with("test-integration/")),
            "{} escaped the integration tree",
            scan.needle
        );
    }
    Ok(())
}

// --- The finding: a joining member never reads the proposal ---
#[test]
fn a_joining_member_waits_for_a_bell_and_discards_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_joining_member_never_reads_the_proposal")?;

    let waits = recorded
        .get("waits")
        .and_then(Value::as_array)
        .ok_or("no recorded waits")?;
    assert_eq!(waits.len(), 2);
    for wait in waits {
        assert_eq!(wait.get("discarded").and_then(Value::as_bool), Some(true));
        assert_eq!(wait.get("binds"), Some(&Value::Null));
        assert!(
            wait.get("route")
                .and_then(Value::as_str)
                .is_some_and(|route| route == REGISTRY_ROUTE || route == ISSUANCE_ROUTE)
        );
    }

    assert_eq!(
        recorded
            .get("proposal_reads_in_these_helpers")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        recorded.get("group_requests_made").and_then(Value::as_bool),
        Some(false)
    );
    assert!(
        !fixture.calls.iter().any(|entry| entry
            .requests
            .iter()
            .any(|request| request.path.starts_with("/multisig/request/"))),
        "a driven round fetched a group request after all"
    );

    let bound: Vec<&NotificationWait> = fixture
        .declarations
        .notification_waits
        .iter()
        .filter(|wait| !wait.discarded)
        .collect();
    assert!(
        bound.iter().all(|wait| wait.binds.is_some()),
        "a bound wait records no binding"
    );
    for (enclosing, route) in [
        ("createRegistryMultisig", REGISTRY_ROUTE),
        ("issueCredentialMultisig", ISSUANCE_ROUTE),
    ] {
        let wait = fixture
            .declarations
            .notification_waits
            .iter()
            .find(|wait| wait.enclosing == enclosing)
            .ok_or("the helper records no wait")?;
        assert_eq!(wait.route, route, "the helper waits on another round's route");
        assert!(wait.discarded, "the helper binds the SAID it waits for");
        assert!(wait.binds.is_none());
    }
    for wait in &fixture.declarations.notification_waits {
        assert!(!wait.file.is_empty() && !wait.enclosing.is_empty());
        assert!(wait.route.starts_with('/'), "a wait names no route");
    }
    for read in &fixture.declarations.proposal_reads {
        assert!(!read.file.is_empty() && !read.enclosing.is_empty());
    }
    Ok(())
}

#[test]
fn a_different_nonce_is_a_different_registry_with_nothing_said() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_different_nonce_is_a_different_registry")?;

    assert_eq!(recorded.get("agree").and_then(Value::as_bool), Some(true));
    assert_eq!(recorded.get("proposed_registry"), recorded.get("joined_registry"));
    assert_eq!(recorded.get("divergent_agrees").and_then(Value::as_bool), Some(false));
    assert_eq!(recorded.get("error"), Some(&Value::Null));
    assert_ne!(recorded.get("proposed_registry"), recorded.get("divergent_registry"));

    let proposed = body(&fixture, "propose_the_registry", "/registries")?;
    assert_eq!(
        proposed.pointer("/vcp/n").and_then(Value::as_str),
        Some(fixture.pinned_confirmations.nonce.as_str())
    );
    assert_eq!(
        proposed.pointer("/vcp/i").and_then(Value::as_str),
        Some(fixture.pinned_confirmations.registry.as_str())
    );
    let divergent = body(&fixture, "join_the_registry_with_a_different_nonce", "/registries")?;
    assert_ne!(proposed.pointer("/vcp/n"), divergent.pointer("/vcp/n"));
    assert_ne!(proposed.pointer("/vcp/i"), divergent.pointer("/vcp/i"));
    Ok(())
}

#[test]
fn different_attributes_are_a_different_credential_with_nothing_said() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "different_attributes_are_a_different_credential")?;
    assert_eq!(recorded.get("agree").and_then(Value::as_bool), Some(true));
    assert_eq!(recorded.get("divergent_agrees").and_then(Value::as_bool), Some(false));
    assert_eq!(recorded.get("error"), Some(&Value::Null));

    let proposed = body(&fixture, "propose_the_issuance", "/credentials")?;
    let divergent = body(&fixture, "join_the_issuance_with_different_attributes", "/credentials")?;
    assert_eq!(
        proposed.pointer("/acdc/d").and_then(Value::as_str),
        Some(fixture.pinned_confirmations.credential.as_str())
    );
    assert_ne!(proposed.pointer("/acdc/d"), divergent.pointer("/acdc/d"));
    assert_ne!(
        proposed.pointer("/acdc/a/LEI"),
        divergent.pointer("/acdc/a/LEI"),
        "the two issuances used the same attributes after all"
    );
    assert_eq!(proposed.pointer("/acdc/s"), divergent.pointer("/acdc/s"));
    assert_eq!(proposed.pointer("/acdc/ri"), divergent.pointer("/acdc/ri"));
    Ok(())
}

// --- The finding: a revocation in the issuance slot ---
#[test]
fn a_revocation_travels_in_the_issuance_slot() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_revocation_travels_in_the_issuance_slot")?;

    assert_eq!(
        recorded.get("announced_route").and_then(Value::as_str),
        Some(REVOCATION_ROUTE)
    );
    assert_eq!(
        recorded.get("announced_slots").and_then(Value::as_array),
        Some(&vec![
            Value::String(TRANSACTION_SLOT.to_owned()),
            Value::String(ANCHOR_SLOT.to_owned()),
        ])
    );
    assert_eq!(recorded.get("embedded_ilk").and_then(Value::as_str), Some("rev"));

    let sent = body(&fixture, "propose_the_revocation", "/exchanges")?;
    let exn = sent.get("exn").ok_or("no exn")?.clone();
    let listing = serde_json::json!([{ "exn": exn, "paths": {}, "groupName": "multisig",
        "memberName": "member1", "sender": LOCAL }]);
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_value(listing)?;
    let entry = decoded.first().ok_or("empty listing")?;
    let refused = ClassifiedExchange::try_from(entry).is_err();
    assert!(refused, "a revocation in the issuance slot was classified");

    assert_eq!(REVOCATION_ROUTE.rsplit('/').next(), Some(REVOCATION_SLOT));
    assert_ne!(REVOCATION_SLOT, TRANSACTION_SLOT);
    Ok(())
}

// --- The two smaller findings ---
#[test]
fn the_issuance_result_drops_the_signatures_it_computed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_issuance_result_drops_its_signatures")?;
    let declared = recorded
        .get("declaration")
        .and_then(Value::as_array)
        .ok_or("no recorded declaration")?;
    let names: Vec<&str> = declared
        .iter()
        .filter_map(|member| member.get("name").and_then(Value::as_str))
        .collect();
    assert_eq!(names, ["acdc", "anc", "iss", "op"]);
    assert!(!names.contains(&"sigs"), "the result now carries its signatures");
    assert_eq!(
        fixture
            .declarations
            .issue_credential_result
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<&str>>(),
        names
    );
    assert!(
        !fixture
            .declarations
            .revoke_credential_result
            .iter()
            .any(|member| member.name == "sigs")
    );
    for member in &fixture.declarations.issue_credential_result {
        assert!(!member.declared.is_empty());
    }

    let reads = call(&fixture, "propose_the_issuance")?
        .requests
        .iter()
        .filter(|request| request.method == "GET" && request.path == "/identifiers/multisig")
        .count();
    assert_eq!(reads, 2, "the issuance round no longer reads the group twice");
    let registry_reads = call(&fixture, "propose_the_registry")?
        .requests
        .iter()
        .filter(|request| request.method == "GET" && request.path == "/identifiers/multisig")
        .count();
    assert_eq!(registry_reads, 1);
    Ok(())
}

#[test]
fn the_registry_round_is_filed_under_its_own_topic() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "one_round_is_filed_under_a_different_topic")?;
    let topics: Vec<&str> = recorded
        .get("vcp_topics")
        .and_then(Value::as_array)
        .ok_or("no recorded topics")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(topics.len() >= 2);
    assert!(topics.contains(&REGISTRY_TOPIC));
    assert!(topics.contains(&"multisig"));
    assert!(
        topics.iter().filter(|topic| **topic == REGISTRY_TOPIC).count() > 1,
        "the registry topic is not the majority form"
    );

    assert_eq!(fixture.pinned_confirmations.registry_topic, REGISTRY_TOPIC);
    assert_eq!(fixture.pinned_confirmations.issuance_topic, "multisig");
    let declared: Vec<&str> = fixture
        .declarations
        .send_calls
        .iter()
        .filter(|entry| entry.route == REGISTRY_ROUTE)
        .map(|entry| entry.topic.as_str())
        .collect();
    assert!(declared.contains(&REGISTRY_TOPIC) && declared.contains(&"multisig"));
    assert!(
        declared.iter().filter(|topic| **topic == REGISTRY_TOPIC).count() * 2 > declared.len(),
        "the registry topic is not the majority form"
    );

    for entry in &fixture.declarations.send_calls {
        assert!(!entry.file.is_empty());
        assert!(entry.route.starts_with("/multisig/") || entry.route.starts_with('<'));
        assert!(!entry.embed_slots.is_empty(), "a send names no embed");

        match entry.route.as_str() {
            REGISTRY_ROUTE => assert_eq!(entry.embed_slots, [REGISTRY_SLOT, ANCHOR_SLOT]),
            ISSUANCE_ROUTE => {
                assert_eq!(entry.embed_slots, [ISSUANCE_SLOT, TRANSACTION_SLOT, ANCHOR_SLOT]);
            }
            REVOCATION_ROUTE => {
                assert_eq!(entry.embed_slots, [TRANSACTION_SLOT, ANCHOR_SLOT]);
                assert!(
                    !entry.embed_slots.iter().any(|slot| slot == REVOCATION_SLOT),
                    "the reference sends a revocation in the slot its route names"
                );
            }
            _ => {}
        }
    }
    Ok(())
}

// --- The rounds themselves ---
#[test]
fn each_round_addresses_its_own_endpoint_and_announces_on_its_own_route() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let confirmations = &fixture.pinned_confirmations;
    assert_eq!(
        confirmations.registry_paths,
        [
            "GET /identifiers/multisig",
            "POST /identifiers/multisig/registries",
            "POST /identifiers/member1/exchanges",
        ]
    );
    assert_eq!(confirmations.registry_route, REGISTRY_ROUTE);
    assert_eq!(confirmations.issuance_route, ISSUANCE_ROUTE);
    assert!(
        confirmations
            .issuance_paths
            .iter()
            .any(|path| path.ends_with("/credentials"))
    );
    assert!(!confirmations.note.is_empty());
    assert_eq!(confirmations.schema.len(), 44);
    assert_eq!(confirmations.group.len(), 44);
    Ok(())
}

#[test]
fn a_registry_proposal_embeds_its_inception_and_its_anchor() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let announced = body(&fixture, "propose_the_registry", "/exchanges")?;
    let embeds = announced
        .pointer("/exn/e")
        .and_then(Value::as_object)
        .ok_or("no embed block")?;
    assert!(embeds.contains_key(REGISTRY_SLOT));
    assert!(embeds.contains_key(ANCHOR_SLOT));
    assert!(embeds.contains_key("d"), "the embed block carries no SAID");
    assert_eq!(embeds.len(), 3);
    assert_eq!(
        announced.pointer("/exn/r").and_then(Value::as_str),
        Some(REGISTRY_ROUTE)
    );
    let created = body(&fixture, "propose_the_registry", "/registries")?;
    assert_eq!(embeds.get(REGISTRY_SLOT), created.get("vcp"));
    let listing = serde_json::json!([{ "exn": announced.get("exn").ok_or("no exn")?.clone(), "paths": {},
        "groupName": "multisig", "memberName": "member1", "sender": LOCAL }]);
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_value(listing)?;
    let entry = decoded.first().ok_or("empty listing")?;
    let classified = ClassifiedExchange::try_from(entry)?;
    let proposal = classified.as_multisig().ok_or("not a multisig proposal")?;
    assert_eq!(proposal.route, MultisigRoute::RegistryInception);
    Ok(())
}

#[test]
fn an_issuance_proposal_embeds_three_messages_and_signs_one() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let announced = body(&fixture, "propose_the_issuance", "/exchanges")?;
    let embeds = announced
        .pointer("/exn/e")
        .and_then(Value::as_object)
        .ok_or("no embed block")?;
    for slot in [ISSUANCE_SLOT, TRANSACTION_SLOT, ANCHOR_SLOT] {
        assert!(embeds.contains_key(slot), "the issuance carries no {slot}");
    }
    assert_eq!(embeds.len(), 4);
    assert_eq!(
        announced.pointer("/exn/r").and_then(Value::as_str),
        Some(ISSUANCE_ROUTE)
    );

    let attachment = announced.get("atc").and_then(Value::as_str).ok_or("no attachment")?;
    for slot in [ISSUANCE_SLOT, TRANSACTION_SLOT, ANCHOR_SLOT] {
        assert!(attachment.contains(&format!("-e-{slot}")), "no path for {slot}");
    }
    assert!(
        attachment.contains(&format!("-e-{ANCHOR_SLOT}-AAB")),
        "the anchor carries no controller signature"
    );
    for slot in [ISSUANCE_SLOT, TRANSACTION_SLOT] {
        assert!(
            !attachment.contains(&format!("-e-{slot}-AAB")),
            "{slot} was signed, which nothing upstream does"
        );
    }

    assert_eq!(ISSUANCE_ROUTE.rsplit('/').next(), Some(TRANSACTION_SLOT));
    assert_eq!(ISSUANCE_SLOT, "acdc");
    let listing = serde_json::json!([{ "exn": announced.get("exn").ok_or("no exn")?.clone(), "paths": {},
        "groupName": "multisig", "memberName": "member1", "sender": LOCAL }]);
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_value(listing)?;
    let entry = decoded.first().ok_or("empty listing")?;
    let classified = ClassifiedExchange::try_from(entry)?;
    assert_eq!(
        classified.as_multisig().map(|proposal| proposal.route),
        Some(MultisigRoute::Issuance)
    );
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 6);
    for (name, finding) in quirks {
        let entry = finding.as_object().ok_or("a divergence is not an object")?;
        for label in ["note", "rust_decision"] {
            assert!(
                entry
                    .get(label)
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.is_empty()),
                "divergence {name} records no {label}"
            );
        }
    }
    Ok(())
}
