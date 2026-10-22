//! Exact vectors for the two rounds a multisig group runs after it exists.
//!
//! Both rounds from syntax tree and recording agent, and three findings including a rotation on the wrong route.

use std::error::Error;

use keria_types::api::MultisigExchangeResource;
use serde::Deserialize;
use serde_json::Value;
use signify_client::endpoint::exchanges::{ClassifiedExchange, MultisigRoute};
use signify_client::multisig::{INTERACTION_ROUTE, INTERACTION_SLOT, ROTATION_ROUTE, ROTATION_SLOT};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/client-multisig-events/v1.json"
));

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
    send_calls: Vec<SendCall>,
    wait_calls: Vec<WaitCall>,
    group_rotate_calls: Vec<Value>,
    member_expressions: Vec<MemberExpression>,
    mismatched_sends: Vec<SendCall>,
    rotation_route: String,
    interaction_route: String,
    scenario_anchor: Value,
    scenario_files: Vec<String>,
    scanned_files: usize,
    notes: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct SendCall {
    file: String,
    enclosing: String,
    route: String,
    embed_variable: Option<String>,
    embed_slots: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WaitCall {
    file: String,
    enclosing: String,
    route: String,
}

#[derive(Debug, Deserialize)]
struct MemberExpression {
    file: String,
    enclosing: String,
    label: String,
    expression: String,
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
    interaction_paths: Vec<String>,
    rotation_paths: Vec<String>,
    join_path: Vec<String>,
    group_prefix: String,
    interaction_digest: String,
    rotation_digest: String,
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

fn body(fixture: &Fixture, name: &str, path: &str) -> Result<Value, Box<dyn Error>> {
    let request = call(fixture, name)?
        .requests
        .iter()
        .find(|entry| entry.path == path)
        .ok_or_else(|| format!("call {name} sent nothing to {path}"))?;
    Ok(serde_json::from_str(request.body.as_deref().ok_or("no body")?)?)
}

fn announcement(fixture: &Fixture, name: &str) -> Result<Value, Box<dyn Error>> {
    let request = call(fixture, name)?
        .requests
        .iter()
        .find(|entry| entry.path.ends_with("/exchanges"))
        .ok_or_else(|| format!("call {name} announced nothing"))?;
    Ok(serde_json::from_str(request.body.as_deref().ok_or("no body")?)?)
}

fn quirk<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Value, Box<dyn Error>> {
    fixture
        .reference_quirks
        .get(name)
        .ok_or_else(|| format!("no recorded divergence {name}").into())
}

// --- Manifest and provenance ---
#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert_ne!(fixture.generated_on, "");
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("multisig.test.ts"))
    );
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("multisig-join.test.ts"))
    );
    assert_eq!(fixture.provenance.bran, "0123456789abcdefghijk");
    assert_eq!(fixture.provenance.fixed_clock_ms, 1_700_000_000_123);
    assert_eq!(fixture.provenance.local_member_prefix, LOCAL);
    assert_eq!(fixture.provenance.peer_prefix, PEER);
    assert!(fixture.provenance.note.contains("inline"));
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 10);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert!(!entry.requests.is_empty(), "call {} sent nothing", entry.name);
        for request in &entry.requests {
            match request.method.as_str() {
                "GET" => assert!(request.body.is_none(), "a read in {} carried a body", entry.name),
                "POST" => assert!(request.body.is_some(), "a write in {} carried none", entry.name),
                other => return Err(format!("call {} used {other}", entry.name).into()),
            }
        }
        assert_eq!(entry.error, None, "call {} failed upstream", entry.name);
        assert!(!entry.result.is_null(), "call {} answered nothing", entry.name);
    }

    for sealed in [&fixture.identifier_record, &fixture.group_record] {
        let salty = sealed
            .pointer("/salty")
            .or_else(|| sealed.pointer("/group/mhab/salty"))
            .ok_or("a recorded record carries no key-manager block")?;
        assert_eq!(salty.get("sxlt").and_then(Value::as_str), Some("<SXLT>"));
        assert!(salty.get("sxlt_opens_to").is_some());
    }
    Ok(())
}

#[test]
fn the_route_constants_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.declarations.rotation_route, ROTATION_ROUTE);
    assert_eq!(fixture.declarations.interaction_route, INTERACTION_ROUTE);
    assert_eq!(MultisigRoute::Rotation.as_str(), ROTATION_ROUTE);
    assert_eq!(MultisigRoute::Interaction.as_str(), INTERACTION_ROUTE);
    assert_eq!(fixture.declarations.scanned_files, 117);
    assert_eq!(fixture.declarations.scenario_files.len(), 3);
    assert!(fixture.declarations.notes.is_object());
    assert_ne!(fixture.declarations.group_rotate_calls, [] as [Value; 0]);
    Ok(())
}

// --- The finding: a rotation announced on the interaction route ---
#[test]
fn both_joining_members_announce_a_rotation_on_the_interaction_route() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_rotation_is_announced_on_the_interaction_route")?;

    let offenders = recorded
        .get("rotations_sent_on_interaction_route")
        .and_then(Value::as_array)
        .ok_or("no recorded offenders")?;
    assert_eq!(offenders.len(), 2);
    for offender in offenders {
        assert_eq!(offender.get("route").and_then(Value::as_str), Some(INTERACTION_ROUTE));
        assert_eq!(
            offender.get("embed_slots").and_then(Value::as_array),
            Some(&vec![Value::String(ROTATION_SLOT.to_owned())])
        );
    }

    let waiting = recorded.get("waits_on_rotation_route").and_then(Value::as_u64);
    assert!(
        waiting.is_some_and(|count| count > 0),
        "nobody waits on the rotation route"
    );

    assert_eq!(
        recorded.get("announced_route").and_then(Value::as_str),
        Some(INTERACTION_ROUTE)
    );
    assert_eq!(
        recorded.get("announced_embed_slots").and_then(Value::as_array),
        Some(&vec![Value::String(ROTATION_SLOT.to_owned())])
    );
    Ok(())
}

#[test]
fn the_mismatched_announcement_is_refused_by_this_ports_classifier() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let sent = announcement(&fixture, "announce_rotation_on_the_interaction_route")?;
    let exn = sent.get("exn").ok_or("no exn")?.clone();
    assert_eq!(exn.get("r").and_then(Value::as_str), Some(INTERACTION_ROUTE));
    assert!(
        exn.get("e")
            .and_then(Value::as_object)
            .is_some_and(|embeds| embeds.contains_key(ROTATION_SLOT))
    );

    let listing = serde_json::json!([{ "exn": exn, "paths": {}, "groupName": "multisig",
        "memberName": "member2", "sender": LOCAL }]);
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_value(listing)?;
    let entry = decoded.first().ok_or("empty listing")?;
    let refused = ClassifiedExchange::try_from(entry).is_err();
    assert!(refused, "a rotation announced as an interaction was classified");

    let proper = announcement(&fixture, "announce_rotation_on_its_own_route")?;
    let proper_exn = proper.get("exn").ok_or("no exn")?.clone();
    assert_eq!(proper_exn.get("r").and_then(Value::as_str), Some(ROTATION_ROUTE));
    let listing = serde_json::json!([{ "exn": proper_exn, "paths": {}, "groupName": "multisig",
        "memberName": "member1", "sender": LOCAL }]);
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_value(listing)?;
    let entry = decoded.first().ok_or("empty listing")?;
    let classified = ClassifiedExchange::try_from(entry)?;
    let proposal = classified.as_multisig().ok_or("not a multisig proposal")?;
    assert_eq!(proposal.route, MultisigRoute::Rotation);

    assert_eq!(
        sent.pointer("/exn/e/rot/d"),
        proper.pointer("/exn/e/rot/d"),
        "the two announcements carry different rotations"
    );
    Ok(())
}

#[test]
fn a_rotations_witness_threshold_arrives_as_a_number() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let rotation = body(&fixture, "propose_rotation", "/identifiers/multisig/events")?;
    let threshold = rotation
        .pointer("/rot/bt")
        .ok_or("the rotation carries no witness threshold")?;
    assert!(threshold.is_number(), "the rotation's `bt` is no longer a number");
    assert_eq!(threshold.as_u64(), Some(3));

    let inception = body(&fixture, "incept_the_group", "/identifiers")?;
    let incepted = inception
        .pointer("/icp/bt")
        .ok_or("the inception carries no witness threshold")?;
    assert!(incepted.is_string(), "the inception's `bt` is no longer text");
    assert_eq!(incepted.as_str(), Some("2"));

    let listing = serde_json::json!([{
        "exn": announcement(&fixture, "announce_rotation_on_its_own_route")?.get("exn").ok_or("no exn")?.clone(),
        "paths": {}, "groupName": "multisig", "memberName": "member1", "sender": LOCAL }]);
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_value(listing)?;
    let entry = decoded.first().ok_or("empty listing")?;
    let classified = ClassifiedExchange::try_from(entry)?;
    assert!(classified.as_multisig().is_some());
    Ok(())
}

#[test]
fn only_the_initiator_uses_the_rotation_route() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let scenario = "test-integration/multisig.test.ts";
    let rotations: Vec<&SendCall> = fixture
        .declarations
        .send_calls
        .iter()
        .filter(|call| call.file == scenario && call.embed_slots.iter().any(|slot| slot == ROTATION_SLOT))
        .collect();
    assert_eq!(rotations.len(), 3);
    assert_eq!(
        rotations.iter().filter(|call| call.route == ROTATION_ROUTE).count(),
        1,
        "more than one member announced on the rotation route"
    );
    assert_eq!(
        rotations.iter().filter(|call| call.route == INTERACTION_ROUTE).count(),
        2
    );
    assert!(rotations.iter().all(|call| call.embed_variable.is_some()));
    Ok(())
}

#[test]
fn the_scan_finds_a_third_mismatch_this_item_does_not_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let others: Vec<&SendCall> = fixture
        .declarations
        .mismatched_sends
        .iter()
        .filter(|call| !call.embed_slots.iter().any(|slot| slot == ROTATION_SLOT))
        .collect();
    assert_eq!(others.len(), 1);
    let revocation = others.first().ok_or("no third mismatch")?;
    assert_eq!(revocation.route, "/multisig/rev");
    assert_eq!(revocation.embed_slots, ["iss", "anc"]);
    assert_eq!(revocation.enclosing, "multisigRevoke");
    Ok(())
}

// --- The finding: a joining member never reads the rotation it joins ---
#[test]
fn a_rebuilt_rotation_can_differ_from_the_one_proposed_with_nothing_said() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_joining_member_never_reads_the_rotation_it_joins")?;

    assert_eq!(recorded.get("styles_agree").and_then(Value::as_bool), Some(true));
    assert_eq!(
        recorded.get("rebuilt_event_digest"),
        recorded.get("proposed_event_digest")
    );
    assert_eq!(
        recorded.get("signed_by_the_join"),
        recorded.get("proposed_event_digest")
    );

    let divergent = recorded.get("divergent").ok_or("no divergent case")?;
    assert_eq!(
        divergent.get("matches_the_proposal").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        divergent.get("error"),
        Some(&Value::Null),
        "the divergent rebuild failed after all"
    );
    assert_ne!(
        divergent.get("rebuilt_next_digests"),
        divergent.get("proposed_next_digests")
    );
    assert_eq!(
        divergent
            .get("rebuilt_next_digests")
            .and_then(Value::as_array)
            .map(Vec::len),
        divergent
            .get("proposed_next_digests")
            .and_then(Value::as_array)
            .map(Vec::len)
    );
    Ok(())
}

#[test]
fn the_join_endpoint_signs_the_event_it_was_shown() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let joined = call(&fixture, "join_the_proposed_rotation")?;
    assert_eq!(
        joined
            .requests
            .iter()
            .map(|request| format!("{} {}", request.method, request.path))
            .collect::<Vec<String>>(),
        fixture.pinned_confirmations.join_path
    );
    let write = joined
        .requests
        .iter()
        .find(|request| request.path.ends_with("/multisig/join"))
        .ok_or("nothing was joined")?;
    assert_eq!(write.path, "/identifiers/multisig/multisig/join");

    let body: Value = serde_json::from_str(write.body.as_deref().ok_or("no body")?)?;
    let proposed = announcement(&fixture, "announce_rotation_on_its_own_route")?;
    assert_eq!(
        body.pointer("/rot/d"),
        proposed.pointer("/exn/e/rot/d"),
        "the join signed an event other than the one proposed"
    );
    for label in ["tpc", "rot", "sigs", "gid", "smids", "rmids"] {
        assert!(body.get(label).is_some(), "the join body carries no {label}");
    }
    Ok(())
}

// --- The finding: the two rotation call sites disagree about `rmids` ---
#[test]
fn the_two_rotation_call_sites_disagree_about_the_rotation_set() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_two_rotation_call_sites_disagree_about_rmids")?;
    let expressions = recorded
        .get("expressions")
        .and_then(Value::as_array)
        .ok_or("no recorded expressions")?;
    assert!(expressions.len() >= 2);

    let sources: Vec<&str> = expressions
        .iter()
        .filter_map(|entry| entry.get("expression").and_then(Value::as_str))
        .collect();
    assert!(
        sources.iter().any(|expression| expression.contains("rstates")),
        "no call site names the rotation states"
    );
    assert!(
        sources.iter().any(|expression| expression.contains("states.map")),
        "no call site substitutes the signing states"
    );
    for entry in &fixture.declarations.member_expressions {
        assert_ne!(entry.file, "");
        assert_ne!(entry.enclosing, "");
        assert_ne!(entry.expression, "");
        assert!(entry.label == "smids" || entry.label == "rmids");
    }
    Ok(())
}

// --- The half the reference gets right ---
#[test]
fn an_interaction_anchors_the_seal_it_was_shown() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "an_interaction_relays_the_data_it_read")?;
    let proposed = recorded
        .get("proposed_anchors")
        .and_then(Value::as_array)
        .ok_or("no proposed anchors")?;
    assert_eq!(proposed.len(), 1);
    assert_eq!(proposed.first(), Some(&fixture.declarations.scenario_anchor));

    let accepted = body(&fixture, "accept_interaction", "/identifiers/multisig/events")?;
    let proposal = body(&fixture, "propose_interaction", "/identifiers/multisig/events")?;
    assert_eq!(accepted.pointer("/ixn/a"), proposal.pointer("/ixn/a"));
    assert_eq!(accepted.pointer("/ixn/d"), proposal.pointer("/ixn/d"));
    assert_eq!(
        accepted.pointer("/ixn/d").and_then(Value::as_str),
        Some(fixture.pinned_confirmations.interaction_digest.as_str())
    );
    Ok(())
}

#[test]
fn each_round_reads_the_group_and_writes_one_event() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(
        fixture.pinned_confirmations.interaction_paths,
        ["GET /identifiers/multisig", "POST /identifiers/multisig/events"]
    );
    assert_eq!(
        fixture.pinned_confirmations.rotation_paths,
        fixture.pinned_confirmations.interaction_paths
    );

    let interaction = body(&fixture, "propose_interaction", "/identifiers/multisig/events")?;
    let rotation = body(&fixture, "propose_rotation", "/identifiers/multisig/events")?;
    assert_eq!(interaction.pointer("/ixn/t").and_then(Value::as_str), Some("ixn"));
    assert_eq!(rotation.pointer("/rot/t").and_then(Value::as_str), Some("rot"));
    for event in [interaction.pointer("/ixn/i"), rotation.pointer("/rot/i")] {
        assert_eq!(
            event.and_then(Value::as_str),
            Some(fixture.pinned_confirmations.group_prefix.as_str())
        );
    }
    assert!(rotation.get("smids").is_some() && rotation.get("rmids").is_some());
    assert!(interaction.get("smids").is_none() && interaction.get("rmids").is_none());
    assert_eq!(
        rotation.pointer("/rot/d").and_then(Value::as_str),
        Some(fixture.pinned_confirmations.rotation_digest.as_str())
    );
    assert_ne!(fixture.pinned_confirmations.note, "");
    Ok(())
}

#[test]
fn the_key_states_the_rounds_read_are_recorded() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.key_states.len(), 2);
    for prefix in [LOCAL, PEER] {
        let state = fixture
            .key_states
            .get(prefix)
            .ok_or("a member has no recorded key state")?;
        assert_eq!(state.get("i").and_then(Value::as_str), Some(prefix));
        assert!(
            state
                .get("n")
                .and_then(Value::as_array)
                .and_then(|digests| digests.first())
                .and_then(Value::as_str)
                .is_some_and(|digest| digest.len() == 44)
        );
    }
    Ok(())
}

#[test]
fn every_wait_names_a_route_some_send_uses() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let sent: Vec<&str> = fixture
        .declarations
        .send_calls
        .iter()
        .map(|call| call.route.as_str())
        .collect();
    for wait in &fixture.declarations.wait_calls {
        assert_ne!(wait.file, "");
        assert_ne!(wait.enclosing, "");
        if wait.route.starts_with("/multisig/") {
            assert!(
                sent.contains(&wait.route.as_str()),
                "{} waits on {} and nothing sends it",
                wait.enclosing,
                wait.route
            );
        }
    }
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 5);
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
    assert_eq!(ROTATION_ROUTE.rsplit('/').next(), Some(ROTATION_SLOT));
    assert_eq!(INTERACTION_ROUTE.rsplit('/').next(), Some(INTERACTION_SLOT));
    Ok(())
}
