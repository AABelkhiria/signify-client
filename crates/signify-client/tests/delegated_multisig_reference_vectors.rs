//! Exact vectors for the round where **both sides of a delegation are groups**.
//!
//! A delegatee group whose inception names a delegator, and a delegator group that approves it by
//! each of its members anchoring the same seal and telling the others. Roadmap 8.6 is the
//! composition of the three items before it — 8.3's group inception, 8.4's interaction
//! announcement, and 8.5's approval address — and the first place a delegated inception is driven
//! at all.
//!
//! The unit is `delegateMultisig`, which lives in the reference's integration utilities, so the
//! generator transpiles that file in memory exactly as 8.3's does and drives the reference's own
//! helper against a recording agent.
//!
//! The finding is about one index. The joining half reads `ixn.a[0]` where the plain interaction
//! round reads `ixn.a` whole, so a delegator group anchoring two delegations has the second
//! dropped — and the one check the reference performs anywhere in this tree fires *after* the
//! approval is already posted, comparing the wrong shape.

use std::error::Error;

use serde::Deserialize;
use serde_json::Value;
use signify_client::endpoint::delegations::{DELEGATION_SEGMENT, InceptionSeal};
use signify_client::endpoint::exchanges::{ClassifiedExchange, MultisigRoute};
use signify_client::multisig::{INTERACTION_ROUTE, INTERACTION_SLOT};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_types::api::MultisigExchangeResource;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-delegated-multisig/v1.json");

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

// ---------------------------------------------------------------------------
// Fixture model.
// ---------------------------------------------------------------------------

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
    delegate_multisig: String,
    signature: Signature,
    anchor_reads: Vec<AnchorRead>,
    member_expressions: Vec<MemberExpression>,
    assertions: Vec<String>,
    inception_arguments: Vec<InceptionArguments>,
    prefix_discoveries: Vec<PrefixDiscovery>,
    delegate_multisig_uses: Scan,
    delegated_inception_uses: Scan,
    scanned_files: usize,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct Signature {
    parameters: Vec<Parameter>,
    returns: String,
}

#[derive(Debug, Deserialize)]
struct Parameter {
    name: String,
    #[serde(rename = "type")]
    declared: String,
    default: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnchorRead {
    file: String,
    binds: String,
    expression: String,
    takes: String,
}

#[derive(Debug, Deserialize)]
struct MemberExpression {
    file: String,
    label: String,
    expression: String,
}

#[derive(Debug, Deserialize)]
struct InceptionArguments {
    properties: Vec<String>,
    delegated: bool,
}

#[derive(Debug, Deserialize)]
struct PrefixDiscovery {
    binds: String,
    from: String,
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
    delegator_group: String,
    delegatee_group: String,
    seal: Value,
    approval_path: String,
    initiator_paths: Vec<String>,
    joiner_paths: Vec<String>,
    announcement_route: String,
    announcement_topic: String,
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

/// The parsed body of the request `name` sent matching `predicate`.
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

// ---------------------------------------------------------------------------
// Manifest and declarations.
// ---------------------------------------------------------------------------

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
            .any(|source| source.ends_with("delegation-multisig.test.ts"))
    );
    assert_eq!(fixture.provenance.bran, "0123456789abcdefghijk");
    assert_eq!(fixture.provenance.fixed_clock_ms, 1_700_000_000_123);
    assert_eq!(fixture.provenance.local_member_prefix, LOCAL);
    assert_eq!(fixture.provenance.peer_prefix, PEER);
    assert!(fixture.provenance.note.contains("transpiled in memory"));
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 7);
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
    }
    // Six of the seven succeed; the one that fails is the finding — and the six that succeed all
    // answered with something.
    assert_eq!(fixture.calls.iter().filter(|entry| entry.error.is_some()).count(), 1);
    for entry in &fixture.calls {
        assert_eq!(
            entry.result.is_null(),
            entry.error.is_some(),
            "call {} recorded both an answer and a failure, or neither",
            entry.name
        );
    }

    // Both sealed salts are recorded as what they open to.
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
    Ok(())
}

#[test]
fn the_helper_is_the_one_the_scenario_calls() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(fixture.declarations.delegate_multisig.contains("delegations()"));
    assert!(fixture.declarations.delegate_multisig.contains("exchanges()"));
    assert_eq!(fixture.declarations.scanned_files, 117);

    // Its signature: six parameters, the last of them the flag that decides which half runs.
    let parameters = &fixture.declarations.signature.parameters;
    assert_eq!(parameters.len(), 6);
    let initiator = parameters.last().ok_or("no parameters")?;
    assert_eq!(initiator.name, "isInitiator");
    assert_eq!(initiator.declared, "boolean");
    assert_eq!(initiator.default.as_deref(), Some("false"));
    // It declares no return type at all, where the endpoint it calls declares
    // `Promise<EventResult>` — so what a caller gets back is whatever the last expression was.
    assert_eq!(fixture.declarations.signature.returns, "<inferred>");

    // And the anchor it declares is **one seal**, not a list — while the code beneath it accepts a
    // list, anchors it, and only then refuses. The declaration and the behaviour disagree.
    let anchor = parameters
        .iter()
        .find(|parameter| parameter.name == "anchor")
        .ok_or("no anchor parameter")?;
    assert_eq!(anchor.declared, "{ i: string; s: string; d: string }");
    assert!(
        !anchor.declared.contains("[]"),
        "the anchor is declared as a list after all"
    );

    // And it is used only in the integration tree.
    let scan = &fixture.declarations.delegate_multisig_uses;
    assert_eq!(scan.needle, "delegateMultisig(");
    assert!(scan.total >= 1);
    assert!(
        scan.files.iter().all(|hit| hit.file.starts_with("test-integration/")),
        "the helper escaped the integration tree"
    );
    assert_eq!(scan.files.iter().map(|hit| hit.count).sum::<usize>(), scan.total);
    assert_eq!(scan.scanned_files, 117);
    assert!(fixture.declarations.notes.is_object());
    Ok(())
}

// ---------------------------------------------------------------------------
// The finding: one index.
// ---------------------------------------------------------------------------

#[test]
fn the_joining_member_takes_only_the_first_seal() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_joining_member_takes_only_the_first_seal")?;

    // Two readings of one field, in one tree.
    let reads = recorded
        .get("reads")
        .and_then(Value::as_array)
        .ok_or("no recorded reads")?;
    assert!(reads.len() >= 2);
    let indexed: Vec<&Value> = reads
        .iter()
        .filter(|read| read.get("takes").and_then(Value::as_str) == Some("the first seal"))
        .collect();
    let whole: Vec<&Value> = reads
        .iter()
        .filter(|read| read.get("takes").and_then(Value::as_str) == Some("the whole list"))
        .collect();
    assert!(!indexed.is_empty(), "nothing indexes the seal list");
    assert!(!whole.is_empty(), "nothing reads the seal list whole");
    // The indexing one is the delegation helper; the whole-list one is Roadmap 8.4's round.
    assert!(
        indexed
            .iter()
            .all(|read| read.get("file").and_then(Value::as_str) == Some("test-integration/utils/multisig-utils.ts"))
    );

    // Driven: the initiator anchors two, the joining member anchors one.
    assert_eq!(
        recorded
            .get("initiator_anchored")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(
        recorded.get("joiner_anchored").and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
    // So the two members sign different events — with no error on either side.
    assert_eq!(recorded.get("events_agree").and_then(Value::as_bool), Some(false));
    assert_eq!(recorded.get("joiner_error"), Some(&Value::Null));
    assert_ne!(recorded.get("initiator_event"), recorded.get("joiner_event"));

    // And the seal it kept is the first of the two, not an arbitrary one.
    let kept = recorded
        .pointer("/joiner_anchored/0")
        .ok_or("the joining member anchored nothing")?;
    assert_eq!(recorded.pointer("/initiator_anchored/0"), Some(kept));
    Ok(())
}

#[test]
fn the_one_check_fires_after_the_approval_is_already_posted() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_check_fires_after_the_approval_is_already_posted")?;

    // The helper throws, so the caller gets an exception rather than an operation.
    assert!(
        recorded
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|error| !error.is_empty())
    );
    // But the approval was written first, so the delegator's log holds both seals.
    assert_eq!(
        recorded.get("anchored_anyway").and_then(Value::as_array).map(Vec::len),
        Some(2)
    );
    let requests = recorded
        .get("requests_made")
        .and_then(Value::as_array)
        .ok_or("no recorded requests")?;
    assert!(
        requests
            .iter()
            .filter_map(Value::as_str)
            .any(|request| request.ends_with("/delegation")),
        "the approval was not posted"
    );
    // And the peers are never told.
    assert_eq!(recorded.get("announced").and_then(Value::as_bool), Some(false));

    // It is the only comparison of its kind in the tree, and it is in a test helper.
    let checks = quirk(&fixture, "the_reference_checks_its_own_work_exactly_once")?;
    let assertions = checks
        .get("declaration")
        .and_then(Value::as_array)
        .ok_or("no recorded assertion")?;
    assert_eq!(assertions.len(), 1);
    assert!(
        assertions
            .first()
            .and_then(Value::as_str)
            .is_some_and(|text| text.contains("assert.equal") && text.contains("expectedAnchor"))
    );
    assert_eq!(fixture.declarations.assertions.len(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// The round itself.
// ---------------------------------------------------------------------------

#[test]
fn a_delegated_group_inception_is_a_dip_naming_its_delegator() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "a_delegated_group_inception_is_a_dip")?;
    assert_eq!(recorded.get("ilk").and_then(Value::as_str), Some("dip"));
    assert_eq!(recorded.get("undelegated_ilk").and_then(Value::as_str), Some("icp"));
    assert_eq!(
        recorded.get("delegator").and_then(Value::as_str),
        Some(fixture.pinned_confirmations.delegator_group.as_str())
    );

    // The scenario incepts one of each with the same helper, differing only in `delpre`.
    let inceptions = &fixture.declarations.inception_arguments;
    assert!(inceptions.iter().any(|call| call.delegated));
    assert!(inceptions.iter().any(|call| !call.delegated));
    for call in inceptions {
        assert_eq!(call.delegated, call.properties.iter().any(|name| name == "delpre"));
    }
    assert!(fixture.declarations.delegated_inception_uses.total >= 1);

    // The delegated group's event says so, and its identifier is the one the seal names.
    let created = body(&fixture, "incept_the_delegatee_group", "/identifiers")?;
    assert_eq!(created.pointer("/icp/t").and_then(Value::as_str), Some("dip"));
    assert_eq!(
        created.pointer("/icp/di").and_then(Value::as_str),
        Some(fixture.pinned_confirmations.delegator_group.as_str())
    );
    assert_eq!(
        created.pointer("/icp/i").and_then(Value::as_str),
        Some(fixture.pinned_confirmations.delegatee_group.as_str())
    );
    Ok(())
}

#[test]
fn a_delegated_group_proposal_still_classifies_as_an_inception() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // Roadmap 8.1's inception embed accepts both ilks, so the proposal a delegated group sends is
    // read as an inception like any other. This is the first item to drive one.
    let announced = body(&fixture, "incept_the_delegatee_group", "/exchanges")?;
    let exn = announced.get("exn").ok_or("no exn")?.clone();
    assert_eq!(
        exn.pointer("/e/icp/t").and_then(Value::as_str),
        Some("dip"),
        "the delegated inception is not in the inception slot"
    );

    let listing = serde_json::json!([{ "exn": exn, "paths": {}, "groupName": "delegatees",
        "memberName": "delegator1", "sender": LOCAL }]);
    let decoded: Vec<MultisigExchangeResource> = serde_json::from_value(listing)?;
    let entry = decoded.first().ok_or("empty listing")?;
    let classified = ClassifiedExchange::try_from(entry)?;
    let proposal = classified.as_multisig().ok_or("not a multisig proposal")?;
    assert_eq!(proposal.route, MultisigRoute::Inception);
    assert_eq!(
        proposal.attributes.group.qb64()?,
        fixture.pinned_confirmations.delegatee_group
    );
    Ok(())
}

#[test]
fn an_approval_is_an_interaction_at_the_delegation_address() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let confirmations = &fixture.pinned_confirmations;
    // The initiator reads the group, approves, and announces.
    assert_eq!(
        confirmations.initiator_paths,
        [
            "GET /identifiers/delegators",
            "POST /identifiers/delegators/delegation",
            "POST /identifiers/delegator1/exchanges",
        ]
    );
    // The joining member reads the announcement first.
    assert_eq!(confirmations.joiner_paths.len(), 4);
    assert!(
        confirmations
            .joiner_paths
            .first()
            .is_some_and(|path| path.contains("/multisig/request/"))
    );
    assert_eq!(
        confirmations.joiner_paths.get(1..),
        confirmations.initiator_paths.get(..)
    );

    // The address is Roadmap 8.5's, and the announcement is Roadmap 8.4's route and slot.
    assert!(confirmations.approval_path.ends_with(DELEGATION_SEGMENT));
    assert_eq!(confirmations.announcement_route, INTERACTION_ROUTE);
    let announced = body(&fixture, "approve_as_the_initiator", "/exchanges")?;
    assert!(
        announced
            .pointer("/exn/e")
            .and_then(Value::as_object)
            .is_some_and(|embeds| embeds.contains_key(INTERACTION_SLOT))
    );
    // The topic is the group's own alias, which is what the helper passes.
    assert_eq!(confirmations.announcement_topic, "delegators");
    assert!(!confirmations.note.is_empty());
    Ok(())
}

#[test]
fn the_two_members_anchor_the_same_seal_on_the_happy_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let initiator = body(&fixture, "approve_as_the_initiator", "/delegation")?;
    let joiner = body(&fixture, "approve_as_a_joining_member", "/delegation")?;

    // One seal each, the same one, in the same event.
    assert_eq!(initiator.pointer("/ixn/a"), joiner.pointer("/ixn/a"));
    assert_eq!(initiator.pointer("/ixn/d"), joiner.pointer("/ixn/d"));
    assert_eq!(initiator.pointer("/ixn/a/0"), Some(&fixture.pinned_confirmations.seal));
    // Which names the delegatee group three ways, as a delegated inception's seal does.
    let seal = InceptionSeal::new(
        IdentifierPrefix::from_qb64(&fixture.pinned_confirmations.delegatee_group)?,
        fixture.pinned_confirmations.delegatee_group.parse::<Said>()?,
    );
    let written: Value = serde_json::from_slice(&seal.to_sad()?.to_json_bytes()?)?;
    assert_eq!(written, fixture.pinned_confirmations.seal);
    Ok(())
}

// ---------------------------------------------------------------------------
// The two divergences this round inherits.
// ---------------------------------------------------------------------------

#[test]
fn the_rotation_set_is_the_signing_set_a_third_time() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_rotation_set_is_the_signing_set_a_third_time")?;
    assert_eq!(recorded.get("identical").and_then(Value::as_bool), Some(true));
    assert_eq!(recorded.get("announced_smids"), recorded.get("announced_rmids"));
    // Unconditional here: no rotation set is consulted at all.
    let expressions = &fixture.declarations.member_expressions;
    assert!(
        expressions
            .iter()
            .any(|entry| entry.label == "smids" && entry.expression.contains("otherMembersAIDs")),
        "the signing set is no longer hand-assembled"
    );
    for entry in expressions {
        assert!(!entry.file.is_empty());
        assert!(["smids", "rmids", "recp"].contains(&entry.label.as_str()));
    }
    Ok(())
}

#[test]
fn the_member_list_is_the_callers_and_the_delivery_list_excludes_the_sender() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_member_list_is_hand_assembled")?;
    // This half does exclude the sender, which Roadmap 8.3's proposing half fails to do.
    assert_eq!(
        recorded.get("sender_is_a_recipient").and_then(Value::as_bool),
        Some(false)
    );
    let members = recorded
        .get("announced_smids")
        .and_then(Value::as_array)
        .ok_or("no recorded members")?;
    let recipients = recorded
        .get("recipients")
        .and_then(Value::as_array)
        .ok_or("no recorded recipients")?;
    assert_eq!(members.len(), recipients.len() + 1);
    assert_eq!(
        recorded.get("sender").and_then(Value::as_str),
        members.first().and_then(Value::as_str),
        "the sender is not the first member"
    );
    Ok(())
}

#[test]
fn the_scenario_still_reads_a_group_prefix_out_of_an_operations_name() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // Roadmap 8.5 recorded this for a single-signature delegate; here it is a group's prefix, and
    // the scenario does it twice.
    let discoveries = &fixture.declarations.prefix_discoveries;
    assert!(discoveries.len() >= 2);
    for discovery in discoveries {
        assert!(discovery.from.contains(".name.split("));
        assert!(!discovery.binds.is_empty());
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
    // And every anchor read the scan found belongs to a file the fixture names as a source.
    for read in &fixture.declarations.anchor_reads {
        assert!(
            fixture.sources.contains(&read.file),
            "{} is not a recorded source",
            read.file
        );
        assert!(!read.binds.is_empty() && !read.expression.is_empty());
        // And it says which of the two readings it is, checked against its own text.
        assert!(
            read.takes == "the first seal" || read.takes == "the whole list",
            "{} reads the seal list in an unrecognised way",
            read.file
        );
        assert_eq!(
            read.takes == "the first seal",
            read.expression.trim_end().ends_with("[0]"),
            "{} disagrees with its own expression",
            read.file
        );
    }
    Ok(())
}
