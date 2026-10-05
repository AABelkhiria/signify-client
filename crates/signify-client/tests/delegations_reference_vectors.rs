//! Exact delegation-endpoint vectors recorded from the pinned reference's own `Delegations`.
//!
//! The only published body approves nothing: it anchors `[null]`, reproduced exactly and then proven unspellable.

mod support;

use std::error::Error;
use std::sync::Arc;

use crate::support::{ADMIN, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on, clock};
use keri_cesr::crypto::cipher::Encrypter;
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::verifier::KeyTransferability;
use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::delegations::{
    DELEGATION_SEGMENT, InceptionSeal, SEAL_DIGEST_LABEL, SEAL_IDENTIFIER_LABEL, SEAL_SEQUENCE_LABEL,
};
use signify_client::endpoint::identifiers::{EVENTS_SEGMENT, IDENTIFIERS_SEGMENT};
use signify_client::error::ClientError;
use signify_http::request::ResourcePath;
use signify_http::transport::Transport;
use signify_keri::manager::DerivationCost;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::Sad;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-delegations/v1.json");

const DELEGATOR: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const DELEGATE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

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
    identifier_record: Value,
    calls: Vec<Call>,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    fixed_clock_ms: u64,
    delegator_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    approve: String,
    members: Vec<String>,
    signature: Signature,
    fetch_calls: Vec<FetchCall>,
    approve_calls: Vec<ApproveCall>,
    prefix_discovery: PrefixDiscovery,
    anchor_wrapping: String,
    delegations_accessor_uses: Scan,
    delegation_segment_uses: Scan,
    file_lines: usize,
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
    optional: bool,
}

#[derive(Debug, Deserialize)]
struct FetchCall {
    path: String,
    method: String,
}

#[derive(Debug, Deserialize)]
struct ApproveCall {
    file: String,
    arguments: Vec<String>,
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
    pinned_name: String,
    pinned_path: String,
    pinned_body: String,
    approval_path: String,
    delegator_prefix: String,
    delegate_prefix: String,
    seal: Value,
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

fn body(fixture: &Fixture, name: &str) -> Result<Value, Box<dyn Error>> {
    let request = call(fixture, name)?
        .requests
        .iter()
        .find(|entry| entry.method == "POST")
        .ok_or_else(|| format!("call {name} wrote nothing"))?;
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
    assert!(fixture.sources.iter().any(|source| source.ends_with("delegating.ts")));
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.delegator_prefix, DELEGATOR);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 7);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert_eq!(
            entry.requests.len(),
            2,
            "call {} sent {} requests",
            entry.name,
            entry.requests.len()
        );
        assert_eq!(
            entry.requests.first().map(|request| request.method.as_str()),
            Some("GET")
        );
        assert_eq!(
            entry.requests.last().map(|request| request.method.as_str()),
            Some("POST")
        );
        for request in &entry.requests {
            assert!(
                request.path.starts_with("/identifiers/"),
                "call {} left the family",
                entry.name
            );
            assert_eq!(request.body.is_some(), request.method == "POST");
        }
        assert_eq!(entry.error, None, "call {} failed upstream", entry.name);
        assert!(!entry.result.is_null(), "call {} answered nothing", entry.name);
    }
    assert_eq!(
        fixture.identifier_record.pointer("/salty/sxlt").and_then(Value::as_str),
        Some("<SXLT>")
    );
    Ok(())
}

#[test]
fn the_class_is_one_method_and_one_address() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.declarations.members, ["client", "approve"]);
    assert_eq!(fixture.declarations.fetch_calls.len(), 1);
    let fetched = fixture.declarations.fetch_calls.first().ok_or("no fetch")?;
    assert_eq!(fetched.method, "POST");
    assert!(fetched.path.contains(DELEGATION_SEGMENT));
    assert!(fixture.declarations.approve.contains("createInteract"));
    assert_eq!(fixture.declarations.file_lines, 33);

    assert_eq!(fixture.declarations.signature.returns, "Promise<EventResult>");
    let parameters = &fixture.declarations.signature.parameters;
    assert_eq!(parameters.len(), 2);
    assert_eq!(
        parameters
            .first()
            .map(|p| (p.name.as_str(), p.declared.as_str(), p.optional)),
        Some(("name", "string", false))
    );
    assert_eq!(
        parameters
            .last()
            .map(|p| (p.name.as_str(), p.declared.as_str(), p.optional)),
        Some(("data", "any", true))
    );
    assert!(fixture.declarations.notes.is_object());
    Ok(())
}

#[test]
fn the_endpoint_has_three_consumers_and_one_is_its_own_test() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let scan = &fixture.declarations.delegations_accessor_uses;
    assert_eq!(scan.needle, "delegations()");
    assert_eq!(scan.scanned_files, 117);
    assert_eq!(
        scan.files.iter().map(|hit| hit.count).sum::<usize>(),
        scan.total,
        "the per-file counts do not add up"
    );
    assert_eq!(scan.files.len(), 4);
    assert!(scan.files.iter().any(|hit| hit.file.ends_with("clienting.ts")));
    assert!(scan.files.iter().any(|hit| hit.file.ends_with("delegating.test.ts")));
    assert!(scan.files.iter().any(|hit| hit.file.ends_with("delegation.test.ts")));
    assert!(scan.files.iter().any(|hit| hit.file.ends_with("multisig-utils.ts")));

    let segment = &fixture.declarations.delegation_segment_uses;
    assert!(segment.files.iter().any(|hit| hit.file.ends_with("delegating.ts")));
    Ok(())
}

// --- The finding: the only published body approves nothing ---
#[test]
fn the_pinned_test_signs_an_approval_of_nothing() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_pinned_test_approves_nothing")?;

    assert!(
        recorded
            .get("wrapping")
            .and_then(Value::as_str)
            .is_some_and(|line| { line.contains("Array.isArray(data)") && line.contains("[data]") })
    );
    assert_eq!(
        recorded.get("anchored").and_then(Value::as_array),
        Some(&vec![Value::Null])
    );
    assert_eq!(
        recorded.get("said").and_then(Value::as_str),
        Some("EBPt7hivibUQN-dlRyE9x_Y5LgFCGJ8QoNLSJrIkBYIg")
    );
    assert_eq!(recorded.get("signatures").and_then(Value::as_u64), Some(1));

    let pinned = recorded.get("pinned_call").ok_or("no pinned call")?;
    assert_eq!(pinned.get("arguments").and_then(Value::as_array).map(Vec::len), Some(1));
    Ok(())
}

#[test]
fn the_pinned_address_method_and_body_reproduce() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let confirmations = &fixture.pinned_confirmations;
    assert_eq!(
        confirmations.pinned_path,
        format!("/identifiers/{}/delegation", confirmations.pinned_name)
    );
    assert_eq!(
        call(&fixture, "approve_with_no_anchor")?
            .requests
            .last()
            .map(|r| r.method.as_str()),
        Some("POST")
    );
    let published = &confirmations.pinned_body;
    assert!(published.contains(r#""a":[null]"#));
    assert!(published.contains(r#""d":"EBPt7hivibUQN-dlRyE9x_Y5LgFCGJ8QoNLSJrIkBYIg""#));
    assert!(published.contains(
        r#""sigs":["AAC4StAw-0IiV_LujceAXB3tnkaK011rPYPBKLgz-u6jI7hwfWGTCu5LDvBUsON4CqXbZAwPgIv6JqYjIusWKv0G"]"#
    ));
    assert!(published.starts_with(r#"{"ixn":"#));
    let order: Vec<usize> = ["\"ixn\":", "\"sigs\":", "\"salty\":"]
        .iter()
        .filter_map(|label| published.find(label))
        .collect();
    assert_eq!(order.len(), 3, "a top-level field is missing");
    assert!(order.is_sorted(), "the fields are out of order");
    let decoded: Value = serde_json::from_str(published)?;

    assert_eq!(confirmations.pinned_name.len(), 44);
    assert_ne!(confirmations.pinned_name, DELEGATOR);
    assert_eq!(decoded.pointer("/ixn/i").and_then(Value::as_str), Some(DELEGATOR));
    Ok(())
}

// --- The finding: the address is the whole difference ---
#[test]
fn an_approval_and_an_interaction_differ_only_in_their_last_segment() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_address_is_the_whole_difference")?;
    assert_eq!(recorded.get("bodies_identical").and_then(Value::as_bool), Some(true));

    let approved = body(&fixture, "approve_a_delegate")?;
    let interacted = body(&fixture, "interact_with_the_same_seal")?;
    assert_eq!(approved, interacted);
    assert_eq!(
        recorded.get("approval_path").and_then(Value::as_str),
        Some("/identifiers/delegator/delegation")
    );
    assert_eq!(
        recorded.get("interaction_path").and_then(Value::as_str),
        Some("/identifiers/delegator/events")
    );

    assert_eq!(DELEGATION_SEGMENT, "delegation");
    assert_eq!(EVENTS_SEGMENT, "events");
    for segment in [DELEGATION_SEGMENT, EVENTS_SEGMENT] {
        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment("delegator")
            .segment(segment)
            .build()?;
        assert_eq!(path.as_str(), format!("/identifiers/delegator/{segment}"));
    }
    Ok(())
}

// --- The finding: one alias, two treatments ---
#[test]
fn one_alias_is_encoded_on_the_read_and_raw_on_the_write() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "one_alias_is_encoded_on_the_read_and_raw_on_the_write")?;
    assert_eq!(
        recorded.get("read_path").and_then(Value::as_str),
        Some("/identifiers/a%2Fb%3Fc%3Dd")
    );
    assert_eq!(
        recorded.get("write_path").and_then(Value::as_str),
        Some("/identifiers/a/b?c=d/delegation")
    );

    let built = ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment("a/b?c=d")
        .segment(DELEGATION_SEGMENT)
        .build()?;
    assert_eq!(built.as_str(), "/identifiers/a%2Fb%3Fc%3Dd/delegation");
    assert_eq!(built.path().split('/').count(), 4);
    assert_eq!(built.query(), None);
    Ok(())
}

// --- The finding: an anchor may be anything ---
#[test]
fn an_anchor_is_never_looked_at_upstream() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "an_anchor_may_be_anything")?;
    assert_eq!(
        recorded.get("string_anchor").and_then(Value::as_array),
        Some(&vec![Value::String("not a seal".to_owned())])
    );
    assert_eq!(
        recorded.get("two_seals").and_then(Value::as_array).map(Vec::len),
        Some(2)
    );

    let wrapped = body(&fixture, "approve_with_a_seal_list")?;
    let bare = body(&fixture, "approve_a_delegate")?;
    assert_eq!(wrapped, bare, "wrapping the seal changed the event");
    Ok(())
}

#[test]
fn a_delegate_need_not_read_its_prefix_out_of_an_operations_name() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = quirk(&fixture, "the_delegate_reads_its_prefix_from_an_operations_name")?;
    let declaration = recorded.get("declaration").ok_or("no declaration")?;
    assert_eq!(
        declaration.get("from").and_then(Value::as_str),
        Some("op2.name.split('.')[1]")
    );
    assert_eq!(declaration.get("binds").and_then(Value::as_str), Some("delegatePrefix"));
    assert_eq!(fixture.declarations.prefix_discovery.binds, "delegatePrefix");
    assert_eq!(fixture.declarations.prefix_discovery.from, "op2.name.split('.')[1]");
    assert!(fixture.declarations.anchor_wrapping.contains("Array.isArray"));

    let seal = InceptionSeal::new(
        IdentifierPrefix::from_qb64(&fixture.pinned_confirmations.delegate_prefix)?,
        fixture.pinned_confirmations.delegate_prefix.parse::<Said>()?,
    );
    let written: Value = serde_json::from_slice(&seal.to_sad()?.to_json_bytes()?)?;
    assert_eq!(written, fixture.pinned_confirmations.seal);
    for label in [SEAL_IDENTIFIER_LABEL, SEAL_SEQUENCE_LABEL, SEAL_DIGEST_LABEL] {
        assert!(written.get(label).is_some(), "the seal carries no {label}");
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
    for entry in &fixture.declarations.approve_calls {
        assert!(
            std::path::Path::new(&entry.file)
                .extension()
                .is_some_and(|kind| kind == "ts")
        );
        assert!(!entry.arguments.is_empty());
    }
    assert!(!fixture.pinned_confirmations.note.is_empty());
    assert!(!fixture.pinned_confirmations.approval_path.is_empty());
    assert_eq!(fixture.pinned_confirmations.delegator_prefix, DELEGATOR);
    Ok(())
}

fn connected(bodies: &[&[u8]]) -> Result<(ConnectedClient, Arc<AgentTransport>), Box<dyn Error>> {
    let configuration = || {
        ClientConfig::new(ADMIN, PASSCODE)
            .and_then(|config| config.with_boot_url(BOOT))
            .map(|config| config.with_derivation_cost(DerivationCost::Ephemeral))
    };
    let probe = SignifyClient::new(
        configuration()?,
        AgentTransport::new(&[]) as Arc<dyn Transport>,
        clock(),
    )?;
    let prefix = probe.controller().prefix().qb64()?;
    let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();

    let state = agent_state(&prefix, &inception);
    let mut answers: Vec<&[u8]> = vec![state.as_bytes(), b"{}"];
    answers.extend_from_slice(bodies);
    let transport = AgentTransport::new(&answers);

    let client = SignifyClient::new(configuration()?, Arc::clone(&transport) as Arc<dyn Transport>, clock())?;
    Ok((block_on(client.connect())?, transport))
}

type SentRequest = (String, String, Option<String>);

fn sent(transport: &AgentTransport) -> Result<Vec<SentRequest>, Box<dyn Error>> {
    Ok(transport
        .endpoint_requests()?
        .into_iter()
        .map(|request| (request.resource(), request.method().to_owned(), request.body_text()))
        .collect())
}

fn sealing_key() -> Result<Encrypter, Box<dyn Error>> {
    let salt = Salt::from_qb64(&format!("0AA{PASSCODE}"), SecurityTier::Low)?;
    let signer = salt.derive_signer("", KeyTransferability::NonTransferable)?;
    Ok(Encrypter::from_verification_key(signer.verifier())?)
}

fn identifier_record(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut record = fixture.identifier_record.clone();
    let opens_to = record
        .pointer("/salty/sxlt_opens_to")
        .and_then(Value::as_str)
        .ok_or("the recorded identifier carries no sealed salt")?
        .to_owned();
    let sealed = sealing_key()?
        .encrypt_salt(&Salt::from_qb64(&opens_to, SecurityTier::Low)?)?
        .qb64()?;
    let salty = record
        .get_mut("salty")
        .and_then(Value::as_object_mut)
        .ok_or("the recorded identifier has no key-manager block")?;
    salty.remove("sxlt_opens_to");
    salty.insert("sxlt".to_owned(), Value::String(sealed));
    Ok(serde_json::to_vec(&record)?)
}

fn seal() -> Result<Sad, Box<dyn Error>> {
    InceptionSeal::new(IdentifierPrefix::from_qb64(DELEGATE)?, DELEGATE.parse::<Said>()?)
        .to_sad()
        .map_err(Into::into)
}

#[test]
fn this_port_addresses_the_approval_where_the_reference_does() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = identifier_record(&fixture)?;
    let (client, transport) = connected(&[&record, b"{}"])?;

    let _ = block_on(client.delegations().approve("delegator", &[seal()?]))?;

    let requests = sent(&transport)?;
    assert_eq!(
        requests
            .iter()
            .map(|(path, method, _)| format!("{method} {path}"))
            .collect::<Vec<String>>(),
        ["GET /identifiers/delegator", "POST /identifiers/delegator/delegation"]
    );
    assert_eq!(
        requests.last().map(|(path, _, _)| path.as_str()),
        Some(fixture.pinned_confirmations.approval_path.as_str())
    );
    Ok(())
}

#[test]
fn this_port_anchors_the_seal_the_reference_anchored() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = identifier_record(&fixture)?;
    let (client, transport) = connected(&[&record, b"{}"])?;

    let _ = block_on(client.delegations().approve("delegator", &[seal()?]))?;

    let requests = sent(&transport)?;
    let (_, _, written) = requests.last().ok_or("nothing was written")?;
    let sent_body: Value = serde_json::from_str(written.as_deref().ok_or("no body")?)?;
    let recorded = body(&fixture, "approve_a_delegate")?;

    assert_eq!(sent_body.pointer("/ixn/a"), recorded.pointer("/ixn/a"));
    for label in ["i", "s", "p", "t", "d"] {
        assert_eq!(
            sent_body.pointer(&format!("/ixn/{label}")),
            recorded.pointer(&format!("/ixn/{label}")),
            "the two events disagree about {label}"
        );
    }
    Ok(())
}

#[test]
fn this_port_cannot_spell_an_approval_of_nothing() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = identifier_record(&fixture)?;
    let (client, transport) = connected(&[&record, b"{}"])?;

    let refused = matches!(
        block_on(client.delegations().approve("delegator", &[])),
        Err(ClientError::NoDelegationSeals)
    );
    assert!(refused, "an approval of nothing was accepted");
    assert!(sent(&transport)?.is_empty());

    assert!(fixture.pinned_confirmations.pinned_body.contains(r#""a":[null]"#));
    Ok(())
}

#[test]
fn this_port_builds_the_seal_from_the_event_rather_than_from_a_name() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let written: Value = serde_json::from_slice(&seal()?.to_json_bytes()?)?;
    assert_eq!(written, fixture.pinned_confirmations.seal);
    assert_eq!(
        written.get(SEAL_IDENTIFIER_LABEL).and_then(Value::as_str),
        Some(DELEGATE)
    );
    assert_eq!(written.get(SEAL_SEQUENCE_LABEL).and_then(Value::as_str), Some("0"));
    Ok(())
}
