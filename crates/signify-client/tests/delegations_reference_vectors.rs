//! Exact delegation-endpoint vectors recorded from the pinned reference's own `Delegations`.
//!
//! The only published body approves nothing: it anchors `[null]`, reproduced exactly and then proven unspellable.

mod support;

use std::error::Error;

use crate::support::{FIXED_MILLIS, Harness, PASSCODE, SentRequest, block_on, connected, reseal, sent_all};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::Sad;
use serde::Deserialize;
use serde_json::Value;
use signify_client::endpoint::delegations::{
    DELEGATION_SEGMENT, InceptionSeal, SEAL_DIGEST_LABEL, SEAL_IDENTIFIER_LABEL, SEAL_SEQUENCE_LABEL,
};
use signify_client::error::ClientError;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

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
    pinned_body: String,
    approval_path: String,
    delegator_prefix: String,
    delegate_prefix: String,
    seal: Value,
    note: String,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    support::fixture("client-delegations")
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
    assert_ne!(fixture.generated_on, "");
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

    let record = identifier_record(&fixture)?;
    let Harness { client, transport, .. } = connected(&[&record, b"{}", &record, b"{}"])?;
    block_on(client.delegations().approve("delegator", &[seal()?]))?;
    block_on(client.identifiers().interact("delegator", vec![seal()?]))?;

    let requests = sent_all(&transport)?;
    let writes: Vec<&SentRequest> = requests
        .iter()
        .filter(|SentRequest { method, .. }| method == "POST")
        .collect();
    let [
        SentRequest {
            path: approval,
            body: approval_body,
            ..
        },
        SentRequest {
            path: interaction,
            body: interaction_body,
            ..
        },
    ] = writes.as_slice()
    else {
        return Err(format!("expected two writes, sent {requests:?}").into());
    };
    assert_eq!(
        Some(approval.as_str()),
        recorded.get("approval_path").and_then(Value::as_str)
    );
    assert_eq!(
        Some(interaction.as_str()),
        recorded.get("interaction_path").and_then(Value::as_str)
    );
    assert_eq!(approval_body, interaction_body);
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

    let record = identifier_record(&fixture)?;
    let Harness { client, transport, .. } = connected(&[&record, b"{}"])?;
    block_on(client.delegations().approve("a/b?c=d", &[seal()?]))?;
    let requests = sent_all(&transport)?;
    let addressed: Vec<(&str, &str)> = requests
        .iter()
        .map(|SentRequest { path, method, .. }| (method.as_str(), path.as_str()))
        .collect();
    assert_eq!(
        addressed,
        [
            ("GET", "/identifiers/a%2Fb%3Fc%3Dd"),
            ("POST", "/identifiers/a%2Fb%3Fc%3Dd/delegation")
        ]
    );
    Ok(())
}

// --- The finding: an anchor may be anything ---

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
        assert_ne!(entry.arguments, [] as [String; 0]);
    }
    assert_ne!(fixture.pinned_confirmations.note, "");
    assert_ne!(fixture.pinned_confirmations.approval_path, "");
    assert_eq!(fixture.pinned_confirmations.delegator_prefix, DELEGATOR);
    Ok(())
}

fn identifier_record(fixture: &Fixture) -> Result<Vec<u8>, Box<dyn Error>> {
    reseal(&fixture.identifier_record, PASSCODE)
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
    let Harness { client, transport, .. } = connected(&[&record, b"{}"])?;

    let _ = block_on(client.delegations().approve("delegator", &[seal()?]))?;

    let requests = sent_all(&transport)?;
    assert_eq!(
        requests
            .iter()
            .map(|SentRequest { path, method, .. }| format!("{method} {path}"))
            .collect::<Vec<String>>(),
        ["GET /identifiers/delegator", "POST /identifiers/delegator/delegation"]
    );
    assert_eq!(
        requests.last().map(|SentRequest { path, .. }| path.as_str()),
        Some(fixture.pinned_confirmations.approval_path.as_str())
    );
    Ok(())
}

#[test]
fn this_port_anchors_the_seal_the_reference_anchored() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = identifier_record(&fixture)?;
    let Harness { client, transport, .. } = connected(&[&record, b"{}"])?;

    let _ = block_on(client.delegations().approve("delegator", &[seal()?]))?;

    let requests = sent_all(&transport)?;
    let SentRequest { body: written, .. } = requests.last().ok_or("nothing was written")?;
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
    let Harness { client, transport, .. } = connected(&[&record, b"{}"])?;

    let refused = matches!(
        block_on(client.delegations().approve("delegator", &[])),
        Err(ClientError::NoDelegationSeals)
    );
    assert!(refused, "an approval of nothing was accepted");
    assert_eq!(
        sent_all(&transport)?
            .into_iter()
            .map(|sent| (sent.path, sent.method, sent.body))
            .collect::<Vec<_>>(),
        [] as [(String, String, Option<String>); 0]
    );

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
