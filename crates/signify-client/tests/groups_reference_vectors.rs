//! Exact group-endpoint vectors recorded from the pinned reference's own `Groups`.
//!
//! Three addresses reproduced through a connected client, and a hostile alias encoded before it reaches the wire.

mod support;

use std::error::Error;
use std::sync::Arc;

use crate::support::{ADMIN, AgentTransport, BOOT, PASSCODE, agent_state, block_on, clock};
use keri_cesr::crypto::cipher::Encrypter;
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keria_types::api::{GroupOperation, MultisigExchangeResource};
use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::exchanges::{ClassifiedExchange, ExchangeDraft, MULTISIG_TOPIC, MultisigRoute};
use signify_http::transport::Transport;
use signify_keys::manager::DerivationCost;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/client-groups/v1.json"));

const EXCHANGES_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/client-exchanges/v1.json"
));

const STAMP: &str = "2023-11-14T22:13:20.123000+00:00";
const REAL_SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const GROUP: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const MEMBER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

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
    pinned_arguments: PinnedArguments,
    calls: Vec<Call>,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    fixed_clock_ms: u64,
    agent_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    get_request_path: String,
    get_request_method: String,
    get_request_signature: Vec<String>,
    get_request_return_type: String,
    send_request_path: String,
    send_request_data: String,
    send_request_method: String,
    send_request_signature: Vec<String>,
    send_request_return_type: String,
    join_path: String,
    join_data: String,
    join_method: String,
    join_signature: Vec<String>,
    join_return_type: String,
    groups_members: Vec<String>,
    schema_exn_multisig: String,
    schema_group_operation_metadata: String,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct PinnedArguments {
    send_request_signatures: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    answer: Value,
    request: Option<RecordedRequest>,
    result: Value,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    body: Option<String>,
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

fn request_of<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a RecordedRequest, Box<dyn Error>> {
    call(fixture, name)?
        .request
        .as_ref()
        .ok_or_else(|| format!("call {name} recorded no request").into())
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

/// The exchanges fixture's `aid1`, its salt sealed under the test passcode's key.
fn identifier_record() -> Result<Vec<u8>, Box<dyn Error>> {
    let exchanges: Value = serde_json::from_str(EXCHANGES_FIXTURE)?;
    let mut record = exchanges
        .pointer("/mock_shortfall/identifier_record")
        .cloned()
        .ok_or("the exchanges fixture carries no identifier record")?;
    let opens_to = record
        .pointer("/salty/sxlt_opens_to")
        .and_then(Value::as_str)
        .ok_or("the recorded identifier carries no sealed salt")?
        .to_owned();
    let signer = Salt::from_qb64(&format!("0AA{PASSCODE}"), SecurityTier::Low)?
        .derive_signer("", KeyTransferability::NonTransferable)?;
    let sealed = Encrypter::from_verification_key(signer.verifier())?
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

// --- Manifest and provenance ---
#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert_ne!(fixture.generated_on, "");
    assert!(fixture.sources.iter().any(|source| source.ends_with("grouping.ts")));
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("grouping.test.ts"))
    );
    assert_eq!(fixture.provenance.bran, "0123456789abcdefghijk");
    assert_eq!(fixture.provenance.admin_url, "http://127.0.0.1:3901");
    assert_eq!(fixture.provenance.fixed_clock_ms, 1_700_000_000_123);
    assert_ne!(fixture.provenance.agent_prefix, "");
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 12);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
        assert!(entry.request.is_some(), "call {} sent nothing", entry.name);
    }
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    assert_eq!(
        declarations.groups_members,
        ["client", "<constructor>", "getRequest", "sendRequest", "join"]
    );

    assert_eq!(declarations.get_request_path, "path = `/multisig/request/` + said");
    assert_eq!(declarations.get_request_method, "method = 'GET'");
    assert_eq!(declarations.get_request_signature, ["said: string"]);
    assert_eq!(declarations.get_request_return_type, "Promise<ExnMultisig[]>");

    assert_eq!(
        declarations.send_request_path,
        "path = `/identifiers/${name}/multisig/request`"
    );
    assert_eq!(declarations.send_request_method, "method = 'POST'");
    for field in ["exn:", "sigs:", "atc:"] {
        assert!(declarations.send_request_data.contains(field), "no {field}");
    }
    for absent in ["tpc:", "rec:"] {
        assert!(
            !declarations.send_request_data.contains(absent),
            "the body now writes {absent}"
        );
    }

    assert_eq!(declarations.join_path, "path = `/identifiers/${name}/multisig/join`");
    assert_eq!(declarations.join_method, "method = 'POST'");
    assert!(declarations.join_data.contains("tpc: 'multisig'"));
    assert!(declarations.join_data.contains("rot: rot.sad"));
    for field in ["sigs:", "gid:", "smids:", "rmids:"] {
        assert!(declarations.join_data.contains(field), "no {field}");
    }
    assert_eq!(
        declarations.send_request_signature,
        ["name: string", "exn: Exn", "sigs: string[]", "atc: string"]
    );
    assert_eq!(declarations.join_signature.len(), 6);
    assert!(
        declarations
            .join_signature
            .iter()
            .any(|parameter| parameter == "rot: any")
    );
    assert!(
        declarations
            .join_signature
            .iter()
            .any(|parameter| parameter.starts_with("gid:"))
    );

    assert!(declarations.notes.is_object());
    Ok(())
}

#[test]
fn the_pinned_proposal_carries_no_signature() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.pinned_arguments.send_request_signatures, [] as [String; 0]);

    let recorded = request_of(&fixture, "send_request_pinned")?;
    let body: Value = serde_json::from_str(recorded.body.as_deref().ok_or("no body")?)?;
    assert_eq!(body.get("sigs"), Some(&Value::Array(Vec::new())));
    assert_eq!(body.get("atc").and_then(Value::as_str), Some(""));
    assert_eq!(
        body.get("exn").and_then(|exn| exn.get("i")).and_then(Value::as_str),
        Some("test")
    );
    assert!(keri_protocol::prefix::IdentifierPrefix::from_qb64("test").is_err());
    Ok(())
}

// --- The addresses ---
#[test]
fn the_real_read_reproduces_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "get_request_real_said")?;
    let request = recorded.request.as_ref().ok_or("the real read recorded no request")?;
    let answer = serde_json::to_vec(&recorded.answer)?;

    let (client, transport) = connected(&[&answer])?;
    let listing = block_on(client.groups().requests(&REAL_SAID.parse::<Said>()?))?;
    assert_eq!(listing.len(), 1);
    assert_eq!(
        sent(&transport)?,
        [(request.path.clone(), request.method.clone(), request.body.clone())]
    );
    Ok(())
}

#[test]
fn an_alias_never_reaches_the_wire_unencoded() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let alias = request_of(&fixture, "send_request_escaping_alias")?;
    assert_eq!(alias.path, "/identifiers/a/b?c=d/multisig/request");

    let record = identifier_record()?;
    let (client, transport) = connected(&[&record, b"{}"])?;
    let draft = ExchangeDraft::new("/multisig/icp", MEMBER.parse::<IdentifierPrefix>()?, STAMP.parse()?);
    let message = block_on(client.exchanges().create_message("aid1", &draft))?;
    block_on(client.groups().send_request("a/b?c=d", &message))?;

    let requests = sent(&transport)?;
    let (path, method, _) = requests.last().ok_or("no proposal was sent")?;
    assert_eq!(method, "POST");
    assert_eq!(path, "/identifiers/a%2Fb%3Fc%3Dd/multisig/request");
    Ok(())
}

// --- The bodies ---
#[test]
fn a_signed_proposal_writes_three_fields_and_no_topic() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "send_request_signed")?;
    let rendered = recorded.body.as_deref().ok_or("no body")?;
    let body: Value = serde_json::from_str(rendered)?;

    assert!(rendered.starts_with(r#"{"exn":"#));
    let fields = body.as_object().ok_or("the body is not an object")?;
    assert_eq!(fields.len(), 3);
    for label in ["exn", "sigs", "atc"] {
        assert!(fields.contains_key(label), "no {label}");
    }
    for absent in ["tpc", "rec"] {
        assert!(!fields.contains_key(absent), "the body now writes {absent}");
    }
    assert_eq!(
        body.get("sigs").and_then(Value::as_array).map(Vec::len),
        Some(1),
        "the signed proposal carries one signature"
    );
    assert_eq!(body.get("atc").and_then(Value::as_str), Some("-LAZ5AACAA-e-icp"));
    Ok(())
}

#[test]
fn a_real_join_writes_the_references_six_fields_in_order() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "join_real")?;
    let rendered = recorded.body.as_deref().ok_or("no body")?;
    let body: Value = serde_json::from_str(rendered)?;

    let mut previous = 0_usize;
    for label in [
        r#""tpc":"#,
        r#""rot":"#,
        r#""sigs":"#,
        r#""gid":"#,
        r#""smids":"#,
        r#""rmids":"#,
    ] {
        let at = rendered.find(label).ok_or_else(|| format!("no {label}"))?;
        assert!(at >= previous, "{label} is out of order in {rendered}");
        previous = at;
    }
    assert_eq!(body.get("tpc").and_then(Value::as_str), Some(MULTISIG_TOPIC));
    assert_eq!(body.get("gid").and_then(Value::as_str), Some(GROUP));
    assert_eq!(
        body.get("rot").and_then(|rot| rot.get("t")).and_then(Value::as_str),
        Some("rot")
    );
    assert_eq!(body.get("smids").and_then(Value::as_array).map(Vec::len), Some(2));
    assert_eq!(body.get("rmids").and_then(Value::as_array).map(Vec::len), Some(2));
    Ok(())
}

#[test]
fn passing_the_event_instead_of_its_serder_sends_no_rotation() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "join_event_instead_of_serder")?;
    let body: Value = serde_json::from_str(recorded.body.as_deref().ok_or("no body")?)?;
    assert_eq!(body.get("rot"), None, "the event was sent after all");
    for label in ["tpc", "sigs", "gid", "smids", "rmids"] {
        assert!(body.get(label).is_some(), "no {label}");
    }
    Ok(())
}

#[test]
fn a_join_naming_no_member_is_sent_upstream_and_refused_here() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "join_no_members")?;
    let body: Value = serde_json::from_str(recorded.body.as_deref().ok_or("no body")?)?;
    assert_eq!(body.get("smids"), Some(&Value::Array(Vec::new())));
    assert_eq!(body.get("rmids"), Some(&Value::Array(Vec::new())));
    Ok(())
}

// --- The answers ---
#[test]
fn a_request_listing_decodes_and_classifies() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "get_request_real_said")?;
    let listing: Vec<MultisigExchangeResource> = serde_json::from_value(recorded.answer.clone())?;
    assert_eq!(listing.len(), 1);

    let first = listing.first().ok_or("empty listing")?;
    assert_eq!(first.group_name.as_deref(), Some("multisig"));
    assert_eq!(first.member_name.as_deref(), Some("member1"));
    assert_eq!(first.sender.as_deref(), Some(MEMBER));

    let classified = ClassifiedExchange::try_from(first)?;
    let proposal = classified.as_multisig().ok_or("not a multisig proposal")?;
    assert_eq!(proposal.route, MultisigRoute::Inception);
    assert_eq!(proposal.attributes.group.qb64()?, GROUP);
    assert_eq!(
        proposal.attributes.signing_members.as_ref().map(Vec::len),
        Some(2),
        "the proposal names both members"
    );
    Ok(())
}

#[test]
fn an_answer_that_is_not_a_listing_is_refused_where_the_reference_casts_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "get_request_wrong_shape")?;
    assert_eq!(recorded.error, None);
    assert!(recorded.result.get("notes").is_some());
    assert!(serde_json::from_value::<Vec<MultisigExchangeResource>>(recorded.answer.clone()).is_err());
    Ok(())
}

#[test]
fn a_join_is_answered_with_the_operation_it_declares() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "join_real")?;
    let operation: GroupOperation = serde_json::from_value(recorded.answer.clone())?;
    assert_eq!(operation.name, format!("group.{GROUP}"));
    assert!(!operation.outcome.is_done());
    assert!(matches!(operation.outcome, keria_types::api::OperationOutcome::Pending));

    assert_eq!(fixture.declarations.join_return_type, "Promise<GroupOperation>");
    assert_eq!(fixture.declarations.send_request_return_type, "Promise<Exn>");
    assert!(fixture.declarations.schema_group_operation_metadata.contains("pre"));
    assert!(fixture.declarations.schema_exn_multisig.contains("paths"));
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 7);
    for (name, quirk) in quirks {
        let entry = quirk.as_object().ok_or("a divergence is not an object")?;
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
