//! Exact credentials-endpoint vectors recorded from the pinned reference's own `Credentials`.
//!
//! All six methods driven through the reference's own mocks, with every value its unit case asserts recomputed.

mod support;

use std::error::Error;
use std::sync::Arc;

use crate::support::{ADMIN, AGENT, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on, clock};
use keri_cesr::crypto::cipher::{Ciphertext, Decrypter, Encrypter};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::Credential as CredentialRecord;
use serde::Deserialize;
use serde_json::Value;
use signify_acdc::credential::{Credential, CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use signify_acdc::revocation::RevocationEventBuilder;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::credentials::{
    CREDENTIAL_QUERY_SEGMENT, CREDENTIALS_SEGMENT, CredentialFilter, DEFAULT_CREDENTIAL_LIMIT,
};
use signify_client::error::ClientError;
use signify_http::request::ResourcePath;
use signify_http::transport::Transport;
use signify_keys::manager::DerivationCost;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-credentials/v1.json");

const FIXED_STAMP: &str = "2023-11-14T22:13:20.123000+00:00";

const IDENTIFIER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const ISSUE_REGISTRY: &str = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const ISSUEE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const CREDENTIAL: &str = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo";
const CREDENTIAL_REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const ISSUANCE: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";

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
    mock_records: MockRecords,
    calls: Vec<Call>,
    renamed_by_agent: RenamedByAgent,
    issue_establishment_only: Refusal,
    revoke_without_registry: Refusal,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    boot_url: String,
    stamp: String,
    fixed_clock_ms: u64,
    agent_prefix: String,
    identifier: String,
    credential: String,
    registry: String,
    schema: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    class_members: Vec<String>,
    filter_interface: String,
    issue_result_interface: String,
    revoke_result_interface: String,
    list_path: String,
    list_filter_default: String,
    list_sort_default: String,
    list_limit_default: String,
    list_skip_default: String,
    list_body: String,
    get_path: String,
    get_headers: String,
    get_return: String,
    delete_path: String,
    delete_fetch: String,
    state_path: String,
    issue_est_only: String,
    issue_est_only_throw: String,
    issue_subject: String,
    issue_acdc: String,
    issue_iss: String,
    issue_anchor: String,
    issue_path: String,
    issue_body: String,
    revoke_credential_lookup: String,
    revoke_registry_lookup: String,
    revoke_rev: String,
    revoke_saidify: String,
    revoke_body: String,
    revoke_path: String,
    credential_schema: String,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct MockRecords {
    identifier: Value,
    establishment_only: Value,
    credential: Value,
    well_formed_credential: Value,
    registryless_credential: Value,
    shortfall: Shortfall,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Shortfall {
    identifier_record_missing: Vec<String>,
    credential_record_fields: Vec<String>,
    credential_schema_fields: Vec<String>,
    credential_record_missing: Vec<String>,
    credential_record_extra: Vec<String>,
    added_inception_stamp: String,
    credential_status_seal: Value,
    credential_status_seal_sequence_type: String,
    credential_status_schema_sequence_type: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    request: Option<RecordedRequest>,
    requests: usize,
    answer: Value,
    result: Value,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    body: Option<String>,
    accept: Option<String>,
    #[serde(default)]
    sxlt_opens_to: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RenamedByAgent {
    asked_for: String,
    answered_with: String,
    path: String,
    method: String,
    requests: usize,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Refusal {
    reference_error_message: String,
    requests_made: usize,
    note: String,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    unit_test_file: String,
    unit_test_assertions: UnitTestAssertions,
    unit_test_files_naming_credentials: Vec<String>,
    published_paths: Vec<String>,
    published_identifiers: Vec<String>,
    asserted_registry: String,
    asserted_revocation_credential: String,
    accessor_assertion: bool,
    usage_scan: Value,
    driven_paths: Vec<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct UnitTestAssertions {
    list_path: String,
    list_method: String,
    list_body: Value,
    get_path: String,
    get_method: String,
    issue_path: String,
    issue_method: String,
    issue_acdc_registry: String,
    issue_acdc_schema: String,
    issue_acdc_issuee: String,
    issue_acdc_lei: String,
    issue_iss_sequence: String,
    issue_iss_kind: String,
    issue_iss_registry: String,
    issue_iss_names_the_credential: bool,
    issue_ixn_kind: String,
    issue_ixn_names_the_issuer: bool,
    issue_ixn_prior_is_the_issuer: bool,
    issue_signature_prefix: String,
    issue_signature_length: usize,
    revoke_path: String,
    revoke_method: String,
    revoke_rev_sequence: String,
    revoke_rev_kind: String,
    revoke_rev_registry: String,
    revoke_rev_credential: String,
    revoke_ixn_kind: String,
    revoke_ixn_identifier: String,
    revoke_ixn_prior: String,
    revoke_signature_prefix: String,
    revoke_signature_length: usize,
    state_path: String,
    state_method: String,
    state_body: Option<String>,
    delete_path: String,
    delete_method: String,
    delete_body: Option<String>,
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

type SentRequest = (String, String, Option<String>, Option<String>);

fn sent(transport: &AgentTransport, index: usize) -> Result<SentRequest, Box<dyn Error>> {
    let recorded = transport.requests();
    let request = recorded.get(2 + index).ok_or("no endpoint request was sent")?;
    let path = request.resource();
    let body = request.body_text();
    let accept = request.header("accept").map(ToOwned::to_owned);
    Ok((path, request.method().to_owned(), body, accept))
}

fn sealing_keys() -> Result<(Encrypter, Decrypter), Box<dyn Error>> {
    let salt = Salt::from_qb64(&format!("0AA{PASSCODE}"), SecurityTier::Low)?;
    let signer = salt.derive_signer("", KeyTransferability::NonTransferable)?;
    Ok((
        Encrypter::from_verification_key(signer.verifier())?,
        Decrypter::from_signer(&signer),
    ))
}

fn mask_sealed(body: &str) -> Result<(String, Vec<String>), Box<dyn Error>> {
    let (_, decrypter) = sealing_keys()?;
    let mut masked = String::with_capacity(body.len());
    let mut opened = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(r#""sxlt":""#) {
        let (head, tail) = rest.split_at(start.saturating_add(r#""sxlt":""#.len()));
        masked.push_str(head);
        let end = tail.find('"').ok_or("an unterminated sealed salt")?;
        let (sealed, remainder) = tail.split_at(end);
        opened.push(
            decrypter
                .decrypt_salt(&Ciphertext::from_qb64(sealed)?, SecurityTier::Low)?
                .expose_qb64()?
                .to_string(),
        );
        masked.push_str("<SXLT>");
        rest = remainder;
    }
    masked.push_str(rest);
    Ok((masked, opened))
}

fn identifier_record(record: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut document = record.clone();
    let (encrypter, _) = sealing_keys()?;
    reseal_in_place(&mut document, &encrypter)?;
    Ok(serde_json::to_vec(&document)?)
}

fn reseal_in_place(document: &mut Value, encrypter: &Encrypter) -> Result<(), Box<dyn Error>> {
    match document {
        Value::Object(fields) => {
            if let Some(Value::String(opens_to)) = fields.get("sxlt_opens_to").cloned() {
                let sealed = encrypter
                    .encrypt_salt(&Salt::from_qb64(&opens_to, SecurityTier::Low)?)?
                    .qb64()?;
                fields.remove("sxlt_opens_to");
                fields.insert("sxlt".to_owned(), Value::String(sealed));
            }
            for value in fields.values_mut() {
                reseal_in_place(value, encrypter)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                reseal_in_place(item, encrypter)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn pinned_credential(stamp: &str) -> Result<Credential, Box<dyn Error>> {
    let attributes = CredentialAttributes::new(stamp.parse()?)
        .issuee(&IdentifierPrefix::from_qb64(ISSUEE)?)?
        .text("LEI", "1234")?
        .timestamp()?;
    Ok(CredentialBuilder::new(
        IdentifierPrefix::from_qb64(IDENTIFIER)?,
        RegistryIdentifier::from_qb64(ISSUE_REGISTRY)?,
        Said::from_qb64(SCHEMA)?,
        attributes,
    )
    .build()?)
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
            .any(|source| source.ends_with("credentialing.ts"))
    );
    assert!(fixture.sources.iter().any(|source| source.ends_with("test-utils.ts")));
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.stamp, FIXED_STAMP);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert_eq!(fixture.provenance.identifier, IDENTIFIER);
    assert_eq!(fixture.provenance.credential, CREDENTIAL);
    assert_eq!(fixture.provenance.registry, CREDENTIAL_REGISTRY);
    assert_eq!(fixture.provenance.schema, SCHEMA);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));
    assert_ne!(fixture.mock_records.note, "");

    assert_eq!(fixture.calls.len(), 16);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
    }
    Ok(())
}

#[test]
fn every_value_the_pinned_unit_test_asserts_is_recorded() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;
    assert_eq!(pinned.unit_test_file, "test/app/credentialing.test.ts");
    assert_eq!(
        pinned.unit_test_files_naming_credentials,
        ["test/app/clienting.test.ts", "test/app/credentialing.test.ts"]
    );
    assert!(pinned.accessor_assertion);
    assert_ne!(pinned.note, "");
    assert!(pinned.usage_scan.is_object());

    let asserted = &pinned.unit_test_assertions;
    assert_ne!(asserted.note, "");
    assert_eq!(asserted.list_path, "/credentials/query");
    assert_eq!(asserted.list_method, "POST");
    assert_eq!(asserted.get_path, format!("/credentials/{SCHEMA}"));
    assert_eq!(asserted.get_method, "GET");
    assert_eq!(asserted.issue_path, "/identifiers/aid1/credentials");
    assert_eq!(asserted.issue_method, "POST");
    assert_eq!(
        asserted.revoke_path,
        format!("/identifiers/aid1/credentials/{IDENTIFIER}")
    );
    assert_eq!(asserted.revoke_method, "DELETE");
    assert_eq!(
        asserted.state_path,
        format!("/registries/{CREDENTIAL_REGISTRY}/{CREDENTIAL}")
    );
    assert_eq!(asserted.state_method, "GET");
    assert_eq!(asserted.delete_path, format!("/credentials/{CREDENTIAL}"));
    assert_eq!(asserted.delete_method, "DELETE");
    assert_eq!(asserted.state_body, None);
    assert_eq!(asserted.delete_body, None);

    assert_eq!(asserted.issue_acdc_registry, ISSUE_REGISTRY);
    assert_eq!(asserted.issue_acdc_schema, SCHEMA);
    assert_eq!(asserted.issue_acdc_issuee, ISSUEE);
    assert_eq!(asserted.issue_acdc_lei, "1234");
    assert_eq!(asserted.issue_iss_sequence, "0");
    assert_eq!(asserted.issue_iss_kind, "iss");
    assert_eq!(asserted.issue_iss_registry, ISSUE_REGISTRY);
    assert!(asserted.issue_iss_names_the_credential);
    assert_eq!(asserted.issue_ixn_kind, "ixn");
    assert!(asserted.issue_ixn_names_the_issuer);
    assert!(asserted.issue_ixn_prior_is_the_issuer);
    assert_eq!(asserted.issue_signature_prefix, "AA");
    assert_eq!(asserted.issue_signature_length, 88);

    assert_eq!(asserted.revoke_rev_sequence, "1");
    assert_eq!(asserted.revoke_rev_kind, "rev");
    assert_eq!(asserted.revoke_rev_registry, CREDENTIAL_REGISTRY);
    assert_eq!(asserted.revoke_rev_registry, pinned.asserted_registry);
    assert_eq!(asserted.revoke_rev_credential, IDENTIFIER);
    assert_eq!(asserted.revoke_rev_credential, pinned.asserted_revocation_credential);
    assert_eq!(asserted.revoke_ixn_kind, "ixn");
    assert_eq!(asserted.revoke_ixn_identifier, IDENTIFIER);
    assert_eq!(asserted.revoke_ixn_prior, IDENTIFIER);
    assert_eq!(asserted.revoke_signature_prefix, "AA");
    assert_eq!(asserted.revoke_signature_length, 88);

    assert_ne!(pinned.published_paths, [] as [String; 0]);
    assert_ne!(pinned.published_identifiers, [] as [String; 0]);
    assert!(pinned.driven_paths.iter().any(|path| path == "/credentials/query"));
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    for member in ["list", "get", "delete", "state", "issue", "revoke"] {
        assert!(
            declarations.class_members.iter().any(|name| name == member),
            "the class no longer declares {member}"
        );
    }

    assert!(declarations.list_path.contains("/credentials/query"));
    assert!(declarations.list_filter_default.contains("kargs.filter === undefined"));
    assert!(declarations.list_sort_default.contains("kargs.sort === undefined"));
    assert!(declarations.list_limit_default.contains("? 25 :"));
    assert!(declarations.list_skip_default.contains("? 0 :"));
    for label in ["filter:", "sort:", "skip:", "limit:"] {
        assert!(declarations.list_body.contains(label), "the body lacks {label}");
    }
    assert!(declarations.filter_interface.contains("skip?: number"));

    for raw in [
        &declarations.get_path,
        &declarations.delete_path,
        &declarations.state_path,
        &declarations.issue_path,
        &declarations.revoke_path,
    ] {
        assert!(!raw.contains("encodeURIComponent"), "{raw} unexpectedly encodes");
    }
    assert!(declarations.get_path.contains("${said}"));
    assert!(declarations.state_path.contains("${ri}"));
    assert!(declarations.state_path.contains("${said}"));
    assert!(declarations.issue_path.contains("${hab.name}"));
    assert!(declarations.revoke_path.contains("${name}"));

    assert!(declarations.get_headers.contains("application/json+cesr"));
    assert!(declarations.get_return.contains("res.text()"));
    assert!(declarations.get_return.contains("res.json()"));
    assert!(declarations.delete_fetch.contains("method"));

    assert!(declarations.issue_subject.contains("Saider.saidify"));
    assert!(declarations.issue_acdc.contains("args.i ?? hab.prefix"));
    assert!(declarations.issue_iss.contains("Ilks.iss"));
    assert!(declarations.issue_anchor.contains("interact"));
    for label in ["acdc:", "iss:", "ixn:", "sigs,"] {
        assert!(declarations.issue_body.contains(label), "the issue body lacks {label}");
    }
    assert!(declarations.issue_est_only.contains("'EO'"));
    assert!(
        declarations
            .issue_est_only_throw
            .contains("Establishment only not implemented")
    );

    assert!(declarations.revoke_credential_lookup.contains("this.get(said)"));
    assert!(declarations.revoke_registry_lookup.contains("cred.sad.ri"));
    assert!(declarations.revoke_registry_lookup.contains("cred.sad.rd"));
    assert!(declarations.revoke_rev.contains(r"s: '1'"));
    assert!(declarations.revoke_rev.contains("cred.status.d"));
    assert!(declarations.revoke_saidify.contains("Saider.saidify"));
    for label in ["rev:", "ixn:", "sigs:"] {
        assert!(
            declarations.revoke_body.contains(label),
            "the revoke body lacks {label}"
        );
    }

    assert!(declarations.issue_result_interface.contains("acdc: Serder"));
    assert!(declarations.revoke_result_interface.contains("rev: Serder"));
    assert!(declarations.credential_schema.contains("issatc"));
    assert!(declarations.notes.is_object());
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 10);
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

// --- The reads ---
#[test]
fn an_unfiltered_listing_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list_default")?;

    let (client, transport) = connected(&[b"[]"])?;
    let listed = block_on(client.credentials().list(&CredentialFilter::new()))?;
    let (path, method, body, _) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, "/credentials/query");
    assert_eq!(method, recorded.method);
    assert_eq!(method, "POST");
    assert_eq!(body.as_deref(), recorded.body.as_deref());
    assert_eq!(body.as_deref(), Some(r#"{"filter":{},"sort":[],"skip":0,"limit":25}"#));
    assert_eq!(listed, [] as [CredentialRecord; 0]);
    assert_eq!(DEFAULT_CREDENTIAL_LIMIT, 25);
    Ok(())
}

#[test]
fn the_pinned_filter_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list_pinned_filter")?;

    let mut equality = Sad::new();
    equality.insert("$eq", ISSUE_REGISTRY)?;
    let mut clause = Sad::new();
    clause.insert("-i", SadValue::Map(equality))?;
    let mut sort = Sad::new();
    sort.insert("-s", SadValue::integer(1)?)?;
    let filter = CredentialFilter::new()
        .with_filter(clause)
        .with_sort(vec![sort])
        .with_skip(5)
        .with_limit(25);

    let (client, transport) = connected(&[b"[]"])?;
    let _ = block_on(client.credentials().list(&filter))?;
    let (path, method, body, _) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_eq!(body.as_deref(), recorded.body.as_deref());

    let asserted = &fixture.pinned_confirmations.unit_test_assertions.list_body;
    let sent_document: Value = serde_json::from_str(&body.unwrap_or_default())?;
    assert_eq!(sent_document, *asserted);
    Ok(())
}

#[test]
fn a_partial_filter_still_sends_the_fields_it_was_not_given() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list_partial")?;

    let (client, transport) = connected(&[b"[]"])?;
    let _ = block_on(client.credentials().list(&CredentialFilter::new().with_limit(1)))?;
    let (_, _, body, _) = sent(&transport, 0)?;
    assert_eq!(body.as_deref(), recorded.body.as_deref());
    assert_eq!(body.as_deref(), Some(r#"{"filter":{},"sort":[],"skip":0,"limit":1}"#));
    Ok(())
}

#[test]
fn a_json_read_addresses_the_recorded_path_and_decodes_its_answer() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "get_json")?;
    let answer = serde_json::to_vec(&fixture.mock_records.well_formed_credential)?;

    let (client, transport) = connected(&[&answer])?;
    let credential = block_on(client.credentials().get(&Said::from_qb64(SCHEMA)?))?;
    let (path, method, body, accept) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, format!("/credentials/{SCHEMA}"));
    assert_eq!(method, "GET");
    assert_eq!(body, None);
    assert_eq!(accept.as_deref(), recorded.accept.as_deref());
    assert_eq!(accept.as_deref(), Some("application/json"));

    assert_eq!(credential.sad.digest, CREDENTIAL);
    assert_eq!(credential.sad.registry.as_deref(), Some(CREDENTIAL_REGISTRY));
    assert_eq!(credential.status.credential(), CREDENTIAL);
    assert!(!credential.status.is_revoked());
    Ok(())
}

#[test]
fn a_cesr_read_declares_the_other_media_type_and_returns_text() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "get_cesr")?;
    let answer = serde_json::to_vec(&fixture.mock_records.well_formed_credential)?;

    let (client, transport) = connected(&[&answer])?;
    let stream = block_on(client.credentials().get_cesr(&Said::from_qb64(SCHEMA)?))?;
    let (path, method, _, accept) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, "GET");
    assert_eq!(accept.as_deref(), recorded.accept.as_deref());
    assert_eq!(accept.as_deref(), Some("application/json+cesr"));
    assert_eq!(recorded.path, request_of(&fixture, "get_json")?.path);
    assert_eq!(stream, String::from_utf8(answer)?);
    Ok(())
}

#[test]
fn a_cesr_answer_that_is_not_utf8_is_refused_rather_than_repaired() -> Result<(), Box<dyn Error>> {
    let (client, _) = connected(&[b"-VAS\xff\xfeGAB"])?;
    let outcome = block_on(client.credentials().get_cesr(&Said::from_qb64(CREDENTIAL)?));
    assert!(
        matches!(outcome, Err(ClientError::Decode { .. })),
        "a non-UTF-8 stream was accepted: {outcome:?}"
    );
    Ok(())
}

#[test]
fn the_references_own_mock_credential_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let shortfall = &fixture.mock_records.shortfall;
    assert_eq!(shortfall.credential_schema_fields.len(), 11);
    assert_eq!(shortfall.credential_record_missing.len(), 7);
    assert_eq!(shortfall.credential_record_extra, ["sadsigers", "sadcigars"]);
    assert_eq!(shortfall.credential_record_fields.len(), 6);
    assert_ne!(shortfall.note, "");
    assert_eq!(shortfall.credential_status_seal_sequence_type, "number");
    assert_eq!(shortfall.credential_status_schema_sequence_type, "string");
    assert!(shortfall.credential_status_seal.get("s").is_some_and(Value::is_number));

    assert_eq!(shortfall.identifier_record_missing, ["icp_dt"]);
    assert_eq!(
        fixture.mock_records.identifier.get("icp_dt").and_then(Value::as_str),
        Some(shortfall.added_inception_stamp.as_str())
    );

    let recorded = call(&fixture, "get_mock_credential")?;
    assert_eq!(recorded.error, None);
    assert!(recorded.result.is_object());

    let answer = serde_json::to_vec(&fixture.mock_records.credential)?;
    assert!(
        serde_json::from_slice::<CredentialRecord>(&answer).is_err(),
        "the reference's own mock decoded as a credential record"
    );

    let (client, _) = connected(&[&answer])?;
    let outcome = block_on(client.credentials().get(&Said::from_qb64(CREDENTIAL)?));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "the mock credential was accepted: {outcome:?}"
    );
    Ok(())
}

#[test]
fn a_said_can_never_reshape_a_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(
        request_of(&fixture, "get_said_needing_encoding")?.path,
        "/credentials/E/../identifiers?x=1#y"
    );
    assert_eq!(
        request_of(&fixture, "state_names_needing_encoding")?.path,
        "/registries/a/b/c/d"
    );
    assert_eq!(
        request_of(&fixture, "revoke_said_needing_encoding")?.path,
        "/identifiers/a/b/credentials/c/d"
    );

    for hostile in ["E/../identifiers?x=1#y", "c/d", "a/b"] {
        assert!(Said::from_qb64(hostile).is_err(), "{hostile:?} parsed as a SAID");
        assert!(
            RegistryIdentifier::from_qb64(hostile).is_err(),
            "{hostile:?} parsed as a registry"
        );
    }
    Ok(())
}

#[test]
fn an_unqualified_said_becomes_a_credential_identifier_upstream() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "revoke_said_needing_encoding")?;
    let body = recorded.body.clone().unwrap_or_default();
    assert!(body.contains(r#""i":"c/d""#), "the recorded body no longer carries it");
    assert!(Said::from_qb64("c/d").is_err());
    Ok(())
}

#[test]
fn a_delete_addresses_the_recorded_path_and_sends_no_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "delete")?;
    assert_eq!(recorded.body, None);

    let (client, transport) = connected(&[b"{}"])?;
    block_on(client.credentials().delete(&Said::from_qb64(CREDENTIAL)?))?;
    let (path, method, body, _) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, format!("/credentials/{CREDENTIAL}"));
    assert_eq!(method, "DELETE");
    assert_eq!(body, None);
    Ok(())
}

#[test]
fn a_state_read_addresses_the_recorded_path_and_decodes_its_answer() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "state")?;
    let answer = serde_json::to_vec(&call(&fixture, "state")?.answer)?;

    let (client, transport) = connected(&[&answer])?;
    let state = block_on(client.credentials().state(
        &RegistryIdentifier::from_qb64(CREDENTIAL_REGISTRY)?,
        &Said::from_qb64(CREDENTIAL)?,
    ))?;
    let (path, method, body, _) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, format!("/registries/{CREDENTIAL_REGISTRY}/{CREDENTIAL}"));
    assert_eq!(method, "GET");
    assert_eq!(body, None);

    assert_eq!(state.credential(), CREDENTIAL);
    assert_eq!(state.status(), "iss");
    assert!(!state.is_revoked());
    Ok(())
}

// --- The writes ---
#[test]
fn the_pinned_issuance_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "issue_pinned")?;
    let record = identifier_record(&fixture.mock_records.identifier)?;
    let operation = serde_json::to_vec(&call(&fixture, "issue_pinned")?.answer)?;

    let (client, transport) = connected(&[&record, &operation])?;
    let issued = block_on(
        client
            .credentials()
            .issue("aid1", pinned_credential(&fixture.provenance.stamp)?),
    )?;

    assert_eq!(call(&fixture, "issue_pinned")?.requests, 2);
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/aid1");
    let (path, method, body, _) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, "/identifiers/aid1/credentials");
    assert_eq!(method, "POST");

    let (masked, opened) = mask_sealed(body.as_deref().ok_or("no body was sent")?)?;
    assert_eq!(masked, recorded.body.clone().unwrap_or_default());
    assert_eq!(opened, recorded.sxlt_opens_to);

    let result = &call(&fixture, "issue_pinned")?.result;
    let expected = |label: &str| result.get(label).and_then(Value::as_str).unwrap_or_default().to_owned();
    assert_eq!(
        core::str::from_utf8(issued.artifacts.credential.raw())?,
        expected("acdc_raw")
    );
    assert_eq!(
        core::str::from_utf8(issued.artifacts.issuance.raw())?,
        expected("iss_raw")
    );
    assert_eq!(
        core::str::from_utf8(issued.artifacts.anchor.event.raw())?,
        expected("anc_raw")
    );
    assert_eq!(issued.artifacts.credential.said().qb64()?, expected("acdc_said"));
    assert_eq!(
        issued.artifacts.credential.attributes_said().qb64()?,
        expected("attributes_said")
    );
    assert_eq!(issued.artifacts.issuance.said().qb64()?, expected("iss_said"));
    assert_eq!(issued.artifacts.anchor.event.said().qb64()?, expected("anc_said"));

    let asserted = &fixture.pinned_confirmations.unit_test_assertions;
    let document: Value = serde_json::from_str(&masked)?;
    let field = |block: &str, label: &str| {
        document
            .get(block)
            .and_then(|value| value.get(label))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(field("acdc", "ri"), asserted.issue_acdc_registry);
    assert_eq!(field("acdc", "s"), asserted.issue_acdc_schema);
    assert_eq!(field("iss", "s"), asserted.issue_iss_sequence);
    assert_eq!(field("iss", "t"), asserted.issue_iss_kind);
    assert_eq!(field("iss", "ri"), asserted.issue_iss_registry);
    assert_eq!(field("iss", "i"), field("acdc", "d"));
    assert_eq!(field("ixn", "t"), asserted.issue_ixn_kind);
    assert_eq!(field("ixn", "i"), field("acdc", "i"));
    assert_eq!(field("ixn", "p"), field("acdc", "i"));

    let signature = document
        .get("sigs")
        .and_then(|sigs| sigs.get(0))
        .and_then(Value::as_str)
        .ok_or("no signature was sent")?;
    assert!(signature.starts_with(&asserted.issue_signature_prefix));
    assert_eq!(signature.len(), asserted.issue_signature_length);
    Ok(())
}

#[test]
fn the_issuance_answer_decodes_into_the_typed_operation() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = identifier_record(&fixture.mock_records.identifier)?;
    let operation = serde_json::to_vec(&call(&fixture, "issue_pinned")?.answer)?;

    let (client, _) = connected(&[&record, &operation])?;
    let issued = block_on(
        client
            .credentials()
            .issue("aid1", pinned_credential(&fixture.provenance.stamp)?),
    )?;
    let typed = issued.operation()?;
    assert_eq!(typed.name, format!("credential.{CREDENTIAL}"));
    let metadata = typed.metadata.ok_or("the operation carried no metadata")?;
    assert_eq!(metadata.ced.digest, CREDENTIAL);
    assert!(issued.operation().is_ok());
    assert_ne!(issued.response_body(), b"");
    Ok(())
}

#[test]
fn a_credential_naming_another_issuer_is_refused_before_anything_is_signed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "issue_with_explicit_issuer")?;
    let result = &recorded.result;
    let issuer = result
        .get("credential_issuer")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let anchoring = result
        .get("anchoring_identifier")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert_eq!(issuer, "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1");
    assert_eq!(anchoring, IDENTIFIER);
    assert_ne!(issuer, anchoring);
    assert_eq!(recorded.error, None);

    let attributes = CredentialAttributes::new(fixture.provenance.stamp.parse()?)
        .issuee(&IdentifierPrefix::from_qb64(ISSUEE)?)?
        .text("LEI", "1234")?
        .timestamp()?;
    let credential = CredentialBuilder::new(
        IdentifierPrefix::from_qb64(issuer)?,
        RegistryIdentifier::from_qb64(ISSUE_REGISTRY)?,
        Said::from_qb64(SCHEMA)?,
        attributes,
    )
    .build()?;

    let record = identifier_record(&fixture.mock_records.identifier)?;
    let (client, transport) = connected(&[&record])?;
    let outcome = block_on(client.credentials().issue("aid1", credential));
    assert!(
        matches!(outcome, Err(ClientError::CredentialIssuerMismatch { .. })),
        "a mismatched issuer was accepted: {outcome:?}"
    );
    assert_eq!(transport.requests().len(), 3);
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/aid1");
    Ok(())
}

#[test]
fn an_issuance_addresses_the_callers_alias_rather_than_the_agents() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let renamed = &fixture.renamed_by_agent;
    assert_eq!(renamed.asked_for, "aid1");
    assert_eq!(renamed.answered_with, "chosen-by-the-agent");
    assert_eq!(renamed.method, "POST");
    assert_eq!(renamed.requests, 2);
    assert_ne!(renamed.note, "");
    assert_eq!(renamed.path, "/identifiers/chosen-by-the-agent/credentials");

    let mut record: Value = fixture.mock_records.identifier.clone();
    if let Some(fields) = record.as_object_mut() {
        fields.insert("name".to_owned(), Value::String(renamed.answered_with.clone()));
    }
    let record = identifier_record(&record)?;
    let (client, transport) = connected(&[&record, b"{}"])?;
    let _ = block_on(
        client
            .credentials()
            .issue("aid1", pinned_credential(&fixture.provenance.stamp)?),
    )?;
    assert_eq!(sent(&transport, 1)?.0, "/identifiers/aid1/credentials");
    Ok(())
}

#[test]
fn an_establishment_only_issuer_is_refused_before_anything_is_derived() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = &fixture.issue_establishment_only;
    assert_eq!(recorded.reference_error_message, "Establishment only not implemented");
    assert_eq!(recorded.requests_made, 1);
    assert_ne!(recorded.note, "");

    let record = identifier_record(&fixture.mock_records.establishment_only)?;
    let (client, transport) = connected(&[&record])?;
    let outcome = block_on(
        client
            .credentials()
            .issue("estonly", pinned_credential(&fixture.provenance.stamp)?),
    );
    assert!(
        matches!(outcome, Err(ClientError::EstablishmentOnlyIssuer { .. })),
        "an establishment-only issuer was not refused: {outcome:?}"
    );
    assert_eq!(transport.requests().len(), 3);
    Ok(())
}

#[test]
fn the_pinned_revocation_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "revoke_pinned")?;
    let record = identifier_record(&fixture.mock_records.identifier)?;
    let operation = serde_json::to_vec(&call(&fixture, "revoke_pinned")?.answer)?;

    let revocation = RevocationEventBuilder::new(
        Said::from_qb64(CREDENTIAL)?,
        RegistryIdentifier::from_qb64(CREDENTIAL_REGISTRY)?,
        Said::from_qb64(ISSUANCE)?,
        fixture.provenance.stamp.parse()?,
    )
    .build()?;

    let (client, transport) = connected(&[&record, &operation])?;
    let revoked = block_on(client.credentials().revoke("aid1", revocation))?;

    assert_eq!(call(&fixture, "revoke_pinned")?.requests, 3);
    assert_eq!(transport.requests().len(), 4);
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/aid1");

    let (path, method, body, _) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, format!("/identifiers/aid1/credentials/{CREDENTIAL}"));
    assert_eq!(method, "DELETE");

    let (masked, opened) = mask_sealed(body.as_deref().ok_or("no body was sent")?)?;
    assert_eq!(masked, recorded.body.clone().unwrap_or_default());
    assert_eq!(opened, recorded.sxlt_opens_to);

    let result = &call(&fixture, "revoke_pinned")?.result;
    let expected = |label: &str| result.get(label).and_then(Value::as_str).unwrap_or_default().to_owned();
    assert_eq!(
        core::str::from_utf8(revoked.artifacts.revocation.raw())?,
        expected("rev_raw")
    );
    assert_eq!(
        core::str::from_utf8(revoked.artifacts.anchor.event.raw())?,
        expected("anc_raw")
    );
    assert_eq!(revoked.artifacts.revocation.said().qb64()?, expected("rev_said"));
    assert_eq!(revoked.artifacts.anchor.event.said().qb64()?, expected("anc_said"));
    Ok(())
}

#[test]
fn the_revocation_the_pinned_unit_test_asserts_reproduces_field_for_field() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "revoke_unit_test_subject")?;
    let record = identifier_record(&fixture.mock_records.identifier)?;
    let asserted = &fixture.pinned_confirmations.unit_test_assertions;

    let revocation = RevocationEventBuilder::new(
        Said::from_qb64(IDENTIFIER)?,
        RegistryIdentifier::from_qb64(CREDENTIAL_REGISTRY)?,
        Said::from_qb64(ISSUANCE)?,
        fixture.provenance.stamp.parse()?,
    )
    .build()?;

    let (client, transport) = connected(&[&record, b"{}"])?;
    let _ = block_on(client.credentials().revoke("aid1", revocation))?;
    let (path, method, body, _) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, asserted.revoke_path);
    assert_eq!(method, asserted.revoke_method);

    let (masked, _) = mask_sealed(body.as_deref().ok_or("no body was sent")?)?;
    assert_eq!(masked, recorded.body.clone().unwrap_or_default());

    let document: Value = serde_json::from_str(&masked)?;
    let field = |block: &str, label: &str| {
        document
            .get(block)
            .and_then(|value| value.get(label))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(field("rev", "s"), asserted.revoke_rev_sequence);
    assert_eq!(field("rev", "t"), asserted.revoke_rev_kind);
    assert_eq!(field("rev", "ri"), asserted.revoke_rev_registry);
    assert_eq!(field("rev", "i"), asserted.revoke_rev_credential);
    assert_eq!(field("ixn", "t"), asserted.revoke_ixn_kind);
    assert_eq!(field("ixn", "i"), asserted.revoke_ixn_identifier);
    assert_eq!(field("ixn", "p"), asserted.revoke_ixn_prior);

    let signature = document
        .get("sigs")
        .and_then(|sigs| sigs.get(0))
        .and_then(Value::as_str)
        .ok_or("no signature was sent")?;
    assert!(signature.starts_with(&asserted.revoke_signature_prefix));
    assert_eq!(signature.len(), asserted.revoke_signature_length);
    Ok(())
}

#[test]
fn a_caller_supplied_revocation_timestamp_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "revoke_with_datetime")?;
    let record = identifier_record(&fixture.mock_records.identifier)?;

    let revocation = RevocationEventBuilder::new(
        Said::from_qb64(CREDENTIAL)?,
        RegistryIdentifier::from_qb64(CREDENTIAL_REGISTRY)?,
        Said::from_qb64(ISSUANCE)?,
        "2023-08-23T15:16:07.553000+00:00".parse()?,
    )
    .build()?;

    let (client, transport) = connected(&[&record, b"{}"])?;
    let _ = block_on(client.credentials().revoke("aid1", revocation))?;
    let (path, _, body, _) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    let (masked, _) = mask_sealed(body.as_deref().ok_or("no body was sent")?)?;
    assert_eq!(masked, recorded.body.clone().unwrap_or_default());
    assert!(masked.contains(r#""dt":"2023-08-23T15:16:07.553000+00:00""#));
    Ok(())
}

#[test]
fn a_revocation_needs_no_credential_lookup_at_all() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = &fixture.revoke_without_registry;
    assert_eq!(
        recorded.reference_error_message,
        "Neither ri nor rd property found in credential"
    );
    assert_eq!(recorded.requests_made, 2);
    assert_ne!(recorded.note, "");
    let registryless = &fixture.mock_records.registryless_credential;
    assert!(
        registryless
            .get("sad")
            .and_then(Value::as_object)
            .is_some_and(|sad| !sad.contains_key("ri") && !sad.contains_key("rd"))
    );

    let record = identifier_record(&fixture.mock_records.identifier)?;
    let revocation = RevocationEventBuilder::new(
        Said::from_qb64(CREDENTIAL)?,
        RegistryIdentifier::from_qb64(CREDENTIAL_REGISTRY)?,
        Said::from_qb64(ISSUANCE)?,
        fixture.provenance.stamp.parse()?,
    )
    .build()?;
    let (client, transport) = connected(&[&record, b"{}"])?;
    let revoked = block_on(client.credentials().revoke("aid1", revocation))?;
    assert_eq!(revoked.artifacts.revocation.registry().qb64()?, CREDENTIAL_REGISTRY);
    assert_eq!(transport.requests().len(), 4);
    Ok(())
}

#[test]
fn a_revocation_answer_decodes_as_an_untyped_operation() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = identifier_record(&fixture.mock_records.identifier)?;
    let operation = serde_json::to_vec(&call(&fixture, "revoke_pinned")?.answer)?;

    let revocation = RevocationEventBuilder::new(
        Said::from_qb64(CREDENTIAL)?,
        RegistryIdentifier::from_qb64(CREDENTIAL_REGISTRY)?,
        Said::from_qb64(ISSUANCE)?,
        fixture.provenance.stamp.parse()?,
    )
    .build()?;
    let (client, _) = connected(&[&record, &operation])?;
    let revoked = block_on(client.credentials().revoke("aid1", revocation))?;

    let untyped = revoked.operation()?;
    assert_eq!(untyped.name, format!("done.{CREDENTIAL}"));
    assert!(untyped.outcome.is_done());
    assert!(revoked.operation().is_ok());
    Ok(())
}

#[test]
fn an_establishment_only_identifier_cannot_revoke_either() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = identifier_record(&fixture.mock_records.establishment_only)?;
    let revocation = RevocationEventBuilder::new(
        Said::from_qb64(CREDENTIAL)?,
        RegistryIdentifier::from_qb64(CREDENTIAL_REGISTRY)?,
        Said::from_qb64(ISSUANCE)?,
        fixture.provenance.stamp.parse()?,
    )
    .build()?;
    let (client, transport) = connected(&[&record])?;
    let outcome = block_on(client.credentials().revoke("estonly", revocation));
    assert!(
        matches!(outcome, Err(ClientError::EstablishmentOnlyIssuer { .. })),
        "an establishment-only identifier revoked: {outcome:?}"
    );
    assert_eq!(transport.requests().len(), 3);
    Ok(())
}

// --- Paths that carry no representable hostile input ---
#[test]
fn an_alias_can_never_leave_its_own_path_segment() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = identifier_record(&fixture.mock_records.identifier)?;
    let (client, transport) = connected(&[&record, b"{}"])?;
    let _ = block_on(
        client
            .credentials()
            .issue("a/b", pinned_credential(&fixture.provenance.stamp)?),
    )?;
    assert_eq!(sent(&transport, 1)?.0, "/identifiers/a%2Fb/credentials");

    let listing = ResourcePath::builder()
        .segment(CREDENTIALS_SEGMENT)
        .segment(CREDENTIAL_QUERY_SEGMENT)
        .build()?;
    assert_eq!(listing.as_str(), "/credentials/query");
    Ok(())
}
