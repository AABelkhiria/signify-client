//! Exact registry-endpoint vectors recorded from the pinned reference's own `Registries`.
//!
//! The pinned `vcp`/`ixn` pair recorded verbatim and its input proven unrepresentable; parity driven instead.

mod support;

use std::error::Error;
use std::sync::Arc;

use crate::support::{ADMIN, AGENT, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on, clock};
use keri_cesr::crypto::cipher::{Ciphertext, Decrypter, Encrypter};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::verifier::KeyTransferability;
use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::registries::{
    CreateRegistryRequest, NO_BACKERS_TRAIT, REGISTRIES_SEGMENT, RegistryBacking,
};
use signify_client::error::ClientError;
use signify_http::request::ResourcePath;
use signify_http::transport::Transport;
use signify_keri::event::ConfigurationTrait;
use signify_keri::manager::DerivationCost;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::registry::RegistryInceptionBuilder;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-registries/v1.json");

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
    identifier_records: IdentifierRecords,
    calls: Vec<Call>,
    generated_nonce_shape: GeneratedNonceShape,
    establishment_only: EstablishmentOnly,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    boot_url: String,
    nonce: String,
    backers: Vec<String>,
    fixed_clock_ms: u64,
    agent_prefix: String,
    identifier: String,
    establishment_only_identifier: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    list_path: String,
    create_arguments: String,
    create_defaults: String,
    create_no_backers: String,
    create_est_only: String,
    create_est_only_throw: String,
    create_incept: String,
    create_anchor: String,
    from_events_path: String,
    from_events_body: String,
    from_events_algorithm: String,
    rename_path: String,
    rename_body: String,
    registry_result_members: Vec<String>,
    registry_result_op: String,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct IdentifierRecords {
    ordinary: Value,
    establishment_only: Value,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    request: Option<RecordedRequest>,
    requests: usize,
    result: Value,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    body: Option<String>,
    #[serde(default)]
    sxlt_opens_to: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GeneratedNonceShape {
    path: String,
    method: String,
    body_fields: Vec<String>,
    vcp_fields: Vec<String>,
    nonce_code: String,
    nonce_length: usize,
    requests: usize,
    regser_said_is_vcp_prefix: bool,
    note: String,
}

#[derive(Debug, Deserialize)]
struct EstablishmentOnly {
    identifier_configuration: Vec<String>,
    reference_error_message: String,
    requests_made: usize,
    note: String,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    unit_test_file: String,
    unit_test_files_naming_registries: Vec<String>,
    published_events: Vec<String>,
    published_paths: Vec<String>,
    published_refusal: Vec<String>,
    issuer_prefix: String,
    nonce: String,
    driven_paths: Vec<String>,
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

fn sent(transport: &AgentTransport, index: usize) -> Result<(String, String, Option<String>), Box<dyn Error>> {
    let endpoint = transport.endpoint_requests()?;
    let request = endpoint.get(index).ok_or("no endpoint request was sent")?;
    Ok((request.resource(), request.method().to_owned(), request.body_text()))
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
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert_eq!(fixture.provenance.backers.len(), 3);
    assert_ne!(fixture.provenance.identifier, "");
    assert_ne!(fixture.provenance.establishment_only_identifier, "");
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));
    assert_ne!(fixture.identifier_records.note, "");

    assert_eq!(fixture.calls.len(), 6);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
    }
    Ok(())
}

#[test]
fn the_pinned_unit_tests_two_vectors_are_recorded_and_their_input_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;
    assert_eq!(pinned.unit_test_file, "test/app/registry.test.ts");
    assert_eq!(
        pinned.unit_test_files_naming_registries,
        ["test/app/clienting.test.ts", "test/app/registry.test.ts"]
    );
    assert_ne!(pinned.note, "");

    assert_eq!(pinned.published_events.len(), 2);
    let inception = pinned.published_events.first().map(String::as_str).unwrap_or_default();
    let anchor = pinned.published_events.get(1).map(String::as_str).unwrap_or_default();
    assert!(inception.contains(r#""t":"vcp""#));
    assert!(inception.contains(r#""c":["NB"]"#));
    assert!(anchor.contains(r#""t":"ixn""#));
    let registry = "EMppKX_JxXBuL_xE3A_a6lOcseYwaB7jAvZ0YFdgecXX";
    assert_eq!(inception.matches(registry).count(), 2);
    assert_eq!(anchor.matches(registry).count(), 2);

    assert_eq!(pinned.issuer_prefix, "hab prefix");
    assert!(
        IdentifierPrefix::from_qb64(&pinned.issuer_prefix).is_err(),
        "the pinned issuer is unexpectedly a valid prefix"
    );
    assert!(inception.contains(&format!(r#""ii":"{}""#, pinned.issuer_prefix)));
    assert!(anchor.contains(&format!(r#""i":"{}""#, pinned.issuer_prefix)));

    assert_eq!(pinned.nonce, "");
    let issuer = IdentifierPrefix::from_qb64(&fixture.provenance.identifier)?;
    let empty_nonce = RegistryInceptionBuilder::new(issuer, pinned.nonce.clone())
        .configuration(vec![ConfigurationTrait::NoBackers])
        .build()?;
    let rendered = String::from_utf8(empty_nonce.raw().to_vec())?;
    assert!(
        rendered.ends_with(r#","n":""}"#),
        "an empty nonce was not written: {rendered}"
    );

    assert_eq!(pinned.published_refusal, ["establishment only not implemented"]);
    Ok(())
}

#[test]
fn the_pinned_unit_test_publishes_the_unencoded_path_itself() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(
        fixture.pinned_confirmations.published_paths,
        ["/identifiers/a name/registries"]
    );
    let encoded = ResourcePath::builder()
        .segment("identifiers")
        .segment("a name")
        .segment(REGISTRIES_SEGMENT)
        .build()?;
    assert_eq!(encoded.as_str(), "/identifiers/a%20name/registries");
    assert!(
        fixture
            .pinned_confirmations
            .driven_paths
            .iter()
            .any(|path| path.ends_with("/registries"))
    );
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    assert!(declarations.list_path.contains(REGISTRIES_SEGMENT));
    for raw in [
        &declarations.list_path,
        &declarations.from_events_path,
        &declarations.rename_path,
    ] {
        assert!(!raw.contains("encodeURIComponent"), "{raw} unexpectedly encodes");
        assert!(raw.contains("/identifiers/"));
    }
    assert!(declarations.rename_path.contains("${registryName}"));

    assert!(declarations.create_defaults.contains("noBackers = true"));
    assert!(declarations.create_no_backers.contains("NoBackers"));
    assert!(declarations.create_arguments.contains("baks?: string[]"));
    assert!(declarations.create_arguments.contains("nonce?: string"));

    assert!(declarations.create_est_only.contains("'EO'"));
    assert!(
        declarations
            .create_est_only_throw
            .contains("establishment only not implemented")
    );

    assert!(declarations.create_incept.contains("vdr.incept"));
    assert!(declarations.create_anchor.contains("regser.pre"));

    for label in ["name:", "vcp:", "ixn:", "sigs:"] {
        assert!(declarations.from_events_body.contains(label), "body lacks {label}");
    }
    assert!(declarations.from_events_algorithm.contains("keeper.params()"));
    assert!(declarations.rename_body.contains("name: newName"));

    assert!(declarations.registry_result_members.iter().any(|member| member == "op"));
    assert!(declarations.registry_result_op.contains("await this.promise"));
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
    assert_eq!(quirks.len(), 6);
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

// --- The calls ---
#[test]
fn a_listing_addresses_the_recorded_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list")?;
    let answer = serde_json::to_vec(&call(&fixture, "list")?.result)?;

    let (client, transport) = connected(&[&answer])?;
    let registries = block_on(client.registries().list("issuer"))?;
    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, "/identifiers/issuer/registries");
    assert_eq!(method, "GET");
    assert_eq!(body, None);

    assert_eq!(registries.len(), 1);
    assert_eq!(registries.first().map(|registry| registry.name.as_str()), Some("vLEI"));
    Ok(())
}

#[test]
fn an_alias_can_never_leave_its_own_path_segment() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(
        request_of(&fixture, "list_alias_needing_encoding")?.path,
        "/identifiers/a/b/registries"
    );
    assert_eq!(
        request_of(&fixture, "rename_names_needing_encoding")?.path,
        "/identifiers/a/b/registries/c/d"
    );

    let (client, transport) = connected(&[b"[]", b"{}"])?;
    let _ = block_on(client.registries().list("a/b"));
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/a%2Fb/registries");
    let _ = block_on(client.registries().rename("a/b", "c/d", "new"));
    assert_eq!(sent(&transport, 1)?.0, "/identifiers/a%2Fb/registries/c%2Fd");
    Ok(())
}

#[test]
fn a_default_creation_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "create_default")?;
    let record = identifier_record(&fixture.identifier_records.ordinary)?;

    let (client, transport) = connected(&[&record, b"{}"])?;
    let request = CreateRegistryRequest::new("issuer", "vLEI").with_nonce(&fixture.provenance.nonce);
    let created = block_on(client.registries().create(&request))?;

    assert_eq!(call(&fixture, "create_default")?.requests, 2);
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/issuer");
    let (path, method, body) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, "POST");

    let (masked, opened) = mask_sealed(body.as_deref().ok_or("no body was sent")?)?;
    assert_eq!(masked, recorded.body.clone().unwrap_or_default());
    assert_eq!(opened, recorded.sxlt_opens_to);

    let registry = created.inception.identifier().qb64()?;
    assert!(masked.contains(&format!(r#""i":"{registry}""#)));
    assert!(masked.contains(&format!(r#""c":["{NO_BACKERS_TRAIT}"]"#)));
    assert_eq!(created.signatures.len(), 1);
    Ok(())
}

#[test]
fn a_backed_creation_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "create_with_backers")?;
    let record = identifier_record(&fixture.identifier_records.ordinary)?;

    let (client, transport) = connected(&[&record, b"{}"])?;
    let request = CreateRegistryRequest::new("issuer", "backed")
        .with_backing(RegistryBacking::Backers {
            backers: fixture.provenance.backers.clone(),
            threshold: 2,
        })
        .with_nonce(&fixture.provenance.nonce);
    let _ = block_on(client.registries().create(&request))?;

    let (path, method, body) = sent(&transport, 1)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    let (masked, opened) = mask_sealed(body.as_deref().ok_or("no body was sent")?)?;
    assert_eq!(masked, recorded.body.clone().unwrap_or_default());
    assert_eq!(opened, recorded.sxlt_opens_to);

    assert!(masked.contains(r#""c":[]"#));
    assert!(masked.contains(r#""bt":"2""#));
    for backer in &fixture.provenance.backers {
        assert!(masked.contains(backer.as_str()), "the backer {backer} is missing");
    }
    Ok(())
}

#[test]
fn a_generated_nonce_has_the_recorded_shape() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let shape = &fixture.generated_nonce_shape;
    assert_eq!(shape.path, "/identifiers/issuer/registries");
    assert_eq!(shape.method, "POST");
    assert_eq!(shape.body_fields, ["name", "vcp", "ixn", "sigs", "salty"]);
    assert_eq!(shape.requests, 2);
    assert!(shape.regser_said_is_vcp_prefix);
    assert_eq!(shape.nonce_code, "A");
    assert_eq!(shape.nonce_length, 44);
    assert_ne!(shape.note, "");
    assert_eq!(shape.vcp_fields, ["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"]);

    let record = identifier_record(&fixture.identifier_records.ordinary)?;
    let (client, transport) = connected(&[&record, b"{}"])?;
    let created = block_on(
        client
            .registries()
            .create(&CreateRegistryRequest::new("issuer", "generated")),
    )?;

    let (_, _, body) = sent(&transport, 1)?;
    let document: Value = serde_json::from_str(&body.unwrap_or_default())?;
    let fields = document.as_object().ok_or("the body is not an object")?;
    assert_eq!(
        fields.keys().cloned().collect::<Vec<_>>().len(),
        shape.body_fields.len()
    );
    for label in &shape.body_fields {
        assert!(fields.contains_key(label), "the body lacks {label}");
    }

    let inception = document
        .get("vcp")
        .and_then(Value::as_object)
        .ok_or("the body carries no registry inception")?;
    assert_eq!(inception.len(), shape.vcp_fields.len());
    for label in &shape.vcp_fields {
        assert!(inception.contains_key(label), "the inception lacks {label}");
    }
    let nonce = inception
        .get("n")
        .and_then(Value::as_str)
        .ok_or("the registry inception carries no nonce")?;
    assert_eq!(nonce.len(), shape.nonce_length);
    assert!(nonce.starts_with(&shape.nonce_code));
    assert_eq!(
        document.get("vcp").and_then(|vcp| vcp.get("i")).and_then(Value::as_str),
        Some(created.inception.identifier().qb64()?.as_str())
    );
    Ok(())
}

#[test]
fn an_establishment_only_issuer_is_refused_before_anything_is_built() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = &fixture.establishment_only;
    assert_eq!(recorded.identifier_configuration, ["EO"]);
    assert_eq!(recorded.reference_error_message, "establishment only not implemented");
    assert_eq!(recorded.requests_made, 1);
    assert_ne!(recorded.note, "");

    let record = identifier_record(&fixture.identifier_records.establishment_only)?;
    let (client, transport) = connected(&[&record])?;
    let outcome = block_on(
        client
            .registries()
            .create(&CreateRegistryRequest::new("estonly", "nope").with_nonce(&fixture.provenance.nonce)),
    );
    assert!(
        matches!(outcome, Err(ClientError::EstablishmentOnlyIssuer { .. })),
        "an establishment-only issuer was not refused: {outcome:?}"
    );
    assert_eq!(transport.requests().len(), 3);
    assert_eq!(sent(&transport, 0)?.0, "/identifiers/estonly");
    Ok(())
}

#[test]
fn a_rename_reproduces_the_recorded_body() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "rename")?;
    let answer = serde_json::to_vec(&call(&fixture, "rename")?.result)?;

    let (client, transport) = connected(&[&answer])?;
    let registry = block_on(client.registries().rename("issuer", "vLEI", "renamed"))?;
    let (path, method, body) = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, "/identifiers/issuer/registries/vLEI");
    assert_eq!(method, "PUT");
    assert_eq!(body.as_deref(), Some(r#"{"name":"renamed"}"#));
    assert_eq!(body.as_deref(), recorded.body.as_deref());
    assert_eq!(registry.name, "vLEI");
    Ok(())
}

#[test]
fn a_creation_answer_decodes_into_the_typed_operation() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let answer = serde_json::to_vec(&call(&fixture, "create_default")?.result)?;
    let operation = serde_json::from_slice::<Value>(&answer);
    assert!(operation.is_ok());

    let record = identifier_record(&fixture.identifier_records.ordinary)?;
    let registry_operation = br#"{"name":"registry.EREG","metadata":{"pre":"EISS","depends":{"name":"witness.EISS.1","metadata":{"pre":"EISS","sn":1},"done":false},"anchor":{"pre":"EISS","sn":1,"d":"EANCHOR"}},"done":false}"#;
    let (client, _) = connected(&[&record, registry_operation])?;
    let created = block_on(
        client
            .registries()
            .create(&CreateRegistryRequest::new("issuer", "vLEI").with_nonce(&fixture.provenance.nonce)),
    )?;

    let operation = created.operation()?;
    assert_eq!(operation.name, "registry.EREG");
    let metadata = operation.metadata.ok_or("the operation carried no metadata")?;
    assert_eq!(metadata.pre, "EISS");
    assert_eq!(metadata.anchor.sn, 1);
    assert_eq!(metadata.depends.name, "witness.EISS.1");
    assert!(created.operation().is_ok());
    assert_ne!(created.response_body(), b"");
    Ok(())
}
