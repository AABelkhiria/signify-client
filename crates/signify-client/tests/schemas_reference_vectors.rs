//! Exact schema-endpoint vectors recorded from the pinned reference's own `Schemas`.
//!
//! No unit test exercises either call, so the vectors are the two SAIDs a live deployment actually sees.

mod support;

use std::collections::BTreeMap;
use std::error::Error;

use crate::support::{ADMIN, AGENT, BOOT, FIXED_MILLIS, Harness, PASSCODE, SentRequest, block_on, connected, sent};
use keri_protocol::said::Said;
use keria_types::api::message::Schema;
use serde::Deserialize;
use serde_json::Value;
use signify_client::endpoint::schemas::SCHEMA_SEGMENT;
use signify_client::error::ClientError;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

const QVI: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const LEGAL_ENTITY: &str = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY";

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
    calls: Vec<Call>,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    boot_url: String,
    fixed_clock_ms: u64,
    agent_prefix: String,
    controller_prefix: String,
    qvi_schema_said: String,
    le_schema_said: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    get_path: String,
    get_method: String,
    list_path: String,
    list_method: String,
    get_return: String,
    class_members: Vec<String>,
    schema_type: String,
    files_naming_schemas: Vec<String>,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
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

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    files_naming_schemas: Vec<String>,
    assertions: BTreeMap<String, Vec<String>>,
    qvi_schema_said: String,
    le_schema_said: String,
    driven_paths: Vec<String>,
    note: String,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    support::fixture("client-schemas")
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

// --- A KERIA agent, answering exactly as the generator's mocked `fetch` did ---

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
    assert_ne!(fixture.provenance.controller_prefix, "");
    assert_eq!(fixture.provenance.qvi_schema_said, QVI);
    assert_eq!(fixture.provenance.le_schema_said, LEGAL_ENTITY);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 6);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
        let request = entry.request.as_ref().ok_or("a recorded call made no request")?;
        assert_eq!(request.body, None, "call {} sent a body", entry.name);
    }
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    assert_eq!(declarations.get_path, "path = `/schema/${said}`");
    assert_eq!(declarations.list_path, "path = `/schema`");
    assert!(declarations.get_path.contains(SCHEMA_SEGMENT));
    assert!(!declarations.get_path.contains("/schemas/"));
    assert!(!declarations.get_path.contains("encodeURIComponent"));
    assert_eq!(declarations.get_method, "method = 'GET'");
    assert_eq!(declarations.list_method, "method = 'GET'");

    assert_eq!(declarations.get_return, "await res.json()");
    assert_eq!(declarations.class_members, ["client", "<constructor>", "get", "list"]);

    for field in [
        "$id",
        "$schema",
        "credentialType",
        "properties",
        "additionalProperties",
        "required",
    ] {
        assert!(declarations.schema_type.contains(field), "the schema lacks {field}");
    }
    assert!(declarations.schema_type.contains("[key: string]: unknown"));
    assert!(declarations.notes.is_object());
    Ok(())
}

#[test]
fn the_pinned_tree_exercises_this_family_only_in_integration() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;
    assert_eq!(
        pinned.files_naming_schemas,
        [
            "src/keri/app/clienting.ts",
            "src/keri/app/credentialing.ts",
            "test-integration/credentials.test.ts",
            "test/app/clienting.test.ts",
        ]
    );
    assert_eq!(pinned.files_naming_schemas, fixture.declarations.files_naming_schemas);
    let unit = pinned
        .assertions
        .get("test/app/clienting.test.ts")
        .ok_or("no recorded unit-test assertions")?;
    assert_eq!(unit.len(), 1);
    assert!(unit.iter().any(|line| line.contains("instanceof Schemas")));

    let integration = pinned
        .assertions
        .get("test-integration/credentials.test.ts")
        .ok_or("no recorded integration assertions")?;
    assert_eq!(integration.len(), 6);
    assert!(integration.iter().any(|line| line.contains("schemas().list()")));
    assert!(integration.iter().any(|line| line.contains("$id, QVI_SCHEMA_SAID")));
    assert!(integration.iter().any(|line| line.contains("holderSchemas.length, 2")));
    assert_ne!(pinned.note, "");

    assert!(Said::from_qb64(&pinned.qvi_schema_said).is_ok());
    assert!(Said::from_qb64(&pinned.le_schema_said).is_ok());

    assert_eq!(
        pinned.driven_paths,
        [
            "/schema",
            "/schema/E/../schema?x=1#y",
            &format!("/schema/{QVI}"),
            &format!("/schema/{LEGAL_ENTITY}"),
        ]
        .map(ToString::to_string)
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
    assert_eq!(quirks.len(), 5);
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
fn both_recorded_reads_address_the_recorded_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, said) in [("get_qvi", QVI), ("get_legal_entity", LEGAL_ENTITY)] {
        let recorded = request_of(&fixture, name)?;
        let answer = serde_json::to_vec(&call(&fixture, name)?.result)?;

        let Harness { client, transport, .. } = connected(&[&answer])?;
        let schema = block_on(client.schemas().get(&Said::from_qb64(said)?))?;
        let SentRequest { path, method, body, .. } = sent(&transport, 0)?;
        assert_eq!(path, recorded.path);
        assert_eq!(path, format!("/schema/{said}"));
        assert_eq!(method, recorded.method);
        assert_eq!(method, "GET");
        assert_eq!(body, None);

        assert_eq!(schema.id, said);
        assert_ne!(schema.credential_type, "");
    }
    Ok(())
}

#[test]
fn a_listing_addresses_the_constant_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list")?;
    let answer = serde_json::to_vec(&call(&fixture, "list")?.result)?;

    let Harness { client, transport, .. } = connected(&[&answer])?;
    let schemas = block_on(client.schemas().list())?;
    let SentRequest { path, method, body, .. } = sent(&transport, 0)?;
    assert_eq!(path, recorded.path);
    assert_eq!(path, "/schema");
    assert_eq!(method, "GET");
    assert_eq!(body, None);
    assert_eq!(schemas.len(), 2);
    assert_eq!(schemas.first().map(|schema| schema.id.as_str()), Some(QVI));
    assert_eq!(schemas.get(1).map(|schema| schema.id.as_str()), Some(LEGAL_ENTITY));

    let empty = request_of(&fixture, "list_empty")?;
    assert_eq!(empty.path, recorded.path);
    let answer = serde_json::to_vec(&call(&fixture, "list_empty")?.result)?;
    let Harness { client, .. } = connected(&[&answer])?;
    assert_eq!(block_on(client.schemas().list())?, [] as [Schema; 0]);
    Ok(())
}

#[test]
fn a_wrong_shaped_answer_is_refused_where_the_reference_casts_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "get_wrong_shape")?;
    assert_eq!(recorded.error, None);
    assert_eq!(recorded.result.get("$id").and_then(Value::as_str), Some(QVI));
    assert_eq!(recorded.result.as_object().map(serde_json::Map::len), Some(1));

    let answer = serde_json::to_vec(&recorded.result)?;
    let Harness { client, transport, .. } = connected(&[&answer])?;
    let outcome = block_on(client.schemas().get(&Said::from_qb64(QVI)?));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "a schema missing nine required fields was not refused: {outcome:?}"
    );
    assert_eq!(sent(&transport, 0)?.path, format!("/schema/{QVI}"));
    Ok(())
}

#[test]
fn nothing_checks_the_schema_came_back_under_the_said_asked_for() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let answer = serde_json::to_vec(&call(&fixture, "get_legal_entity")?.result)?;
    let Harness { client, .. } = connected(&[&answer])?;
    let schema = block_on(client.schemas().get(&Said::from_qb64(QVI)?))?;
    assert_eq!(schema.id, LEGAL_ENTITY);
    assert_ne!(schema.id, QVI);
    assert!(
        fixture
            .pinned_confirmations
            .assertions
            .values()
            .flatten()
            .any(|line| line.contains("$id, QVI_SCHEMA_SAID"))
    );
    Ok(())
}
