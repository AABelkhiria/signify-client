//! Exact configuration-endpoint vectors recorded from the pinned reference's own `Config`.
//!
//! One constant address across five recorded answers, and the one shape only this port refuses.

mod support;

use std::error::Error;
use std::sync::Arc;

use crate::support::{ADMIN, AGENT, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on, clock};
use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::config::CONFIG_SEGMENT;
use signify_client::error::ClientError;
use signify_http::transport::Transport;
use signify_keys::manager::DerivationCost;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-config/v1.json");

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
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    config_path: String,
    config_method: String,
    config_fetch: String,
    config_return: String,
    config_members: Vec<String>,
    agent_config_schema: String,
    agent_config_uses: Scan,
    config_accessor_uses: Scan,
    notes: Value,
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

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    published_paths: Vec<String>,
    driven_paths: Vec<String>,
    every_pinned_path_is_driven: bool,
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

fn sent(transport: &AgentTransport) -> Result<(String, String, Option<String>), Box<dyn Error>> {
    let endpoint = transport.endpoint_requests()?;
    let request = endpoint.first().ok_or("no endpoint request was sent")?;
    Ok((request.resource(), request.method().to_owned(), request.body_text()))
}

// --- Manifest and provenance ---
#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert_ne!(fixture.generated_on, "");
    assert!(fixture.sources.iter().any(|source| source.ends_with("coring.ts")));
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert_ne!(fixture.provenance.controller_prefix, "");
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 5);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
    }
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    assert_eq!(declarations.config_path, "path = `/config`");
    assert!(declarations.config_path.contains(CONFIG_SEGMENT));
    assert!(!declarations.config_path.contains("${"));
    assert_eq!(declarations.config_method, "method = 'GET'");
    assert!(declarations.config_fetch.contains("null"));

    assert_eq!(declarations.config_return, "await res.json()");

    assert_eq!(declarations.config_members, ["client", "<constructor>", "get"]);

    assert_eq!(declarations.agent_config_schema, "AgentConfig: { iurls?: string[]; };");
    assert_eq!(declarations.agent_config_uses.needle, "AgentConfig");
    assert_eq!(declarations.agent_config_uses.scanned_files, 117);
    assert!(
        declarations
            .agent_config_uses
            .files
            .iter()
            .any(|hit| hit.file.ends_with("keria-api-schema.ts") && hit.count == 1)
    );
    assert!(declarations.config_accessor_uses.total >= 1);
    assert!(declarations.notes.is_object());
    Ok(())
}

#[test]
fn the_one_pinned_path_is_produced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(fixture.pinned_confirmations.every_pinned_path_is_driven);
    assert_eq!(fixture.pinned_confirmations.published_paths, ["/config"]);
    assert_eq!(fixture.pinned_confirmations.driven_paths, ["/config"]);
    assert_ne!(fixture.pinned_confirmations.note, "");
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 4);
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

// --- The call ---
#[test]
fn a_configuration_read_addresses_the_recorded_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "config_with_introductions")?;
    let request = recorded.request.as_ref().ok_or("no recorded request")?;
    let answer = serde_json::to_vec(&recorded.answer)?;

    let (client, transport) = connected(&[&answer])?;
    let config = block_on(client.agent_config().get())?;

    let (path, method, body) = sent(&transport)?;
    assert_eq!(path, request.path);
    assert_eq!(path, "/config");
    assert_eq!(method, request.method);
    assert_eq!(method, "GET");
    assert_eq!(body, None);
    assert_eq!(request.body, None);

    assert_eq!(
        config.introduction_urls.as_ref().map(Vec::len),
        recorded.result.get("iurls").and_then(Value::as_array).map(Vec::len)
    );
    Ok(())
}

#[test]
fn every_recorded_answer_produces_the_same_request() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for entry in &fixture.calls {
        let request = entry.request.as_ref().ok_or("no recorded request")?;
        assert_eq!(request.path, "/config", "call {} addressed something else", entry.name);
        assert_eq!(request.method, "GET");
        assert_eq!(request.body, None);
    }
    Ok(())
}

#[test]
fn an_absent_list_and_an_empty_one_stay_distinguishable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    let absent = call(&fixture, "config_absent_field")?;
    assert_eq!(absent.result, serde_json::json!({}));
    let (client, _) = connected(&[&serde_json::to_vec(&absent.answer)?])?;
    let config = block_on(client.agent_config().get())?;
    assert_eq!(config.introduction_urls, None);

    let empty = call(&fixture, "config_empty_list")?;
    assert_eq!(empty.result, serde_json::json!({ "iurls": [] }));
    let (client, _) = connected(&[&serde_json::to_vec(&empty.answer)?])?;
    let config = block_on(client.agent_config().get())?;
    assert_eq!(config.introduction_urls, Some(Vec::new()));
    Ok(())
}

#[test]
fn an_undeclared_field_is_ignored_where_the_reference_keeps_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "config_unknown_fields")?;
    assert!(recorded.result.get("curls").is_some());
    assert!(recorded.result.get("unknown").is_some());

    let (client, _) = connected(&[&serde_json::to_vec(&recorded.answer)?])?;
    let config = block_on(client.agent_config().get())?;
    assert_eq!(config.introduction_urls, Some(Vec::new()));
    assert_eq!(serde_json::to_string(&config)?, r#"{"iurls":[]}"#);
    Ok(())
}

#[test]
fn an_answer_of_the_wrong_shape_is_refused_where_the_reference_casts_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "config_wrong_shape")?;
    assert_eq!(recorded.error, None);
    assert_eq!(recorded.result.get("iurls").and_then(Value::as_str), Some("not-a-list"));

    let (client, transport) = connected(&[&serde_json::to_vec(&recorded.answer)?])?;
    let outcome = block_on(client.agent_config().get());
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "a wrong-shaped configuration was not refused: {outcome:?}"
    );
    assert_eq!(sent(&transport)?.0, "/config");
    Ok(())
}
