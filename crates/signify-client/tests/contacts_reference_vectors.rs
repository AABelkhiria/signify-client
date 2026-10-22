//! Exact contact-endpoint vectors recorded from the pinned reference's own `Contacts`.
//!
//! All five paths and methods, both write bodies field for field, and that a delete carries no body.

mod support;

use core::time::Duration;
use std::error::Error;
use std::sync::Arc;
use std::time::SystemTime;

use crate::support::{ADMIN, AGENT, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadValue};
use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::contacts::{
    ALIAS_FIELD, CONTACTS_SEGMENT, ContactFilter, FILTER_FIELD_PARAMETER, FILTER_VALUE_PARAMETER, GROUP_PARAMETER,
};
use signify_client::error::ClientError;
use signify_http::retry::{Clock, TestClock};
use signify_http::transport::Transport;
use signify_keys::manager::DerivationCost;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/client-contacts/v1.json"));

const CONTACT: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const OTHER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

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
    contact_prefix: String,
    other_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    list_parameters: Vec<String>,
    list_group_guard: String,
    list_filter_guard: String,
    list_path: String,
    get_path: String,
    get_method: String,
    add_path: String,
    add_method: String,
    delete_path: String,
    delete_method: String,
    delete_fetch: String,
    update_path: String,
    update_method: String,
    get_return: String,
    class_members: Vec<String>,
    contact_info_interface: String,
    contact_type: String,
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
    body_is_undefined: bool,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    unit_test_assertions: Vec<String>,
    unit_test_paths: Vec<String>,
    unit_test_info: Value,
    unit_test_methods: Vec<String>,
    integration_helper_call: String,
    call_sites: Scan,
    driven_paths: Vec<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Scan {
    total: usize,
    scanned_files: usize,
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

fn answer_of(fixture: &Fixture, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(serde_json::to_vec(&call(fixture, name)?.result)?)
}

type Harness = (ConnectedClient, Arc<AgentTransport>);

fn connected(bodies: &[&[u8]]) -> Result<Harness, Box<dyn Error>> {
    let configuration = || {
        ClientConfig::new(ADMIN, PASSCODE)
            .and_then(|config| config.with_boot_url(BOOT))
            .map(|config| config.with_derivation_cost(DerivationCost::Ephemeral))
    };
    let clock: Arc<dyn Clock> = Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(FIXED_MILLIS),
    ));
    let probe = SignifyClient::new(
        configuration()?,
        AgentTransport::new(&[]) as Arc<dyn Transport>,
        Arc::clone(&clock),
    )?;
    let prefix = probe.controller().prefix().qb64()?;
    let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();

    let state = agent_state(&prefix, &inception);
    let mut answers: Vec<&[u8]> = vec![state.as_bytes(), b"{}"];
    answers.extend_from_slice(bodies);
    let transport = AgentTransport::new(&answers);

    let client = SignifyClient::new(
        configuration()?,
        Arc::clone(&transport) as Arc<dyn Transport>,
        Arc::clone(&clock),
    )?;
    Ok((block_on(client.connect())?, transport))
}

fn sent(transport: &AgentTransport) -> Result<(String, String, Option<String>), Box<dyn Error>> {
    let endpoint = transport.endpoint_requests()?;
    let request = endpoint.first().ok_or("no endpoint request was sent")?;
    Ok((request.resource(), request.method().to_owned(), request.body_text()))
}

fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
    Ok(IdentifierPrefix::from_qb64(text)?)
}

fn pinned_info() -> Result<Sad, Box<dyn Error>> {
    let mut info = Sad::new();
    info.insert("name", "John Doe".to_owned())?;
    info.insert("company", "My Company".to_owned())?;
    Ok(info)
}

// --- Manifest and provenance ---
#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert_ne!(fixture.generated_on, "");
    assert!(fixture.sources.iter().any(|source| source.ends_with("contacting.ts")));
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert_ne!(fixture.provenance.controller_prefix, "");
    assert_eq!(fixture.provenance.contact_prefix, CONTACT);
    assert_eq!(fixture.provenance.other_prefix, OTHER);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 16);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
        assert!(entry.request.is_some(), "call {} made no request", entry.name);
    }
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    assert_eq!(
        declarations.class_members,
        ["client", "<constructor>", "list", "get", "add", "delete", "update"]
    );

    assert_eq!(
        declarations.list_parameters,
        ["group?: string", "filterField?: string", "filterValue?: string"]
    );
    assert!(
        declarations
            .list_filter_guard
            .contains("filterField !== undefined && filterValue !== undefined")
    );
    assert!(declarations.list_group_guard.contains("group !== undefined"));
    assert!(declarations.list_filter_guard.contains(FILTER_FIELD_PARAMETER));
    assert!(declarations.list_filter_guard.contains(FILTER_VALUE_PARAMETER));
    assert!(declarations.list_group_guard.contains(GROUP_PARAMETER));

    assert_eq!(declarations.list_path, "path = `/contacts` + '?' + params.toString()");

    for path in [
        &declarations.get_path,
        &declarations.add_path,
        &declarations.delete_path,
        &declarations.update_path,
    ] {
        assert_eq!(*path, "path = `/contacts/` + pre");
        assert!(!path.contains("encodeURIComponent"));
    }
    assert!(declarations.get_path.contains(CONTACTS_SEGMENT));

    assert_eq!(declarations.get_method, "method = 'GET'");
    assert_eq!(declarations.add_method, "method = 'POST'");
    assert_eq!(declarations.update_method, "method = 'PUT'");
    assert_eq!(declarations.delete_method, "method = 'DELETE'");
    assert!(declarations.delete_fetch.contains("undefined"));

    assert_eq!(declarations.get_return, "await res.json()");
    assert!(declarations.contact_info_interface.contains("[key: string]: unknown"));
    assert!(declarations.contact_type.contains("id: string"));
    assert!(declarations.contact_type.contains("[key: string]: unknown"));
    Ok(())
}

#[test]
fn every_assertion_the_pinned_unit_test_makes_is_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;

    assert_eq!(pinned.unit_test_assertions.len(), 4);
    assert!(
        pinned
            .unit_test_assertions
            .iter()
            .any(|line| line.contains("filter_field=company&filter_value=mycompany"))
    );
    assert!(
        pinned
            .unit_test_assertions
            .iter()
            .any(|line| line.contains("deepEqual(lastBody, info)"))
    );
    assert!(
        pinned
            .unit_test_assertions
            .iter()
            .any(|line| line.contains("body, undefined"))
    );

    assert_eq!(pinned.unit_test_methods, ["GET", "GET", "POST", "PUT", "DELETE"]);
    assert_eq!(pinned.unit_test_paths.len(), 2);
    for path in &pinned.unit_test_paths {
        assert!(
            pinned.driven_paths.iter().any(|driven| driven == path),
            "the pinned test asserts {path}, which nothing here drove"
        );
    }

    let info = pinned
        .unit_test_info
        .as_object()
        .ok_or("the pinned info is not an object")?;
    assert_eq!(info.len(), 2);
    assert_eq!(info.get("name").and_then(Value::as_str), Some("John Doe"));
    assert_eq!(info.get("company").and_then(Value::as_str), Some("My Company"));

    assert!(pinned.integration_helper_call.contains("list(undefined, 'alias'"));
    assert!(pinned.call_sites.total >= 3);
    assert!(pinned.call_sites.scanned_files > 100);
    assert_ne!(pinned.note, "");
    Ok(())
}

#[test]
fn every_recorded_divergence_names_its_reason_and_its_rust_decision() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = fixture
        .reference_quirks
        .as_object()
        .ok_or("the recorded divergences are not an object")?;
    assert_eq!(quirks.len(), 8);
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

// --- `list` ---
#[test]
fn the_pinned_filtered_listing_reproduces_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list_filtered")?;
    assert_eq!(
        recorded.path,
        "/contacts?group=mygroup&filter_field=company&filter_value=mycompany"
    );

    let answer = answer_of(&fixture, "list_filtered")?;
    let (client, transport) = connected(&[&answer])?;
    let filter = ContactFilter::new("company", "mycompany");
    let contacts = block_on(client.contacts().list(Some("mygroup"), Some(&filter)))?;
    let (path, method, body) = sent(&transport)?;

    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_eq!(method, "GET");
    assert_eq!(body, None);
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts.first().map(|contact| contact.id.as_str()), Some(CONTACT));
    Ok(())
}

#[test]
fn a_group_only_listing_writes_one_parameter() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list_group_only")?;
    assert_eq!(recorded.path, "/contacts?group=mygroup");

    let (client, transport) = connected(&[b"[]"])?;
    block_on(client.contacts().list(Some("mygroup"), None))?;
    assert_eq!(sent(&transport)?.0, recorded.path);
    Ok(())
}

#[test]
fn the_integration_helpers_own_listing_reproduces() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list_filter_only")?;
    assert_eq!(recorded.path, "/contacts?filter_field=alias&filter_value=%5Ealice%24");

    let answer = answer_of(&fixture, "list_filter_only")?;
    let (client, transport) = connected(&[&answer])?;
    let filter = ContactFilter::alias("^alice$");
    assert_eq!(filter.field, ALIAS_FIELD);
    let contacts = block_on(client.contacts().list(None, Some(&filter)))?;
    assert_eq!(sent(&transport)?.0, recorded.path);
    assert_eq!(
        contacts.first().and_then(|contact| contact.alias.as_deref()),
        Some("alice")
    );
    Ok(())
}

#[test]
fn an_unfiltered_listing_is_the_one_deliberate_path_difference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list_unfiltered")?;
    assert_eq!(recorded.path, "/contacts?");

    let answer = answer_of(&fixture, "list_unfiltered")?;
    let (client, transport) = connected(&[&answer])?;
    let contacts = block_on(client.contacts().list(None, None))?;
    let (path, _, _) = sent(&transport)?;

    assert_eq!(path, "/contacts");
    assert_ne!(path, recorded.path);
    assert_eq!(path, recorded.path.trim_end_matches('?'));
    assert_eq!(contacts.len(), 2);
    Ok(())
}

#[test]
fn half_a_filter_is_unrepresentable_where_the_reference_drops_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for name in ["list_half_a_filter", "list_half_a_filter_value_only"] {
        let recorded = request_of(&fixture, name)?;
        assert_eq!(recorded.path, "/contacts?", "{name} sent something else");
        assert!(!recorded.path.contains(FILTER_FIELD_PARAMETER), "{name}");
        assert!(!recorded.path.contains(FILTER_VALUE_PARAMETER), "{name}");
    }

    let (client, transport) = connected(&[b"[]"])?;
    let filter = ContactFilter::new(ALIAS_FIELD, "");
    block_on(client.contacts().list(None, Some(&filter)))?;
    let (path, _, _) = sent(&transport)?;
    assert_eq!(path, "/contacts?filter_field=alias&filter_value=");
    assert!(path.contains(FILTER_FIELD_PARAMETER) && path.contains(FILTER_VALUE_PARAMETER));
    Ok(())
}

#[test]
fn a_filter_value_is_encoded_on_both_sides() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list_filter_needing_encoding")?;
    assert_eq!(recorded.path, "/contacts?filter_field=alias&filter_value=a%26b%3Dc");

    let (client, transport) = connected(&[b"[]"])?;
    let filter = ContactFilter::new(ALIAS_FIELD, "a&b=c");
    block_on(client.contacts().list(None, Some(&filter)))?;
    assert_eq!(sent(&transport)?.0, recorded.path);
    Ok(())
}

// --- `get`, `add`, `update`, `delete` ---
#[test]
fn the_pinned_read_reproduces_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "get")?;
    assert_eq!(recorded.path, format!("/contacts/{CONTACT}"));

    let answer = answer_of(&fixture, "get")?;
    let (client, transport) = connected(&[&answer])?;
    let contact = block_on(client.contacts().get(&prefix(CONTACT)?))?;
    let (path, method, body) = sent(&transport)?;

    assert_eq!(path, recorded.path);
    assert_eq!(method, "GET");
    assert_eq!(body, None);
    assert_eq!(contact.id, CONTACT);
    assert_eq!(contact.alias.as_deref(), Some("John Doe"));
    Ok(())
}

#[test]
fn both_pinned_writes_reproduce_their_body_field_for_field() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, expected_method) in [("add", "POST"), ("update", "PUT")] {
        let recorded = request_of(&fixture, name)?;
        assert_eq!(recorded.path, format!("/contacts/{CONTACT}"));
        assert_eq!(recorded.method, expected_method);
        assert_eq!(
            recorded.body.as_deref(),
            Some(r#"{"name":"John Doe","company":"My Company"}"#),
            "{name} sent a different body"
        );

        let answer = answer_of(&fixture, name)?;
        let (client, transport) = connected(&[&answer])?;
        let info = pinned_info()?;
        let contacts = client.contacts();
        let identifier = prefix(CONTACT)?;
        let result = if name == "add" {
            block_on(contacts.add(&identifier, &info))
        } else {
            block_on(contacts.update(&identifier, &info))
        }?;
        let (path, method, body) = sent(&transport)?;

        assert_eq!(path, recorded.path);
        assert_eq!(method, recorded.method);
        assert_eq!(body, recorded.body, "{name} built a different body");
        assert_eq!(result.id, CONTACT);
    }
    Ok(())
}

#[test]
fn an_ordered_info_reaches_the_wire_in_the_callers_order() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "add_nested_info")?;
    assert_eq!(
        recorded.body.as_deref(),
        Some(r#"{"z":1,"a":{"nested":true},"list":[1,2,3]}"#)
    );

    let mut nested = Sad::new();
    nested.insert("nested", true)?;
    let mut info = Sad::new();
    info.insert("z", SadValue::Integer(1))?;
    info.insert("a", SadValue::Map(nested))?;
    info.insert(
        "list",
        SadValue::Array(vec![SadValue::Integer(1), SadValue::Integer(2), SadValue::Integer(3)]),
    )?;

    let answer = answer_of(&fixture, "add_nested_info")?;
    let (client, transport) = connected(&[&answer])?;
    block_on(client.contacts().add(&prefix(CONTACT)?, &info))?;
    let (_, _, body) = sent(&transport)?;
    assert_eq!(body, recorded.body);
    Ok(())
}

#[test]
fn an_empty_info_is_written_rather_than_omitted() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "add_empty_info")?;
    assert_eq!(recorded.body.as_deref(), Some("{}"));

    let answer = answer_of(&fixture, "add_empty_info")?;
    let (client, transport) = connected(&[&answer])?;
    block_on(client.contacts().add(&prefix(CONTACT)?, &Sad::new()))?;
    assert_eq!(sent(&transport)?.2, recorded.body);
    Ok(())
}

#[test]
fn a_delete_carries_no_body_at_all() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "delete")?;
    assert_eq!(recorded.path, format!("/contacts/{CONTACT}"));
    assert_eq!(recorded.method, "DELETE");
    assert!(recorded.body_is_undefined);
    assert_eq!(recorded.body, None);

    let (client, transport) = connected(&[b"{}"])?;
    block_on(client.contacts().delete(&prefix(CONTACT)?))?;
    let (path, method, body) = sent(&transport)?;
    assert_eq!(path, recorded.path);
    assert_eq!(method, "DELETE");
    assert_eq!(body, None);
    Ok(())
}

#[test]
fn a_prefix_that_would_escape_the_path_is_unrepresentable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "get_prefix_needing_encoding")?;
    assert_eq!(recorded.path, "/contacts/a/b?c=d");
    assert!(IdentifierPrefix::from_qb64("a/b?c=d").is_err());
    Ok(())
}

#[test]
fn a_wrong_shaped_answer_is_refused_where_the_reference_casts_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    let single = call(&fixture, "get_wrong_shape")?;
    assert_eq!(single.error, None);
    assert_eq!(single.result.get("unexpected").and_then(Value::as_bool), Some(true));
    let answer = serde_json::to_vec(&single.result)?;
    let (client, transport) = connected(&[&answer])?;
    let outcome = block_on(client.contacts().get(&prefix(CONTACT)?));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "an answer naming no identifier was not refused: {outcome:?}"
    );
    assert_eq!(sent(&transport)?.0, format!("/contacts/{CONTACT}"));

    let listing = call(&fixture, "list_wrong_shape")?;
    assert_eq!(listing.error, None);
    let answer = serde_json::to_vec(&listing.result)?;
    let (client, _) = connected(&[&answer])?;
    let outcome = block_on(client.contacts().list(None, None));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "a contact with no identifier was not refused: {outcome:?}"
    );
    Ok(())
}
