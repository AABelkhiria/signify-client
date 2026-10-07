//! Exact notification-endpoint vectors recorded from the pinned reference's own `Notifications`.
//!
//! Three methods, the port's second windowed listing, and what a notification's identifier actually is.

mod support;

use core::time::Duration;
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::time::SystemTime;

use crate::support::{ADMIN, AGENT, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on};
use keria_types::api::contact::Notification;
use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::notifications::{NOTIFICATION_RANGE_UNIT, NOTIFICATIONS_SEGMENT};
use signify_client::error::ClientError;
use signify_http::request::{ItemRange, RangeUnit};
use signify_http::retry::{Clock, TestClock};
use signify_http::transport::Transport;
use signify_keri::manager::DerivationCost;
use signify_keri::said::Said;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const KERIPY_SHA: &str = "4ce4cc79e06653f77342be1bf604086b89b1f090";
const FIXTURE: &str = include_str!("../../../fixtures/client-notifications/v1.json");

const PINNED_LITERAL: &str = "notificationSAID";

// --- Fixture model ---
#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    keripy_sha: String,
    generated_on: String,
    sources: Vec<String>,
    keripy_sources: Vec<String>,
    provenance: Provenance,
    declarations: Declarations,
    notification_identifier: IdentifierRecord,
    calls: Vec<Call>,
    pinned_confirmations: PinnedConfirmations,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    fixed_clock_ms: u64,
    agent_prefix: String,
    sample_nonce: String,
    sample_said: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    list_parameters: Vec<String>,
    list_range_header: String,
    list_path: String,
    list_method: String,
    list_content_range: String,
    list_range_parse: String,
    list_return: String,
    mark_parameters: Vec<String>,
    mark_path: String,
    mark_method: String,
    mark_return: String,
    delete_parameters: Vec<String>,
    delete_path: String,
    delete_method: String,
    delete_fetch: String,
    class_members: Vec<String>,
    notification_type: String,
}

#[derive(Debug, Deserialize)]
struct IdentifierRecord {
    documentation: String,
    signify_random_nonce: String,
    signify_nonce: String,
    signify_nonce_leading: String,
    keripy_random_nonce_code: String,
    keripy_nonce: String,
    keripy_nonce_leading: String,
    keripy_notice_leaves_it_empty: String,
    keripy_dicter_fills_it: String,
    keripy_dicter_fill_sites: usize,
    sample_said: String,
    sample_said_leading: String,
    keripy_sha: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    payload: Value,
    request: Option<RecordedRequest>,
    content_range: Option<String>,
    result: Value,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
    body_is_undefined: bool,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    unit_test_assertions: Vec<String>,
    unit_test_identifier: String,
    unit_test_range_header: String,
    unit_test_paths: Vec<String>,
    integration_usage: Vec<String>,
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
    Ok(serde_json::to_vec(&call(fixture, name)?.payload)?)
}

type Harness = (ConnectedClient, Arc<AgentTransport>);

fn connected(bodies: &[&[u8]], content_range: Option<&str>) -> Result<Harness, Box<dyn Error>> {
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
    if let Some(range) = content_range {
        transport.with_content_range(range);
    }

    let client = SignifyClient::new(
        configuration()?,
        Arc::clone(&transport) as Arc<dyn Transport>,
        Arc::clone(&clock),
    )?;
    Ok((block_on(client.connect())?, transport))
}

type SentRequest = (String, String, Option<String>, Option<String>);

fn sent(transport: &AgentTransport) -> Result<SentRequest, Box<dyn Error>> {
    let recorded = transport.requests();
    let request = recorded.get(2).ok_or("no endpoint request was sent")?;
    let path = request.resource();
    let range = request.header("range").map(ToOwned::to_owned);
    let body = request.body_text();
    Ok((path, request.method().to_owned(), range, body))
}

fn unit() -> Result<RangeUnit, Box<dyn Error>> {
    Ok(RangeUnit::new(NOTIFICATION_RANGE_UNIT)?)
}

// --- Manifest and provenance ---
#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.keripy_sha, KERIPY_SHA);
    assert_eq!(fixture.keripy_sources.len(), 2);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert_ne!(fixture.generated_on, "");
    assert!(fixture.sources.iter().any(|source| source.ends_with("notifying.ts")));
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 12);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert_eq!(entry.error, None, "call {} was refused upstream", entry.name);
        let request = entry.request.as_ref().ok_or("a recorded call made no request")?;
        assert!(
            request.path.starts_with("/notifications"),
            "call {} addressed {}",
            entry.name,
            request.path
        );
    }
    Ok(())
}

#[test]
fn a_notification_identifier_is_not_a_said() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let record = &fixture.notification_identifier;

    assert!(record.documentation.contains("SAID of the notification"));
    assert!(record.mark_parameters_are_named_said());

    assert!(record.keripy_notice_leaves_it_empty.contains(r#"i="""#));
    assert!(record.keripy_dicter_fills_it.contains("randomNonce()"));
    assert!(record.keripy_dicter_fill_sites >= 1);
    assert_eq!(record.keripy_sha, KERIPY_SHA);

    assert!(record.signify_random_nonce.contains("Ed25519_Seed"));
    assert!(record.keripy_random_nonce_code.contains("Salt_128"));
    assert_eq!(record.signify_nonce_leading, "A");
    assert_eq!(record.keripy_nonce_leading, "0A");
    assert_eq!(record.sample_said_leading, "E");
    assert_ne!(record.signify_nonce_leading, record.sample_said_leading);
    assert_ne!(record.keripy_nonce_leading, record.sample_said_leading);

    assert!(Said::from_qb64(&record.signify_nonce).is_err());
    assert!(Said::from_qb64(&record.keripy_nonce).is_err());
    assert!(Said::from_qb64(&record.sample_said).is_ok());
    assert_eq!(record.sample_said, fixture.provenance.sample_said);
    assert!(Said::from_qb64(PINNED_LITERAL).is_err());

    assert_ne!(record.note, "");
    assert_ne!(record.rust_decision, "");
    Ok(())
}

impl IdentifierRecord {
    fn mark_parameters_are_named_said(&self) -> bool {
        self.documentation.contains("@param {string} said")
    }
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    assert_eq!(
        declarations.class_members,
        ["client", "<constructor>", "list", "mark", "delete"]
    );

    assert_eq!(declarations.list_parameters, ["start: number = 0", "end: number = 24"]);
    assert!(declarations.list_range_header.contains("notes=${start}-${end}"));
    assert!(declarations.list_range_header.contains("Range"));
    assert_eq!(declarations.list_path, "path = `/notifications`");
    assert_eq!(declarations.list_method, "method = 'GET'");
    assert!(declarations.list_path.contains(NOTIFICATIONS_SEGMENT));
    assert!(declarations.list_range_header.contains(NOTIFICATION_RANGE_UNIT));

    assert!(declarations.list_content_range.contains("content-range"));
    assert!(declarations.list_range_parse.contains("parseRangeHeaders"));
    assert!(declarations.list_return.contains("start: range.start"));
    assert!(declarations.list_return.contains("notes: notes"));

    assert_eq!(declarations.mark_path, "path = `/notifications/` + said");
    assert_eq!(declarations.delete_path, declarations.mark_path);
    assert!(!declarations.mark_path.contains("encodeURIComponent"));
    assert_eq!(declarations.mark_method, "method = 'PUT'");
    assert_eq!(declarations.delete_method, "method = 'DELETE'");
    assert_eq!(declarations.mark_parameters, ["said: string"]);
    assert_eq!(declarations.delete_parameters, ["said: string"]);

    assert_eq!(declarations.mark_return, "await res.text()");
    assert!(declarations.delete_fetch.contains("undefined"));

    assert!(declarations.notification_type.contains("i: string"));
    assert!(declarations.notification_type.contains("r: boolean"));
    Ok(())
}

#[test]
fn every_assertion_the_pinned_unit_test_makes_is_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;

    assert_eq!(pinned.unit_test_assertions.len(), 3);
    assert!(
        pinned
            .unit_test_assertions
            .iter()
            .any(|line| line.contains("'notes=20-40'"))
    );
    assert_eq!(pinned.unit_test_range_header, "notes=20-40");
    assert_eq!(pinned.unit_test_identifier, PINNED_LITERAL);

    assert_eq!(pinned.unit_test_paths.len(), 2);
    for path in &pinned.unit_test_paths {
        assert!(
            pinned.driven_paths.iter().any(|driven| driven == path),
            "the pinned test asserts {path}, which nothing here drove"
        );
    }

    assert_eq!(pinned.integration_usage.len(), 3);
    assert!(
        pinned
            .integration_usage
            .iter()
            .any(|line| line.contains("mark(note.i)"))
    );
    assert!(pinned.call_sites.total >= 5);
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
    assert_eq!(quirks.len(), 9);
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
fn the_pinned_windowed_listing_reproduces_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "list_windowed")?;
    assert_eq!(recorded.path, "/notifications");
    assert_eq!(recorded.method, "GET");
    assert_eq!(recorded.headers.get("range").map(String::as_str), Some("notes=20-40"));

    let answer = answer_of(&fixture, "list_windowed")?;
    let range = call(&fixture, "list_windowed")?.content_range.clone();
    let (client, transport) = connected(&[&answer], range.as_deref())?;
    let listing = block_on(client.notifications().list(ItemRange::new(20, 40)?))?;
    let (path, method, header, body) = sent(&transport)?;

    assert_eq!(path, recorded.path);
    assert_eq!(method, recorded.method);
    assert_eq!(header.as_deref(), Some("notes=20-40"));
    assert_eq!(body, None);

    let window = listing.window.ok_or("no window was reported")?;
    assert_eq!(window.start(), 20);
    assert_eq!(window.end(), 40);
    assert_eq!(window.total(), 100);
    assert_eq!(listing.notifications.len(), 1);
    assert_eq!(listing.unread().count(), 1);
    Ok(())
}

#[test]
fn the_default_window_produces_the_same_request_as_naming_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let defaulted = request_of(&fixture, "list_default_window")?;
    assert_eq!(defaulted.headers.get("range").map(String::as_str), Some("notes=0-24"));
    assert_eq!(ItemRange::DEFAULT.header_value(&unit()?), "notes=0-24");

    let answer = answer_of(&fixture, "list_default_window")?;
    let range = call(&fixture, "list_default_window")?.content_range.clone();
    let (client, transport) = connected(&[&answer], range.as_deref())?;
    block_on(client.notifications().list(ItemRange::DEFAULT))?;
    assert_eq!(sent(&transport)?.2.as_deref(), Some("notes=0-24"));
    Ok(())
}

#[test]
fn an_absent_content_range_stays_unreported_rather_than_becoming_zeroes() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "list_no_content_range")?;
    assert_eq!(recorded.content_range, None);
    assert_eq!(recorded.payload.as_array().map(Vec::len), Some(1));
    for field in ["start", "end", "total"] {
        assert_eq!(
            recorded.result.get(field).and_then(Value::as_u64),
            Some(0),
            "the reference no longer reports {field} as zero"
        );
    }
    assert_eq!(
        recorded.result.get("notes").and_then(Value::as_array).map(Vec::len),
        Some(1),
        "the reference lost the page it was answered with"
    );

    let answer = answer_of(&fixture, "list_no_content_range")?;
    let (client, _) = connected(&[&answer], None)?;
    let listing = block_on(client.notifications().list(ItemRange::DEFAULT))?;

    assert_eq!(listing.window, None);
    assert_eq!(listing.notifications.len(), 1);
    let empty = answer_of(&fixture, "list_empty")?;
    let empty_range = call(&fixture, "list_empty")?.content_range.clone();
    let (client, _) = connected(&[&empty], empty_range.as_deref())?;
    let empty_listing = block_on(client.notifications().list(ItemRange::DEFAULT))?;
    assert!(empty_listing.window.is_some());
    assert_eq!(empty_listing.notifications, [] as [Notification; 0]);
    assert_ne!(listing.window, empty_listing.window);
    Ok(())
}

#[test]
fn a_window_that_is_not_a_count_of_items_is_unrepresentable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let fractional = request_of(&fixture, "list_fractional_window")?;
    assert_eq!(
        fractional.headers.get("range").map(String::as_str),
        Some("notes=1.5-2.5")
    );
    let reversed = request_of(&fixture, "list_reversed_window")?;
    assert_eq!(reversed.headers.get("range").map(String::as_str), Some("notes=40-20"));

    assert!(ItemRange::new(40, 20).is_err());
    let header = ItemRange::new(1, 2)?.header_value(&unit()?);
    assert_eq!(header, "notes=1-2");
    assert!(!header.contains('.'));
    Ok(())
}

#[test]
fn a_wrong_shaped_page_is_refused_where_the_reference_does_not_even_type_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "list_wrong_shape")?;
    assert_eq!(recorded.error, None);
    assert_eq!(recorded.payload.as_array().map(Vec::len), Some(1));
    assert_eq!(
        recorded.result.get("notes").and_then(Value::as_array).map(Vec::len),
        Some(1),
        "the reference no longer hands the page back"
    );

    let answer = answer_of(&fixture, "list_wrong_shape")?;
    let range = recorded.content_range.clone();
    let (client, transport) = connected(&[&answer], range.as_deref())?;
    let outcome = block_on(client.notifications().list(ItemRange::DEFAULT));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "a notification missing its declared fields was not refused: {outcome:?}"
    );
    assert_eq!(sent(&transport)?.0, "/notifications");
    Ok(())
}

// --- `mark` and `delete` ---
#[test]
fn both_pinned_single_notification_calls_reproduce_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, expected_method) in [("mark", "PUT"), ("delete", "DELETE")] {
        let recorded = request_of(&fixture, name)?;
        assert_eq!(recorded.path, format!("/notifications/{PINNED_LITERAL}"));
        assert_eq!(recorded.method, expected_method);

        let (client, transport) = connected(&[b"\"\""], None)?;
        let notifications = client.notifications();
        if name == "mark" {
            block_on(notifications.mark(PINNED_LITERAL))?;
        } else {
            block_on(notifications.delete(PINNED_LITERAL))?;
        }
        let (path, method, _, body) = sent(&transport)?;
        assert_eq!(path, recorded.path, "{name} addressed a different resource");
        assert_eq!(method, recorded.method);
        assert_eq!(body, None, "{name} sent a body");
    }
    Ok(())
}

#[test]
fn a_real_identifier_reproduces_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let nonce = fixture.provenance.sample_nonce.clone();
    for name in ["mark_nonce", "delete_nonce"] {
        let recorded = request_of(&fixture, name)?;
        assert_eq!(recorded.path, format!("/notifications/{nonce}"));

        let (client, transport) = connected(&[b"\"\""], None)?;
        let notifications = client.notifications();
        if name == "mark_nonce" {
            block_on(notifications.mark(&nonce))?;
        } else {
            block_on(notifications.delete(&nonce))?;
        }
        assert_eq!(sent(&transport)?.0, recorded.path, "{name} rewrote the identifier");
    }
    Ok(())
}

#[test]
fn an_identifier_that_would_escape_the_path_is_encoded() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "mark_needing_encoding")?;
    assert_eq!(recorded.path, "/notifications/a?b=c");

    let (client, transport) = connected(&[b"\"\""], None)?;
    block_on(client.notifications().mark("a?b=c"))?;
    let (path, _, _, _) = sent(&transport)?;
    assert_eq!(path, "/notifications/a%3Fb%3Dc");
    assert_ne!(path, recorded.path);
    assert!(!path.contains('?'));
    Ok(())
}

#[test]
fn a_delete_carries_no_body_where_mark_sends_null() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let deleted = request_of(&fixture, "delete")?;
    assert!(deleted.body_is_undefined);
    assert_eq!(deleted.body, None);
    let marked = request_of(&fixture, "mark")?;
    assert!(!marked.body_is_undefined);

    let (client, transport) = connected(&[b"{}"], None)?;
    block_on(client.notifications().delete(PINNED_LITERAL))?;
    assert_eq!(sent(&transport)?.3, None);
    Ok(())
}

#[test]
fn marking_returns_its_body_as_strictly_decoded_text() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.declarations.mark_return, "await res.text()");

    let (client, _) = connected(&[b"marked"], None)?;
    assert_eq!(block_on(client.notifications().mark(PINNED_LITERAL))?, "marked");

    let (client, _) = connected(&[&[0xff, 0xfe, 0x00]], None)?;
    let outcome = block_on(client.notifications().mark(PINNED_LITERAL));
    assert!(
        matches!(outcome, Err(ClientError::Decode { .. })),
        "a non-UTF-8 answer was not refused: {outcome:?}"
    );
    Ok(())
}
