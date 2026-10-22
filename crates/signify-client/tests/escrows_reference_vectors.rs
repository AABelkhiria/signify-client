//! Exact escrows-endpoint vectors recorded from the pinned reference's own `Escrows`.
//!
//! Thirteen listings, twelve byte-exact, the unfiltered one's bare `?` omitted, and four answers refused.

mod support;

use std::error::Error;
use std::sync::Arc;

use crate::support::{ADMIN, AGENT, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on, clock};
use keri_protocol::event::reply::ReplyBuilder;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::serialization::{Sad, SadValue};
use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::escrows::{ESCROWS_SEGMENT, PRESENTATION_REQUEST_ROUTE, REPLY_SEGMENT, ROUTE_PARAMETER};
use signify_client::error::ClientError;
use signify_http::transport::Transport;
use signify_keys::manager::DerivationCost;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const KERIPY_SHA: &str = "4ce4cc79e06653f77342be1bf604086b89b1f090";
const FIXTURE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/client-escrows/v1.json"));

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
    keripy_corroboration: KeripyCorroboration,
    reference_quirks: Value,
}

#[derive(Debug, Deserialize)]
struct KeripyCorroboration {
    keripy_sha: String,
    escrow_reply_declaration: String,
    reply_routes: Vec<String>,
    presentation_request_files: Vec<ScanHit>,
    presentation_request_ilk: String,
    presentation_request_route_line: String,
    presentation_request_is_a_reply_route: bool,
    note: String,
    scoping: String,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    bran: String,
    admin_url: String,
    boot_url: String,
    fixed_clock_ms: u64,
    reply_stamp: String,
    agent_prefix: String,
    controller_prefix: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    list_reply_params: String,
    list_reply_guard: String,
    list_reply_path: String,
    list_reply_method: String,
    list_reply_fetch: String,
    list_reply_return: String,
    list_reply_signature: Vec<String>,
    escrows_members: Vec<String>,
    escrows_exports: Vec<String>,
    rpy_alias: String,
    rpy_schema: String,
    rpy_v1_schema: String,
    rpy_v2_schema: String,
    rpy_alias_consumers: Scan,
    escrows_accessor_uses: Scan,
    list_reply_uses: Scan,
    pinned_route_uses: Scan,
    reply_route_uses: ReplyRouteUses,
    exchanging_imports_rpy: String,
    notes: Value,
}

#[derive(Debug, Deserialize)]
struct ReplyRouteUses {
    end_role_add: Scan,
    loc_scheme: Scan,
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
    arguments: Vec<String>,
    answer: Value,
    request: Option<RecordedRequest>,
    result: Value,
    error: Option<String>,
}

impl Call {
    fn route(&self) -> Option<&str> {
        self.arguments.first().map(String::as_str)
    }
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
    published_routes: Vec<String>,
    published_method: String,
    driven_path: String,
    driven_method: String,
    every_pinned_assertion_is_driven: bool,
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

fn sent(transport: &AgentTransport) -> Result<SentRequest, Box<dyn Error>> {
    let endpoint = transport.endpoint_requests()?;
    let request = endpoint.first().ok_or("no endpoint request was sent")?;
    Ok((request.resource(), request.method().to_owned(), request.body_text()))
}

type SentRequest = (String, String, Option<String>);

type DrivenListing = (SentRequest, Result<Vec<Value>, ClientError>);

fn drive(recorded: &Call) -> Result<DrivenListing, Box<dyn Error>> {
    let answer = serde_json::to_vec(&recorded.answer)?;
    let (client, transport) = connected(&[&answer])?;
    let outcome = block_on(client.escrows().list_replies(recorded.route()));
    let listing = outcome.map(|replies| {
        replies
            .iter()
            .filter_map(|reply| serde_json::to_value(reply).ok())
            .collect::<Vec<Value>>()
    });
    Ok((sent(&transport)?, listing))
}

// --- Manifest and provenance ---
#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert_ne!(fixture.generated_on, "");
    assert!(fixture.sources.iter().any(|source| source.ends_with("escrowing.ts")));
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("escrowing.test.ts"))
    );
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.reply_stamp, "2023-11-14T22:13:20.123000+00:00");
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert_ne!(fixture.provenance.controller_prefix, "");
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 13);
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

    assert_eq!(declarations.list_reply_params, "params = new URLSearchParams()");
    assert_eq!(
        declarations.list_reply_guard,
        "if (route !== undefined) { params.append('route', route); }"
    );
    assert_eq!(
        declarations.list_reply_path,
        "path = `/escrows/rpy` + '?' + params.toString()"
    );
    assert!(declarations.list_reply_path.contains(ESCROWS_SEGMENT));
    assert!(declarations.list_reply_path.contains(REPLY_SEGMENT));
    assert!(declarations.list_reply_guard.contains(ROUTE_PARAMETER));
    assert_eq!(declarations.list_reply_method, "method = 'GET'");
    assert!(declarations.list_reply_fetch.contains("null"));

    assert_eq!(declarations.list_reply_return, "await res.json()");

    assert_eq!(declarations.list_reply_signature, ["route?: string"]);
    assert_eq!(declarations.escrows_members, ["client", "<constructor>", "listReply"]);

    assert_eq!(declarations.escrows_exports, ["Escrows", "Rpy"]);
    Ok(())
}

#[test]
fn the_response_type_is_the_shared_reply_record() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    assert_eq!(
        declarations.rpy_alias,
        "export type Rpy = components['schemas']['Rpy'];"
    );
    assert_eq!(
        declarations.rpy_schema,
        "Rpy: | components['schemas']['RPY_V_1'] | components['schemas']['RPY_V_2'];"
    );
    assert_eq!(
        declarations.rpy_v1_schema,
        "RPY_V_1: { v: string; t: string; d: string; dt: string; r: string; a: unknown; };"
    );
    assert_eq!(
        declarations.rpy_v2_schema,
        "RPY_V_2: { v: string; t: string; d: string; i: string; dt: string; r: string; a: unknown; };"
    );
    assert!(declarations.rpy_v1_schema.contains("t: string"));

    assert_eq!(declarations.rpy_alias_consumers.total, 1);
    assert!(
        declarations
            .rpy_alias_consumers
            .files
            .iter()
            .any(|hit| hit.file.ends_with("app/exchanging.ts") && hit.count == 1)
    );
    assert!(declarations.exchanging_imports_rpy.contains("escrowing"));
    assert_eq!(declarations.rpy_alias_consumers.scanned_files, 117);
    Ok(())
}

#[test]
fn the_escrow_vocabulary_is_one_route_named_only_in_a_test() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    assert_eq!(declarations.pinned_route_uses.needle, PRESENTATION_REQUEST_ROUTE);
    assert_eq!(declarations.pinned_route_uses.total, 1);
    assert_eq!(
        declarations
            .pinned_route_uses
            .files
            .iter()
            .map(|hit| hit.file.as_str())
            .collect::<Vec<&str>>(),
        ["test/app/escrowing.test.ts"]
    );

    for scan in [
        &declarations.reply_route_uses.end_role_add,
        &declarations.reply_route_uses.loc_scheme,
    ] {
        assert!(scan.total >= 1, "{} is produced nowhere", scan.needle);
        for hit in &scan.files {
            assert!(
                !hit.file.contains("escrowing"),
                "{} is used as an escrow filter after all, in {}",
                scan.needle,
                hit.file
            );
        }
    }

    assert!(declarations.escrows_accessor_uses.total >= 1);
    assert!(declarations.list_reply_uses.total >= 1);
    assert!(declarations.notes.is_object());
    Ok(())
}

#[test]
fn keripy_corroborates_that_the_one_named_route_is_not_a_reply_route() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let keripy = &fixture.keripy_corroboration;
    assert_eq!(keripy.keripy_sha, KERIPY_SHA);
    assert!(keripy.scoping.starts_with("corroboration only"));
    assert_ne!(keripy.note, "");

    assert!(keripy.escrow_reply_declaration.starts_with("def escrowReply("));

    assert_eq!(
        keripy.reply_routes,
        [
            "/end/role/{action}",
            "/introduce",
            "/ksn/{aid}",
            "/loc/scheme",
            "/tsn/credential/{aid}",
            "/tsn/registry/{aid}",
            "/watcher/{aid}/{action}",
        ]
    );
    assert!(keripy.reply_routes.iter().any(|route| route == "/loc/scheme"));
    assert!(keripy.reply_routes.iter().any(|route| route.starts_with("/end/role/")));

    assert!(!keripy.presentation_request_is_a_reply_route);
    assert!(
        !keripy
            .reply_routes
            .iter()
            .any(|route| route == PRESENTATION_REQUEST_ROUTE)
    );
    assert_eq!(
        keripy
            .presentation_request_files
            .iter()
            .map(|hit| hit.file.as_str())
            .collect::<Vec<&str>>(),
        ["ref/Peer2PeerCredentials.md"]
    );
    assert!(keripy.presentation_request_ilk.starts_with(r#""t": "exn""#));
    assert!(
        keripy
            .presentation_request_route_line
            .contains(PRESENTATION_REQUEST_ROUTE)
    );

    let recorded = call(&fixture, "pinned_route")?;
    let ((path, _, _), _) = drive(recorded)?;
    assert_eq!(path, "/escrows/rpy?route=%2Fpresentation%2Frequest");
    Ok(())
}

#[test]
fn the_pinned_url_and_method_are_produced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let confirmations = &fixture.pinned_confirmations;
    assert!(confirmations.every_pinned_assertion_is_driven);
    assert_eq!(
        confirmations.published_paths,
        ["/escrows/rpy?route=%2Fpresentation%2Frequest"]
    );
    assert_eq!(confirmations.published_routes, [PRESENTATION_REQUEST_ROUTE]);
    assert_eq!(confirmations.published_method, "GET");
    let published = confirmations
        .published_paths
        .first()
        .ok_or("the pinned test publishes no path")?;
    assert_eq!(&confirmations.driven_path, published);
    assert_eq!(confirmations.driven_method, "GET");
    assert_ne!(confirmations.note, "");

    let recorded = call(&fixture, "pinned_route")?;
    let ((path, method, body), _) = drive(recorded)?;
    assert_eq!(&path, published);
    assert_eq!(method, "GET");
    assert_eq!(body, None);
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

// --- The requests ---
#[test]
fn every_recorded_request_reproduces_except_the_bare_question_mark() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let mut reproduced = 0_usize;
    for recorded in &fixture.calls {
        let expected = recorded.request.as_ref().ok_or("no recorded request")?;
        let ((path, method, body), _) = drive(recorded)?;
        assert_eq!(method, expected.method, "call {}", recorded.name);
        assert_eq!(method, "GET");
        assert_eq!(body, None, "call {} sent a body", recorded.name);
        assert_eq!(expected.body, None);
        if recorded.name == "no_route" {
            assert_eq!(expected.path, "/escrows/rpy?");
            assert_eq!(path, "/escrows/rpy");
        } else {
            assert_eq!(path, expected.path, "call {}", recorded.name);
            reproduced = reproduced.saturating_add(1);
        }
    }
    assert_eq!(reproduced, 12);
    Ok(())
}

#[test]
fn a_route_reaches_the_query_encoded_exactly_once() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, expected) in [
        ("route_with_query_delimiters", "/escrows/rpy?route=a%26b%3Dc"),
        ("route_with_space", "/escrows/rpy?route=a+b"),
        ("route_that_would_climb", "/escrows/rpy?route=..%2F..%2Fidentifiers"),
        ("end_role_route", "/escrows/rpy?route=%2Fend%2Frole%2Fadd"),
        ("loc_scheme_route", "/escrows/rpy?route=%2Floc%2Fscheme"),
    ] {
        let recorded = call(&fixture, name)?;
        assert_eq!(
            recorded.request.as_ref().map(|request| request.path.as_str()),
            Some(expected)
        );
        let ((path, _, _), _) = drive(recorded)?;
        assert_eq!(path, expected, "call {name}");
        assert!(path.starts_with("/escrows/rpy?"));
        assert_eq!(path.matches('?').count(), 1);
        assert_eq!(path.matches('&').count(), 0);
    }
    Ok(())
}

#[test]
fn an_empty_route_and_an_absent_one_are_two_requests() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;

    let empty = call(&fixture, "empty_route")?;
    assert_eq!(empty.arguments, [""]);
    assert_eq!(
        empty.request.as_ref().map(|request| request.path.as_str()),
        Some("/escrows/rpy?route=")
    );
    let ((path, _, _), _) = drive(empty)?;
    assert_eq!(path, "/escrows/rpy?route=");

    let absent = call(&fixture, "no_route")?;
    assert_eq!(absent.arguments, [] as [String; 0]);
    let ((path, _, _), _) = drive(absent)?;
    assert_eq!(path, "/escrows/rpy");
    Ok(())
}

// --- The answers ---
#[test]
fn the_pinned_listing_decodes_into_the_replies_the_reference_built() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "pinned_route")?;
    let answered = recorded.answer.as_array().ok_or("the pinned answer is not a list")?;
    assert_eq!(answered.len(), 2);

    let (_, listing) = drive(recorded)?;
    let listing = listing?;
    assert_eq!(listing.len(), 2);

    assert_eq!(recorded.result, recorded.answer);
    for (decoded, sent) in listing.iter().zip(answered) {
        for label in ["v", "t", "d", "dt", "r"] {
            assert_eq!(decoded.get(label), sent.get(label), "field {label}");
        }
        assert_eq!(decoded.get("t").and_then(Value::as_str), Some("rpy"));
        assert_eq!(
            decoded.get("r").and_then(Value::as_str),
            Some(PRESENTATION_REQUEST_ROUTE)
        );
        assert_eq!(decoded.get("i"), None);
    }
    Ok(())
}

#[test]
fn an_escrowed_reply_is_one_this_port_could_have_built() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "pinned_route")?;
    let first = recorded
        .answer
        .as_array()
        .and_then(|entries| entries.first())
        .ok_or("the pinned answer is empty")?;

    let mut inner = Sad::new();
    inner.insert("d", SadValue::text("EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo"))?;
    let mut attributes = Sad::new();
    attributes.insert("i", SadValue::text(fixture.provenance.controller_prefix.clone()))?;
    attributes.insert("s", SadValue::text("EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"))?;
    attributes.insert("a", SadValue::Map(inner))?;

    let stamp: Timestamp = fixture.provenance.reply_stamp.parse()?;
    let rebuilt = ReplyBuilder::new(PRESENTATION_REQUEST_ROUTE, stamp)
        .attributes(attributes)
        .build()?;

    assert_eq!(
        Some(rebuilt.said().qb64()?.as_str()),
        first.get("d").and_then(Value::as_str),
        "the rebuilt reply derives a different identifier"
    );
    let decoded: Value = serde_json::from_slice(rebuilt.raw())?;
    assert_eq!(&decoded, first);
    assert_eq!(decoded.get("v").and_then(Value::as_str), Some("KERI10JSON00013f_"));
    assert_ne!(core::str::from_utf8(rebuilt.raw())?, serde_json::to_string(first)?);
    Ok(())
}

#[test]
fn an_empty_listing_is_an_answer() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "empty_listing")?;
    assert_eq!(recorded.result, serde_json::json!([]));
    let (_, listing) = drive(recorded)?;
    assert_eq!(listing?, [] as [Value; 0]);
    Ok(())
}

#[test]
fn a_wrong_ilk_answer_is_refused_where_the_reference_counts_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "wrong_ilk_answer")?;
    assert_eq!(recorded.error, None);
    assert_eq!(
        recorded
            .result
            .as_array()
            .and_then(|entries| entries.first())
            .and_then(|entry| entry.get("t"))
            .and_then(Value::as_str),
        Some("icp")
    );

    let ((path, _, _), listing) = drive(recorded)?;
    assert!(
        matches!(listing, Err(ClientError::Api { .. })),
        "an inception event was accepted as an escrowed reply: {listing:?}"
    );
    assert_eq!(path, "/escrows/rpy?route=%2Fpresentation%2Frequest");
    Ok(())
}

#[test]
fn an_answer_that_is_not_a_listing_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for name in ["not_a_list_answer", "incomplete_answer"] {
        let recorded = call(&fixture, name)?;
        assert_eq!(recorded.error, None, "the reference refused {name}");
        let (_, listing) = drive(recorded)?;
        assert!(
            matches!(listing, Err(ClientError::Api { .. })),
            "{name} was accepted: {listing:?}"
        );
    }
    Ok(())
}

#[test]
fn an_undeclared_field_is_ignored_where_the_reference_keeps_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "unknown_field_answer")?;
    assert_eq!(
        recorded
            .result
            .as_array()
            .and_then(|entries| entries.first())
            .and_then(|entry| entry.get("escrowed")),
        Some(&Value::Bool(true))
    );

    let (_, listing) = drive(recorded)?;
    let listing = listing?;
    assert_eq!(listing.len(), 1);
    let decoded = listing.first().ok_or("the listing is empty")?;
    assert_eq!(decoded.get("escrowed"), None);
    assert_eq!(
        decoded.get("a"),
        recorded
            .answer
            .as_array()
            .and_then(|entries| entries.first())
            .and_then(|entry| entry.get("a"))
    );
    Ok(())
}
