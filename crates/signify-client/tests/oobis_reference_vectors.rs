//! Exact OOBI-endpoint vectors recorded from the pinned reference's own `Oobis`.
//!
//! Four exact paths, both `resolve` body fields, and both methods, recomputed from the reference's own output.

mod support;

use std::error::Error;
use std::sync::Arc;

use crate::support::{ADMIN, AGENT, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on, clock};
use keri_protocol::prefix::IdentifierPrefix;
use keria_types::api::{EndRole, OperationOutcome, Role};
use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::endpoint::oobis::{
    DEFAULT_ROLE, END_ROLES_SEGMENT, OOBIS_SEGMENT, OobiResolution, RESOLUTIONS_SEGMENT, ROLE_PARAMETER,
};
use signify_client::error::ClientError;
use signify_http::transport::{RequestUrl, Transport};
use signify_keys::manager::DerivationCost;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-oobis/v1.json");

const GROUP_AID: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const UNKNOWN_AID: &str = "EXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const UNKNOWN_VALID_AID: &str = "EAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const SCHEMA_OOBI: &str = "http://vlei-server:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const WITNESS_OOBI: &str = "http://witness-demo:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller";

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
    group_aid: String,
    unknown_aid: String,
    unknown_valid_aid: String,
    schema_oobi: String,
    witness_oobi: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    get_path: String,
    get_method: String,
    get_parameters: Vec<String>,
    get_return: String,
    resolve_path: String,
    resolve_method: String,
    resolve_parameters: Vec<String>,
    resolve_body: String,
    resolve_alias: String,
    endroles_path: String,
    endroles_parameters: Vec<String>,
    class_members: Vec<String>,
    oobi_type: String,
    end_role_type: String,
    oobi_role_enum: Vec<EnumMember>,
}

#[derive(Debug, Deserialize)]
struct EnumMember {
    name: String,
    value: String,
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
    unit_test_assertions: Vec<String>,
    unit_test_paths: Vec<String>,
    driven_paths: Vec<String>,
    get_call_sites: Vec<GetCallSite>,
    get_call_sites_taking_the_default: Vec<GetCallSite>,
    resolve_call_count: usize,
    integration_expectations: Vec<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct GetCallSite {
    file: String,
    call: String,
    argument_count: usize,
    role: Option<String>,
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

fn prefix(text: &str) -> Result<IdentifierPrefix, Box<dyn Error>> {
    Ok(IdentifierPrefix::from_qb64(text)?)
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
    assert!(
        fixture
            .sources
            .iter()
            .any(|source| source.ends_with("endroles-by-aid.test.ts"))
    );
    assert_eq!(fixture.provenance.bran, PASSCODE);
    assert_eq!(fixture.provenance.admin_url, ADMIN);
    assert_eq!(fixture.provenance.boot_url, BOOT);
    assert_eq!(fixture.provenance.fixed_clock_ms, FIXED_MILLIS);
    assert_eq!(fixture.provenance.agent_prefix, AGENT);
    assert_ne!(fixture.provenance.controller_prefix, "");
    assert_eq!(fixture.provenance.group_aid, GROUP_AID);
    assert_eq!(fixture.provenance.unknown_aid, UNKNOWN_AID);
    assert_eq!(fixture.provenance.unknown_valid_aid, UNKNOWN_VALID_AID);
    assert_eq!(fixture.provenance.schema_oobi, SCHEMA_OOBI);
    assert_eq!(fixture.provenance.witness_oobi, WITNESS_OOBI);
    assert!(fixture.provenance.note.contains("PUBLIC TEST MATERIAL"));

    assert_eq!(fixture.calls.len(), 23);
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
        declarations.get_path,
        "path = `/identifiers/${name}/oobis?role=${role}`"
    );
    assert_eq!(declarations.resolve_path, "path = `/oobis`");
    assert_eq!(
        declarations.endroles_path,
        "path = role ? `/endroles/${aid}/${role}` : `/endroles/${aid}`"
    );
    for path in [
        &declarations.get_path,
        &declarations.resolve_path,
        &declarations.endroles_path,
    ] {
        assert!(!path.contains("encodeURIComponent"), "{path} encodes something");
        assert!(!path.contains("URLSearchParams"), "{path} builds a query safely");
    }
    assert!(declarations.get_path.contains(&format!("/{OOBIS_SEGMENT}?")));
    assert!(declarations.get_path.contains(&format!("{ROLE_PARAMETER}=")));
    assert!(declarations.resolve_path.contains(RESOLUTIONS_SEGMENT));
    assert!(declarations.endroles_path.contains(END_ROLES_SEGMENT));

    assert_eq!(declarations.get_method, "method = 'GET'");
    assert_eq!(declarations.resolve_method, "method = 'POST'");

    assert_eq!(declarations.get_parameters, ["name: string", "role: string = 'agent'"]);
    assert!(
        declarations
            .get_parameters
            .iter()
            .any(|parameter| { parameter.contains(&format!("= '{role}'", role = DEFAULT_ROLE.as_str())) })
    );
    assert_eq!(declarations.resolve_parameters, ["oobi: string", "alias?: string"]);
    assert_eq!(declarations.endroles_parameters, ["aid: string", "role?: string"]);

    assert_eq!(declarations.resolve_body, "data: any = { url: oobi, }");
    assert_eq!(
        declarations.resolve_alias,
        "if (alias !== undefined) { data.oobialias = alias; }"
    );

    assert_eq!(declarations.get_return, "await res.json()");
    assert_eq!(
        declarations.class_members,
        ["client", "<constructor>", "get", "resolve", "endroles"]
    );

    assert!(declarations.oobi_type.contains("role: OOBIRole"));
    assert!(declarations.oobi_type.contains("oobis: string[]"));
    assert!(declarations.end_role_type.contains("cid: string"));
    assert!(declarations.end_role_type.contains("eid: string"));
    assert_eq!(declarations.oobi_role_enum.len(), Role::DECLARED.len());
    for (declared, recorded) in Role::DECLARED.iter().zip(&declarations.oobi_role_enum) {
        assert_eq!(declared.as_str(), recorded.value);
        assert_eq!(declared.as_str(), recorded.name);
    }
    Ok(())
}

#[test]
fn every_assertion_the_pinned_unit_test_makes_is_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;

    assert_eq!(pinned.unit_test_assertions.len(), 6);
    for expected in [
        "url + '/identifiers/aid/oobis?role=agent'",
        "url + '/oobis'",
        "lastBody.url, 'http://oobiurl.com'",
        "lastBody.oobialias, 'witness'",
        "url + `/endroles/${aid}`",
        "url + `/endroles/${aid}/agent`",
    ] {
        assert!(
            pinned.unit_test_assertions.iter().any(|line| line == expected),
            "the pinned unit test no longer asserts {expected}"
        );
    }

    assert_eq!(pinned.unit_test_paths.len(), 4);
    for path in &pinned.unit_test_paths {
        assert!(
            pinned.driven_paths.iter().any(|driven| driven == path),
            "the pinned unit test asserts {path}, which nothing here drove"
        );
    }
    assert_ne!(pinned.note, "");

    assert_eq!(pinned.integration_expectations.len(), 10);
    assert!(
        pinned
            .integration_expectations
            .iter()
            .any(|line| line.contains("groupOobi.oobis[0].split"))
    );
    Ok(())
}

#[test]
fn only_one_pinned_call_site_takes_the_default_role() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;

    assert!(pinned.get_call_sites.len() > 50);
    assert_eq!(pinned.get_call_sites_taking_the_default.len(), 1);
    let defaulted = pinned
        .get_call_sites_taking_the_default
        .first()
        .ok_or("no defaulted call site")?;
    assert_eq!(defaulted.argument_count, 1);
    assert_eq!(defaulted.role, None);
    assert_eq!(defaulted.call, "oobis().get('delegate')");
    assert!(defaulted.file.ends_with("delegation.test.ts"));

    for site in &pinned.get_call_sites {
        if let Some(role) = &site.role {
            if role.starts_with('\'') || role.contains("Name") || role.contains('.') {
                continue;
            }
            assert!(
                Role::DECLARED.iter().any(|declared| declared.as_str() == role),
                "{role} at {} is not a declared role",
                site.file
            );
        }
    }

    let defaulted_request = request_of(&fixture, "get_default_role")?;
    assert_eq!(defaulted_request.path, "/identifiers/delegate/oobis?role=agent");
    assert_eq!(DEFAULT_ROLE, Role::Agent);
    assert!(pinned.resolve_call_count > 30);
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

// --- `get` ---
#[test]
fn every_recorded_publication_addresses_the_recorded_path() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, alias, role) in [
        ("get_agent", "aid", Role::Agent),
        ("get_default_role", "delegate", DEFAULT_ROLE),
        ("get_witness_role", "name1", Role::Witness),
        ("get_mailbox_role", "aid1", Role::Mailbox),
    ] {
        let recorded = request_of(&fixture, name)?;
        let answer = answer_of(&fixture, name)?;

        let (client, transport) = connected(&[&answer])?;
        let listing = block_on(client.oobis().get(alias, &role))?;
        let (path, method, body) = sent(&transport)?;
        assert_eq!(path, recorded.path, "{name} addressed a different resource");
        assert_eq!(method, recorded.method);
        assert_eq!(method, "GET");
        assert_eq!(body, None, "{name} sent a body");

        assert_eq!(listing.role, role);
        assert!(
            listing.oobis.iter().all(|oobi| RequestUrl::new(oobi.as_str()).is_ok()),
            "{name} answered with something that is not a URL"
        );
    }
    Ok(())
}

#[test]
fn an_alias_that_would_escape_the_path_is_encoded() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "get_name_needing_encoding")?;
    assert_eq!(recorded.path, "/identifiers/a/b?c=d/oobis?role=agent");

    let (client, transport) = connected(&[b"{\"role\":\"agent\",\"oobis\":[]}"])?;
    block_on(client.oobis().get("a/b?c=d", &Role::Agent))?;
    let (path, _, _) = sent(&transport)?;
    assert_eq!(path, "/identifiers/a%2Fb%3Fc%3Dd/oobis?role=agent");
    assert_ne!(path, recorded.path);
    assert_eq!(path.split('?').next().map(|route| route.split('/').count()), Some(4));
    Ok(())
}

#[test]
fn a_role_can_never_add_a_query_parameter() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "get_role_injecting_a_parameter")?;
    assert_eq!(recorded.path, "/identifiers/aid/oobis?role=agent&extra=1");
    assert_eq!(recorded.path.matches('=').count(), 2);

    let role = Role::Other("agent&extra=1".to_owned());
    let (client, transport) = connected(&[b"{\"role\":\"agent\",\"oobis\":[]}"])?;
    block_on(client.oobis().get("aid", &role))?;
    let (path, _, _) = sent(&transport)?;
    assert_eq!(path, "/identifiers/aid/oobis?role=agent%26extra%3D1");
    assert_eq!(path.matches('=').count(), 1);
    Ok(())
}

#[test]
fn a_wrong_shaped_publication_is_refused_where_the_reference_casts_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "get_wrong_shape")?;
    assert_eq!(recorded.error, None);
    assert_eq!(recorded.result.get("unexpected").and_then(Value::as_bool), Some(true));

    let answer = serde_json::to_vec(&recorded.result)?;
    let (client, transport) = connected(&[&answer])?;
    let outcome = block_on(client.oobis().get("aid", &Role::Agent));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "an answer naming neither a role nor an OOBI list was not refused: {outcome:?}"
    );
    assert_eq!(sent(&transport)?.0, "/identifiers/aid/oobis?role=agent");
    Ok(())
}

// --- `resolve` ---
#[test]
fn every_recorded_resolution_reproduces_its_body_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, url, alias) in [
        ("resolve_without_alias", "http://oobiurl.com", None),
        ("resolve_with_alias", "http://oobiurl.com", Some("witness")),
        ("resolve_schema_oobi", SCHEMA_OOBI, Some("schema")),
        ("resolve_witness_oobi", WITNESS_OOBI, Some("member1")),
        ("resolve_empty_alias", "http://oobiurl.com", Some("")),
    ] {
        let recorded = request_of(&fixture, name)?;
        let answer = answer_of(&fixture, name)?;

        let mut resolution = OobiResolution::new(RequestUrl::new(url)?);
        if let Some(alias) = alias {
            resolution = resolution.with_alias(alias);
        }
        assert_eq!(
            String::from_utf8(resolution.body()?)?,
            recorded.body.clone().unwrap_or_default(),
            "{name} built a different body"
        );

        let (client, transport) = connected(&[&answer])?;
        let operation = block_on(client.oobis().resolve(&resolution))?;
        let (path, method, body) = sent(&transport)?;
        assert_eq!(path, recorded.path);
        assert_eq!(path, "/oobis");
        assert_eq!(method, recorded.method);
        assert_eq!(method, "POST");
        assert_eq!(body, recorded.body, "{name} sent a different body");

        assert_eq!(operation.metadata.map(|metadata| metadata.oobi), Some(url.to_owned()));
        assert!(operation.name.starts_with("oobi."));
    }
    Ok(())
}

#[test]
fn a_resolution_returns_an_operation_rather_than_waiting() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pending = answer_of(&fixture, "resolve_without_alias")?;
    let (client, _) = connected(&[&pending])?;
    let operation = block_on(
        client
            .oobis()
            .resolve(&OobiResolution::new(RequestUrl::new("http://oobiurl.com")?)),
    )?;
    assert!(matches!(operation.outcome, OperationOutcome::Pending));
    assert!(!operation.outcome.is_done());

    let completed = answer_of(&fixture, "resolve_schema_oobi")?;
    let (client, _) = connected(&[&completed])?;
    let operation = block_on(
        client
            .oobis()
            .resolve(&OobiResolution::new(RequestUrl::new(SCHEMA_OOBI)?)),
    )?;
    assert!(operation.outcome.is_done());
    assert_eq!(
        operation.outcome.response().map(|state| state.identifier.as_str()),
        Some(GROUP_AID)
    );
    Ok(())
}

#[test]
fn an_oobi_the_agent_could_not_fetch_is_refused_where_the_reference_sends_it() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, sent_body, hostile) in [
        ("resolve_empty_url", r#"{"url":""}"#, ""),
        ("resolve_not_a_url", r#"{"url":"not a url at all"}"#, "not a url at all"),
        (
            "resolve_url_with_newline",
            "{\"url\":\"http://oobiurl.com/\\n\\r x\"}",
            "http://oobiurl.com/\n\r x",
        ),
    ] {
        let recorded = request_of(&fixture, name)?;
        assert_eq!(recorded.body.as_deref(), Some(sent_body), "{name} sent something else");
        assert_eq!(recorded.path, "/oobis");
        assert!(RequestUrl::new(hostile).is_err(), "{name}'s OOBI was accepted as a URL");
    }
    Ok(())
}

// --- `endroles` ---
#[test]
fn both_pinned_end_role_paths_reproduce() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for (name, role) in [
        ("endroles_without_role", None),
        ("endroles_with_role", Some(Role::Agent)),
        ("endroles_mailbox", Some(Role::Mailbox)),
    ] {
        let recorded = request_of(&fixture, name)?;
        let answer = answer_of(&fixture, name)?;

        let (client, transport) = connected(&[&answer])?;
        let roles = block_on(client.oobis().end_roles(&prefix(GROUP_AID)?, role.as_ref()))?;
        let (path, method, body) = sent(&transport)?;
        assert_eq!(path, recorded.path, "{name} addressed a different resource");
        assert_eq!(method, recorded.method);
        assert_eq!(method, "GET");
        assert_eq!(body, None);
        assert!(roles.iter().all(|end_role| end_role.cid == GROUP_AID));
        if let Some(role) = &role {
            assert!(roles.iter().all(|end_role| &end_role.role == role));
        }
    }

    let unfiltered = request_of(&fixture, "endroles_without_role")?;
    let filtered = request_of(&fixture, "endroles_with_role")?;
    assert_eq!(unfiltered.path, format!("/endroles/{GROUP_AID}"));
    assert_eq!(filtered.path, format!("/endroles/{GROUP_AID}/agent"));

    assert_eq!(
        call(&fixture, "endroles_mailbox")?.result.as_array().map(Vec::len),
        Some(0)
    );
    Ok(())
}

#[test]
fn the_unknown_aid_the_reference_asks_about_is_not_a_prefix() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = request_of(&fixture, "endroles_unknown_aid")?;
    assert_eq!(UNKNOWN_AID.len(), 43);
    assert_eq!(GROUP_AID.len(), 44);
    assert_eq!(recorded.path, format!("/endroles/{UNKNOWN_AID}"));
    assert!(IdentifierPrefix::from_qb64(UNKNOWN_AID).is_err());

    let valid = request_of(&fixture, "endroles_unknown_valid_aid")?;
    assert_eq!(valid.path, format!("/endroles/{UNKNOWN_VALID_AID}"));
    let answer = answer_of(&fixture, "endroles_unknown_valid_aid")?;
    let (client, transport) = connected(&[&answer])?;
    let roles = block_on(client.oobis().end_roles(&prefix(UNKNOWN_VALID_AID)?, None))?;
    assert_eq!(roles, [] as [EndRole; 0]);
    assert_eq!(sent(&transport)?.0, valid.path);
    Ok(())
}

#[test]
fn an_aid_or_a_role_filter_that_would_escape_the_path_is_unrepresentable() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let escaping_aid = request_of(&fixture, "endroles_aid_needing_encoding")?;
    assert_eq!(escaping_aid.path, "/endroles/a/b?c=d");
    assert!(IdentifierPrefix::from_qb64("a/b?c=d").is_err());

    let escaping_role = request_of(&fixture, "endroles_role_needing_encoding")?;
    assert_eq!(escaping_role.path, format!("/endroles/{GROUP_AID}/../identifiers"));

    let role = Role::Other("../identifiers".to_owned());
    let (client, transport) = connected(&[b"[]"])?;
    block_on(client.oobis().end_roles(&prefix(GROUP_AID)?, Some(&role)))?;
    let (path, _, _) = sent(&transport)?;
    assert_eq!(path, format!("/endroles/{GROUP_AID}/..%2Fidentifiers"));
    assert_ne!(path, escaping_role.path);
    Ok(())
}

#[test]
fn a_wrong_shaped_end_role_listing_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "endroles_wrong_shape")?;
    assert_eq!(recorded.error, None);
    assert_eq!(
        recorded
            .result
            .as_array()
            .and_then(|records| records.first())
            .and_then(|record| record.as_object())
            .map(serde_json::Map::len),
        Some(1)
    );

    let answer = serde_json::to_vec(&recorded.result)?;
    let (client, transport) = connected(&[&answer])?;
    let outcome = block_on(client.oobis().end_roles(&prefix(GROUP_AID)?, None));
    assert!(
        matches!(outcome, Err(ClientError::Api { .. })),
        "an end role missing its role and endpoint was not refused: {outcome:?}"
    );
    assert_eq!(sent(&transport)?.0, format!("/endroles/{GROUP_AID}"));
    Ok(())
}
