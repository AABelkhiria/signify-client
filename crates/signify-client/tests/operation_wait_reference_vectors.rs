//! Exact polling vectors recorded from the pinned reference's own `Operations.wait`.
//!
//! What each shape costs in requests and in what order, when the dependency is walked, and which exits throw.

mod support;

use core::time::Duration;
use std::error::Error;
use std::future::Future;
use std::sync::Arc;
use std::time::SystemTime;

use crate::support::{ADMIN, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on};
use keria_types::api::{KelMetadata, KelResponse, Operation, OperationOutcome, RegistryMetadata};
use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::error::ClientError;
use signify_client::operation::{DEFAULT_DEADLINE, PollPolicy, Poller, PollingLimit};
use signify_http::retry::{Clock, FixedJitter, Jitter, TestClock};
use signify_http::transport::Transport;
use signify_keys::manager::DerivationCost;

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/client-operation-wait/v1.json"
));

const NAME: &str = "witness.EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1.0";
const DEPENDENCY: &str = "witness.EABC.0";
const REGISTRY: &str = "registry.EREG";

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
    operation_name: String,
    dependency_name: String,
    registry_name: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Declarations {
    wait_body: String,
    wait_overloads: usize,
    wait_defaults: WaitDefaults,
    wait_delay: String,
    wait_dependency_guard: String,
    wait_loop: String,
    wait_abort: String,
    has_depends_body: String,
    throw_if_failed_body: String,
    integration_wait_operation: String,
    integration_delete_operations: String,
}

#[derive(Debug, Deserialize)]
struct WaitDefaults {
    min_sleep: String,
    max_sleep: String,
    increase_factor: String,
}

#[derive(Debug, Deserialize)]
struct Call {
    name: String,
    note: String,
    requests: Vec<RecordedRequest>,
    request_count: usize,
    delays_ms: Vec<u64>,
    result: Value,
    returned_the_same_object: Option<bool>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    path: String,
    method: String,
}

#[derive(Debug, Deserialize)]
struct PinnedConfirmations {
    integration_timeout: String,
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

type Harness = (ConnectedClient, Arc<AgentTransport>, Arc<TestClock>);

fn connected(bodies: &[&[u8]]) -> Result<Harness, Box<dyn Error>> {
    let configuration = || {
        ClientConfig::new(ADMIN, PASSCODE)
            .and_then(|config| config.with_boot_url(BOOT))
            .map(|config| config.with_derivation_cost(DerivationCost::Ephemeral))
    };
    let clock = Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(FIXED_MILLIS),
    ));
    let probe = SignifyClient::new(
        configuration()?,
        AgentTransport::new(&[]) as Arc<dyn Transport>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )?;
    let prefix = probe.controller().prefix().qb64()?;
    let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();

    let state = agent_state(&prefix, &inception);
    let mut answers: Vec<&[u8]> = vec![state.as_bytes(), b"{}"];
    answers.extend_from_slice(bodies);
    let transport = AgentTransport::new(&answers);
    transport.repeating_last();

    let client = SignifyClient::new(
        configuration()?,
        Arc::clone(&transport) as Arc<dyn Transport>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )?;
    let connected = block_on(client.connect())?;
    Ok((connected, transport, clock))
}

fn reference_poller(client: &ConnectedClient) -> Result<Poller<'_>, Box<dyn Error>> {
    let policy = PollPolicy::builder()
        .jitter(Jitter::None)
        .without_deadline()
        .max_attempts(64)
        .build()?;
    Ok(client
        .poller()
        .with_policy(policy)
        .with_jitter_source(Arc::new(FixedJitter::new(0))))
}

fn pending(name: &str) -> String {
    format!(r#"{{"name":"{name}","done":false}}"#)
}

fn done(name: &str) -> String {
    format!(r#"{{"name":"{name}","done":true,"response":{{}}}}"#)
}

fn failed(name: &str, code: i64, message: &str) -> String {
    format!(r#"{{"name":"{name}","done":true,"error":{{"code":{code},"message":"{message}"}}}}"#)
}

fn key_event() -> String {
    r#"{"v":"KERI10JSON000000_","t":"ixn","d":"EDIG","i":"EPRE","s":"1","p":"EPRI","a":[]}"#.to_owned()
}

fn registry(dependency_done: bool, done_itself: bool) -> String {
    let depends = if dependency_done {
        format!(
            r#"{{"name":"{DEPENDENCY}","done":true,"response":{event}}}"#,
            event = key_event()
        )
    } else {
        pending(DEPENDENCY)
    };
    let metadata =
        format!(r#""metadata":{{"pre":"EPRE","depends":{depends},"anchor":{{"i":"EPRE","s":"0","d":"EANCHOR"}}}}"#);
    if done_itself {
        format!(
            r#"{{"name":"{REGISTRY}",{metadata},"done":true,"response":{{"anchor":{{"i":"EPRE","s":"0","d":"EANCHOR"}}}}}}"#
        )
    } else {
        format!(r#"{{"name":"{REGISTRY}",{metadata},"done":false}}"#)
    }
}

fn snapshot<M: serde::de::DeserializeOwned, R: serde::de::DeserializeOwned>(
    body: &str,
) -> Result<Operation<M, R>, Box<dyn Error>> {
    Ok(serde_json::from_str(body)?)
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
    assert!(fixture.sources.iter().any(|source| source.ends_with("test-util.ts")));
    assert_eq!(fixture.provenance.operation_name, NAME);
    assert_eq!(fixture.provenance.dependency_name, DEPENDENCY);
    assert_eq!(fixture.provenance.registry_name, REGISTRY);
    assert!(fixture.provenance.note.contains("global timer replaced"));

    assert_eq!(fixture.calls.len(), 15);
    for entry in &fixture.calls {
        assert!(!entry.note.is_empty(), "call {} records no note", entry.name);
        assert_eq!(
            entry.requests.len(),
            entry.request_count,
            "call {} disagrees with its own request count",
            entry.name
        );
        for request in &entry.requests {
            assert_eq!(request.method, "GET");
            assert!(
                request.path.starts_with("/operations/"),
                "a poll addressed {}",
                request.path
            );
        }
    }
    Ok(())
}

#[test]
fn the_ported_declarations_are_the_references_own() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    assert_eq!(
        declarations.wait_defaults.min_sleep,
        "minSleep = options.minSleep ?? 10"
    );
    assert_eq!(
        declarations.wait_defaults.max_sleep,
        "maxSleep = options.maxSleep ?? 10000"
    );
    assert_eq!(
        declarations.wait_defaults.increase_factor,
        "increaseFactor = options.increaseFactor ?? 50"
    );

    assert_eq!(
        declarations.wait_delay,
        "delay = Math.max( minSleep, Math.min(maxSleep, 2 ** retries * increaseFactor) )"
    );

    assert!(declarations.wait_loop.starts_with("while (true)"));
    assert!(!declarations.wait_body.contains("Date.now()"));
    assert!(!declarations.wait_body.contains("maxRetries"));
    assert_eq!(declarations.wait_abort, "options.signal?.throwIfAborted();");
    let slept = declarations
        .wait_body
        .find("setTimeout")
        .ok_or("the sleep moved out of the loop")?;
    let aborted = declarations
        .wait_body
        .find("throwIfAborted")
        .ok_or("the abort check moved out of the loop")?;
    assert!(slept < aborted, "the abort is no longer read after the sleep");

    assert!(declarations.wait_dependency_guard.contains("!op.metadata.depends.done"));
    assert_eq!(
        declarations.has_depends_body,
        "{ return op.metadata !== undefined && 'depends' in op.metadata; }"
    );
    assert!(declarations.throw_if_failed_body.contains("op.error !== null"));

    assert_eq!(declarations.wait_overloads, 16);

    assert!(
        declarations
            .integration_wait_operation
            .contains("AbortSignal.timeout(30000)")
    );
    assert!(declarations.integration_delete_operations.contains("deleteOperations"));
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

// --- The five pinned cases ---
#[test]
fn an_already_finished_operation_costs_no_request() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "already_done")?;
    assert_eq!(recorded.request_count, 0);
    assert_eq!(recorded.returned_the_same_object, Some(true));

    let (client, transport, clock) = connected(&[])?;
    let operation: Operation<Value, Value> = snapshot(&done(NAME))?;
    let finished = block_on(reference_poller(&client)?.wait(operation))?;

    assert!(transport.endpoint_calls().is_empty(), "a finished snapshot was polled");
    assert_eq!(clock.recorded_sleeps(), [] as [Duration; 0]);
    assert_eq!(finished.name(), NAME);
    assert_eq!(*finished.response(), serde_json::json!({}));
    Ok(())
}

#[test]
fn an_operation_done_after_one_poll_makes_one_request() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "done_after_first_poll")?;
    assert_eq!(recorded.request_count, 1);
    assert!(recorded.delays_ms.is_empty(), "the reference slept before returning");

    let answer = done(NAME);
    let (client, transport, clock) = connected(&[answer.as_bytes()])?;
    let operation: Operation<Value, Value> = snapshot(&pending(NAME))?;
    block_on(reference_poller(&client)?.wait(operation))?;

    assert_eq!(
        transport.endpoint_calls(),
        [("GET".to_owned(), format!("/operations/{NAME}"))]
    );
    assert_eq!(clock.recorded_sleeps(), [] as [Duration; 0]);
    Ok(())
}

#[test]
fn an_operation_done_after_two_polls_makes_two_requests_and_sleeps_once() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "done_after_second_poll")?;
    assert_eq!(recorded.request_count, 2);
    assert_eq!(recorded.delays_ms, [10]);

    let pending_body = pending(NAME);
    let done_body = done(NAME);
    let (client, transport, clock) = connected(&[pending_body.as_bytes(), done_body.as_bytes()])?;
    let policy = PollPolicy::builder()
        .max_delay(Duration::from_millis(10))
        .jitter(Jitter::None)
        .without_deadline()
        .max_attempts(64)
        .build()?;
    let poller = client.poller().with_policy(policy);
    let operation: Operation<Value, Value> = snapshot(&pending(NAME))?;
    block_on(poller.wait(operation))?;

    assert_eq!(transport.endpoint_calls().len(), 2);
    assert_eq!(clock.recorded_sleeps(), [Duration::from_millis(10)]);
    Ok(())
}

#[test]
fn a_dependency_is_polled_to_completion_before_its_parent() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "dependency_polled_first")?;
    assert_eq!(recorded.request_count, 4);
    assert_eq!(recorded.delays_ms, [10, 10]);
    let paths: Vec<&str> = recorded.requests.iter().map(|request| request.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            &format!("/operations/{DEPENDENCY}")[..],
            &format!("/operations/{DEPENDENCY}")[..],
            &format!("/operations/{REGISTRY}")[..],
            &format!("/operations/{REGISTRY}")[..],
        ]
    );

    let answers = [
        pending(DEPENDENCY),
        format!(
            r#"{{"name":"{DEPENDENCY}","done":true,"response":{event}}}"#,
            event = key_event()
        ),
        registry(true, false),
        registry(true, true),
    ];
    let bodies: Vec<&[u8]> = answers.iter().map(String::as_bytes).collect();
    let (client, transport, clock) = connected(&bodies)?;
    let policy = PollPolicy::builder()
        .max_delay(Duration::from_millis(10))
        .jitter(Jitter::None)
        .without_deadline()
        .max_attempts(64)
        .build()?;
    let operation: Operation<RegistryMetadata, Value> = snapshot(&registry(false, false))?;
    let finished = block_on(client.poller().with_policy(policy).wait(operation))?;

    assert_eq!(
        transport.endpoint_calls(),
        paths
            .iter()
            .map(|path| ("GET".to_owned(), (*path).to_owned()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        clock.recorded_sleeps(),
        [Duration::from_millis(10), Duration::from_millis(10)]
    );
    assert_eq!(finished.name(), REGISTRY);
    Ok(())
}

#[test]
fn a_dependency_the_snapshot_reports_finished_is_never_polled() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "dependency_already_done")?;
    assert_eq!(recorded.request_count, 1);
    assert_eq!(
        recorded.requests.first().map(|request| request.path.as_str()),
        Some(&format!("/operations/{REGISTRY}")[..])
    );

    let answer = registry(true, true);
    let (client, transport, _) = connected(&[answer.as_bytes()])?;
    let operation: Operation<RegistryMetadata, Value> = snapshot(&registry(true, false))?;
    block_on(reference_poller(&client)?.wait(operation))?;

    assert_eq!(
        transport.endpoint_calls(),
        [("GET".to_owned(), format!("/operations/{REGISTRY}"))]
    );
    Ok(())
}

// --- The branches the pinned test does not reach ---
#[test]
fn a_dependency_that_finished_unsuccessfully_is_skipped_in_silence() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "dependency_done_but_failed")?;
    assert_eq!(recorded.request_count, 1);
    assert_eq!(recorded.error, None);

    let depends = failed(DEPENDENCY, 500, "witness receipts timed out");
    let parent = format!(
        r#"{{"name":"{REGISTRY}","metadata":{{"pre":"EPRE","depends":{depends},"anchor":{{"i":"EPRE","s":"0","d":"EANCHOR"}}}},"done":false}}"#
    );
    let answer = registry(true, true);
    let (client, transport, _) = connected(&[answer.as_bytes()])?;
    let operation: Operation<RegistryMetadata, Value> = snapshot(&parent)?;
    let finished = block_on(reference_poller(&client)?.wait(operation))?;

    assert_eq!(transport.endpoint_calls().len(), 1);
    assert_eq!(finished.name(), REGISTRY);
    Ok(())
}

#[test]
fn a_dependency_that_fails_while_polled_surfaces_under_its_own_name() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "dependency_fails_while_polled")?;
    assert_eq!(recorded.request_count, 1);
    let message = recorded
        .error
        .as_deref()
        .ok_or("the dependency's failure was not raised")?;
    assert!(message.contains(DEPENDENCY), "{message}");
    assert!(!message.contains(REGISTRY), "{message}");

    let answer = failed(DEPENDENCY, 500, "witness receipts timed out");
    let (client, transport, _) = connected(&[answer.as_bytes()])?;
    let operation: Operation<RegistryMetadata, Value> = snapshot(&registry(false, false))?;
    let outcome = block_on(reference_poller(&client)?.wait(operation));

    match outcome {
        Err(ClientError::OperationFailed {
            name, code, message, ..
        }) => {
            assert_eq!(name, DEPENDENCY);
            assert_eq!(code, 500);
            assert_eq!(message, "witness receipts timed out");
        }
        other => return Err(format!("a failed dependency was not raised: {other:?}").into()),
    }
    assert_eq!(transport.endpoint_calls().len(), 1);
    Ok(())
}

#[test]
fn an_already_failed_operation_throws_before_asking() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "already_failed")?;
    assert_eq!(recorded.request_count, 0);
    let message = recorded.error.as_deref().ok_or("the failure was not raised")?;
    assert!(message.contains("[Code 400]"), "{message}");
    assert!(message.contains("bad witness threshold"), "{message}");

    let (client, transport, _) = connected(&[])?;
    let operation: Operation<Value, Value> = snapshot(&failed(NAME, 400, "bad witness threshold"))?;
    let outcome = block_on(reference_poller(&client)?.wait(operation));

    assert!(
        matches!(outcome, Err(ClientError::OperationFailed { code: 400, .. })),
        "{outcome:?}"
    );
    assert!(transport.endpoint_calls().is_empty(), "a failed snapshot was polled");
    Ok(())
}

#[test]
fn a_failure_found_by_polling_keeps_its_parts_apart() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let plain = call(&fixture, "fails_while_polling")?;
    let detailed = call(&fixture, "fails_with_details")?;
    let plain_message = plain.error.as_deref().unwrap_or_default();
    let detailed_message = detailed.error.as_deref().unwrap_or_default();
    assert!(plain_message.starts_with(&format!("Operation '{NAME}' failed [Code 500]:")));
    assert!(!plain_message.contains("Details:"));
    assert!(detailed_message.contains(r#"Details: {"witnesses":["BABC"],"received":1}"#));

    let answer = failed(NAME, 500, "witness receipts timed out");
    let (client, _, _) = connected(&[answer.as_bytes()])?;
    let operation: Operation<Value, Value> = snapshot(&pending(NAME))?;
    let outcome = block_on(reference_poller(&client)?.wait(operation));

    match outcome {
        Err(ClientError::OperationFailed {
            name,
            code,
            message,
            details,
        }) => {
            assert_eq!(name, NAME);
            assert_eq!(code, 500);
            assert_eq!(message, "witness receipts timed out");
            assert_eq!(details, None);
        }
        other => return Err(format!("a failure was not raised: {other:?}").into()),
    }
    Ok(())
}

#[test]
fn a_metadata_block_with_no_dependency_skips_the_guard() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    for name in ["metadata_without_depends", "dependency_null"] {
        let recorded = call(&fixture, name)?;
        assert_eq!(recorded.request_count, 1, "{name}");
    }

    let body = format!(
        r#"{{"name":"{REGISTRY}","metadata":{{"pre":"EPRE","depends":null,"anchor":{{"i":"EPRE","s":"0","d":"EA"}}}},"done":false}}"#
    );
    let answer = done(REGISTRY);
    let (client, transport, _) = connected(&[answer.as_bytes()])?;
    let operation: Operation<Value, Value> = snapshot(&body)?;
    block_on(reference_poller(&client)?.wait(operation))?;
    assert_eq!(transport.endpoint_calls().len(), 1);
    Ok(())
}

#[test]
fn the_long_run_reproduces_the_recorded_delay_schedule() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "long_run_reaches_the_ceiling")?;
    assert_eq!(recorded.request_count, 13);
    assert_eq!(
        recorded.delays_ms,
        [50, 100, 200, 400, 800, 1600, 3200, 6400, 10_000, 10_000, 10_000, 10_000]
    );

    let mut bodies: Vec<String> = (0..12).map(|_| pending(NAME)).collect();
    bodies.push(done(NAME));
    let answers: Vec<&[u8]> = bodies.iter().map(String::as_bytes).collect();
    let (client, transport, clock) = connected(&answers)?;
    let operation: Operation<Value, Value> = snapshot(&pending(NAME))?;
    block_on(reference_poller(&client)?.wait(operation))?;

    assert_eq!(transport.endpoint_calls().len(), 13);
    let slept: Vec<u128> = clock.recorded_sleeps().iter().map(Duration::as_millis).collect();
    let expected: Vec<u128> = recorded.delays_ms.iter().map(|delay| u128::from(*delay)).collect();
    assert_eq!(slept, expected, "the recorded schedule no longer reproduces");
    Ok(())
}

// --- What this port does and the reference does not ---
#[test]
fn an_operation_that_never_finishes_stops_on_the_attempt_bound() -> Result<(), Box<dyn Error>> {
    let answer = pending(NAME);
    let (client, transport, _) = connected(&[answer.as_bytes()])?;
    let policy = PollPolicy::builder()
        .jitter(Jitter::None)
        .without_deadline()
        .max_attempts(4)
        .build()?;
    let operation: Operation<Value, Value> = snapshot(&pending(NAME))?;
    let outcome = block_on(client.poller().with_policy(policy).wait(operation));

    match outcome {
        Err(ClientError::PollingStopped {
            name, limit, attempts, ..
        }) => {
            assert_eq!(name, NAME);
            assert_eq!(limit, PollingLimit::Attempts);
            assert_eq!(attempts, 4);
        }
        other => return Err(format!("an unfinishable operation did not stop: {other:?}").into()),
    }
    assert_eq!(transport.endpoint_calls().len(), 4);
    Ok(())
}

#[test]
fn an_operation_that_never_finishes_stops_on_the_deadline() -> Result<(), Box<dyn Error>> {
    let answer = pending(NAME);
    let (client, transport, clock) = connected(&[answer.as_bytes()])?;
    let policy = PollPolicy::builder()
        .jitter(Jitter::None)
        .deadline(Duration::from_millis(400))
        .max_attempts(64)
        .build()?;
    let operation: Operation<Value, Value> = snapshot(&pending(NAME))?;
    let outcome = block_on(client.poller().with_policy(policy).wait(operation));

    match outcome {
        Err(ClientError::PollingStopped {
            limit,
            attempts,
            elapsed,
            ..
        }) => {
            assert_eq!(limit, PollingLimit::Deadline);
            assert_eq!(attempts, 4);
            assert!(elapsed < Duration::from_millis(400), "{elapsed:?}");
        }
        other => return Err(format!("a deadline did not stop the poll: {other:?}").into()),
    }
    assert_eq!(transport.endpoint_calls().len(), 4);
    assert_eq!(
        clock.recorded_sleeps(),
        [
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_millis(200)
        ]
    );
    Ok(())
}

#[test]
fn the_default_deadline_is_the_references_own_integration_timeout() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(
        fixture
            .pinned_confirmations
            .integration_timeout
            .contains("AbortSignal.timeout(30000)")
    );
    assert_eq!(DEFAULT_DEADLINE, Duration::from_secs(30));
    assert_eq!(PollPolicy::default().deadline(), Some(DEFAULT_DEADLINE));
    Ok(())
}

#[test]
fn a_finished_operation_with_no_response_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "done_after_first_poll")?;
    assert_eq!(
        recorded.result.get("done").and_then(Value::as_bool),
        Some(true),
        "the reference returned something else"
    );
    assert!(
        recorded.result.get("response").is_none(),
        "the reference's own answer now carries a response"
    );

    let literal = format!(r#"{{"name":"{NAME}","done":true}}"#);
    assert!(serde_json::from_str::<Operation<Value, Value>>(&literal).is_err());

    let (client, transport, _) = connected(&[literal.as_bytes()])?;
    let operation: Operation<Value, Value> = snapshot(&pending(NAME))?;
    let outcome = block_on(reference_poller(&client)?.wait(operation));
    assert!(matches!(outcome, Err(ClientError::Api { .. })), "{outcome:?}");
    assert_eq!(transport.endpoint_calls().len(), 1);
    Ok(())
}

#[test]
fn a_completed_operation_carrying_a_null_error_is_not_a_failure() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "error_null_is_not_a_failure")?;
    assert_eq!(recorded.error, None, "the reference treated a null error as a failure");

    let answer = format!(r#"{{"name":"{NAME}","done":true,"response":{{}},"error":null}}"#);
    let (client, _, _) = connected(&[answer.as_bytes()])?;
    let operation: Operation<Value, Value> = snapshot(&pending(NAME))?;
    let finished = block_on(reference_poller(&client)?.wait(operation))?;
    assert_eq!(finished.name(), NAME);
    Ok(())
}

#[test]
fn dropping_the_future_stops_the_poll_at_once() -> Result<(), Box<dyn Error>> {
    use core::task::{Context, Poll, Waker};

    #[derive(Debug)]
    struct StallingClock {
        inner: TestClock,
    }

    impl Clock for StallingClock {
        fn now(&self) -> std::time::Instant {
            self.inner.now()
        }

        fn sleep(&self, _duration: Duration) -> signify_http::retry::SleepFuture<'_> {
            Box::pin(core::future::pending())
        }

        fn wall_clock(&self) -> SystemTime {
            self.inner.wall_clock()
        }
    }

    let configuration = || {
        ClientConfig::new(ADMIN, PASSCODE)
            .and_then(|config| config.with_boot_url(BOOT))
            .map(|config| config.with_derivation_cost(DerivationCost::Ephemeral))
    };
    let clock: Arc<dyn Clock> = Arc::new(StallingClock {
        inner: TestClock::with_wall_clock(SystemTime::UNIX_EPOCH + Duration::from_millis(FIXED_MILLIS)),
    });
    let probe = SignifyClient::new(
        configuration()?,
        AgentTransport::new(&[]) as Arc<dyn Transport>,
        Arc::clone(&clock),
    )?;
    let prefix = probe.controller().prefix().qb64()?;
    let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();
    let state = agent_state(&prefix, &inception);
    let pending_body = pending(NAME);
    let transport = AgentTransport::new(&[state.as_bytes(), b"{}", pending_body.as_bytes()]);
    transport.repeating_last();
    let client = SignifyClient::new(
        configuration()?,
        Arc::clone(&transport) as Arc<dyn Transport>,
        Arc::clone(&clock),
    )?;
    let connected = block_on(client.connect())?;

    let operation: Operation<Value, Value> = snapshot(&pending(NAME))?;
    let poller = connected.poller();
    let mut future = Box::pin(poller.wait(operation));
    let mut context = Context::from_waker(Waker::noop());

    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(transport.endpoint_calls().len(), 1);

    drop(future);
    assert_eq!(
        transport.endpoint_calls().len(),
        1,
        "a dropped poll asked the agent again"
    );
    Ok(())
}

#[test]
fn waiting_by_name_reads_the_operation_first() -> Result<(), Box<dyn Error>> {
    let first = pending(NAME);
    let second = done(NAME);
    let (client, transport, _) = connected(&[first.as_bytes(), second.as_bytes()])?;
    let finished = block_on(reference_poller(&client)?.wait_named::<Value, Value>(NAME))?;

    assert_eq!(finished.name(), NAME);
    assert_eq!(transport.endpoint_calls().len(), 2);
    Ok(())
}

#[test]
fn a_typed_dependency_is_always_a_key_event_operation() -> Result<(), Box<dyn Error>> {
    let body = format!(r#"{{"name":"{DEPENDENCY}","done":false}}"#);
    let dependency: Operation<KelMetadata, KelResponse> = serde_json::from_str(&body)?;
    assert!(matches!(dependency.outcome, OperationOutcome::Pending));

    let parent: Operation<RegistryMetadata, Value> = snapshot(&registry(false, false))?;
    let names = parent.metadata.map(|metadata| metadata.depends.name.clone());
    assert_eq!(names.as_deref(), Some(DEPENDENCY));
    Ok(())
}
