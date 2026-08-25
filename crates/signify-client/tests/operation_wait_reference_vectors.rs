//! Exact polling vectors recorded from the pinned reference's own `Operations.wait`.
//!
//! Roadmap 5.4 already reproduces this function's **delay schedule**, recorded by executing it with
//! the global timer replaced. What is checked here is everything else the loop does: how many
//! requests each shape costs and in what order, when the dependency is walked and when it is
//! skipped, which exits throw, and what the failure carries.
//!
//! The pinned `coring.test.ts` has five `wait` cases, four of which assert an **exact request
//! count**. Every one of those counts is reproduced here, against the same counts driven out of the
//! reference itself.

use core::time::Duration;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde::Deserialize;
use serde_json::Value;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::error::ClientError;
use signify_client::operation::{DEFAULT_DEADLINE, PollPolicy, Poller, PollingLimit};
use signify_crypto::signer::Signer;
use signify_crypto::verifier::KeyTransferability;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, FixedJitter, Jitter, TestClock};
use signify_http::signature::authentication::RequestSigner;
use signify_http::signature::input::{RequestTarget, default_components};
use signify_http::signature::timestamp::SignifyTimestamp;
use signify_http::transport::{Method, Request, Response, StatusCode, Transport, TransportError, TransportFuture};
use signify_keri::manager::DerivationCost;
use signify_types::api::{KelMetadata, KelResponse, Operation, OperationOutcome, RegistryMetadata};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/client-operation-wait/v1.json");

const ADMIN: &str = "http://127.0.0.1:3901";
const BOOT: &str = "http://127.0.0.1:3903";
const PASSCODE: &str = "0123456789abcdefghijk";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";

/// The names the generator drives the reference with.
const NAME: &str = "witness.EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1.0";
const DEPENDENCY: &str = "witness.EABC.0";
const REGISTRY: &str = "registry.EREG";

const AGENT_SEED: [u8; 32] = [
    187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192, 61, 145, 222, 110, 59, 160, 152, 2, 72, 122, 87,
    143, 109, 39, 98, 153, 192, 148,
];

const FIXED_MILLIS: u64 = 1_700_000_000_123;

// ---------------------------------------------------------------------------
// Fixture model.
// ---------------------------------------------------------------------------

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
    #[serde(rename = "depends_declarations")]
    depends_owners: Vec<DependsOwner>,
    kel_operation_schema: String,
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
struct DependsOwner {
    owner: String,
    declaration: String,
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
    unit_test_cases: Vec<UnitTestCase>,
    asserted_request_counts: Vec<String>,
    returns_the_same_object: bool,
    wait_call_sites: Scan,
    integration_wait_call_sites: Scan,
    integration_timeout: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct UnitTestCase {
    title: String,
    expects: Option<usize>,
    driven: String,
    reproduced: Option<usize>,
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

// ---------------------------------------------------------------------------
// A KERIA agent answering a queue of operation states.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct AgentTransport {
    answers: Mutex<Vec<Vec<u8>>>,
    recorded: Mutex<Vec<Request>>,
}

impl AgentTransport {
    fn new(answers: &[&[u8]]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().rev().map(|body| body.to_vec()).collect()),
            recorded: Mutex::new(Vec::new()),
        })
    }

    fn requests(&self) -> Vec<Request> {
        self.recorded.lock().map_or_else(|_| Vec::new(), |guard| guard.clone())
    }

    /// Every endpoint request after the lifecycle's two, as `(method, path)`.
    fn endpoint_calls(&self) -> Vec<(String, String)> {
        self.requests()
            .iter()
            .skip(2)
            .map(|request| {
                let url = request.url().as_str();
                (
                    request.method().as_str().to_owned(),
                    url.strip_prefix(ADMIN).unwrap_or(url).to_owned(),
                )
            })
            .collect()
    }

    /// Pops the next answer, repeating the last one once the queue is down to it.
    fn answer(&self, request: &Request) -> Result<Response, TransportError> {
        let body = {
            let mut queue = self
                .answers
                .lock()
                .map_err(|_| TransportError::signing("the scripted answers are poisoned"))?;
            if queue.len() > 1 {
                queue.pop().unwrap_or_default()
            } else {
                queue.last().cloned().unwrap_or_else(|| b"{}".to_vec())
            }
        };
        signed_response(request.method(), request.url().path(), body)
            .map_err(|error| TransportError::signing(error.to_string()))
    }
}

impl Transport for AgentTransport {
    fn execute(&self, request: Request) -> TransportFuture<'_> {
        let answer = {
            if let Ok(mut guard) = self.recorded.lock() {
                guard.push(request.clone());
            }
            self.answer(&request)
        };
        let future: Pin<Box<dyn Future<Output = Result<Response, TransportError>> + Send + '_>> =
            Box::pin(async move { answer });
        future
    }
}

fn agent_signer() -> Result<Signer, Box<dyn Error>> {
    Ok(Signer::from_seed(&AGENT_SEED, KeyTransferability::NonTransferable)?)
}

fn signed_response(method: Method, path: &str, body: Vec<u8>) -> Result<Response, Box<dyn Error>> {
    let stamp = SignifyTimestamp::from_unix(Duration::from_millis(FIXED_MILLIS))?;
    let mut headers = Headers::new();
    headers.insert(HeaderName::new("signify-resource")?, HeaderValue::new(AGENT)?)?;
    headers.insert(HeaderName::new("signify-timestamp")?, stamp.to_header_value()?)?;
    let signer = RequestSigner::new(agent_signer()?);
    let input = signer.signature_input(default_components()?, stamp.created())?;
    let target = RequestTarget::new(method.as_str(), path)?;
    signer.sign(&input, &target, &headers)?.apply(&mut headers)?;
    Ok(Response::new(StatusCode::new(202)?, headers, body)?)
}

fn block_on<F: Future>(future: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
}

fn agent_verification_key() -> String {
    agent_signer()
        .and_then(|signer| Ok(signer.verifier().qb64()?))
        .unwrap_or_default()
}

fn agent_state(controller: &str, inception: &str) -> String {
    let agent = format!(
        r#"{{"vn":[1,0],"i":"{AGENT}","s":"0","p":"","d":"{AGENT}","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1","k":["{key}"],"nt":"1","n":["EL6zVoZ0F8OXcbXP4LOm5oJTxCXP6ZLp5o3vNfvVZ9YB"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{AGENT}","br":[],"ba":[]}},"di":"{controller}"}}"#,
        key = agent_verification_key()
    );
    format!(r#"{{"agent":{agent},"controller":{{"state":{agent},"ee":{inception}}},"ridx":0,"pidx":0}}"#)
}

/// A connected client, the transport recording its requests, and the clock recording its sleeps.
type Harness = (ConnectedClient, Arc<AgentTransport>, Arc<TestClock>);

/// A connected client whose clock is a [`TestClock`], so every sleep is instant and recorded.
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

    let client = SignifyClient::new(
        configuration()?,
        Arc::clone(&transport) as Arc<dyn Transport>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )?;
    let connected = block_on(client.connect())?;
    // The lifecycle's own two requests are recorded before any poll, and its signing reads the
    // clock without sleeping, so the recorded sleeps below are the poll's alone.
    Ok((connected, transport, clock))
}

/// A poller reproducing the reference's schedule exactly: no jitter, no deadline, plenty of tries.
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

/// One pending operation body, of the shape the generator queued.
fn pending(name: &str) -> String {
    format!(r#"{{"name":"{name}","done":false}}"#)
}

/// One completed operation body. The reference's own queued bodies omit `response`, which
/// Roadmap 4.1 refuses; `a_finished_operation_with_no_response_is_refused` proves that separately.
fn done(name: &str) -> String {
    format!(r#"{{"name":"{name}","done":true,"response":{{}}}}"#)
}

/// One failed operation body.
fn failed(name: &str, code: i64, message: &str) -> String {
    format!(r#"{{"name":"{name}","done":true,"error":{{"code":{code},"message":"{message}"}}}}"#)
}

/// One interaction event, which is what a key-event operation completes with.
///
/// A `KelResponse` chooses its variant by the `t` field, so a dependency's response cannot be the
/// empty object the reference's own queued bodies use.
fn key_event() -> String {
    r#"{"v":"KERI10JSON000000_","t":"ixn","d":"EDIG","i":"EPRE","s":"1","p":"EPRI","a":[]}"#.to_owned()
}

/// A registry operation whose metadata names the key-event operation it waits on.
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
        format!(r#""metadata":{{"pre":"EPRE","depends":{depends},"anchor":{{"pre":"EPRE","sn":0,"d":"EANCHOR"}}}}"#);
    if done_itself {
        format!(
            r#"{{"name":"{REGISTRY}",{metadata},"done":true,"response":{{"anchor":{{"pre":"EPRE","sn":0,"d":"EANCHOR"}}}}}}"#
        )
    } else {
        format!(r#"{{"name":"{REGISTRY}",{metadata},"done":false}}"#)
    }
}

/// Builds the typed snapshot a caller would hold before waiting.
fn snapshot<M: serde::de::DeserializeOwned, R: serde::de::DeserializeOwned>(
    body: &str,
) -> Result<Operation<M, R>, Box<dyn Error>> {
    Ok(serde_json::from_str(body)?)
}

// ---------------------------------------------------------------------------
// Manifest and provenance.
// ---------------------------------------------------------------------------

#[test]
fn the_manifest_matches_the_pinned_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert!(fixture.upstream.contains("WebOfTrust/signify-ts"));
    assert!(!fixture.generated_on.is_empty());
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
        // Every request a poll makes is a read of one operation.
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

    // The three defaults this port's builder carries.
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

    // The formula Roadmap 5.4 reproduces, floor outside the ceiling.
    assert_eq!(
        declarations.wait_delay,
        "delay = Math.max( minSleep, Math.min(maxSleep, 2 ** retries * increaseFactor) )"
    );

    // The unbounded loop, and the abort read after it.
    assert!(declarations.wait_loop.starts_with("while (true)"));
    assert!(!declarations.wait_body.contains("Date.now()"));
    assert!(!declarations.wait_body.contains("maxRetries"));
    assert_eq!(declarations.wait_abort, "options.signal?.throwIfAborted();");
    // The abort appears *after* the sleep in the source text, which is the whole defect.
    let slept = declarations
        .wait_body
        .find("setTimeout")
        .ok_or("the sleep moved out of the loop")?;
    let aborted = declarations
        .wait_body
        .find("throwIfAborted")
        .ok_or("the abort check moved out of the loop")?;
    assert!(slept < aborted, "the abort is no longer read after the sleep");

    // The guard, and the run-time key test behind it.
    assert!(declarations.wait_dependency_guard.contains("!op.metadata.depends.done"));
    assert_eq!(
        declarations.has_depends_body,
        "{ return op.metadata !== undefined && 'depends' in op.metadata; }"
    );
    assert!(declarations.throw_if_failed_body.contains("op.error !== null"));

    // Sixteen declarations of `wait`: fifteen overloads and the implementation.
    assert_eq!(declarations.wait_overloads, 16);

    // The integration helper, whose timeout becomes this port's default deadline.
    assert!(
        declarations
            .integration_wait_operation
            .contains("AbortSignal.timeout(30000)")
    );
    assert!(declarations.integration_delete_operations.contains("deleteOperations"));
    Ok(())
}

#[test]
fn the_dependency_chain_is_one_link_long() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let declarations = &fixture.declarations;

    // Exactly three schema shapes declare `depends`, and this list is exhaustive over the file.
    let mut owners: Vec<&str> = declarations
        .depends_owners
        .iter()
        .map(|entry| entry.owner.as_str())
        .collect();
    owners.sort_unstable();
    assert_eq!(
        owners,
        [
            "CredentialOperationMetadata",
            "DelegatorOperationMetadata",
            "RegistryOperationMetadata"
        ]
    );
    // All three type it as a `KelOperation`…
    for entry in &declarations.depends_owners {
        assert!(
            entry.declaration.contains("['KelOperation']"),
            "{} declares its dependency as something else",
            entry.owner
        );
    }
    // …and a `KelOperation` declares none of its own, so the recursion cannot go deeper.
    assert!(!declarations.kel_operation_schema.contains("depends"));
    // Which is exactly what the reference *writes* as recursion.
    assert!(
        declarations
            .wait_dependency_guard
            .contains("this.wait(op.metadata.depends")
    );
    Ok(())
}

#[test]
fn every_request_count_the_pinned_unit_test_asserts_is_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let pinned = &fixture.pinned_confirmations;

    assert_eq!(pinned.unit_test_cases.len(), 5);
    assert_eq!(pinned.asserted_request_counts.len(), 4);
    assert!(pinned.returns_the_same_object);
    assert!(pinned.integration_timeout.contains("AbortSignal.timeout(30000)"));
    assert!(!pinned.note.is_empty());

    // Every case with an asserted count reproduces it when the reference is driven.
    for entry in &pinned.unit_test_cases {
        if let Some(expected) = entry.expects {
            assert_eq!(
                entry.reproduced,
                Some(expected),
                "the case {:?} asserts {expected} requests",
                entry.title
            );
            let driven = call(&fixture, &entry.driven)?;
            assert_eq!(driven.request_count, expected);
        }
    }

    // `wait` itself is called directly only from those five cases and the integration helper;
    // everything else in the pinned tree goes through `waitOperation`, 262 times.
    assert_eq!(pinned.wait_call_sites.total, 6);
    assert!(pinned.integration_wait_call_sites.total > 200);
    assert!(pinned.wait_call_sites.scanned_files > 100);
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

// ---------------------------------------------------------------------------
// The five pinned cases.
// ---------------------------------------------------------------------------

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
    assert!(clock.recorded_sleeps().is_empty());
    // Returned by value, so the caller gets back exactly what it handed in.
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
    // A poll that finishes never sleeps, which is what the recorded empty schedule says.
    assert!(clock.recorded_sleeps().is_empty());
    Ok(())
}

#[test]
fn an_operation_done_after_two_polls_makes_two_requests_and_sleeps_once() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "done_after_second_poll")?;
    assert_eq!(recorded.request_count, 2);
    // The pinned case passes `maxSleep: 10`, so its one sleep is the ceiling.
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
    // The pinned `returns when child operation is also done` case: four requests, two sleeps.
    assert_eq!(recorded.request_count, 4);
    assert_eq!(recorded.delays_ms, [10, 10]);
    // The dependency's two come first, then the parent's two.
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

// ---------------------------------------------------------------------------
// The branches the pinned test does not reach.
// ---------------------------------------------------------------------------

#[test]
fn a_dependency_that_finished_unsuccessfully_is_skipped_in_silence() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let recorded = call(&fixture, "dependency_done_but_failed")?;
    // One request — the parent's. The failed dependency is passed over entirely, and nothing
    // upstream reports it.
    assert_eq!(recorded.request_count, 1);
    assert_eq!(recorded.error, None);

    let depends = failed(DEPENDENCY, 500, "witness receipts timed out");
    let parent = format!(
        r#"{{"name":"{REGISTRY}","metadata":{{"pre":"EPRE","depends":{depends},"anchor":{{"pre":"EPRE","sn":0,"d":"EANCHOR"}}}},"done":false}}"#
    );
    let answer = registry(true, true);
    let (client, transport, _) = connected(&[answer.as_bytes()])?;
    let operation: Operation<RegistryMetadata, Value> = snapshot(&parent)?;
    let finished = block_on(reference_poller(&client)?.wait(operation))?;

    // Reproduced exactly: the guard reads `done`, not success.
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
    // Upstream names the *dependency*, because the throw happens inside the recursive call.
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
    // The parent was never asked for.
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
    // Upstream interpolates all four values into one sentence, and appends the detail block whole.
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
            // Four separate values where the reference has one string.
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

    // An explicit `null` dependency and an absent one are the same value here.
    let body = format!(
        r#"{{"name":"{REGISTRY}","metadata":{{"pre":"EPRE","depends":null,"anchor":{{"pre":"EPRE","sn":0,"d":"EA"}}}},"done":false}}"#
    );
    let answer = done(REGISTRY);
    let (client, transport, _) = connected(&[answer.as_bytes()])?;
    let operation: Operation<Value, Value> = snapshot(&body)?;
    block_on(reference_poller(&client)?.wait(operation))?;
    assert_eq!(transport.endpoint_calls().len(), 1);
    Ok(())
}

#[test]
fn the_long_run_reproduces_the_schedule_roadmap_5_4_recorded() -> Result<(), Box<dyn Error>> {
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

// ---------------------------------------------------------------------------
// What this port does and the reference does not.
// ---------------------------------------------------------------------------

#[test]
fn an_operation_that_never_finishes_stops_on_the_attempt_bound() -> Result<(), Box<dyn Error>> {
    // Upstream is `while (true)`: this case does not terminate there at all.
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
            // 50 + 100 + 200 = 350 ms of sleeping; the next 400 ms wait would pass the budget, so
            // the poll stops rather than sleeping into it.
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
    // Three of the reference's own queued bodies are `{name, done: true}` with neither a response
    // nor an error — a shape Roadmap 4.1 refuses, because it leaves the outcome undecided. The
    // request counts above are therefore reproduced with well-formed bodies, and the reference's
    // own literal is proven refused here.
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
    // The request still went out, so this refuses the answer rather than the poll.
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

    /// A clock whose sleeps never complete, so a poll parks in its first wait.
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

    // One poll: the agent is asked once, the answer is still pending, and the wait parks.
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(transport.endpoint_calls().len(), 1);

    // Dropping cancels the outstanding sleep immediately. Upstream would have waited out the whole
    // delay — up to ten seconds — before reading its abort signal.
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
    // The `typeof op === 'string'` branch of the reference's own `waitOperation` helper.
    let first = pending(NAME);
    let second = done(NAME);
    let (client, transport, _) = connected(&[first.as_bytes(), second.as_bytes()])?;
    let finished = block_on(reference_poller(&client)?.wait_named::<Value, Value>(NAME))?;

    assert_eq!(finished.name(), NAME);
    // Two requests: the read that makes the snapshot, and the poll that finishes it.
    assert_eq!(transport.endpoint_calls().len(), 2);
    Ok(())
}

#[test]
fn a_typed_dependency_is_always_a_key_event_operation() -> Result<(), Box<dyn Error>> {
    // Which is what makes the chain one link long, checked here against the Rust types rather than
    // against the schema text.
    let body = format!(r#"{{"name":"{DEPENDENCY}","done":false}}"#);
    let dependency: Operation<KelMetadata, KelResponse> = serde_json::from_str(&body)?;
    assert!(matches!(dependency.outcome, OperationOutcome::Pending));

    let parent: Operation<RegistryMetadata, Value> = snapshot(&registry(false, false))?;
    let names = parent.metadata.map(|metadata| metadata.depends.name.clone());
    assert_eq!(names.as_deref(), Some(DEPENDENCY));
    Ok(())
}
