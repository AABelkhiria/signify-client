//! Every delay the pinned TypeScript reference waits, reproduced exactly.
//!
//! The reference has no retry module to compare against function by function, so the evidence is
//! its own behaviour: the production `Operations.wait` executed with its timer replaced, its
//! formula read from its own syntax tree, and a scan proving it never reads `Retry-After`.
//!
//! Every recorded schedule is reproduced here under [`Jitter::None`], which exists for exactly
//! this purpose — the default is jittered, because the reference's fixed schedule is a defect this
//! crate does not inherit.

use core::time::Duration;
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use serde::Deserialize;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{
    Clock, FixedJitter, GiveUpEvent, Jitter, RetryAfter, RetryAfterPolicy, RetryObserver, RetryPolicy, RetryScope,
    RetryingTransport, StopReason, TestClock,
};
use signify_http::transport::{Method, Request, RequestUrl, Response, ScriptedTransport, StatusCode, Transport};

const REFERENCE_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const FIXTURE: &str = include_str!("../../../fixtures/http-retry/v1.json");

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    generated_on: String,
    sources: Vec<String>,
    provenance: Provenance,
    wait_schedules: Vec<WaitSchedule>,
    integration_helper: IntegrationHelper,
    server_guidance_scan: GuidanceScan,
    reference_quirks: Quirks,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    operation_name: String,
    typescript_version: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct WaitSchedule {
    name: String,
    options: WaitOptions,
    polls: u32,
    done: bool,
    delays_ms: Vec<u64>,
    note: String,
}

#[derive(Debug, Default, Deserialize)]
struct WaitOptions {
    #[serde(rename = "minSleep")]
    min_sleep: Option<u64>,
    #[serde(rename = "maxSleep")]
    max_sleep: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct IntegrationHelper {
    path: String,
    defaults: BTreeMap<String, u64>,
    delay_expression: String,
    production_delay_expression: String,
    formulas_are_identical: bool,
    retries_on_any_error: bool,
    note: String,
}

#[derive(Debug, Deserialize)]
struct GuidanceScan {
    roots: Vec<String>,
    files_scanned: u32,
    matches: BTreeMap<String, u32>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Quirks {
    production_polling_is_unbounded: UnboundedQuirk,
    production_abort_is_checked_after_sleeping: OrderQuirk,
    helper_abort_differs_from_production: AbortQuirk,
    no_jitter_anywhere: ExpressionQuirk,
    server_guidance_is_ignored: GuidanceQuirk,
    min_sleep_cannot_bind_at_the_defaults: FloorQuirk,
    an_equal_floor_and_ceiling_flattens_the_curve: DelaysQuirk,
    the_ceiling_binds_and_the_delay_stops_growing: DelaysQuirk,
    every_failure_is_retried_by_the_helper: CatchQuirk,
}

#[derive(Debug, Deserialize)]
struct UnboundedQuirk {
    #[serde(rename = "loop")]
    loop_form: String,
    has_deadline: bool,
    has_attempt_cap: bool,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct OrderQuirk {
    order: Vec<String>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct AbortQuirk {
    helper_passes_signal: bool,
    production_passes_signal: bool,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct ExpressionQuirk {
    expression: String,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct GuidanceQuirk {
    matches: BTreeMap<String, u32>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct FloorQuirk {
    default_min_sleep: u64,
    default_increase_factor: u64,
    first_delay_ms: u64,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct DelaysQuirk {
    delays_ms: Vec<u64>,
    note: String,
    rust_decision: String,
}

#[derive(Debug, Deserialize)]
struct CatchQuirk {
    catches: String,
    note: String,
    rust_decision: String,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let fixture: Fixture = serde_json::from_str(FIXTURE)?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/signify-ts.git");
    assert_eq!(fixture.generated_on, "2026-08-23");
    assert_eq!(fixture.sources.len(), 2);
    assert!(fixture.sources.contains(&"src/keri/app/coring.ts".to_owned()));
    assert_eq!(fixture.provenance.operation_name, "witness.EPRE");
    assert_eq!(fixture.provenance.typescript_version, "5.9.2");
    assert_ne!(fixture.provenance.note, "");
    Ok(fixture)
}

/// Builds the policy one recorded `Operations.wait` option set describes.
///
/// The reference's `increaseFactor` is this crate's base delay, and its `minSleep`/`maxSleep` are
/// the floor and the ceiling. Jitter is off, because the reference has none.
fn policy_for(options: &WaitOptions, attempts: u32) -> Result<RetryPolicy, Box<dyn Error>> {
    Ok(RetryPolicy::builder()
        .base_delay(Duration::from_millis(50))
        .min_delay(Duration::from_millis(options.min_sleep.unwrap_or(10)))
        .max_delay(Duration::from_millis(options.max_sleep.unwrap_or(10_000)))
        .jitter(Jitter::None)
        .max_attempts(attempts)
        .without_deadline()
        .build()?)
}

#[test]
fn every_recorded_schedule_is_reproduced_exactly() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.wait_schedules.len(), 5);

    for schedule in &fixture.wait_schedules {
        assert!(!schedule.note.is_empty(), "{}", schedule.name);
        assert!(
            schedule.done,
            "{}: the reference's own poll never completed",
            schedule.name
        );
        // One more poll than delays: the reference sleeps *between* polls.
        assert_eq!(
            u64::from(schedule.polls),
            schedule.delays_ms.len() as u64 + 1,
            "{}",
            schedule.name,
        );

        let attempts = schedule.polls.max(1);
        let policy = policy_for(&schedule.options, attempts)?;
        let ours: Vec<u64> = (0..schedule.delays_ms.len())
            .map(|attempt| {
                let attempt = u32::try_from(attempt).unwrap_or(u32::MAX);
                u64::try_from(policy.delay_for(attempt).as_millis()).unwrap_or(u64::MAX)
            })
            .collect();
        assert_eq!(ours, schedule.delays_ms, "schedule {}", schedule.name);
    }

    // And the specific shapes the notes describe.
    let by_name: BTreeMap<&str, &WaitSchedule> = fixture
        .wait_schedules
        .iter()
        .map(|schedule| (schedule.name.as_str(), schedule))
        .collect();
    assert_eq!(
        by_name.get("defaults").map(|schedule| schedule.delays_ms.as_slice()),
        Some([50, 100, 200, 400, 800, 1600, 3200, 6400].as_slice()),
    );
    assert_eq!(
        by_name.get("immediate").map(|schedule| schedule.delays_ms.len()),
        Some(0),
        "an operation already done never sleeps",
    );
    Ok(())
}

#[test]
fn the_recorded_schedule_is_driven_end_to_end_through_a_transport() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let schedule = fixture
        .wait_schedules
        .iter()
        .find(|schedule| schedule.name == "defaults")
        .ok_or("fixture has no `defaults` schedule")?;

    // The transport answers with a transient status as many times as the reference polled an
    // unfinished operation, then succeeds — the same shape as `Operations.wait`.
    let mut scripted = ScriptedTransport::new();
    for _ in 0..schedule.delays_ms.len() {
        scripted = scripted.respond(Response::new(StatusCode::new(503)?, Headers::new(), Vec::new())?);
    }
    scripted = scripted.respond(Response::new(StatusCode::new(200)?, Headers::new(), Vec::new())?);

    let clock = Arc::new(TestClock::new());
    let attempts = schedule.polls;
    let transport = RetryingTransport::new(Arc::new(scripted))
        .with_policy(policy_for(&schedule.options, attempts)?)
        .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);

    let request = Request::builder(
        Method::Get,
        RequestUrl::new("http://localhost:3901/operations/witness.EPRE")?,
    )
    .build()?;
    let answer = block_on(transport.execute(request));
    assert_eq!(answer.map(|response| response.status().as_u16()).ok(), Some(200));

    let waited: Vec<u64> = clock
        .recorded_sleeps()
        .iter()
        .map(|delay| u64::try_from(delay.as_millis()).unwrap_or(u64::MAX))
        .collect();
    assert_eq!(waited, schedule.delays_ms);
    // Simulated time only: the whole schedule is 12.75 s and the test takes none of it.
    assert_eq!(
        clock.elapsed(),
        Duration::from_millis(schedule.delays_ms.iter().sum::<u64>()),
    );
    Ok(())
}

#[test]
fn the_two_upstream_formulas_are_one_formula() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let helper = &fixture.integration_helper;
    assert_eq!(helper.path, "test-integration/utils/retry.ts");
    assert_ne!(helper.note, "");

    // Read from the reference's own syntax tree, which is why executing only the production one is
    // sufficient evidence for both.
    assert!(helper.formulas_are_identical, "{}", helper.delay_expression);
    assert_eq!(helper.delay_expression, helper.production_delay_expression);
    assert!(helper.delay_expression.contains("Math.max"));
    assert!(helper.delay_expression.contains("2 ** retries * increaseFactor"));

    // Its defaults, reproduced as a policy.
    assert_eq!(helper.defaults.get("increaseFactor"), Some(&50));
    assert_eq!(helper.defaults.get("minSleep"), Some(&10));
    assert_eq!(helper.defaults.get("maxSleep"), Some(&1_000));
    assert_eq!(helper.defaults.get("timeout"), Some(&10_000));

    let policy = RetryPolicy::builder()
        .base_delay(Duration::from_millis(50))
        .min_delay(Duration::from_millis(10))
        .max_delay(Duration::from_secs(1))
        .deadline(Duration::from_secs(10))
        .jitter(Jitter::None)
        .max_attempts(64)
        .build()?;
    let delays: Vec<u64> = (0..8)
        .map(|attempt| u64::try_from(policy.delay_for(attempt).as_millis()).unwrap_or(u64::MAX))
        .collect();
    // The helper's lower ceiling flattens four steps earlier than production's.
    assert_eq!(delays, [50, 100, 200, 400, 800, 1000, 1000, 1000]);
    Ok(())
}

#[test]
fn the_reference_never_reads_server_guidance() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let scan = &fixture.server_guidance_scan;
    assert_eq!(scan.roots, ["src", "test", "test-integration"]);
    assert_eq!(scan.files_scanned, 117);
    assert_ne!(scan.note, "");

    // Every spelling, and both statuses that usually carry the header: zero, across the tree.
    assert_eq!(scan.matches.len(), 6);
    for (needle, count) in &scan.matches {
        assert_eq!(*count, 0, "{needle} appears in the pinned tree after all");
    }

    // So this capability has no upstream counterpart to compare against; RFC 9110 governs it, and
    // these are its own two forms.
    let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    assert_eq!(RetryAfter::parse("30")?.delay_from(now), Duration::from_secs(30));
    assert_eq!(
        RetryAfter::parse("Tue, 14 Nov 2023 22:15:00 GMT")?.delay_from(now),
        Duration::from_secs(100),
    );
    Ok(())
}

#[test]
fn the_defects_are_pinned_and_not_reproduced() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let quirks = &fixture.reference_quirks;

    // 1. Unbounded polling: reproduced as *bounded*, and there is no way to ask for otherwise.
    let unbounded = &quirks.production_polling_is_unbounded;
    assert_eq!(unbounded.loop_form, "while (true)");
    assert!(!unbounded.has_deadline);
    assert!(!unbounded.has_attempt_cap);
    // A zero attempt count is refused, and the count itself is capped, so a schedule terminates.
    assert!(RetryPolicy::builder().max_attempts(0).build().is_err());
    assert!(RetryPolicy::builder().max_attempts(u32::MAX).build().is_err());
    assert_eq!(RetryPolicy::default().max_attempts(), 5);
    assert!(RetryPolicy::default().deadline().is_some());

    // 2 and 3. Aborting: the reference checks after sleeping, and its two implementations differ.
    let order = &quirks.production_abort_is_checked_after_sleeping;
    assert_eq!(order.order.len(), 2);
    assert!(order.order.first().is_some_and(|step| step.contains("sleep")));
    let abort = &quirks.helper_abort_differs_from_production;
    assert!(abort.helper_passes_signal);
    assert!(!abort.production_passes_signal);

    // 4. No jitter: the reference's delay is a pure function of the attempt, and ours is not by
    // default — but `Jitter::None` reproduces it, which is what every test above relies on.
    let jitter = &quirks.no_jitter_anywhere;
    assert!(jitter.expression.contains("2 ** retries"));
    assert_eq!(RetryPolicy::default().jitter(), Jitter::Equal);
    let jittered = RetryPolicy::builder().base_delay(Duration::from_millis(800)).build()?;
    let shortest = jittered.delay_with_guidance(0, 0, None, std::time::SystemTime::UNIX_EPOCH);
    let longest = jittered.delay_with_guidance(0, u32::MAX, None, std::time::SystemTime::UNIX_EPOCH);
    assert_eq!(shortest, Duration::from_millis(400));
    assert_eq!(longest, Duration::from_millis(800));

    // 5. Server guidance ignored: ours honours it, capped.
    let guidance = &quirks.server_guidance_is_ignored;
    assert!(guidance.matches.values().all(|count| *count == 0));
    assert!(matches!(
        RetryPolicy::default().retry_after(),
        RetryAfterPolicy::Honor { .. }
    ));

    // 6. The floor cannot bind at the reference's own defaults, because 2^0 * 50 already exceeds it.
    let floor = &quirks.min_sleep_cannot_bind_at_the_defaults;
    assert_eq!(floor.default_min_sleep, 10);
    assert_eq!(floor.default_increase_factor, 50);
    assert_eq!(floor.first_delay_ms, 50);
    let policy = RetryPolicy::builder()
        .base_delay(Duration::from_millis(50))
        .min_delay(Duration::from_millis(10))
        .jitter(Jitter::None)
        .build()?;
    assert_eq!(policy.delay_for(0), Duration::from_millis(50));

    // 7 and 8. The flat curve and the binding ceiling, reproduced from their recorded delays.
    let flat = &quirks.an_equal_floor_and_ceiling_flattens_the_curve;
    assert!(flat.delays_ms.iter().all(|delay| *delay == 500));
    let ceiling = &quirks.the_ceiling_binds_and_the_delay_stops_growing;
    assert_eq!(ceiling.delays_ms.last(), Some(&10_000));

    // 9. The helper retries everything; this classifies first.
    let catches = &quirks.every_failure_is_retried_by_the_helper;
    assert_eq!(catches.catches, "catch (err)");
    assert!(fixture.integration_helper.retries_on_any_error);
    assert_eq!(RetryPolicy::default().scope(), RetryScope::IdempotentOnly);
    assert!(!RetryScope::IdempotentOnly.admits(Method::Post));

    // Every divergence names what this crate does instead.
    for (name, note, decision) in [
        ("unbounded", &unbounded.note, &unbounded.rust_decision),
        ("abort_order", &order.note, &order.rust_decision),
        ("abort_differs", &abort.note, &abort.rust_decision),
        ("no_jitter", &jitter.note, &jitter.rust_decision),
        ("guidance", &guidance.note, &guidance.rust_decision),
        ("floor", &floor.note, &floor.rust_decision),
        ("flat", &flat.note, &flat.rust_decision),
        ("ceiling", &ceiling.note, &ceiling.rust_decision),
        ("catches", &catches.note, &catches.rust_decision),
    ] {
        assert!(!note.is_empty(), "{name} records no observation");
        assert!(!decision.is_empty(), "{name} records no decision");
    }
    Ok(())
}

#[test]
fn a_deadline_ends_a_sequence_the_reference_would_have_run_forever() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    // The reference's `while (true)` never stops while the operation stays unfinished; this does.
    assert!(!fixture.reference_quirks.production_polling_is_unbounded.has_deadline);

    let mut scripted = ScriptedTransport::new();
    for _ in 0..64 {
        scripted = scripted.respond(Response::new(StatusCode::new(503)?, Headers::new(), Vec::new())?);
    }
    let clock = Arc::new(TestClock::new());
    let transport = RetryingTransport::new(Arc::new(scripted))
        .with_policy(
            RetryPolicy::builder()
                .base_delay(Duration::from_millis(50))
                .min_delay(Duration::from_millis(10))
                .max_delay(Duration::from_secs(10))
                .deadline(Duration::from_secs(5))
                .max_attempts(1_000)
                .jitter(Jitter::None)
                .build()?,
        )
        .with_clock(Arc::clone(&clock) as Arc<dyn Clock>)
        .with_jitter_source(Arc::new(FixedJitter::new(0)));

    let request = Request::builder(Method::Get, RequestUrl::new("http://localhost:3901/operations/x")?).build()?;
    let answer = block_on(transport.execute(request));
    // The last outcome is returned rather than being turned into a failure of its own.
    assert_eq!(answer.map(|response| response.status().as_u16()).ok(), Some(503));
    // 50+100+200+400+800+1600 = 3150; the next wait of 3200 would pass five seconds.
    assert_eq!(
        clock.recorded_sleeps().iter().map(Duration::as_millis).sum::<u128>(),
        3_150,
    );
    assert!(clock.elapsed() < Duration::from_secs(5));
    Ok(())
}

#[test]
fn guidance_the_reference_would_ignore_is_honoured_and_capped() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(fixture.server_guidance_scan.matches.values().all(|count| *count == 0));

    let mut headers = Headers::new();
    headers.insert(HeaderName::new("Retry-After")?, HeaderValue::new("3600")?)?;
    let scripted = ScriptedTransport::new()
        .respond(Response::new(StatusCode::new(429)?, headers, Vec::new())?)
        .respond(Response::new(StatusCode::new(200)?, Headers::new(), Vec::new())?);

    let clock = Arc::new(TestClock::new());
    let transport = RetryingTransport::new(Arc::new(scripted))
        .with_policy(
            RetryPolicy::builder()
                .max_attempts(3)
                .jitter(Jitter::None)
                .without_deadline()
                .retry_after(RetryAfterPolicy::Honor {
                    maximum: Duration::from_secs(30),
                })
                .build()?,
        )
        .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);

    let request = Request::builder(Method::Get, RequestUrl::new("http://localhost:3901/identifiers")?).build()?;
    let answer = block_on(transport.execute(request));
    assert_eq!(answer.map(|response| response.status().as_u16()).ok(), Some(200));
    // The server asked for an hour; the policy's ceiling is what a caller actually waits.
    assert_eq!(clock.recorded_sleeps(), [Duration::from_secs(30)]);
    Ok(())
}

#[test]
fn a_post_the_helper_would_have_repeated_is_not_repeated() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert!(fixture.integration_helper.retries_on_any_error);

    let scripted = Arc::new(
        ScriptedTransport::new()
            .respond(Response::new(StatusCode::new(503)?, Headers::new(), Vec::new())?)
            .respond(Response::new(StatusCode::new(200)?, Headers::new(), Vec::new())?),
    );
    let observer = Arc::new(GiveUpRecorder::default());
    let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
        .with_policy(RetryPolicy::builder().max_attempts(5).jitter(Jitter::None).build()?)
        .with_clock(Arc::new(TestClock::new()))
        .with_observer(Arc::clone(&observer) as Arc<dyn RetryObserver>);

    // `identifiers().create` is a POST; repeating it can incept a second identifier.
    let request = Request::builder(Method::Post, RequestUrl::new("http://localhost:3901/identifiers")?)
        .body(br#"{"name":"aid1"}"#.to_vec())
        .build()?;
    let answer = block_on(transport.execute(request));
    assert_eq!(answer.map(|response| response.status().as_u16()).ok(), Some(503));
    assert_eq!(scripted.answered(), 1, "the POST was repeated");
    // And the reason is named rather than inferred from the attempt count.
    assert_eq!(
        observer.give_ups().first().map(|event| event.reason),
        Some(StopReason::MethodNotIdempotent),
    );
    Ok(())
}

/// Records why a sequence ended, so a test can assert the reason rather than infer it.
#[derive(Debug, Default)]
struct GiveUpRecorder {
    events: std::sync::Mutex<Vec<GiveUpEvent>>,
}

impl GiveUpRecorder {
    fn give_ups(&self) -> Vec<GiveUpEvent> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl RetryObserver for GiveUpRecorder {
    fn on_give_up(&self, event: &GiveUpEvent) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
    }
}

/// A minimal executor; every future reachable from a scripted transport and a test clock is ready
/// on its first poll, so no runtime is needed and no wall-clock time passes.
fn block_on<F: core::future::Future>(future: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
}
