//! Invariants of the retry policy, the clock, and the `Retry-After` parser.
//!
//! The generators include the boundaries that matter here: an attempt number past the width of the
//! shift, a floor above its ceiling, a delay of zero, a date one character away from valid, and a
//! deadline that expires exactly on a wait.

use core::time::Duration;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use proptest::prelude::*;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{
    Backoff, Clock, FixedJitter, Jitter, JitterSource, MAX_ATTEMPTS, MAX_DELAY_BOUND_SECONDS, MAX_DELAY_SECONDS,
    MAX_RETRY_AFTER_BYTES, RetryAfter, RetryAfterError, RetryAfterPolicy, RetryDecision, RetryPolicy, RetryPolicyError,
    RetryScope, RetryingTransport, StopReason, TestClock,
};
use signify_http::transport::{Method, Request, RequestUrl, Response, ScriptedTransport, StatusCode, Transport};

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn method_of(index: usize) -> Method {
    *Method::ALL.get(index % Method::ALL.len()).unwrap_or(&Method::Get)
}

/// A minimal executor; every future in this crate's test path is ready on its first poll.
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

proptest! {
    /// A delay always lands inside the policy's bounds, and the schedule never decreases and
    /// flattens once the ceiling binds.
    #[test]
    fn a_schedule_is_bounded_monotonic_and_flattens(
        base_ms in 1_u64..5_000,
        min_ms in 1_u64..5_000,
        max_ms in 1_u64..20_000,
        attempt in any::<u32>(),
        steps in 1_u32..40,
    ) {
        let policy = RetryPolicy::builder()
            .base_delay(Duration::from_millis(base_ms))
            .min_delay(Duration::from_millis(min_ms))
            .max_delay(Duration::from_millis(max_ms))
            .jitter(Jitter::None)
            .build()
            .map_err(fail)?;

        let within_bounds = |delay: Duration| -> Result<(), TestCaseError> {
            // The reference applies the floor *outside* the ceiling, so a floor above the ceiling wins.
            prop_assert!(delay >= Duration::from_millis(min_ms), "{delay:?}");
            if min_ms <= max_ms {
                prop_assert!(delay <= Duration::from_millis(max_ms), "{delay:?}");
            } else {
                prop_assert_eq!(delay, Duration::from_millis(min_ms));
            }
            // Nothing overflows, whatever the attempt number.
            prop_assert!(delay <= Duration::from_millis(min_ms.max(max_ms)));
            Ok(())
        };

        within_bounds(policy.delay_for(attempt))?;
        let mut previous = Duration::ZERO;
        for step in 0..steps {
            let delay = policy.delay_for(step);
            within_bounds(delay)?;
            prop_assert!(delay >= previous, "attempt {step}: {delay:?} < {previous:?}");
            previous = delay;
        }
        // Far enough out, it has stopped growing entirely.
        prop_assert_eq!(policy.delay_for(60), policy.delay_for(61));
    }

    /// Jitter never leaves its band, whatever the randomness.
    #[test]
    fn jitter_stays_inside_its_band(delay_nanos in 0_u64..1_000_000_000_000, randomness in any::<u32>()) {
        let delay = Duration::from_nanos(delay_nanos);
        prop_assert_eq!(Jitter::None.apply(delay, randomness), delay);

        let equal = Jitter::Equal.apply(delay, randomness);
        prop_assert!(equal >= delay / 2, "{equal:?} < {:?}", delay / 2);
        prop_assert!(equal <= delay, "{equal:?} > {delay:?}");

        let full = Jitter::Full.apply(delay, randomness);
        prop_assert!(full <= delay, "{full:?} > {delay:?}");

        // The band's edges are reached exactly, which is what `FixedJitter` relies on.
        prop_assert_eq!(Jitter::Full.apply(delay, 0), Duration::ZERO);
        prop_assert_eq!(Jitter::Equal.apply(delay, u32::MAX), delay);
    }

    /// A policy is accepted exactly when every bound it names is usable.
    #[test]
    fn a_policy_is_accepted_exactly_when_it_is_usable(
        attempts in 0_u32..2_000,
        base_secs in 0_u64..5_000,
        deadline_secs in 0_u64..100,
    ) {
        let built = RetryPolicy::builder()
            .max_attempts(attempts)
            .base_delay(Duration::from_secs(base_secs))
            .deadline(Duration::from_secs(deadline_secs))
            .build();

        match built {
            Ok(policy) => {
                prop_assert!(attempts > 0 && attempts <= MAX_ATTEMPTS);
                prop_assert!(base_secs > 0 && base_secs <= MAX_DELAY_BOUND_SECONDS);
                prop_assert!(deadline_secs > 0);
                prop_assert_eq!(policy.max_attempts(), attempts);
                prop_assert_eq!(policy.deadline(), Some(Duration::from_secs(deadline_secs)));
            }
            Err(RetryPolicyError::NoAttempts) => prop_assert_eq!(attempts, 0),
            Err(RetryPolicyError::TooManyAttempts { .. }) => prop_assert!(attempts > MAX_ATTEMPTS),
            Err(RetryPolicyError::ZeroDelay { .. }) => prop_assert_eq!(base_secs, 0),
            Err(RetryPolicyError::DelayTooLong { .. }) => {
                prop_assert!(base_secs > MAX_DELAY_BOUND_SECONDS);
            }
            Err(RetryPolicyError::ZeroDeadline) => prop_assert_eq!(deadline_secs, 0),
            Err(other) => return Err(fail(other)),
        }
    }

    /// A schedule always terminates, and never sleeps past its own deadline.
    #[test]
    fn a_schedule_always_terminates(
        attempts in 1_u32..40,
        base_ms in 1_u64..500,
        deadline_ms in 1_u64..20_000,
        index in 0_usize..8,
    ) {
        let policy = RetryPolicy::builder()
            .max_attempts(attempts)
            .base_delay(Duration::from_millis(base_ms))
            .min_delay(Duration::from_millis(1))
            .max_delay(Duration::from_secs(10))
            .deadline(Duration::from_millis(deadline_ms))
            .jitter(Jitter::None)
            .scope(RetryScope::AnyMethod)
            .build()
            .map_err(fail)?;

        let start = Instant::now();
        let mut backoff = Backoff::new(policy, start);
        let mut elapsed = Duration::ZERO;
        let mut retries = 0_u32;
        let stop = loop {
            let now = start.checked_add(elapsed).unwrap_or(start);
            match backoff.next(now, method_of(index), true, 0, None, SystemTime::UNIX_EPOCH) {
                RetryDecision::Retry { delay, attempt } => {
                    retries = retries.saturating_add(1);
                    prop_assert_eq!(attempt, retries);
                    // Every wait finishes inside the budget; that is what makes it a real bound.
                    let fits = elapsed.saturating_add(delay) < Duration::from_millis(deadline_ms);
                    prop_assert!(fits, "a wait would have run past the deadline");
                    elapsed = elapsed.saturating_add(delay);
                }
                RetryDecision::Stop(reason) => break reason,
            }
            // The loop cannot run away: the attempt cap alone bounds it.
            prop_assert!(retries < attempts, "{} retries against {} attempts", retries, attempts);
        };
        let bounded = matches!(stop, StopReason::AttemptsExhausted | StopReason::DeadlineElapsed);
        prop_assert!(bounded, "unexpected stop reason");
        prop_assert!(elapsed < Duration::from_millis(deadline_ms));
        prop_assert_eq!(backoff.attempts_made(), retries.saturating_add(1));
    }

    /// A method that changes state is never retried unless the scope was widened.
    #[test]
    fn the_scope_decides_which_methods_repeat(index in 0_usize..8, widen in any::<bool>()) {
        let scope = if widen { RetryScope::AnyMethod } else { RetryScope::RepeatableOnly };
        let policy = RetryPolicy::builder().max_attempts(5).scope(scope).build().map_err(fail)?;
        let method = method_of(index);
        let now = Instant::now();
        let mut backoff = Backoff::new(policy, now);

        let decision = backoff.next(now, method, true, 0, None, SystemTime::UNIX_EPOCH);
        let admitted = widen || method == Method::Get;
        match decision {
            RetryDecision::Retry { .. } => prop_assert!(admitted, "an unsafe method was retried"),
            RetryDecision::Stop(StopReason::MethodNotRepeatable) => {
                prop_assert!(!admitted, "a repeatable method was refused");
            }
            other @ RetryDecision::Stop(_) => return Err(fail(format!("{other:?}"))),
        }
        prop_assert_eq!(scope.admits(method), admitted);
    }

    /// A test clock's time is exactly the sum of what it was asked to wait.
    #[test]
    fn a_test_clock_accounts_for_every_wait(waits in proptest::collection::vec(0_u64..100_000, 0..32)) {
        let clock = TestClock::new();
        let start = clock.now();
        let start_wall = clock.wall_clock();
        for wait in &waits {
            block_on(clock.sleep(Duration::from_micros(*wait)));
        }
        let total: u64 = waits.iter().sum();
        prop_assert_eq!(clock.elapsed(), Duration::from_micros(total));
        prop_assert_eq!(clock.now().duration_since(start), Duration::from_micros(total));
        prop_assert_eq!(clock.recorded_sleeps().len(), waits.len());
        // The wall clock moves with it, so a date-form `Retry-After` is deterministic too.
        let wall_elapsed = clock.wall_clock().duration_since(start_wall).map_err(fail)?;
        prop_assert_eq!(wall_elapsed, Duration::from_micros(total));
    }

    /// A delay-seconds value round trips, and anything outside the grammar is refused.
    #[test]
    fn retry_after_delays_round_trip(seconds in 0_u64..MAX_DELAY_SECONDS) {
        let rendered = seconds.to_string();
        let parsed = RetryAfter::parse(&rendered).map_err(fail)?;
        prop_assert_eq!(parsed, RetryAfter::Delay(Duration::from_secs(seconds)));
        prop_assert_eq!(parsed.delay_from(SystemTime::UNIX_EPOCH), Duration::from_secs(seconds));

        // A sign or a fraction makes it a malformed date rather than a number.
        for prefix in ["-", "+", " "] {
            let signed = format!("{prefix}{rendered}");
            let refused = RetryAfter::parse(&signed).is_err();
            prop_assert!(refused, "{} was accepted", signed);
        }
    }

    /// Any input at all is either a usable value or a typed refusal, never a panic.
    #[test]
    fn arbitrary_retry_after_values_never_panic(value in ".{0,80}") {
        match RetryAfter::parse(&value) {
            Ok(parsed) => {
                prop_assert!(value.len() <= MAX_RETRY_AFTER_BYTES);
                // A delay never exceeds the ceiling, and a date always yields a finite wait.
                let delay = parsed.delay_from(SystemTime::UNIX_EPOCH);
                let bounded = delay <= Duration::from_secs(MAX_DELAY_SECONDS) || matches!(parsed, RetryAfter::At(_));
                prop_assert!(bounded, "unbounded delay {:?}", delay);
                match parsed {
                    RetryAfter::Delay(_) => {
                        let all_digits = value.bytes().all(|byte| byte.is_ascii_digit());
                        prop_assert!(all_digits, "a non-numeric value parsed as a delay");
                    }
                    RetryAfter::At(_) => prop_assert_eq!(value.len(), 29),
                }
            }
            Err(error) => {
                let expected = matches!(
                    error,
                    RetryAfterError::Empty
                        | RetryAfterError::TooLong { .. }
                        | RetryAfterError::DelayOutOfRange { .. }
                        | RetryAfterError::InvalidDate { .. }
                );
                prop_assert!(expected, "unexpected error: {}", error);
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    /// Server guidance replaces the computed delay and never exceeds the policy's ceiling.
    #[test]
    fn guidance_is_honoured_within_its_ceiling(
        asked_secs in 0_u64..10_000,
        ceiling_secs in 1_u64..MAX_DELAY_BOUND_SECONDS,
        attempt in 0_u32..16,
        randomness in any::<u32>(),
    ) {
        let ceiling = Duration::from_secs(ceiling_secs);
        let policy = RetryPolicy::builder()
            .base_delay(Duration::from_millis(50))
            .retry_after(RetryAfterPolicy::Honor { maximum: ceiling })
            .build()
            .map_err(fail)?;

        let guidance = RetryAfter::Delay(Duration::from_secs(asked_secs));
        let delay = policy.delay_with_guidance(attempt, randomness, Some(guidance), SystemTime::UNIX_EPOCH);
        prop_assert_eq!(delay, Duration::from_secs(asked_secs).min(ceiling));
        prop_assert!(delay <= ceiling);

        // Ignoring it falls back to the computed schedule, which is what the reference does.
        let ignoring = RetryPolicy::builder()
            .base_delay(Duration::from_millis(50))
            .jitter(Jitter::None)
            .retry_after(RetryAfterPolicy::Ignore)
            .build()
            .map_err(fail)?;
        prop_assert_eq!(
            ignoring.delay_with_guidance(attempt, randomness, Some(guidance), SystemTime::UNIX_EPOCH),
            ignoring.delay_for(attempt),
        );
    }

    /// A transport retries exactly as many times as its policy allows, and returns the last answer.
    #[test]
    fn a_transport_retries_within_its_policy(
        attempts in 1_u32..8,
        failures in 0_usize..12,
        randomness in any::<u32>(),
    ) {
        let mut scripted = ScriptedTransport::new();
        for _ in 0..failures {
            let response = Response::new(StatusCode::new(503).map_err(fail)?, Headers::new(), Vec::new())
                .map_err(fail)?;
            scripted = scripted.respond(response);
        }
        let success = Response::new(StatusCode::new(200).map_err(fail)?, Headers::new(), Vec::new())
            .map_err(fail)?;
        scripted = scripted.respond(success);
        let scripted = Arc::new(scripted);

        let clock = Arc::new(TestClock::new());
        let policy = RetryPolicy::builder()
            .max_attempts(attempts)
            .base_delay(Duration::from_millis(50))
            .min_delay(Duration::from_millis(1))
            .max_delay(Duration::from_secs(10))
            .without_deadline()
            .build()
            .map_err(fail)?;
        let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>, Arc::clone(&clock) as Arc<dyn Clock>)
            .with_policy(policy)
            .with_jitter_source(Arc::new(FixedJitter::new(randomness)));

        let url = RequestUrl::new("http://localhost:3901/identifiers").map_err(fail)?;
        let request = Request::builder(Method::Get, url).build().map_err(fail)?;
        let answer = block_on(transport.execute(request)).map_err(fail)?;

        let expected_attempts = usize::try_from(attempts).unwrap_or(usize::MAX).min(failures + 1);
        prop_assert_eq!(scripted.answered(), expected_attempts);
        // One wait per retry, never more.
        prop_assert_eq!(clock.recorded_sleeps().len(), expected_attempts.saturating_sub(1));
        // The last answer is returned whatever it was; a status is never turned into a failure here.
        let expected_status = if failures < usize::try_from(attempts).unwrap_or(usize::MAX) { 200 } else { 503 };
        prop_assert_eq!(answer.status().as_u16(), expected_status);
    }

    /// A malformed or absent `Retry-After` costs the server its timing and nothing else.
    ///
    /// The values hold no digit and are shorter than an HTTP date, so none can parse.
    #[test]
    fn a_broken_guidance_header_falls_back_to_the_schedule(
        value in "[A-Za-z ,:;=-]{0,24}",
        base_ms in 10_u64..5_000,
    ) {
        let mut headers = Headers::new();
        if let (Ok(name), Ok(header_value)) = (HeaderName::new("Retry-After"), HeaderValue::new(&value)) {
            let _ = headers.insert(name, header_value);
        }
        let response = Response::new(StatusCode::new(503).map_err(fail)?, headers, Vec::new()).map_err(fail)?;
        let success = Response::new(StatusCode::new(200).map_err(fail)?, Headers::new(), Vec::new())
            .map_err(fail)?;

        let clock = Arc::new(TestClock::new());
        let transport = RetryingTransport::new(Arc::new(
            ScriptedTransport::new().respond(response).respond(success),
        ),
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .with_policy(
            RetryPolicy::builder()
                .max_attempts(3)
                .base_delay(Duration::from_millis(base_ms))
                .jitter(Jitter::None)
                .without_deadline()
                .retry_after(RetryAfterPolicy::Honor { maximum: Duration::from_secs(30) })
                .build()
                .map_err(fail)?,
        );

        let url = RequestUrl::new("http://localhost:3901/identifiers").map_err(fail)?;
        let request = Request::builder(Method::Get, url).build().map_err(fail)?;
        let answer = block_on(transport.execute(request)).map_err(fail)?;
        prop_assert_eq!(answer.status().as_u16(), 200);

        // Exactly one wait: the first step of the schedule, `base * 2^0`, inside the default
        // `[10 ms, 10 s]` bounds.
        prop_assert_eq!(clock.recorded_sleeps(), vec![Duration::from_millis(base_ms)]);
    }

    /// A jitter source always yields something usable, and a fixed one is fixed.
    #[test]
    fn jitter_sources_answer_within_range(value in any::<u32>()) {
        let fixed = FixedJitter::new(value);
        prop_assert_eq!(fixed.next_u32(), value);
        prop_assert_eq!(fixed.next_u32(), value);
    }
}
