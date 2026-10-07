#![no_main]

//! Fuzzes the retry policy's parser and its bounds.
//!
//! One value here comes from outside the process: `Retry-After`, which a server controls entirely
//! and which decides how long a client waits. Everything else is configuration, but a policy built
//! from hostile-looking numbers must still terminate — an attempt count, a floor, a ceiling, and a
//! deadline are exactly the parameters that overflow a shift or invert a clamp if they are not
//! checked.
//!
//! The target asserts that nothing panics, that every rejection is a typed error with a non-empty
//! description, that an accepted delay always lands inside the bounds its policy names, and — the
//! property that matters most — that **every schedule terminates**, with its waits summing to less
//! than its own deadline. The reference's `Operations.wait` cannot make that claim: it is a
//! `while (true)`.

use core::time::Duration;
use std::time::{Instant, SystemTime};

use libfuzzer_sys::fuzz_target;
use signify_http::retry::{
    Backoff, Jitter, MAX_ATTEMPTS, MAX_DELAY_BOUND_SECONDS, MAX_DELAY_SECONDS, MAX_RETRY_AFTER_BYTES, RetryAfter,
    RetryAfterError, RetryAfterPolicy, RetryDecision, RetryPolicy, RetryPolicyError, RetryScope, StopReason,
};
use signify_http::transport::Method;

/// Returns whether a rejection is one a policy is allowed to produce.
fn is_expected_policy_error(error: &RetryPolicyError) -> bool {
    matches!(
        error,
        RetryPolicyError::NoAttempts
            | RetryPolicyError::TooManyAttempts { .. }
            | RetryPolicyError::ZeroDelay { .. }
            | RetryPolicyError::DelayTooLong { .. }
            | RetryPolicyError::ZeroDeadline
    )
}

/// Returns whether a rejection is one the `Retry-After` parser is allowed to produce.
fn is_expected_guidance_error(error: &RetryAfterError) -> bool {
    matches!(
        error,
        RetryAfterError::Empty
            | RetryAfterError::TooLong { .. }
            | RetryAfterError::DelayOutOfRange { .. }
            | RetryAfterError::InvalidDate { .. }
    )
}

fuzz_target!(|data: &[u8]| {
    let [attempts, base, floor, ceiling, budget, selector, rest @ ..] = data else {
        return;
    };
    let text = String::from_utf8_lossy(rest).into_owned();

    // ---------------------------------------------------------------
    // The server's half: a `Retry-After` value it controls entirely.
    // ---------------------------------------------------------------
    let guidance = match RetryAfter::parse(&text) {
        Ok(parsed) => {
            assert!(text.len() <= MAX_RETRY_AFTER_BYTES);
            match parsed {
                RetryAfter::Delay(delay) => {
                    // A delay is bounded, so one header cannot park a caller indefinitely.
                    assert!(delay <= Duration::from_secs(MAX_DELAY_SECONDS), "{delay:?}");
                    assert!(text.bytes().all(|byte| byte.is_ascii_digit()));
                }
                RetryAfter::At(_) => assert_eq!(text.len(), 29),
            }
            // Reading it against any moment yields a finite wait, never a negative one.
            for now in [SystemTime::UNIX_EPOCH, SystemTime::now()] {
                let _ = parsed.delay_from(now);
            }
            Some(parsed)
        }
        Err(error) => {
            assert!(is_expected_guidance_error(&error), "{error:?}");
            assert!(!error.to_string().is_empty());
            None
        }
    };

    // ---------------------------------------------------------------
    // The configuration's half: a policy built from whatever the input said.
    // ---------------------------------------------------------------
    let jitter = match selector % 3 {
        0 => Jitter::None,
        1 => Jitter::Equal,
        _ => Jitter::Full,
    };
    let scope = if selector & 0x80 == 0 {
        RetryScope::IdempotentOnly
    } else {
        RetryScope::AnyMethod
    };
    let method = *Method::ALL
        .get(usize::from(selector >> 2) % Method::ALL.len())
        .unwrap_or(&Method::Get);

    let builder = RetryPolicy::builder()
        .max_attempts(u32::from(*attempts))
        .base_delay(Duration::from_millis(u64::from(*base) * 10))
        .min_delay(Duration::from_millis(u64::from(*floor) * 10))
        .max_delay(Duration::from_millis(u64::from(*ceiling) * 40))
        .deadline(Duration::from_millis(u64::from(*budget) * 100))
        .jitter(jitter)
        .scope(scope)
        .retry_after(RetryAfterPolicy::Honor {
            maximum: Duration::from_secs(30),
        });

    let policy = match builder.build() {
        Ok(policy) => policy,
        Err(error) => {
            assert!(is_expected_policy_error(&error), "{error:?}");
            assert!(!error.to_string().is_empty());
            return;
        }
    };

    // Every bound the policy reports is the one it was given, and inside the published limits.
    assert!(policy.max_attempts() >= 1 && policy.max_attempts() <= MAX_ATTEMPTS);
    let hour = Duration::from_secs(MAX_DELAY_BOUND_SECONDS);
    assert!(!policy.base_delay().is_zero() && policy.base_delay() <= hour);
    assert!(!policy.min_delay().is_zero() && policy.min_delay() <= hour);
    assert!(!policy.max_delay().is_zero() && policy.max_delay() <= hour);

    // A delay never leaves its band, whatever the attempt number — including past the width of
    // the shift, where the reference gets `Infinity` and this must saturate instead.
    for attempt in [0_u32, 1, 31, 32, 63, 64, 1_000, u32::MAX] {
        let delay = policy.delay_for(attempt);
        assert!(delay >= policy.min_delay(), "{attempt}: {delay:?}");
        assert!(
            delay <= policy.min_delay().max(policy.max_delay()),
            "{attempt}: {delay:?}"
        );
    }
    // The schedule never decreases.
    let mut previous = Duration::ZERO;
    for attempt in 0..24_u32 {
        let delay = policy.delay_for(attempt);
        assert!(delay >= previous, "attempt {attempt} went backwards");
        previous = delay;
    }

    // Guidance replaces the computed delay and is capped by the policy's own ceiling.
    let guided = policy.delay_with_guidance(0, u32::from(*selector), guidance, SystemTime::UNIX_EPOCH);
    if guidance.is_some() {
        assert!(guided <= Duration::from_secs(30), "{guided:?}");
    } else {
        assert!(guided <= policy.min_delay().max(policy.max_delay()), "{guided:?}");
    }

    // ---------------------------------------------------------------
    // The property that matters: the schedule terminates.
    // ---------------------------------------------------------------
    let Some(deadline) = policy.deadline() else {
        return;
    };
    let start = Instant::now();
    let mut backoff = Backoff::new(policy, start);
    let mut elapsed = Duration::ZERO;
    let mut retries = 0_u32;
    loop {
        let now = start.checked_add(elapsed).unwrap_or(start);
        match backoff.next(now, method, true, u32::from(*selector), None, SystemTime::UNIX_EPOCH) {
            RetryDecision::Retry { delay, attempt } => {
                retries = retries.saturating_add(1);
                assert_eq!(attempt, retries);
                // Every wait finishes inside the budget rather than merely starting inside it.
                assert!(elapsed.saturating_add(delay) < deadline, "a wait ran past the deadline");
                elapsed = elapsed.saturating_add(delay);
            }
            RetryDecision::Stop(reason) => {
                assert!(matches!(
                    reason,
                    StopReason::AttemptsExhausted | StopReason::DeadlineElapsed | StopReason::MethodNotIdempotent
                ));
                if reason == StopReason::MethodNotIdempotent {
                    assert_eq!(scope, RetryScope::IdempotentOnly);
                    assert_eq!(method, Method::Post);
                }
                break;
            }
        }
        // The attempt cap alone bounds the loop; reaching this means it did not.
        assert!(retries < policy.max_attempts(), "{retries} retries past the cap");
    }
    assert!(elapsed < deadline);
    assert_eq!(backoff.attempts_made(), retries.saturating_add(1));

    // A non-retryable outcome always stops, whatever the schedule had left.
    let mut fresh = Backoff::new(policy, start);
    assert_eq!(
        fresh.next(start, method, false, 0, None, SystemTime::UNIX_EPOCH),
        RetryDecision::Stop(StopReason::NotRetryable),
    );
});
