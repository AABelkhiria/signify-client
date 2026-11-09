//! How long to wait before trying again, and when to stop trying.
//!
//! The delay formula is the pinned reference's, exactly:
//!
//! ```text
//! Math.max(minSleep, Math.min(maxSleep, 2 ** retries * increaseFactor))
//! ```
//!
//! It appears twice upstream — in the production `Operations.wait` and in the integration
//! `retry.ts` helper — and `fixtures/http-retry/v1.json` records both, the first by executing it
//! and the second from the reference's own syntax tree. Reproducing it exactly is what lets a Rust
//! client keep the timing a KERIA deployment was tuned against.
//!
//! # What is added, and why
//!
//! **Bounds.** `Operations.wait` is a `while (true)` with no deadline and no attempt cap, so an
//! operation the agent never finishes hangs the caller forever. [`RetryPolicy`] requires a maximum
//! attempt count and accepts an optional total deadline, so a schedule always terminates.
//!
//! **Jitter.** The reference's delay is a pure function of the attempt number, so every client
//! that started an operation at the same moment retries at the same moments forever.
//! Retry delay must use jitter; [`Jitter::Equal`] is the default and [`Jitter::None`] reproduces
//! the reference's schedule exactly.
//!
//! # The floor is applied outside the ceiling
//!
//! `max(min_delay, min(max_delay, …))` is not a clamp: when the floor is above the ceiling the
//! floor wins. That ordering is reproduced rather than tidied, because `Duration::clamp` with an
//! inverted range is a different function and the reference's own `multisig-join` case passes an
//! equal floor and ceiling.

use core::fmt;
use core::num::NonZeroU32;
use core::time::Duration;
use std::error::Error;
use std::time::Instant;

use crate::transport::{Method, StatusCode, TransportError};

use super::retry_after::RetryAfter;

/// Largest accepted delay bound, in seconds.
///
/// An hour. Any parameter above this is a configuration mistake rather than a policy: a client
/// that waits longer than this between attempts has stopped being a client.
pub const MAX_DELAY_BOUND_SECONDS: u64 = 3_600;

/// Largest accepted attempt count.
///
/// With the reference's own ceiling of ten seconds, 1024 attempts is over two hours of waiting;
/// the bound exists so an attempt count cannot silently become a deadline of its own.
pub const MAX_ATTEMPTS: u32 = 1_024;

/// How a computed delay is randomised.
///
/// ```
/// use core::time::Duration;
/// use signify_http::retry::Jitter;
///
/// let delay = Duration::from_millis(800);
/// // `None` returns the delay untouched, which is what the reference does.
/// assert_eq!(Jitter::None.apply(delay, u32::MAX), delay);
/// // `Equal` keeps half and randomises the rest, so the result never collapses to zero.
/// assert_eq!(Jitter::Equal.apply(delay, 0), Duration::from_millis(400));
/// assert_eq!(Jitter::Full.apply(delay, 0), Duration::ZERO);
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Jitter {
    /// The computed delay, unchanged. Reproduces the reference's schedule.
    None,
    /// Half the delay, plus a random share of the other half: a delay in `[d/2, d]`.
    ///
    /// The default. It spreads a fleet of clients without letting a delay collapse towards zero,
    /// which full jitter can do — and a near-zero delay on a server that is already struggling is
    /// the opposite of what backoff is for.
    #[default]
    Equal,
    /// A random share of the whole delay: a delay in `[0, d]`.
    Full,
}

impl Jitter {
    /// Applies this jitter to one delay, given a uniformly distributed value.
    ///
    /// `randomness` is spread across the whole `u32` range; the caller draws it from a
    /// [`JitterSource`](super::JitterSource).
    #[must_use]
    pub fn apply(self, delay: Duration, randomness: u32) -> Duration {
        match self {
            Self::None => delay,
            Self::Equal => {
                let half = delay / 2;
                half.saturating_add(scale(delay.saturating_sub(half), randomness))
            }
            Self::Full => scale(delay, randomness),
        }
    }
}

/// Returns `span * randomness / u32::MAX`, in whole nanoseconds and without floating point.
///
/// Exact values never use floating point; a delay is not a protocol value, but using integers
/// here keeps the result reproducible across platforms, which is what makes the jitter testable at
/// all.
fn scale(span: Duration, randomness: u32) -> Duration {
    let nanos = span.as_nanos();
    let scaled = nanos
        .saturating_mul(u128::from(randomness))
        .checked_div(u128::from(u32::MAX))
        .unwrap_or(0);
    Duration::from_nanos(u64::try_from(scaled).unwrap_or(u64::MAX))
}

/// Which methods a policy will retry automatically.
///
/// The reference's integration helper retries whatever its callback threw, and the suites wrap
/// whole credential lookups in it — so a `POST` that already created something is repeated on any
/// failure. An automatic retry is allowed only when a request is known repeatable, which is
/// what the default enforces.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum RetryScope {
    /// Only `GET`.
    ///
    /// The default. A `POST` can create a second identifier, registry, or credential, a KERIA `PUT`
    /// can rotate a passcode or approve a delegation, and a `DELETE` can revoke a credential.
    #[default]
    RepeatableOnly,
    /// Every method, including `POST`.
    ///
    /// The caller asserts that repeating the request is safe — because the endpoint is idempotent
    /// in practice, or because the body carries something that makes it so. Nothing in this crate
    /// can check that claim.
    AnyMethod,
}

impl RetryScope {
    /// Returns whether a request using `method` may be retried automatically.
    #[must_use]
    pub const fn admits(self, method: Method) -> bool {
        match self {
            Self::AnyMethod => true,
            Self::RepeatableOnly => match method {
                Method::Get => true,
                Method::Post | Method::Put | Method::Delete => false,
            },
        }
    }
}

/// Whether a status is one worth trying again.
///
/// The set is `408`, `429`, `502`, `503`, and `504`: a request the server timed out on, a rate
/// limit, and the three gateway failures that mean the request never reached its destination or
/// its answer never came back.
///
/// `500` and `501` are deliberately excluded. A `500` from KERIA is an unhandled exception that
/// will recur on the same input, so repeating it spends a deadline to reach the same place, and
/// `501` is permanent. The reference draws no distinction at all — its helper retries every
/// failure — so there is no upstream behaviour to preserve here.
#[must_use]
pub const fn is_transient_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504)
}

/// Whether a transport failure is one worth trying again.
///
/// A timeout, a connection failure, and an unreadable response are transient: the first two are
/// the network, and the third is what a connection reset mid-body looks like once hyper has given
/// up parsing it. Everything else describes the request itself — a malformed URL, an oversized
/// body, a duplicate header — and will fail identically however many times it is sent.
#[must_use]
pub const fn is_transient_error(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Timeout { .. } | TransportError::Connect { .. } | TransportError::InvalidResponse { .. }
    )
}

/// What a policy does with a `Retry-After` header.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum RetryAfterPolicy {
    /// Ignore the header and use the computed backoff, as the reference does.
    Ignore,
    /// Wait as long as the server asked, up to `maximum`.
    ///
    /// The ceiling matters: without it one header parks a caller for as long as a mistaken or
    /// hostile server likes, past any deadline the caller set.
    Honor {
        /// Longest delay a server may ask for.
        maximum: Duration,
    },
}

impl Default for RetryAfterPolicy {
    fn default() -> Self {
        Self::Honor {
            maximum: Duration::from_mins(1),
        }
    }
}

/// A bounded exponential-backoff policy.
///
/// ```
/// use core::time::Duration;
/// use signify_http::retry::{Jitter, RetryPolicy};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // The pinned reference's own production schedule.
/// let policy = RetryPolicy::builder()
///     .base_delay(Duration::from_millis(50))
///     .min_delay(Duration::from_millis(10))
///     .max_delay(Duration::from_secs(10))
///     .jitter(Jitter::None)
///     .max_attempts(9)
///     .build()?;
///
/// let delays: Vec<u64> = (0..8).map(|attempt| policy.delay_for(attempt).as_millis() as u64).collect();
/// assert_eq!(delays, [50, 100, 200, 400, 800, 1600, 3200, 6400]);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: NonZeroU32,
    base_delay: Duration,
    min_delay: Duration,
    max_delay: Duration,
    deadline: Option<Duration>,
    jitter: Jitter,
    scope: RetryScope,
    retry_after: RetryAfterPolicy,
}

impl RetryPolicy {
    /// Starts building a policy.
    #[must_use]
    pub fn builder() -> RetryPolicyBuilder {
        RetryPolicyBuilder::default()
    }

    /// Returns how many attempts may be made in total, the first included.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts.get()
    }

    /// Returns the delay the first retry is computed from.
    #[must_use]
    pub const fn base_delay(&self) -> Duration {
        self.base_delay
    }

    /// Returns the floor, which is applied after the ceiling.
    #[must_use]
    pub const fn min_delay(&self) -> Duration {
        self.min_delay
    }

    /// Returns the ceiling the doubling flattens at.
    #[must_use]
    pub const fn max_delay(&self) -> Duration {
        self.max_delay
    }

    /// Returns the total time budget, when there is one.
    #[must_use]
    pub const fn deadline(&self) -> Option<Duration> {
        self.deadline
    }

    /// Returns how a computed delay is randomised.
    #[must_use]
    pub const fn jitter(&self) -> Jitter {
        self.jitter
    }

    /// Returns which methods may be retried.
    #[must_use]
    pub const fn scope(&self) -> RetryScope {
        self.scope
    }

    /// Returns what happens to a `Retry-After` header.
    #[must_use]
    pub const fn retry_after(&self) -> RetryAfterPolicy {
        self.retry_after
    }

    /// Returns the un-jittered delay before the retry following `attempt`.
    ///
    /// `attempt` is zero-based: `delay_for(0)` is the wait after the first try fails. This is the
    /// reference's formula exactly, including the floor being applied outside the ceiling, and
    /// including the saturation the reference gets for free from `Infinity`.
    #[must_use]
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let doubled = self
            .base_delay
            .checked_mul(1_u32.checked_shl(attempt).unwrap_or(u32::MAX))
            .unwrap_or(Duration::MAX);
        // `max(min, min(max, doubled))`, in that order: a floor above the ceiling wins.
        self.min_delay.max(self.max_delay.min(doubled))
    }

    /// Returns the delay to wait, jittered, and honouring server guidance when the policy says to.
    ///
    /// `randomness` is drawn by the caller from a [`JitterSource`](super::JitterSource); `now` is
    /// used only to interpret the date form of `Retry-After`.
    #[must_use]
    pub fn delay_with_guidance(
        &self,
        attempt: u32,
        randomness: u32,
        guidance: Option<RetryAfter>,
        now: std::time::SystemTime,
    ) -> Duration {
        if let (RetryAfterPolicy::Honor { maximum }, Some(guidance)) = (self.retry_after, guidance) {
            // Server guidance replaces the computed delay rather than adding to it, and is not
            // jittered: the server named a moment, and spreading clients away from it is the
            // server's business, not the client's.
            return guidance.delay_from(now).min(maximum);
        }
        self.jitter.apply(self.delay_for(attempt), randomness)
    }
}

impl Default for RetryPolicy {
    /// The workspace's default policy.
    ///
    /// The reference's own delay shape — 50 ms doubling to a 10 s ceiling — with the bounds it
    /// lacks: five attempts and a thirty-second total budget, jittered, `GET` only.
    fn default() -> Self {
        Self {
            max_attempts: NonZeroU32::new(5).unwrap_or(NonZeroU32::MIN),
            base_delay: Duration::from_millis(50),
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_secs(10),
            deadline: Some(Duration::from_secs(30)),
            jitter: Jitter::Equal,
            scope: RetryScope::RepeatableOnly,
            retry_after: RetryAfterPolicy::default(),
        }
    }
}

/// Assembles a [`RetryPolicy`].
///
/// Every setter is infallible; [`RetryPolicyBuilder::build`] checks every bound at once, so a zero
/// attempt count and an oversized delay are reported the same way.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicyBuilder {
    max_attempts: u32,
    base_delay: Duration,
    min_delay: Duration,
    max_delay: Duration,
    deadline: Option<Duration>,
    jitter: Jitter,
    scope: RetryScope,
    retry_after: RetryAfterPolicy,
}

impl Default for RetryPolicyBuilder {
    /// Starts from [`RetryPolicy::default`].
    fn default() -> Self {
        let policy = RetryPolicy::default();
        Self {
            max_attempts: policy.max_attempts(),
            base_delay: policy.base_delay,
            min_delay: policy.min_delay,
            max_delay: policy.max_delay,
            deadline: policy.deadline,
            jitter: policy.jitter,
            scope: policy.scope,
            retry_after: policy.retry_after,
        }
    }
}

impl RetryPolicyBuilder {
    /// Sets how many attempts may be made in total, the first included.
    #[must_use]
    pub const fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Sets the delay the first retry is computed from.
    #[must_use]
    pub const fn base_delay(mut self, delay: Duration) -> Self {
        self.base_delay = delay;
        self
    }

    /// Sets the floor, which is applied after the ceiling.
    #[must_use]
    pub const fn min_delay(mut self, delay: Duration) -> Self {
        self.min_delay = delay;
        self
    }

    /// Sets the ceiling the doubling flattens at.
    #[must_use]
    pub const fn max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Sets the total time budget, measured from the first attempt.
    #[must_use]
    pub const fn deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Removes the total time budget, leaving the attempt count as the only bound.
    ///
    /// The schedule still terminates: retries must be bounded, which is why there is no way to
    /// remove *both* bounds and reproduce the reference's `while (true)`.
    #[must_use]
    pub const fn without_deadline(mut self) -> Self {
        self.deadline = None;
        self
    }

    /// Sets how a computed delay is randomised.
    #[must_use]
    pub const fn jitter(mut self, jitter: Jitter) -> Self {
        self.jitter = jitter;
        self
    }

    /// Sets which methods may be retried.
    #[must_use]
    pub const fn scope(mut self, scope: RetryScope) -> Self {
        self.scope = scope;
        self
    }

    /// Sets what happens to a `Retry-After` header.
    #[must_use]
    pub const fn retry_after(mut self, retry_after: RetryAfterPolicy) -> Self {
        self.retry_after = retry_after;
        self
    }

    /// Validates and assembles the policy.
    ///
    /// # Errors
    ///
    /// Returns [`RetryPolicyError::NoAttempts`] for a zero attempt count,
    /// [`RetryPolicyError::TooManyAttempts`] above [`MAX_ATTEMPTS`],
    /// [`RetryPolicyError::ZeroDelay`] for a zero base, floor, or ceiling,
    /// [`RetryPolicyError::DelayTooLong`] above [`MAX_DELAY_BOUND_SECONDS`], and
    /// [`RetryPolicyError::ZeroDeadline`] for a zero deadline.
    pub fn build(self) -> Result<RetryPolicy, RetryPolicyError> {
        let Some(max_attempts) = NonZeroU32::new(self.max_attempts) else {
            return Err(RetryPolicyError::NoAttempts);
        };
        if self.max_attempts > MAX_ATTEMPTS {
            return Err(RetryPolicyError::TooManyAttempts {
                maximum: MAX_ATTEMPTS,
                requested: self.max_attempts,
            });
        }
        let ceiling = Duration::from_secs(MAX_DELAY_BOUND_SECONDS);
        for (which, delay) in [
            ("base", self.base_delay),
            ("minimum", self.min_delay),
            ("maximum", self.max_delay),
        ] {
            if delay.is_zero() {
                return Err(RetryPolicyError::ZeroDelay { which });
            }
            if delay > ceiling {
                return Err(RetryPolicyError::DelayTooLong {
                    which,
                    requested: delay,
                });
            }
        }
        if let Some(deadline) = self.deadline
            && deadline.is_zero()
        {
            return Err(RetryPolicyError::ZeroDeadline);
        }
        if let RetryAfterPolicy::Honor { maximum } = self.retry_after
            && maximum > ceiling
        {
            return Err(RetryPolicyError::DelayTooLong {
                which: "Retry-After",
                requested: maximum,
            });
        }
        Ok(RetryPolicy {
            max_attempts,
            base_delay: self.base_delay,
            min_delay: self.min_delay,
            max_delay: self.max_delay,
            deadline: self.deadline,
            jitter: self.jitter,
            scope: self.scope,
            retry_after: self.retry_after,
        })
    }
}

/// Stable retry-policy construction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RetryPolicyError {
    /// The attempt count is zero, so nothing would ever be tried.
    NoAttempts,
    /// The attempt count exceeds [`MAX_ATTEMPTS`].
    TooManyAttempts {
        /// Accepted maximum.
        maximum: u32,
        /// Requested count.
        requested: u32,
    },
    /// A delay bound is zero, which would spin instead of backing off.
    ZeroDelay {
        /// Which bound.
        which: &'static str,
    },
    /// A delay bound exceeds [`MAX_DELAY_BOUND_SECONDS`].
    DelayTooLong {
        /// Which bound.
        which: &'static str,
        /// Requested value.
        requested: Duration,
    },
    /// The total deadline is zero, so the first attempt would already be too late.
    ZeroDeadline,
}

impl fmt::Display for RetryPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAttempts => formatter.write_str("a retry policy must allow at least one attempt"),
            Self::TooManyAttempts { maximum, requested } => {
                write!(formatter, "{requested} attempts exceeds maximum {maximum}")
            }
            Self::ZeroDelay { which } => write!(formatter, "the {which} delay may not be zero"),
            Self::DelayTooLong { which, requested } => write!(
                formatter,
                "the {which} delay of {requested:?} exceeds maximum {MAX_DELAY_BOUND_SECONDS} s"
            ),
            Self::ZeroDeadline => formatter.write_str("a retry deadline may not be zero"),
        }
    }
}

impl Error for RetryPolicyError {}

/// One retry schedule in progress.
///
/// Holds the attempt counter and the moment the first attempt started, so a deadline is measured
/// from the beginning rather than from the last failure.
#[derive(Clone, Copy, Debug)]
pub struct Backoff {
    policy: RetryPolicy,
    attempt: u32,
    started: Instant,
}

/// What a schedule says to do next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDecision {
    /// Wait this long, then try again.
    Retry {
        /// How long to wait.
        delay: Duration,
        /// Which attempt is about to be made, zero-based.
        attempt: u32,
    },
    /// Stop, for this reason.
    Stop(StopReason),
}

/// Why a schedule stopped.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum StopReason {
    /// The outcome is not one this policy retries.
    NotRetryable,
    /// The request's method is outside the policy's [`RetryScope`].
    MethodNotRepeatable,
    /// Every allowed attempt has been made.
    AttemptsExhausted,
    /// The total deadline would elapse before, or during, the next wait.
    DeadlineElapsed,
}

impl Backoff {
    /// Starts a schedule at `now`.
    #[must_use]
    pub const fn new(policy: RetryPolicy, now: Instant) -> Self {
        Self {
            policy,
            attempt: 0,
            started: now,
        }
    }

    /// Returns how many attempts have been made.
    #[must_use]
    pub const fn attempts_made(&self) -> u32 {
        self.attempt.saturating_add(1)
    }

    /// Returns the policy this schedule follows.
    #[must_use]
    pub const fn policy(&self) -> &RetryPolicy {
        &self.policy
    }

    /// Decides what to do after an attempt failed, and advances the schedule when it says retry.
    ///
    /// `retryable` is whether the outcome itself is worth repeating —
    /// [`is_transient_status`] and [`is_transient_error`] answer that — and `method` is checked
    /// against the policy's scope. `guidance` is the response's `Retry-After`, when it had one.
    ///
    /// A wait that would carry the schedule past its deadline stops instead of sleeping into it,
    /// which is what makes the deadline a real bound rather than a check that happens too late.
    #[must_use]
    pub fn next(
        &mut self,
        now: Instant,
        method: Method,
        retryable: bool,
        randomness: u32,
        guidance: Option<RetryAfter>,
        wall_clock: std::time::SystemTime,
    ) -> RetryDecision {
        if !retryable {
            return RetryDecision::Stop(StopReason::NotRetryable);
        }
        if !self.policy.scope.admits(method) {
            return RetryDecision::Stop(StopReason::MethodNotRepeatable);
        }
        if self.attempts_made() >= self.policy.max_attempts() {
            return RetryDecision::Stop(StopReason::AttemptsExhausted);
        }

        let delay = self
            .policy
            .delay_with_guidance(self.attempt, randomness, guidance, wall_clock);

        if let Some(deadline) = self.policy.deadline {
            let elapsed = now.saturating_duration_since(self.started);
            // The wait must finish inside the budget, not merely start inside it: the reference
            // checks its timeout only at the top of the loop, so its last sleep can run past it.
            if elapsed.saturating_add(delay) >= deadline {
                return RetryDecision::Stop(StopReason::DeadlineElapsed);
            }
        }

        self.attempt = self.attempt.saturating_add(1);
        RetryDecision::Retry {
            delay,
            attempt: self.attempt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::displays_and_sources;
    use std::error::Error;

    fn reference_policy() -> Result<RetryPolicy, Box<dyn Error>> {
        Ok(RetryPolicy::builder()
            .base_delay(Duration::from_millis(50))
            .min_delay(Duration::from_millis(10))
            .max_delay(Duration::from_secs(10))
            .jitter(Jitter::None)
            .max_attempts(64)
            .without_deadline()
            .build()?)
    }

    fn millis(policy: &RetryPolicy, count: u32) -> Vec<u64> {
        (0..count)
            .map(|attempt| u64::try_from(policy.delay_for(attempt).as_millis()).unwrap_or(u64::MAX))
            .collect()
    }

    #[test]
    fn the_reference_schedule_is_reproduced() -> Result<(), Box<dyn Error>> {
        let policy = reference_policy()?;
        assert_eq!(
            millis(&policy, 12),
            [50, 100, 200, 400, 800, 1600, 3200, 6400, 10_000, 10_000, 10_000, 10_000]
        );
        Ok(())
    }

    #[test]
    fn a_floor_that_binds_is_reproduced() -> Result<(), Box<dyn Error>> {
        // The vLEI suites' options: minSleep 1000, maxSleep 10000.
        let policy = RetryPolicy::builder()
            .base_delay(Duration::from_millis(50))
            .min_delay(Duration::from_secs(1))
            .max_delay(Duration::from_secs(10))
            .jitter(Jitter::None)
            .max_attempts(64)
            .build()?;
        assert_eq!(millis(&policy, 8), [1000, 1000, 1000, 1000, 1000, 1600, 3200, 6400]);
        Ok(())
    }

    #[test]
    fn an_equal_floor_and_ceiling_flattens_the_curve() -> Result<(), Box<dyn Error>> {
        // multisig-join's options: minSleep === maxSleep === 500.
        let policy = RetryPolicy::builder()
            .base_delay(Duration::from_millis(50))
            .min_delay(Duration::from_millis(500))
            .max_delay(Duration::from_millis(500))
            .jitter(Jitter::None)
            .max_attempts(64)
            .build()?;
        assert_eq!(millis(&policy, 5), [500, 500, 500, 500, 500]);
        Ok(())
    }

    #[test]
    fn a_floor_above_the_ceiling_wins() -> Result<(), Box<dyn Error>> {
        // `max(min, min(max, x))` is not a clamp; the reference applies the floor last.
        let policy = RetryPolicy::builder()
            .base_delay(Duration::from_millis(50))
            .min_delay(Duration::from_secs(2))
            .max_delay(Duration::from_secs(1))
            .jitter(Jitter::None)
            .max_attempts(8)
            .build()?;
        assert_eq!(millis(&policy, 4), [2000, 2000, 2000, 2000]);
        Ok(())
    }

    #[test]
    fn the_doubling_saturates_rather_than_overflowing() -> Result<(), Box<dyn Error>> {
        let policy = reference_policy()?;
        // The reference gets `Infinity` here and `Math.min` pins it to the ceiling; a shift past
        // the width would wrap, so it is checked.
        for attempt in [31_u32, 32, 63, 64, 1_000, u32::MAX] {
            assert_eq!(policy.delay_for(attempt), Duration::from_secs(10), "{attempt}");
        }
        Ok(())
    }

    #[test]
    fn the_jitter_extremes_are_exact() {
        let delay = Duration::from_millis(800);
        assert_eq!(Jitter::Equal.apply(delay, 0), Duration::from_millis(400));
        assert_eq!(Jitter::Full.apply(delay, u32::MAX), delay);
        assert_eq!(Jitter::default(), Jitter::Equal);
        // A zero delay stays zero however it is jittered.
        for jitter in [Jitter::None, Jitter::Equal, Jitter::Full] {
            assert_eq!(jitter.apply(Duration::ZERO, u32::MAX), Duration::ZERO);
        }
    }

    #[test]
    fn jitter_does_not_overflow_on_an_enormous_delay() {
        let jittered = Jitter::Full.apply(Duration::MAX, u32::MAX);
        assert!(jittered <= Duration::MAX);
        assert!(Jitter::Equal.apply(Duration::MAX, u32::MAX) <= Duration::MAX);
    }

    #[test]
    fn the_scope_guards_unsafe_methods() {
        assert!(RetryScope::RepeatableOnly.admits(Method::Get));
        assert!(RetryScope::AnyMethod.admits(Method::Get));
        assert!(!RetryScope::RepeatableOnly.admits(Method::Post));
        assert!(!RetryScope::RepeatableOnly.admits(Method::Put));
        assert!(!RetryScope::RepeatableOnly.admits(Method::Delete));
        assert!(RetryScope::AnyMethod.admits(Method::Post));
        assert_eq!(RetryScope::default(), RetryScope::RepeatableOnly);
    }

    #[test]
    fn only_transient_outcomes_are_retried() -> Result<(), Box<dyn Error>> {
        for code in [408_u16, 429, 502, 503, 504] {
            assert!(is_transient_status(StatusCode::new(code)?), "{code}");
        }
        for code in [200_u16, 201, 301, 400, 401, 403, 404, 409, 500, 501, 505] {
            assert!(!is_transient_status(StatusCode::new(code)?), "{code}");
        }

        assert!(is_transient_error(&TransportError::Timeout { milliseconds: 1 }));
        assert!(is_transient_error(&TransportError::connect("refused")));
        assert!(is_transient_error(&TransportError::invalid_response("truncated")));
        for error in [
            TransportError::InvalidUrl { reason: "empty" },
            TransportError::RequestBodyTooLarge { maximum: 1, actual: 2 },
            TransportError::ResponseBodyTooLarge { limit: 1, actual: 2 },
            TransportError::ResponseLimitTooLarge {
                maximum: 1,
                requested: 2,
            },
            TransportError::InvalidStatus { status: 99 },
            TransportError::ScriptExhausted { answered: 1 },
            TransportError::signing("no covered header"),
        ] {
            assert!(!is_transient_error(&error), "{error}");
        }
        Ok(())
    }

    #[test]
    fn a_schedule_is_bounded_by_its_attempt_count() -> Result<(), Box<dyn Error>> {
        let policy = RetryPolicy::builder()
            .max_attempts(3)
            .jitter(Jitter::None)
            .without_deadline()
            .build()?;
        let now = Instant::now();
        let mut backoff = Backoff::new(policy, now);
        assert_eq!(backoff.attempts_made(), 1);
        assert_eq!(backoff.policy().max_attempts(), 3);

        for expected in 1..3_u32 {
            let decision = backoff.next(now, Method::Get, true, 0, None, std::time::SystemTime::now());
            assert!(
                matches!(decision, RetryDecision::Retry { attempt, .. } if attempt == expected),
                "{decision:?}",
            );
        }
        // Three attempts made; the third failure has nothing left.
        assert_eq!(
            backoff.next(now, Method::Get, true, 0, None, std::time::SystemTime::now()),
            RetryDecision::Stop(StopReason::AttemptsExhausted),
        );
        Ok(())
    }

    #[test]
    fn a_schedule_stops_rather_than_sleeping_past_its_deadline() -> Result<(), Box<dyn Error>> {
        let policy = RetryPolicy::builder()
            .max_attempts(100)
            .base_delay(Duration::from_secs(1))
            .min_delay(Duration::from_millis(1))
            .max_delay(Duration::from_secs(10))
            .deadline(Duration::from_secs(3))
            .jitter(Jitter::None)
            .build()?;
        let start = Instant::now();
        let mut backoff = Backoff::new(policy, start);

        // One second in: a one-second wait fits inside the three-second budget.
        let first = backoff.next(start, Method::Get, true, 0, None, std::time::SystemTime::now());
        assert!(matches!(first, RetryDecision::Retry { delay, .. } if delay == Duration::from_secs(1)));

        // Two seconds in, the next wait is two seconds and would land exactly on the deadline.
        let second = backoff.next(
            start + Duration::from_secs(1),
            Method::Get,
            true,
            0,
            None,
            std::time::SystemTime::now(),
        );
        assert_eq!(second, RetryDecision::Stop(StopReason::DeadlineElapsed));
        Ok(())
    }

    #[test]
    fn a_non_retryable_outcome_and_an_unsafe_method_stop_immediately() -> Result<(), Box<dyn Error>> {
        let policy = RetryPolicy::builder().max_attempts(5).build()?;
        let now = Instant::now();
        let wall = std::time::SystemTime::now();

        let mut backoff = Backoff::new(policy, now);
        assert_eq!(
            backoff.next(now, Method::Get, false, 0, None, wall),
            RetryDecision::Stop(StopReason::NotRetryable),
        );

        let mut backoff = Backoff::new(policy, now);
        assert_eq!(
            backoff.next(now, Method::Post, true, 0, None, wall),
            RetryDecision::Stop(StopReason::MethodNotRepeatable),
        );
        // Widening the scope admits it.
        let wide = RetryPolicy::builder()
            .max_attempts(5)
            .scope(RetryScope::AnyMethod)
            .build()?;
        let mut backoff = Backoff::new(wide, now);
        assert!(matches!(
            backoff.next(now, Method::Post, true, 0, None, wall),
            RetryDecision::Retry { .. }
        ));
        Ok(())
    }

    #[test]
    fn the_default_policy_is_bounded_and_jittered() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts(), 5);
        assert_eq!(policy.base_delay(), Duration::from_millis(50));
        assert_eq!(policy.min_delay(), Duration::from_millis(10));
        assert_eq!(policy.max_delay(), Duration::from_secs(10));
        assert_eq!(policy.deadline(), Some(Duration::from_secs(30)));
        assert_eq!(policy.jitter(), Jitter::Equal);
        assert_eq!(policy.scope(), RetryScope::RepeatableOnly);
        assert_eq!(
            policy.retry_after(),
            RetryAfterPolicy::Honor {
                maximum: Duration::from_mins(1)
            },
        );
    }

    #[test]
    fn errors_carry_readable_text() {
        let cases: [(RetryPolicyError, &[&str]); 3] = [
            (
                RetryPolicyError::TooManyAttempts {
                    maximum: 1_031,
                    requested: 9_999,
                },
                &["1031", "9999"],
            ),
            (RetryPolicyError::ZeroDelay { which: "base" }, &["base"]),
            (
                RetryPolicyError::DelayTooLong {
                    which: "max",
                    requested: Duration::from_secs(9_999),
                },
                &["max", "9999s"],
            ),
        ];
        for (error, fragments) in cases {
            displays_and_sources(&error, fragments, false);
        }
        for (error, expected) in [
            (
                RetryPolicyError::NoAttempts,
                "a retry policy must allow at least one attempt",
            ),
            (RetryPolicyError::ZeroDeadline, "a retry deadline may not be zero"),
        ] {
            assert_eq!(error.to_string(), expected);
            assert!(error.source().is_none());
        }
    }
}
