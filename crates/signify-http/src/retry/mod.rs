//! Retrying a request: how long to wait, when to stop, and who gets told.
//!
//! The pinned reference has no retry module. The delay formula appears twice — in the production
//! `Operations.wait` of `app/coring.ts` and in `test-integration/utils/retry.ts` — and nothing else
//! in the tree retries anything. `fixtures/http-retry/v1.json` records the first by *executing* it
//! with the global timer replaced, and the second from the reference's own syntax tree; the
//! schedule here reproduces both exactly under [`Jitter::None`].
//!
//! What the reference lacks, and this adds, is every bound: `Operations.wait` is a `while (true)`
//! with no deadline and no attempt cap, its abort signal is checked only *after* a sleep of up to
//! ten seconds, there is no jitter, `Retry-After` is ignored — the header appears nowhere in the
//! pinned tree — and the integration helper retries whatever its callback threw, including a
//! `POST` that has already created something.
//!
//! # Layering: signing must happen *inside* the retry loop
//!
//! [`RetryingTransport`] re-executes the **request it was given**, so whatever sits beneath it runs
//! again on every attempt. That is what makes the ordering load-bearing once Roadmap 5.5 adds a
//! signing transport:
//!
//! ```text
//! RetryingTransport  ->  <signing transport>  ->  HttpTransport      correct
//! <signing transport>  ->  RetryingTransport  ->  HttpTransport      replays a stale signature
//! ```
//!
//! A KERIA request carries `Signify-Timestamp`, and its signature covers that value. Signing
//! outside the loop would resend the same timestamp and the same signature minutes later, which is
//! a replay the agent may reject and which no test of the happy path would catch. Signing inside
//! it re-derives both per attempt.
//!
//! # Example
//!
//! ```
//! use core::time::Duration;
//! use std::sync::Arc;
//! use signify_http::retry::{FixedJitter, Jitter, RetryPolicy, RetryingTransport, TestClock};
//! use signify_http::transport::ScriptedTransport;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let policy = RetryPolicy::builder()
//!     .max_attempts(4)
//!     .base_delay(Duration::from_millis(50))
//!     .jitter(Jitter::None)
//!     .build()?;
//!
//! let clock = Arc::new(TestClock::new());
//! let transport = RetryingTransport::new(Arc::new(ScriptedTransport::new()))
//!     .with_policy(policy)
//!     .with_clock(Arc::clone(&clock) as Arc<dyn signify_http::retry::Clock>)
//!     .with_jitter_source(Arc::new(FixedJitter::new(0)));
//!
//! assert_eq!(transport.policy().max_attempts(), 4);
//! assert!(clock.recorded_sleeps().is_empty());
//! # Ok(())
//! # }
//! ```

pub mod backoff;
pub mod clock;
pub mod jitter_source;
pub mod retry_after;

use core::fmt;
use core::time::Duration;
use std::sync::Arc;

pub use backoff::{
    Backoff, Jitter, MAX_ATTEMPTS, MAX_DELAY_BOUND_SECONDS, RetryAfterPolicy, RetryDecision, RetryPolicy,
    RetryPolicyBuilder, RetryPolicyError, RetryScope, StopReason, is_transient_error, is_transient_status,
};
#[cfg(feature = "http-client")]
pub use clock::TokioClock;
pub use clock::{Clock, SleepFuture, TestClock};
pub use jitter_source::{FixedJitter, JitterSource, OsJitter};
pub use retry_after::{MAX_DELAY_SECONDS, MAX_RETRY_AFTER_BYTES, RetryAfter, RetryAfterError};

use crate::response::RequestOrigin;
use crate::transport::{Request, Response, StatusCode, Transport, TransportError, TransportFuture};

/// The header a server names its own timing in.
const RETRY_AFTER_HEADER: &str = "retry-after";

/// One retry that is about to happen.
///
/// Carries the method and the path **without its query**, reusing Roadmap 5.3's
/// [`RequestOrigin`] so an observer that logs cannot accidentally record a caller's filter values.
/// It carries no headers, no body, and no URL — nothing an observer could leak.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RetryEvent {
    /// Which call is being retried.
    pub origin: RequestOrigin,
    /// Which attempt is about to be made, one-based after the first.
    pub attempt: u32,
    /// How long the client will wait first.
    pub delay: Duration,
    /// The status that prompted the retry, when a response arrived at all.
    pub status: Option<StatusCode>,
    /// Whether the delay came from a `Retry-After` header rather than the computed backoff.
    pub from_server_guidance: bool,
}

/// One retry sequence that has ended without success.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GiveUpEvent {
    /// Which call was abandoned.
    pub origin: RequestOrigin,
    /// How many attempts were made in total.
    pub attempts: u32,
    /// Why no further attempt was made.
    pub reason: StopReason,
    /// The status of the last response, when one arrived at all.
    pub status: Option<StatusCode>,
}

/// Watches what a [`RetryingTransport`] does.
///
/// `AGENTS.md` §2.5 requires retries to be observable. This is a trait rather than a log line
/// because a library may not initialise a logger (§2.2), and rather than a `tracing` dependency
/// because a caller who wants one can write four lines in their own crate.
///
/// Both methods default to doing nothing.
pub trait RetryObserver: fmt::Debug + Send + Sync {
    /// Called before each wait, with the retry that is about to be made.
    fn on_retry(&self, event: &RetryEvent) {
        let _ = event;
    }

    /// Called when a sequence ends without a retryable outcome becoming a usable one.
    fn on_give_up(&self, event: &GiveUpEvent) {
        let _ = event;
    }
}

/// An observer that does nothing. The default.
#[derive(Clone, Copy, Debug, Default)]
pub struct IgnoreRetries;

impl RetryObserver for IgnoreRetries {}

/// A [`Transport`] that retries the transport beneath it according to a [`RetryPolicy`].
///
/// A non-success status is still returned as a [`Response`], exactly as Roadmap 5.1 decided: this
/// retries a `503` and then hands back whatever the last attempt produced. Turning a status into a
/// typed failure remains Roadmap 5.3's [`ResourceResponse`](crate::response::ResourceResponse).
///
/// Cancellation is dropping the returned future, which stops inside the wait — the thing the
/// reference cannot do, because it checks its abort signal only after waking.
#[derive(Clone, Debug)]
pub struct RetryingTransport {
    inner: Arc<dyn Transport>,
    policy: RetryPolicy,
    clock: Arc<dyn Clock>,
    jitter: Arc<dyn JitterSource>,
    observer: Arc<dyn RetryObserver>,
}

impl RetryingTransport {
    /// Wraps a transport with the default policy, an operating-system jitter source, and a clock.
    ///
    /// Without the `http-client` feature there is no runtime to wait on, so the default clock is a
    /// [`TestClock`] and a caller must supply a real one with [`RetryingTransport::with_clock`]. With
    /// the feature the default is [`TokioClock`].
    #[must_use]
    pub fn new(inner: Arc<dyn Transport>) -> Self {
        #[cfg(feature = "http-client")]
        let clock: Arc<dyn Clock> = Arc::new(TokioClock);
        #[cfg(not(feature = "http-client"))]
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new());
        Self {
            inner,
            policy: RetryPolicy::default(),
            clock,
            jitter: Arc::new(OsJitter),
            observer: Arc::new(IgnoreRetries),
        }
    }

    /// Sets the policy.
    #[must_use]
    pub fn with_policy(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Sets the clock this transport measures and waits with.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Sets where jitter draws its randomness from.
    #[must_use]
    pub fn with_jitter_source(mut self, jitter: Arc<dyn JitterSource>) -> Self {
        self.jitter = jitter;
        self
    }

    /// Sets the observer told about each retry.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn RetryObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Returns the policy in force.
    #[must_use]
    pub const fn policy(&self) -> &RetryPolicy {
        &self.policy
    }
}

/// Reads the server's own timing from a response, when it gave one and the policy wants it.
fn guidance_of(policy: &RetryPolicy, response: &Response) -> Option<RetryAfter> {
    if matches!(policy.retry_after(), RetryAfterPolicy::Ignore) {
        return None;
    }
    // A malformed value is *not* an error: the computed backoff takes over, so the worst a broken
    // header costs is the server's preferred timing.
    RetryAfter::parse(response.headers().get(RETRY_AFTER_HEADER)?).ok()
}

impl Transport for RetryingTransport {
    fn execute(&self, request: Request) -> TransportFuture<'_> {
        Box::pin(async move {
            let origin = RequestOrigin::of(&request);
            let method = request.method();
            let mut backoff = Backoff::new(self.policy, self.clock.now());

            loop {
                // Each attempt sends its own clone, so whatever sits beneath — a signing transport
                // in Roadmap 5.5 — runs again and re-derives anything time-dependent.
                let outcome: Result<Response, TransportError> = self.inner.execute(request.clone()).await;

                let (retryable, status, guidance) = match &outcome {
                    Ok(response) => (
                        is_transient_status(response.status()),
                        Some(response.status()),
                        guidance_of(&self.policy, response),
                    ),
                    Err(error) => (is_transient_error(error), None, None),
                };
                if !retryable {
                    // Every success lands here, and so does every failure that repeating cannot fix.
                    return outcome;
                }

                let from_server_guidance = guidance.is_some();
                let decision = backoff.next(
                    self.clock.now(),
                    method,
                    true,
                    self.jitter.next_u32(),
                    guidance,
                    self.clock.wall_clock(),
                );

                match decision {
                    RetryDecision::Retry { delay, attempt } => {
                        self.observer.on_retry(&RetryEvent {
                            origin: origin.clone(),
                            attempt,
                            delay,
                            status,
                            from_server_guidance,
                        });
                        self.clock.sleep(delay).await;
                    }
                    RetryDecision::Stop(reason) => {
                        self.observer.on_give_up(&GiveUpEvent {
                            origin,
                            attempts: backoff.attempts_made(),
                            reason,
                            status,
                        });
                        return outcome;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{HeaderName, HeaderValue, Headers};
    use crate::transport::{Method, RequestUrl, ScriptedTransport};
    use std::error::Error;
    use std::sync::Mutex;

    /// Compile-time proof that a value can cross threads.
    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    /// A minimal executor; every future reachable from a scripted transport and a test clock is
    /// ready on its first poll.
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

    #[derive(Debug, Default)]
    struct Recorder {
        retries: Mutex<Vec<RetryEvent>>,
        give_ups: Mutex<Vec<GiveUpEvent>>,
    }

    impl Recorder {
        fn retries(&self) -> Vec<RetryEvent> {
            self.retries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn give_ups(&self) -> Vec<GiveUpEvent> {
            self.give_ups
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl RetryObserver for Recorder {
        fn on_retry(&self, event: &RetryEvent) {
            self.retries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event.clone());
        }

        fn on_give_up(&self, event: &GiveUpEvent) {
            self.give_ups
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event.clone());
        }
    }

    fn request(method: Method) -> Result<Request, Box<dyn Error>> {
        Ok(Request::builder(
            method,
            RequestUrl::new("http://localhost:3901/identifiers?filter=secret")?,
        )
        .build()?)
    }

    fn response(status: u16, retry_after: Option<&str>) -> Result<Response, Box<dyn Error>> {
        let mut headers = Headers::new();
        if let Some(value) = retry_after {
            headers.insert(HeaderName::new("Retry-After")?, HeaderValue::new(value)?)?;
        }
        Ok(Response::new(StatusCode::new(status)?, headers, Vec::new())?)
    }

    fn reference_policy(attempts: u32) -> Result<RetryPolicy, Box<dyn Error>> {
        Ok(RetryPolicy::builder()
            .max_attempts(attempts)
            .base_delay(Duration::from_millis(50))
            .min_delay(Duration::from_millis(10))
            .max_delay(Duration::from_secs(10))
            .jitter(Jitter::None)
            .without_deadline()
            .build()?)
    }

    #[test]
    fn a_success_is_returned_without_retrying() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(TestClock::new());
        let scripted = Arc::new(ScriptedTransport::new().respond(response(200, None)?));
        let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
            .with_policy(reference_policy(5)?)
            .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);

        let answer = block_on(transport.execute(request(Method::Get)?));
        assert_eq!(answer.map(|response| response.status().as_u16()).ok(), Some(200));
        assert_eq!(scripted.answered(), 1);
        assert_eq!(clock.recorded_sleeps(), [] as [Duration; 0]);
        Ok(())
    }

    #[test]
    fn a_transient_status_is_retried_on_the_reference_schedule() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(TestClock::new());
        let observer = Arc::new(Recorder::default());
        let scripted = Arc::new(
            ScriptedTransport::new()
                .respond(response(503, None)?)
                .respond(response(503, None)?)
                .respond(response(200, None)?),
        );
        let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
            .with_policy(reference_policy(5)?)
            .with_clock(Arc::clone(&clock) as Arc<dyn Clock>)
            .with_observer(Arc::clone(&observer) as Arc<dyn RetryObserver>);

        let answer = block_on(transport.execute(request(Method::Get)?));
        assert_eq!(answer.map(|response| response.status().as_u16()).ok(), Some(200));
        assert_eq!(scripted.answered(), 3);
        // The reference's own first two delays, and no wall-clock time spent on them.
        assert_eq!(
            clock.recorded_sleeps(),
            [Duration::from_millis(50), Duration::from_millis(100)]
        );

        let retries = observer.retries();
        assert_eq!(retries.len(), 2);
        assert_eq!(retries.first().map(|event| event.attempt), Some(1));
        assert_eq!(
            retries.first().and_then(|event| event.status).map(StatusCode::as_u16),
            Some(503),
        );
        // The observer never sees the query.
        assert_eq!(retries.first().map(|event| event.origin.path()), Some("/identifiers"));
        assert_eq!(observer.give_ups(), [] as [GiveUpEvent; 0]);
        Ok(())
    }

    #[test]
    fn a_permanent_status_is_returned_untouched() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(TestClock::new());
        // 500 is deliberately not in the transient set.
        for status in [400_u16, 404, 500, 501] {
            let scripted = Arc::new(ScriptedTransport::new().respond(response(status, None)?));
            let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
                .with_policy(reference_policy(5)?)
                .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);
            let answer = block_on(transport.execute(request(Method::Get)?));
            assert_eq!(
                answer.map(|response| response.status().as_u16()).ok(),
                Some(status),
                "{status}",
            );
            assert_eq!(scripted.answered(), 1, "{status}");
        }
        assert_eq!(clock.recorded_sleeps(), [] as [Duration; 0]);
        Ok(())
    }

    #[test]
    fn a_post_is_not_retried_unless_the_scope_widens() -> Result<(), Box<dyn Error>> {
        let observer = Arc::new(Recorder::default());
        let scripted = Arc::new(
            ScriptedTransport::new()
                .respond(response(503, None)?)
                .respond(response(200, None)?),
        );
        let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
            .with_policy(reference_policy(5)?)
            .with_clock(Arc::new(TestClock::new()))
            .with_observer(Arc::clone(&observer) as Arc<dyn RetryObserver>);

        // Repeating this could create a second identifier.
        let answer = block_on(transport.execute(request(Method::Post)?));
        assert_eq!(answer.map(|response| response.status().as_u16()).ok(), Some(503));
        assert_eq!(scripted.answered(), 1);
        assert_eq!(
            observer.give_ups().first().map(|event| event.reason),
            Some(StopReason::MethodNotIdempotent),
        );

        // The caller may assert that repeating is safe.
        let scripted = Arc::new(
            ScriptedTransport::new()
                .respond(response(503, None)?)
                .respond(response(200, None)?),
        );
        let widened = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
            .with_policy(
                RetryPolicy::builder()
                    .max_attempts(5)
                    .jitter(Jitter::None)
                    .scope(RetryScope::AnyMethod)
                    .build()?,
            )
            .with_clock(Arc::new(TestClock::new()));
        let answer = block_on(widened.execute(request(Method::Post)?));
        assert_eq!(answer.map(|response| response.status().as_u16()).ok(), Some(200));
        assert_eq!(scripted.answered(), 2);
        Ok(())
    }

    #[test]
    fn server_guidance_overrides_the_computed_delay() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(TestClock::new());
        let observer = Arc::new(Recorder::default());
        let scripted = Arc::new(
            ScriptedTransport::new()
                .respond(response(429, Some("5"))?)
                .respond(response(200, None)?),
        );
        let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
            .with_policy(reference_policy(5)?)
            .with_clock(Arc::clone(&clock) as Arc<dyn Clock>)
            .with_observer(Arc::clone(&observer) as Arc<dyn RetryObserver>);

        let _ = block_on(transport.execute(request(Method::Get)?));
        // Five seconds, not the computed fifty milliseconds.
        assert_eq!(clock.recorded_sleeps(), [Duration::from_secs(5)]);
        assert_eq!(
            observer.retries().first().map(|event| event.from_server_guidance),
            Some(true),
        );
        Ok(())
    }

    #[test]
    fn a_malformed_retry_after_falls_back_to_the_computed_delay() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(TestClock::new());
        let scripted = Arc::new(
            ScriptedTransport::new()
                .respond(response(503, Some("soon please"))?)
                .respond(response(200, None)?),
        );
        let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
            .with_policy(reference_policy(5)?)
            .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);

        let _ = block_on(transport.execute(request(Method::Get)?));
        // The broken header costs the server its preferred timing, nothing more.
        assert_eq!(clock.recorded_sleeps(), [Duration::from_millis(50)]);
        Ok(())
    }

    #[test]
    fn attempts_are_bounded_and_the_last_outcome_is_returned() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(TestClock::new());
        let observer = Arc::new(Recorder::default());
        let mut scripted = ScriptedTransport::new();
        for _ in 0..8 {
            scripted = scripted.respond(response(503, None)?);
        }
        let scripted = Arc::new(scripted);
        let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
            .with_policy(reference_policy(3)?)
            .with_clock(Arc::clone(&clock) as Arc<dyn Clock>)
            .with_observer(Arc::clone(&observer) as Arc<dyn RetryObserver>);

        let answer = block_on(transport.execute(request(Method::Get)?));
        assert_eq!(answer.map(|response| response.status().as_u16()).ok(), Some(503));
        // Three attempts, so two waits.
        assert_eq!(scripted.answered(), 3);
        assert_eq!(
            clock.recorded_sleeps(),
            [Duration::from_millis(50), Duration::from_millis(100)]
        );
        let give_up = observer.give_ups();
        assert_eq!(give_up.len(), 1);
        assert_eq!(
            give_up.first().map(|event| (event.attempts, event.reason)),
            Some((3, StopReason::AttemptsExhausted)),
        );
        Ok(())
    }

    #[test]
    fn a_deadline_stops_the_sequence_before_it_sleeps_past_it() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(TestClock::new());
        let observer = Arc::new(Recorder::default());
        let mut scripted = ScriptedTransport::new();
        for _ in 0..20 {
            scripted = scripted.respond(response(503, None)?);
        }
        let transport = RetryingTransport::new(Arc::new(scripted) as Arc<dyn Transport>)
            .with_policy(
                RetryPolicy::builder()
                    .max_attempts(100)
                    .base_delay(Duration::from_millis(50))
                    .min_delay(Duration::from_millis(10))
                    .max_delay(Duration::from_secs(10))
                    .deadline(Duration::from_secs(1))
                    .jitter(Jitter::None)
                    .build()?,
            )
            .with_clock(Arc::clone(&clock) as Arc<dyn Clock>)
            .with_observer(Arc::clone(&observer) as Arc<dyn RetryObserver>);

        let _ = block_on(transport.execute(request(Method::Get)?));
        // 50 + 100 + 200 + 400 = 750; the next wait of 800 ms would pass one second, so it never
        // happens. The reference would have slept into and past its own timeout.
        assert_eq!(
            clock.recorded_sleeps(),
            [
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(400),
            ],
        );
        assert!(clock.elapsed() < Duration::from_secs(1));
        assert_eq!(
            observer.give_ups().first().map(|event| event.reason),
            Some(StopReason::DeadlineElapsed),
        );
        Ok(())
    }

    #[test]
    fn a_transient_transport_failure_is_retried_and_a_permanent_one_is_not() -> Result<(), Box<dyn Error>> {
        let clock = Arc::new(TestClock::new());
        let scripted = Arc::new(
            ScriptedTransport::new()
                .fail(TransportError::connect("connection refused"))
                .respond(response(200, None)?),
        );
        let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
            .with_policy(reference_policy(5)?)
            .with_clock(Arc::clone(&clock) as Arc<dyn Clock>);
        let answer = block_on(transport.execute(request(Method::Get)?));
        assert_eq!(answer.map(|response| response.status().as_u16()).ok(), Some(200));
        assert_eq!(clock.recorded_sleeps(), [Duration::from_millis(50)]);

        // A request that is malformed will be malformed again.
        let scripted = Arc::new(
            ScriptedTransport::new()
                .fail(TransportError::RequestBodyTooLarge { maximum: 1, actual: 2 })
                .respond(response(200, None)?),
        );
        let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
            .with_policy(reference_policy(5)?)
            .with_clock(Arc::new(TestClock::new()));
        assert!(block_on(transport.execute(request(Method::Get)?)).is_err());
        assert_eq!(scripted.answered(), 1);
        Ok(())
    }

    #[test]
    fn dropping_the_future_stops_the_sequence() -> Result<(), Box<dyn Error>> {
        let scripted = Arc::new(
            ScriptedTransport::new()
                .respond(response(503, None)?)
                .respond(response(200, None)?),
        );
        let transport = RetryingTransport::new(Arc::clone(&scripted) as Arc<dyn Transport>)
            .with_policy(reference_policy(5)?)
            .with_clock(Arc::new(TestClock::new()));

        // Never polled, so nothing was sent at all.
        let pending = transport.execute(request(Method::Get)?);
        drop(pending);
        assert_eq!(scripted.answered(), 0);
        Ok(())
    }

    #[test]
    fn the_transport_is_usable_behind_a_trait_object() -> Result<(), Box<dyn Error>> {
        let transport: Arc<dyn Transport> = Arc::new(
            RetryingTransport::new(Arc::new(ScriptedTransport::new().respond(response(200, None)?)))
                .with_clock(Arc::new(TestClock::new())),
        );
        let answer = block_on(transport.execute(request(Method::Get)?));
        assert!(answer.is_ok());
        assert_ne!(format!("{transport:?}"), "");
        assert_send_sync(&transport);
        Ok(())
    }

    #[test]
    fn the_default_observer_and_policy_are_usable() -> Result<(), Box<dyn Error>> {
        let transport = RetryingTransport::new(Arc::new(ScriptedTransport::new()));
        assert_eq!(transport.policy().max_attempts(), 5);
        // The no-op observer accepts both events without doing anything.
        let origin = RequestOrigin::of(&request(Method::Get)?);
        IgnoreRetries.on_retry(&RetryEvent {
            origin: origin.clone(),
            attempt: 1,
            delay: Duration::ZERO,
            status: None,
            from_server_guidance: false,
        });
        IgnoreRetries.on_give_up(&GiveUpEvent {
            origin,
            attempts: 1,
            reason: StopReason::NotRetryable,
            status: None,
        });
        Ok(())
    }
}
