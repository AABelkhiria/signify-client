//! Time, and waiting, as something a test can control.
//!
//! A retry policy needs three things from the world: a monotonic reading to measure a deadline
//! against, a way to wait, and — only to interpret a `Retry-After` that names a date — a wall-clock
//! reading. All three come through [`Clock`], so `AGENTS.md` §8's "tests may not sleep in
//! wall-clock time" is a property of the design rather than of the discipline of whoever writes
//! the next test.
//!
//! # Why the two readings are separate
//!
//! [`Clock::now`] is monotonic and is the only thing a deadline is measured against, because a
//! wall clock can step backwards when an operator or NTP corrects it — which would either expire a
//! deadline early or extend it indefinitely. [`Clock::wall_clock`] exists solely to subtract *now*
//! from the HTTP-date form of `Retry-After`, where a wall reading is what the server's value
//! means. Nothing else in this crate reads it.

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

/// The future one wait produces.
///
/// Boxed for the same reason [`Transport`](crate::transport::Transport)'s is: a client holds one
/// clock for its whole life and must be able to hold it as `Arc<dyn Clock>` — a real one in a
/// binary, a [`TestClock`] in a test — without a type parameter reaching every caller.
pub type SleepFuture<'clock> = Pin<Box<dyn Future<Output = ()> + Send + 'clock>>;

/// A monotonic time source that can also wait.
///
/// Implementations are shared across threads, so they are `Send + Sync`.
///
/// Dropping a [`SleepFuture`] must cancel the wait and do nothing else observable; that is how a
/// retry is cancelled, and it is the one thing the reference cannot do — `Operations.wait` checks
/// its abort signal only *after* waking, so aborting during a sleep still waits out the full
/// delay.
pub trait Clock: fmt::Debug + Send + Sync {
    /// Returns a monotonic reading, used to measure a total deadline.
    fn now(&self) -> Instant;

    /// Waits for `duration`.
    fn sleep(&self, duration: Duration) -> SleepFuture<'_>;

    /// Returns the current wall-clock time.
    ///
    /// Used only to interpret the HTTP-date form of `Retry-After`. The default reads the system
    /// clock; a test clock overrides it so that form is deterministic too.
    fn wall_clock(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock whose time only moves when a wait asks it to.
///
/// Every [`TestClock::sleep`] completes immediately, advances the clock by exactly the requested
/// duration, and records it. A test therefore observes the schedule a policy *would* have waited
/// without waiting for any of it, and a deadline expires at the exact simulated moment.
///
/// ```
/// use core::time::Duration;
/// use signify_http::retry::{Clock, TestClock};
///
/// # fn main() {
/// let clock = TestClock::new();
/// let start = clock.now();
///
/// // Both waits return immediately; only the clock's idea of the time moves.
/// block_on(clock.sleep(Duration::from_millis(50)));
/// block_on(clock.sleep(Duration::from_millis(100)));
///
/// assert_eq!(clock.recorded_sleeps(), [Duration::from_millis(50), Duration::from_millis(100)]);
/// assert_eq!(clock.now().duration_since(start), Duration::from_millis(150));
/// # }
/// # /// Every future this clock returns is ready on its first poll.
/// # fn block_on<F: core::future::Future>(future: F) -> F::Output {
/// #     use core::task::{Context, Poll, Waker};
/// #     let mut future = Box::pin(future);
/// #     let mut context = Context::from_waker(Waker::noop());
/// #     loop {
/// #         if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
/// #             return value;
/// #         }
/// #     }
/// # }
/// ```
#[derive(Debug)]
pub struct TestClock {
    /// The instant the clock was created; simulated time is an offset from it.
    origin: Instant,
    /// The wall-clock reading the clock was created with.
    wall_origin: SystemTime,
    state: Mutex<TestClockState>,
}

#[derive(Debug, Default)]
struct TestClockState {
    elapsed: Duration,
    sleeps: Vec<Duration>,
}

impl TestClock {
    /// Creates a clock at zero simulated elapsed time.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            wall_origin: SystemTime::now(),
            state: Mutex::new(TestClockState::default()),
        }
    }

    /// Creates a clock whose wall-clock reading starts at a chosen instant.
    ///
    /// Only the HTTP-date form of `Retry-After` reads the wall clock, so this exists to make that
    /// form deterministic.
    #[must_use]
    pub fn with_wall_clock(wall_origin: SystemTime) -> Self {
        Self {
            origin: Instant::now(),
            wall_origin,
            state: Mutex::new(TestClockState::default()),
        }
    }

    /// Moves simulated time forward without recording a sleep.
    ///
    /// Use this to expire a deadline directly; [`TestClock::sleep`] advances the clock too, and
    /// what separates them is only that a sleep is recorded.
    pub fn advance(&self, duration: Duration) {
        self.with_state(|state| {
            state.elapsed = state.elapsed.saturating_add(duration);
        });
    }

    /// Returns every duration this clock has been asked to sleep for, in order.
    #[must_use]
    pub fn recorded_sleeps(&self) -> Vec<Duration> {
        self.with_state(|state| state.sleeps.clone())
    }

    /// Returns how much simulated time has passed since the clock was created.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.with_state(|state| state.elapsed)
    }

    /// Runs `action` against the state, recovering from a poisoned lock.
    ///
    /// A test that already failed inside a sleep should report *its* failure, not a second panic
    /// from this clock; the same reasoning as Roadmap 5.1's scripted transport.
    fn with_state<T>(&self, action: impl FnOnce(&mut TestClockState) -> T) -> T {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        action(&mut state)
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TestClock {
    fn now(&self) -> Instant {
        self.origin.checked_add(self.elapsed()).unwrap_or(self.origin)
    }

    fn sleep(&self, duration: Duration) -> SleepFuture<'_> {
        self.with_state(|state| {
            state.sleeps.push(duration);
            state.elapsed = state.elapsed.saturating_add(duration);
        });
        Box::pin(core::future::ready(()))
    }

    fn wall_clock(&self) -> SystemTime {
        self.wall_origin.checked_add(self.elapsed()).unwrap_or(self.wall_origin)
    }
}

/// A clock backed by the tokio runtime.
///
/// Available with the `http-client` feature, which is where `AGENTS.md` §2.5's deliberate runtime
/// adoption happened (ADR `0020`). A caller bringing a different runtime implements [`Clock`] over
/// its own timer instead; the trait is the whole contract, and nothing below `signify-http`
/// links a runtime either way.
#[cfg(feature = "http-client")]
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioClock;

#[cfg(feature = "http-client")]
impl Clock for TokioClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) -> SleepFuture<'_> {
        Box::pin(tokio::time::sleep(duration))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time proof that a value can cross threads.
    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    /// A minimal executor; every future in this module is ready on its first poll.
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

    #[test]
    fn a_test_clock_records_and_advances() {
        let clock = TestClock::new();
        let start = clock.now();
        assert_eq!(clock.elapsed(), Duration::ZERO);
        assert!(clock.recorded_sleeps().is_empty());

        block_on(clock.sleep(Duration::from_millis(50)));
        block_on(clock.sleep(Duration::from_millis(100)));
        assert_eq!(
            clock.recorded_sleeps(),
            [Duration::from_millis(50), Duration::from_millis(100)]
        );
        assert_eq!(clock.elapsed(), Duration::from_millis(150));
        assert_eq!(clock.now().duration_since(start), Duration::from_millis(150));
    }

    #[test]
    fn advancing_moves_time_without_recording_a_sleep() {
        let clock = TestClock::default();
        clock.advance(Duration::from_secs(30));
        assert_eq!(clock.elapsed(), Duration::from_secs(30));
        assert!(clock.recorded_sleeps().is_empty());
        // A sleep does both.
        block_on(clock.sleep(Duration::from_secs(1)));
        assert_eq!(clock.elapsed(), Duration::from_secs(31));
        assert_eq!(clock.recorded_sleeps(), [Duration::from_secs(1)]);
    }

    #[test]
    fn a_zero_sleep_is_still_a_sleep() {
        let clock = TestClock::new();
        block_on(clock.sleep(Duration::ZERO));
        assert_eq!(clock.recorded_sleeps(), [Duration::ZERO]);
        assert_eq!(clock.elapsed(), Duration::ZERO);
    }

    #[test]
    fn the_wall_clock_moves_with_simulated_time() {
        let origin = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = TestClock::with_wall_clock(origin);
        assert_eq!(clock.wall_clock(), origin);
        block_on(clock.sleep(Duration::from_mins(1)));
        assert_eq!(clock.wall_clock(), origin + Duration::from_mins(1));
        // The default clock reads the real system time, which only has to be plausible.
        assert!(TestClock::new().wall_clock() > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn an_enormous_sleep_saturates_rather_than_overflowing() {
        let clock = TestClock::new();
        block_on(clock.sleep(Duration::MAX));
        block_on(clock.sleep(Duration::MAX));
        // Saturated, not wrapped, and `now` fell back to the origin rather than panicking.
        assert_eq!(clock.elapsed(), Duration::MAX);
        assert_eq!(clock.now(), clock.now());
    }

    #[test]
    fn a_dropped_sleep_does_nothing_further() {
        let clock = TestClock::new();
        // The duration is recorded when the future is *created*, which is what makes a schedule
        // observable without polling; dropping it neither repeats nor undoes that.
        let pending = clock.sleep(Duration::from_millis(10));
        drop(pending);
        assert_eq!(clock.recorded_sleeps(), [Duration::from_millis(10)]);
    }

    #[test]
    fn the_clock_is_usable_behind_a_trait_object() {
        let clock: std::sync::Arc<dyn Clock> = std::sync::Arc::new(TestClock::new());
        let before = clock.now();
        block_on(clock.sleep(Duration::from_millis(5)));
        assert_eq!(clock.now().duration_since(before), Duration::from_millis(5));
        assert_send_sync(&clock);
    }
}
