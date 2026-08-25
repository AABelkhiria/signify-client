//! Waiting for a long-running KERIA operation to finish.
//!
//! A KERIA agent answers most write requests with an operation rather than a result, so almost
//! every workflow ends in a poll. [`Poller::wait`] is that poll: it walks the operation's
//! dependency, then asks the agent for the operation itself until it finishes, sleeping on
//! Roadmap 5.4's schedule between attempts.
//!
//! This ports `Operations.wait` from the pinned `src/keri/app/coring.ts`, together with the
//! private `hasDepends` it consults and the `throwIfFailed` it applies at every exit.
//!
//! # It is bounded, where the reference is not
//!
//! Upstream `wait` is a `while (true)` with no deadline, no attempt cap, and an abort signal read
//! only *after* a sleep of up to ten seconds — so an operation the agent never finishes is polled
//! for as long as the process lives, and a caller who gives up still waits out the current delay.
//! Here the schedule is a [`PollPolicy`], which is Roadmap 5.4's [`RetryPolicy`] — the same
//! formula, so every recorded delay still reproduces — plus the two bounds the reference lacks.
//! Its default deadline is **thirty seconds**, which is not invented: it is what the reference's
//! own `waitOperation` integration helper supplies through `AbortSignal.timeout(30000)`.
//!
//! Cancellation is dropping the future, which is ADR `0019`'s decision for this whole crate, so
//! there is no signal to read late: dropping cancels the outstanding request or sleep at once.
//!
//! # The dependency chain is one link long
//!
//! `wait` calls itself on `op.metadata.depends`, which reads as arbitrary depth. It is not: the
//! schema declares `depends` on exactly three shapes — a registry, a credential, and a delegator
//! operation — and all three declare it as a `KelOperation`, whose own metadata declares none. The
//! reference's type declarations bound its recursion at one link, so this is a loop over one
//! optional dependency rather than a recursion over remote data. See `fixtures/client-operation-wait/`.
//!
//! # Example
//!
//! ```
//! use core::time::Duration;
//! use signify_client::operation::{PollPolicy, PollingLimit};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // The reference's own schedule, with the bounds it lacks.
//! let policy = PollPolicy::builder()
//!     .max_attempts(20)
//!     .deadline(Duration::from_secs(60))
//!     .build()?;
//!
//! assert_eq!(policy.initial_delay(), Duration::from_millis(50));
//! assert_eq!(policy.max_delay(), Duration::from_secs(10));
//! assert_eq!(policy.deadline(), Some(Duration::from_secs(60)));
//! assert_eq!(PollingLimit::Deadline.to_string(), "the total deadline elapsed");
//! # Ok(())
//! # }
//! ```

use core::fmt;
use core::time::Duration;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde_json::Value;
use signify_http::retry::{
    Backoff, Jitter, JitterSource, OsJitter, RetryDecision, RetryPolicy, RetryPolicyError, RetryScope, StopReason,
};
use signify_http::transport::Method;
use signify_types::api::{
    ChallengeMetadata, CredentialMetadata, DelegatorMetadata, DoneMetadata, EndRoleMetadata, ExchangeMetadata,
    KelMetadata, LocationSchemeMetadata, LogPositionMetadata, OobiMetadata, Operation, OperationOutcome, QueryMetadata,
    RegistryMetadata,
};

use crate::client::ConnectedClient;
use crate::endpoint::operations::completed;
use crate::error::ClientError;

/// The deadline the reference's own integration helper supplies.
///
/// `waitOperation` passes `AbortSignal.timeout(30000)` to every wait in the pinned integration
/// suite, which is upstream's only statement of how long polling should be allowed to take.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

/// How many attempts a default policy makes before giving up.
///
/// The reference makes unboundedly many. Twenty is what the default schedule fits inside
/// [`DEFAULT_DEADLINE`] with room to spare: the un-jittered delays sum past thirty seconds by the
/// ninth, so in practice the deadline is the binding limit and this is a backstop.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 20;

/// One operation another is waiting on.
///
/// The reference embeds the whole dependency in its parent's metadata and consults exactly two
/// things about it: whether it has finished, and what it is called. Those are the two fields here.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Dependency {
    /// The dependency's operation name, which is also its path segment.
    pub name: String,
    /// Whether the snapshot reports it as finished — successfully **or not**.
    pub finished: bool,
}

/// Operation metadata that may name another operation it waits on.
///
/// This is the typed counterpart of the reference's `hasDepends`, which is a run-time
/// `'depends' in op.metadata`. It is implemented for every metadata type in
/// [`signify_types::api`], and exactly three of them — a registry, a credential, and a delegator
/// operation — return anything but [`None`], which is precisely the set the schema declares.
pub trait PollableMetadata {
    /// Returns the operation this one waits on, when its family has one.
    ///
    /// The default is [`None`], which is the right answer for the nine families whose metadata
    /// declares no dependency.
    fn dependency(&self) -> Option<Dependency> {
        None
    }
}

/// Builds a [`Dependency`] from a nested key-event operation.
fn dependency_of<M, R>(operation: &Operation<M, R>) -> Dependency {
    Dependency {
        name: operation.name.clone(),
        finished: operation.outcome.is_done(),
    }
}

impl PollableMetadata for RegistryMetadata {
    /// A registry inception always waits on the key event that anchors it.
    fn dependency(&self) -> Option<Dependency> {
        Some(dependency_of(self.depends.as_ref()))
    }
}

impl PollableMetadata for CredentialMetadata {
    /// A credential issuance waits on the key event anchoring it, when the agent reports one.
    fn dependency(&self) -> Option<Dependency> {
        self.depends.as_deref().map(dependency_of)
    }
}

impl PollableMetadata for DelegatorMetadata {
    /// A delegation approval waits on the delegator's own key event, when the agent reports one.
    fn dependency(&self) -> Option<Dependency> {
        self.depends.as_deref().map(dependency_of)
    }
}

impl PollableMetadata for LogPositionMetadata {}
impl PollableMetadata for OobiMetadata {}
impl PollableMetadata for QueryMetadata {}
impl PollableMetadata for EndRoleMetadata {}
impl PollableMetadata for LocationSchemeMetadata {}
impl PollableMetadata for ChallengeMetadata {}
impl PollableMetadata for ExchangeMetadata {}
impl PollableMetadata for DoneMetadata {}
impl PollableMetadata for KelMetadata {}

impl PollableMetadata for Value {
    /// Reads a dependency out of metadata whose family is not yet known.
    ///
    /// This is the closest honest equivalent of the reference's `'depends' in op.metadata`, and it
    /// is what lets an [`UntypedOperation`](signify_types::api::UntypedOperation) be waited on
    /// exactly as upstream's union overload can be. A `depends` that is not an object naming a
    /// string `name` is treated as absent, which is what the truthiness test beside the reference's
    /// own guard does.
    fn dependency(&self) -> Option<Dependency> {
        let depends = self.get("depends")?;
        Some(Dependency {
            name: depends.get("name")?.as_str()?.to_owned(),
            finished: depends.get("done").and_then(Value::as_bool).unwrap_or(false),
        })
    }
}

/// An operation that has finished successfully.
///
/// The reference's `CompletedOperation`, with the guarantee in the type: this is constructed only
/// by [`Poller::wait`], and only from an outcome that carried a response. A caller holding one
/// need not re-check anything.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Completed<M, R> {
    name: String,
    metadata: Option<M>,
    response: R,
}

impl<M, R> Completed<M, R> {
    /// Returns the operation's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the family metadata the agent reported, when it reported any.
    #[must_use]
    pub const fn metadata(&self) -> Option<&M> {
        self.metadata.as_ref()
    }

    /// Returns what the operation produced.
    #[must_use]
    pub const fn response(&self) -> &R {
        &self.response
    }

    /// Consumes this value and returns what the operation produced.
    #[must_use]
    pub fn into_response(self) -> R {
        self.response
    }

    /// Consumes this value and returns its name, metadata, and response.
    #[must_use]
    pub fn into_parts(self) -> (String, Option<M>, R) {
        (self.name, self.metadata, self.response)
    }
}

/// Which bound stopped a poll before the operation finished.
///
/// The reference has neither, so it has no such state: its loop simply does not end.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PollingLimit {
    /// Every attempt the policy allows had been made.
    Attempts,
    /// The next wait would have carried the poll past its total deadline.
    Deadline,
}

impl fmt::Display for PollingLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Attempts => "every allowed attempt was made",
            Self::Deadline => "the total deadline elapsed",
        })
    }
}

/// How long to keep polling, and how long to wait between attempts.
///
/// The schedule is Roadmap 5.4's [`RetryPolicy`] — the reference's own
/// `max(minSleep, min(maxSleep, 2 ** retries * increaseFactor))`, floor applied outside the
/// ceiling and all — so a policy built here reproduces any delay sequence the reference produces.
/// What this type adds is that the two knobs a *transport* retry needs and a poll does not,
/// [`RetryScope`] and `Retry-After` handling, cannot be set: a scope that excluded `GET` would stop
/// a poll for a reason that has nothing to do with polling, and no agent sends `Retry-After` on an
/// operation read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollPolicy {
    schedule: RetryPolicy,
}

impl PollPolicy {
    /// Starts building a policy.
    #[must_use]
    pub fn builder() -> PollPolicyBuilder {
        PollPolicyBuilder::default()
    }

    /// Returns the underlying schedule, so the shared formula is visible and testable.
    #[must_use]
    pub const fn schedule(&self) -> &RetryPolicy {
        &self.schedule
    }

    /// Returns the delay before the first retry; the reference's `increaseFactor`.
    #[must_use]
    pub const fn initial_delay(&self) -> Duration {
        self.schedule.base_delay()
    }

    /// Returns the floor, applied after the ceiling; the reference's `minSleep`.
    #[must_use]
    pub const fn min_delay(&self) -> Duration {
        self.schedule.min_delay()
    }

    /// Returns the ceiling the doubling flattens at; the reference's `maxSleep`.
    #[must_use]
    pub const fn max_delay(&self) -> Duration {
        self.schedule.max_delay()
    }

    /// Returns how many times the agent may be asked, the first attempt included.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.schedule.max_attempts()
    }

    /// Returns the total budget, when there is one.
    #[must_use]
    pub const fn deadline(&self) -> Option<Duration> {
        self.schedule.deadline()
    }

    /// Returns how a computed delay is randomised.
    #[must_use]
    pub const fn jitter(&self) -> Jitter {
        self.schedule.jitter()
    }

    /// Returns the un-jittered delay before the retry following `attempt`, zero-based.
    ///
    /// This is the reference's formula exactly, and is what makes a recorded schedule reproducible.
    #[must_use]
    pub fn delay_for(&self, attempt: u32) -> Duration {
        self.schedule.delay_for(attempt)
    }
}

impl Default for PollPolicy {
    /// The reference's delay shape with the bounds it lacks.
    ///
    /// 50 ms doubling to a 10 s ceiling above a 10 ms floor — upstream's own defaults — capped at
    /// [`DEFAULT_MAX_ATTEMPTS`] attempts and [`DEFAULT_DEADLINE`], and jittered, which is Roadmap
    /// 5.4's decision for the same schedule. [`Jitter::None`] reproduces the reference exactly.
    fn default() -> Self {
        Self::builder().build().unwrap_or(Self {
            schedule: RetryPolicy::default(),
        })
    }
}

/// Builds a [`PollPolicy`].
///
/// The three delay knobs carry the reference's own defaults, so a policy built with no calls at
/// all produces upstream's schedule.
#[derive(Clone, Copy, Debug)]
pub struct PollPolicyBuilder {
    initial_delay: Duration,
    min_delay: Duration,
    max_delay: Duration,
    max_attempts: u32,
    deadline: Option<Duration>,
    jitter: Jitter,
}

impl Default for PollPolicyBuilder {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(50),
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_secs(10),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            deadline: Some(DEFAULT_DEADLINE),
            jitter: Jitter::Equal,
        }
    }
}

impl PollPolicyBuilder {
    /// Sets the delay before the first retry; the reference's `increaseFactor`.
    #[must_use]
    pub const fn initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Sets the floor, which is applied after the ceiling; the reference's `minSleep`.
    #[must_use]
    pub const fn min_delay(mut self, delay: Duration) -> Self {
        self.min_delay = delay;
        self
    }

    /// Sets the ceiling the doubling flattens at; the reference's `maxSleep`.
    #[must_use]
    pub const fn max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Sets how many times the agent may be asked, the first attempt included.
    #[must_use]
    pub const fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Sets the total budget a poll must finish inside.
    #[must_use]
    pub const fn deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Removes the total budget, leaving the attempt count as the only bound.
    ///
    /// This is as close to the reference's unbounded loop as this type allows: `wait` still stops
    /// after [`max_attempts`](Self::max_attempts) rather than never.
    #[must_use]
    pub const fn without_deadline(mut self) -> Self {
        self.deadline = None;
        self
    }

    /// Sets how a computed delay is randomised.
    ///
    /// [`Jitter::None`] reproduces the reference's schedule exactly.
    #[must_use]
    pub const fn jitter(mut self, jitter: Jitter) -> Self {
        self.jitter = jitter;
        self
    }

    /// Validates the policy.
    ///
    /// # Errors
    ///
    /// Returns whatever [`RetryPolicy`]'s own builder rejects: a zero attempt count, a zero or
    /// excessive delay, or a deadline too short for a single attempt.
    pub fn build(self) -> Result<PollPolicy, RetryPolicyError> {
        let mut schedule = RetryPolicy::builder()
            .base_delay(self.initial_delay)
            .min_delay(self.min_delay)
            .max_delay(self.max_delay)
            .max_attempts(self.max_attempts)
            .jitter(self.jitter)
            // A poll is a `GET`, and this is never exposed: a scope excluding it would stop a poll
            // for a transport reason.
            .scope(RetryScope::IdempotentOnly);
        schedule = match self.deadline {
            Some(deadline) => schedule.deadline(deadline),
            None => schedule.without_deadline(),
        };
        Ok(PollPolicy {
            schedule: schedule.build()?,
        })
    }
}

/// Polls long-running operations until they finish.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through — the shape Roadmap 6.5 settled for every endpoint family. Unlike a family, this
/// is a *workflow*: it knows no paths of its own and reaches the agent only through
/// [`Operations`](crate::endpoint::operations::Operations).
#[derive(Clone)]
pub struct Poller<'client> {
    client: &'client ConnectedClient,
    policy: PollPolicy,
    jitter: Arc<dyn JitterSource>,
}

impl fmt::Debug for Poller<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Poller")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<'client> Poller<'client> {
    /// Binds a poller to a connected client, with the default policy.
    #[must_use]
    pub fn new(client: &'client ConnectedClient) -> Self {
        Self {
            client,
            policy: PollPolicy::default(),
            jitter: Arc::new(OsJitter),
        }
    }

    /// Sets the policy this poller follows.
    #[must_use]
    pub const fn with_policy(mut self, policy: PollPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Sets where jitter draws its randomness from.
    ///
    /// Production uses the operating system. A test injects a fixed source so a schedule can be
    /// asserted exactly, which is Roadmap 5.4's arrangement.
    #[must_use]
    pub fn with_jitter_source(mut self, jitter: Arc<dyn JitterSource>) -> Self {
        self.jitter = jitter;
        self
    }

    /// Returns the policy in force.
    #[must_use]
    pub const fn policy(&self) -> &PollPolicy {
        &self.policy
    }

    /// Waits for one operation to finish, walking its dependency first.
    ///
    /// The operation is taken by value: a snapshot that already reports success is returned
    /// without a single request, which is what the reference does and what its own unit test
    /// asserts by object identity.
    ///
    /// # The dependency is skipped when it has *finished*, not when it has succeeded
    ///
    /// The reference's guard is `!op.metadata.depends.done`, so a dependency the snapshot already
    /// reports as done-**and-failed** is passed over in silence and the parent is polled as though
    /// nothing were wrong. That is reproduced here, because the parent's own outcome is the thing
    /// being waited on and the agent still decides it — but it is named rather than left implicit.
    ///
    /// # Cancellation
    ///
    /// Dropping the returned future cancels the outstanding request or sleep immediately. There is
    /// no abort signal, and so no equivalent of the reference's reading one only after waking.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::OperationFailed`] when the operation — or its dependency — finished
    /// unsuccessfully, [`ClientError::PollingStopped`] when a bound was reached before it finished,
    /// and whatever [`Operations::get`](crate::endpoint::operations::Operations::get) returns for
    /// each attempt.
    pub async fn wait<M, R>(&self, operation: Operation<M, R>) -> Result<Completed<M, R>, ClientError>
    where
        M: PollableMetadata + DeserializeOwned,
        R: DeserializeOwned,
    {
        if let Some(dependency) = operation
            .metadata
            .as_ref()
            .and_then(PollableMetadata::dependency)
            .filter(|dependency| !dependency.finished)
        {
            // The dependency is always a key-event operation — the schema declares all three
            // `depends` fields as `KelOperation` — and a key-event operation declares no dependency
            // of its own, so this cannot recurse further.
            let _ = self.poll_untyped(&dependency.name).await?;
        }
        // A snapshot that has already finished is settled without asking, failure included.
        if operation.outcome.is_done() {
            return self.finish(operation);
        }
        self.poll(operation.name).await
    }

    /// Reads one operation by name and waits for it to finish.
    ///
    /// This is the `typeof op === 'string'` branch of the reference's own `waitOperation`
    /// integration helper: fetch it, then wait. The family must be named, because an operation's
    /// answer says which one it belongs to only in its metadata.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::wait`] returns, plus the decode failure of narrowing the first
    /// answer to `M` and `R`.
    pub async fn wait_named<M, R>(&self, name: &str) -> Result<Completed<M, R>, ClientError>
    where
        M: PollableMetadata + DeserializeOwned,
        R: DeserializeOwned,
    {
        let operation = self.client.operations().get_typed::<M, R>(name).await?;
        self.wait(operation).await
    }

    /// Polls one named operation of a known family until it finishes or a bound is reached.
    async fn poll<M, R>(&self, name: String) -> Result<Completed<M, R>, ClientError>
    where
        M: DeserializeOwned,
        R: DeserializeOwned,
    {
        let clock = self.client.clock();
        let started = clock.now();
        let mut backoff = Backoff::new(*self.policy.schedule(), started);
        loop {
            let attempt = self.client.operations().get_typed::<M, R>(&name).await?;
            if attempt.outcome.is_done() {
                return self.finish(attempt);
            }
            match backoff.next(
                clock.now(),
                Method::Get,
                true,
                self.jitter.next_u32(),
                None,
                clock.wall_clock(),
            ) {
                RetryDecision::Retry { delay, .. } => clock.sleep(delay).await,
                RetryDecision::Stop(reason) => {
                    return Err(ClientError::PollingStopped {
                        name,
                        limit: limit_of(reason),
                        attempts: backoff.attempts_made(),
                        elapsed: clock.now().saturating_duration_since(started),
                    });
                }
            }
        }
    }

    /// Polls a dependency, whose family is a key-event operation this module never inspects.
    ///
    /// The result is discarded exactly as the reference discards it: what the parent's next poll
    /// reports is what decides the parent's outcome. A dependency that *fails* is not discarded —
    /// it surfaces as [`ClientError::OperationFailed`] under the dependency's own name, which is
    /// what upstream's recursive `throwIfFailed` produces.
    async fn poll_untyped(&self, name: &str) -> Result<Completed<Value, Value>, ClientError> {
        self.poll::<Value, Value>(name.to_owned()).await
    }

    /// Turns a finished operation into a [`Completed`], or into the failure it carries.
    fn finish<M, R>(&self, operation: Operation<M, R>) -> Result<Completed<M, R>, ClientError> {
        let _ = self;
        let name = operation.name.clone();
        let metadata = operation.metadata;
        // Roadmap 6.5's `completed` is the reference's `throwIfFailed`, with the pending state told
        // apart; it cannot report pending here, because the caller has just checked.
        let response = completed(Operation {
            name: operation.name,
            metadata: None::<M>,
            outcome: match operation.outcome {
                OperationOutcome::Pending => OperationOutcome::Pending,
                OperationOutcome::Completed(response) => OperationOutcome::Completed(response),
                OperationOutcome::Failed(status) => OperationOutcome::Failed(status),
            },
        })?;
        Ok(Completed {
            name,
            metadata,
            response,
        })
    }
}

/// Maps a schedule's stop reason onto the two a poll can actually reach.
///
/// `NotRetryable` and `MethodNotIdempotent` are unreachable: a poll always passes `true` and always
/// asks with `GET`, and [`PollPolicy`] cannot express a scope that excludes it. Neither is
/// representable in [`PollingLimit`], so they collapse onto the attempt bound rather than inventing
/// a state.
const fn limit_of(reason: StopReason) -> PollingLimit {
    match reason {
        StopReason::DeadlineElapsed => PollingLimit::Deadline,
        StopReason::NotRetryable | StopReason::MethodNotIdempotent | StopReason::AttemptsExhausted => {
            PollingLimit::Attempts
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signify_types::api::{Anchor, KelResponse, KeyState, OperationStatus};
    use std::error::Error;

    fn kel_operation(name: &str, done: bool) -> Operation<KelMetadata, KelResponse> {
        Operation {
            name: name.to_owned(),
            metadata: None,
            outcome: if done {
                OperationOutcome::Failed(OperationStatus {
                    code: 500,
                    message: "no".to_owned(),
                    details: None,
                })
            } else {
                OperationOutcome::Pending
            },
        }
    }

    fn registry_metadata(depends: Operation<KelMetadata, KelResponse>) -> RegistryMetadata {
        RegistryMetadata {
            pre: "EPRE".to_owned(),
            depends: Box::new(depends),
            anchor: Anchor {
                pre: "EPRE".to_owned(),
                sn: 0,
                digest: "EANCHOR".to_owned(),
            },
        }
    }

    #[test]
    fn the_default_policy_is_the_references_schedule_with_the_bounds_it_lacks() {
        let policy = PollPolicy::default();
        // Upstream's own three defaults: `increaseFactor` 50, `minSleep` 10, `maxSleep` 10000.
        assert_eq!(policy.initial_delay(), Duration::from_millis(50));
        assert_eq!(policy.min_delay(), Duration::from_millis(10));
        assert_eq!(policy.max_delay(), Duration::from_secs(10));
        // The two bounds it has none of.
        assert_eq!(policy.max_attempts(), DEFAULT_MAX_ATTEMPTS);
        assert_eq!(policy.deadline(), Some(DEFAULT_DEADLINE));
        // And the deadline is the reference's own integration-helper timeout.
        assert_eq!(DEFAULT_DEADLINE, Duration::from_secs(30));
    }

    #[test]
    fn the_schedule_is_the_one_roadmap_5_4_recorded() -> Result<(), Box<dyn Error>> {
        let policy = PollPolicy::builder().jitter(Jitter::None).build()?;
        let delays: Vec<u128> = (0..12).map(|attempt| policy.delay_for(attempt).as_millis()).collect();
        assert_eq!(
            delays,
            [50, 100, 200, 400, 800, 1600, 3200, 6400, 10_000, 10_000, 10_000, 10_000]
        );
        Ok(())
    }

    #[test]
    fn a_floor_above_the_ceiling_wins_as_it_does_upstream() -> Result<(), Box<dyn Error>> {
        // `max(minSleep, min(maxSleep, …))`, in that order.
        let policy = PollPolicy::builder()
            .min_delay(Duration::from_secs(1))
            .max_delay(Duration::from_millis(500))
            .jitter(Jitter::None)
            .build()?;
        assert_eq!(policy.delay_for(0), Duration::from_secs(1));
        assert_eq!(policy.delay_for(8), Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn a_policy_cannot_express_a_scope_that_would_stop_a_poll() -> Result<(), Box<dyn Error>> {
        // There is no builder method for it, and the schedule always admits the `GET` a poll makes.
        let policy = PollPolicy::builder().build()?;
        assert!(policy.schedule().scope().admits(Method::Get));
        Ok(())
    }

    #[test]
    fn exactly_three_metadata_families_name_a_dependency() {
        // The schema declares `depends` on exactly these three, all typed `KelOperation`.
        assert!(
            registry_metadata(kel_operation("witness.EABC", false))
                .dependency()
                .is_some()
        );
        let credential: Result<CredentialMetadata, _> = serde_json::from_str(
            r#"{"ced":{"v":"ACDC10JSON000000_","d":"ED","i":"EI","s":"ES","a":{}},"depends":{"name":"witness.EABC","done":false}}"#,
        );
        assert!(credential.is_ok_and(|metadata| metadata.dependency()
            == Some(Dependency {
                name: "witness.EABC".to_owned(),
                finished: false,
            })));
        assert!(
            DelegatorMetadata {
                pre: "EPRE".to_owned(),
                teepre: "ETEE".to_owned(),
                anchor: None,
                depends: Some(Box::new(kel_operation("witness.EABC", false))),
            }
            .dependency()
            .is_some()
        );

        // Every other family declares none, so the chain cannot be longer than one link.
        assert!(
            LogPositionMetadata {
                pre: "E".to_owned(),
                sn: 0
            }
            .dependency()
            .is_none()
        );
        assert!(
            OobiMetadata {
                oobi: "http://x".to_owned()
            }
            .dependency()
            .is_none()
        );
        assert!(
            QueryMetadata {
                pre: "E".to_owned(),
                sn: 0,
                anchor: None
            }
            .dependency()
            .is_none()
        );
        assert!(
            EndRoleMetadata {
                cid: "E".to_owned(),
                role: "agent".to_owned(),
                eid: "E".to_owned()
            }
            .dependency()
            .is_none()
        );
    }

    #[test]
    fn an_optional_dependency_that_is_absent_is_no_dependency() {
        let metadata = DelegatorMetadata {
            pre: "EPRE".to_owned(),
            teepre: "ETEE".to_owned(),
            anchor: None,
            depends: None,
        };
        assert_eq!(metadata.dependency(), None);
    }

    #[test]
    fn a_dependency_carries_only_its_name_and_whether_it_finished() {
        let unfinished = registry_metadata(kel_operation("witness.EABC", false)).dependency();
        assert_eq!(
            unfinished,
            Some(Dependency {
                name: "witness.EABC".to_owned(),
                finished: false,
            })
        );
        // A dependency that finished *unsuccessfully* still reports `finished`, which is exactly
        // what the reference's `!depends.done` guard reads — and why it skips a failed one.
        let failed = registry_metadata(kel_operation("witness.EABC", true)).dependency();
        assert_eq!(failed.map(|dependency| dependency.finished), Some(true));
    }

    #[test]
    fn untyped_metadata_reads_its_dependency_the_way_the_reference_does() -> Result<(), Box<dyn Error>> {
        let with: Value = serde_json::from_str(r#"{"pre":"E","depends":{"name":"witness.EABC","done":false}}"#)?;
        assert_eq!(
            with.dependency(),
            Some(Dependency {
                name: "witness.EABC".to_owned(),
                finished: false,
            })
        );
        // `hasDepends` is `'depends' in op.metadata`, so an explicit null passes that guard and is
        // then dropped by the truthiness test beside it. Here both steps are one `Option`.
        let null: Value = serde_json::from_str(r#"{"pre":"E","depends":null}"#)?;
        assert_eq!(null.dependency(), None);
        let absent: Value = serde_json::from_str(r#"{"pre":"E"}"#)?;
        assert_eq!(absent.dependency(), None);
        // A dependency that is not an object naming a string is absent rather than a failure.
        let malformed: Value = serde_json::from_str(r#"{"depends":{"done":true}}"#)?;
        assert_eq!(malformed.dependency(), None);
        Ok(())
    }

    #[test]
    fn a_polling_limit_says_which_bound_was_reached() {
        assert_eq!(limit_of(StopReason::DeadlineElapsed), PollingLimit::Deadline);
        assert_eq!(limit_of(StopReason::AttemptsExhausted), PollingLimit::Attempts);
        // The two a poll cannot reach collapse rather than inventing a state.
        assert_eq!(limit_of(StopReason::NotRetryable), PollingLimit::Attempts);
        assert_eq!(limit_of(StopReason::MethodNotIdempotent), PollingLimit::Attempts);
        assert_eq!(PollingLimit::Attempts.to_string(), "every allowed attempt was made");
        assert_eq!(PollingLimit::Deadline.to_string(), "the total deadline elapsed");
    }

    #[test]
    fn a_completed_operation_keeps_what_the_agent_reported() {
        let completed = Completed {
            name: "oobi.EABC".to_owned(),
            metadata: Some(OobiMetadata {
                oobi: "http://oobiurl.com".to_owned(),
            }),
            response: 42_u8,
        };
        assert_eq!(completed.name(), "oobi.EABC");
        assert_eq!(
            completed.metadata().map(|metadata| metadata.oobi.as_str()),
            Some("http://oobiurl.com")
        );
        assert_eq!(*completed.response(), 42);
        let (name, metadata, response) = completed.into_parts();
        assert_eq!(name, "oobi.EABC");
        assert!(metadata.is_some());
        assert_eq!(response, 42);
    }

    #[test]
    fn a_zero_attempt_policy_is_refused() {
        assert!(PollPolicy::builder().max_attempts(0).build().is_err());
    }

    #[test]
    fn a_policy_without_a_deadline_still_stops() -> Result<(), Box<dyn Error>> {
        let policy = PollPolicy::builder().without_deadline().max_attempts(3).build()?;
        assert_eq!(policy.deadline(), None);
        assert_eq!(policy.max_attempts(), 3);
        // Which is the whole difference from upstream: `while (true)` has neither bound.
        Ok(())
    }

    /// A `KeyState` is what an OOBI resolution completes with, so this asserts the bound compiles.
    #[test]
    fn the_metadata_bound_admits_every_family_the_schema_declares() {
        fn accepts<M: PollableMetadata + DeserializeOwned, R: DeserializeOwned>() {}
        accepts::<OobiMetadata, KeyState>();
        accepts::<RegistryMetadata, Value>();
        accepts::<CredentialMetadata, Value>();
        accepts::<DelegatorMetadata, String>();
        accepts::<LogPositionMetadata, Value>();
        accepts::<KelMetadata, KelResponse>();
        accepts::<DoneMetadata, KelResponse>();
        accepts::<Value, Value>();
    }
}
