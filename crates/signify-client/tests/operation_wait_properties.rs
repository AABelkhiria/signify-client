//! Invariants of the operation polling loop.
//!
//! A poll always terminates within its policy's budget, and the schedule reproduces the reference's formula.

mod support;

use core::time::Duration;
use std::error::Error;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use crate::support::{ADMIN, AgentTransport, BOOT, FIXED_MILLIS, PASSCODE, agent_state, block_on};
use keria_types::api::{DelegatorMetadata, Operation, RegistryMetadata};
use proptest::prelude::*;
use serde_json::{Value, json};
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::error::ClientError;
use signify_client::operation::{Dependency, PollPolicy, PollableMetadata, PollingLimit};
use signify_http::retry::{Backoff, Clock, Jitter, RetryDecision, TestClock};
use signify_http::transport::{Method, Transport};
use signify_keys::manager::DerivationCost;

const NAME: &str = "witness.EABC.0";

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

// --- Strategies ---
fn policies() -> impl Strategy<Value = PollPolicy> {
    (
        1_u64..=20_000,
        0_u64..=20_000,
        1_u64..=20_000,
        1_u32..=12,
        proptest::option::of(1_u64..=120_000),
        prop_oneof![Just(Jitter::None), Just(Jitter::Equal), Just(Jitter::Full)],
    )
        .prop_filter_map("not a policy", |(initial, min, max, attempts, deadline, jitter)| {
            let mut builder = PollPolicy::builder()
                .initial_delay(Duration::from_millis(initial))
                .min_delay(Duration::from_millis(min))
                .max_delay(Duration::from_millis(max))
                .max_attempts(attempts)
                .jitter(jitter);
            builder = match deadline {
                Some(millis) => builder.deadline(Duration::from_millis(millis)),
                None => builder.without_deadline(),
            };
            builder.build().ok()
        })
}

fn names() -> impl Strategy<Value = String> {
    "[a-z]{3,10}\\.[A-Za-z0-9_-]{4,20}(\\.[0-9]{1,3})?"
}

type Harness = (ConnectedClient, Arc<AgentTransport>, Arc<TestClock>);

fn connected(body: &str) -> Result<Harness, Box<dyn Error>> {
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
    let transport = AgentTransport::new(&[state.as_bytes(), b"{}", body.as_bytes()]);
    transport.repeating_last();
    let client = SignifyClient::new(
        configuration()?,
        Arc::clone(&transport) as Arc<dyn Transport>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )?;
    Ok((block_on(client.connect())?, transport, clock))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn the_delay_is_always_the_references_formula(policy in policies(), attempt in 0_u32..24) {
        let doubled = policy
            .initial_delay()
            .checked_mul(1_u32.checked_shl(attempt).unwrap_or(u32::MAX))
            .unwrap_or(Duration::MAX);
        let expected = policy.min_delay().max(policy.max_delay().min(doubled));
        prop_assert_eq!(policy.delay_for(attempt), expected);
    }

    #[test]
    fn every_schedule_stops_within_its_attempt_bound(policy in policies()) {
        let start = Instant::now();
        let mut backoff = Backoff::new(*policy.schedule(), start);
        let mut elapsed = Duration::ZERO;
        let mut steps = 0_u32;
        loop {
            let decision = backoff.next(
                start.checked_add(elapsed).unwrap_or(start),
                Method::Get,
                true,
                0,
                None,
                SystemTime::UNIX_EPOCH,
            );
            match decision {
                RetryDecision::Retry { delay, .. } => {
                    elapsed = elapsed.saturating_add(delay);
                    steps = steps.saturating_add(1);
                    prop_assert!(
                        steps < policy.max_attempts(),
                        "the schedule retried past its own attempt bound"
                    );
                }
                RetryDecision::Stop(_) => break,
            }
        }
        prop_assert!(steps < policy.max_attempts());
    }

    #[test]
    fn a_policy_always_admits_the_request_a_poll_makes(policy in policies()) {
        prop_assert!(policy.schedule().scope().admits(Method::Get));
        prop_assert!(policy.max_attempts() >= 1);
    }

    #[test]
    fn typed_and_untyped_metadata_read_the_same_dependency(
        name in names(),
        finished in any::<bool>(),
    ) {
        let depends = if finished {
            json!({"name": name, "done": true, "response": {"v":"KERI10JSON000000_","t":"ixn","d":"ED","i":"EI","s":"1","p":"EP","a":[]}})
        } else {
            json!({"name": name, "done": false})
        };
        let document = json!({
            "pre": "EPRE",
            "depends": depends,
            "anchor": {"i": "EPRE", "s": "0", "d": "EANCHOR"},
        });

        let typed: RegistryMetadata = serde_json::from_value(document.clone()).map_err(fail)?;
        let expected = Dependency { name: name.clone(), finished };
        prop_assert_eq!(typed.dependency(), Some(expected.clone()));
        prop_assert_eq!(document.dependency(), Some(expected));
    }

    #[test]
    fn an_absent_optional_dependency_is_none(prefix in "[A-Z][A-Za-z0-9_-]{3,20}") {
        let document = json!({"pre": prefix, "teepre": "ETEE"});
        let typed: DelegatorMetadata = serde_json::from_value(document.clone()).map_err(fail)?;
        prop_assert_eq!(typed.dependency(), None);
        prop_assert_eq!(document.dependency(), None);
    }

    #[test]
    fn a_finished_dependency_is_finished_however_it_ended(name in names()) {
        for depends in [
            json!({"name": name, "done": true, "error": {"code": 500, "message": "no"}}),
            json!({"name": name, "done": true, "response": {"v":"KERI10JSON000000_","t":"ixn","d":"ED","i":"EI","s":"1","p":"EP","a":[]}}),
        ] {
            let document = json!({"pre": "EPRE", "depends": depends, "anchor": {"i":"EPRE","s":"0","d":"EA"}});
            let typed: RegistryMetadata = serde_json::from_value(document.clone()).map_err(fail)?;
            prop_assert_eq!(typed.dependency().map(|dependency| dependency.finished), Some(true));
            prop_assert_eq!(document.dependency().map(|dependency| dependency.finished), Some(true));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    #[test]
    fn an_unfinishable_operation_stops_after_exactly_its_attempt_bound(attempts in 1_u32..8) {
        let policy = PollPolicy::builder()
            .jitter(Jitter::None)
            .without_deadline()
            .max_attempts(attempts)
            .build()
            .map_err(fail)?;
        let body = format!(r#"{{"name":"{NAME}","done":false}}"#);
        let (client, transport, clock) = connected(&body).map_err(fail)?;
        let operation: Operation<Value, Value> = serde_json::from_str(&body).map_err(fail)?;

        let outcome = block_on(client.poller().with_policy(policy).wait(operation));
        match outcome {
            Err(ClientError::PollingStopped { name, limit, attempts: made, .. }) => {
                prop_assert_eq!(name, NAME);
                prop_assert_eq!(limit, PollingLimit::Attempts);
                prop_assert_eq!(made, attempts);
            }
            other => prop_assert!(false, "an unfinishable operation did not stop: {:?}", other),
        }
        prop_assert_eq!(transport.endpoint_calls().len(), attempts as usize);
        prop_assert_eq!(clock.recorded_sleeps().len(), attempts.saturating_sub(1) as usize);
    }
}

#[test]
fn a_floor_above_the_ceiling_is_the_delay() -> Result<(), Box<dyn Error>> {
    let policy = PollPolicy::builder()
        .min_delay(Duration::from_secs(5))
        .max_delay(Duration::from_millis(100))
        .initial_delay(Duration::from_millis(50))
        .jitter(Jitter::None)
        .without_deadline()
        .max_attempts(4)
        .build()?;
    for attempt in 0..8 {
        assert_eq!(policy.delay_for(attempt), Duration::from_secs(5));
    }
    Ok(())
}

#[test]
fn a_deadline_below_the_first_delay_stops_immediately() -> Result<(), Box<dyn Error>> {
    let policy = PollPolicy::builder()
        .initial_delay(Duration::from_secs(5))
        .min_delay(Duration::from_secs(5))
        .max_delay(Duration::from_secs(5))
        .deadline(Duration::from_millis(10))
        .jitter(Jitter::None)
        .max_attempts(16)
        .build()?;
    let body = format!(r#"{{"name":"{NAME}","done":false}}"#);
    let (client, transport, clock) = connected(&body)?;
    let operation: Operation<Value, Value> = serde_json::from_str(&body)?;

    let outcome = block_on(client.poller().with_policy(policy).wait(operation));
    assert!(
        matches!(
            outcome,
            Err(ClientError::PollingStopped {
                limit: PollingLimit::Deadline,
                attempts: 1,
                ..
            })
        ),
        "{outcome:?}"
    );
    assert_eq!(transport.endpoint_calls().len(), 1);
    assert_eq!(clock.recorded_sleeps(), [] as [Duration; 0]);
    Ok(())
}

#[test]
fn a_malformed_untyped_dependency_is_absent() {
    for malformed in [
        json!({"depends": 7}),
        json!({"depends": "witness.EABC"}),
        json!({"depends": []}),
        json!({"depends": {}}),
        json!({"depends": {"done": true}}),
        json!({"depends": {"name": 7}}),
        json!({"depends": null}),
        json!({}),
        json!(null),
    ] {
        assert_eq!(malformed.dependency(), None, "{malformed} was read as a dependency");
    }
}
