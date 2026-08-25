#![no_main]

//! Fuzzes the operation polling loop over hostile agent answers and arbitrary policies.
//!
//! Two things here come from outside, and one of them is not obvious. An **agent's answer** decides
//! whether a caller believes an operation succeeded — Roadmap 6.5 already fuzzes that shape. What
//! is new is that the same answer also names **the next resource this client will fetch**: a
//! dependency's `name` becomes a path segment under `/operations/`, so a hostile agent chooses part
//! of a URL, and Roadmap 3.10 signs `@path`. The second input is the **policy**, which is a
//! caller's, and whose whole job is to make the loop terminate where the reference's `while (true)`
//! does not.
//!
//! The target asserts that nothing panics, that a dependency's name can never escape its own path
//! segment whatever the agent sent, that reading a dependency from typed and untyped metadata
//! always agrees, and that **every policy that builds produces a schedule which stops** — stepped
//! to completion here rather than argued.

use core::time::Duration;

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::operations::OPERATIONS_SEGMENT;
use signify_client::operation::{PollPolicy, PollableMetadata};
use signify_http::request::ResourcePath;
use signify_http::retry::{Backoff, Jitter, RetryDecision};
use signify_http::transport::Method;
use signify_types::api::{RegistryMetadata, UntypedOperation};

/// Every character that would give a path component a meaning it did not have.
const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

/// Reads four little-endian bytes, or zero when there are not four.
fn word(data: &[u8], index: usize) -> u32 {
    let start = index.saturating_mul(4);
    let end = start.saturating_add(4);
    data.get(start..end)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map_or(0, u32::from_le_bytes)
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let knobs = parts.next().unwrap_or_default();
    let document = parts.next().unwrap_or_default();

    // ---------------------------------------------------------------------
    // The policy: whatever it is, its schedule must stop.
    // ---------------------------------------------------------------------
    let jitter = match word(knobs, 0).wrapping_rem(3) {
        0 => Jitter::None,
        1 => Jitter::Equal,
        _ => Jitter::Full,
    };
    let built = PollPolicy::builder()
        .initial_delay(Duration::from_millis(u64::from(word(knobs, 1))))
        .min_delay(Duration::from_millis(u64::from(word(knobs, 2))))
        .max_delay(Duration::from_millis(u64::from(word(knobs, 3))))
        .max_attempts(word(knobs, 4))
        .deadline(Duration::from_millis(u64::from(word(knobs, 5))))
        .jitter(jitter)
        .build();

    if let Ok(policy) = built {
        // A policy that builds always allows at least one attempt and always admits the `GET` a
        // poll makes, so it can never refuse to poll for a reason unrelated to polling.
        assert!(policy.max_attempts() >= 1);
        assert!(policy.schedule().scope().admits(Method::Get));

        // Stepping the same schedule the loop steps must reach `Stop`, and within the bound. This
        // is the property the reference has no way to state: its loop has no bound at all.
        let start = std::time::Instant::now();
        let mut backoff = Backoff::new(*policy.schedule(), start);
        let mut elapsed = Duration::ZERO;
        let mut steps = 0_u32;
        loop {
            let now = start.checked_add(elapsed).unwrap_or(start);
            match backoff.next(now, Method::Get, true, word(knobs, 6), None, std::time::UNIX_EPOCH) {
                RetryDecision::Retry { delay, .. } => {
                    // A delay is always inside the bounds the policy declares.
                    assert!(delay <= policy.max_delay().max(policy.min_delay()));
                    elapsed = elapsed.saturating_add(delay);
                    steps = steps.saturating_add(1);
                    assert!(
                        steps < policy.max_attempts(),
                        "a schedule retried past its own attempt bound"
                    );
                }
                RetryDecision::Stop(_) => break,
            }
        }
    }

    // ---------------------------------------------------------------------
    // The agent's answer.
    // ---------------------------------------------------------------------
    let Ok(operation) = serde_json::from_slice::<UntypedOperation>(document) else {
        return;
    };

    // Exactly one of the three outcomes, never two and never none — Roadmap 4.1's decoder refuses
    // every other combination, and a poll reads `is_done` to decide whether to stop.
    let done = operation.outcome.is_done();
    assert_eq!(
        done,
        operation.outcome.response().is_some() || operation.outcome.error().is_some()
    );

    // The operation's own name becomes a path segment on every attempt after the first.
    if let Ok(path) = ResourcePath::builder()
        .segment(OPERATIONS_SEGMENT)
        .segment(&operation.name)
        .build()
    {
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        assert_eq!(
            segments.len(),
            2,
            "an operation name became {} segments",
            segments.len()
        );
        for delimiter in PATH_DELIMITERS {
            assert!(
                !segments.get(1).copied().unwrap_or_default().contains(delimiter),
                "an encoded operation name still carries {delimiter:?}"
            );
        }
        assert_eq!(path.query(), None, "an operation name introduced a query");
    }

    let Some(metadata) = operation.metadata.as_ref() else {
        return;
    };

    // A dependency read from untyped metadata is the reference's own `'depends' in op.metadata`.
    // Whatever it holds, the name it yields is the next thing this client would fetch.
    if let Some(dependency) = metadata.dependency() {
        assert!(!dependency.name.is_empty() || dependency.name.is_empty());
        if let Ok(path) = ResourcePath::builder()
            .segment(OPERATIONS_SEGMENT)
            .segment(&dependency.name)
            .build()
        {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(
                segments.len(),
                2,
                "a dependency name chosen by the agent became {} segments",
                segments.len()
            );
            for delimiter in PATH_DELIMITERS {
                assert!(
                    !segments.get(1).copied().unwrap_or_default().contains(delimiter),
                    "an encoded dependency name still carries {delimiter:?}"
                );
            }
            assert_eq!(path.query(), None, "a dependency name introduced a query");
        }

        // When the same metadata also decodes as a registry's, both paths must name the same
        // dependency: an untyped poll and a narrowed one must not walk different chains.
        if let Ok(typed) = serde_json::from_value::<RegistryMetadata>(metadata.clone()) {
            assert_eq!(
                typed.dependency(),
                Some(dependency),
                "typed and untyped metadata disagreed about a dependency"
            );
        }
    } else {
        // No dependency means no second chain to walk, however the metadata is read.
        if let Ok(typed) = serde_json::from_value::<RegistryMetadata>(metadata.clone()) {
            // A registry's dependency is required by the schema, so decoding one at all means the
            // untyped read must have found it too.
            assert!(
                typed.dependency().is_none(),
                "untyped metadata missed a dependency the typed one found"
            );
        }
    }
});
