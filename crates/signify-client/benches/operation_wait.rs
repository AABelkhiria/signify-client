//! Microbenchmark for the operation polling loop.
//!
//! Polling is a *loop*, so its per-attempt cost is worth knowing even when it is small: an SDK that
//! spent milliseconds deciding how long to sleep would be spending them once per attempt, on every
//! workflow, for as long as the agent takes.
//!
//! Three things are measured. The **schedule** is computed once per attempt. The **dependency
//! read** runs once per wait and, on the untyped path, walks a document the agent controls. And
//! **building a policy** happens once per poller, which a caller may construct per call.
//!
//! Inputs: schedules of 1, 8, and 20 attempts; metadata with and without a dependency, typed and
//! untyped; operation documents of the three outcomes.
//!
//! Nothing here is the real cost of polling. One attempt is one signed HTTP request, whose
//! signature alone Roadmap 6.4 measured at ~25 µs and whose round trip is the network — so every
//! number below is noise beside it, which is the point of recording them.

use core::time::Duration;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keria_types::api::{RegistryMetadata, UntypedOperation};
use serde_json::Value;
use signify_client::operation::{PollPolicy, PollableMetadata};
use signify_http::retry::Jitter;

/// A registry operation's metadata, which is the one family that always names a dependency.
const REGISTRY_METADATA: &str =
    r#"{"pre":"EPRE","depends":{"name":"witness.EABC.0","done":false},"anchor":{"pre":"EPRE","sn":0,"d":"EANCHOR"}}"#;

/// An OOBI resolution's metadata, which never names one.
const OOBI_METADATA: &str =
    r#"{"oobi":"http://witness-demo:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller"}"#;

const PENDING: &str = r#"{"name":"witness.EABC.0","metadata":{"pre":"EPRE","sn":0},"done":false}"#;
const COMPLETED: &str =
    r#"{"name":"witness.EABC.0","metadata":{"pre":"EPRE","sn":0},"done":true,"response":{"v":"KERI10JSON000000_"}}"#;
const FAILED: &str = r#"{"name":"witness.EABC.0","done":true,"error":{"code":500,"message":"witness receipts timed out","details":{"received":1}}}"#;

fn benchmark_polling(criterion: &mut Criterion) {
    let Ok(policy) = PollPolicy::builder().jitter(Jitter::None).build() else {
        return;
    };
    let Ok(jittered) = PollPolicy::builder().jitter(Jitter::Equal).build() else {
        return;
    };

    // Building a policy, which a caller may do once per poller.
    criterion.bench_function("poll_policy_build", |bencher| {
        bencher.iter(|| {
            PollPolicy::builder()
                .initial_delay(black_box(Duration::from_millis(50)))
                .max_attempts(black_box(20))
                .build()
                .is_ok()
        });
    });

    // The schedule: one delay, and a whole run of them.
    criterion.bench_function("poll_delay_for_one_attempt", |bencher| {
        bencher.iter(|| policy.delay_for(black_box(3)));
    });
    for attempts in [1_u32, 8, 20] {
        criterion.bench_function(&format!("poll_schedule_{attempts}_attempts"), |bencher| {
            bencher.iter(|| {
                (0..black_box(attempts))
                    .map(|attempt| policy.delay_for(attempt).as_millis())
                    .sum::<u128>()
            });
        });
    }
    // Jitter costs an extra multiply and a draw, and is on by default.
    criterion.bench_function("poll_delay_for_one_attempt_jittered", |bencher| {
        bencher.iter(|| {
            jittered
                .jitter()
                .apply(jittered.delay_for(black_box(3)), black_box(u32::MAX / 2))
        });
    });

    // Reading a dependency: a field access when the family is known, a map walk when it is not.
    let Ok(typed) = serde_json::from_str::<RegistryMetadata>(REGISTRY_METADATA) else {
        return;
    };
    let Ok(untyped) = serde_json::from_str::<Value>(REGISTRY_METADATA) else {
        return;
    };
    let Ok(without) = serde_json::from_str::<Value>(OOBI_METADATA) else {
        return;
    };
    criterion.bench_function("poll_dependency_typed", |bencher| {
        bencher.iter(|| black_box(&typed).dependency().is_some());
    });
    criterion.bench_function("poll_dependency_untyped", |bencher| {
        bencher.iter(|| black_box(&untyped).dependency().is_some());
    });
    criterion.bench_function("poll_dependency_untyped_absent", |bencher| {
        bencher.iter(|| black_box(&without).dependency().is_none());
    });

    // Decoding one attempt's answer, which happens once per request.
    for (label, document) in [("pending", PENDING), ("completed", COMPLETED), ("failed", FAILED)] {
        criterion.bench_function(&format!("poll_decode_{label}"), |bencher| {
            bencher.iter(|| serde_json::from_str::<UntypedOperation>(black_box(document)).is_ok());
        });
    }
}

criterion_group!(benches, benchmark_polling);
criterion_main!(benches);
