//! Microbenchmarks for the retry policy.
//!
//! Nothing here waits — a benchmark that slept would be measuring the clock — so what is measured
//! is the decision-making a retry costs *besides* the wait: computing a delay, jittering it,
//! drawing the randomness, parsing a server's guidance, and taking one step of a schedule.
//!
//! The number that matters is that all of it is negligible beside the delay it schedules. The
//! reference's own shortest delay is 50 ms; anything here in the nanoseconds is free by
//! comparison, and the point of measuring is to notice if it ever stops being.

use core::time::Duration;
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use criterion::{Criterion, criterion_group, criterion_main};
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{
    Backoff, Clock, FixedJitter, Jitter, JitterSource, OsJitter, RetryAfter, RetryAfterPolicy, RetryPolicy, RetryScope,
    RetryingTransport, TestClock,
};
use signify_http::transport::{Method, Request, RequestUrl, Response, ScriptedTransport, StatusCode, Transport};

/// A minimal executor; every future on this path is ready on its first poll.
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

/// The reference's own production parameters, with jitter off.
fn reference_policy() -> Option<RetryPolicy> {
    RetryPolicy::builder()
        .base_delay(Duration::from_millis(50))
        .min_delay(Duration::from_millis(10))
        .max_delay(Duration::from_secs(10))
        .jitter(Jitter::None)
        .max_attempts(64)
        .without_deadline()
        .build()
        .ok()
}

fn benchmark_delay(criterion: &mut Criterion) {
    let Some(policy) = reference_policy() else {
        return;
    };
    // The first attempt, and one far enough out that the ceiling binds and the shift saturates.
    for attempt in [0_u32, 8, 64] {
        criterion.bench_function(&format!("delay_for/attempt_{attempt}"), |bencher| {
            bencher.iter(|| black_box(&policy).delay_for(black_box(attempt)));
        });
    }

    let jittered = RetryPolicy::builder().jitter(Jitter::Equal).build().ok();
    let Some(jittered) = jittered else {
        return;
    };
    criterion.bench_function("delay_with_guidance/computed", |bencher| {
        bencher.iter(|| {
            black_box(&jittered).delay_with_guidance(
                black_box(3),
                black_box(u32::MAX / 2),
                None,
                SystemTime::UNIX_EPOCH,
            )
        });
    });
    let guidance = Some(RetryAfter::Delay(Duration::from_secs(5)));
    criterion.bench_function("delay_with_guidance/server_named", |bencher| {
        bencher.iter(|| {
            black_box(&jittered).delay_with_guidance(
                black_box(3),
                black_box(u32::MAX / 2),
                black_box(guidance),
                SystemTime::UNIX_EPOCH,
            )
        });
    });
}

fn benchmark_jitter(criterion: &mut Criterion) {
    let delay = Duration::from_millis(800);
    for (name, jitter) in [("none", Jitter::None), ("equal", Jitter::Equal), ("full", Jitter::Full)] {
        criterion.bench_function(&format!("jitter/{name}"), |bencher| {
            bencher.iter(|| black_box(jitter).apply(black_box(delay), black_box(u32::MAX / 3)));
        });
    }

    // Where the randomness comes from, which is the one part that leaves the process.
    criterion.bench_function("jitter_source/os", |bencher| {
        bencher.iter(|| black_box(&OsJitter).next_u32());
    });
    let fixed = FixedJitter::new(7);
    criterion.bench_function("jitter_source/fixed", |bencher| {
        bencher.iter(|| black_box(&fixed).next_u32());
    });
}

fn benchmark_retry_after(criterion: &mut Criterion) {
    criterion.bench_function("retry_after_parse/delay_seconds", |bencher| {
        bencher.iter(|| RetryAfter::parse(black_box("120")));
    });
    // The date form is the expensive one: fixed-width validation plus a civil-date conversion.
    criterion.bench_function("retry_after_parse/imf_fixdate", |bencher| {
        bencher.iter(|| RetryAfter::parse(black_box("Sun, 06 Nov 1994 08:49:37 GMT")));
    });
    criterion.bench_function("retry_after_parse/rejected", |bencher| {
        bencher.iter(|| RetryAfter::parse(black_box("Sunday, 06-Nov-94 08:49:37 GMT")));
    });

    let date = RetryAfter::parse("Sun, 06 Nov 1994 08:49:37 GMT").ok();
    let Some(date) = date else {
        return;
    };
    criterion.bench_function("retry_after_delay_from/date", |bencher| {
        bencher.iter(|| black_box(date).delay_from(black_box(SystemTime::UNIX_EPOCH)));
    });
}

fn benchmark_schedule(criterion: &mut Criterion) {
    let Some(policy) = reference_policy() else {
        return;
    };
    let now = Instant::now();
    // One decision: the whole cost of a retry besides the wait it schedules.
    criterion.bench_function("backoff_next/one_decision", |bencher| {
        bencher.iter_batched(
            || Backoff::new(policy, now),
            |mut backoff| backoff.next(now, Method::Get, true, u32::MAX / 2, None, SystemTime::UNIX_EPOCH),
            criterion::BatchSize::SmallInput,
        );
    });

    // A whole sequence, driven through the transport against a scripted server: eight attempts,
    // seven waits, and none of the 12.75 s the reference would have spent on them.
    let Ok(url) = RequestUrl::new("http://localhost:3901/operations/witness.EPRE") else {
        return;
    };
    let Ok(request) = Request::builder(Method::Get, url).build() else {
        return;
    };
    criterion.bench_function("retrying_transport/eight_attempts", |bencher| {
        bencher.iter_batched(
            || {
                let mut scripted = ScriptedTransport::new();
                for _ in 0..7 {
                    if let Ok(status) = StatusCode::new(503)
                        && let Ok(response) = Response::new(status, Headers::new(), Vec::new())
                    {
                        scripted = scripted.respond(response);
                    }
                }
                if let Ok(status) = StatusCode::new(200)
                    && let Ok(response) = Response::new(status, Headers::new(), Vec::new())
                {
                    scripted = scripted.respond(response);
                }
                RetryingTransport::new(Arc::new(scripted))
                    .with_policy(policy)
                    .with_clock(Arc::new(TestClock::new()) as Arc<dyn Clock>)
                    .with_jitter_source(Arc::new(FixedJitter::new(0)))
            },
            |transport| block_on(transport.execute(request.clone())),
            criterion::BatchSize::SmallInput,
        );
    });

    // And the same sequence when every answer names its own timing, which adds a header parse per
    // attempt.
    let guided = RetryPolicy::builder()
        .base_delay(Duration::from_millis(50))
        .jitter(Jitter::None)
        .max_attempts(8)
        .scope(RetryScope::IdempotentOnly)
        .retry_after(RetryAfterPolicy::Honor {
            maximum: Duration::from_secs(30),
        })
        .without_deadline()
        .build()
        .ok();
    let Some(guided) = guided else {
        return;
    };
    criterion.bench_function("retrying_transport/eight_attempts_with_guidance", |bencher| {
        bencher.iter_batched(
            || {
                let mut scripted = ScriptedTransport::new();
                for _ in 0..7 {
                    let mut headers = Headers::new();
                    if let (Ok(name), Ok(value)) = (HeaderName::new("Retry-After"), HeaderValue::new("1")) {
                        let _ = headers.insert(name, value);
                    }
                    if let Ok(status) = StatusCode::new(503)
                        && let Ok(response) = Response::new(status, headers, Vec::new())
                    {
                        scripted = scripted.respond(response);
                    }
                }
                if let Ok(status) = StatusCode::new(200)
                    && let Ok(response) = Response::new(status, Headers::new(), Vec::new())
                {
                    scripted = scripted.respond(response);
                }
                RetryingTransport::new(Arc::new(scripted))
                    .with_policy(guided)
                    .with_clock(Arc::new(TestClock::new()) as Arc<dyn Clock>)
                    .with_jitter_source(Arc::new(FixedJitter::new(0)))
            },
            |transport| block_on(transport.execute(request.clone())),
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    benchmark_delay,
    benchmark_jitter,
    benchmark_retry_after,
    benchmark_schedule,
);
criterion_main!(benches);
