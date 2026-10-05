//! Microbenchmarks for the authenticated-transport composition.
//!
//! Unlike the retry policy, this one *is* cryptographic: every request carries an Ed25519
//! signature over a base the layer rebuilds each time. That cost is paid on **every attempt**,
//! because Roadmap 5.4's ordering puts signing inside the retry loop — so what these measure is
//! what a retry actually costs beyond its wait, and what a response costs to trust.

use core::time::Duration;
use std::hint::black_box;
use std::sync::Arc;
use std::time::SystemTime;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::retry::{Clock, TestClock};
use signify_http::signature::authentication::{RequestSigner, ResponseVerifier};
use signify_http::signature::input::{
    RequestTarget, SIGNIFY_RESOURCE_HEADER_NAME, SIGNIFY_TIMESTAMP_HEADER_NAME, default_components,
};
use signify_http::signature::timestamp::SignifyTimestamp;
use signify_http::signature::transport::{Freshness, ResponseAuthenticator, SigningTransport};
use signify_http::transport::{Method, Request, RequestUrl, Response, ScriptedTransport, StatusCode, Transport};

/// The controller prefix the fixture uses.
const RESOURCE: &str = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose";

/// The instant the fixture pins, so the benchmark and the vectors describe the same work.
const FIXED_MILLIS: u64 = 1_700_000_000_123;

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

fn pinned_clock() -> Arc<TestClock> {
    Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(FIXED_MILLIS),
    ))
}

fn benchmark_timestamp(criterion: &mut Criterion) {
    // Rendering the header is a civil-date conversion and one `format!`.
    criterion.bench_function("signify_timestamp/render", |bencher| {
        bencher.iter(|| SignifyTimestamp::from_unix(black_box(Duration::from_millis(FIXED_MILLIS))));
    });
}

fn benchmark_signing(criterion: &mut Criterion) {
    let clock = pinned_clock();
    let Ok(signer) = Signer::generate(KeyTransferability::Transferable) else {
        return;
    };
    let Ok(resource) = HeaderValue::new(RESOURCE) else {
        return;
    };
    let Ok(transport) = SigningTransport::new(Arc::new(ScriptedTransport::new()), RequestSigner::new(signer), resource)
    else {
        return;
    };
    let transport = transport.with_clock(Arc::clone(&clock) as Arc<dyn Clock>);

    // The plainest authenticated call the reference makes: a GET with no body.
    let Ok(url) = RequestUrl::new("http://localhost:3901/identifiers") else {
        return;
    };
    let Ok(plain) = Request::builder(Method::Get, url.clone()).build() else {
        return;
    };
    criterion.bench_function("sign_request/get_no_body", |bencher| {
        bencher.iter(|| transport.sign_request(black_box(&plain)));
    });

    // A creation, whose body is carried but not covered — so the body's size should not matter.
    for size in [64_usize, 4_096, 65_536] {
        let Ok(request) = Request::builder(Method::Post, url.clone())
            .body(vec![b'x'; size])
            .build()
        else {
            return;
        };
        criterion.bench_function(&format!("sign_request/post_body_{size}_bytes"), |bencher| {
            bencher.iter(|| transport.sign_request(black_box(&request)));
        });
    }

    // The whole decorator, including handing the signed request to the transport beneath.
    criterion.bench_function("signing_transport/execute", |bencher| {
        bencher.iter_batched(
            || {
                let mut scripted = ScriptedTransport::new();
                if let Ok(status) = StatusCode::new(200)
                    && let Ok(response) = Response::new(status, Headers::new(), Vec::new())
                {
                    scripted = scripted.respond(response);
                }
                scripted
            },
            |scripted| {
                let Ok(signer) = Signer::generate(KeyTransferability::Transferable) else {
                    return;
                };
                let Ok(resource) = HeaderValue::new(RESOURCE) else {
                    return;
                };
                let Ok(transport) = SigningTransport::new(Arc::new(scripted), RequestSigner::new(signer), resource)
                else {
                    return;
                };
                let transport = transport.with_clock(Arc::clone(&clock) as Arc<dyn Clock>);
                let Ok(request) = Request::builder(Method::Get, url.clone()).build() else {
                    return;
                };
                let _ = block_on(transport.execute(request));
            },
            BatchSize::SmallInput,
        );
    });
}

/// Builds one response the agent signed, and the authenticator that checks it.
fn signed_response() -> Option<(ResponseAuthenticator, RequestTarget, Headers)> {
    let clock = pinned_clock();
    let agent = Signer::generate(KeyTransferability::NonTransferable).ok()?;
    let key = agent.verifier().clone();
    let agent_signer = RequestSigner::new(agent);

    let target = RequestTarget::new("GET", "/identifiers").ok()?;
    let stamp = SignifyTimestamp::at(clock.wall_clock()).ok()?;
    let mut headers = Headers::new();
    headers
        .insert(
            HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME).ok()?,
            HeaderValue::new(RESOURCE).ok()?,
        )
        .ok()?;
    headers
        .insert(
            HeaderName::new(SIGNIFY_TIMESTAMP_HEADER_NAME).ok()?,
            stamp.to_header_value().ok()?,
        )
        .ok()?;
    let input = agent_signer
        .signature_input(default_components().ok()?, stamp.created())
        .ok()?;
    agent_signer
        .sign(&input, &target, &headers)
        .ok()?
        .apply(&mut headers)
        .ok()?;

    let authenticator = ResponseAuthenticator::new(
        ResponseVerifier::new(key),
        HeaderValue::new(RESOURCE).ok()?,
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    Some((authenticator, target, headers))
}

fn benchmark_authentication(criterion: &mut Criterion) {
    let Some((authenticator, target, headers)) = signed_response() else {
        return;
    };

    // The whole check: resource equality, signature verification, then freshness.
    criterion.bench_function("authenticate/valid", |bencher| {
        bencher.iter(|| authenticator.authenticate(black_box(&target), black_box(&headers)));
    });

    // The reference's own policy, so the freshness check's own cost is visible by difference.
    let permissive = signed_response().map(|(authenticator, _, _)| authenticator.with_freshness(Freshness::Ignore));
    if let Some(permissive) = permissive {
        criterion.bench_function("authenticate/valid_without_freshness", |bencher| {
            bencher.iter(|| permissive.authenticate(black_box(&target), black_box(&headers)));
        });
    }

    // A rejection that never reaches the signature, which is the cheap path a hostile peer hits.
    let Ok(other) = HeaderValue::new("EOTHERAGENTPREFIXAAAAAAAAAAAAAAAAAAAAAAAAAAA") else {
        return;
    };
    let Some((_, _, mut foreign)) = signed_response() else {
        return;
    };
    let Ok(name) = HeaderName::new(SIGNIFY_RESOURCE_HEADER_NAME) else {
        return;
    };
    let mut replaced = Headers::new();
    for (existing, value) in &foreign {
        let value = if existing.matches(SIGNIFY_RESOURCE_HEADER_NAME) {
            other.clone()
        } else {
            value.clone()
        };
        if replaced.insert(existing.clone(), value).is_err() {
            return;
        }
    }
    foreign = replaced;
    let _ = name;
    criterion.bench_function("authenticate/foreign_resource", |bencher| {
        bencher.iter(|| authenticator.authenticate(black_box(&target), black_box(&foreign)));
    });

    // Freshness alone, so its contribution is not guessed at.
    let now = SystemTime::UNIX_EPOCH + Duration::from_millis(FIXED_MILLIS);
    criterion.bench_function("freshness/check", |bencher| {
        bencher.iter(|| Freshness::default().check(black_box(FIXED_MILLIS / 1_000), black_box(now)));
    });
}

criterion_group!(
    benches,
    benchmark_timestamp,
    benchmark_signing,
    benchmark_authentication,
);
criterion_main!(benches);
