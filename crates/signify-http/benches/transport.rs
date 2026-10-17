//! Microbenchmarks for the transport boundary.
//!
//! Nothing here is cryptographic, so these measure the cost the boundary itself adds to every
//! request: parsing a URL, assembling a request, and the one heap allocation the boxed future
//! costs — the price accepted in exchange for a dyn-compatible trait. Measuring it is the point:
//! it must stay far below a network round trip.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::transport::{Method, Request, RequestUrl, Response, ScriptedTransport, StatusCode, Transport};

/// The longest URL the reference builds: an authenticated path with a query.
const URL: &str = "http://localhost:3901/contacts?group=group&filter_field=field&filter_value=value";

/// A minimal executor; the scripted transport's future is ready on its first poll.
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

/// Builds the five-header authenticated request the reference sends after connecting.
fn authenticated_request() -> Option<Request> {
    let mut builder = Request::builder(Method::Put, RequestUrl::new(URL).ok()?);
    for (name, value) in [
        ("content-type", "application/json"),
        ("signature", "indexed=\"?0\";signify=\"0BAbc\""),
        ("signature-input", "signify=(\"signify-resource\");created=1700000000"),
        ("signify-resource", "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"),
        ("signify-timestamp", "2026-08-22T12:00:00.000000+00:00"),
    ] {
        builder = builder.header(HeaderName::new(name).ok()?, HeaderValue::new(value).ok()?);
    }
    builder.body(br#"{"name":"renamed"}"#.to_vec()).build().ok()
}

fn benchmark_construction(criterion: &mut Criterion) {
    criterion.bench_function("request_url_parse", |bencher| {
        bencher.iter(|| RequestUrl::new(black_box(URL)).is_ok());
    });

    criterion.bench_function("request_build_bare", |bencher| {
        let Ok(url) = RequestUrl::new(URL) else {
            return;
        };
        bencher.iter(|| Request::builder(Method::Get, black_box(url.clone())).build().is_ok());
    });

    criterion.bench_function("request_build_authenticated", |bencher| {
        bencher.iter(|| authenticated_request().is_some());
    });
}

/// Measures one whole round trip through the boundary, which is the boxed future's real cost.
fn benchmark_round_trip(criterion: &mut Criterion) {
    criterion.bench_function("scripted_round_trip", |bencher| {
        bencher.iter_batched(
            || {
                let response = Response::new(
                    StatusCode::new(200).ok()?,
                    Headers::new(),
                    br#"{"name":"aid1"}"#.to_vec(),
                )
                .ok()?;
                Some((ScriptedTransport::new().respond(response), authenticated_request()?))
            },
            |setup| setup.map(|(transport, request)| block_on(transport.execute(request)).is_ok()),
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, benchmark_construction, benchmark_round_trip);
criterion_main!(benches);
