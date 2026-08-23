//! Microbenchmarks for the production transport's request conversion.
//!
//! A whole round trip is dominated by the network, so what is worth measuring here is the cost the
//! transport itself adds before a byte leaves: converting a validated [`Request`] into hyper's own
//! message, which is where the URL and every header are re-checked. Building the transport is
//! measured too, because it loads the platform's certificate roots and a caller that builds one
//! per request would pay that every time.

#![cfg(feature = "http-client")]

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_http::header::{HeaderName, HeaderValue};
use signify_http::transport::{HttpTransport, Method, Request, RequestUrl};

/// The authenticated request shape the reference sends after connecting.
const URL: &str = "https://keria.example/identifiers/a%20name%20with%20%C3%B1!";

fn authenticated_request() -> Option<Request> {
    let mut builder = Request::builder(Method::Put, RequestUrl::new(URL).ok()?);
    for (name, value) in [
        ("content-type", "application/json"),
        ("signature", "indexed=\"?0\";signify=\"0BAbc\""),
        ("signature-input", "signify=(\"signify-resource\");created=1700000000"),
        ("signify-resource", "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"),
        ("signify-timestamp", "2026-08-23T12:00:00.000000+00:00"),
    ] {
        builder = builder.header(HeaderName::new(name).ok()?, HeaderValue::new(value).ok()?);
    }
    builder.body(br#"{"name":"renamed"}"#.to_vec()).build().ok()
}

fn benchmark_transport(criterion: &mut Criterion) {
    // Building the transport reads the platform trust store, so it is sampled sparingly and
    // exists to show it is a per-client cost, never a per-request one.
    let mut group = criterion.benchmark_group("setup");
    group.sample_size(20);
    group.bench_function("http_transport_build", |bencher| {
        bencher.iter(|| {
            HttpTransport::builder()
                .timeout(black_box(Duration::from_secs(30)))
                .build()
                .is_ok()
        });
    });
    group.finish();

    criterion.bench_function("authenticated_request_build", |bencher| {
        bencher.iter(|| authenticated_request().is_some());
    });
}

criterion_group!(benches, benchmark_transport);
criterion_main!(benches);
