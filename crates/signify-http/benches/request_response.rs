//! Microbenchmarks for the request builder and the response decoder.
//!
//! Every SDK call passes through both of these, and both of them allocate: a path builder encodes
//! each component into a fresh `String`, and a decoder clones the headers off the response it
//! consumes. Neither is cryptographic and neither touches a network, so what is measured here is
//! the cost the layer itself adds — and, for the decoder, whether that cost grows with the body,
//! which is the number that matters for a large credential listing.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::request::{
    BaseUrl, ItemRange, MediaType, RangeUnit, ResourcePath, ResourceRequestBuilder, encode_path_component,
    encode_query_component,
};
use signify_http::response::{ContentRange, RequestOrigin, ResourceResponse};
use signify_http::transport::{Method, Request, RequestUrl, Response, StatusCode};

/// The base URL a client is configured with.
const BASE: &str = "http://localhost:3901";

/// An ordinary alias: nothing needs escaping, which is the common case.
const PLAIN_ALIAS: &str = "EPRE_yBSc0Pg9DhRfqOZWQXFOAAcJlLGCwNGVAQ_z_A0";

/// The alias the pinned unit test uses: fourteen characters, five of which escape.
const ESCAPED_ALIAS: &str = "a name with ñ!";

fn benchmark_encoding(criterion: &mut Criterion) {
    criterion.bench_function("encode_path_component/plain_44_bytes", |bencher| {
        bencher.iter(|| encode_path_component(black_box(PLAIN_ALIAS)));
    });
    criterion.bench_function("encode_path_component/escaped_15_bytes", |bencher| {
        bencher.iter(|| encode_path_component(black_box(ESCAPED_ALIAS)));
    });
    criterion.bench_function("encode_query_component/escaped_13_bytes", |bencher| {
        bencher.iter(|| encode_query_component(black_box("/multisig/icp")));
    });
}

fn benchmark_url_composition(criterion: &mut Criterion) {
    let Ok(base) = BaseUrl::new(BASE) else {
        return;
    };

    // The deepest path the reference builds, and the widest query.
    criterion.bench_function("resource_path/four_components", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(black_box("identifiers"))
                .segment(black_box(PLAIN_ALIAS))
                .segment(black_box("registries"))
                .segment(black_box("vLEI"))
                .build()
        });
    });
    criterion.bench_function("resource_path/three_parameters", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(black_box("contacts"))
                .parameter(black_box("group"), black_box("group"))
                .parameter(black_box("filter_field"), black_box("field"))
                .parameter(black_box("filter_value"), black_box("value"))
                .build()
        });
    });

    let Ok(path) = ResourcePath::builder()
        .segment("identifiers")
        .segment(PLAIN_ALIAS)
        .build()
    else {
        return;
    };
    criterion.bench_function("base_url_join", |bencher| {
        bencher.iter(|| base.join(black_box(&path)));
    });
}

fn benchmark_request_assembly(criterion: &mut Criterion) {
    let Ok(base) = BaseUrl::new(BASE) else {
        return;
    };
    let Ok(path) = ResourcePath::builder().segment("identifiers").build() else {
        return;
    };
    let Ok(url) = base.join(&path) else {
        return;
    };
    let Ok(unit) = RangeUnit::new("aids") else {
        return;
    };

    // A paged list: the shape `identifiers().list()` sends.
    criterion.bench_function("resource_request/paged_list", |bencher| {
        bencher.iter(|| {
            ResourceRequestBuilder::new(Method::Get, black_box(url.clone()))
                .content_type(MediaType::json())
                .range(black_box(&unit), ItemRange::DEFAULT)
                .build()
        });
    });

    // A creation: the largest body the reference sends from an endpoint module. The body is
    // cloned as *setup*, so what is timed is the assembly rather than the memcpy.
    criterion.bench_function("resource_request/json_body_4096_bytes", |bencher| {
        bencher.iter_batched(
            || (url.clone(), vec![b'x'; 4_096]),
            |(url, body)| ResourceRequestBuilder::new(Method::Post, url).json_body(body).build(),
            BatchSize::SmallInput,
        );
    });
}

fn benchmark_response_decoding(criterion: &mut Criterion) {
    let Ok(unit) = RangeUnit::new("aids") else {
        return;
    };
    criterion.bench_function("content_range_parse", |bencher| {
        bencher.iter(|| ContentRange::parse(black_box("aids 0-24/1024"), black_box(&unit)));
    });

    let Ok(url) = RequestUrl::new("http://localhost:3901/identifiers?limit=25") else {
        return;
    };
    let Ok(request) = Request::builder(Method::Get, url).build() else {
        return;
    };
    let origin = RequestOrigin::of(&request);
    criterion.bench_function("request_origin_capture", |bencher| {
        bencher.iter(|| RequestOrigin::of(black_box(&request)));
    });

    let headers = build_response_headers();
    for size in [64_usize, 16 * 1024, 256 * 1024] {
        let body = vec![b'x'; size];
        let Ok(status) = StatusCode::new(200) else {
            return;
        };
        let Ok(response) = Response::new(status, headers.clone(), body) else {
            return;
        };
        // The decoder moves the body and clones only the headers, so this must be flat in the
        // body size. The response is cloned as *setup*, because a clone does copy the body and
        // timing that instead would hide exactly the regression this is here to catch.
        criterion.bench_function(&format!("resource_response_decode/{size}_bytes"), |bencher| {
            bencher.iter_batched(
                || response.clone(),
                |response| ResourceResponse::decode(black_box(&origin), response),
                BatchSize::SmallInput,
            );
        });
    }

    // Reading a decoded body is a content-type check and a slice, whatever the body's size.
    let Ok(status) = StatusCode::new(200) else {
        return;
    };
    let Ok(response) = Response::new(status, headers, vec![b'x'; 256 * 1024]) else {
        return;
    };
    let Ok(decoded) = ResourceResponse::decode(&origin, response) else {
        return;
    };
    criterion.bench_function("resource_response_json/262144_bytes", |bencher| {
        bencher.iter(|| black_box(&decoded).json());
    });
    criterion.bench_function("resource_response_content_range", |bencher| {
        bencher.iter(|| black_box(&decoded).content_range(black_box(&unit)));
    });
}

/// The headers a KERIA list response carries.
fn build_response_headers() -> Headers {
    let mut headers = Headers::new();
    for (name, value) in [
        ("Content-Type", "application/json"),
        ("Content-Range", "aids 0-24/1024"),
        ("Signify-Resource", "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY"),
    ] {
        if let (Ok(name), Ok(value)) = (HeaderName::new(name), HeaderValue::new(value)) {
            let _ = headers.insert(name, value);
        }
    }
    headers
}

criterion_group!(
    benches,
    benchmark_encoding,
    benchmark_url_composition,
    benchmark_request_assembly,
    benchmark_response_decoding,
);
criterion_main!(benches);
