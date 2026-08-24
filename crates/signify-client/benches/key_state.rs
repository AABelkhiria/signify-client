//! Microbenchmark for the key-event and key-state endpoints.
//!
//! Neither family derives a key or signs anything, so the client's own ~25 µs signature
//! (Roadmap 6.4) dominates any request either sends. What is worth measuring is what they add: a
//! query built from one prefix or many, a body written from a typed request, and the decoding of
//! the three documents a KERIA agent answers with.
//!
//! Inputs: one 44-character prefix, listings of one to sixteen of them, one key-event record with
//! its CESR attachment, one key state, and one pending query operation.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_client::endpoint::key_events::{EVENTS_SEGMENT, PREFIX_PARAMETER};
use signify_client::endpoint::key_states::{KeyStateQuery, QUERIES_SEGMENT, QuerySequence, STATES_SEGMENT};
use signify_http::request::ResourcePath;
use signify_keri::prefix::IdentifierPrefix;
use signify_types::api::{KeyEventRecord, KeyState, QueryOperation, Seal};

const PREFIX: &str = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";
const OTHER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

const KEY_EVENT_RECORD: &str = r#"{"ked":{"v":"KERI10JSON00012b_","t":"icp","d":"EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX","i":"EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX","s":"0","kt":"1","k":["DGBw7C7AfC7jbD3jLLRS3SzIWFndM947TyNWKQ52iQx5"],"nt":"1","n":["EML5FrjCpz8SEl4dh0U15l8bMRhV_O5iDcR1opLJGBSH"],"bt":"0","b":[],"c":[],"a":[]},"atc":"-VAn-AABAAB0mGa6DKRLR6-1DXBlvIP0DEHkTLQtNQqHqPTLTUdMBBB0mGa6DKRLR6"}"#;

const KEY_STATE: &str = r#"{"vn":[1,0],"i":"EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX","s":"0","p":"","d":"EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"icp","kt":"1","k":["DGBw7C7AfC7jbD3jLLRS3SzIWFndM947TyNWKQ52iQx5"],"nt":"1","n":["EML5FrjCpz8SEl4dh0U15l8bMRhV_O5iDcR1opLJGBSH"],"bt":"0","b":[],"c":[],"ee":{"s":"0","d":"EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX","br":[],"ba":[]},"di":""}"#;

const QUERY_OPERATION: &str = r#"{"name":"query.EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX","metadata":{"pre":"EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX","sn":1},"done":false}"#;

fn benchmark_key_state(criterion: &mut Criterion) {
    let (Ok(prefix), Ok(other)) = (IdentifierPrefix::from_qb64(PREFIX), IdentifierPrefix::from_qb64(OTHER)) else {
        return;
    };
    let Ok(text) = prefix.qb64() else { return };

    // Addressing: one prefix, then a listing of several.
    criterion.bench_function("key_events_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(EVENTS_SEGMENT)
                .parameter(PREFIX_PARAMETER, black_box(&text))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("key_states_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(STATES_SEGMENT)
                .parameter(PREFIX_PARAMETER, black_box(&text))
                .build()
                .is_ok()
        });
    });
    for count in [4_usize, 16] {
        criterion.bench_function(&format!("key_states_list_path_{count}"), |bencher| {
            bencher.iter(|| {
                let mut builder = ResourcePath::builder().segment(STATES_SEGMENT);
                for _ in 0..black_box(count) {
                    builder = builder.parameter(PREFIX_PARAMETER, &text);
                }
                builder.build().is_ok()
            });
        });
    }
    criterion.bench_function("key_states_queries_path", |bencher| {
        bencher.iter(|| ResourcePath::builder().segment(QUERIES_SEGMENT).build().is_ok());
    });

    // Writing a query body, in each of its three shapes.
    let latest = KeyStateQuery::latest(prefix.clone());
    let at = KeyStateQuery::at(prefix.clone(), QuerySequence::Decimal(1));
    let anchoring = KeyStateQuery::anchoring(
        prefix,
        Seal {
            identifier: Some(other.qb64().unwrap_or_default()),
            sequence_number: "0".to_owned(),
            digest: OTHER.to_owned(),
        },
    );
    for (name, query) in [
        ("key_states_query_body_latest", &latest),
        ("key_states_query_body_at", &at),
        ("key_states_query_body_anchoring", &anchoring),
    ] {
        criterion.bench_function(name, |bencher| {
            bencher.iter(|| black_box(query).body().is_ok());
        });
    }

    // Rendering a sequence number, which is the one place a caller's choice reaches the wire.
    criterion.bench_function("key_states_sequence_text", |bencher| {
        bencher.iter(|| black_box(QuerySequence::Hexadecimal(255)).to_text());
    });

    // Decoding the three documents an agent answers with.
    criterion.bench_function("key_events_decode_record", |bencher| {
        bencher.iter(|| serde_json::from_str::<KeyEventRecord>(black_box(KEY_EVENT_RECORD)).is_ok());
    });
    criterion.bench_function("key_states_decode_state", |bencher| {
        bencher.iter(|| serde_json::from_str::<KeyState>(black_box(KEY_STATE)).is_ok());
    });
    criterion.bench_function("key_states_decode_query_operation", |bencher| {
        bencher.iter(|| serde_json::from_str::<QueryOperation>(black_box(QUERY_OPERATION)).is_ok());
    });
}

criterion_group!(benches, benchmark_key_state);
criterion_main!(benches);
