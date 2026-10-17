//! Microbenchmark for the operations endpoint.
//!
//! Nothing here signs or derives: the endpoint builds a path, and the client's own signing cost
//! (the `lifecycle` benchmark measured it at ~25 µs) dominates any request. What is worth measuring
//! is the part this family adds — building the path, decoding the agent's answer into the typed
//! model, and turning a completed operation into its response or its failure.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keria_types::api::{KeyEvent, Operation, UntypedOperation, WitnessMetadata};
use signify_client::endpoint::operations::{OPERATIONS_SEGMENT, TYPE_PARAMETER, completed};
use signify_http::request::ResourcePath;

const NAME: &str = "witness.EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1.0";

const PENDING: &str = r#"{"name":"witness.EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1.0","metadata":{"pre":"EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1","sn":0},"done":false,"error":null}"#;

const COMPLETED: &str = r#"{"name":"witness.EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1.0","metadata":{"pre":"EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1","sn":0},"done":true,"error":null,"response":{"v":"KERI10JSON00012b_","t":"icp","d":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose","i":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose","s":"0","kt":"1","k":["DAbWjobbaLqRB94KiAutAHb_qzPpOHm3LURA_ksxetVc"],"nt":"1","n":["EIFG_uqfr1yN560LoHYHfvPAhxQ5sN6xZZT_E3h7d2tL"],"bt":"0","b":[],"c":[],"a":[]}}"#;

const FAILED: &str = r#"{"name":"witness.EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1.0","metadata":{"pre":"EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1","sn":0},"done":true,"error":{"code":408,"message":"Timed out waiting for witness receipts","details":{"received":2,"expected":3}}}"#;

fn benchmark_operations(criterion: &mut Criterion) {
    // The two paths this family builds, one of which encodes a dynamic component.
    criterion.bench_function("operations_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(OPERATIONS_SEGMENT)
                .segment(black_box(NAME))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("operations_list_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(OPERATIONS_SEGMENT)
                .optional_parameter(TYPE_PARAMETER, black_box(Some("witness")))
                .build()
                .is_ok()
        });
    });

    // Decoding the agent's answer, untyped and then narrowed.
    criterion.bench_function("operations_decode_untyped", |bencher| {
        bencher.iter(|| serde_json::from_str::<UntypedOperation>(black_box(COMPLETED)).is_ok());
    });
    criterion.bench_function("operations_decode_typed", |bencher| {
        bencher.iter(|| {
            serde_json::from_str::<UntypedOperation>(black_box(COMPLETED))
                .ok()
                .and_then(|operation| operation.into_typed::<WitnessMetadata, KeyEvent>().ok())
                .is_some()
        });
    });

    // Reading the outcome, which is where a caller ends up on every poll.
    for (name, document) in [
        ("operations_outcome_pending", PENDING),
        ("operations_outcome_completed", COMPLETED),
        ("operations_outcome_failed", FAILED),
    ] {
        let Ok(untyped) = serde_json::from_str::<UntypedOperation>(document) else {
            return;
        };
        let Ok(typed) = untyped.into_typed::<WitnessMetadata, KeyEvent>() else {
            return;
        };
        criterion.bench_function(name, |bencher| {
            bencher.iter(|| {
                let operation = Operation {
                    name: typed.name.clone(),
                    metadata: typed.metadata.clone(),
                    outcome: typed.outcome.clone(),
                };
                completed(black_box(operation)).is_ok()
            });
        });
    }
}

criterion_group!(benches, benchmark_operations);
criterion_main!(benches);
