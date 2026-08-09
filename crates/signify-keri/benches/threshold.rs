//! Microbenchmarks for exact threshold parsing and satisfaction.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_keri::threshold::SigningThreshold;

fn benchmark_threshold(criterion: &mut Criterion) {
    criterion.bench_function("threshold_parse_numeric", |bencher| {
        bencher.iter(|| SigningThreshold::from_sith(black_box("b")));
    });

    let weighted = "[[\"1/2\",\"1/2\",\"1/2\"],[\"1/3\",\"1/3\",\"1/3\",\"1/3\"]]";
    criterion.bench_function("threshold_parse_weighted_7_keys", |bencher| {
        bencher.iter(|| SigningThreshold::from_sith(black_box(weighted)));
    });

    if let Ok(threshold) = SigningThreshold::from_sith(weighted) {
        criterion.bench_function("threshold_satisfy_weighted_7_keys", |bencher| {
            bencher.iter(|| threshold.is_satisfied_by(black_box(&[0, 2, 3, 5, 6])));
        });
    }
}

criterion_group!(benches, benchmark_threshold);
criterion_main!(benches);
