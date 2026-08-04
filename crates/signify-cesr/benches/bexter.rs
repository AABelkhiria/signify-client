//! Microbenchmarks for Base64-text conversion and attacker-facing parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_cesr::bexter::Base64Text;

fn benchmark_bexter(criterion: &mut Criterion) {
    let path = "-a-field0-1";
    criterion.bench_function("bexter_construct_path_11_chars", |bencher| {
        bencher.iter(|| Base64Text::new(black_box(path)));
    });

    if let Ok(value) = Base64Text::new(path)
        && let Ok(qb64) = value.qb64()
    {
        criterion.bench_function("bexter_parse_qb64_path", |bencher| {
            bencher.iter(|| Base64Text::from_qb64(black_box(&qb64)));
        });
    }

    let large = "B".repeat(16_381);
    criterion.bench_function("bexter_construct_large_16_kib", |bencher| {
        bencher.iter(|| Base64Text::new(black_box(&large)));
    });
}

criterion_group!(benches, benchmark_bexter);
criterion_main!(benches);
