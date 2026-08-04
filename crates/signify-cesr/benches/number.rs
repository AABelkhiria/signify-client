//! Microbenchmarks for exact-number construction and attacker-facing parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_cesr::number::CesrNumber;

fn benchmark_number(criterion: &mut Criterion) {
    criterion.bench_function("number_construct_u128_max", |bencher| {
        bencher.iter(|| CesrNumber::new(black_box(u128::MAX)));
    });

    let qb64 = "0AD_____________________";
    criterion.bench_function("number_parse_qb64_huge_24_chars", |bencher| {
        bencher.iter(|| CesrNumber::from_qb64(black_box(qb64)));
    });

    if let Ok(qb2) = CesrNumber::new(u128::MAX).qb2() {
        criterion.bench_function("number_parse_qb2_huge_18_bytes", |bencher| {
            bencher.iter(|| CesrNumber::from_qb2(black_box(&qb2)));
        });
    }
}

criterion_group!(benches, benchmark_number);
criterion_main!(benches);
