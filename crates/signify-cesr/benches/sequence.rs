//! Microbenchmarks for fixed-width sequence construction and attacker-facing parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_cesr::sequence::SequenceNumber;

fn benchmark_sequence(criterion: &mut Criterion) {
    criterion.bench_function("sequence_construct_u128_max", |bencher| {
        bencher.iter(|| SequenceNumber::new(black_box(u128::MAX)));
    });

    let qb64 = "0AD_____________________";
    criterion.bench_function("sequence_parse_qb64_24_chars", |bencher| {
        bencher.iter(|| SequenceNumber::from_qb64(black_box(qb64)));
    });

    if let Ok(qb2) = SequenceNumber::new(u128::MAX).qb2() {
        criterion.bench_function("sequence_parse_qb2_18_bytes", |bencher| {
            bencher.iter(|| SequenceNumber::from_qb2(black_box(&qb2)));
        });
    }
}

criterion_group!(benches, benchmark_sequence);
criterion_main!(benches);
