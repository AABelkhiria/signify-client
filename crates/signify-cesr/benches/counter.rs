//! Microbenchmarks for counter construction and attacker-facing parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_cesr::counter::{Counter, CounterCode, CounterVersion};

fn benchmark_counter(criterion: &mut Criterion) {
    criterion.bench_function("counter_construct_short", |bencher| {
        bencher.iter(|| Counter::new(black_box(CounterCode::CONTROLLER_INDEXED_SIGNATURES), black_box(5)));
    });

    let big_qb64 = "-0VAAAQA";
    criterion.bench_function("counter_parse_qb64_big_8_chars", |bencher| {
        bencher.iter(|| Counter::from_qb64(black_box(big_qb64)));
    });

    if let Ok(version) = CounterVersion::new(1, 2, 3)
        && let Ok(counter) = Counter::protocol_stack(version)
        && let Ok(qb2) = counter.qb2()
    {
        criterion.bench_function("counter_parse_qb2_protocol_6_bytes", |bencher| {
            bencher.iter(|| Counter::from_qb2(black_box(&qb2)));
        });
    }
}

criterion_group!(benches, benchmark_counter);
criterion_main!(benches);
