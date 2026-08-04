//! Microbenchmarks for SAD-path construction, composition, and attacker-facing parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_cesr::path::SadPath;

fn benchmark_path(criterion: &mut Criterion) {
    criterion.bench_function("path_construct_four_components", |bencher| {
        bencher.iter(|| SadPath::from_components(black_box(["e", "credential", "a", "0"])));
    });

    if let Ok(path) = SadPath::from_components(["e", "credential", "a", "0"])
        && let Ok(qb64) = path.qb64()
    {
        criterion.bench_function("path_parse_qb64_qualified", |bencher| {
            bencher.iter(|| SadPath::from_qb64(black_box(&qb64)));
        });
    }

    if let (Ok(root), Ok(tail)) = (
        SadPath::from_components(["e", "credential"]),
        SadPath::from_components(["a", "0"]),
    ) {
        criterion.bench_function("path_root_four_components", |bencher| {
            bencher.iter(|| tail.root(black_box(&root)));
        });
    }

    let large_component = "B".repeat(16_380);
    criterion.bench_function("path_construct_first_large_16_kib", |bencher| {
        bencher.iter(|| SadPath::from_components(black_box([large_component.as_str()])));
    });
}

criterion_group!(benches, benchmark_path);
criterion_main!(benches);
