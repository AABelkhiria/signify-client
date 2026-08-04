//! Microbenchmarks for repeated CESR derivation-code lookup and classification.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_cesr::code::{CodeFamily, DerivationCode};

fn benchmark_code_tables(criterion: &mut Criterion) {
    for code in ["A", "0I", "1AAJ", "9AAB"] {
        criterion.bench_function(&format!("derivation_code_parse_{code}"), |bencher| {
            bencher.iter(|| black_box(code).parse::<DerivationCode>());
        });
    }

    criterion.bench_function("derivation_code_metadata", |bencher| {
        bencher.iter(|| black_box(DerivationCode::X25519_CIPHER_SEED).size());
    });
    criterion.bench_function("derivation_code_family", |bencher| {
        bencher.iter(|| black_box(DerivationCode::BLAKE3_256).belongs_to(black_box(CodeFamily::Digest)));
    });
}

criterion_group!(benches, benchmark_code_tables);
criterion_main!(benches);
