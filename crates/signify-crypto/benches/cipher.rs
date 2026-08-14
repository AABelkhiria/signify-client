//! Microbenchmarks for ciphertext construction and hostile-input parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_crypto::cipher::{Ciphertext, CiphertextKind, SEED_CIPHERTEXT_RAW_SIZE};

fn benchmark_ciphertext(criterion: &mut Criterion) {
    let raw = [0x5a_u8; SEED_CIPHERTEXT_RAW_SIZE];
    criterion.bench_function("ciphertext_seed_construct_92_bytes", |bencher| {
        bencher.iter(|| Ciphertext::from_raw(CiphertextKind::QualifiedSeed, black_box(&raw)));
    });

    if let Ok(ciphertext) = Ciphertext::from_raw(CiphertextKind::QualifiedSeed, &raw)
        && let Ok(qb64) = ciphertext.qb64()
    {
        criterion.bench_function("ciphertext_seed_parse_qb64_124_chars", |bencher| {
            bencher.iter(|| Ciphertext::from_qb64(black_box(&qb64)));
        });
    }
}

criterion_group!(benches, benchmark_ciphertext);
criterion_main!(benches);
