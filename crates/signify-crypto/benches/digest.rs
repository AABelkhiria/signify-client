//! Microbenchmarks for digest derivation, verification, and hostile-input parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_crypto::digest::{Digest, DigestAlgorithm};

fn benchmark_digest(criterion: &mut Criterion) {
    let serialization = [0x5a_u8; 1_024];
    criterion.bench_function("digest_blake3_256_1_kib", |bencher| {
        bencher.iter(|| Digest::derive(DigestAlgorithm::Blake3_256, black_box(&serialization)));
    });

    let digest = Digest::derive(DigestAlgorithm::Blake3_256, &serialization);
    criterion.bench_function("digest_verify_blake3_256_1_kib", |bencher| {
        bencher.iter(|| digest.verify(black_box(&serialization)));
    });

    if let Ok(qb64) = digest.qb64() {
        criterion.bench_function("digest_parse_qb64_44_chars", |bencher| {
            bencher.iter(|| Digest::from_qb64(black_box(&qb64)));
        });
    }
}

criterion_group!(benches, benchmark_digest);
criterion_main!(benches);
