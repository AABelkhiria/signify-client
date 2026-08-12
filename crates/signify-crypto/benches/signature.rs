//! Microbenchmarks for unindexed-signature construction and parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_crypto::signature::{SignatureAlgorithm, UnindexedSignature};

const ED25519_QB64: &str = "0BB43fz0GkIj6INCvq732d7FBZxt3Gw08S1mak9TeRgStsrxiUPEKcMAP9SlJrt6sg5h2pEvTshrYz56rM8IIzcO";
const RAW: [u8; 64] = [0x5a; 64];

fn benchmark_signature(criterion: &mut Criterion) {
    criterion.bench_function("signature_construct_ed25519_raw_64_bytes", |bencher| {
        bencher.iter(|| UnindexedSignature::from_raw(SignatureAlgorithm::Ed25519, black_box(&RAW)));
    });
    criterion.bench_function("signature_parse_ed25519_qb64_88_chars", |bencher| {
        bencher.iter(|| UnindexedSignature::from_qb64(black_box(ED25519_QB64)));
    });
}

criterion_group!(benches, benchmark_signature);
criterion_main!(benches);
