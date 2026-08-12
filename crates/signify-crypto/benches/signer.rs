//! Microbenchmarks for secret-key construction and deterministic Ed25519 signing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_crypto::{
    signer::{SignaturePlacement, Signer},
    verifier::KeyTransferability,
};

const SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31,
];
const MESSAGE: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn benchmark_signer(criterion: &mut Criterion) {
    criterion.bench_function("signer_construct_ed25519_seed_32_bytes", |bencher| {
        bencher.iter(|| Signer::from_seed(black_box(&SEED), KeyTransferability::Transferable));
    });

    if let Ok(signer) = Signer::from_seed(&SEED, KeyTransferability::Transferable) {
        criterion.bench_function("signer_ed25519_unindexed_36_bytes", |bencher| {
            bencher.iter(|| signer.sign_unindexed(black_box(MESSAGE)));
        });
        criterion.bench_function("signer_ed25519_indexed_36_bytes", |bencher| {
            bencher.iter(|| signer.sign_indexed(black_box(MESSAGE), SignaturePlacement::both_lists(0)));
        });
    }
}

criterion_group!(benches, benchmark_signer);
criterion_main!(benches);
