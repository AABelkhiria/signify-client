//! Microbenchmarks for ciphertext construction and hostile-input parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_crypto::{
    cipher::{Ciphertext, CiphertextKind, Encrypter, SEED_CIPHERTEXT_RAW_SIZE},
    signer::Signer,
    verifier::KeyTransferability,
};

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

    if let Ok(signer) = Signer::from_seed(&[0x68_u8; 32], KeyTransferability::Transferable) {
        criterion.bench_function("encrypter_ed25519_to_x25519", |bencher| {
            bencher.iter(|| Encrypter::from_verification_key(black_box(signer.verifier())));
        });

        if let Ok(encrypter) = Encrypter::from_verification_key(signer.verifier()) {
            let seed_qb64 = b"ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr";
            criterion.bench_function("encrypter_seal_qualified_seed_44_bytes", |bencher| {
                bencher.iter(|| encrypter.encrypt_seed_qb64(black_box(seed_qb64)));
            });
        }
    }
}

criterion_group!(benches, benchmark_ciphertext);
criterion_main!(benches);
