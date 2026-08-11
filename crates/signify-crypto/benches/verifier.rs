//! Microbenchmarks for public-key parsing and detached-signature verification.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_crypto::verifier::VerificationKey;

const MESSAGE: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const ED25519_QB64: &str = "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
const ED25519_SIGNATURE: [u8; 64] = [
    120, 221, 252, 244, 26, 66, 35, 232, 131, 66, 190, 174, 247, 217, 222, 197, 5, 156, 109, 220, 108, 52, 241, 45,
    102, 106, 79, 83, 121, 24, 18, 182, 202, 241, 137, 67, 196, 41, 195, 0, 63, 212, 165, 38, 187, 122, 178, 14, 97,
    218, 145, 47, 78, 200, 107, 99, 62, 122, 172, 207, 8, 35, 55, 14,
];
const P256_QB64: &str = "1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ";
const P256_SAFE_SIGNATURE: [u8; 64] = [
    230, 114, 73, 144, 137, 97, 127, 30, 141, 40, 83, 123, 165, 18, 120, 1, 181, 58, 93, 215, 85, 94, 5, 20, 64, 8, 17,
    182, 30, 217, 77, 251, 86, 229, 180, 200, 13, 165, 96, 90, 147, 61, 229, 129, 189, 195, 185, 241, 16, 31, 60, 58,
    177, 254, 97, 129, 217, 85, 17, 120, 122, 77, 23, 205,
];

fn benchmark_verifier(criterion: &mut Criterion) {
    criterion.bench_function("verifier_parse_ed25519_qb64_44_chars", |bencher| {
        bencher.iter(|| VerificationKey::from_qb64(black_box(ED25519_QB64)));
    });
    criterion.bench_function("verifier_parse_p256_qb64_48_chars", |bencher| {
        bencher.iter(|| VerificationKey::from_qb64(black_box(P256_QB64)));
    });

    if let Ok(key) = VerificationKey::from_qb64(ED25519_QB64) {
        criterion.bench_function("verifier_ed25519_36_bytes", |bencher| {
            bencher.iter(|| key.verify(black_box(&ED25519_SIGNATURE), black_box(MESSAGE)));
        });
    }
    if let Ok(key) = VerificationKey::from_qb64(P256_QB64) {
        criterion.bench_function("verifier_p256_sha256_36_bytes", |bencher| {
            bencher.iter(|| key.verify(black_box(&P256_SAFE_SIGNATURE), black_box(MESSAGE)));
        });
    }
}

criterion_group!(benches, benchmark_verifier);
criterion_main!(benches);
