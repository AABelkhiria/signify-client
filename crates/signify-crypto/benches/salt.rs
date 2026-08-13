//! Microbenchmarks for deterministic Argon2id signer derivation.

use std::{hint::black_box, time::Duration};

use criterion::{Criterion, criterion_group, criterion_main};
use signify_crypto::{
    salt::{KeyDerivationProfile, Salt, SecurityTier},
    verifier::KeyTransferability,
};

const SALT: &[u8; 16] = b"0123456789abcdef";
const PATH: &str = "signify:controller00";

fn benchmark_salt(criterion: &mut Criterion) {
    if let Ok(salt) = Salt::from_raw(SALT, SecurityTier::Low) {
        criterion.bench_function("salt_argon2id_temporary_path_20_bytes", |bencher| {
            bencher.iter(|| {
                salt.derive_signer_with_profile(
                    black_box(PATH),
                    KeyTransferability::Transferable,
                    KeyDerivationProfile::Temporary,
                )
            });
        });

        let mut low = criterion.benchmark_group("salt_expensive");
        low.sample_size(10);
        low.measurement_time(Duration::from_secs(10));
        low.bench_function("argon2id_low_path_20_bytes_memory_64_mib", |bencher| {
            bencher.iter(|| salt.derive_signer(black_box(PATH), KeyTransferability::Transferable));
        });
        low.finish();
    }
}

criterion_group!(benches, benchmark_salt);
criterion_main!(benches);
