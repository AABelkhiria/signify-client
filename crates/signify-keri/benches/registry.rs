//! Microbenchmark for registry inception.
//!
//! A registry inception is one event build — a serialization for sizing, a BLAKE3-256 digest, and
//! a final serialization — with no key derivation, so this measures the pure construction cost a
//! client pays per registry.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::registry::RegistryInceptionBuilder;

const ISSUER: &str = "ECJIoBpEcCWMzvquk861dXP8JJZ-vbmJczlDR-NYcE3g";
const NONCE: &str = "AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s";

fn benchmark_inception(criterion: &mut Criterion) {
    let Ok(issuer) = IdentifierPrefix::from_qb64(ISSUER) else {
        return;
    };

    criterion.bench_function("registry_incept", |bencher| {
        bencher.iter(|| {
            RegistryInceptionBuilder::new(black_box(issuer.clone()), black_box(NONCE))
                .build()
                .is_ok()
        });
    });

    // Three backers with the defaulted threshold, which is the witnessed shape.
    let backers: Vec<String> = (0..3).map(|index| format!("backer-{index}")).collect();
    criterion.bench_function("registry_incept_three_backers", |bencher| {
        bencher.iter(|| {
            RegistryInceptionBuilder::new(black_box(issuer.clone()), black_box(NONCE))
                .backers(black_box(backers.clone()))
                .build()
                .is_ok()
        });
    });
}

criterion_group!(benches, benchmark_inception);
criterion_main!(benches);
