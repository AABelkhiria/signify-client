//! Microbenchmarks for habitat creation.
//!
//! `make_habitat` is one manager inception — an Argon2 pass per key — plus one complete event
//! construction, so this measures the whole cost of "create an identifier" as an edge client
//! experiences it. The ephemeral cost is measured alongside the low production tier so the Argon2
//! cost is separated from the composition around it.

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use signify_keys::identifier::{Habery, HabitatRequest};
use signify_keys::manager::DerivationCost;

fn registry(cost: DerivationCost) -> Option<Habery> {
    let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).ok()?;
    Habery::builder("signify").salt(salt).derivation_cost(cost).build().ok()
}

/// Measures habitat creation with the Argon2 cost minimized: the composition itself.
fn benchmark_ephemeral(criterion: &mut Criterion) {
    criterion.bench_function("make_habitat_ephemeral", |bencher| {
        bencher.iter_batched(
            || registry(DerivationCost::Ephemeral),
            |habery| habery.map(|mut habery| habery.make_habitat("test", HabitatRequest::default()).is_ok()),
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Measures habitat creation at the low production tier the reference hardcodes: two keys at
/// 64 MiB each, which dominates everything around them.
fn benchmark_production(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("production");
    group.sample_size(10);
    group.bench_function("make_habitat_low_tier", |bencher| {
        bencher.iter_batched(
            || registry(DerivationCost::Production),
            |habery| habery.map(|mut habery| habery.make_habitat("test", HabitatRequest::default()).is_ok()),
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, benchmark_ephemeral, benchmark_production);
criterion_main!(benches);
