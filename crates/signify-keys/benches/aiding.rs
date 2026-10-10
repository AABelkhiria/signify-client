//! Microbenchmarks for identifier-artifact construction.
//!
//! Each artifact is one keeper operation — an Argon2 pass per derived key — plus one event build
//! and one signature per key, so this measures what a client pays per identifier operation before
//! the network. The ephemeral cost is measured alongside the low production tier so the Argon2
//! cost is separated from the composition around it.

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keria_types::api::KeyState;
use signify_keys::identifier::{
    CreateAlgorithm, CreateIdentifierRequest, IdentifierArtifact, RotateIdentifierRequest, incept_identifier,
    interact_identifier, rotate_identifier,
};
use signify_keys::manager::{DerivationCost, IdentifierKeeper, KeeperFactory};

const PASSCODE: &str = "0123456789abcdefghijk";

fn request(cost: DerivationCost) -> CreateIdentifierRequest {
    CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some(PASSCODE.to_owned()),
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost,
    })
}

fn keeper(cost: DerivationCost) -> Option<Box<dyn IdentifierKeeper>> {
    let factory = KeeperFactory::new(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).ok()?);
    factory.create(request(cost).keeper_request(0).ok()?).ok()
}

fn state_of(artifact: &IdentifierArtifact) -> Option<KeyState> {
    let event: serde_json::Value = serde_json::from_slice(artifact.event.raw()).ok()?;
    serde_json::from_value(serde_json::json!({
        "i": event.get("i")?, "s": "0", "p": "", "d": event.get("d")?, "f": "0",
        "dt": "2023-12-01T10:05:25.062609+00:00", "et": "icp",
        "kt": event.get("kt")?, "k": event.get("k")?, "nt": event.get("nt")?, "n": event.get("n")?,
        "bt": "0", "b": [], "c": [],
        "ee": {"s": "0", "d": event.get("d")?, "br": [], "ba": []}, "di": ""
    }))
    .ok()
}

/// Measures each artifact with the Argon2 cost minimized: the composition itself.
fn benchmark_ephemeral(criterion: &mut Criterion) {
    criterion.bench_function("incept_identifier_ephemeral", |bencher| {
        bencher.iter_batched(
            || keeper(DerivationCost::Ephemeral),
            |keeper| {
                keeper.map(|mut keeper| incept_identifier(keeper.as_mut(), &request(DerivationCost::Ephemeral)).is_ok())
            },
            criterion::BatchSize::SmallInput,
        );
    });

    criterion.bench_function("interact_identifier_ephemeral", |bencher| {
        bencher.iter_batched(
            || {
                let mut keeper = keeper(DerivationCost::Ephemeral)?;
                let artifact = incept_identifier(keeper.as_mut(), &request(DerivationCost::Ephemeral)).ok()?;
                let state = state_of(&artifact)?;
                Some((keeper, state))
            },
            |setup| setup.map(|(keeper, state)| interact_identifier(keeper.as_ref(), &state, Vec::new()).is_ok()),
            criterion::BatchSize::SmallInput,
        );
    });

    criterion.bench_function("rotate_identifier_ephemeral", |bencher| {
        bencher.iter_batched(
            || {
                let mut keeper = keeper(DerivationCost::Ephemeral)?;
                let artifact = incept_identifier(keeper.as_mut(), &request(DerivationCost::Ephemeral)).ok()?;
                let state = state_of(&artifact)?;
                Some((keeper, state))
            },
            |setup| {
                setup.map(|(mut keeper, state)| {
                    rotate_identifier(keeper.as_mut(), &state, &RotateIdentifierRequest::default()).is_ok()
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Measures a creation at the low production tier the reference hardcodes.
fn benchmark_production(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("production");
    group.sample_size(10);
    group.bench_function("incept_identifier_low_tier", |bencher| {
        bencher.iter_batched(
            || keeper(DerivationCost::Production),
            |keeper| {
                keeper
                    .map(|mut keeper| incept_identifier(keeper.as_mut(), &request(DerivationCost::Production)).is_ok())
            },
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, benchmark_ephemeral, benchmark_production);
criterion_main!(benches);
