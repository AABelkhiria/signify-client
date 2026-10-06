//! Microbenchmarks for controller creation, delegation approval, and passcode rotation.
//!
//! A controller derives two keys per construction — an Argon2 pass each — and one more encryption
//! key plus four derivations per passcode rotation, so these measure the client's connect-time and
//! rotation-time costs. The ephemeral cost is measured alongside the low production tier so the
//! Argon2 cost is separated from the composition around it.

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::salt::SecurityTier;
use keria_types::api::KeyState;
use signify_keri::controller::{Agent, Controller, ControllerOptions};
use signify_keri::manager::DerivationCost;

const PASSCODE: &str = "0123456789abcdefghijk";
const SECOND_PASSCODE: &str = "abcdefghijk0123456789";

fn ephemeral() -> Option<Controller> {
    Controller::with_options(
        PASSCODE,
        SecurityTier::Low,
        ControllerOptions {
            derivation_cost: DerivationCost::Ephemeral,
            ..ControllerOptions::default()
        },
    )
    .ok()
}

fn agent() -> Option<Agent> {
    let state: KeyState = serde_json::from_value(serde_json::json!({
        "i": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
        "s": "0",
        "p": "",
        "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
        "f": "0",
        "dt": "2023-12-01T10:05:25.062609+00:00",
        "et": "dip",
        "kt": "1",
        "k": ["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE"],
        "nt": "1",
        "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", "br": [], "ba": []},
        "di": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"
    }))
    .ok()?;
    Agent::from_key_state(state).ok()
}

/// Measures the composition with the Argon2 cost minimized.
fn benchmark_ephemeral(criterion: &mut Criterion) {
    criterion.bench_function("controller_new_ephemeral", |bencher| {
        bencher.iter(|| ephemeral().is_some());
    });

    criterion.bench_function("approve_delegation_ephemeral", |bencher| {
        bencher.iter_batched(
            || (ephemeral(), agent()),
            |(controller, agent)| match (controller, agent) {
                (Some(mut controller), Some(agent)) => controller.approve_delegation(&agent).is_ok(),
                _ => false,
            },
            criterion::BatchSize::SmallInput,
        );
    });

    criterion.bench_function("rotate_passcode_ephemeral", |bencher| {
        bencher.iter_batched(
            ephemeral,
            |controller| controller.map(|mut controller| controller.rotate_passcode(SECOND_PASSCODE, &[]).is_ok()),
            criterion::BatchSize::SmallInput,
        );
    });
}

/// Measures controller creation at the low production tier the reference hardcodes: two keys at
/// 64 MiB each.
fn benchmark_production(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("production");
    group.sample_size(10);
    group.bench_function("controller_new_low_tier", |bencher| {
        bencher.iter(|| Controller::new(PASSCODE, SecurityTier::Low).is_ok());
    });
    group.finish();
}

criterion_group!(benches, benchmark_ephemeral, benchmark_production);
criterion_main!(benches);
