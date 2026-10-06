//! Microbenchmark for rotating a passcode over the identifiers it moves.
//!
//! Roadmap 4.5's own benchmark measures a rotation with **no** identifiers, which is the only shape
//! the reference's test suite ever runs. The number that matters to a client is the other one: what
//! it costs to move every managed identifier's key material to a new passcode, since each one is
//! opened, re-derived, checked against its reported key state, and sealed again.
//!
//! Measured at one, eight, and thirty-two identifiers, at the ephemeral derivation cost so the
//! per-identifier work is visible rather than buried under Argon2 — and once with the production
//! cost at a single identifier, so the two are comparable. Planning is measured rather than
//! applying, because planning is where all the work is.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::cipher::Encrypter;
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keria_types::api::{AcceptedHab, Hab};
use signify_keri::controller::{Controller, ControllerOptions};
use signify_keri::manager::DerivationCost;

const PASSCODE: &str = "0123456789abcdefghijk";
const SECOND_PASSCODE: &str = "abcdefghijk0123456789";

fn controller(cost: DerivationCost) -> Option<Controller> {
    Controller::with_options(
        PASSCODE,
        SecurityTier::Low,
        ControllerOptions {
            derivation_cost: cost,
            ..ControllerOptions::default()
        },
    )
    .ok()
}

/// The encryption key the old passcode derives, at one cost.
fn encrypter(cost: DerivationCost) -> Option<Encrypter> {
    let salt = Salt::from_qb64(&format!("0AA{PASSCODE}"), SecurityTier::Low).ok()?;
    let signer = salt
        .derive_signer_with_profile("", KeyTransferability::NonTransferable, cost.profile(SecurityTier::Low))
        .ok()?;
    Encrypter::from_verification_key(signer.verifier()).ok()
}

/// `count` randy identifiers, each holding one private key sealed to the old passcode.
///
/// Randy rather than salty because a randy identifier's keys need no derivation to verify, so the
/// measurement is the re-sealing rather than an Argon2 pass per identifier.
fn identifiers(count: usize, encrypter: &Encrypter) -> Option<Vec<AcceptedHab>> {
    let mut records = Vec::with_capacity(count);
    for index in 0..count {
        let mut seed = [0_u8; 32];
        seed[0] = u8::try_from(index % 251).ok()?;
        seed[1] = u8::try_from(index / 251).ok()?;
        let signer = Signer::from_seed(&seed, KeyTransferability::Transferable).ok()?;
        let public = signer.verifier().qb64().ok()?;
        let sealed = encrypter.encrypt_signer(&signer).ok()?.qb64().ok()?;
        let record: Hab = serde_json::from_value(serde_json::json!({
            "name": format!("aid{index}"),
            "prefix": public,
            "icp_dt": "2023-12-01T10:05:25.062609+00:00",
            "randy": { "prxs": [sealed], "nxts": [] },
            "state": {
                "i": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
                "s": "0", "p": "", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
                "f": "0", "dt": "2023-12-01T10:05:25.062609+00:00", "et": "icp",
                "kt": "1", "k": [public], "nt": "1",
                "n": ["ENBWnU8wNHqq9oqJIimWhxUtNDHReUXtiCwwtjg9zKY0"],
                "bt": "0", "b": [], "c": [],
                "ee": {"s": "0", "d": "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", "br": [], "ba": []},
                "di": ""
            }
        }))
        .ok()?;
        let Hab::Accepted(record) = record else {
            return None;
        };
        records.push(record);
    }
    Some(records)
}

fn benchmarks(criterion: &mut Criterion) {
    let Some(sealing) = encrypter(DerivationCost::Ephemeral) else {
        return;
    };

    for count in [1_usize, 8, 32] {
        let Some(records) = identifiers(count, &sealing) else {
            continue;
        };
        criterion.bench_function(&format!("rotate_passcode_{count}_identifiers"), |bencher| {
            bencher.iter_batched(
                || controller(DerivationCost::Ephemeral),
                |controller| {
                    controller.map(|controller| {
                        black_box(controller.plan_passcode_rotation(SECOND_PASSCODE, black_box(&records))).is_ok()
                    })
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    // And once at the production cost the reference always uses, so the Argon2 passes are visible: five
    // derivations per rotation here against the reference's four, for the encryption key that
    // actually moves.
    if let Some(sealing) = encrypter(DerivationCost::Production)
        && let Some(records) = identifiers(1, &sealing)
    {
        criterion.bench_function("rotate_passcode_production_cost", |bencher| {
            bencher.iter_batched(
                || controller(DerivationCost::Production),
                |controller| {
                    controller.map(|controller| {
                        black_box(controller.plan_passcode_rotation(SECOND_PASSCODE, black_box(&records))).is_ok()
                    })
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
