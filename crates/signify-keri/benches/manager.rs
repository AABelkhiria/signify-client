//! Microbenchmarks for key creation, inception, rotation, and signing.
//!
//! Every identifier operation an edge signer performs starts here: a salty derivation is one
//! Argon2 pass per key, which dominates everything around it, and signing runs once per event and
//! once per authenticated request. The temporary profile is measured alongside the low tier so the
//! Argon2 cost is separated from the bookkeeping it sits inside.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::salt::{KeyDerivationProfile, Salt, SecurityTier};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use signify_keri::manager::{
    InceptionRequest, KeyIndices, KeyManager, RotationRequest, SaltyKeyCreator, SignatureForm, Stem,
};

/// The encryption seed the pinned unit test uses.
const CRYPT_SEED: [u8; 32] = [
    104, 44, 35, 124, 138, 112, 34, 18, 196, 51, 116, 50, 166, 225, 24, 25, 240, 102, 50, 44, 121, 196, 194, 49, 64,
    245, 64, 21, 46, 162, 26, 207,
];

/// Measures the Argon2 derivation every salty key costs.
fn benchmark_creation(criterion: &mut Criterion) {
    let (Ok(salt), Ok(stem)) = (
        Salt::from_raw(b"0123456789abcdef", SecurityTier::Low),
        Stem::new("signify:aid"),
    ) else {
        return;
    };
    let creator = SaltyKeyCreator::new(&salt, stem);

    // One key at the temporary profile: the bookkeeping, with the Argon2 cost minimized.
    criterion.bench_function("derive_one_key_temporary", |bencher| {
        bencher.iter(|| {
            creator
                .create(
                    black_box(1),
                    KeyTransferability::Transferable,
                    KeyIndices::inception(0),
                    KeyDerivationProfile::Temporary,
                )
                .is_ok()
        });
    });

    // Three keys, which is what a small multisig member set costs.
    criterion.bench_function("derive_three_keys_temporary", |bencher| {
        bencher.iter(|| {
            creator
                .create(
                    black_box(3),
                    KeyTransferability::Transferable,
                    KeyIndices::inception(0),
                    KeyDerivationProfile::Temporary,
                )
                .is_ok()
        });
    });

    // The same key at the low production tier: 64 MiB and two Argon2 passes.
    criterion.bench_function("derive_one_key_low_tier", |bencher| {
        bencher.iter(|| {
            creator
                .create(
                    black_box(1),
                    KeyTransferability::Transferable,
                    KeyIndices::inception(0),
                    KeyDerivationProfile::Standard(SecurityTier::Low),
                )
                .is_ok()
        });
    });
}

/// Measures the operations a manager performs on top of derivation.
fn benchmark_operations(criterion: &mut Criterion) {
    let (Ok(stem), Ok(seed)) = (
        Stem::new("signify:aid"),
        Signer::from_seed(&CRYPT_SEED, KeyTransferability::NonTransferable),
    ) else {
        return;
    };

    // A whole inception: two key sets, two digests, and the state written for them.
    criterion.bench_function("incept_unencrypted", |bencher| {
        bencher.iter_batched(
            || {
                Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)
                    .ok()
                    .and_then(|salt| KeyManager::builder().salt(salt).build().ok())
            },
            |manager| {
                manager.is_some_and(|mut manager| {
                    manager
                        .incept(InceptionRequest {
                            stem: stem.clone(),
                            profile: KeyDerivationProfile::Temporary,
                            ..InceptionRequest::default()
                        })
                        .is_ok()
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // An inception that seals both key sets, which is what a randy or encrypted salty client pays.
    criterion.bench_function("incept_encrypted", |bencher| {
        bencher.iter_batched(
            || {
                Salt::from_raw(b"0123456789abcdef", SecurityTier::Low)
                    .ok()
                    .and_then(|salt| KeyManager::builder().salt(salt).build_encrypted(&seed).ok())
            },
            |manager| {
                manager.is_some_and(|mut manager| {
                    manager
                        .incept(InceptionRequest {
                            stem: stem.clone(),
                            profile: KeyDerivationProfile::Temporary,
                            ..InceptionRequest::default()
                        })
                        .is_ok()
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // A rotation, which derives one new key set and rewrites the state.
    criterion.bench_function("rotate_unencrypted", |bencher| {
        bencher.iter_batched(
            || {
                let salt = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).ok()?;
                let mut manager = KeyManager::builder().salt(salt).build().ok()?;
                let incepted = manager
                    .incept(InceptionRequest {
                        stem: stem.clone(),
                        profile: KeyDerivationProfile::Temporary,
                        ..InceptionRequest::default()
                    })
                    .ok()?;
                Some((manager, incepted.prefix))
            },
            |state| {
                state.is_some_and(|(mut manager, prefix)| {
                    manager
                        .rotate(RotationRequest {
                            profile: KeyDerivationProfile::Temporary,
                            ..RotationRequest::new(prefix)
                        })
                        .is_ok()
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Signing: one derivation to recover the key, then one Ed25519 signature.
    if let Ok(mut manager) = KeyManager::builder()
        .salt(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).unwrap_or_else(|_| salt_placeholder()))
        .build()
        && let Ok(incepted) = manager.incept(InceptionRequest {
            stem: stem.clone(),
            profile: KeyDerivationProfile::Temporary,
            ..InceptionRequest::default()
        })
    {
        let keys = vec![incepted.prefix];
        criterion.bench_function("sign_indexed_regenerating_the_key", |bencher| {
            bencher.iter(|| {
                manager
                    .sign(
                        black_box(b"event serialization"),
                        &keys,
                        &SignatureForm::IndexedByPosition,
                    )
                    .is_ok()
            });
        });
    }
}

/// Never reached; keeps the benchmark total without an `unwrap` on the hot path.
fn salt_placeholder() -> Salt {
    Salt::from_raw(b"0000000000000000", SecurityTier::Low).unwrap_or_else(|_| salt_placeholder())
}

/// Measures the keeper operations a client performs per identifier.
///
/// A salty keeper hardcodes the production Argon2 profile, so an inception or a rotation costs one
/// 64 MiB pass per key — which is what a deployed client actually pays. The ephemeral profile is
/// measured alongside it to separate the bookkeeping from the derivation.
fn benchmark_keepers(criterion: &mut Criterion) {
    use signify_keri::manager::keeper::salty::{SaltyKeeperConfig, SaltySource};
    use signify_keri::manager::{
        DerivationCost, IdentifierKeeper, KeeperFactory, KeeperRequest, KeeperRotation, RandyKeeperRequest,
        SaltyKeeper, SigningPurpose,
    };

    let Ok(salt) = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low) else {
        return;
    };
    let passcode = "0123456789abcdefghijk";

    for (label, cost) in [
        ("production", DerivationCost::Production),
        ("ephemeral", DerivationCost::Ephemeral),
    ] {
        criterion.bench_function(&format!("salty_keeper_incept_{label}"), |bencher| {
            bencher.iter(|| {
                SaltyKeeper::new(
                    &salt,
                    SaltySource::Passcode(passcode.to_owned()),
                    SaltyKeeperConfig {
                        transferability: KeyTransferability::Transferable,
                        profile: cost,
                        ..SaltyKeeperConfig::default()
                    },
                )
                .is_ok_and(|mut keeper| keeper.incept(KeyTransferability::Transferable).is_ok())
            });
        });
    }

    // Rotation and signing, measured on an already-built keeper.
    if let Ok(mut keeper) = SaltyKeeper::new(
        &salt,
        SaltySource::Passcode(passcode.to_owned()),
        SaltyKeeperConfig {
            transferability: KeyTransferability::Transferable,
            profile: DerivationCost::Ephemeral,
            ..SaltyKeeperConfig::default()
        },
    ) && keeper.incept(KeyTransferability::Transferable).is_ok()
    {
        criterion.bench_function("salty_keeper_sign_ephemeral", |bencher| {
            bencher.iter(|| {
                keeper
                    .sign(
                        black_box(b"event serialization"),
                        &SignatureForm::IndexedByPosition,
                        SigningPurpose::Current,
                    )
                    .is_ok()
            });
        });
        criterion.bench_function("salty_keeper_rotate_ephemeral", |bencher| {
            bencher.iter(|| keeper.rotate(KeeperRotation::to_keys(1)).is_ok());
        });
    }

    // A randy keeper seals every key it creates, so its cost is the sealed box rather than Argon2.
    let Ok(factory) = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).map(KeeperFactory::new) else {
        return;
    };
    criterion.bench_function("randy_keeper_incept_ephemeral", |bencher| {
        bencher.iter(|| {
            factory
                .create(KeeperRequest::Randy(RandyKeeperRequest {
                    current_count: 1,
                    next_count: 1,
                    transferability: KeyTransferability::Transferable,
                    profile: DerivationCost::Ephemeral,
                    ..RandyKeeperRequest::default()
                }))
                .is_ok_and(|mut keeper| keeper.incept(KeyTransferability::Transferable).is_ok())
        });
    });
}

criterion_group!(benches, benchmark_creation, benchmark_operations, benchmark_keepers);
criterion_main!(benches);
