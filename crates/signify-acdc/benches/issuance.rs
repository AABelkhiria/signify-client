//! Microbenchmark for credential issuance and revocation artifacts.
//!
//! Issuing a credential costs three BLAKE3-256 derivations, not one: the credential itself (two,
//! measured by the `credential` benchmark), then the transaction event, then the interaction event
//! anchoring it. Only the last two are measured here, plus the signature the anchor carries —
//! which is the one asymmetric operation in the whole path and, on evidence, the one that
//! dominates it.
//!
//! The keeper uses the **ephemeral** derivation cost. A production keeper spends 64 MiB of Argon2
//! per key, which would swamp everything else and is not what this measures; the key derivation
//! happens once in setup either way, and what is timed is signing with a key already in hand.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use signify_acdc::credential::{Credential, CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use signify_acdc::issuance::{IssuanceEvent, issue_credential};
use signify_acdc::revocation::RevocationEventBuilder;
use signify_acdc::transaction::{TransactionSeal, anchor, anchor_event};
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::manager::{DerivationCost, IdentifierKeeper, KeeperFactory};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_types::api::KeyState;

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const ISSUANCE: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

/// The QVI credential of the pinned single-signature vLEI suite.
fn credential() -> Option<Credential> {
    CredentialBuilder::new(
        IdentifierPrefix::from_qb64(ISSUER).ok()?,
        RegistryIdentifier::from_qb64(REGISTRY).ok()?,
        Said::from_qb64(SCHEMA).ok()?,
        CredentialAttributes::new(STAMP.parse().ok()?)
            .issuee(&IdentifierPrefix::from_qb64(HOLDER).ok()?)
            .ok()?
            .timestamp()
            .ok()?
            .text("LEI", "254900OPPU84GM83MG36")
            .ok()?,
    )
    .build()
    .ok()
}

/// A key state at position one, which is where an issuer that has just been incepted sits.
fn key_state() -> Option<KeyState> {
    serde_json::from_value(serde_json::json!({
        "i": ISSUER,
        "s": "1",
        "p": "",
        "d": ISSUANCE,
        "f": "0",
        "dt": STAMP,
        "et": "icp",
        "kt": "1",
        "k": ["DAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"],
        "nt": "1",
        "n": [ISSUANCE],
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": ISSUANCE, "br": [], "ba": []},
        "di": "",
    }))
    .ok()
}

/// A salty keeper at the ephemeral cost, whose key derivation happens once here rather than in a
/// timed section.
fn keeper() -> Option<Box<dyn IdentifierKeeper>> {
    let factory = KeeperFactory::new(Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).ok()?);
    let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some("0123456789abcdefghijk".to_owned()),
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Ephemeral,
    });
    factory.create(request.keeper_request(0).ok()?).ok()
}

fn benchmark_issuance(criterion: &mut Criterion) {
    let (Some(credential), Some(state), Some(keeper)) = (credential(), key_state(), keeper()) else {
        return;
    };
    let (Ok(registry), Ok(prior)) = (RegistryIdentifier::from_qb64(REGISTRY), Said::from_qb64(ISSUANCE)) else {
        return;
    };
    let Ok(issuance) = IssuanceEvent::for_credential(&credential) else {
        return;
    };

    // One transaction event: an assembly, a BLAKE3-256 derivation, and a serialization.
    criterion.bench_function("issuance_event", |bencher| {
        bencher.iter(|| IssuanceEvent::for_credential(black_box(&credential)).is_ok());
    });

    // The same, plus the one field a revocation adds.
    let Ok(timestamp) = STAMP.parse::<signify_keri::event::Timestamp>() else {
        return;
    };
    criterion.bench_function("revocation_event", |bencher| {
        bencher.iter_batched(
            || RevocationEventBuilder::new(credential.said(), registry.clone(), prior, timestamp.clone()),
            |builder| black_box(builder).build().is_ok(),
            BatchSize::SmallInput,
        );
    });

    // The anchor without a signature: the interaction event alone.
    let seal = issuance.seal();
    criterion.bench_function("anchor_event", |bencher| {
        bencher.iter(|| anchor_event(black_box(&state), black_box(&seal)).is_ok());
    });

    // The anchor with its signature, which is where the asymmetric cost lands.
    criterion.bench_function("anchor_signed", |bencher| {
        bencher.iter(|| anchor(keeper.as_ref(), black_box(&state), black_box(&seal)).is_ok());
    });

    // The whole issuance path from a finished credential: transaction event, anchor, signature.
    criterion.bench_function("issue_credential", |bencher| {
        bencher.iter_batched(
            || credential.clone(),
            |credential| issue_credential(keeper.as_ref(), black_box(&state), credential).is_ok(),
            BatchSize::SmallInput,
        );
    });

    // Both attachments, which are pure encoding and should be nearly free beside the rest.
    criterion.bench_function("credential_attachment", |bencher| {
        bencher.iter(|| black_box(&issuance).credential_attachment().is_ok());
    });
    let anchor_seal = TransactionSeal::new(issuance.credential(), 1, issuance.said());
    criterion.bench_function("transaction_seal", |bencher| {
        bencher.iter(|| black_box(&anchor_seal).to_sad().is_ok());
    });
}

criterion_group!(benches, benchmark_issuance);
criterion_main!(benches);
