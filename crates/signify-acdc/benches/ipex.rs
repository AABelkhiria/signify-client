//! Microbenchmark for IPEX message construction.
//!
//! Every IPEX message costs one exchange derivation plus one signature. A grant costs more than
//! the rest put together: it derives a SAID over the embed block as well as over the message, and
//! that block holds three complete artifacts — so the message it hashes is several times larger
//! than any other route's, and it transposes three attachment groups on top.
//!
//! The keeper uses the **ephemeral** derivation cost. A production keeper spends 64 MiB of Argon2
//! per key, which happens once in setup either way; what is timed is signing with a key in hand.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use signify_acdc::credential::{Credential, CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use signify_acdc::ipex::{Disclosure, IpexEnvelope, admit, agree, apply, grant, offer};
use signify_acdc::issuance::issue_credential;
use signify_keri::event::Timestamp;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::manager::{DerivationCost, IdentifierKeeper, KeeperFactory};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};
use signify_types::api::KeyState;

const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const RECIPIENT: &str = "ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k";
const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const DIGEST: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

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

fn key_state() -> Option<KeyState> {
    serde_json::from_value(serde_json::json!({
        "i": ISSUER,
        "s": "0",
        "p": "",
        "d": DIGEST,
        "f": "0",
        "dt": STAMP,
        "et": "icp",
        "kt": "1",
        "k": ["DAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C"],
        "nt": "1",
        "n": [DIGEST],
        "bt": "0",
        "b": [],
        "c": [],
        "ee": {"s": "0", "d": DIGEST, "br": [], "ba": []},
        "di": "",
    }))
    .ok()
}

fn benchmark_ipex(criterion: &mut Criterion) {
    let (Some(keeper), Some(credential), Some(state)) = (keeper(), credential(), key_state()) else {
        return;
    };
    let (Ok(sender), Ok(recipient), Ok(schema), Ok(prior), Ok(stamp)) = (
        IdentifierPrefix::from_qb64(SENDER),
        IdentifierPrefix::from_qb64(RECIPIENT),
        Said::from_qb64(SCHEMA),
        Said::from_qb64(DIGEST),
        STAMP.parse::<Timestamp>(),
    ) else {
        return;
    };
    let Ok(envelope) = IpexEnvelope::new(sender, recipient, "", stamp) else {
        return;
    };
    let Ok(artifacts) = issue_credential(keeper.as_ref(), &state, credential.clone()) else {
        return;
    };
    let Ok(disclosure) = Disclosure::from_issuance(&artifacts) else {
        return;
    };

    // The cheapest route: a payload of two fields and one signature.
    criterion.bench_function("ipex_agree", |bencher| {
        bencher.iter(|| agree(keeper.as_ref(), black_box(&envelope), black_box(prior)).is_ok());
    });
    criterion.bench_function("ipex_admit", |bencher| {
        bencher.iter(|| admit(keeper.as_ref(), black_box(&envelope), black_box(prior)).is_ok());
    });

    // An apply adds the schema and an attribute block.
    let mut attributes = Sad::new();
    if attributes
        .insert("LEI", SadValue::text("254900OPPU84GM83MG36"))
        .is_err()
    {
        return;
    }
    criterion.bench_function("ipex_apply", |bencher| {
        bencher.iter_batched(
            || attributes.clone(),
            |attributes| apply(keeper.as_ref(), black_box(&envelope), black_box(schema), attributes).is_ok(),
            BatchSize::SmallInput,
        );
    });

    // An offer embeds the credential, which adds a second SAID derivation over the embed block.
    criterion.bench_function("ipex_offer", |bencher| {
        bencher.iter(|| offer(keeper.as_ref(), black_box(&envelope), black_box(&credential), None).is_ok());
    });

    // A grant embeds three artifacts and transposes three attachment groups.
    criterion.bench_function("ipex_grant", |bencher| {
        bencher.iter(|| grant(keeper.as_ref(), black_box(&envelope), black_box(&disclosure), None).is_ok());
    });

    // Assembling the disclosure is a separate cost, paid once per credential rather than per
    // message: three attachment encodings over artifacts already in hand.
    criterion.bench_function("ipex_disclosure_from_issuance", |bencher| {
        bencher.iter(|| Disclosure::from_issuance(black_box(&artifacts)).is_ok());
    });
}

criterion_group!(benches, benchmark_ipex);
criterion_main!(benches);
