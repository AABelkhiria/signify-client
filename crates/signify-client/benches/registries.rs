//! Microbenchmark for the registry endpoint family.
//!
//! `create` is the most expensive call in the crate after connecting: it derives the issuer's keys
//! to sign, builds two events, and writes a body carrying both. What is worth measuring is the
//! split between the derivation — which dominates everything — and the event construction and body
//! assembly this family actually adds.
//!
//! It is also where the reference's doubled keeper resolution shows up: upstream, `create` resolves
//! the issuer's keeper to sign and `createFromEvents` resolves it again to write its parameters,
//! which for a salty identifier is two Argon2 derivations per registry. This port resolves it once.
//!
//! Inputs: one issuer prefix, one pinned nonce, and backer sets of zero to sixteen.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_protocol::event::ConfigurationTrait;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::registry::RegistryInceptionBuilder;
use keri_protocol::serialization::Sad;
use keria_types::api::{Registry, RegistryOperation};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::registries::{CreateRegistryRequest, REGISTRIES_SEGMENT, RegistryBacking};
use signify_http::request::ResourcePath;

const ISSUER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const NONCE: &str = "0ACDEyMzQ1Njc4OWxtbm9wcXJzdHV2";
const REGISTRY: &str = "EJ1TxRlqdIeonxEd8aYwA_HI22ACwqEUrfpL8Y20qHKQ";

const REGISTRY_RECORD: &str = r#"{"name":"vLEI","regk":"EJ1TxRlqdIeonxEd8aYwA_HI22ACwqEUrfpL8Y20qHKQ","pre":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","state":{"vn":[1,0],"i":"EJ1TxRlqdIeonxEd8aYwA_HI22ACwqEUrfpL8Y20qHKQ","s":"0","d":"EJ1TxRlqdIeonxEd8aYwA_HI22ACwqEUrfpL8Y20qHKQ","ii":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","dt":"2021-06-27T21:26:21.233257+00:00","et":"vcp","bt":"0","b":[],"c":["NB"]}}"#;

const REGISTRY_OPERATION: &str = r#"{"name":"registry.EJ1TxRlqdIeonxEd8aYwA_HI22ACwqEUrfpL8Y20qHKQ","metadata":{"pre":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","depends":{"name":"witness.ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK.1","metadata":{"pre":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","sn":1},"done":false},"anchor":{"pre":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","sn":1,"d":"EANCHOR"}},"done":false}"#;

fn benchmark_registries(criterion: &mut Criterion) {
    let Ok(issuer) = IdentifierPrefix::from_qb64(ISSUER) else {
        return;
    };

    // Addressing: the collection both `list` and `create` use, and the member a rename addresses.
    criterion.bench_function("registries_collection_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(IDENTIFIERS_SEGMENT)
                .segment(black_box("issuer"))
                .segment(REGISTRIES_SEGMENT)
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("registries_member_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(IDENTIFIERS_SEGMENT)
                .segment(black_box("issuer"))
                .segment(REGISTRIES_SEGMENT)
                .segment(black_box("vLEI"))
                .build()
                .is_ok()
        });
    });

    // Building the registry inception, unbacked and then with growing backer sets. This is the
    // one event this family constructs that no other does.
    criterion.bench_function("registries_incept_unbacked", |bencher| {
        bencher.iter(|| {
            RegistryInceptionBuilder::new(issuer.clone(), black_box(NONCE))
                .configuration(vec![ConfigurationTrait::NoBackers])
                .build()
                .is_ok()
        });
    });
    for count in [1_usize, 4, 16] {
        let backers: Vec<String> = (0..count).map(|index| format!("B{index:043}")).collect();
        criterion.bench_function(&format!("registries_incept_backed_{count}"), |bencher| {
            bencher.iter(|| {
                RegistryInceptionBuilder::new(issuer.clone(), NONCE)
                    .backers(black_box(backers.clone()))
                    .backer_threshold(1)
                    .build()
                    .is_ok()
            });
        });
    }

    // The seal that anchors a registry, which names its identifier twice.
    criterion.bench_function("registries_anchor_seal", |bencher| {
        bencher.iter(|| {
            let mut seal = Sad::new();
            seal.insert("i", black_box(REGISTRY).to_owned())
                .and_then(|()| seal.insert("s", "0".to_owned()))
                .and_then(|()| seal.insert("d", REGISTRY.to_owned()))
                .and_then(|()| seal.to_json_bytes())
                .is_ok()
        });
    });

    // The rename body, which is the smallest one this family sends.
    criterion.bench_function("registries_rename_body", |bencher| {
        bencher.iter(|| {
            let mut body = Sad::new();
            body.insert("name", black_box("renamed").to_owned())
                .and_then(|()| body.to_json_bytes())
                .is_ok()
        });
    });

    // Building a request, which is free beside everything else and is measured to show it.
    criterion.bench_function("registries_request", |bencher| {
        bencher.iter(|| {
            CreateRegistryRequest::new(black_box("issuer"), black_box("vLEI"))
                .with_backing(RegistryBacking::None)
                .with_nonce(NONCE)
                .registry
                .len()
        });
    });

    // Reading the agent's answers.
    criterion.bench_function("registries_decode_record", |bencher| {
        bencher.iter(|| serde_json::from_str::<Registry>(black_box(REGISTRY_RECORD)).is_ok());
    });
    criterion.bench_function("registries_decode_operation", |bencher| {
        bencher.iter(|| serde_json::from_str::<RegistryOperation>(black_box(REGISTRY_OPERATION)).is_ok());
    });
}

criterion_group!(benches, benchmark_registries);
criterion_main!(benches);
