//! Microbenchmark for a group's registry, issuance, and revocation rounds.
//!
//! These are the largest messages the multisig tree sends: an issuance proposal carries a whole
//! credential, its transaction event, and the key event anchoring it. What a joining member pays to
//! **read** one is therefore the number worth having — and it is the cost the reference avoids by
//! not reading at all.
//!
//! Three proposals, at a credential with two, sixteen, and sixty-four attributes: reading each
//! (decode plus the route table's classification), beside the registry and revocation rounds whose
//! messages do not grow.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keria_types::api::MultisigExchangeResource;
use signify_client::endpoint::exchanges::{ClassifiedExchange, GROUP_LABEL};
use signify_client::multisig::{
    ANCHOR_SLOT, ISSUANCE_ROUTE, ISSUANCE_SLOT, REGISTRY_ROUTE, REGISTRY_SLOT, REVOCATION_ROUTE, REVOCATION_SLOT,
    TRANSACTION_SLOT,
};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const REGISTRY: &str = "EJBglnT4bORqW6oF87S050gj5i1qBQSHwTj3bLPyMpbX";
const CREDENTIAL: &str = "ECk3MhIQkFtytQZCiAKKEAA94Y9oL8OtDTINpzsI8JSg";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const ANCHOR: &str = r#"{"v":"KERI10JSON000_","t":"ixn","d":"EANC","i":"EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk","s":"1","p":"EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk","a":[]}"#;

/// A credential attribute block with `count` fields beyond the two every one carries.
fn attributes(count: usize) -> String {
    let extra: Vec<String> = (0..count)
        .map(|index| format!(r#""field{index}":"5493001KJTIIGC8Y1R17""#))
        .collect();
    let mut fields = vec![
        format!(r#""i":"{PEER}""#),
        r#""dt":"2023-11-14T22:13:20.123000+00:00""#.to_owned(),
    ];
    fields.extend(extra);
    format!("{{{}}}", fields.join(","))
}

fn proposal(route: &str, embeds: &str) -> String {
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}"}},"e":{{"d":"EEMB",{embeds}}}}}"#
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#)
}

fn issuance(count: usize) -> String {
    let embeds = format!(
        r#""{ISSUANCE_SLOT}":{{"v":"ACDC10JSON000_","d":"{CREDENTIAL}","i":"{GROUP}","ri":"{REGISTRY}","s":"{SCHEMA}","a":{attributes}}},"{TRANSACTION_SLOT}":{{"v":"KERI10JSON000_","t":"iss","d":"EISS","i":"{CREDENTIAL}","s":"0","ri":"{REGISTRY}","dt":"2023-11-14T22:13:20.123000+00:00"}},"{ANCHOR_SLOT}":{ANCHOR}"#,
        attributes = attributes(count)
    );
    proposal(ISSUANCE_ROUTE, &embeds)
}

fn registry() -> String {
    let embeds = format!(
        r#""{REGISTRY_SLOT}":{{"v":"KERI10JSON000_","t":"vcp","d":"{REGISTRY}","i":"{REGISTRY}","ii":"{GROUP}","s":"0","c":[],"bt":"0","b":[],"n":"AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s"}},"{ANCHOR_SLOT}":{ANCHOR}"#
    );
    proposal(REGISTRY_ROUTE, &embeds)
}

fn revocation() -> String {
    let embeds = format!(
        r#""{REVOCATION_SLOT}":{{"v":"KERI10JSON000_","t":"rev","d":"EREV","i":"{CREDENTIAL}","s":"1","ri":"{REGISTRY}","p":"EISS","dt":"2023-11-14T22:13:20.123000+00:00"}},"{ANCHOR_SLOT}":{ANCHOR}"#
    );
    proposal(REVOCATION_ROUTE, &embeds)
}

fn read(document: &str) -> bool {
    let listing: Vec<MultisigExchangeResource> = serde_json::from_str(document).unwrap_or_default();
    listing
        .first()
        .is_some_and(|entry| ClassifiedExchange::try_from(entry).is_ok())
}

fn benchmark_multisig_credentials(criterion: &mut Criterion) {
    for count in [2_usize, 16, 64] {
        let document = issuance(count);
        criterion.bench_function(&format!("multisig_read_issuance_{count}"), |bencher| {
            bencher.iter(|| read(black_box(&document)));
        });
    }

    let registry = registry();
    criterion.bench_function("multisig_read_registry", |bencher| {
        bencher.iter(|| read(black_box(&registry)));
    });

    let revocation = revocation();
    criterion.bench_function("multisig_read_revocation", |bencher| {
        bencher.iter(|| read(black_box(&revocation)));
    });
}

criterion_group!(benches, benchmark_multisig_credentials);
criterion_main!(benches);
