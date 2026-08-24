//! Microbenchmark for the identifier endpoint family.
//!
//! Three costs matter here and they differ by four orders of magnitude, which is the point of
//! measuring them together. Addressing a resource and decoding a record are free beside the
//! client's own ~25 µs signature (Roadmap 6.4). **Deriving an identifier's keys is not**: a salty
//! creation runs Argon2 at the reference's production profile, and a caller who does not know that
//! will put it on a UI thread.
//!
//! Inputs: one identifier record of the shape KERIA returns, one alias needing percent-encoding,
//! and one long-running operation answer.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_client::endpoint::identifiers::{
    EVENTS_SEGMENT, IDENTIFIER_RANGE_UNIT, IDENTIFIERS_SEGMENT, IdentifierUpdate,
};
use signify_crypto::salt::{Salt, SecurityTier};
use signify_crypto::verifier::KeyTransferability;
use signify_http::request::{ItemRange, RangeUnit, ResourcePath};
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, incept_identifier};
use signify_keri::manager::{DerivationCost, KeeperFactory};
use signify_types::api::{AcceptedHab, Hab, UntypedOperation};

const ALIAS: &str = "aid1";
const AWKWARD_ALIAS: &str = "a name with ñ!";
const PASSCODE: &str = "0123456789abcdefghijk";

/// One accepted identifier record, in the field order a KERIA response carries.
const RECORD: &str = r#"{"name":"aid1","prefix":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","icp_dt":"2021-06-27T21:26:21.233257+00:00","state":{"vn":[1,0],"i":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","s":"0","p":"","d":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","f":"0","dt":"2021-06-27T21:26:21.233257+00:00","et":"icp","kt":"1","k":["DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9"],"nt":"1","n":["EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc"],"bt":"0","b":[],"c":[],"ee":{"s":"0","d":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","br":[],"ba":[]},"di":""},"transferable":true,"windexes":[],"salty":{"tier":"low","sxlt":"0AAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pidx":0,"kidx":0,"stem":"signify:aid","dcode":"E","icodes":["A"],"ncodes":["A"],"transferable":true}}"#;

/// The answer a submission comes back with.
const OPERATION: &str = r#"{"name":"witness.ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK.0","metadata":{"pre":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","sn":0},"done":false,"error":null}"#;

fn benchmark_identifiers(criterion: &mut Criterion) {
    // Addressing a resource: the three shapes this family builds.
    criterion.bench_function("identifiers_record_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(IDENTIFIERS_SEGMENT)
                .segment(black_box(ALIAS))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("identifiers_record_path_encoding", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(IDENTIFIERS_SEGMENT)
                .segment(black_box(AWKWARD_ALIAS))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("identifiers_events_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(IDENTIFIERS_SEGMENT)
                .segment(black_box(ALIAS))
                .segment(EVENTS_SEGMENT)
                .build()
                .is_ok()
        });
    });

    // The one header this family sends.
    let Ok(unit) = RangeUnit::new(IDENTIFIER_RANGE_UNIT) else {
        return;
    };
    criterion.bench_function("identifiers_range_header", |bencher| {
        bencher.iter(|| black_box(ItemRange::DEFAULT).header_value(&unit));
    });

    // Reading an agent's answers: one record, and the operation a submission returns.
    criterion.bench_function("identifiers_decode_record", |bencher| {
        bencher.iter(|| serde_json::from_str::<Hab>(black_box(RECORD)).is_ok());
    });
    criterion.bench_function("identifiers_decode_operation", |bencher| {
        bencher.iter(|| serde_json::from_str::<UntypedOperation>(black_box(OPERATION)).is_ok());
    });

    // Re-encoding a record, which a group creation does for its local member.
    let Ok(record) = serde_json::from_str::<AcceptedHab>(RECORD) else {
        return;
    };
    criterion.bench_function("identifiers_encode_record", |bencher| {
        bencher.iter(|| serde_json::to_vec(black_box(&record)).is_ok());
    });

    // Writing an update body, the smallest one this family sends.
    criterion.bench_function("identifiers_update_body", |bencher| {
        bencher.iter(|| serde_json::to_vec(&black_box(IdentifierUpdate::rename("aid2")).name).is_ok());
    });

    // What a creation actually costs. The keeper is where the time goes: Argon2 at the reference's
    // production profile, sixty-four mebibytes a pass. The ephemeral profile is measured beside it
    // so the ratio is visible; a keeper built that way cannot be stored, so it is not what a real
    // creation pays.
    let Ok(salt) = Salt::from_qb64(&format!("0AA{PASSCODE}"), SecurityTier::Low) else {
        return;
    };
    let factory = KeeperFactory::new(salt);
    for (name, cost) in [
        ("identifiers_incept_ephemeral", DerivationCost::Ephemeral),
        ("identifiers_incept_production", DerivationCost::Production),
    ] {
        criterion.bench_function(name, |bencher| {
            bencher.iter(|| {
                let request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
                    passcode: Some(PASSCODE.to_owned()),
                    tier: SecurityTier::Low,
                    current_count: 1,
                    next_count: 1,
                    cost: black_box(cost),
                });
                request
                    .keeper_request(0)
                    .ok()
                    .and_then(|keeper_request| factory.create(keeper_request).ok())
                    .and_then(|mut keeper| incept_identifier(keeper.as_mut(), &request).ok())
                    .is_some()
            });
        });
    }

    // Keeps the transferability type reachable from this benchmark's inputs.
    let _ = black_box(KeyTransferability::Transferable);
}

criterion_group!(benches, benchmark_identifiers);
criterion_main!(benches);
