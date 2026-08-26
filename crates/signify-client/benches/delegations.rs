//! Microbenchmark for the delegation endpoint.
//!
//! One method, one address, one three-field block. There is nothing here that grows with anything,
//! which is itself worth measuring: a delegator approving a hundred delegates pays this cost a
//! hundred times, and what it is dominated by should be the signature rather than this module.
//!
//! Three things.
//!
//! **The two addresses**, which carry one caller value each and differ in a single segment.
//!
//! **The seal**, built and written — the whole payload of the call.
//!
//! **A batch of seals**, from one to sixty-four, because the event format permits more than one and
//! a delegator with several pending delegates could anchor them together.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_client::endpoint::delegations::{DELEGATION_SEGMENT, InceptionSeal};
use signify_client::endpoint::identifiers::{EVENTS_SEGMENT, IDENTIFIERS_SEGMENT};
use signify_http::request::ResourcePath;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};

const DELEGATE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

/// `count` distinct delegate prefixes, varying the last two characters.
fn delegates(count: usize) -> Vec<String> {
    let alphabet: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let letter = |index: usize| {
        alphabet
            .get(index % alphabet.len())
            .map_or('A', |byte| char::from(*byte))
    };
    (0..count)
        .map(|index| {
            if index == 0 {
                return DELEGATE.to_owned();
            }
            let mut prefix: String = DELEGATE.chars().take(DELEGATE.chars().count() - 2).collect();
            prefix.push(letter(index / alphabet.len()));
            prefix.push(letter(index));
            prefix
        })
        .collect()
}

fn seal(delegate: &str) -> Option<InceptionSeal> {
    Some(InceptionSeal::new(
        IdentifierPrefix::from_qb64(delegate).ok()?,
        delegate.parse::<Said>().ok()?,
    ))
}

fn benchmark_delegations(criterion: &mut Criterion) {
    for segment in [DELEGATION_SEGMENT, EVENTS_SEGMENT] {
        criterion.bench_function(&format!("delegations_path_{segment}"), |bencher| {
            bencher.iter(|| {
                ResourcePath::builder()
                    .segment(IDENTIFIERS_SEGMENT)
                    .segment(black_box("delegator"))
                    .segment(segment)
                    .build()
                    .is_ok()
            });
        });
    }

    criterion.bench_function("delegations_seal", |bencher| {
        bencher.iter(|| {
            seal(black_box(DELEGATE))
                .as_ref()
                .and_then(|seal| seal.to_sad().ok())
                .is_some()
        });
    });

    for count in [1_usize, 8, 64] {
        let prefixes = delegates(count);
        criterion.bench_function(&format!("delegations_seal_batch_{count}"), |bencher| {
            bencher.iter(|| {
                let seals: Vec<SadValue> = prefixes
                    .iter()
                    .filter_map(|delegate| seal(delegate))
                    .filter_map(|seal| seal.to_sad().ok())
                    .map(SadValue::Map)
                    .collect();
                let mut anchored = Sad::new();
                anchored.insert("a", SadValue::Array(black_box(seals))).is_ok()
            });
        });
    }
}

criterion_group!(benches, benchmark_delegations);
criterion_main!(benches);
