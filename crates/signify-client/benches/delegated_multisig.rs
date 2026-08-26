//! Microbenchmark for a group approving a delegation.
//!
//! What is particular to this round is that **the payload is a list**, and the list is what the
//! reference truncates. So the numbers worth having are about reading a proposal as its seal count
//! grows: a delegator group with many pending delegates is exactly the case where dropping all but
//! the first matters, and it should not be the case where reading them all costs anything notable.
//!
//! Two things, each from one seal to sixty-four: **reading a proposal** — decode plus Roadmap 8.1's
//! classification plus taking the seals out — and **building the seal list** a proposal anchors.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_client::endpoint::delegations::InceptionSeal;
use signify_client::endpoint::exchanges::{
    ClassifiedExchange, GROUP_LABEL, ROTATION_MEMBERS_LABEL, SIGNING_MEMBERS_LABEL,
};
use signify_client::multisig::{INTERACTION_ROUTE, INTERACTION_SLOT};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::Sad;
use signify_types::api::MultisigExchangeResource;

const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const DELEGATEE: &str = "EDNA2EUYd0HbW_4NU1kMv01LK2zqAWK6o7VkIQsK_LyR";

/// `count` distinct delegatee prefixes, varying the last two characters.
fn delegatees(count: usize) -> Vec<String> {
    let alphabet: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let letter = |index: usize| {
        alphabet
            .get(index % alphabet.len())
            .map_or('A', |byte| char::from(*byte))
    };
    (0..count)
        .map(|index| {
            if index == 0 {
                return DELEGATEE.to_owned();
            }
            let mut prefix: String = DELEGATEE.chars().take(DELEGATEE.chars().count() - 2).collect();
            prefix.push(letter(index / alphabet.len()));
            prefix.push(letter(index));
            prefix
        })
        .collect()
}

fn seals(count: usize) -> Vec<Sad> {
    delegatees(count)
        .iter()
        .filter_map(|delegatee| {
            let built = InceptionSeal::new(
                IdentifierPrefix::from_qb64(delegatee).ok()?,
                delegatee.parse::<Said>().ok()?,
            );
            built.to_sad().ok()
        })
        .collect()
}

/// One delegation-approval proposal anchoring `count` seals.
fn proposal(count: usize) -> String {
    let written: Vec<String> = seals(count)
        .iter()
        .filter_map(|seal| seal.to_json_bytes().ok())
        .filter_map(|bytes| String::from_utf8(bytes).ok())
        .collect();
    let event = format!(
        r#"{{"v":"KERI10JSON000_","t":"ixn","d":"EIXNDIGEST","i":"{GROUP}","s":"1","p":"{GROUP}","a":[{seals}]}}"#,
        seals = written.join(",")
    );
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{GROUP}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{INTERACTION_ROUTE}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":["{LOCAL}"],"{ROTATION_MEMBERS_LABEL}":["{LOCAL}"]}},"e":{{"d":"EEMB","{INTERACTION_SLOT}":{event}}}}}"#
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"delegators","memberName":"delegator1","sender":"{LOCAL}"}}]"#)
}

fn benchmark_delegated_multisig(criterion: &mut Criterion) {
    for count in [1_usize, 8, 64] {
        let document = proposal(count);
        criterion.bench_function(&format!("delegated_multisig_read_proposal_{count}"), |bencher| {
            bencher.iter(|| {
                let listing: Vec<MultisigExchangeResource> =
                    serde_json::from_str(black_box(&document)).unwrap_or_default();
                listing
                    .first()
                    .and_then(|entry| ClassifiedExchange::try_from(entry).ok())
                    .and_then(|classified| classified.as_multisig().map(|proposal| proposal.proposed.digest.len()))
                    .is_some()
            });
        });

        let prefixes = delegatees(count);
        criterion.bench_function(&format!("delegated_multisig_build_seals_{count}"), |bencher| {
            bencher.iter(|| {
                prefixes
                    .iter()
                    .filter_map(|delegatee| {
                        let built = InceptionSeal::new(
                            IdentifierPrefix::from_qb64(black_box(delegatee)).ok()?,
                            delegatee.parse::<Said>().ok()?,
                        );
                        built.to_sad().ok()
                    })
                    .count()
            });
        });
    }
}

criterion_group!(benches, benchmark_delegated_multisig);
criterion_main!(benches);
