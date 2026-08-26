//! Microbenchmark for a multisig group's rotation and interaction rounds.
//!
//! What is particular to these two rounds, against Roadmap 8.3's inception, is that a member
//! **checks**: it reads a proposal, rebuilds the event, and compares what it built with what it was
//! shown. So the numbers worth having are the ones on that path.
//!
//! Three things.
//!
//! **Reading a proposal** — decode plus Roadmap 8.1's classification — at each group size, once for
//! a rotation and once for an interaction, because a rotation carries every member's key while an
//! interaction carries only its seals.
//!
//! **The check itself**, which is a digest comparison and should be free beside the read.
//!
//! **Reading the seals** an interaction anchors, from one to sixty-four, since that list is the
//! only part of an interaction that grows.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_client::endpoint::exchanges::{
    ClassifiedExchange, GROUP_LABEL, ROTATION_MEMBERS_LABEL, SIGNING_MEMBERS_LABEL,
};
use signify_client::multisig::{INTERACTION_ROUTE, INTERACTION_SLOT, ROTATION_ROUTE, ROTATION_SLOT};
use signify_types::api::MultisigExchangeResource;

const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const DIGEST: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const KEY: &str = "DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9";
const NEXT: &str = "EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc";

/// `count` distinct member prefixes, the first of them the local one.
fn members(count: usize) -> Vec<String> {
    let alphabet: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let letter = |index: usize| {
        alphabet
            .get(index % alphabet.len())
            .map_or('A', |byte| char::from(*byte))
    };
    (0..count)
        .map(|index| {
            if index == 0 {
                return LOCAL.to_owned();
            }
            let mut member: String = LOCAL.chars().take(LOCAL.chars().count() - 2).collect();
            member.push(letter(index / alphabet.len()));
            member.push(letter(index));
            member
        })
        .collect()
}

fn quoted(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<String>>()
        .join(",")
}

/// A rotation naming `count` members, of the shape a proposal embeds.
fn rotation(count: usize) -> String {
    let names = quoted(&members(count));
    let keys = quoted(&vec![KEY.to_owned(); count]);
    let digests = quoted(&vec![NEXT.to_owned(); count]);
    // `bt` as the bare number the reference writes for a non-zero threshold.
    let event = format!(
        r#"{{"v":"KERI10JSON000_","t":"rot","d":"{DIGEST}","i":"{GROUP}","s":"1","p":"{GROUP}","kt":"2","k":[{keys}],"nt":"2","n":[{digests}],"bt":3,"br":[],"ba":[],"a":[]}}"#
    );
    proposal(ROTATION_ROUTE, ROTATION_SLOT, &names, &event)
}

/// An interaction anchoring `count` seals.
fn interaction(count: usize) -> String {
    let names = quoted(&members(2));
    let seals: Vec<String> = (0..count)
        .map(|index| format!(r#"{{"i":"{GROUP}","s":"{index}","d":"{DIGEST}"}}"#))
        .collect();
    let event = format!(
        r#"{{"v":"KERI10JSON000_","t":"ixn","d":"{DIGEST}","i":"{GROUP}","s":"1","p":"{GROUP}","a":[{seals}]}}"#,
        seals = seals.join(",")
    );
    proposal(INTERACTION_ROUTE, INTERACTION_SLOT, &names, &event)
}

fn proposal(route: &str, slot: &str, names: &str, event: &str) -> String {
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{GROUP}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":[{names}],"{ROTATION_MEMBERS_LABEL}":[{names}]}},"e":{{"d":"EEMB","{slot}":{event}}}}}"#
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#)
}

fn read(document: &str) -> bool {
    let listing: Vec<MultisigExchangeResource> = serde_json::from_str(document).unwrap_or_default();
    listing
        .first()
        .is_some_and(|entry| ClassifiedExchange::try_from(entry).is_ok())
}

fn benchmark_multisig_events(criterion: &mut Criterion) {
    for count in [2_usize, 8, 64] {
        let rotation = rotation(count);
        criterion.bench_function(&format!("multisig_read_rotation_{count}"), |bencher| {
            bencher.iter(|| read(black_box(&rotation)));
        });

        let interaction = interaction(count);
        criterion.bench_function(&format!("multisig_read_interaction_{count}"), |bencher| {
            bencher.iter(|| read(black_box(&interaction)));
        });
    }

    // The check a joining member performs once it has rebuilt: two qualified digests compared.
    criterion.bench_function("multisig_proposal_check", |bencher| {
        bencher.iter(|| black_box(DIGEST) == black_box(GROUP));
    });
}

criterion_group!(benches, benchmark_multisig_events);
criterion_main!(benches);
