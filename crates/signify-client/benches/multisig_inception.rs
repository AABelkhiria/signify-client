//! Microbenchmark for multisig group inception.
//!
//! This workflow is dominated by things measured elsewhere — the key derivation Roadmap 4.3's
//! benchmark covers and the round trips the transport pays for. What is *this module's* cost is the
//! decision work between them, and that is what is measured here.
//!
//! Three things.
//!
//! **The delivery list**, from two members to sixty-four. A proposal names one addressee and
//! reaches every other participant, so this runs once per proposal and grows with the group.
//!
//! **Reading a proposal**, which is what a joining member does before it rebuilds anything: decode
//! the listing, classify it, and take the values the group identifier is a digest over. Every field
//! it reads wrong is a group it will never converge on.
//!
//! **The attribute block**, which is the three labels a proposal writes, at each group size.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_client::endpoint::exchanges::{
    ClassifiedExchange, GROUP_LABEL, ROTATION_MEMBERS_LABEL, SIGNING_MEMBERS_LABEL,
};
use signify_client::multisig::{INCEPTION_ROUTE, INCEPTION_SLOT, delivery_list};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::serialization::{Sad, SadValue};
use signify_types::api::MultisigExchangeResource;

const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

/// `count` distinct member prefixes, the first of them the local one.
///
/// The trailing character varies, which keeps every one a valid prefix of the same code.
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

fn prefixes(count: usize) -> Vec<IdentifierPrefix> {
    members(count)
        .iter()
        .filter_map(|member| IdentifierPrefix::from_qb64(member).ok())
        .collect()
}

fn quoted(members: &[String]) -> String {
    members
        .iter()
        .map(|member| format!("\"{member}\""))
        .collect::<Vec<String>>()
        .join(",")
}

/// One inception proposal naming `count` members, of the shape the agent answers with.
fn proposal(count: usize) -> String {
    let names = quoted(&members(count));
    let event = format!(
        r#"{{"v":"KERI10JSON000_","t":"icp","d":"{GROUP}","i":"{GROUP}","s":"0","kt":"2","k":["DAA"],"nt":"2","n":["EAA"],"bt":"2","b":[],"c":[],"a":[]}}"#
    );
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{GROUP}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{INCEPTION_ROUTE}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}","{SIGNING_MEMBERS_LABEL}":[{names}],"{ROTATION_MEMBERS_LABEL}":[{names}]}},"e":{{"d":"EEMB","{INCEPTION_SLOT}":{event}}}}}"#
    );
    format!(r#"[{{"exn":{exn},"paths":{{}},"groupName":"multisig","memberName":"member1","sender":"{LOCAL}"}}]"#)
}

fn benchmark_multisig_inception(criterion: &mut Criterion) {
    for count in [2_usize, 8, 64] {
        let participants = prefixes(count);
        let local = participants.first().cloned();
        criterion.bench_function(&format!("multisig_delivery_list_{count}"), |bencher| {
            bencher.iter(|| {
                local
                    .as_ref()
                    .is_some_and(|local| delivery_list(black_box(local), black_box(&participants)).is_ok())
            });
        });

        let document = proposal(count);
        criterion.bench_function(&format!("multisig_read_proposal_{count}"), |bencher| {
            bencher.iter(|| {
                let listing: Vec<MultisigExchangeResource> =
                    serde_json::from_str(black_box(&document)).unwrap_or_default();
                listing
                    .first()
                    .is_some_and(|entry| ClassifiedExchange::try_from(entry).is_ok())
            });
        });

        let names = members(count);
        criterion.bench_function(&format!("multisig_attribute_block_{count}"), |bencher| {
            bencher.iter(|| {
                let mut payload = Sad::new();
                let encoded: Vec<SadValue> = names.iter().map(SadValue::text).collect();
                payload.insert(GROUP_LABEL, black_box(GROUP).to_owned()).is_ok()
                    && payload
                        .insert(SIGNING_MEMBERS_LABEL, SadValue::Array(encoded.clone()))
                        .is_ok()
                    && payload.insert(ROTATION_MEMBERS_LABEL, SadValue::Array(encoded)).is_ok()
            });
        });
    }
}

criterion_group!(benches, benchmark_multisig_inception);
criterion_main!(benches);
