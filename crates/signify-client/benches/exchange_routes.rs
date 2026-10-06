//! Microbenchmark for the exchange route table and the message classifiers.
//!
//! Classification sits on the read path of every group workflow Roadmap 8.2 through 8.4 will build:
//! a member polls for notifications, reads each proposal, and has to decide what it is before it
//! can do anything. So the numbers worth having are what deciding costs, and how it compares with
//! what the reference spends on the same decision — which is one string comparison and nothing
//! else.
//!
//! Three things are measured.
//!
//! **The route lookup**, which is the whole of the reference's `assert*`: a linear scan over
//! thirteen constants.
//!
//! **The classification**, which is the lookup plus the work the reference does not do — decoding
//! the embed the route promises and the attribute block beside it. Measured for the largest
//! proposal (an issuance, three whole messages) and the smallest (an interaction).
//!
//! **The refusal**, because an agent chooses what it sends: a route whose embed belongs to another
//! route, and a route the table does not name at all.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keria_types::api::ExchangeRecord;
use signify_client::endpoint::exchanges::{ClassifiedExchange, ExchangeRoute, MultisigRoute};

const MEMBER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const GROUP: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

const ANCHOR: &str = r#"{"v":"KERI10JSON000_","t":"ixn","d":"EANC","i":"EGRP","s":"2","p":"EIXN","a":[]}"#;
const ACDC: &str = r#"{"v":"ACDC10JSON000_","d":"ECRED","i":"EISSUER","ri":"EREG","s":"ESCHEMA","a":{"d":"EATTR","i":"EHOLDER","dt":"2023-11-14T22:13:20.123000+00:00"}}"#;
const ISSUANCE: &str = r#"{"v":"KERI10JSON000_","t":"iss","d":"EISS","i":"ECRED","s":"0","ri":"EREG","dt":"2023-11-14T22:13:20.123000+00:00"}"#;
const INTERACTION: &str = r#"{"v":"KERI10JSON000_","t":"ixn","d":"EIXN","i":"EGRP","s":"1","p":"EICP","a":[]}"#;

/// One message on `route`, with the given attribute and embed blocks.
fn message(route: &str, attributes: &str, embeds: &str) -> Option<ExchangeRecord> {
    let document = format!(
        r#"{{"v":"KERI10JSON000100_","t":"exn","d":"EEXN","i":"{MEMBER}","rp":"{MEMBER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{attributes},"e":{embeds}}}"#
    );
    serde_json::from_str(&document).ok()
}

fn group_block() -> String {
    format!(r#"{{"gid":"{GROUP}","smids":["{MEMBER}"],"rmids":["{MEMBER}"]}}"#)
}

fn benchmark_exchange_routes(criterion: &mut Criterion) {
    // The lookup, which is the whole of what the reference's assertion does.
    criterion.bench_function("exchange_route_lookup_first", |bencher| {
        bencher.iter(|| ExchangeRoute::parse(black_box("/multisig/icp")).is_some());
    });
    criterion.bench_function("exchange_route_lookup_last", |bencher| {
        bencher.iter(|| ExchangeRoute::parse(black_box("/ipex/admit")).is_some());
    });
    criterion.bench_function("exchange_route_lookup_absent", |bencher| {
        bencher.iter(|| ExchangeRoute::parse(black_box("/challenge/response")).is_none());
    });

    // Classification: the lookup plus the check the reference does not make.
    let Some(issuance) = message(
        "/multisig/iss",
        &group_block(),
        &format!(r#"{{"d":"EEMB","acdc":{ACDC},"iss":{ISSUANCE},"anc":{ANCHOR}}}"#),
    ) else {
        return;
    };
    criterion.bench_function("exchange_classify_issuance", |bencher| {
        bencher.iter(|| ClassifiedExchange::classify(black_box(&issuance)).is_ok());
    });

    let Some(interaction) = message(
        "/multisig/ixn",
        &group_block(),
        &format!(r#"{{"d":"EEMB","ixn":{INTERACTION}}}"#),
    ) else {
        return;
    };
    criterion.bench_function("exchange_classify_interaction", |bencher| {
        bencher.iter(|| ClassifiedExchange::classify(black_box(&interaction)).is_ok());
    });

    let Some(admit) = message("/ipex/admit", "{}", "{}") else {
        return;
    };
    criterion.bench_function("exchange_classify_empty_ipex_step", |bencher| {
        bencher.iter(|| ClassifiedExchange::classify(black_box(&admit)).is_ok());
    });

    // The refusals, both of which an agent can choose to send.
    let Some(mismatched) = message(
        "/multisig/icp",
        &group_block(),
        &format!(r#"{{"d":"EEMB","ixn":{INTERACTION}}}"#),
    ) else {
        return;
    };
    criterion.bench_function("exchange_classify_mismatched_embed", |bencher| {
        bencher.iter(|| ClassifiedExchange::classify(black_box(&mismatched)).is_err());
    });

    let Some(unnamed) = message("/challenge/response", r#"{"words":["shell"]}"#, "{}") else {
        return;
    };
    criterion.bench_function("exchange_classify_unnamed_route", |bencher| {
        bencher.iter(|| ClassifiedExchange::classify(black_box(&unnamed)).is_ok());
    });

    // Every route in turn, which is what a member polling a busy group does.
    let proposals: Vec<ExchangeRecord> = MultisigRoute::ALL
        .into_iter()
        .filter_map(|route| {
            let embeds = match route {
                MultisigRoute::Issuance => format!(r#"{{"d":"EEMB","acdc":{ACDC},"iss":{ISSUANCE},"anc":{ANCHOR}}}"#),
                _ => format!(r#"{{"d":"EEMB","ixn":{INTERACTION}}}"#),
            };
            message(route.as_str(), &group_block(), &embeds)
        })
        .collect();
    criterion.bench_function("exchange_classify_eight_proposals", |bencher| {
        bencher.iter(|| {
            proposals
                .iter()
                .filter(|record| ClassifiedExchange::classify(black_box(record)).is_ok())
                .count()
        });
    });
}

criterion_group!(benches, benchmark_exchange_routes);
criterion_main!(benches);
