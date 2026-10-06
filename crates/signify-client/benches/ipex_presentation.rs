//! Microbenchmark for reading one step of a disclosure conversation.
//!
//! Every method here answers a step that arrived, so what a caller pays is the cost of **reading**
//! it: decoding the message, classifying it through Roadmap 8.1's table, and taking out the SAID
//! the answer chains to. That is the cost the reference avoids by taking a bare string from a
//! waiter and building on it unchecked.
//!
//! Four things are measured: reading an apply, an agree, and a grant — the largest step, which
//! carries a whole credential — and turning an apply into the credential filter it asks for, at
//! two, sixteen, and sixty-four requested attributes.

use std::fmt::Write as _;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keria_types::api::ExchangeResource;
use signify_acdc::ipex::IpexRoute;
use signify_client::presentation::{ReceivedStep, requested_credentials};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SAID: &str = "EDgvqnAQWAks1nXM1WD8kXRAan4ZkdoGAhP9_UtkGfFg";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const CREDENTIAL: &str = "EGdeVjXib7lVynr1NAddi1YTO2BCU5oi_I5DT69n9zJd";
const REGISTRY: &str = "EJBglnT4bORqW6oF87S050gj5i1qBQSHwTj3bLPyMpbX";

/// An attribute block with `count` requested values.
fn requested(count: usize) -> String {
    let mut written = String::new();
    for index in 0..count {
        if index > 0 {
            written.push(',');
        }
        let _ = write!(written, r#""field{index}":"value{index}""#);
    }
    written
}

/// One IPEX step as the agent returns it.
fn document(route: IpexRoute, attributes: &str, embeds: &str) -> String {
    format!(
        r#"{{"exn":{{"v":"KERI10JSON000100_","t":"exn","d":"{SAID}","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{attributes},"e":{embeds}}},"pathed":{{}}}}"#,
        route = route.as_str()
    )
}

fn apply(count: usize) -> String {
    let block = format!(r#"{{"m":"","s":"{SCHEMA}","a":{{{}}}}}"#, requested(count));
    document(IpexRoute::Apply, &block, "{}")
}

fn agree() -> String {
    document(IpexRoute::Agree, r#"{"m":""}"#, "{}")
}

fn grant() -> String {
    let embeds = format!(
        r#"{{"d":"EEMB","acdc":{{"v":"ACDC10JSON000100_","d":"{CREDENTIAL}","i":"{LOCAL}","ri":"{REGISTRY}","s":"{SCHEMA}","a":{{"i":"{PEER}","LEI":"5493001KJTIIGC8Y1R17","dt":"2023-11-14T22:13:20.123000+00:00"}}}},"iss":{{"v":"KERI10JSON000100_","t":"iss","d":"EISS","i":"{CREDENTIAL}","s":"0","ri":"{REGISTRY}","dt":"2023-11-14T22:13:20.123000+00:00"}},"anc":{{"v":"KERI10JSON000100_","t":"ixn","d":"EANC","i":"{LOCAL}","s":"1","p":"{LOCAL}","a":[]}}}}"#
    );
    document(IpexRoute::Grant, r#"{"m":""}"#, &embeds)
}

/// Decodes and classifies one step, which is what answering it costs before anything is built.
fn read(text: &str) -> Option<ReceivedStep> {
    let resource: ExchangeResource = serde_json::from_str(text).ok()?;
    ReceivedStep::of("0AAnote", &resource).ok()
}

fn benchmarks(criterion: &mut Criterion) {
    for (label, text) in [
        ("ipex_read_apply", apply(2)),
        ("ipex_read_agree", agree()),
        ("ipex_read_grant", grant()),
    ] {
        criterion.bench_function(label, |bencher| {
            bencher.iter(|| black_box(read(black_box(&text))).is_some());
        });
    }

    // And what a holder pays to turn an apply into the query that finds the credential.
    for count in [2usize, 16, 64] {
        let text = apply(count);
        let Some(step) = read(&text) else {
            continue;
        };
        criterion.bench_function(&format!("ipex_requested_credentials_{count}"), |bencher| {
            bencher.iter(|| black_box(requested_credentials(black_box(&step))).is_ok());
        });
    }
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
