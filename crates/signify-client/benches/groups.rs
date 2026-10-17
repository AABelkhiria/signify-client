//! Microbenchmark for the group endpoint family.
//!
//! This family is where a multisig member spends its polling time: read the proposals the agent
//! holds, classify each, decide. The reads dominate, which is why the numbers here are about the
//! **listing** rather than the two writes — those are called nowhere in the reference outside its
//! own unit test.
//!
//! Three things are measured.
//!
//! **The three addresses**, which carry one caller value each.
//!
//! **The listing**, from one proposal to sixty-four, decoded and then classified — because a member
//! polling a busy group pays both costs together and the route table's check is the larger of the
//! two.
//!
//! **The two bodies**, which are the smallest requests any family in this crate sends.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::MultisigExchangeResource;
use signify_client::endpoint::exchanges::{ClassifiedExchange, MULTISIG_TOPIC};
use signify_client::endpoint::groups::{JOIN_SEGMENT, MULTISIG_SEGMENT, REQUEST_SEGMENT};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_http::request::ResourcePath;

const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const GROUP: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const MEMBER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

/// A listing of `count` inception proposals, of the shape the agent answers with.
fn listing(count: usize) -> String {
    let inception = r#"{"v":"KERI10JSON000_","t":"icp","d":"EICP","i":"EGRP","s":"0","kt":"2","k":["DAA","DBB"],"nt":"2","n":["EAA","EBB"],"bt":"0","b":[],"c":[],"a":[]}"#;
    let entries: Vec<String> = (0..count)
        .map(|index| {
            format!(
                r#"{{"exn":{{"v":"KERI10JSON000_","t":"exn","d":"{SAID}","i":"{MEMBER}","rp":"{GROUP}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"/multisig/icp","q":{{}},"a":{{"gid":"{GROUP}","smids":["{MEMBER}"],"rmids":["{MEMBER}"]}},"e":{{"d":"EEMB","icp":{inception}}}}},"paths":{{}},"groupName":"multisig","memberName":"member{index}","sender":"{MEMBER}"}}"#
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

fn benchmark_groups(criterion: &mut Criterion) {
    criterion.bench_function("groups_read_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(MULTISIG_SEGMENT)
                .segment(REQUEST_SEGMENT)
                .segment(black_box(SAID))
                .build()
                .is_ok()
        });
    });
    for action in [REQUEST_SEGMENT, JOIN_SEGMENT] {
        criterion.bench_function(&format!("groups_write_path_{action}"), |bencher| {
            bencher.iter(|| {
                ResourcePath::builder()
                    .segment(IDENTIFIERS_SEGMENT)
                    .segment(black_box("aid1"))
                    .segment(MULTISIG_SEGMENT)
                    .segment(action)
                    .build()
                    .is_ok()
            });
        });
    }

    // The listing: decoding alone, then decoding plus the classification a member actually needs.
    for count in [1_usize, 8, 64] {
        let document = listing(count);
        criterion.bench_function(&format!("groups_decode_{count}_proposals"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Vec<MultisigExchangeResource>>(black_box(&document)).is_ok());
        });
        criterion.bench_function(&format!("groups_decode_and_classify_{count}_proposals"), |bencher| {
            bencher.iter(|| {
                serde_json::from_str::<Vec<MultisigExchangeResource>>(black_box(&document))
                    .map(|entries| {
                        entries
                            .iter()
                            .filter(|entry| ClassifiedExchange::try_from(*entry).is_ok())
                            .count()
                    })
                    .unwrap_or_default()
            });
        });
    }

    // The two bodies, which are the smallest this crate sends.
    criterion.bench_function("groups_request_body", |bencher| {
        bencher.iter(|| {
            let mut body = Sad::new();
            let _ = body.insert("exn", SadValue::Map(Sad::new()));
            let _ = body.insert("sigs", SadValue::Array(vec![SadValue::text("AAB")]));
            let _ = body.insert("atc", String::new());
            body.to_json_bytes().is_ok()
        });
    });
    criterion.bench_function("groups_join_body", |bencher| {
        bencher.iter(|| {
            let mut body = Sad::new();
            let _ = body.insert("tpc", MULTISIG_TOPIC.to_owned());
            let _ = body.insert("rot", SadValue::Map(Sad::new()));
            let _ = body.insert("sigs", SadValue::Array(vec![SadValue::text("AAB")]));
            let _ = body.insert("gid", GROUP.to_owned());
            let _ = body.insert("smids", SadValue::Array(vec![SadValue::text(MEMBER)]));
            let _ = body.insert("rmids", SadValue::Array(vec![SadValue::text(MEMBER)]));
            body.to_json_bytes().is_ok()
        });
    });
}

criterion_group!(benches, benchmark_groups);
criterion_main!(benches);
