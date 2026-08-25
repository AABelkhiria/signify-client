//! Microbenchmark for the escrows endpoint family.
//!
//! One method, so the numbers worth having are about the **answer**. This is the third unpaged
//! listing in the crate — after Roadmap 7.3's contacts and, with a caller-chosen window, 7.5's
//! notifications — and it is the one whose entries are whole KERI messages: each carries an
//! attribute block the schema types `unknown`, so the per-entry cost is dominated by material the
//! *agent* chooses the size of rather than by the request.
//!
//! Inputs: the two address shapes; listings of 1, 32, and 256 escrowed replies, at a small
//! attribute block and at one of 32 fields.
//!
//! As everywhere in this crate, the addressing is negligible beside one signed request, whose
//! signature alone Roadmap 6.4 measured at ~25 µs. The decode is not, which is the point.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_client::endpoint::escrows::{ESCROWS_SEGMENT, PRESENTATION_REQUEST_ROUTE, REPLY_SEGMENT, ROUTE_PARAMETER};
use signify_http::request::ResourcePath;
use signify_types::api::ReplyRecord;

const DIGEST: &str = "EKpb2k5qGRzqhqpgTCL8wWyMb9Mv7HNZlS69ck7_3KDK";
const CONTROLLER: &str = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose";

/// An attribute block of `fields` labels, of the shape an authorization reply carries.
fn attributes(fields: usize) -> String {
    use std::fmt::Write;

    let mut block = format!(r#""cid":"{CONTROLLER}","role":"agent""#);
    for index in 0..fields {
        let _ = write!(block, r#","field{index}":"value {index}""#);
    }
    format!("{{{block}}}")
}

/// A listing of `count` escrowed replies, each carrying `fields` extra attributes.
fn listing(count: usize, fields: usize) -> String {
    let block = attributes(fields);
    let entries: Vec<String> = (0..count)
        .map(|index| {
            format!(
                r#"{{"v":"KERI10JSON00013f_","t":"rpy","d":"{DIGEST}","dt":"2023-11-14T22:13:2{}.123000+00:00","r":"{PRESENTATION_REQUEST_ROUTE}","a":{block}}}"#,
                index % 10
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

fn benchmark_escrows(criterion: &mut Criterion) {
    // Addressing: the two shapes this family has.
    criterion.bench_function("escrows_listing_path_unfiltered", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(ESCROWS_SEGMENT)
                .segment(REPLY_SEGMENT)
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("escrows_listing_path_filtered", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(ESCROWS_SEGMENT)
                .segment(REPLY_SEGMENT)
                .optional_parameter(ROUTE_PARAMETER, black_box(Some(PRESENTATION_REQUEST_ROUTE)))
                .build()
                .is_ok()
        });
    });

    // Decoding: what a listing costs as the escrow backlog grows, at two block sizes.
    for count in [1_usize, 32, 256] {
        let small = listing(count, 0);
        criterion.bench_function(&format!("escrows_decode_{count}_small_block"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Vec<ReplyRecord>>(black_box(&small)).is_ok());
        });
        let wide = listing(count, 32);
        criterion.bench_function(&format!("escrows_decode_{count}_wide_block"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Vec<ReplyRecord>>(black_box(&wide)).is_ok());
        });
    }

    // The refusal path: a listing whose last entry is not a reply at all. Worth measuring beside
    // the accepting path, because an agent chooses where the bad entry sits.
    let mut rejected = listing(256, 0);
    rejected.truncate(rejected.len().saturating_sub(1));
    rejected.push_str(r#",{"v":"KERI10JSON00013f_","t":"icp","d":"E","dt":"x","r":"/x","a":{}}]"#);
    criterion.bench_function("escrows_refuse_256_last_entry", |bencher| {
        bencher.iter(|| serde_json::from_str::<Vec<ReplyRecord>>(black_box(&rejected)).is_err());
    });
}

criterion_group!(benches, benchmark_escrows);
criterion_main!(benches);
