//! Microbenchmark for the OOBI endpoint family.
//!
//! Three things here are not measured elsewhere. The **addresses** are three distinct shapes where
//! every earlier family had one or two — a nested path with a query, a constant, and a path whose
//! last segment is optional. The **URL validation** is the only per-call check any family in this
//! crate performs on a caller's argument, and it is what makes an OOBI a URL rather than a string.
//! And the **answers** are the small end of the range: an OOBI listing and an end-role listing are
//! a few hundred bytes where a schema is kilobytes, which is worth having beside it.
//!
//! Inputs: a 44-character prefix, aliases of 4 and 64 characters, OOBI URLs of 22 and 512 bytes,
//! and listings of 1, 16, and 64 entries.
//!
//! Nothing here signs, derives a key, or reads a clock: those costs are the `lifecycle` benchmark's
//! and dwarf all of this. A resolution is one HTTP round trip whose real cost is the agent going
//! and fetching the URL.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_protocol::prefix::IdentifierPrefix;
use keria_types::api::{EndRole, Oobi, OobiOperation, Role};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::oobis::{
    END_ROLES_SEGMENT, OOBIS_SEGMENT, OobiResolution, RESOLUTIONS_SEGMENT, ROLE_PARAMETER,
};
use signify_http::request::ResourcePath;
use signify_http::transport::RequestUrl;

const GROUP_AID: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const AGENT_PREFIX: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";
const SHORT_OOBI: &str = "http://oobiurl.com";

/// A long but ordinary OOBI: a witness URL padded to the far end of what a deployment sends.
fn long_oobi() -> String {
    format!(
        "http://witness-demo:5642/oobi/{GROUP_AID}/controller?{}",
        "a=1&".repeat(120)
    )
}

/// An OOBI listing of `count` URLs, of the shape KERIA answers `get` with.
fn oobi_listing(count: usize) -> String {
    let urls: Vec<String> = (0..count)
        .map(|index| format!(r#""http://127.0.0.1:390{index}/oobi/{GROUP_AID}/agent/{AGENT_PREFIX}""#))
        .collect();
    format!(r#"{{"role":"agent","oobis":[{}]}}"#, urls.join(","))
}

/// An end-role listing of `count` records.
fn end_role_listing(count: usize) -> String {
    let records: Vec<String> = (0..count)
        .map(|_| format!(r#"{{"cid":"{GROUP_AID}","role":"agent","eid":"{AGENT_PREFIX}"}}"#))
        .collect();
    format!("[{}]", records.join(","))
}

/// A pending OOBI resolution operation.
fn pending_operation() -> String {
    format!(r#"{{"name":"oobi.{SHORT_OOBI}","metadata":{{"oobi":"{SHORT_OOBI}"}},"done":false}}"#)
}

fn benchmark_oobis(criterion: &mut Criterion) {
    let Ok(identifier) = IdentifierPrefix::from_qb64(GROUP_AID) else {
        return;
    };
    let Ok(prefix_text) = identifier.qb64() else { return };
    let Ok(short_url) = RequestUrl::new(SHORT_OOBI) else {
        return;
    };
    let long = long_oobi();
    let Ok(long_url) = RequestUrl::new(long.clone()) else {
        return;
    };

    // Addressing: the three shapes, with a short and a long alias.
    for (label, alias) in [("short", "aid"), ("long", &"a".repeat(64)[..])] {
        criterion.bench_function(&format!("oobis_get_path_{label}_alias"), |bencher| {
            bencher.iter(|| {
                ResourcePath::builder()
                    .segment(IDENTIFIERS_SEGMENT)
                    .segment(black_box(alias))
                    .segment(OOBIS_SEGMENT)
                    .parameter(ROLE_PARAMETER, black_box(Role::Agent.as_str()))
                    .build()
                    .is_ok()
            });
        });
    }
    criterion.bench_function("oobis_resolve_path", |bencher| {
        bencher.iter(|| ResourcePath::builder().segment(RESOLUTIONS_SEGMENT).build().is_ok());
    });
    criterion.bench_function("oobis_end_roles_path_unfiltered", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(END_ROLES_SEGMENT)
                .segment(black_box(&prefix_text))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("oobis_end_roles_path_filtered", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(END_ROLES_SEGMENT)
                .segment(black_box(&prefix_text))
                .segment(black_box(Role::Agent.as_str()))
                .build()
                .is_ok()
        });
    });

    // Validating an OOBI, which is what makes it a URL rather than a string.
    criterion.bench_function("oobis_validate_short_url", |bencher| {
        bencher.iter(|| RequestUrl::new(black_box(SHORT_OOBI)).is_ok());
    });
    criterion.bench_function("oobis_validate_long_url", |bencher| {
        bencher.iter(|| RequestUrl::new(black_box(long.as_str())).is_ok());
    });

    // Building the one body this family sends, with and without an alias.
    let plain = OobiResolution::new(short_url);
    let aliased = OobiResolution::new(long_url).with_alias("member1");
    criterion.bench_function("oobis_resolution_body_short", |bencher| {
        bencher.iter(|| black_box(&plain).body().is_ok());
    });
    criterion.bench_function("oobis_resolution_body_long_with_alias", |bencher| {
        bencher.iter(|| black_box(&aliased).body().is_ok());
    });

    // Decoding the three answers.
    for count in [1_usize, 16, 64] {
        let listing = oobi_listing(count);
        criterion.bench_function(&format!("oobis_decode_listing_{count}"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Oobi>(black_box(&listing)).is_ok());
        });
        let roles = end_role_listing(count);
        criterion.bench_function(&format!("oobis_decode_end_roles_{count}"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Vec<EndRole>>(black_box(&roles)).is_ok());
        });
    }
    let operation = pending_operation();
    criterion.bench_function("oobis_decode_operation", |bencher| {
        bencher.iter(|| serde_json::from_str::<OobiOperation>(black_box(&operation)).is_ok());
    });
}

criterion_group!(benches, benchmark_oobis);
criterion_main!(benches);
