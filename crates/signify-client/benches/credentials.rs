//! Microbenchmark for the credentials endpoint family.
//!
//! Three things here are worth measuring, and they are not the same kind of thing.
//!
//! **The filter body.** `list` is the only read in the crate that sends a document, and that
//! document is the *agent's* query language: a caller filtering over many clauses pays for
//! rendering all of them on every page. It is measured over growing clause counts.
//!
//! **The write bodies.** `issue` and `revoke` each assemble a body carrying two or three whole
//! events plus the key-manager block, which is the part this family adds on top of Roadmap 6.2's
//! artifact construction.
//!
//! **The answer.** A credential record is the largest document any read in this crate returns —
//! eleven fields, three of them whole events, one of them a complete JSON Schema — so decoding is
//! measured beside the listing of them, which has no paging and returns every match at once.
//!
//! Inputs: filters of 1 to 64 clauses, one credential record, and listings of 1, 8, and 32.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keria_types::api::Credential;
use signify_client::endpoint::credentials::{CREDENTIAL_QUERY_SEGMENT, CREDENTIALS_SEGMENT, CredentialFilter};
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::registries::REGISTRIES_SEGMENT;
use signify_http::request::ResourcePath;
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue};

const CREDENTIAL: &str = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const ISSUANCE: &str = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";
const ANCHOR: &str = "EIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt";

/// One complete credential record, as a KERIA agent returns it.
fn credential_record() -> String {
    format!(
        r#"{{"sad":{{"v":"ACDC10JSON000197_","d":"{CREDENTIAL}","i":"{ISSUER}","ri":"{REGISTRY}","s":"{SCHEMA}","a":{{"d":"EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P","i":"{ISSUER}","dt":"2023-08-23T15:16:07.553000+00:00","LEI":"5493001KJTIIGC8Y1R17"}}}},"atc":"-IAB","iss":{{"v":"KERI10JSON0000ed_","t":"iss","d":"{ISSUANCE}","i":"{CREDENTIAL}","s":"0","ri":"{REGISTRY}","dt":"2023-08-23T15:16:07.553000+00:00"}},"issatc":"-VAS","pre":"{ISSUER}","schema":{{"$id":"{SCHEMA}","$schema":"http://json-schema.org/draft-07/schema#","title":"t","description":"d","type":"object","credentialType":"C","version":"1.0.0","properties":{{"LEI":{{"type":"string"}}}},"additionalProperties":false,"required":["i","d"]}},"chains":[],"status":{{"vn":[1,0],"i":"{CREDENTIAL}","s":"0","d":"{ISSUANCE}","ri":"{REGISTRY}","a":{{"s":"2","d":"{ANCHOR}"}},"dt":"2023-08-23T15:16:07.553000+00:00","et":"iss","ra":{{}}}},"anchor":{{"pre":"{ISSUER}","sn":2,"d":"{ANCHOR}"}},"anc":{{"v":"KERI10JSON0000cb_","t":"ixn","d":"{ANCHOR}","i":"{ISSUER}","s":"2","p":"{ANCHOR}","a":[]}},"ancatc":[]}}"#
    )
}

/// A filter carrying `clauses` equality tests, which is the shape the reference's own filter has.
fn filter_with(clauses: usize) -> Option<CredentialFilter> {
    let mut query = Sad::new();
    for index in 0..clauses {
        let mut equality = Sad::new();
        equality.insert("$eq", CREDENTIAL).ok()?;
        query.insert(format!("-a{index}"), SadValue::Map(equality)).ok()?;
    }
    Some(CredentialFilter::new().with_filter(query).with_limit(25))
}

fn benchmark_credentials(criterion: &mut Criterion) {
    // Addressing: the two constant-segment listing path, one credential, and the two-value state
    // read the reference builds by concatenation.
    criterion.bench_function("credentials_query_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(CREDENTIALS_SEGMENT)
                .segment(CREDENTIAL_QUERY_SEGMENT)
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("credentials_member_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(CREDENTIALS_SEGMENT)
                .segment(black_box(CREDENTIAL))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("credentials_state_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(REGISTRIES_SEGMENT)
                .segment(black_box(REGISTRY))
                .segment(black_box(CREDENTIAL))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("credentials_submission_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(IDENTIFIERS_SEGMENT)
                .segment(black_box("issuer"))
                .segment(CREDENTIALS_SEGMENT)
                .build()
                .is_ok()
        });
    });

    // Parsing a SAID, which is what makes the path above unable to carry a delimiter.
    criterion.bench_function("credentials_parse_said", |bencher| {
        bencher.iter(|| Said::from_qb64(black_box(CREDENTIAL)).is_ok());
    });

    // The filter body, over growing clause counts. A listing has no paging, so a caller filtering
    // over many clauses pays this on every request.
    for clauses in [1_usize, 8, 64] {
        let Some(filter) = filter_with(clauses) else {
            return;
        };
        criterion.bench_function(&format!("credentials_filter_body_{clauses}"), |bencher| {
            bencher.iter(|| black_box(&filter).to_json_bytes().is_ok());
        });
    }
    let unfiltered = CredentialFilter::new();
    criterion.bench_function("credentials_filter_body_empty", |bencher| {
        bencher.iter(|| black_box(&unfiltered).to_json_bytes().is_ok());
    });

    // Decoding the answer: one record, then listings of growing size. `list` returns every match
    // in one body, bounded only by Roadmap 5.1's transport limit.
    let record = credential_record();
    criterion.bench_function("credentials_decode_record", |bencher| {
        bencher.iter(|| serde_json::from_str::<Credential>(black_box(&record)).is_ok());
    });
    for count in [1_usize, 8, 32] {
        let listing = format!(
            "[{}]",
            core::iter::repeat_n(record.as_str(), count)
                .collect::<Vec<_>>()
                .join(",")
        );
        criterion.bench_function(&format!("credentials_decode_listing_{count}"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Vec<Credential>>(black_box(&listing)).is_ok());
        });
    }

    // Re-encoding one record, which is what a caller storing an answer pays.
    if let Ok(decoded) = serde_json::from_str::<Credential>(&record) {
        criterion.bench_function("credentials_encode_record", |bencher| {
            bencher.iter(|| serde_json::to_vec(black_box(&decoded)).is_ok());
        });
    }
}

criterion_group!(benches, benchmark_credentials);
criterion_main!(benches);
