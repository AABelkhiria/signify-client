//! Microbenchmarks for decoding and encoding KERIA API documents.
//!
//! Every call a client makes returns one of these documents, and the bytes come from the network,
//! so decoding is both on the hot path of the whole SDK and the place attacker-influenced content
//! first becomes typed. Encoding is measured alongside it because a request body and a stored
//! record both go back out the same way.
//!
//! The inputs are the pinned documents the cross-language fixture records: an agent key state, a
//! salty identifier record, a pending witness operation, and a credential with its schema, its
//! issuance event, and its anchor — which is the largest single document KERIA returns.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_types::api::{Credential, Hab, KeyState, WitnessOperation, from_json_slice, to_json_string};

const KEY_STATE: &str = r#"{"vn":[1,0],"i":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","s":"0","p":"","d":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","f":"0","dt":"2023-08-19T21:04:57.948863+00:00","et":"dip","kt":"1","k":["DMZh_y-H5C3cSbZZST-fqnsmdNTReZxIh0t2xSTOJQ8a"],"nt":"1","n":["EM9M2EQNCBK0MyAhVYBvR98Q0tefpvHgE-lHLs82XgqC"],"bt":"0","b":[],"c":[],"ee":{"s":"0","d":"EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei","br":[],"ba":[]},"di":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"}"#;

const IDENTIFIER: &str = r#"{"name":"aid1","prefix":"ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK","icp_dt":"2023-08-21T22:30:46.473545+00:00","transferable":true,"windexes":[],"salty":{"tier":"low","sxlt":"1AAHnNQTkD0yxOC9tSz_ukbB2e-qhDTStH18uCsi5PCwOyXLONDR3MeKwWv_AVJKGKGi6xiBQH25_R1RXLS2OuK3TN3ovoUKH7-A","pidx":0,"kidx":0,"stem":"signify:aid","dcode":"E","icodes":["A"],"ncodes":["A"],"transferable":true}}"#;

const OPERATION: &str = r#"{"name":"witness.EABC","metadata":{"pre":"EABC","sn":0},"done":false}"#;

const CREDENTIAL: &str = r#"{"sad":{"v":"ACDC10JSON000_","d":"ECRED","i":"EISS","ri":"EREG","s":"ESCH","a":{"d":"EATT","i":"EHOLD","LEI":"254900OPPU84GM83MG36"}},"atc":"-AAB","iss":{"v":"KERI10JSON0000ed_","t":"iss","d":"EISSEV","i":"ECRED","s":"0","ri":"EREG","dt":"2023-08-19T21:04:57.948863+00:00"},"issatc":"-AAC","pre":"EISS","schema":{"$id":"ESCH","$schema":"http://json-schema.org/draft-07/schema#","title":"Legal Entity","description":"vLEI","type":"object","credentialType":"LegalEntityvLEICredential","version":"1.0.0","properties":{},"additionalProperties":false,"required":["i"]},"chains":[],"status":{"vn":[1,0],"i":"ECRED","s":"0","d":"EAB","ri":"EREG","a":{"s":"1","d":"EANC"},"dt":"2023-08-19T21:04:57.948863+00:00","et":"iss","ra":{}},"anchor":{"pre":"EISS","sn":1,"d":"EANC"},"anc":{"v":"KERI10JSON0000cb_","t":"ixn","d":"EANC","i":"EISS","s":"1","p":"EPP","a":[]},"ancatc":["-AAD"]}"#;

/// Measures decoding and encoding one document with one record type.
macro_rules! measure {
    ($criterion:expr, $label:literal, $record:ty, $document:expr) => {
        let bytes = $document.as_bytes();
        $criterion.bench_function(concat!("decode_", $label), |bencher| {
            bencher.iter(|| from_json_slice::<$record>(black_box(bytes)).is_ok());
        });
        if let Ok(record) = from_json_slice::<$record>(bytes) {
            $criterion.bench_function(concat!("encode_", $label), |bencher| {
                bencher.iter(|| to_json_string(black_box(&record)).is_ok());
            });
        }
    };
}

fn benchmark_keria_api(criterion: &mut Criterion) {
    // 428 bytes: the response every connect, query, and OOBI resolution returns.
    measure!(criterion, "key_state", KeyState, KEY_STATE);
    // 386 bytes: one entry of an identifier list, whose union is resolved at decoding.
    measure!(criterion, "identifier", Hab, IDENTIFIER);
    // 69 bytes: polled repeatedly until an operation finishes, so the smallest and the hottest.
    measure!(criterion, "operation", WitnessOperation, OPERATION);
    // 1,090 bytes: the largest single document, carrying six nested records.
    measure!(criterion, "credential", Credential, CREDENTIAL);
}

criterion_group!(benches, benchmark_keria_api);
criterion_main!(benches);
