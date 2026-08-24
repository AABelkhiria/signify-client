//! Microbenchmark for the schema endpoint family.
//!
//! Unlike the other reading families, this one's cost is genuinely in the **decode**: a `Schema`
//! carries an open JSON Schema `properties` map, and a real vLEI schema is several kilobytes where
//! a key state is a few hundred bytes. `list` returns all of them at once, with no paging, so the
//! interesting number is how decoding scales with the document rather than how the path is built.
//!
//! Inputs: one 44-character SAID, and schema documents with 1, 16, and 64 declared properties,
//! decoded singly and as listings.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_client::endpoint::schemas::SCHEMA_SEGMENT;
use signify_http::request::ResourcePath;
use signify_keri::said::Said;
use signify_types::api::Schema;

const QVI: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/// A complete schema declaring `count` properties, of the shape KERIA answers with.
fn schema_document(count: usize) -> String {
    let properties: Vec<String> = (0..count)
        .map(|index| format!(r#""field{index}":{{"description":"Field {index}","type":"string","format":"text"}}"#))
        .collect();
    format!(
        r#"{{"$id":"{QVI}","$schema":"http://json-schema.org/draft-07/schema#","title":"Qualified vLEI Issuer","description":"A credential","type":"object","credentialType":"QualifiedvLEIIssuervLEICredential","version":"1.0.0","properties":{{{}}},"additionalProperties":false,"required":["i","ri","s","d"]}}"#,
        properties.join(",")
    )
}

fn benchmark_schemas(criterion: &mut Criterion) {
    let Ok(said) = Said::from_qb64(QVI) else {
        return;
    };
    let Ok(text) = said.qb64() else { return };

    // Addressing: one SAID, and the constant listing path.
    criterion.bench_function("schemas_get_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(SCHEMA_SEGMENT)
                .segment(black_box(&text))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("schemas_list_path", |bencher| {
        bencher.iter(|| ResourcePath::builder().segment(SCHEMA_SEGMENT).build().is_ok());
    });

    // Parsing a SAID, which is what makes the injection unrepresentable.
    criterion.bench_function("schemas_parse_said", |bencher| {
        bencher.iter(|| Said::from_qb64(black_box(QVI)).is_ok());
    });

    // Decoding one schema, as its declared properties grow.
    for count in [1_usize, 16, 64] {
        let document = schema_document(count);
        criterion.bench_function(&format!("schemas_decode_{count}_properties"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Schema>(black_box(&document)).is_ok());
        });
    }

    // Decoding a whole listing, which is what `list` actually returns.
    for count in [2_usize, 16] {
        let one = schema_document(16);
        let listing = format!("[{}]", vec![one; count].join(","));
        criterion.bench_function(&format!("schemas_decode_listing_of_{count}"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Vec<Schema>>(black_box(&listing)).is_ok());
        });
    }

    // Re-encoding one, which is what a caller storing a schema pays.
    let Ok(schema) = serde_json::from_str::<Schema>(&schema_document(16)) else {
        return;
    };
    criterion.bench_function("schemas_encode", |bencher| {
        bencher.iter(|| serde_json::to_vec(black_box(&schema)).is_ok());
    });
}

criterion_group!(benches, benchmark_schemas);
criterion_main!(benches);
