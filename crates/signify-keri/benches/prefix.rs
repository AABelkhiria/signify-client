//! Microbenchmarks for identifier-prefix derivation and verification.
//!
//! Every identifier a controller creates is derived once, and every inception event received from
//! a peer is verified once over attacker-influenced content. Self-addressing derivation is
//! dominated by the serialization it performs rather than by BLAKE3, so it is measured against the
//! basic derivation, which only parses one key.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_keri::prefix::{IdentifierPrefix, PrefixDerivation, PrefixVerification};
use signify_keri::serialization::Sad;

/// The 299-byte inception event from the `Prefixer` assertions in `test/core/serder.test.ts`.
const INCEPTION_EVENT: &str = concat!(
    r#"{"v":"KERI10JSON000000_","t":"icp","d":"","i":"","s":"0","kt":"1","#,
    r#""k":["DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e"],"nt":"1","#,
    r#""n":["EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj"],"bt":"0","b":[],"c":[],"a":[]}"#
);

/// The self-addressing prefix that event derives.
const SELF_ADDRESSING_PREFIX: &str = "ECHOi6qRaswNpvytpCtpvEh2cB2aLAwVHBLFinno3YVW";

/// Rebuilds a SAD with one field replaced, preserving field order.
fn with_field(sad: &Sad, label: &str, value: &str) -> Option<Sad> {
    let mut rebuilt = Sad::new();
    for (existing, existing_value) in sad.entries() {
        let replacement = if existing == label {
            signify_keri::serialization::SadValue::text(value)
        } else {
            existing_value.clone()
        };
        rebuilt.insert(existing.to_owned(), replacement).ok()?;
    }
    Some(rebuilt)
}

fn benchmark_prefix(criterion: &mut Criterion) {
    let Ok(inception) = Sad::from_json_bytes(INCEPTION_EVENT.as_bytes()) else {
        return;
    };

    criterion.bench_function("prefix_derive_self_addressing_299_bytes", |bencher| {
        bencher.iter(|| IdentifierPrefix::derive(black_box(&inception), PrefixDerivation::Blake3_256));
    });

    criterion.bench_function("prefix_derive_basic_transferable", |bencher| {
        bencher.iter(|| IdentifierPrefix::derive(black_box(&inception), PrefixDerivation::Ed25519));
    });

    let completed = with_field(&inception, "i", SELF_ADDRESSING_PREFIX)
        .and_then(|sad| with_field(&sad, "d", SELF_ADDRESSING_PREFIX));
    if let (Some(completed), Ok(prefix)) = (completed, IdentifierPrefix::from_qb64(SELF_ADDRESSING_PREFIX)) {
        criterion.bench_function("prefix_verify_strict_self_addressing_299_bytes", |bencher| {
            bencher.iter(|| prefix.verify(black_box(&completed), PrefixVerification::Strict));
        });
    }

    criterion.bench_function("prefix_parse_qb64", |bencher| {
        bencher.iter(|| IdentifierPrefix::from_qb64(black_box(SELF_ADDRESSING_PREFIX)));
    });
}

criterion_group!(benches, benchmark_prefix);
criterion_main!(benches);
