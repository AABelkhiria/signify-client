//! Microbenchmarks for self-addressing-identifier derivation and verification.
//!
//! Every message a peer sends is SAID-derived once and every message received is verified once,
//! and both run over attacker-influenced content. Derivation is dominated by the serialization it
//! performs rather than by BLAKE3, so both the versioned and version-less shapes are measured.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::digest::DigestAlgorithm;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::Sad;

/// The 292-byte `rep` message from the pinned `test/core/saider.test.ts`, before derivation.
const REP_MESSAGE: &str = concat!(
    r#"{"v":"KERI10JSON000000_","t":"rep","d":"","dt":"2020-08-22T17:50:12.988921+00:00","#,
    r#""r":"logs/processor","a":{"d":"EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg","#,
    r#""i":"EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb","name":"John Jones","role":"Founder"}}"#
);

/// A version-less block, the shape ACDC nests inside a credential.
const NESTED_BLOCK: &str = r#"{"d":"","i":"EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb","name":"John Jones"}"#;

fn benchmark_said(criterion: &mut Criterion) {
    if let Ok(sad) = Sad::from_json_bytes(REP_MESSAGE.as_bytes()) {
        criterion.bench_function("said_compute_versioned_292_bytes", |bencher| {
            bencher.iter(|| Said::compute(black_box(&sad), DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL));
        });

        if let Ok(computed) = Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL) {
            let said = *computed.said();
            let completed = computed.sad().clone();
            criterion.bench_function("said_verify_strict_versioned_292_bytes", |bencher| {
                bencher.iter(|| said.verify(black_box(&completed), DEFAULT_SAID_LABEL, SaidVerification::strict()));
            });
        }
    }

    if let Ok(nested) = Sad::from_json_bytes(NESTED_BLOCK.as_bytes()) {
        criterion.bench_function("said_compute_version_less_78_bytes", |bencher| {
            bencher.iter(|| Said::compute(black_box(&nested), DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL));
        });
    }
}

criterion_group!(benches, benchmark_said);
criterion_main!(benches);
