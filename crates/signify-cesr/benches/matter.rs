//! Microbenchmarks for qualified-material construction and attacker-facing parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_cesr::{code::DerivationCode, matter::QualifiedMaterial};

fn benchmark_matter(criterion: &mut Criterion) {
    let raw_32 = [0x5a_u8; 32];
    criterion.bench_function("matter_construct_fixed_32_bytes", |bencher| {
        bencher.iter(|| QualifiedMaterial::new(black_box(DerivationCode::BLAKE3_256), black_box(&raw_32)));
    });

    if let Ok(fixed) = QualifiedMaterial::new(DerivationCode::BLAKE3_256, &raw_32)
        && let (Ok(qb64), Ok(qb2)) = (fixed.qb64(), fixed.qb2())
    {
        criterion.bench_function("matter_parse_qb64_fixed_44_chars", |bencher| {
            bencher.iter(|| QualifiedMaterial::from_qb64(black_box(&qb64)));
        });
        criterion.bench_function("matter_parse_qb2_fixed_33_bytes", |bencher| {
            bencher.iter(|| QualifiedMaterial::from_qb2(black_box(&qb2)));
        });
    }

    let raw_variable = vec![0xa5_u8; 12_288];
    criterion.bench_function("matter_construct_variable_12_kib", |bencher| {
        bencher
            .iter(|| QualifiedMaterial::new(black_box(DerivationCode::BASE64_TEXT_LEAD_0), black_box(&raw_variable)));
    });
    if let Ok(variable) = QualifiedMaterial::new(DerivationCode::BASE64_TEXT_LEAD_0, &raw_variable)
        && let Ok(qb64) = variable.qb64()
    {
        criterion.bench_function("matter_parse_qb64_variable_16_kib", |bencher| {
            bencher.iter(|| QualifiedMaterial::from_qb64(black_box(&qb64)));
        });
    }
}

criterion_group!(benches, benchmark_matter);
criterion_main!(benches);
