//! Microbenchmarks for indexed-material construction and attacker-facing parsing.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_cesr::indexer::{IndexedMaterial, IndexerCode};

fn benchmark_indexer(criterion: &mut Criterion) {
    let signature = [0x5a_u8; 64];
    criterion.bench_function("indexer_construct_small_64_bytes", |bencher| {
        bencher.iter(|| {
            IndexedMaterial::new(
                black_box(IndexerCode::ED25519),
                black_box(5),
                black_box(None),
                black_box(&signature),
            )
        });
    });

    if let Ok(material) = IndexedMaterial::new(IndexerCode::ED25519_BIG, 90, Some(65), &signature)
        && let (Ok(qb64), Ok(qb2)) = (material.qb64(), material.qb2())
    {
        criterion.bench_function("indexer_parse_qb64_big_92_chars", |bencher| {
            bencher.iter(|| IndexedMaterial::from_qb64(black_box(&qb64)));
        });
        criterion.bench_function("indexer_parse_qb2_big_69_bytes", |bencher| {
            bencher.iter(|| IndexedMaterial::from_qb2(black_box(&qb2)));
        });
    }
}

criterion_group!(benches, benchmark_indexer);
criterion_main!(benches);
