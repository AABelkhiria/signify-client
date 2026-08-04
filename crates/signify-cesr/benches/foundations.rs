//! Microbenchmarks for repeated CESR foundation operations.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_cesr::{
    base64::{decode_u64, decode_url_safe, encode_u64, encode_url_safe},
    bytes::{bytes_to_integer, integer_to_bytes},
};

fn benchmark_foundations(criterion: &mut Criterion) {
    for size in [32_usize, 1024] {
        let bytes = vec![0xa5; size];
        let encoded = encode_url_safe(&bytes);
        criterion.bench_function(&format!("base64_encode_{size}_bytes"), |bencher| {
            bencher.iter(|| encode_url_safe(black_box(&bytes)));
        });
        criterion.bench_function(&format!("base64_decode_{size}_bytes"), |bencher| {
            bencher.iter(|| decode_url_safe(black_box(&encoded)));
        });
    }

    criterion.bench_function("base64_u64_max", |bencher| {
        bencher.iter(|| encode_u64(black_box(u64::MAX), 1));
    });
    criterion.bench_function("base64_u64_decode_max", |bencher| {
        bencher.iter(|| decode_u64(black_box("P__________")));
    });
    criterion.bench_function("integer_to_16_bytes", |bencher| {
        bencher.iter(|| integer_to_bytes(black_box(u128::MAX), 16));
    });
    criterion.bench_function("integer_from_16_bytes", |bencher| {
        bencher.iter(|| bytes_to_integer(black_box(&[0xff; 16])));
    });
}

criterion_group!(benches, benchmark_foundations);
criterion_main!(benches);
