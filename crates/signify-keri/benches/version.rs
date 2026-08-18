//! Microbenchmarks for version-string parsing/formatting and event-kind parsing.
//!
//! Every received KERI or ACDC event carries one seventeen-character version string and one ilk,
//! so both parses run repeatedly over attacker-controlled input; formatting runs once per built
//! event. Inputs are fixed constants, so no fixture loading or allocation setup is measured.

use std::hint::black_box;
use std::str::FromStr;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_keri::event::kind::EventKind;
use signify_keri::serialization::{Protocol, ProtocolVersion, SerializationKind, VersionString};

fn benchmark_version(criterion: &mut Criterion) {
    criterion.bench_function("version_string_parse_17_bytes", |bencher| {
        bencher.iter(|| VersionString::from_str(black_box("KERI10JSON00011c_")));
    });

    if let Ok(version) = VersionString::new(Protocol::Keri, ProtocolVersion::V1_0, SerializationKind::Json, 0x11c) {
        criterion.bench_function("version_string_format_17_bytes", |bencher| {
            bencher.iter(|| black_box(version).to_string());
        });
    }

    criterion.bench_function("event_kind_parse_3_bytes", |bencher| {
        bencher.iter(|| EventKind::from_str(black_box("rot")));
    });
}

criterion_group!(benches, benchmark_version);
criterion_main!(benches);
