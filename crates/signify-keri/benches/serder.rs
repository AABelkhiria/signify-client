//! Microbenchmarks for deterministic message serialization and hostile-input parsing.
//!
//! Every sent message is serialized at least once and every received message is parsed once, both
//! over attacker-influenced content, so these are the hot paths of any KERI workload. Inputs are
//! the exact pinned reference messages, so no fixture loading or allocation setup is measured.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_keri::serialization::{Sad, SerializedEvent};

/// The 211-byte inception event asserted by the pinned `test/core/serder.test.ts`.
const INCEPTION: &str = concat!(
    r#"{"v":"KERI10JSON0000d3_","t":"icp","d":"","i":"","s":"0","kt":"1","k":"#,
    r#"["DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e"],"nt":"1","n":"#,
    r#"["EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj"],"bt":"0","b":[],"c":[],"a":[]}"#
);

/// The 315-byte interaction event asserted by the same test, with a nested anchor array.
const INTERACTION: &str = concat!(
    r#"{"v":"KERI10JSON00013b_","t":"ixn","d":"EDMbT6cc2P4aPozDJhat1T_S-G98Gc7Jj8K0qxAL7EuC","#,
    r#""i":"EDKLs7y-U4N_EIv_oqJqdmWOvR5Y-nSEHJPrprT1RLFb","s":"39","#,
    r#""p":"EI696dhEGo9cDK7MpvSsPkNkVhF4pwwgof3GaRVVESXb","#,
    r#""a":[{"i":"EFMXIFSIyEL6JTCyZAbO3nHgSdOw5UbLH9fAr9zO8_LH","s":"0","#,
    r#""d":"EFMXIFSIyEL6JTCyZAbO3nHgSdOw5UbLH9fAr9zO8_LH"}]}"#
);

fn benchmark_serder(criterion: &mut Criterion) {
    criterion.bench_function("sad_parse_inception_211_bytes", |bencher| {
        bencher.iter(|| Sad::from_json_bytes(black_box(INCEPTION.as_bytes())));
    });

    if let Ok(sad) = Sad::from_json_bytes(INCEPTION.as_bytes()) {
        criterion.bench_function("sad_encode_inception_211_bytes", |bencher| {
            bencher.iter(|| black_box(&sad).to_json_bytes());
        });

        criterion.bench_function("event_size_and_serialize_inception_211_bytes", |bencher| {
            bencher.iter(|| SerializedEvent::from_sad(black_box(&sad).clone()));
        });
    }

    criterion.bench_function("event_parse_inception_211_bytes", |bencher| {
        bencher.iter(|| SerializedEvent::parse(black_box(INCEPTION.as_bytes())));
    });

    criterion.bench_function("event_parse_interaction_315_bytes", |bencher| {
        bencher.iter(|| SerializedEvent::parse(black_box(INTERACTION.as_bytes())));
    });
}

criterion_group!(benches, benchmark_serder);
criterion_main!(benches);
