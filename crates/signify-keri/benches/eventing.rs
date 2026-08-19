//! Microbenchmarks for core key-event construction.
//!
//! An edge signer builds one event per identifier operation, and every one of them derives a
//! digest over the serialized event. Inception is measured in both prefix derivations because a
//! basic prefix skips the digest entirely, and rotation and interaction are measured because they
//! are the operations a long-lived identifier repeats.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use signify_crypto::digest::Digest;
use signify_crypto::verifier::VerificationKey;
use signify_keri::event::inception::InceptionBuilder;
use signify_keri::event::interaction::InteractionBuilder;
use signify_keri::event::reply::ReplyBuilder;
use signify_keri::event::rotation::RotationBuilder;
use signify_keri::event::timestamp::Timestamp;
use signify_keri::event::witness::{AmpleMode, ample};
use signify_keri::prefix::{IdentifierPrefix, PrefixDerivation};
use signify_keri::serialization::{Sad, SadValue};

const KEY: &str = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";
const SECOND_KEY: &str = "DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ";
const NEXT_DIGEST: &str = "EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W";
const WITNESS: &str = "BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ";
const STAMP: &str = "2021-06-27T21:26:21.233257+00:00";

fn benchmark_eventing(criterion: &mut Criterion) {
    let (Ok(key), Ok(second), Ok(digest), Ok(witness)) = (
        VerificationKey::from_qb64(KEY),
        VerificationKey::from_qb64(SECOND_KEY),
        Digest::from_qb64(NEXT_DIGEST),
        IdentifierPrefix::from_qb64(WITNESS),
    ) else {
        return;
    };

    criterion.bench_function("incept_basic_prefix", |bencher| {
        bencher.iter(|| InceptionBuilder::new(vec![black_box(key.clone())]).build());
    });

    criterion.bench_function("incept_self_addressing_prefix", |bencher| {
        bencher.iter(|| {
            InceptionBuilder::new(vec![black_box(key.clone())])
                .next_key_digests(vec![digest])
                .prefix_derivation(PrefixDerivation::Blake3_256)
                .build()
        });
    });

    criterion.bench_function("incept_multisig_with_witnesses", |bencher| {
        bencher.iter(|| {
            InceptionBuilder::new(vec![black_box(key.clone()), second.clone()])
                .next_key_digests(vec![digest, digest])
                .witnesses(vec![witness.clone()])
                .build()
        });
    });

    let Ok(root) = InceptionBuilder::new(vec![key.clone()])
        .next_key_digests(vec![digest])
        .prefix_derivation(PrefixDerivation::Blake3_256)
        .build()
    else {
        return;
    };

    criterion.bench_function("rotate", |bencher| {
        bencher.iter(|| {
            RotationBuilder::new(
                black_box(root.identifier().clone()),
                root.said(),
                1,
                vec![second.clone()],
            )
            .next_key_digests(vec![digest])
            .build()
        });
    });

    criterion.bench_function("interact", |bencher| {
        bencher.iter(|| InteractionBuilder::new(black_box(root.identifier().clone()), root.said(), 1).build());
    });

    criterion.bench_function("ample_default_threshold", |bencher| {
        bencher.iter(|| ample(black_box(64), None, AmpleMode::Weak));
    });

    // A reply is built once per endpoint authorisation and its timestamp is parsed from whatever
    // the caller's time library produced, so both are on the path of every such operation.
    if let Ok(stamp) = Timestamp::parse(STAMP) {
        criterion.bench_function("reply_end_role", |bencher| {
            bencher.iter(|| {
                let mut attributes = Sad::new();
                let _ = attributes.insert("cid", SadValue::text(KEY));
                let _ = attributes.insert("role", SadValue::text("agent"));
                ReplyBuilder::new(black_box("/end/role/add"), stamp.clone())
                    .attributes(attributes)
                    .build()
            });
        });
    }

    criterion.bench_function("timestamp_parse", |bencher| {
        bencher.iter(|| Timestamp::parse(black_box(STAMP)));
    });
}

criterion_group!(benches, benchmark_eventing);
criterion_main!(benches);
