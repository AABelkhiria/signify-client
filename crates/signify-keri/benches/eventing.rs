//! Microbenchmarks for core key-event construction.
//!
//! An edge signer builds one event per identifier operation, and every one of them derives a
//! digest over the serialized event. Inception is measured in both prefix derivations because a
//! basic prefix skips the digest entirely, and rotation and interaction are measured because they
//! are the operations a long-lived identifier repeats.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::digest::Digest;
use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::sequence::SequenceNumber;
use signify_keri::attachment::{ReceiptCouple, SignatureSeal, SignedMessageBuilder};
use signify_keri::event::KeyEvent;
use signify_keri::event::exchange::{ExchangeBuilder, ExchangeEmbed};
use signify_keri::event::inception::InceptionBuilder;
use signify_keri::event::interaction::InteractionBuilder;
use signify_keri::event::reply::ReplyBuilder;
use signify_keri::event::rotation::RotationBuilder;
use signify_keri::event::timestamp::Timestamp;
use signify_keri::event::witness::{AmpleMode, ample};
use signify_keri::prefix::{IdentifierPrefix, PrefixDerivation};
use signify_keri::said::Said;
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

const KEY: &str = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";
const SECOND_KEY: &str = "DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ";
const NEXT_DIGEST: &str = "EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W";
const WITNESS: &str = "BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ";
const STAMP: &str = "2021-06-27T21:26:21.233257+00:00";
const EXCHANGE_STAMP: &str = "2023-08-30T17:22:54.183000+00:00";
const BENCH_SIGNATURE: &str =
    "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I";
const BENCH_IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
const BENCH_WITNESS_KEY: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
const BENCH_WITNESS_SIGNATURE: &str =
    "AACeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";
const BENCH_RECEIPT_SIGNATURE: &str =
    "0BCeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";

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

    benchmark_attachments(criterion, &root);
    benchmark_exchange(criterion, &root);
}

/// Every multisig step and every IPEX step is one exchange message, and a grant carries three
/// embeds whose SAIDs are derived over the whole block.
fn benchmark_exchange(criterion: &mut Criterion, root: &KeyEvent) {
    let (Ok(sender), Ok(recipient), Ok(stamp), Ok(embedded)) = (
        IdentifierPrefix::from_qb64(BENCH_IDENTIFIER),
        IdentifierPrefix::from_qb64(WITNESS),
        Timestamp::parse(EXCHANGE_STAMP),
        SerializedEvent::parse(root.raw()),
    ) else {
        return;
    };
    let builder = || ExchangeBuilder::new("/ipex/grant", sender.clone(), recipient.clone(), stamp.clone());

    criterion.bench_function("exchange_without_embeds", |bencher| {
        bencher.iter(|| {
            let mut payload = Sad::new();
            let _ = payload.insert("m", SadValue::text(""));
            black_box(builder()).payload(payload).build()
        });
    });

    let Ok(attached) = ExchangeEmbed::new("acdc", &embedded)
        .and_then(|embed| embed.with_attachment(format!("-AAB{BENCH_SIGNATURE}").into_bytes()))
    else {
        return;
    };

    criterion.bench_function("exchange_with_one_embed", |bencher| {
        bencher.iter(|| black_box(builder()).embeds(vec![attached.clone()]).build());
    });

    let (Ok(iss), Ok(anc)) = (
        ExchangeEmbed::new("iss", &embedded),
        ExchangeEmbed::new("anc", &embedded),
    ) else {
        return;
    };

    criterion.bench_function("exchange_with_three_embeds", |bencher| {
        bencher.iter(|| {
            black_box(builder())
                .embeds(vec![attached.clone(), iss.clone(), anc.clone()])
                .build()
        });
    });
}

/// Every message a controller sends is composed once with its signatures attached.
fn benchmark_attachments(criterion: &mut Criterion, root: &KeyEvent) {
    if let (Ok(event), Ok(signature)) = (
        SerializedEvent::parse(root.raw()),
        IndexedSignature::from_qb64(BENCH_SIGNATURE),
    ) {
        criterion.bench_function("attach_controller_signature", |bencher| {
            bencher.iter(|| {
                SignedMessageBuilder::new(black_box(&event))
                    .controller_signatures(vec![signature.clone()])
                    .build()
            });
        });

        if let (Ok(identifier), Ok(said)) = (
            IdentifierPrefix::from_qb64(BENCH_IDENTIFIER),
            Said::from_qb64(BENCH_IDENTIFIER),
        ) {
            criterion.bench_function("attach_seal_and_signature", |bencher| {
                bencher.iter(|| {
                    SignedMessageBuilder::new(black_box(&event))
                        .controller_signatures(vec![signature.clone()])
                        .seal(SignatureSeal::Event {
                            identifier: identifier.clone(),
                            sequence_number: SequenceNumber::new(0),
                            said,
                        })
                        .build()
                });
            });
        }

        // A witnessed message carries all three group kinds at once.
        if let (Ok(witness_key), Ok(witness_signature), Ok(receipt_signature)) = (
            VerificationKey::from_qb64(BENCH_WITNESS_KEY),
            IndexedSignature::from_qb64(BENCH_WITNESS_SIGNATURE),
            UnindexedSignature::from_qb64(BENCH_RECEIPT_SIGNATURE),
        ) && let (Ok(witness), Ok(receipt)) = (
            witness_signature.with_verifier(witness_key.clone()),
            ReceiptCouple::new(witness_key, receipt_signature),
        ) {
            criterion.bench_function("attach_witness_and_receipt_groups", |bencher| {
                bencher.iter(|| {
                    SignedMessageBuilder::new(black_box(&event))
                        .controller_signatures(vec![signature.clone()])
                        .witness_signatures(vec![witness.clone()])
                        .receipt_couples(vec![receipt.clone()])
                        .build()
                });
            });
        }
    }
}

criterion_group!(benches, benchmark_eventing);
criterion_main!(benches);
