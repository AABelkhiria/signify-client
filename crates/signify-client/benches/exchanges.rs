//! Microbenchmark for the exchange endpoint family.
//!
//! This is the generic form of what the IPEX submission does for five fixed routes, so the two
//! benchmarks are deliberately comparable. What is measured here is the part a caller of *this*
//! family controls and the IPEX caller does not: the **message itself**.
//!
//! Three things scale, and all three are the caller's.
//!
//! **The embeds.** A multisig proposal carries whole key events inside the message, each with its
//! own transposed CESR attachment, and building one means deriving a SAID over the lot. Measured
//! from none to four.
//!
//! **The delivery list.** The one part of the body that grows freely, measured from one recipient
//! to sixty-four — the same range the IPEX benchmark used.
//!
//! **The answer**, which is decoded twice over: this is the one family whose reference declares two
//! incompatible types for it, so a caller may try both, and the cost of the failing attempt is
//! worth knowing.
//!
//! Not measured here: the **signature**, which dominates everything below and belongs to the
//! keeper rather than to this module — the `lifecycle` benchmark measured one at ~25 µs — and the
//! keeper rebuild behind it, which is an Argon2 cost.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_protocol::event::exchange::{ExchangeBuilder, ExchangeEmbed};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadValue, SerializedEvent};
use keria_types::api::{ExchangeOperation, ExchangeRecord};
use signify_client::endpoint::exchanges::EXCHANGES_SEGMENT;
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_http::request::ResourcePath;

const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const RECIPIENT: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SAID: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const STAMP: &str = "2023-11-14T22:13:20.123000+00:00";

/// One embedded interaction event, of the shape a multisig proposal carries.
fn embedded_event() -> Option<SerializedEvent> {
    let mut sad = Sad::new();
    sad.insert("v", SadValue::text("KERI10JSON0000cb_")).ok()?;
    sad.insert("t", SadValue::text("ixn")).ok()?;
    sad.insert("d", SadValue::text(SAID)).ok()?;
    sad.insert("i", SadValue::text(SENDER)).ok()?;
    sad.insert("s", SadValue::text("1")).ok()?;
    sad.insert("p", SadValue::text(SAID)).ok()?;
    sad.insert("a", SadValue::Array(Vec::new())).ok()?;
    SerializedEvent::from_sad(sad).ok()
}

/// `count` embeds, each carrying a short attachment so the transposition is exercised.
fn embeds(count: usize) -> Vec<ExchangeEmbed> {
    let Some(event) = embedded_event() else {
        return Vec::new();
    };
    (0..count)
        .filter_map(|index| {
            ExchangeEmbed::new(format!("e{index}"), &event)
                .and_then(|embed| embed.with_attachment("-AABAA".repeat(4).into_bytes()))
                .ok()
        })
        .collect()
}

/// A submission body with `count` recipients, as the family assembles it.
fn body(message: &Sad, count: usize) -> Option<Vec<u8>> {
    let mut body = Sad::new();
    body.insert("tpc", "multisig".to_owned()).ok()?;
    body.insert("exn", SadValue::Map(message.clone())).ok()?;
    body.insert("sigs", SadValue::Array(vec![SadValue::text("A".repeat(88))]))
        .ok()?;
    body.insert("atc", String::new()).ok()?;
    body.insert(
        "rec",
        SadValue::Array((0..count).map(|_| SadValue::text(RECIPIENT)).collect()),
    )
    .ok()?;
    body.to_json_bytes().ok()
}

fn benchmark_exchanges(criterion: &mut Criterion) {
    let (Ok(sender), Ok(recipient), Ok(stamp)) = (
        IdentifierPrefix::from_qb64(SENDER),
        IdentifierPrefix::from_qb64(RECIPIENT),
        STAMP.parse::<Timestamp>(),
    ) else {
        return;
    };

    // Addressing: the two shapes this family has.
    criterion.bench_function("exchanges_submission_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(IDENTIFIERS_SEGMENT)
                .segment(black_box("aid1"))
                .segment(EXCHANGES_SEGMENT)
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("exchanges_read_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(EXCHANGES_SEGMENT)
                .segment(black_box(SAID))
                .build()
                .is_ok()
        });
    });

    // The message: what an embed costs, which is what a multisig proposal is made of.
    let mut payload = Sad::new();
    let _ = payload.insert("gid", SadValue::text(SENDER));
    for count in [0_usize, 1, 4] {
        let prepared = embeds(count);
        criterion.bench_function(&format!("exchanges_build_message_{count}_embeds"), |bencher| {
            bencher.iter(|| {
                ExchangeBuilder::new("/multisig/icp", sender.clone(), recipient.clone(), stamp.clone())
                    .payload(payload.clone())
                    .embeds(black_box(prepared.clone()))
                    .build()
                    .is_ok()
            });
        });
    }

    // The body: the one part that scales with a caller's delivery list.
    let Ok(message) = ExchangeBuilder::new("/multisig/icp", sender, recipient, stamp)
        .payload(payload)
        .build()
    else {
        return;
    };
    let document = message.sad().clone();
    for count in [1_usize, 8, 64] {
        criterion.bench_function(&format!("exchanges_body_recipients_{count}"), |bencher| {
            bencher.iter(|| body(black_box(&document), count).is_some());
        });
    }

    // The answer, decoded both declared ways — including the attempt that fails.
    let operation = br#"{"name":"exchange.EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-","metadata":{"said":"EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-"},"done":true,"response":{"said":"EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-"}}"#;
    criterion.bench_function("exchanges_decode_operation", |bencher| {
        bencher.iter(|| serde_json::from_slice::<ExchangeOperation>(black_box(operation)).is_ok());
    });
    criterion.bench_function("exchanges_decode_operation_as_exchange", |bencher| {
        bencher.iter(|| serde_json::from_slice::<ExchangeRecord>(black_box(operation)).is_err());
    });
    let exchange = format!(
        r#"{{"v":"KERI10JSON0000bf_","t":"exn","d":"{SAID}","i":"{SENDER}","rp":"{RECIPIENT}","p":"","dt":"{STAMP}","r":"/multisig/icp","q":{{}},"a":{{"i":"{RECIPIENT}"}},"e":{{}}}}"#
    );
    criterion.bench_function("exchanges_decode_exchange", |bencher| {
        bencher.iter(|| serde_json::from_str::<ExchangeRecord>(black_box(&exchange)).is_ok());
    });
}

criterion_group!(benches, benchmark_exchanges);
criterion_main!(benches);
