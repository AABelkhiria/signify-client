//! Microbenchmark for the IPEX submission endpoint.
//!
//! This family adds very little to what Roadmap 6.3 already produced, and the benchmark is here to
//! say how little. Two things are measured.
//!
//! **The body.** A grant is the largest request any endpoint in this crate sends: three whole
//! embedded messages plus a CESR attachment chaining them, all of it already built. What this
//! module contributes is copying the exchange document into an ordered body beside the signatures,
//! the attachment, and the recipients — measured against an apply, which is the smallest.
//!
//! **The recipient list.** It is the one part a caller supplies freely and the only part that
//! scales, so it is measured from one recipient to sixty-four.
//!
//! Inputs: an apply-sized and a grant-sized exchange document, attachments of 0 and ~200 bytes, and
//! recipient lists of 1, 8, and 64.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::ExchangeOperation;
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::ipex::IPEX_SEGMENT;
use signify_http::request::ResourcePath;
use signify_keys::acdc::ipex::IpexRoute;

const SENDER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const HOLDER: &str = "ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k";
const CREDENTIAL: &str = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo";

/// The grant attachment the pinned reference produces, which is the largest this family sends.
const GRANT_ATTACHMENT: &str = concat!(
    "-LAg4AACA-e-acdc-IABEMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo0AAAAAAAAAAAAAAAAAAAAAAAENf3IEYwYtFmlq5Zz",
    "oI-zFzeR7E3ZNRN2YH_0KAFbdJW-LAW5AACAA-e-iss-VAS-GAB0AAAAAAAAAAAAAAAAAAAAAABECVCyxNpB4PJkpLbWqI02WXs1wf7VU",
    "xPNY2W28SN2qqm-LAa5AACAA-e-anc-AABAADMtDfNihvCSXJNp1VronVojcPGo--0YZ4Kh6CAnowRnn4Or4FgZQqaqCEv6XVS413qfZo",
    "Vp8j2uxTTPkItO7ED"
);

/// One exchange operation, the shape a submission is answered with.
const OPERATION: &str = concat!(
    r#"{"name":"exchange.EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-","#,
    r#""metadata":{"said":"EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-"},"done":true,"#,
    r#""response":{"said":"EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-"}}"#
);

/// A small exchange document, the size an apply carries.
///
/// `embeds` is the message's `e` block, which is empty for an apply and holds three messages for a
/// grant — the one field that makes the two sizes differ by an order of magnitude.
fn exchange_document(route: IpexRoute, embeds: Sad) -> Option<Sad> {
    let mut payload = Sad::new();
    payload.insert("i", HOLDER).ok()?;
    payload.insert("m", "Applying").ok()?;
    payload.insert("s", CREDENTIAL).ok()?;
    let mut exchange = Sad::new();
    exchange.insert("v", "KERI10JSON0001aa_").ok()?;
    exchange.insert("t", "exn").ok()?;
    exchange.insert("d", CREDENTIAL).ok()?;
    exchange.insert("i", SENDER).ok()?;
    exchange.insert("rp", HOLDER).ok()?;
    exchange.insert("p", "").ok()?;
    exchange.insert("dt", "2023-08-23T15:16:07.553000+00:00").ok()?;
    exchange.insert("r", route.as_str()).ok()?;
    exchange.insert("q", SadValue::Map(Sad::new())).ok()?;
    exchange.insert("a", SadValue::Map(payload)).ok()?;
    exchange.insert("e", SadValue::Map(embeds)).ok()?;
    Some(exchange)
}

/// The apply-sized document: no embedded messages at all.
fn apply_document() -> Option<Sad> {
    exchange_document(IpexRoute::Apply, Sad::new())
}

/// A large exchange document, the size a grant carries: three embedded messages.
fn grant_document() -> Option<Sad> {
    let mut embedded = Sad::new();
    for label in ["acdc", "iss", "anc"] {
        let mut message = Sad::new();
        message.insert("v", "KERI10JSON000197_").ok()?;
        message.insert("d", CREDENTIAL).ok()?;
        message.insert("i", SENDER).ok()?;
        message.insert("ri", CREDENTIAL).ok()?;
        message.insert("s", CREDENTIAL).ok()?;
        message.insert("dt", "2023-08-23T15:16:07.553000+00:00").ok()?;
        embedded.insert(label, SadValue::Map(message)).ok()?;
    }
    embedded.insert("d", CREDENTIAL).ok()?;
    exchange_document(IpexRoute::Grant, embedded)
}

/// Assembles a submission body the way the endpoint does.
fn body(exchange: &Sad, attachment: &str, recipients: &[String], carries: bool) -> Option<Vec<u8>> {
    let mut document = Sad::new();
    document.insert("exn", SadValue::Map(exchange.clone())).ok()?;
    document
        .insert("sigs", SadValue::Array(vec![SadValue::text("AAB")]))
        .ok()?;
    if carries {
        document.insert("atc", attachment.to_owned()).ok()?;
    }
    document
        .insert(
            "rec",
            SadValue::Array(recipients.iter().cloned().map(SadValue::Text).collect()),
        )
        .ok()?;
    document.to_json_bytes().ok()
}

fn benchmark_ipex(criterion: &mut Criterion) {
    // Addressing: one shape, five routes, all constant apart from the alias.
    criterion.bench_function("ipex_submission_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(IDENTIFIERS_SEGMENT)
                .segment(black_box("multisig"))
                .segment(IPEX_SEGMENT)
                .segment(black_box("grant"))
                .build()
                .is_ok()
        });
    });

    let (Some(apply), Some(grant)) = (apply_document(), grant_document()) else {
        return;
    };
    let one = vec![HOLDER.to_owned()];

    // The two ends of the body-size range: an apply with no attachment, a grant with the real one.
    criterion.bench_function("ipex_body_apply", |bencher| {
        bencher.iter(|| body(black_box(&apply), "", &one, false).is_some());
    });
    criterion.bench_function("ipex_body_grant", |bencher| {
        bencher.iter(|| body(black_box(&grant), GRANT_ATTACHMENT, &one, true).is_some());
    });

    // The recipient list is the only part that scales with what a caller asks for.
    for count in [1_usize, 8, 64] {
        let recipients: Vec<String> = core::iter::repeat_n(HOLDER.to_owned(), count).collect();
        criterion.bench_function(&format!("ipex_body_grant_recipients_{count}"), |bencher| {
            bencher.iter(|| body(&grant, GRANT_ATTACHMENT, black_box(&recipients), true).is_some());
        });
    }

    // Validating one recipient, which is what makes the list unable to carry anything else.
    criterion.bench_function("ipex_parse_recipient", |bencher| {
        bencher.iter(|| IdentifierPrefix::from_qb64(black_box(HOLDER)).is_ok());
    });

    // Reading the answer, which is the smallest response any family in this crate decodes.
    criterion.bench_function("ipex_decode_operation", |bencher| {
        bencher.iter(|| serde_json::from_str::<ExchangeOperation>(black_box(OPERATION)).is_ok());
    });
}

criterion_group!(benches, benchmark_ipex);
criterion_main!(benches);
