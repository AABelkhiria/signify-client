//! Microbenchmark for the contacts endpoint family.
//!
//! One thing here is genuinely unbounded and not measured anywhere else: **a listing has no
//! paging**. No range, no limit, no cursor — an agent holding many contacts answers with all of
//! them in one body, so the decode scales with the address book rather than with the request. That
//! is the number worth having.
//!
//! Beside it: the two address shapes, and the write body, which is the first caller-authored open
//! document any family in this crate sends.
//!
//! Inputs: a 44-character prefix; listings of 1, 32, and 256 contacts; info bodies of 2, 16, and 64
//! fields.
//!
//! As everywhere in this crate, all of it is small beside one signed request, whose signature alone
//! the `lifecycle` benchmark measured at ~25 µs.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::Contact;
use signify_client::endpoint::contacts::{
    ALIAS_FIELD, CONTACTS_SEGMENT, ContactFilter, FILTER_FIELD_PARAMETER, FILTER_VALUE_PARAMETER, GROUP_PARAMETER,
};
use signify_http::request::ResourcePath;

const CONTACT: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";

/// A listing of `count` contacts, of the shape KERIA answers with.
fn listing(count: usize) -> String {
    let entries: Vec<String> = (0..count)
        .map(|index| {
            format!(
                r#"{{"id":"{CONTACT}","alias":"contact{index}","oobi":"http://127.0.0.1:3901/oobi/{CONTACT}/agent/{AGENT}","challenges":[],"wellKnowns":[],"company":"Company {index}"}}"#
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

/// A contact info body of `count` fields, in the caller's own order.
fn info(count: usize) -> Sad {
    let mut info = Sad::new();
    for index in 0..count {
        let _ = info.insert(format!("field{index}"), SadValue::text(format!("value {index}")));
    }
    info
}

fn benchmark_contacts(criterion: &mut Criterion) {
    let Ok(prefix) = IdentifierPrefix::from_qb64(CONTACT) else {
        return;
    };
    let Ok(text) = prefix.qb64() else { return };

    // Addressing: one record, and a listing with every combination of its two filters.
    criterion.bench_function("contacts_record_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(CONTACTS_SEGMENT)
                .segment(black_box(&text))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("contacts_listing_path_unfiltered", |bencher| {
        bencher.iter(|| ResourcePath::builder().segment(CONTACTS_SEGMENT).build().is_ok());
    });
    let filter = ContactFilter::alias("^alice$");
    criterion.bench_function("contacts_listing_path_filtered", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(CONTACTS_SEGMENT)
                .optional_parameter(GROUP_PARAMETER, black_box(Some("mygroup")))
                .parameter(FILTER_FIELD_PARAMETER, black_box(&filter.field))
                .parameter(FILTER_VALUE_PARAMETER, black_box(&filter.value))
                .build()
                .is_ok()
        });
    });
    criterion.bench_function("contacts_filter_build", |bencher| {
        bencher.iter(|| ContactFilter::new(black_box(ALIAS_FIELD), black_box("^alice$")));
    });

    // Writing: the body `add` and `update` share, as a caller's document grows.
    for count in [2_usize, 16, 64] {
        let body = info(count);
        criterion.bench_function(&format!("contacts_info_body_{count}_fields"), |bencher| {
            bencher.iter(|| black_box(&body).to_json_bytes().is_ok());
        });
    }

    // Reading: the unbounded one. A listing decodes every contact the agent holds.
    for count in [1_usize, 32, 256] {
        let document = listing(count);
        criterion.bench_function(&format!("contacts_decode_listing_{count}"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Vec<Contact>>(black_box(&document)).is_ok());
        });
    }
    let single = listing(1);
    criterion.bench_function("contacts_decode_one", |bencher| {
        bencher.iter(|| serde_json::from_str::<Vec<Contact>>(black_box(&single)).is_ok());
    });
}

criterion_group!(benches, benchmark_contacts);
criterion_main!(benches);
