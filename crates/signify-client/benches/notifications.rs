//! Microbenchmark for the notifications endpoint family.
//!
//! One thing here is worth measuring and is not measured elsewhere: **a page is windowed, and the
//! window is the caller's**. Roadmap 7.3's contact listing has no paging at all and its decode
//! scales with the whole address book; this one scales with whatever page was asked for, so the
//! interesting number is what a page *costs* as it grows — which is what tells a caller how large a
//! window is reasonable.
//!
//! Beside it: the two address shapes, the `Range` header, and reading a `Content-Range` back.
//!
//! Inputs: windows of 1, 25, and 250 positions; pages of 1, 25, and 250 notifications; a 24-character
//! qualified nonce.
//!
//! As everywhere in this crate, all of it is small beside one signed request, whose signature alone
//! Roadmap 6.4 measured at ~25 µs.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keria_types::api::Notification;
use signify_client::endpoint::notifications::{NOTIFICATION_RANGE_UNIT, NOTIFICATIONS_SEGMENT};
use signify_http::request::{ItemRange, RangeUnit, ResourcePath};
use signify_http::response::ContentRange;

/// A notification identifier of the shape a KERIA agent produces.
const NONCE: &str = "0AADChEYHyYtNDtCSVBXXmVs";

/// A page of `count` notifications, of the shape KERIA answers with.
fn page(count: usize) -> String {
    let entries: Vec<String> = (0..count)
        .map(|index| {
            format!(
                r#"{{"i":"{NONCE}","dt":"2023-11-14T22:13:20.123000+00:00","r":{read},"a":{{"r":"/multisig/icp","d":"EPb8JgedkvOGMn7iw9y9L3gwo8uvBifSQenEbxyTbtIz","m":""}}}}"#,
                read = index % 2 == 0
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

fn benchmark_notifications(criterion: &mut Criterion) {
    let Ok(unit) = RangeUnit::new(NOTIFICATION_RANGE_UNIT) else {
        return;
    };

    // Addressing: the listing's constant path, and one notification's.
    criterion.bench_function("notifications_listing_path", |bencher| {
        bencher.iter(|| ResourcePath::builder().segment(NOTIFICATIONS_SEGMENT).build().is_ok());
    });
    criterion.bench_function("notifications_record_path", |bencher| {
        bencher.iter(|| {
            ResourcePath::builder()
                .segment(NOTIFICATIONS_SEGMENT)
                .segment(black_box(NONCE))
                .build()
                .is_ok()
        });
    });

    // The window: written into a `Range`, and read back out of a `Content-Range`.
    for span in [1_u64, 25, 250] {
        let Ok(window) = ItemRange::new(0, span.saturating_sub(1)) else {
            continue;
        };
        criterion.bench_function(&format!("notifications_range_header_{span}"), |bencher| {
            bencher.iter(|| black_box(window).header_value(black_box(&unit)));
        });
    }
    criterion.bench_function("notifications_parse_content_range", |bencher| {
        bencher.iter(|| ContentRange::parse(black_box("notes 20-40/100"), black_box(&unit)).is_ok());
    });

    // Reading: the page, as the window a caller asked for grows.
    for count in [1_usize, 25, 250] {
        let document = page(count);
        criterion.bench_function(&format!("notifications_decode_page_{count}"), |bencher| {
            bencher.iter(|| serde_json::from_str::<Vec<Notification>>(black_box(&document)).is_ok());
        });
    }
}

criterion_group!(benches, benchmark_notifications);
criterion_main!(benches);
