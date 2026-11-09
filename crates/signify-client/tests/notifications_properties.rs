//! Invariants of the notifications endpoint.
//!
//! A window reaching a `Range` header cannot be a fraction or a reversed pair, and an identifier stays put.

mod support;

use std::error::Error;

use crate::support::fail;
use keria_types::api::Notification;
use proptest::prelude::*;
use serde_json::{Value, json};
use signify_client::endpoint::notifications::{NOTIFICATION_RANGE_UNIT, NOTIFICATIONS_SEGMENT, NotificationListing};
use signify_http::request::{ItemRange, RangeUnit, ResourcePath};
use signify_http::response::ContentRange;

const NONCE: &str = "0AADChEYHyYtNDtCSVBXXmVs";

fn unit() -> Result<RangeUnit, TestCaseError> {
    RangeUnit::new(NOTIFICATION_RANGE_UNIT).map_err(fail)
}

fn windows() -> impl Strategy<Value = ItemRange> {
    (0_u64..=1_000_000, 0_u64..=1_000).prop_filter_map("not a window", |(start, span)| {
        ItemRange::new(start, start.saturating_add(span)).ok()
    })
}

fn hostile_text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[\\PC]{0,48}",
        Just("a?b=c".to_owned()),
        Just("a/b".to_owned()),
        Just("../identifiers".to_owned()),
        Just("..".to_owned()),
        Just("x#y".to_owned()),
        Just(NONCE.to_owned()),
        Just(String::new()),
    ]
}

fn record_path(id: &str) -> Result<ResourcePath, TestCaseError> {
    ResourcePath::builder()
        .segment(NOTIFICATIONS_SEGMENT)
        .segment(id)
        .build()
        .map_err(fail)
}

const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn a_window_always_writes_two_whole_numbers(window in windows()) {
        let header = window.header_value(&unit()?);
        prop_assert!(header.starts_with("notes="), "the header was {}", header);
        prop_assert!(!header.contains('.'), "a window wrote a fraction: {}", header);
        prop_assert_eq!(header.matches('-').count(), 1);
        prop_assert_eq!(header, format!("notes={}-{}", window.start(), window.end()));
    }

    #[test]
    fn a_window_is_never_reversed(window in windows()) {
        prop_assert!(window.start() <= window.end());
        prop_assert_eq!(window.count(), window.end() - window.start() + 1);
        prop_assert!(window.count() >= 1);
    }

    #[test]
    fn a_reversed_window_is_always_refused(start in 1_u64..=100_000, span in 1_u64..=1_000) {
        let end = start.saturating_sub(span.min(start));
        prop_assume!(end < start);
        prop_assert!(ItemRange::new(start, end).is_err(), "{}-{} was accepted", start, end);
    }

    #[test]
    fn an_identifier_is_always_exactly_one_path_segment(id in hostile_text()) {
        let path = record_path(&id)?;
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(segments.len(), 2, "an identifier became {} segments", segments.len());
        prop_assert_eq!(segments.first().copied(), Some(NOTIFICATIONS_SEGMENT));
        prop_assert_eq!(path.query(), None, "an identifier introduced a query");
        for delimiter in PATH_DELIMITERS {
            prop_assert!(
                !segments.get(1).copied().unwrap_or_default().contains(delimiter),
                "an encoded identifier still carries {}",
                delimiter
            );
        }
    }

    #[test]
    fn a_qualified_nonce_reaches_the_path_unchanged(body in "[A-Za-z0-9_-]{22,43}", salt in any::<bool>()) {
        let nonce = if salt { format!("0A{body}") } else { format!("A{body}") };
        let path = record_path(&nonce)?;
        prop_assert_eq!(path.as_str(), format!("/{NOTIFICATIONS_SEGMENT}/{nonce}"));
        prop_assert_eq!(path.query(), None);
    }

    #[test]
    fn a_listing_keeps_its_window_apart_from_its_page(
        reported in proptest::option::of((0_u64..=1_000, 0_u64..=1_000, 0_u64..=10_000)),
        read in proptest::collection::vec(any::<bool>(), 0..8),
    ) {
        let page: Vec<Value> = read
            .iter()
            .map(|read| json!({"i": NONCE, "dt": "2023-01-01T00:00:00.000000+00:00", "r": read, "a": {}}))
            .collect();
        let notifications: Vec<Notification> =
            serde_json::from_value(Value::Array(page)).map_err(fail)?;

        let window = match reported {
            Some((start, span, total)) => {
                let end = start.saturating_add(span);
                let header = format!("notes {start}-{end}/{total}");
                Some(ContentRange::parse(&header, &unit()?).map_err(fail)?)
            }
            None => None,
        };
        let listing = NotificationListing { window, notifications };

        prop_assert_eq!(listing.notifications.len(), read.len());
        prop_assert_eq!(listing.window.is_some(), reported.is_some());
        prop_assert_eq!(listing.unread().count(), read.iter().filter(|read| !**read).count());
        prop_assert!(listing.unread().all(|notification| !notification.read));
    }

    #[test]
    fn a_notification_needs_every_declared_field(read in any::<bool>(), drop_field in 0_usize..5) {
        let mut document = json!({
            "i": NONCE,
            "dt": "2023-11-14T22:13:20.123000+00:00",
            "r": read,
            "a": {"r": "/multisig/icp"},
        });
        let dropped = ["i", "dt", "r", "a"].get(drop_field).copied();
        if let (Some(field), Some(object)) = (dropped, document.as_object_mut()) {
            object.remove(field);
        }
        let decoded = serde_json::from_value::<Notification>(document);
        if dropped.is_some() {
            prop_assert!(decoded.is_err(), "a notification missing a declared field was accepted");
        } else {
            let notification = decoded.map_err(fail)?;
            prop_assert_eq!(notification.id, NONCE);
            prop_assert_eq!(notification.read, read);
        }
    }
}

#[test]
fn the_pinned_window_writes_the_pinned_header() -> Result<(), Box<dyn Error>> {
    let unit = RangeUnit::new(NOTIFICATION_RANGE_UNIT)?;
    assert_eq!(ItemRange::new(20, 40)?.header_value(&unit), "notes=20-40");
    assert_eq!(ItemRange::DEFAULT.header_value(&unit), "notes=0-24");
    Ok(())
}

#[test]
fn a_single_position_window_asks_for_one_notification() -> Result<(), Box<dyn Error>> {
    let unit = RangeUnit::new(NOTIFICATION_RANGE_UNIT)?;
    let window = ItemRange::new(0, 0)?;
    assert_eq!(window.count(), 1);
    assert_eq!(window.header_value(&unit), "notes=0-0");
    Ok(())
}

#[test]
fn an_identifier_of_two_dots_stays_one_segment() -> Result<(), Box<dyn Error>> {
    let path = ResourcePath::builder()
        .segment(NOTIFICATIONS_SEGMENT)
        .segment("..")
        .build()?;
    assert_eq!(path.as_str(), "/notifications/..");
    assert_eq!(path.path().split('/').count(), 3);
    Ok(())
}

#[test]
fn an_empty_page_an_empty_window_and_no_window_are_distinct() -> Result<(), Box<dyn Error>> {
    let unit = RangeUnit::new(NOTIFICATION_RANGE_UNIT)?;
    let unreported = NotificationListing {
        window: None,
        notifications: Vec::new(),
    };
    let empty_window = NotificationListing {
        window: Some(ContentRange::parse("notes 0-0/0", &unit)?),
        notifications: Vec::new(),
    };
    let full_page_no_window = NotificationListing {
        window: None,
        notifications: serde_json::from_str(&format!(
            r#"[{{"i":"{NONCE}","dt":"2023-01-01T00:00:00.000000+00:00","r":false,"a":{{}}}}]"#
        ))?,
    };

    assert_ne!(unreported.window, empty_window.window);
    assert_eq!(unreported.window, full_page_no_window.window);
    assert_ne!(unreported.notifications.len(), full_page_no_window.notifications.len());
    assert_eq!(empty_window.window.map(ContentRange::total), Some(0));
    Ok(())
}
