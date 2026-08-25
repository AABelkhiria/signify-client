#![no_main]

//! Fuzzes the notifications endpoint over hostile identifiers, windows, and agent pages.
//!
//! Three things come from outside. An **identifier** is a path component the reference concatenates
//! raw — Roadmap 5.3's own fixture recorded `notifications().mark("a?b=c")` turning the path into a
//! query — and Roadmap 3.10 signs `@path`. A **window** is the only place in this crate where a
//! caller's numbers reach a header, and upstream both bounds are stringified into a template. And a
//! **page** is an agent's answer that the reference does not type at all: `list` returns
//! `Promise<any>`, so nothing upstream stands between a caller and whatever arrived.
//!
//! The target asserts that nothing panics, that an identifier is always exactly one path segment
//! carrying no `/`, `?`, or `#`, that a window always writes two whole numbers under the right unit
//! and is never reversed, that a `Content-Range` either parses or is refused, and that a page
//! decodes into notifications that survive a round trip or is refused whole.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::notifications::{NOTIFICATION_RANGE_UNIT, NOTIFICATIONS_SEGMENT, NotificationListing};
use signify_http::request::{ItemRange, RangeUnit, ResourcePath};
use signify_http::response::ContentRange;
use signify_types::api::Notification;

/// Every character that would give a path component a meaning it did not have.
const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

/// Reads eight little-endian bytes, or zero when there are not eight.
fn word(data: &[u8], index: usize) -> u64 {
    let start = index.saturating_mul(8);
    let end = start.saturating_add(8);
    data.get(start..end)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map_or(0, u64::from_le_bytes)
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let bounds = parts.next().unwrap_or_default();
    let identifier = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let content_range = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let page = parts.next().unwrap_or_default();

    let Ok(unit) = RangeUnit::new(NOTIFICATION_RANGE_UNIT) else {
        return;
    };

    // -----------------------------------------------------------------------
    // The identifier: always exactly one path segment.
    // -----------------------------------------------------------------------
    if let Ok(path) = ResourcePath::builder()
        .segment(NOTIFICATIONS_SEGMENT)
        .segment(&identifier)
        .build()
    {
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        assert_eq!(segments.len(), 2, "an identifier became {} segments", segments.len());
        assert_eq!(segments.first().copied(), Some(NOTIFICATIONS_SEGMENT));
        for delimiter in PATH_DELIMITERS {
            assert!(
                !segments.get(1).copied().unwrap_or_default().contains(delimiter),
                "an encoded identifier still carries {delimiter:?}"
            );
        }
        assert_eq!(path.query(), None, "an identifier introduced a query");
    }

    // -----------------------------------------------------------------------
    // The window: two whole numbers, never reversed.
    // -----------------------------------------------------------------------
    let start = word(bounds, 0);
    let end = word(bounds, 1);
    match ItemRange::new(start, end) {
        Ok(window) => {
            assert!(start <= end, "a reversed window was accepted: {start}-{end}");
            assert_eq!(window.start(), start);
            assert_eq!(window.end(), end);
            let header = window.header_value(&unit);
            assert_eq!(header, format!("notes={start}-{end}"));
            assert!(!header.contains('.'), "a window wrote a fraction: {header}");
            // The end is inclusive, so a window always covers at least one position.
            assert!(window.count() >= 1);
        }
        Err(_) => assert!(end < start, "a valid window was refused: {start}-{end}"),
    }

    // -----------------------------------------------------------------------
    // The window the agent reports back.
    // -----------------------------------------------------------------------
    if let Ok(parsed) = ContentRange::parse(&content_range, &unit) {
        // A parsed window re-reads to the same three numbers, so a stored one is stable.
        let rendered = format!(
            "{} {}-{}/{}",
            NOTIFICATION_RANGE_UNIT,
            parsed.start(),
            parsed.end(),
            parsed.total()
        );
        let again = ContentRange::parse(&rendered, &unit);
        assert!(again.is_ok(), "a rendered window failed to re-parse: {rendered}");
        if let Ok(again) = again {
            assert_eq!(again.start(), parsed.start());
            assert_eq!(again.end(), parsed.end());
            assert_eq!(again.total(), parsed.total());
        }
    }

    // -----------------------------------------------------------------------
    // The page, which the reference does not type at all.
    // -----------------------------------------------------------------------
    let Ok(notifications) = serde_json::from_slice::<Vec<Notification>>(page) else {
        return;
    };
    let unread = notifications.iter().filter(|notification| !notification.read).count();

    let encoded = serde_json::to_vec(&notifications);
    assert!(encoded.is_ok(), "a decoded page failed to re-encode");
    let again = serde_json::from_slice::<Vec<Notification>>(&encoded.unwrap_or_default());
    assert!(again.is_ok(), "a re-encoded page failed to decode");
    if let Ok(again) = again {
        assert_eq!(again.len(), notifications.len(), "a round trip changed the page length");
        for (left, right) in again.iter().zip(&notifications) {
            assert_eq!(left.id, right.id, "a round trip changed an identifier");
            assert_eq!(left.read, right.read, "a round trip changed a read flag");
        }
    }

    // A listing's window and page never depend on each other.
    let listing = NotificationListing {
        window: None,
        notifications,
    };
    assert_eq!(listing.window, None);
    assert_eq!(listing.unread().count(), unread);
    assert!(listing.unread().all(|notification| !notification.read));
});
