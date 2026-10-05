//! Property and invalid-near-miss coverage for reply messages and their timestamps.

use keri_cesr::crypto::digest::DigestAlgorithm;
use proptest::{prelude::*, test_runner::TestCaseError};
use signify_keri::event::EventError;
use signify_keri::event::reply::{MAX_ROUTE_BYTES, ReplyBuilder};
use signify_keri::event::timestamp::Timestamp;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

/// Generates well-formed timestamps across the whole accepted range.
fn timestamp_strategy() -> impl Strategy<Value = String> {
    (
        0_u32..=9999,
        1_u32..=12,
        1_u32..=31,
        0_u32..=23,
        0_u32..=59,
        0_u32..=60,
        0_u32..=999_999,
        prop_oneof![Just('+'), Just('-')],
        0_u32..=23,
        0_u32..=59,
    )
        .prop_map(
            |(year, month, day, hour, minute, second, fraction, sign, offset_hour, offset_minute)| {
                format!(
                    "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{fraction:06}{sign}{offset_hour:02}:{offset_minute:02}"
                )
            },
        )
}

fn route_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("/end/role/add".to_owned()),
        Just("/loc/scheme".to_owned()),
        "/[a-z]{1,8}(/[a-z]{1,8}){0,3}",
        "[ -~\\u{80}-\\u{2ff}]{0,40}",
    ]
}

fn attributes_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
    proptest::collection::vec(("[a-z]{1,6}", "[ -~\\u{80}-\\u{2ff}]{0,24}"), 0..5)
}

fn build_attributes(pairs: &[(String, String)]) -> Sad {
    let mut attributes = Sad::new();
    for (label, value) in pairs {
        // Duplicate labels are rejected by `Sad`, so later ones are simply skipped.
        let _ = attributes.insert(label.clone(), SadValue::text(value.clone()));
    }
    attributes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(160))]

    /// Every well-formed timestamp round trips through its canonical text unchanged.
    #[test]
    fn timestamps_round_trip(text in timestamp_strategy()) {
        let stamp = fail(Timestamp::parse(&text))?;
        prop_assert_eq!(stamp.as_str(), text.as_str());
        prop_assert_eq!(stamp.to_string(), text.clone());
        prop_assert_eq!(text.len(), Timestamp::LENGTH);
        prop_assert_eq!(fail(text.parse::<Timestamp>())?, stamp);
    }

    /// Mutating any single byte of a valid timestamp either keeps it valid or is refused; it never
    /// panics and never silently repairs the input.
    #[test]
    fn mutated_timestamps_are_rejected_or_canonical(
        text in timestamp_strategy(),
        position in 0_usize..Timestamp::LENGTH,
        replacement in 0x20_u8..0x7f,
    ) {
        let mut bytes = text.clone().into_bytes();
        let Some(slot) = bytes.get_mut(position) else {
            return Err(TestCaseError::fail("position outside the timestamp"));
        };
        *slot = replacement;
        let Ok(mutated) = String::from_utf8(bytes) else {
            return Err(TestCaseError::fail("mutation produced invalid UTF-8"));
        };

        if let Ok(stamp) = Timestamp::parse(&mutated) {
            // Anything accepted reproduces itself exactly.
            prop_assert_eq!(stamp.as_str(), mutated.as_str());
        }
    }

    /// Hostile text never panics the parser, and anything accepted is canonical.
    #[test]
    fn hostile_text_is_rejected_or_canonical(text in "[-+:.T0-9A-Za-z ]{0,48}") {
        if let Ok(stamp) = Timestamp::parse(&text) {
            prop_assert_eq!(stamp.as_str(), text.as_str());
            prop_assert_eq!(text.len(), Timestamp::LENGTH);
        }
    }

    /// Any reply the builder accepts is self-consistent and verifiable by a recipient.
    #[test]
    fn replies_are_self_consistent(
        route in route_strategy(),
        stamp in timestamp_strategy(),
        attributes in attributes_strategy(),
    ) {
        let timestamp = fail(Timestamp::parse(&stamp))?;
        let reply = fail(
            ReplyBuilder::new(route.clone(), timestamp)
                .attributes(build_attributes(&attributes))
                .build(),
        )?;

        // Declared size, byte length, and reparsed content all agree.
        prop_assert_eq!(reply.serialized().size(), reply.raw().len());
        let reparsed = fail(SerializedEvent::parse(reply.raw()))?;
        prop_assert_eq!(reparsed.sad(), reply.sad());

        // The message carries exactly what it was told to.
        prop_assert_eq!(reply.route(), Some(route.as_str()));
        prop_assert_eq!(reply.sad().get_text("dt"), Some(stamp.as_str()));
        prop_assert_eq!(reply.sad().get_text("t"), Some("rpy"));

        // A reply carries an ordinary SAID, so the ordinary check recomputes it.
        let said = fail(reply.said().qb64())?;
        prop_assert_eq!(reply.sad().get_text("d"), Some(said.as_str()));
        fail(reply.said().verify(reply.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict()))?;
        let recomputed = fail(Said::compute(reply.sad(), DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;
        prop_assert_eq!(recomputed.said(), &reply.said());
    }

    /// Building the same reply twice is deterministic, and any change to any input changes the
    /// identifier -- which is what makes a signature over it meaningful.
    #[test]
    fn every_input_is_committed_to(
        route in route_strategy(),
        stamp in timestamp_strategy(),
        attributes in attributes_strategy(),
    ) {
        let timestamp = fail(Timestamp::parse(&stamp))?;
        let build = |route: String, stamp: Timestamp, attributes: &[(String, String)]| {
            ReplyBuilder::new(route, stamp)
                .attributes(build_attributes(attributes))
                .build()
        };

        let first = fail(build(route.clone(), timestamp.clone(), &attributes))?;
        let second = fail(build(route.clone(), timestamp.clone(), &attributes))?;
        prop_assert_eq!(first.raw(), second.raw());

        // A different route is a different message.
        let other_route = format!("{route}/other");
        if other_route.len() <= MAX_ROUTE_BYTES {
            let changed = fail(build(other_route, timestamp.clone(), &attributes))?;
            prop_assert_ne!(changed.said(), first.said());
        }

        // So is a different timestamp.
        let later = fail(Timestamp::parse("2099-01-01T00:00:00.000000+00:00"))?;
        if later != timestamp {
            let changed = fail(build(route, later, &attributes))?;
            prop_assert_ne!(changed.said(), first.said());
        }
    }

    /// The route bound is enforced in bytes, not characters.
    #[test]
    fn routes_are_bounded_in_bytes(length in 0_usize..=64, multi_byte in any::<bool>()) {
        let unit = if multi_byte { "ü" } else { "x" };
        let route = unit.repeat(length);
        let timestamp = fail(Timestamp::parse("2021-06-27T21:26:21.233257+00:00"))?;

        let built = ReplyBuilder::new(route.clone(), timestamp).build();
        // Everything this short is accepted whichever unit it uses.
        let reply = fail(built)?;
        prop_assert_eq!(reply.route(), Some(route.as_str()));
        // The version string counts bytes, so a multi-byte route is longer than its length.
        prop_assert_eq!(reply.serialized().size(), reply.raw().len());
        prop_assert!(reply.raw().len() >= route.len());
    }

    /// An overlong route is refused rather than truncated.
    #[test]
    fn overlong_routes_are_refused(excess in 1_usize..=32) {
        let route = "/".repeat(MAX_ROUTE_BYTES + excess);
        let timestamp = fail(Timestamp::parse("2021-06-27T21:26:21.233257+00:00"))?;
        prop_assert!(matches!(
            ReplyBuilder::new(route, timestamp).build(),
            Err(EventError::RouteTooLong { .. })
        ), "an overlong route was accepted");
    }
}
