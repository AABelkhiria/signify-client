//! Property and invalid-near-miss coverage for version strings and event kinds.

use std::str::FromStr;

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_keri::event::kind::EventKind;
use signify_keri::serialization::{Protocol, ProtocolVersion, SerializationKind, VersionString};

fn version_value<T>(result: Result<T, signify_keri::serialization::VersionError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn protocol_strategy() -> impl Strategy<Value = Protocol> {
    prop_oneof![Just(Protocol::Keri), Just(Protocol::Acdc)]
}

fn event_kind_strategy() -> impl Strategy<Value = EventKind> {
    proptest::sample::select(EventKind::ALL.as_slice())
}

proptest! {
    #[test]
    fn every_valid_version_string_round_trips_canonically(
        protocol in protocol_strategy(),
        major in 0_u8..=15,
        minor in 0_u8..=15,
        size in 0_u32..=VersionString::MAX_SIZE,
    ) {
        let version = version_value(ProtocolVersion::new(major, minor))?;
        let built = version_value(VersionString::new(
            protocol,
            version,
            SerializationKind::Json,
            size,
        ))?;
        let text = built.to_string();
        prop_assert_eq!(text.len(), VersionString::FULL_SIZE);
        prop_assert!(text.ends_with('_'));
        let reparsed = version_value(VersionString::from_str(&text))?;
        prop_assert_eq!(reparsed, built);
        prop_assert_eq!(reparsed.to_string(), text);
    }

    #[test]
    fn out_of_range_construction_is_always_rejected(
        protocol in protocol_strategy(),
        size in (VersionString::MAX_SIZE + 1)..=u32::MAX,
        component in 16_u8..=u8::MAX,
    ) {
        prop_assert!(VersionString::new(
            protocol,
            ProtocolVersion::V1_0,
            SerializationKind::Json,
            size,
        ).is_err());
        prop_assert!(ProtocolVersion::new(component, 0).is_err());
        prop_assert!(ProtocolVersion::new(0, component).is_err());
    }

    #[test]
    fn corrupting_any_position_with_an_invalid_byte_rejects(
        protocol in protocol_strategy(),
        size in 0_u32..=VersionString::MAX_SIZE,
        position in 0_usize..VersionString::FULL_SIZE,
        corruption in prop_oneof![Just('!'), Just(' '), Just('~'), Just('\u{0}')],
    ) {
        let built = version_value(VersionString::new(
            protocol,
            ProtocolVersion::V1_0,
            SerializationKind::Json,
            size,
        ))?;
        let mut characters: Vec<char> = built.to_string().chars().collect();
        if let Some(target) = characters.get_mut(position) {
            *target = corruption;
        }
        let corrupted: String = characters.iter().collect();
        prop_assert!(VersionString::from_str(&corrupted).is_err());
    }

    #[test]
    fn any_non_full_length_input_rejects(
        protocol in protocol_strategy(),
        size in 0_u32..=VersionString::MAX_SIZE,
        cut in 0_usize..VersionString::FULL_SIZE,
        suffix in "[A-Za-z0-9_-]{1,8}",
    ) {
        let built = version_value(VersionString::new(
            protocol,
            ProtocolVersion::V1_0,
            SerializationKind::Json,
            size,
        ))?;
        let text = built.to_string();
        let truncated: String = text.chars().take(cut).collect();
        prop_assert!(VersionString::from_str(&truncated).is_err());
        let extended = format!("{text}{suffix}");
        prop_assert!(VersionString::from_str(&extended).is_err());
    }

    #[test]
    fn uppercase_hexadecimal_digits_are_never_accepted(
        size in 0_u32..=VersionString::MAX_SIZE,
    ) {
        let built = version_value(VersionString::new(
            Protocol::Keri,
            ProtocolVersion::V1_0,
            SerializationKind::Json,
            size,
        ))?;
        let text = built.to_string();
        let uppercase_size: String = text
            .char_indices()
            .map(|(index, character)| {
                if (10..16).contains(&index) {
                    character.to_ascii_uppercase()
                } else {
                    character
                }
            })
            .collect();
        if uppercase_size == text {
            // All-digit sizes have no letter to change; canonical text must still parse.
            prop_assert!(VersionString::from_str(&text).is_ok());
        } else {
            prop_assert!(VersionString::from_str(&uppercase_size).is_err());
        }
    }

    #[test]
    fn event_kinds_round_trip_and_near_misses_reject(
        kind in event_kind_strategy(),
        noise in "[a-z]{1,4}",
    ) {
        let reparsed = EventKind::from_str(kind.as_str())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(reparsed, kind);
        prop_assert_eq!(kind.to_string(), kind.as_str());

        let uppercase = kind.as_str().to_ascii_uppercase();
        prop_assert!(EventKind::from_str(&uppercase).is_err());
        let padded = format!("{} ", kind.as_str());
        prop_assert!(EventKind::from_str(&padded).is_err());

        let in_table = EventKind::ALL.iter().any(|entry| entry.as_str() == noise);
        prop_assert_eq!(EventKind::from_str(&noise).is_ok(), in_table);
    }
}
