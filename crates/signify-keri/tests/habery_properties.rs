//! Invariants of the habitat registry.
//!
//! Every salty case uses the ephemeral derivation cost. The production profile costs 64 MiB per
//! key, which a property test would multiply by its case count; the composition under test does
//! not depend on the profile, and the cross-language vectors cover the production one exactly.

use proptest::prelude::*;
use signify_crypto::salt::{Salt, SecurityTier};
use signify_crypto::verifier::KeyTransferability;
use signify_keri::event::kind::EventKind;
use signify_keri::identifier::{Habery, Habitat, HabitatRequest, IdentifierError};
use signify_keri::manager::DerivationCost;
use signify_keri::serialization::{SadValue, SerializedEvent};
use signify_keri::threshold::SigningThreshold;

fn salt() -> Result<Salt, TestCaseError> {
    Salt::from_raw(b"0123456789abcdef", SecurityTier::Low).map_err(|error| TestCaseError::fail(error.to_string()))
}

fn ephemeral(name: &str) -> Result<Habery, TestCaseError> {
    Habery::builder(name)
        .salt(salt()?)
        .derivation_cost(DerivationCost::Ephemeral)
        .build()
        .map_err(|error| TestCaseError::fail(error.to_string()))
}

fn text_field(habitat: &Habitat, label: &str) -> Option<String> {
    habitat.inception().sad().get_text(label).map(str::to_owned)
}

fn list_len(habitat: &Habitat, label: &str) -> usize {
    match habitat.inception().sad().get(label) {
        Some(SadValue::Array(items)) => items.len(),
        _ => usize::MAX,
    }
}

proptest! {
    /// The same name, salt, and request always produce the same event bytes, and a different
    /// registry name produces different keys.
    #[test]
    fn habitat_creation_is_deterministic(
        name in "[a-z]{1,12}",
        count in 1_usize..5,
    ) {
        let request = HabitatRequest { current_keys: count, ..HabitatRequest::default() };
        let mut first = ephemeral(&name)?;
        let mut second = ephemeral(&name)?;
        let left = first.make_habitat("test", request.clone())?.inception().raw().to_vec();
        let right = second.make_habitat("test", request.clone())?.inception().raw().to_vec();
        prop_assert_eq!(&left, &right);

        let mut renamed = ephemeral(&format!("{name}x"))?;
        let other = renamed.make_habitat("test", request)?.inception().raw().to_vec();
        prop_assert_ne!(left, other);
    }

    /// The default thresholds are the reference's majority formula on both sides, written in
    /// lowercase hexadecimal, over however many keys the habitat has.
    #[test]
    fn default_thresholds_are_the_reference_majorities(count in 1_usize..26) {
        let mut habery = ephemeral("signify")?;
        let habitat = habery.make_habitat(
            "test",
            HabitatRequest { current_keys: count, ..HabitatRequest::default() },
        )?;
        let expected = format!("{:x}", 1.max(count.div_ceil(2)));
        prop_assert_eq!(text_field(habitat, "kt"), Some(expected.clone()));
        prop_assert_eq!(text_field(habitat, "nt"), Some(expected));
        prop_assert_eq!(list_len(habitat, "k"), count);
        prop_assert_eq!(list_len(habitat, "n"), count);
    }

    /// An explicit signing threshold carries over to the next keys exactly when no next threshold
    /// is given, as the reference's `nsith ??= isith` does.
    #[test]
    fn an_explicit_signing_threshold_propagates(
        count in 1_usize..6,
        threshold in 1_u128..6,
        explicit_next in proptest::option::of(1_u128..6),
    ) {
        prop_assume!(threshold <= count as u128);
        if let Some(next) = explicit_next {
            prop_assume!(next <= count as u128);
        }
        let mut habery = ephemeral("signify")?;
        let habitat = habery.make_habitat(
            "test",
            HabitatRequest {
                current_keys: count,
                signing_threshold: Some(SigningThreshold::numeric(threshold)),
                next_threshold: explicit_next.map(SigningThreshold::numeric),
                ..HabitatRequest::default()
            },
        )?;
        let expected_next = explicit_next.unwrap_or(threshold);
        prop_assert_eq!(text_field(habitat, "kt"), Some(format!("{threshold:x}")));
        prop_assert_eq!(text_field(habitat, "nt"), Some(format!("{expected_next:x}")));
    }

    /// A non-transferable habitat always has a basic `B` prefix, no next keys, and a zero next
    /// threshold; more than one key is refused, because a basic prefix is a single key.
    #[test]
    fn a_non_transferable_habitat_commits_to_nothing(count in 1_usize..4) {
        let mut habery = ephemeral("signify")?;
        let request = HabitatRequest {
            current_keys: count,
            transferability: KeyTransferability::NonTransferable,
            ..HabitatRequest::default()
        };
        if count == 1 {
            let habitat = habery.make_habitat("test", request)?;
            prop_assert!(habitat.prefix().qb64().is_ok_and(|qb64| qb64.starts_with('B')));
            prop_assert!(!habitat.prefix().is_transferable());
            prop_assert_eq!(text_field(habitat, "nt"), Some("0".to_owned()));
            prop_assert_eq!(list_len(habitat, "n"), 0);
        } else {
            let refused = matches!(
                habery.make_habitat("test", request),
                Err(IdentifierError::BasicDerivationNeedsOneKey { .. })
            );
            prop_assert!(refused);
            prop_assert_eq!(habery.manager().prefix_index(), 0);
        }
    }

    /// Every accepted event is self-consistent: it reparses to the same field map, agrees with its
    /// declared size, and its identifier is the digest the event claims.
    #[test]
    fn every_habitat_event_is_self_consistent(
        name in "[a-z]{0,8}",
        count in 1_usize..4,
        transferable in any::<bool>(),
    ) {
        let mut habery = ephemeral(&name)?;
        let request = HabitatRequest {
            current_keys: if transferable { count } else { 1 },
            transferability: if transferable {
                KeyTransferability::Transferable
            } else {
                KeyTransferability::NonTransferable
            },
            ..HabitatRequest::default()
        };
        let habitat = habery.make_habitat("test", request)?;
        let event = habitat.inception();
        prop_assert_eq!(event.kind(), EventKind::Inception);
        prop_assert_eq!(event.sequence_number(), 0);
        prop_assert_eq!(event.serialized().size(), event.raw().len());
        let reparsed = SerializedEvent::parse(event.raw())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(reparsed.sad(), event.sad());
        if transferable {
            // The default derivation digests the event, so the identifier is its own SAID.
            prop_assert_eq!(
                event.identifier().qb64().ok(),
                event.said().qb64().ok()
            );
        }
    }

    /// The event's signing keys are exactly the keys the manager filed, so what the event names
    /// can actually sign.
    #[test]
    fn the_event_keys_are_the_managed_keys(name in "[a-z]{1,8}", count in 1_usize..4) {
        let mut habery = ephemeral(&name)?;
        let habitat = habery
            .make_habitat(
                "test",
                HabitatRequest { current_keys: count, ..HabitatRequest::default() },
            )?
            .clone();
        let Some(SadValue::Array(items)) = habitat.inception().sad().get("k") else {
            return Err(TestCaseError::fail("the event has no key list"));
        };
        let Some(SadValue::Text(first)) = items.first() else {
            return Err(TestCaseError::fail("the key list is empty"));
        };
        // The manager files the identifier under its first public key, as the reference leaves it.
        let situation = habery
            .manager()
            .store()
            .situation(first)
            .ok_or_else(|| TestCaseError::fail("the manager has no state for the habitat"))?;
        let keys: Vec<String> = items
            .iter()
            .filter_map(|item| match item {
                SadValue::Text(text) => Some(text.clone()),
                _ => None,
            })
            .collect();
        prop_assert_eq!(&situation.current.public_keys, &keys);
    }

    /// A refused request never advances the manager: the pre-checks run before any key derives.
    #[test]
    fn a_refused_request_leaves_the_manager_untouched(
        threshold in 3_u128..10,
        count in 1_usize..3,
    ) {
        prop_assume!(threshold > count as u128);
        let mut habery = ephemeral("signify")?;
        let refused = habery
            .make_habitat(
                "test",
                HabitatRequest {
                    current_keys: count,
                    signing_threshold: Some(SigningThreshold::numeric(threshold)),
                    ..HabitatRequest::default()
                },
            )
            .is_err();
        prop_assert!(refused);
        prop_assert_eq!(habery.manager().prefix_index(), 0);
        prop_assert!(habery.habitats().is_empty());
        prop_assert!(habery.habitat_by_name("test").is_none());
    }

    /// An empty-name registry can hold several habitats; every name is registered once, lookup
    /// finds each, and a duplicate is refused without touching the manager.
    #[test]
    fn registration_and_lookup_are_consistent(count in 1_usize..5) {
        let mut habery = ephemeral("")?;
        let names: Vec<String> = (0..count).map(|index| format!("habitat-{index}")).collect();
        for name in &names {
            habery.make_habitat(name.clone(), HabitatRequest::default())?;
        }
        let expected_index =
            u32::try_from(count).map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(habery.habitats().len(), count);
        prop_assert_eq!(habery.manager().prefix_index(), expected_index);
        let listed: Vec<&str> = habery.habitats().iter().map(Habitat::name).collect();
        prop_assert_eq!(&listed, &names.iter().map(String::as_str).collect::<Vec<_>>());
        for name in &names {
            prop_assert_eq!(habery.habitat_by_name(name).map(Habitat::name), Some(name.as_str()));
        }
        let first = names
            .first()
            .cloned()
            .ok_or_else(|| TestCaseError::fail("no habitat names were generated"))?;
        let refused = matches!(
            habery.make_habitat(first, HabitatRequest::default()),
            Err(IdentifierError::DuplicateHabitat { .. })
        );
        prop_assert!(refused);
        prop_assert_eq!(habery.manager().prefix_index(), expected_index);
    }
}
