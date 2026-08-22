#![no_main]

//! Fuzzes habitat creation: registry names, habitat names, and the whole request surface.
//!
//! A registry name is caller-chosen text that becomes a derivation stem, and a request mixes
//! counts, thresholds, transferability, witnesses, and delegation in combinations the reference
//! silently rewrites. The target asserts that nothing panics, that every rejection is a typed
//! [`IdentifierError`] with a non-empty description, that an accepted event is self-consistent —
//! it reparses to the same field map, agrees with its declared size, and its identifier is the
//! digest or key it claims — and that a refused pre-check never advances the manager.
//!
//! Every derivation uses the ephemeral cost; the production profile is covered by the
//! cross-language vectors, and the composition under test does not depend on it.

use libfuzzer_sys::fuzz_target;
use signify_crypto::salt::{Salt, SecurityTier};
use signify_crypto::verifier::KeyTransferability;
use signify_keri::identifier::{Habery, HabitatRequest, IdentifierError};
use signify_keri::manager::DerivationCost;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::serialization::SerializedEvent;
use signify_keri::threshold::SigningThreshold;

/// A valid witness prefix for requests that name one; the value only has to parse.
const WITNESS: &str = "BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ";
/// A valid self-addressing delegator for delegated requests.
const DELEGATOR: &str = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C";

fuzz_target!(|data: &[u8]| {
    let [b0, b1, b2, b3, b4, name_bytes @ ..] = data else {
        return;
    };
    let name = String::from_utf8_lossy(name_bytes).into_owned();

    let Ok(salt) = Salt::from_raw(b"0123456789abcdef", SecurityTier::Low) else {
        return;
    };
    let mut habery = match Habery::builder(name.clone())
        .salt(salt)
        .derivation_cost(DerivationCost::Ephemeral)
        .prefix_index(u32::from(*b4))
        .build()
    {
        Ok(habery) => habery,
        Err(error) => {
            // The only way a salty registry fails to build is an oversized name.
            assert!(matches!(&error, IdentifierError::Manager { .. }), "{error:?}");
            assert!(!error.to_string().is_empty());
            return;
        }
    };
    assert_eq!(habery.name(), name);

    let transferability = if b0 & 1 == 0 {
        KeyTransferability::Transferable
    } else {
        KeyTransferability::NonTransferable
    };
    let witnesses = match b3 & 3 {
        0 => Vec::new(),
        1 => IdentifierPrefix::from_qb64(WITNESS).into_iter().collect(),
        // A duplicated witness, which must always be refused.
        _ => IdentifierPrefix::from_qb64(WITNESS)
            .into_iter()
            .chain(IdentifierPrefix::from_qb64(WITNESS))
            .collect(),
    };
    let request = HabitatRequest {
        current_keys: usize::from(b0 >> 1),
        next_keys: (b1 & 1 == 1).then_some(usize::from(b1 >> 1)),
        signing_threshold: (b2 & 1 == 1).then(|| SigningThreshold::numeric(u128::from(b2 >> 4))),
        next_threshold: (b2 & 2 == 2).then(|| SigningThreshold::numeric(u128::from(b2 >> 5))),
        transferability,
        derivation: None,
        witnesses,
        witness_threshold: (b3 & 4 == 4).then_some(u32::from(b3 >> 3)),
        delegator: (b3 & 8 == 8)
            .then(|| IdentifierPrefix::from_qb64(DELEGATOR).ok())
            .flatten(),
        configuration: Vec::new(),
        anchors: Vec::new(),
    };

    let prefix_index_before = habery.manager().prefix_index();
    match habery.make_habitat("fuzzed", request) {
        Ok(habitat) => {
            let event = habitat.inception();
            // The event agrees with its own declared size and reparses losslessly.
            assert_eq!(event.serialized().size(), event.raw().len());
            let Ok(reparsed) = SerializedEvent::parse(event.raw()) else {
                unreachable_event(event.raw());
                return;
            };
            assert_eq!(reparsed.sad(), event.sad());
            // The identifier field carries exactly what the prefix derives to.
            let Ok(qb64) = habitat.prefix().qb64() else {
                unreachable_event(event.raw());
                return;
            };
            assert_eq!(event.sad().get_text("i"), Some(qb64.as_str()));
            // A non-transferable habitat never commits to next keys.
            if transferability == KeyTransferability::NonTransferable {
                assert!(qb64.starts_with('B'));
                assert_eq!(event.sad().get_text("nt"), Some("0"));
            }
            // The habitat is registered and findable, and the manager advanced exactly once.
            assert_eq!(habery.habitats().len(), 1);
            assert!(habery.habitat_by_name("fuzzed").is_some());
            assert_eq!(habery.manager().prefix_index(), prefix_index_before + 1);
        }
        Err(error) => {
            // Every rejection is typed and described; the pre-checked ones leave the manager
            // untouched, which registering nothing makes observable.
            assert!(!error.to_string().is_empty());
            assert!(habery.habitats().is_empty());
            assert!(habery.habitat_by_name("fuzzed").is_none());
            if !matches!(&error, IdentifierError::Manager { .. } | IdentifierError::Event { .. }) {
                // A conflict refusal happens before any derivation.
                assert_eq!(habery.manager().prefix_index(), prefix_index_before);
            }
        }
    }
});

/// Marks an event state no accepted habitat can reach.
fn unreachable_event(raw: &[u8]) {
    assert!(raw.is_empty(), "an accepted habitat produced an inconsistent event");
}
