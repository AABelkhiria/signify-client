#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_keri::prefix::{IdentifierPrefix, PrefixDerivation, PrefixVerification};
use signify_keri::serialization::{Sad, SadValue};

/// Rebuilds a SAD with one field replaced or appended, preserving field order.
fn with_field(sad: &Sad, label: &str, value: &str) -> Option<Sad> {
    let mut rebuilt = Sad::new();
    let mut replaced = false;
    for (existing, existing_value) in sad.entries() {
        if existing == label {
            rebuilt.insert(existing.to_owned(), SadValue::text(value)).ok()?;
            replaced = true;
        } else {
            rebuilt.insert(existing.to_owned(), existing_value.clone()).ok()?;
        }
    }
    if !replaced {
        rebuilt.insert(label.to_owned(), SadValue::text(value)).ok()?;
    }
    Some(rebuilt)
}

fuzz_target!(|data: &[u8]| {
    // Hostile qualified text may only ever produce a typed error or a prefix that reproduces the
    // exact text it was parsed from; nothing is silently repaired.
    if let Ok(text) = core::str::from_utf8(data)
        && let Ok(prefix) = IdentifierPrefix::from_qb64(text)
    {
        if let Ok(qb64) = prefix.qb64() {
            assert_eq!(qb64, text, "an accepted prefix did not round trip");
        }
        // The code table and the parsed material must agree on what this prefix is.
        assert_eq!(prefix.code(), prefix.derivation().code());
        assert_eq!(prefix.is_digestive(), prefix.derivation().is_digestive());
    }

    // Hostile inception data must derive deterministically or fail cleanly, and anything derived
    // must verify against the event that commits to it.
    if let Ok(sad) = Sad::from_json_bytes(data) {
        for derivation in PrefixDerivation::ALL {
            let Ok(prefix) = IdentifierPrefix::derive(&sad, derivation) else {
                continue;
            };
            assert_eq!(prefix.derivation(), derivation, "derivation changed identity");

            // Derivation is deterministic and does not consume or disturb its input.
            match IdentifierPrefix::derive(&sad, derivation) {
                Ok(again) => assert_eq!(again, prefix, "derivation is not deterministic"),
                Err(error) => panic!("a repeated derivation failed: {error}"),
            }

            let Ok(qb64) = prefix.qb64() else { continue };
            assert!(
                prefix.verify(&sad, PrefixVerification::DerivationOnly).is_ok(),
                "a derived prefix failed to verify against its own event",
            );

            // Completing the event cannot change the prefix: the placeholder is exactly as wide
            // as the prefix that replaces it. This is the invariant a peer depends on.
            let completed = if prefix.is_digestive() {
                with_field(&sad, "i", &qb64).and_then(|filled| with_field(&filled, "d", &qb64))
            } else {
                with_field(&sad, "i", &qb64)
            };
            if let Some(completed) = completed {
                match IdentifierPrefix::derive(&completed, derivation) {
                    Ok(again) => assert_eq!(again, prefix, "completing the event changed the prefix"),
                    Err(error) => panic!("a completed event failed to re-derive: {error}"),
                }
                assert!(
                    prefix.verify(&completed, PrefixVerification::Strict).is_ok(),
                    "a completed event failed strict verification",
                );
            }
        }
    }
});
