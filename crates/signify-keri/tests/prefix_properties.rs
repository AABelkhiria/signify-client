//! Property and invalid-near-miss coverage for identifier prefixes.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_keri::prefix::{IdentifierPrefix, PrefixDerivation, PrefixError, PrefixVerification};
use signify_keri::said::DUMMY_CHARACTER;
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

/// A transferable Ed25519 key, its non-transferable form, and a second unrelated key.
const TRANSFERABLE_KEY: &str = "DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";
const NON_TRANSFERABLE_KEY: &str = "BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";
const OTHER_KEY: &str = "DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e";
const NEXT_DIGEST: &str = "EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj";

fn prefix_value<T>(result: Result<T, PrefixError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn sad_value<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn derivation_strategy() -> impl Strategy<Value = PrefixDerivation> {
    prop_oneof![
        Just(PrefixDerivation::Ed25519NonTransferable),
        Just(PrefixDerivation::Ed25519),
        Just(PrefixDerivation::Blake3_256),
    ]
}

fn payload_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
    proptest::collection::vec(("[e-hj-mp-uxyz]{1,5}", "[ -~\\u{80}-\\u{2ff}]{0,20}"), 0..5)
}

fn kind_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("icp"), Just("dip"), Just("vcp")]
}

/// Builds inception data that every derivation can consume.
///
/// The event kind and key are chosen to satisfy the derivation under test, so any failure is a
/// real defect rather than an intentionally rejected input.
fn build_inception(
    derivation: PrefixDerivation,
    kind: &str,
    payload: &[(String, String)],
    with_said_field: bool,
) -> Result<Sad, TestCaseError> {
    let key = if derivation == PrefixDerivation::Ed25519NonTransferable {
        NON_TRANSFERABLE_KEY
    } else {
        TRANSFERABLE_KEY
    };
    let mut sad = Sad::new();
    // A sizeable message needs its version string first.
    sad_value(sad.insert("v", SadValue::text("KERI10JSON000000_")))?;
    sad_value(sad.insert("t", SadValue::text(kind)))?;
    if with_said_field {
        sad_value(sad.insert("d", SadValue::text("")))?;
    }
    sad_value(sad.insert("i", SadValue::text("")))?;
    sad_value(sad.insert("s", SadValue::text("0")))?;
    sad_value(sad.insert("kt", SadValue::text("1")))?;
    sad_value(sad.insert("k", SadValue::Array(vec![SadValue::text(key)])))?;
    for (label, value) in payload {
        if !matches!(
            label.as_str(),
            "v" | "t" | "d" | "i" | "s" | "kt" | "k" | "n" | "b" | "a"
        ) {
            let _ = sad.insert(label.clone(), SadValue::text(value.clone()));
        }
    }
    Ok(sad)
}

/// Rebuilds a SAD with one field replaced or appended, preserving field order.
fn with_field(sad: &Sad, label: &str, value: SadValue) -> Result<Sad, TestCaseError> {
    let mut rebuilt = Sad::new();
    let mut replaced = false;
    for (existing, existing_value) in sad.entries() {
        if existing == label {
            sad_value(rebuilt.insert(existing.to_owned(), value.clone()))?;
            replaced = true;
        } else {
            sad_value(rebuilt.insert(existing.to_owned(), existing_value.clone()))?;
        }
    }
    if !replaced {
        sad_value(rebuilt.insert(label.to_owned(), value))?;
    }
    Ok(rebuilt)
}

/// Fills the identifier field, and the SAID field for a digestive prefix, as a builder will.
fn complete(sad: &Sad, prefix: &IdentifierPrefix) -> Result<Sad, TestCaseError> {
    let qb64 = prefix_value(prefix.qb64())?;
    let completed = with_field(sad, "i", SadValue::text(qb64.clone()))?;
    if prefix.is_digestive() {
        with_field(&completed, "d", SadValue::text(qb64))
    } else {
        Ok(completed)
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    /// Deriving, completing, and verifying must always agree, or a peer could not check what we
    /// produced.
    #[test]
    fn deriving_then_verifying_always_succeeds(
        derivation in derivation_strategy(),
        kind in kind_strategy(),
        payload in payload_strategy(),
        with_said_field in any::<bool>(),
    ) {
        let sad = build_inception(derivation, kind, &payload, with_said_field)?;
        let prefix = prefix_value(IdentifierPrefix::derive(&sad, derivation))?;
        let completed = complete(&sad, &prefix)?;

        let qb64 = prefix_value(prefix.qb64())?;
        prop_assert_eq!(completed.get_text("i"), Some(qb64.as_str()));
        prefix_value(prefix.verify(&completed, PrefixVerification::Strict))?;
        prefix_value(prefix.verify(&completed, PrefixVerification::DerivationOnly))?;
    }

    /// Derivation depends only on the data, and completing the event does not change it. This is
    /// the placeholder-width invariant: the prefix is exactly as wide as the placeholder it
    /// replaces, so substituting it cannot alter a single byte count.
    #[test]
    fn derivation_is_deterministic_and_survives_completion(
        derivation in derivation_strategy(),
        kind in kind_strategy(),
        payload in payload_strategy(),
        with_said_field in any::<bool>(),
    ) {
        let sad = build_inception(derivation, kind, &payload, with_said_field)?;
        let prefix = prefix_value(IdentifierPrefix::derive(&sad, derivation))?;
        prop_assert_eq!(prefix_value(IdentifierPrefix::derive(&sad, derivation))?, prefix.clone());

        let completed = complete(&sad, &prefix)?;
        prop_assert_eq!(prefix_value(IdentifierPrefix::derive(&completed, derivation))?, prefix.clone());

        // The declared size of the finished event equals the one derivation computed over
        // placeholders, so the bytes a peer hashes are the bytes we hashed.
        if prefix.is_digestive() {
            let dummy: String = core::iter::repeat_n(DUMMY_CHARACTER, prefix_value(prefix.qb64())?.len()).collect();
            let mut dummied = with_field(&sad, "i", SadValue::text(dummy.clone()))?;
            dummied = with_field(&dummied, "d", SadValue::text(dummy))?;
            let placeholder_event = sad_value(SerializedEvent::from_sad(dummied))?;
            let finished = sad_value(SerializedEvent::from_sad(completed))?;
            prop_assert_eq!(placeholder_event.size(), finished.size());
        }
    }

    /// A self-addressing prefix commits to every field, so any change to any of them is detected.
    #[test]
    fn tampering_breaks_a_self_addressing_prefix(
        kind in kind_strategy(),
        payload in payload_strategy(),
        tampered in "[ -~]{1,12}",
    ) {
        let sad = build_inception(PrefixDerivation::Blake3_256, kind, &payload, true)?;
        let prefix = prefix_value(IdentifierPrefix::derive(&sad, PrefixDerivation::Blake3_256))?;
        let completed = complete(&sad, &prefix)?;

        // Changing the sequence number, the key, or an arbitrary payload field all break it. The
        // identifier and SAID fields are excluded because derivation replaces them anyway.
        for (label, value) in [
            ("s", SadValue::text(tampered.clone())),
            ("kt", SadValue::text(tampered.clone())),
            ("k", SadValue::Array(vec![SadValue::text(OTHER_KEY)])),
        ] {
            if completed.get_text(label) == value.as_text() {
                continue;
            }
            let broken = with_field(&completed, label, value)?;
            prop_assert!(
                matches!(
                    prefix.verify(&broken, PrefixVerification::DerivationOnly),
                    Err(PrefixError::PrefixMismatch)
                ),
                "field {} was not committed to",
                label,
            );
        }
    }

    /// A basic prefix is the controller's key, and verification tracks the key the event lists.
    #[test]
    fn a_basic_prefix_tracks_its_key(
        non_transferable in any::<bool>(),
        kind in kind_strategy(),
        payload in payload_strategy(),
    ) {
        let derivation = if non_transferable {
            PrefixDerivation::Ed25519NonTransferable
        } else {
            PrefixDerivation::Ed25519
        };
        let sad = build_inception(derivation, kind, &payload, true)?;
        let prefix = prefix_value(IdentifierPrefix::derive(&sad, derivation))?;

        let expected = if non_transferable { NON_TRANSFERABLE_KEY } else { TRANSFERABLE_KEY };
        prop_assert_eq!(prefix_value(prefix.qb64())?, expected);
        prop_assert_eq!(prefix.is_transferable(), !non_transferable);
        prop_assert!(!prefix.is_digestive());

        // Listing a different key derives a different prefix.
        let other = with_field(&sad, "k", SadValue::Array(vec![SadValue::text(OTHER_KEY)]))?;
        if non_transferable {
            prop_assert!(matches!(
                prefix.verify(&other, PrefixVerification::DerivationOnly),
                Err(PrefixError::KeyCodeMismatch { .. })
            ), "a non-transferable prefix accepted a transferable key");
        } else {
            prop_assert!(matches!(
                prefix.verify(&other, PrefixVerification::DerivationOnly),
                Err(PrefixError::PrefixMismatch)
            ));
        }
    }

    /// A non-transferable identifier can never rotate, so its inception event may promise nothing
    /// that would require rotation.
    #[test]
    fn non_transferable_derivation_rejects_any_rotatable_content(
        kind in kind_strategy(),
        payload in payload_strategy(),
        label in prop_oneof![Just("n"), Just("b"), Just("a")],
        content in prop_oneof![
            Just(SadValue::Array(vec![SadValue::text(NEXT_DIGEST)])),
            Just(SadValue::text(NEXT_DIGEST)),
            Just(SadValue::Null),
        ],
    ) {
        let sad = build_inception(PrefixDerivation::Ed25519NonTransferable, kind, &payload, true)?;
        // Empty forms stay acceptable.
        for empty in [SadValue::Array(Vec::new()), SadValue::text("")] {
            let benign = with_field(&sad, label, empty)?;
            prefix_value(IdentifierPrefix::derive(&benign, PrefixDerivation::Ed25519NonTransferable))?;
        }

        let populated = with_field(&sad, label, content)?;
        prop_assert!(matches!(
            IdentifierPrefix::derive(&populated, PrefixDerivation::Ed25519NonTransferable),
            Err(PrefixError::NonTransferableFieldNotEmpty { .. })
        ), "rotatable content was accepted for a non-transferable identifier");
        // The transferable derivation accepts the same content, once the key matches.
        let transferable = with_field(&populated, "k", SadValue::Array(vec![SadValue::text(TRANSFERABLE_KEY)]))?;
        prefix_value(IdentifierPrefix::derive(&transferable, PrefixDerivation::Ed25519))?;
    }

    /// Every prefix round trips through its canonical qualified text, and nothing else parses.
    #[test]
    fn qualified_text_round_trips(
        derivation in derivation_strategy(),
        kind in kind_strategy(),
        payload in payload_strategy(),
    ) {
        let sad = build_inception(derivation, kind, &payload, true)?;
        let prefix = prefix_value(IdentifierPrefix::derive(&sad, derivation))?;
        let qb64 = prefix_value(prefix.qb64())?;

        prop_assert_eq!(prefix_value(IdentifierPrefix::from_qb64(&qb64))?, prefix.clone());
        prop_assert_eq!(qb64.parse::<IdentifierPrefix>().ok(), Some(prefix.clone()));
        prop_assert_eq!(prefix.to_string(), qb64.clone());
        prop_assert_eq!(qb64.len(), 44);
        prop_assert_eq!(prefix.code(), derivation.code());
    }

    /// Hostile qualified text is either rejected or reproduces itself exactly; it is never
    /// silently repaired.
    #[test]
    fn hostile_qualified_text_is_rejected_or_canonical(text in "[-_A-Za-z0-9#*]{0,60}") {
        if let Ok(prefix) = IdentifierPrefix::from_qb64(&text) {
            prop_assert_eq!(prefix_value(prefix.qb64())?, text);
        }
    }

    /// An event that does not claim the prefix is rejected by the default policy, whatever else it
    /// claims.
    #[test]
    fn strict_verification_requires_the_event_to_claim_the_prefix(
        derivation in derivation_strategy(),
        kind in kind_strategy(),
        payload in payload_strategy(),
        claimed in prop_oneof![Just(""), Just("icp"), Just(OTHER_KEY), Just(NEXT_DIGEST)],
    ) {
        let sad = build_inception(derivation, kind, &payload, true)?;
        let prefix = prefix_value(IdentifierPrefix::derive(&sad, derivation))?;
        let mislabeled = with_field(&sad, "i", SadValue::text(claimed))?;

        // The derivation still succeeds, because it replaces or ignores the identifier field --
        // which is exactly why checking the field separately matters.
        prefix_value(prefix.verify(&mislabeled, PrefixVerification::DerivationOnly))?;
        prop_assert!(matches!(
            prefix.verify(&mislabeled, PrefixVerification::Strict),
            Err(PrefixError::IdentifierFieldMismatch)
        ));
    }
}
