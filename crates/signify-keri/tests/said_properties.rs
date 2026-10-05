//! Property and invalid-near-miss coverage for self-addressing identifiers.

use keri_cesr::crypto::digest::DigestAlgorithm;
use proptest::{prelude::*, test_runner::TestCaseError};
use signify_keri::said::{DEFAULT_SAID_LABEL, DUMMY_CHARACTER, Said, SaidError, SaidVerification};
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

fn said_value<T>(result: Result<T, SaidError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn fail<T>(message: &str) -> Result<T, TestCaseError> {
    Err(TestCaseError::fail(message.to_owned()))
}

fn payload_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
    proptest::collection::vec(("[a-hj-uw-z]{1,6}", "[ -~\\u{80}-\\u{2ff}]{0,20}"), 0..6)
}

/// Builds a SAD with an identifier field, optionally preceded by a version string.
fn build_sad(versioned: bool, payload: &[(String, String)]) -> Result<Sad, TestCaseError> {
    let mut sad = Sad::new();
    if versioned {
        // The version field must be first for a message to be sizeable.
        sad.insert("v", SadValue::text("KERI10JSON000000_"))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
    }
    sad.insert(DEFAULT_SAID_LABEL, SadValue::text(""))
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
    for (label, value) in payload {
        if label != "v" && label != DEFAULT_SAID_LABEL {
            let _ = sad.insert(label.clone(), SadValue::text(value.clone()));
        }
    }
    Ok(sad)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    #[test]
    fn computing_then_verifying_always_succeeds(
        versioned in any::<bool>(),
        payload in payload_strategy(),
    ) {
        let sad = build_sad(versioned, &payload)?;
        let computed = said_value(Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;

        // The completed data claims exactly the identifier that commits to it.
        let qb64 = said_value(computed.said().qb64())?;
        prop_assert_eq!(computed.sad().get_text(DEFAULT_SAID_LABEL), Some(qb64.as_str()));
        said_value(computed.said().verify(computed.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict()))?;
    }

    #[test]
    fn derivation_is_deterministic_and_idempotent(
        versioned in any::<bool>(),
        payload in payload_strategy(),
    ) {
        let sad = build_sad(versioned, &payload)?;
        let first = said_value(Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;
        let second = said_value(Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;
        prop_assert_eq!(first.said(), second.said());

        // Recomputing over already-completed data yields the same identifier, because derivation
        // replaces the identifier field either way. This is what makes verification possible.
        let recomputed = said_value(Said::compute(first.sad(), DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;
        prop_assert_eq!(recomputed.said(), first.said());
        prop_assert_eq!(recomputed.sad(), first.sad());
    }

    #[test]
    fn substituting_the_identifier_never_changes_the_message_size(
        payload in payload_strategy(),
    ) {
        let sad = build_sad(true, &payload)?;
        let computed = said_value(Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;

        // The placeholder and the identifier are the same width, so the size the version string
        // recorded during hashing still describes the finished message exactly.
        let declared = computed
            .sad()
            .get_text("v")
            .ok_or_else(|| TestCaseError::fail("versioned data lost its version string"))?;
        let event = SerializedEvent::from_sad(computed.sad().clone())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(event.sad().get_text("v"), Some(declared));
        prop_assert_eq!(event.size(), event.raw().len());

        let qb64 = said_value(computed.said().qb64())?;
        prop_assert_eq!(qb64.len(), DUMMY_CHARACTER.len_utf8() * 44);
    }

    #[test]
    fn tampering_with_any_field_breaks_the_digest(
        versioned in any::<bool>(),
        payload in payload_strategy(),
        suffix in "[a-z]{1,4}",
    ) {
        prop_assume!(!payload.is_empty());
        let sad = build_sad(versioned, &payload)?;
        let computed = said_value(Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;
        let said = *computed.said();

        // Rebuild the completed data with one payload field altered, preserving field order.
        let mut tampered = Sad::new();
        let mut changed = false;
        for (label, value) in computed.sad().entries() {
            if label != "v" && label != DEFAULT_SAID_LABEL && !changed {
                let original = value.as_text().unwrap_or_default();
                tampered
                    .insert(label.to_owned(), SadValue::text(format!("{original}{suffix}")))
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
                changed = true;
            } else {
                tampered
                    .insert(label.to_owned(), value.clone())
                    .map_err(|error| TestCaseError::fail(error.to_string()))?;
            }
        }
        prop_assume!(changed);

        let outcome = said.verify(&tampered, DEFAULT_SAID_LABEL, SaidVerification::digest_only());
        prop_assert!(matches!(outcome, Err(SaidError::DigestMismatch)));
    }

    #[test]
    fn an_unclaimed_identifier_is_rejected_by_the_default_policy(
        versioned in any::<bool>(),
        payload in payload_strategy(),
    ) {
        let sad = build_sad(versioned, &payload)?;
        let computed = said_value(Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;
        let said = *computed.said();

        // The input still has an empty identifier field. Its digest matches, because derivation
        // replaces that field -- which is exactly why the reference's default accepts it.
        said_value(said.verify(&sad, DEFAULT_SAID_LABEL, SaidVerification::digest_only()))?;
        let strict = said.verify(&sad, DEFAULT_SAID_LABEL, SaidVerification::strict());
        prop_assert!(matches!(strict, Err(SaidError::LabelFieldMismatch)));
    }

    #[test]
    fn a_missing_identifier_field_is_always_rejected(payload in payload_strategy()) {
        let mut sad = Sad::new();
        sad.insert("v", SadValue::text("KERI10JSON000000_"))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        for (label, value) in &payload {
            if label != "v" && label != DEFAULT_SAID_LABEL {
                let _ = sad.insert(label.clone(), SadValue::text(value.clone()));
            }
        }
        let outcome = Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL);
        let rejected = matches!(outcome, Err(SaidError::MissingLabelField { .. }));
        prop_assert!(rejected);
    }

    #[test]
    fn distinct_content_yields_distinct_identifiers(
        left in payload_strategy(),
        right in payload_strategy(),
    ) {
        let left_sad = build_sad(false, &left)?;
        let right_sad = build_sad(false, &right)?;
        let left_said = said_value(Said::compute(&left_sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;
        let right_said = said_value(Said::compute(&right_sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;

        let left_bytes = left_sad.to_json_bytes().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let right_bytes = right_sad.to_json_bytes().map_err(|e| TestCaseError::fail(e.to_string()))?;
        if left_bytes == right_bytes {
            prop_assert_eq!(left_said.said(), right_said.said());
        } else {
            prop_assert_ne!(left_said.said(), right_said.said());
        }
    }

    #[test]
    fn identifier_material_round_trips_through_text(
        versioned in any::<bool>(),
        payload in payload_strategy(),
    ) {
        let sad = build_sad(versioned, &payload)?;
        let computed = said_value(Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;
        let qb64 = said_value(computed.said().qb64())?;

        let Ok(reparsed) = Said::from_qb64(&qb64) else {
            return fail("a produced identifier failed to reparse");
        };
        prop_assert_eq!(&reparsed, computed.said());
        prop_assert_eq!(reparsed.to_string(), qb64);
        said_value(reparsed.verify(computed.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict()))?;
    }
}
