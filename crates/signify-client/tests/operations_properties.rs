//! Invariants of the operations endpoint.
//!
//! Address, decoding, and dependency invariants for the operations family.

mod support;

use crate::support::fail;
use keria_types::api::{KeyEvent, Operation, OperationOutcome, OperationStatus, UntypedOperation, WitnessMetadata};
use proptest::prelude::*;
use signify_client::endpoint::operations::{MAX_FAILURE_MESSAGE_BYTES, OPERATIONS_SEGMENT, TYPE_PARAMETER, completed};
use signify_client::error::ClientError;
use signify_http::request::ResourcePath;

fn operation_path(name: &str) -> Result<ResourcePath, TestCaseError> {
    ResourcePath::builder()
        .segment(OPERATIONS_SEGMENT)
        .segment(name)
        .build()
        .map_err(fail)
}

proptest! {
    #[test]
    fn an_operation_name_never_escapes_its_segment(name in "[ -~]{1,48}") {
        let path = operation_path(&name)?;
        prop_assert!(path.as_str().starts_with("/operations/"));
        prop_assert_eq!(path.query(), None, "a name introduced a query");
        prop_assert_eq!(path.path(), path.as_str());

        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(segments.len(), 2);
        prop_assert_eq!(segments.first().copied(), Some(OPERATIONS_SEGMENT));

        let encoded = segments.get(1).copied().unwrap_or_default();
        prop_assert!(!encoded.contains('/'));
        prop_assert!(!encoded.contains('?'));
        prop_assert!(!encoded.contains('#'));
    }

    #[test]
    fn a_listing_carries_a_query_exactly_when_filtered(kind in prop::option::of("[ -~]{1,24}")) {
        let path = ResourcePath::builder()
            .segment(OPERATIONS_SEGMENT)
            .optional_parameter(TYPE_PARAMETER, kind.as_deref())
            .build()
            .map_err(fail)?;

        prop_assert!(path.path().starts_with("/operations"));
        if kind.is_some() {
            let query = path
                .query()
                .ok_or_else(|| TestCaseError::fail("a filter wrote no query"))?;
            let expected = format!("{TYPE_PARAMETER}=");
            prop_assert!(query.starts_with(&expected), "a filter wrote the wrong parameter");
            prop_assert_eq!(query.matches('&').count(), 0);
        } else {
            prop_assert_eq!(path.query(), None);
            prop_assert_eq!(path.as_str(), "/operations");
        }
        prop_assert_eq!(path.path(), "/operations");
    }

    #[test]
    fn only_a_completed_operation_yields_a_response(
        state in 0_usize..3,
        code in 400_i64..600,
        message in "[ -~]{0,64}",
    ) {
        let outcome = match state {
            0 => OperationOutcome::Pending,
            1 => OperationOutcome::Completed("done".to_owned()),
            _ => OperationOutcome::Failed(
                serde_json::from_value(serde_json::json!({"code": code, "message": message}))
                    .map_err(fail)?,
            ),
        };
        let done = outcome.is_done();
        let operation: Operation<WitnessMetadata, String> = Operation {
            name: "witness.EABC.0".to_owned(),
            metadata: None,
            outcome,
        };

        match completed(operation) {
            Ok(response) => {
                prop_assert_eq!(state, 1);
                prop_assert!(done);
                prop_assert_eq!(response, "done");
            }
            Err(ClientError::OperationPending { name }) => {
                prop_assert_eq!(state, 0);
                prop_assert!(!done);
                prop_assert_eq!(name, "witness.EABC.0");
            }
            Err(ClientError::OperationFailed { code: reported, message: kept, .. }) => {
                prop_assert_eq!(state, 2);
                prop_assert!(done);
                prop_assert_eq!(reported, code);
                prop_assert_eq!(kept, message);
            }
            Err(other) => return Err(fail(other)),
        }
    }

    #[test]
    fn a_failure_message_is_bounded_on_a_character_boundary(repeats in 0_usize..400) {
        const LOCK: char = '\u{1f510}';
        let message: String = core::iter::repeat_n(LOCK, repeats).collect();
        let status: OperationStatus =
            serde_json::from_value(serde_json::json!({"code": 500, "message": message}))
                .map_err(fail)?;
        let operation: Operation<WitnessMetadata, String> = Operation {
            name: "witness.EABC.0".to_owned(),
            metadata: None,
            outcome: OperationOutcome::Failed(status),
        };
        let Err(ClientError::OperationFailed { message: kept, .. }) = completed(operation) else {
            return Err(TestCaseError::fail("a failed operation was not reported as one"));
        };
        prop_assert!(kept.len() <= MAX_FAILURE_MESSAGE_BYTES);
        prop_assert!(
            kept.chars().all(|character| character == LOCK),
            "a message was split through a character"
        );
        if message.len() <= MAX_FAILURE_MESSAGE_BYTES {
            prop_assert_eq!(kept.as_str(), message.as_str());
        }
        prop_assert_eq!(kept.len() % 4, 0);
    }

    #[test]
    fn narrowing_never_changes_the_outcome(done in any::<bool>(), failed in any::<bool>()) {
        let document = if !done {
            serde_json::json!({"name": "witness.EABC.0", "metadata": {"pre": "EABC", "sn": 0}, "done": false, "error": null})
        } else if failed {
            serde_json::json!({"name": "witness.EABC.0", "metadata": {"pre": "EABC", "sn": 0}, "done": true, "error": {"code": 500, "message": "no"}})
        } else {
            serde_json::json!({
                "name": "witness.EABC.0",
                "metadata": {"pre": "EABC", "sn": 0},
                "done": true,
                "error": null,
                "response": {
                    "v": "KERI10JSON00012b_", "t": "icp",
                    "d": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose",
                    "i": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose",
                    "s": "0", "kt": "1", "k": ["DAbWjobbaLqRB94KiAutAHb_qzPpOHm3LURA_ksxetVc"],
                    "nt": "1", "n": ["EIFG_uqfr1yN560LoHYHfvPAhxQ5sN6xZZT_E3h7d2tL"],
                    "bt": "0", "b": [], "c": [], "a": []
                }
            })
        };

        let untyped: UntypedOperation = serde_json::from_value(document).map_err(fail)?;
        let before = untyped.outcome.is_done();
        prop_assert_eq!(before, done);

        let typed: Operation<WitnessMetadata, KeyEvent> = untyped.into_typed().map_err(fail)?;
        prop_assert_eq!(typed.outcome.is_done(), before);
        prop_assert_eq!(typed.name.as_str(), "witness.EABC.0");
        prop_assert_eq!(typed.metadata.as_ref().map(|metadata| metadata.sn), Some(0));

        prop_assert_eq!(completed(typed).is_ok(), done && !failed);
    }
}

#[test]
fn a_dot_segment_name_is_encoded() -> Result<(), Box<dyn std::error::Error>> {
    let path = ResourcePath::builder()
        .segment(OPERATIONS_SEGMENT)
        .segment("..")
        .build()?;
    assert_eq!(path.as_str(), "/operations/..");
    assert_eq!(path.query(), None);

    let escaping = ResourcePath::builder()
        .segment(OPERATIONS_SEGMENT)
        .segment("../identifiers")
        .build()?;
    assert_eq!(escaping.as_str(), "/operations/..%2Fidentifiers");
    Ok(())
}

#[test]
fn a_contradictory_operation_is_refused() {
    let both = serde_json::json!({
        "name": "witness.EABC.0", "done": true,
        "error": {"code": 500, "message": "no"},
        "response": {"anything": true}
    });
    assert!(serde_json::from_value::<UntypedOperation>(both).is_err());

    let neither = serde_json::json!({"name": "witness.EABC.0", "done": true, "error": null});
    assert!(serde_json::from_value::<UntypedOperation>(neither).is_err());

    let running_with_response = serde_json::json!({
        "name": "witness.EABC.0", "done": false, "error": null, "response": {"anything": true}
    });
    assert!(serde_json::from_value::<UntypedOperation>(running_with_response).is_err());
}
