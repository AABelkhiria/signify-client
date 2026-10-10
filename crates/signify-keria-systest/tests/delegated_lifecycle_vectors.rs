//! Hermetic assertions over the recorded delegated lifecycle.
//!
//! Two delegated inceptions, a delegated rotation, both refresh modes, and the anchor query's idempotence.

use std::error::Error;
use std::fs;
use std::path::Path;

use keri_protocol::prefix::{IdentifierPrefix, PrefixVerification};
use keri_protocol::said::{Said, SaidVerification};
use keri_protocol::serialization::Sad;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    delegator_prefix: String,
    steps: Vec<DelegatedStep>,
    anchor_query_idempotent: Option<bool>,
    completed_kind: Option<String>,
    completed_sequence: Option<String>,
    delegator_operations_remaining: usize,
    delegate_operations_remaining: usize,
    delegate_transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct DelegatedStep {
    prefix: String,
    derived_event: String,
    derived_said: String,
    operation_name: String,
    pending_before_approval: bool,
    approval_event: String,
    refreshed_by: String,
    witnessed: bool,
}

#[derive(Debug, Deserialize)]
struct Observation {
    method: String,
    resource: String,
    request_body: Option<String>,
}

fn captured(name: &str) -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join(format!("fixtures/keria-integration/observations/{name}.json"));
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

fn text_field(document: &Value, label: &str) -> Result<String, Box<dyn Error>> {
    document
        .get(label)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("the document carries no text field {label}").into())
}

fn check_step(step: &DelegatedStep, delegator: &str) -> Result<(), Box<dyn Error>> {
    assert!(
        step.pending_before_approval,
        "{} completed without approval",
        step.operation_name
    );
    assert_eq!(step.operation_name, format!("delegation.{}", step.derived_said));

    let event: Value = serde_json::from_str(&step.derived_event)?;
    let sad = Sad::from_json_bytes(step.derived_event.as_bytes())?;
    match text_field(&event, "t")?.as_str() {
        "dip" => {
            assert_eq!(text_field(&event, "di")?, delegator);
            assert_eq!(step.derived_said, step.prefix);
            IdentifierPrefix::from_qb64(&step.prefix)?.verify(&sad, PrefixVerification::Strict)?;
        }
        "drt" => {
            assert!(event.get("di").is_none(), "a drt unexpectedly carries di");
            Said::from_qb64(&step.derived_said)?.verify(&sad, "d", SaidVerification::strict())?;
        }
        other => return Err(format!("unexpected event kind {other}").into()),
    }

    let approval: Value = serde_json::from_str(&step.approval_event)?;
    assert_eq!(text_field(&approval, "t")?, "ixn");
    assert_eq!(text_field(&approval, "i")?, delegator);
    let anchors = approval
        .get("a")
        .and_then(Value::as_array)
        .ok_or("the approval carries no anchor list")?;
    let seal = match anchors.as_slice() {
        [seal] => seal,
        other => return Err(format!("expected exactly one anchored seal, found {}", other.len()).into()),
    };
    assert_eq!(text_field(seal, "i")?, step.prefix);
    assert_eq!(text_field(seal, "d")?, step.derived_said);
    Ok(())
}

#[test]
fn both_delegated_inceptions_pend_and_complete_under_their_refresh_modes() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured("singlesig_dip")? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "singlesig_dip");
    assert_ne!(captured.preset, "");
    assert_eq!(captured.delegator_operations_remaining, 0);
    assert_eq!(captured.delegate_operations_remaining, 0);

    let [first, second] = captured.steps.as_slice() else {
        return Err("the recording does not hold exactly two steps".into());
    };
    for step in [first, second] {
        check_step(step, &captured.delegator_prefix)?;
    }
    assert!(!first.witnessed);
    assert_eq!(first.refreshed_by, "sequence");
    assert!(second.witnessed);
    assert_eq!(second.refreshed_by, "anchor");
    let witnessed: Value = serde_json::from_str(&second.derived_event)?;
    assert_eq!(text_field(&witnessed, "bt")?, "3");

    assert_eq!(captured.anchor_query_idempotent, Some(true));
    let anchor_queries = captured
        .delegate_transcript
        .iter()
        .filter(|observation| {
            observation.method == "POST"
                && observation.resource == "/queries"
                && observation
                    .request_body
                    .as_deref()
                    .is_some_and(|body| body.contains("\"anchor\"") && !body.contains("\"sn\""))
        })
        .count();
    assert_eq!(
        anchor_queries, 2,
        "the anchor query and its idempotent repeat were not both sent"
    );
    Ok(())
}

#[test]
fn a_delegated_rotation_pends_like_its_inception_did() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured("singlesig_drt")? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "singlesig_drt");
    assert_eq!(captured.delegator_operations_remaining, 0);
    assert_eq!(captured.delegate_operations_remaining, 0);

    let [inception, rotation] = captured.steps.as_slice() else {
        return Err("the recording does not hold exactly two steps".into());
    };
    check_step(inception, &captured.delegator_prefix)?;
    check_step(rotation, &captured.delegator_prefix)?;
    assert_eq!(inception.prefix, rotation.prefix);
    let event: Value = serde_json::from_str(&rotation.derived_event)?;
    assert_eq!(text_field(&event, "t")?, "drt");
    assert_eq!(text_field(&event, "s")?, "1");

    assert_eq!(captured.completed_kind.as_deref(), Some("drt"));
    assert_eq!(captured.completed_sequence.as_deref(), Some("1"));
    Ok(())
}
