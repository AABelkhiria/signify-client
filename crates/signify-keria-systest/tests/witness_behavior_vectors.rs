//! Hermetic assertions over the recorded witness behavior.
//!
//! Wave 7 drove `test-integration/witness.test.ts` against a live deployment: an identifier
//! incepted with one witness at threshold one, rotated keeping it, rotated it out with a cut, and
//! rotated it back in with an add — four establishment events the agent completed only once the
//! named witness set had receipted them. This file re-checks the recording from the events' own
//! bytes: the witness ladder, the cut and add fields, the SAIDs, and one finding worth pinning —
//! **`bt` changes JSON type with its value inside a single log** (Roadmap 8.4's discovery,
//! reproduced deliberately by this port) and a live KERIA accepts both spellings interleaved.
//!
//! Not ignored: it reads a checked-in recording and never touches a network.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use signify_keri::prefix::{IdentifierPrefix, PrefixVerification};
use signify_keri::said::{Said, SaidVerification};
use signify_keri::serialization::Sad;

/// Wan, the first witness of the demo triple; the one whose membership changes.
const WITNESS: &str = "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha";

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    witness: String,
    prefix: String,
    steps: Vec<Step>,
    operations_remaining: usize,
    transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct Step {
    action: String,
    derived_event: String,
    derived_said: String,
    agent_event: String,
    witnesses_after: Vec<String>,
    threshold_after: String,
    sequence_after: String,
}

#[derive(Debug, Deserialize)]
struct Observation {
    method: String,
    resource: String,
    request_body: Option<String>,
    status: u16,
}

fn captured() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/observations/witness_behavior.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

/// Reads one text field out of a JSON document, by label.
fn text_field(document: &Value, label: &str) -> Result<String, Box<dyn Error>> {
    document
        .get(label)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("the document carries no text field {label}").into())
}

/// Reads one array of text out of a JSON document, by label.
fn text_array(document: &Value, label: &str) -> Result<Vec<String>, Box<dyn Error>> {
    document
        .get(label)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| value.as_str().map(ToOwned::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .and_then(|texts| texts)
        .ok_or_else(|| format!("the document carries no text array {label}").into())
}

#[test]
fn the_recording_is_the_whole_scenario() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "witness_behavior");
    assert!(!captured.preset.is_empty());
    assert!(!captured.transcript.is_empty(), "the recording kept no transcript");
    assert_eq!(captured.witness, WITNESS);
    assert_eq!(captured.operations_remaining, 0);

    // Four establishment events, in the upstream case's order, at sequences zero to three.
    let actions: Vec<&str> = captured.steps.iter().map(|step| step.action.as_str()).collect();
    assert_eq!(actions, ["incept", "rotate", "cut", "add"]);
    let sequences: Vec<&str> = captured.steps.iter().map(|step| step.sequence_after.as_str()).collect();
    assert_eq!(sequences, ["0", "1", "2", "3"]);
    Ok(())
}

#[test]
fn the_witness_ladder_is_kept_cut_and_added_back() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The upstream case's assertions: the key state's witness list after each step.
    let sets: Vec<&[String]> = captured
        .steps
        .iter()
        .map(|step| step.witnesses_after.as_slice())
        .collect();
    let expected: [&[String]; 4] = [&[WITNESS.to_owned()], &[WITNESS.to_owned()], &[], &[WITNESS.to_owned()]];
    assert_eq!(sets, expected);
    let thresholds: Vec<&str> = captured
        .steps
        .iter()
        .map(|step| step.threshold_after.as_str())
        .collect();
    assert_eq!(thresholds, ["1", "1", "0", "1"]);

    // And the events themselves carry the change: the inception names the witness in `b`, the
    // cut names it in `br`, the add in `ba`, and the plain rotation names nobody.
    let documents: Vec<Value> = captured
        .steps
        .iter()
        .map(|step| serde_json::from_str(&step.derived_event))
        .collect::<Result<_, _>>()?;
    let [incept, rotate, cut, add] = documents.as_slice() else {
        return Err("the recording does not hold exactly four events".into());
    };
    assert_eq!(text_array(incept, "b")?, [WITNESS]);
    assert_eq!(text_array(rotate, "br")?, Vec::<String>::new());
    assert_eq!(text_array(rotate, "ba")?, Vec::<String>::new());
    assert_eq!(text_array(cut, "br")?, [WITNESS]);
    assert_eq!(text_array(add, "ba")?, [WITNESS]);
    Ok(())
}

#[test]
fn the_witness_threshold_changes_json_type_with_its_value() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // Roadmap 8.4's finding, live: `incept` writes `bt` as hexadecimal text while `rotate`
    // defaults `intive` and writes a bare number for a non-zero threshold and text at zero — so
    // one identifier's log carries "1", 1, "0", 1 — and a real KERIA accepts all four
    // interleaved. The port reproduces the spellings deliberately (Roadmap 3.5); if this ever
    // fails, either the port's encoding or the deployment's tolerance changed, and both are worth
    // knowing.
    let spellings: Vec<Value> = captured
        .steps
        .iter()
        .map(|step| {
            serde_json::from_str::<Value>(&step.derived_event)
                .map(|event| event.get("bt").cloned().unwrap_or(Value::Null))
        })
        .collect::<Result<_, _>>()?;
    let expected = [
        Value::String("1".to_owned()),
        Value::from(1),
        Value::String("0".to_owned()),
        Value::from(1),
    ];
    assert_eq!(spellings, expected);
    Ok(())
}

#[test]
fn every_event_verifies_and_was_accepted_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    for (index, step) in captured.steps.iter().enumerate() {
        // The SAID (or, for the inception, the prefix) re-verifies over the derived bytes.
        let sad = Sad::from_json_bytes(step.derived_event.as_bytes())?;
        if step.action == "incept" {
            IdentifierPrefix::from_qb64(&captured.prefix)?.verify(&sad, PrefixVerification::Strict)?;
        } else {
            Said::from_qb64(&step.derived_said)?.verify(&sad, "d", SaidVerification::strict())?;
        }

        // The agent echoed the same document back.
        let echoed: Value = serde_json::from_str(&step.agent_event)?;
        assert_eq!(text_field(&echoed, "d")?, step.derived_said, "step {index} echo");

        // And the exact bytes appear inside a successful POST body in the transcript.
        let resource = if step.action == "incept" {
            "/identifiers"
        } else {
            "/identifiers/aid1/events"
        };
        assert!(
            captured.transcript.iter().any(|observation| {
                observation.method == "POST"
                    && observation.resource == resource
                    && (200..300).contains(&observation.status)
                    && observation
                        .request_body
                        .as_deref()
                        .is_some_and(|body| body.contains(&step.derived_event))
            }),
            "the exact {} bytes were never accepted by the agent",
            step.action
        );
    }
    Ok(())
}
