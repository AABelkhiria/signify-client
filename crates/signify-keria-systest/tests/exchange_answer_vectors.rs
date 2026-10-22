//! Hermetic assertions over which shape an agent answered an exchange submission with.
//!
//! Both submission paths answer with an operation, so `sendFromEvents`'s declared `Promise<Exn>` is wrong.

use std::error::Error;
use std::fs;
use std::path::Path;

use keria_types::api::{ExchangeOperation, ExchangeRecord, OperationOutcome};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    submissions: Vec<Submission>,
    conclusion: String,
}

#[derive(Debug, Deserialize)]
struct Submission {
    path: String,
    declared_upstream: String,
    sent: bool,
    answer: Option<String>,
    decodes_as_operation: bool,
    decodes_as_exchange: bool,
    error: Option<String>,
}

fn captured() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("crates/signify-client/fixtures/keria-integration/observations/exchange_answer.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

#[test]
fn both_submission_paths_were_actually_reached() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "exchange_answer");
    assert_ne!(captured.preset, "");
    assert_eq!(captured.submissions.len(), 2);

    for submission in &captured.submissions {
        assert!(
            submission.sent,
            "{} never reached the agent: {}",
            submission.path,
            submission.error.as_deref().unwrap_or("no reason recorded")
        );
        assert!(submission.error.is_none());
        assert!(submission.answer.is_some(), "{} recorded no answer", submission.path);
    }

    let exchanges = captured
        .submissions
        .iter()
        .find(|entry| entry.path.ends_with("exchanges"))
        .ok_or("the recording never posted to the exchanges path")?;
    let ipex = captured
        .submissions
        .iter()
        .find(|entry| entry.path.contains("ipex"))
        .ok_or("the recording never posted to the ipex path")?;
    assert_eq!(exchanges.declared_upstream, "Exn");
    assert_eq!(ipex.declared_upstream, "ExchangeOperation");
    Ok(())
}

#[test]
fn every_answer_is_an_operation_and_none_is_an_exchange_message() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    for submission in &captured.submissions {
        let answer = submission
            .answer
            .as_deref()
            .ok_or_else(|| format!("{} recorded no answer", submission.path))?;

        let operation: ExchangeOperation = serde_json::from_str(answer)
            .map_err(|error| format!("{}'s answer is not an operation: {error}", submission.path))?;
        assert!(submission.decodes_as_operation);

        assert!(
            serde_json::from_str::<ExchangeRecord>(answer).is_err(),
            "{}'s answer decodes as both shapes, which contradicts the disjointness property",
            submission.path
        );
        assert!(!submission.decodes_as_exchange);

        let OperationOutcome::Completed(result) = &operation.outcome else {
            return Err(format!("{}'s answer is not a completed operation", submission.path).into());
        };
        let metadata = operation
            .metadata
            .as_ref()
            .ok_or_else(|| format!("{}'s answer carried no metadata", submission.path))?;
        assert_eq!(
            result.said, metadata.said,
            "the operation's result names a different message than its metadata"
        );
        assert!(
            operation.name.ends_with(&metadata.said),
            "the operation {} is not named after the message it carries",
            operation.name
        );
    }
    Ok(())
}

#[test]
fn the_reference_declared_one_of_the_two_paths_wrongly() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    let exchanges = captured
        .submissions
        .iter()
        .find(|entry| entry.path.ends_with("exchanges"))
        .ok_or("the recording never posted to the exchanges path")?;
    assert_eq!(exchanges.declared_upstream, "Exn");
    assert!(
        exchanges.decodes_as_operation && !exchanges.decodes_as_exchange,
        "the exchanges path now answers as declared, so this finding is stale"
    );

    assert!(
        captured.conclusion.starts_with("**The two paths agree**"),
        "the recording concludes something else: {}",
        captured.conclusion
    );
    Ok(())
}
