//! Hermetic assertions over which shape an agent answered an exchange submission with.
//!
//! `PORTING.md` §10 carried this as an open question owed to Roadmap 9.2. Upstream declares the two
//! submission paths differently — `Exchanges.sendFromEvents` as `Promise<Exn>`,
//! `Ipex.submit*` as `Promise<ExchangeOperation>` — for the same shape of POST to the same agent,
//! and both are unchecked `res.json()` casts, so at most one can be right and neither is checked.
//!
//! **Both paths answer with an operation.** So `sendFromEvents`'s `Promise<Exn>` is wrong: a caller
//! who believed it would read an operation as an exchange message. The port never had to guess —
//! `SentExchange` keeps the body and offers both decoders — and this file records which one a
//! deployment actually justifies.
//!
//! Not ignored: it reads a checked-in recording and never touches a network.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use signify_types::api::{ExchangeOperation, ExchangeRecord, OperationOutcome};

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
        .join("fixtures/keria-integration/observations/exchange_answer.json");
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
    assert!(!captured.preset.is_empty());
    assert_eq!(captured.submissions.len(), 2);

    // The comparison is only worth anything if both halves happened. A path that never reached the
    // agent says nothing about what the agent answers with.
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

    // And they must be the two different paths, not the same one twice.
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

    // The finding. Decoded here again from the recorded bytes rather than trusting the flags the
    // scenario wrote: a recording that merely reports its own conclusion proves nothing.
    for submission in &captured.submissions {
        let answer = submission
            .answer
            .as_deref()
            .ok_or_else(|| format!("{} recorded no answer", submission.path))?;

        let operation: ExchangeOperation = serde_json::from_str(answer)
            .map_err(|error| format!("{}'s answer is not an operation: {error}", submission.path))?;
        assert!(submission.decodes_as_operation);

        // The two shapes are proven disjoint by a property in `signify-client`. Here is the other
        // half of that claim, against real bytes: the answer is not an exchange message.
        assert!(
            serde_json::from_str::<ExchangeRecord>(answer).is_err(),
            "{}'s answer decodes as both shapes, which contradicts the disjointness property",
            submission.path
        );
        assert!(!submission.decodes_as_exchange);

        // A completed operation whose result names the message that was submitted, which is what
        // `Operation<ExchangeMetadata, ExchangeMetadata>` says it is.
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

    // `/ipex` was declared `ExchangeOperation` and answers with one; `/exchanges` was declared
    // `Exn` and answers with an operation too. So the reference is right about one path and wrong
    // about the other, and a port that had believed either declaration in isolation would have had
    // a 50% chance of typing a caller's answer as something it is not.
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
