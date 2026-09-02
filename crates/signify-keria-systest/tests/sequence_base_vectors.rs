//! Hermetic assertions over which base a live KERIA read a query's sequence number in.
//!
//! Three spellings of event ten: only hexadecimal `a` resolved, so this agent reads `sn` in base sixteen.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use signify_client::endpoint::key_states::QuerySequence;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    log_length: u64,
    remote_prefix: String,
    remote_note: String,
    attempts: Vec<Attempt>,
    conclusion: String,
}

#[derive(Debug, Deserialize)]
struct Attempt {
    spelling: String,
    base: String,
    completed: bool,
    answered_sequence: Option<String>,
    error: Option<String>,
}

fn captured() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/observations/sequence_base.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

#[test]
fn the_recording_asked_a_log_long_enough_for_the_bases_to_disagree() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "sequence_base");
    assert!(!captured.preset.is_empty());
    assert!(!captured.remote_prefix.is_empty());

    assert!(
        captured.log_length > 10,
        "a log of {} events cannot distinguish the bases: they agree below ten",
        captured.log_length
    );

    assert!(captured.remote_note.contains("own prefix"));
    Ok(())
}

#[test]
fn exactly_the_hexadecimal_spelling_resolved() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    let resolved: Vec<&Attempt> = captured.attempts.iter().filter(|attempt| attempt.completed).collect();
    assert_eq!(
        resolved.len(),
        1,
        "expected exactly one spelling to resolve, got {resolved:#?}"
    );
    let resolved = resolved.first().ok_or("no spelling resolved")?;
    assert_eq!(resolved.base, "hexadecimal");
    assert_eq!(resolved.spelling, "a");
    assert!(resolved.error.is_none());

    assert_eq!(resolved.answered_sequence.as_deref(), Some("a"));
    assert_eq!(QuerySequence::Hexadecimal(10).to_text(), "a");
    assert_eq!(QuerySequence::Hexadecimal(10).value(), 10);
    Ok(())
}

#[test]
fn the_decimal_spellings_named_events_the_log_does_not_have() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    for spelling in ["10", "16"] {
        let attempt = captured
            .attempts
            .iter()
            .find(|attempt| attempt.spelling == spelling)
            .ok_or_else(|| format!("the recording has no attempt spelled {spelling}"))?;
        assert!(!attempt.completed, "{spelling} resolved, so the finding is stale");
        assert!(attempt.answered_sequence.is_none());
        let error = attempt
            .error
            .as_deref()
            .ok_or_else(|| format!("{spelling} neither resolved nor reported why"))?;
        assert!(
            error.contains("still running"),
            "{spelling} failed for some reason other than never resolving: {error}"
        );

        let asked = u64::from_str_radix(spelling, 16).unwrap_or_default();
        assert!(
            asked >= captured.log_length,
            "{spelling} reads as event {asked} in base sixteen, which the log does have, so the \
             timeout is not explained by asking past the end"
        );
    }
    Ok(())
}

#[test]
fn the_run_concluded_hexadecimal_without_making_it_a_default() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert!(
        captured.conclusion.starts_with("**Hexadecimal.**"),
        "the recording concludes something else: {}",
        captured.conclusion
    );

    assert!(captured.conclusion.contains("not a licence to choose for every caller"));
    assert_ne!(
        QuerySequence::Decimal(10).to_text(),
        QuerySequence::Hexadecimal(10).to_text(),
        "the two variants no longer render differently, so the caller's choice has stopped mattering"
    );
    Ok(())
}
