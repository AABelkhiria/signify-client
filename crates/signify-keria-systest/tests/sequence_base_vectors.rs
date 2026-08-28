//! Hermetic assertions over which base a live KERIA read a query's sequence number in.
//!
//! `PORTING.md` §10 carried this as an open question owed to Roadmap 9.2, and Roadmap 6.7 refused
//! to guess: every `sn` literal the pinned reference sends is a single digit, where decimal and
//! hexadecimal agree, so its own recorded traffic cannot settle it. Only a deployment can, and
//! `wave1_sequence_base` asked one.
//!
//! **The answer is hexadecimal.** Against a log of eleven events, `a` resolved and returned event
//! ten; `10` and `16` never resolved at all. Read in base sixteen those name events 16 and 22,
//! which that log does not have — and read in base ten the outcome would have been the mirror
//! image. So a caller who spells event ten `"10"`, which is what every recorded reference call site
//! looks like it would do, asks this deployment about an event that does not exist and waits until
//! the deadline.
//!
//! That does **not** make [`QuerySequence::Hexadecimal`] a default. One deployment is evidence
//! about that deployment; ADR `0030` keeps both variants and no default, and this file records the
//! evidence rather than spending it.
//!
//! Not ignored: it reads a checked-in recording and never touches a network.

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

    // Below ten the two spellings are the same text, so a shorter log could not have distinguished
    // them however the deployment answered. Eleven events means sequence ten exists.
    assert!(
        captured.log_length > 10,
        "a log of {} events cannot distinguish the bases: they agree below ten",
        captured.log_length
    );

    // And it had to be somebody else's prefix, or the agent could have answered from its own log
    // without the mailbox query whose semantics are in question ever happening.
    assert!(captured.remote_note.contains("own prefix"));
    Ok(())
}

#[test]
fn exactly_the_hexadecimal_spelling_resolved() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The finding, stated as the shape of the outcome rather than as prose: one spelling of the
    // three resolved, and it is the hexadecimal one.
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

    // It answered about the event asked for, written the way the protocol writes a sequence
    // number — which is the same hexadecimal the request used.
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

    // Read as hexadecimal — which this deployment does — `10` is event 16 and `16` is event 22.
    // The log stops at ten, so neither exists and both queries wait until the deadline. This is
    // the cost of the wrong base: not an error, a timeout.
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

    // The scenario is not allowed to turn one deployment into a default, and the port has not:
    // both variants survive and neither is `Default`.
    assert!(captured.conclusion.contains("not a licence to choose for every caller"));
    assert_ne!(
        QuerySequence::Decimal(10).to_text(),
        QuerySequence::Hexadecimal(10).to_text(),
        "the two variants no longer render differently, so the caller's choice has stopped mattering"
    );
    Ok(())
}
