//! keripy's verdicts on the reference's passcode rotation and on this port's.
//!
//! `fixtures/client-passcode-rotation-keripy/v1.json` replays the log a connected signify-ts client
//! holds — inception, delegation-approval interaction — into keripy and records what keripy does
//! with each candidate rotation. This file requires those verdicts to stand, and requires this
//! port's rotation to be, byte for byte, the one keripy accepted. ADR `0034`.

use std::error::Error;

use keri_cesr::crypto::salt::SecurityTier;
use serde::Deserialize;
use serde_json::Value;
use signify_keri::controller::{Controller, ControllerOptions};
use signify_keri::serialization::SerializedEvent;

const KERIPY_SHA: &str = "4ce4cc79e06653f77342be1bf604086b89b1f090";
const SIGNIFY_TS_SHA: &str = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const VERDICTS: &str = include_str!("../../../fixtures/client-passcode-rotation-keripy/v1.json");
const RECORDING: &str = include_str!("../../../fixtures/client-passcode-rotation/v1.json");

#[derive(Debug, Deserialize)]
struct KeripyFixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    reference_version: String,
    generated_on: String,
    sources: Vec<String>,
    generator: String,
    input: Input,
    verdicts: Vec<Judgement>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Input {
    fixture: String,
    signify_ts_sha: String,
    controller_prefix: String,
    inception_said: String,
    interaction_said: String,
}

#[derive(Debug, Deserialize)]
struct Judgement {
    name: String,
    description: String,
    rotation_sequence: String,
    rotation_prior: String,
    rotation_said: String,
    log_before: LogPosition,
    verdict: String,
    error_class: Option<String>,
    error_message: Option<String>,
    log_after: LogPosition,
}

#[derive(Debug, Deserialize)]
struct LogPosition {
    sn: u64,
    ilk: String,
    said: String,
}

#[derive(Debug, Deserialize)]
struct Recording {
    provenance: Provenance,
    request: Request,
    kel: Kel,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    passcode: String,
    second_passcode: String,
    controller_prefix: String,
}

#[derive(Debug, Deserialize)]
struct Request {
    rotation: Value,
}

#[derive(Debug, Deserialize)]
struct Kel {
    inception: SignedEvent,
    interaction: SignedEvent,
    reference_rotation: SignedEvent,
    corrected_rotation: SignedEvent,
    inception_prior_rotation: SignedEvent,
}

#[derive(Debug, Deserialize)]
struct SignedEvent {
    raw: String,
    sigs: Vec<String>,
}

fn verdicts() -> Result<KeripyFixture, Box<dyn Error>> {
    Ok(serde_json::from_str(VERDICTS)?)
}

fn recording() -> Result<Recording, Box<dyn Error>> {
    Ok(serde_json::from_str(RECORDING)?)
}

fn verdict<'a>(fixture: &'a KeripyFixture, name: &str) -> Result<&'a Judgement, Box<dyn Error>> {
    fixture
        .verdicts
        .iter()
        .find(|verdict| verdict.name == name)
        .ok_or_else(|| format!("keripy recorded no verdict on {name}").into())
}

fn said_of(raw: &str) -> Result<String, Box<dyn Error>> {
    let event = SerializedEvent::parse(raw.as_bytes())?;
    Ok(event.said().ok_or("the event carries no SAID")?.to_owned())
}

#[test]
fn the_manifest_names_the_pinned_references_and_its_input() -> Result<(), Box<dyn Error>> {
    let fixture = verdicts()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/keripy.git");
    assert_eq!(fixture.reference_sha, KERIPY_SHA);
    assert_eq!(fixture.reference_version, "1.3.6");
    assert_eq!(fixture.generated_on, "2026-09-16");
    assert!(fixture.sources.iter().any(|source| source.contains("Kever.rotate")));
    assert_eq!(
        fixture.generator,
        "tools/reference-vectors/client_passcode_rotation_keripy.py"
    );
    assert_eq!(fixture.input.fixture, "fixtures/client-passcode-rotation/v1.json");
    assert_eq!(fixture.input.signify_ts_sha, SIGNIFY_TS_SHA);
    assert!(fixture.note.contains("500"));

    // The input the verdicts were computed from is the checked-in recording, not a copy of it.
    let recorded = recording()?;
    assert_eq!(fixture.input.controller_prefix, recorded.provenance.controller_prefix);
    assert_eq!(fixture.input.inception_said, said_of(&recorded.kel.inception.raw)?);
    assert_eq!(fixture.input.interaction_said, said_of(&recorded.kel.interaction.raw)?);
    for verdict in &fixture.verdicts {
        assert!(!verdict.description.is_empty(), "{}", verdict.name);
    }
    Ok(())
}

#[test]
fn the_recorded_request_is_the_reference_rotation_keripy_judged() -> Result<(), Box<dyn Error>> {
    let recorded = recording()?;
    let rotation = &recorded.request.rotation;
    let raw = &recorded.kel.reference_rotation.raw;
    let parsed: Value = serde_json::from_str(raw)?;
    assert_eq!(&parsed, rotation);
    for label in ["s", "p", "d"] {
        assert_eq!(parsed.get(label), rotation.get(label), "{label}");
    }
    // Every candidate is a canonical KERI event whose sizes and labels survive a strict parse.
    for event in [
        &recorded.kel.inception,
        &recorded.kel.interaction,
        &recorded.kel.reference_rotation,
        &recorded.kel.corrected_rotation,
        &recorded.kel.inception_prior_rotation,
    ] {
        SerializedEvent::parse(event.raw.as_bytes())?;
        assert!(!event.sigs.is_empty());
    }
    Ok(())
}

#[test]
fn keripy_refuses_the_reference_rotation_as_a_failed_recovery() -> Result<(), Box<dyn Error>> {
    let fixture = verdicts()?;
    let refused = verdict(&fixture, "reference_rotation")?;
    assert_eq!(refused.rotation_sequence, "1");
    assert_eq!(refused.rotation_prior, fixture.input.interaction_said);
    assert_eq!(refused.log_before.sn, 1);
    assert_eq!(refused.log_before.ilk, "ixn");
    assert_eq!(refused.verdict, "refused");
    assert_eq!(refused.error_class.as_deref(), Some("ValidationError"));
    let message = refused.error_message.as_deref().unwrap_or_default();
    assert!(message.contains("Invalid recovery attempt"), "{message}");
    assert!(message.contains(&fixture.input.inception_said), "{message}");
    // The log stays where it was.
    assert_eq!(refused.log_after.sn, 1);
    assert_eq!(refused.log_after.said, fixture.input.interaction_said);
    Ok(())
}

#[test]
fn keripy_accepts_the_rotation_at_the_next_sequence_number() -> Result<(), Box<dyn Error>> {
    let fixture = verdicts()?;
    let accepted = verdict(&fixture, "corrected_rotation")?;
    assert_eq!(accepted.rotation_sequence, "2");
    assert_eq!(accepted.rotation_prior, fixture.input.interaction_said);
    assert_eq!(accepted.verdict, "accepted");
    assert!(accepted.error_class.is_none() && accepted.error_message.is_none());
    assert_eq!(accepted.log_after.sn, 2);
    assert_eq!(accepted.log_after.ilk, "rot");
    assert_eq!(accepted.log_after.said, accepted.rotation_said);
    Ok(())
}

#[test]
fn keripy_refuses_the_next_sequence_number_over_a_stale_prior() -> Result<(), Box<dyn Error>> {
    let fixture = verdicts()?;
    let refused = verdict(&fixture, "inception_prior_rotation")?;
    assert_eq!(refused.rotation_sequence, "2");
    assert_eq!(refused.rotation_prior, fixture.input.inception_said);
    assert_eq!(refused.verdict, "refused");
    assert_eq!(refused.error_class.as_deref(), Some("ValidationError"));
    assert!(
        refused
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("Mismatch event dig")),
        "{:?}",
        refused.error_message
    );
    assert_eq!(refused.log_after.sn, 1);
    Ok(())
}

#[test]
fn this_ports_rotation_is_the_one_keripy_accepted() -> Result<(), Box<dyn Error>> {
    let recorded = recording()?;
    let fixture = verdicts()?;

    // The controller a connected client holds: the reference's passcode, restored at the
    // recorded delegation-approval interaction, at the production cost the reference always uses.
    let interaction = SerializedEvent::parse(recorded.kel.interaction.raw.as_bytes())?;
    let controller = Controller::restore(
        &recorded.provenance.passcode,
        SecurityTier::Low,
        ControllerOptions::default(),
        interaction,
    )?;
    assert_eq!(controller.prefix().qb64()?, recorded.provenance.controller_prefix);
    assert_eq!(controller.current_sequence_number(), 1);

    let planned = controller.plan_passcode_rotation(&recorded.provenance.second_passcode, &[])?;
    let artifacts = planned.artifacts();
    let corrected = &recorded.kel.corrected_rotation;
    assert_eq!(
        core::str::from_utf8(artifacts.rotation.raw())?,
        corrected.raw,
        "this port's rotation is not the event keripy accepted"
    );
    let signatures = artifacts
        .signatures
        .iter()
        .map(keri_cesr::crypto::signature::IndexedSignature::qb64)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(signatures, corrected.sigs);

    assert_ne!(
        core::str::from_utf8(artifacts.rotation.raw())?,
        recorded.kel.reference_rotation.raw
    );
    assert_eq!(
        artifacts.rotation.sad().get_text("d"),
        Some(verdict(&fixture, "corrected_rotation")?.rotation_said.as_str())
    );
    Ok(())
}
