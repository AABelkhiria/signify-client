//! Wave 17 — passcode rotation against a live agent, twice, with a reconnection after each.
//!
//! Not an upstream scenario: the reference's passcode rotation is covered only by a mocked unit
//! test, and signify-tui found that a live KERIA refuses it. ADR `0034`.
//!
//! **Only against a KERIA whose agent endpoint checks the rotation's signature correctly**, such
//! as `WebOfTrust` KERIA from `ba5001d`. A deployment whose handler tests
//! `if not self.authn.inbound(req)` inverts that check: it applies the rotation, answers `403`, and
//! never stores the re-sealed key material, so the throwaway controller this creates is left
//! unusable. Harmless here, since everything is created for the run.
//!
//! Reconnecting is by the persisted controller prefix; the scenario also records that the new
//! passcode alone finds no agent and that the replaced passcode is refused.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave17_passcode_rotation -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keria_types::api::Hab;
use serde::Serialize;
use signify_client::client::ConnectedClient;
use signify_client::random::random_passcode;
use signify_keria_systest::{
    Environment, Observation, connect, dump_tails, progress, ready_identifier, reconnect, record, recorder,
};

/// The alias of the one managed identifier whose key material moves with each rotation.
const ALIAS: &str = "rotating";

/// One rotation, as the controller adopted it.
#[derive(Debug, Serialize)]
struct Rotation {
    /// The status the agent answered the rotation with.
    status: u16,
    sequence_number: String,
    said: String,
    prior: String,
    /// The controller's sequence number and SAID immediately before rotating.
    sequence_before: String,
    said_before: String,
    /// Whether the same session's next signed request was accepted.
    same_session_read: bool,
}

/// What a fresh client connecting with the new passcode saw.
#[derive(Debug, Serialize)]
struct Reconnection {
    sequence_number: String,
    said: String,
    /// Whether the managed identifier could be read — a signed request under the new key.
    identifier_read: bool,
    /// Whether its stored key material opened under the new passcode.
    keeper_opened: bool,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    controller_prefix: String,
    identifier_prefix: String,
    connected_sequence_number: String,
    /// What connecting with the new passcode alone answered: the gap the persisted prefix closes.
    new_passcode_alone: String,
    /// What connecting with the replaced passcode and the prefix answered.
    replaced_passcode: String,
    first: Rotation,
    after_first: Reconnection,
    second: Rotation,
    after_second: Reconnection,
    transcript: Vec<Observation>,
}

fn position(client: &ConnectedClient) -> Result<(String, String), Box<dyn Error>> {
    Ok((
        format!("{:x}", client.controller().current_sequence_number()),
        client.controller().current_said().qb64()?,
    ))
}

/// Describes a connection attempt that is expected to fail, as the error it failed with.
fn refusal(outcome: Result<ConnectedClient, Box<dyn Error>>) -> String {
    match outcome {
        Ok(_) => "connected".to_owned(),
        Err(error) => error.to_string(),
    }
}

async fn rotate(client: &mut ConnectedClient) -> Result<(Rotation, String), Box<dyn Error>> {
    let passcode = random_passcode()?;
    let (sequence_before, said_before) = position(client)?;
    let record = client.identifiers().get(ALIAS).await?;
    progress(&format!("rotating the passcode from sequence {sequence_before}"));
    let answered = client.rotate_passcode(&passcode, &[record]).await?;

    let event = client.controller().current_event().sad();
    let text = |label: &str| event.get_text(label).map(ToOwned::to_owned).unwrap_or_default();
    progress(&format!("rotated to sequence {} with prior {}", text("s"), text("p")));
    let same_session_read = client.identifiers().get(ALIAS).await.is_ok();
    Ok((
        Rotation {
            status: answered.status().as_u16(),
            sequence_number: text("s"),
            said: text("d"),
            prior: text("p"),
            sequence_before,
            said_before,
            same_session_read,
        },
        passcode.expose().to_owned(),
    ))
}

async fn reconnected(client: &ConnectedClient) -> Result<Reconnection, Box<dyn Error>> {
    let (sequence_number, said) = position(client)?;
    progress(&format!("reconnected at sequence {sequence_number}"));
    let record = client.identifiers().get(ALIAS).await;
    let identifier_read = record.is_ok();
    let keeper_opened = match record {
        Ok(record) => client.keepers().keeper_for(&Hab::Accepted(record)).is_ok(),
        Err(_) => false,
    };
    Ok(Reconnection {
        sequence_number,
        said,
        identifier_read,
        keeper_opened,
    })
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation"]
async fn a_passcode_rotates_twice_and_each_new_passcode_reconnects() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let recorded = recorder("passcode_rotation")?;

    let outcome = Box::pin(scenario(&environment, &recorded)).await;
    if outcome.is_err() {
        dump_tails(&[&recorded], 4);
    }
    let mut captured = outcome?;
    captured.transcript = recorded.observations();

    assert_eq!(
        captured.connected_sequence_number, "1",
        "connecting did not approve the delegation"
    );
    assert!(
        captured.new_passcode_alone.contains("no agent"),
        "the new passcode alone found an agent: {}",
        captured.new_passcode_alone
    );
    assert!(
        captured.replaced_passcode.contains("passcode derives"),
        "the replaced passcode was not refused: {}",
        captured.replaced_passcode
    );
    assert_eq!(captured.first.sequence_number, "2");
    assert_eq!(captured.first.prior, captured.first.said_before);
    assert!(
        captured.first.same_session_read,
        "the rotated session's next request was refused"
    );
    assert_eq!(captured.after_first.sequence_number, "2");
    assert!(captured.after_first.identifier_read && captured.after_first.keeper_opened);
    assert_eq!(captured.second.sequence_number, "3");
    assert_eq!(captured.second.prior, captured.first.said);
    assert!(captured.second.same_session_read);
    assert_eq!(captured.after_second.sequence_number, "3");
    assert!(captured.after_second.identifier_read && captured.after_second.keeper_opened);
    record("observations/passcode_rotation.json", &captured)?;
    Ok(())
}

async fn scenario(
    environment: &Environment,
    recorded: &std::sync::Arc<signify_keria_systest::Recorder>,
) -> Result<Captured, Box<dyn Error>> {
    let first_passcode = random_passcode()?;
    progress("connecting a fresh client");
    let mut client = connect(environment, first_passcode.expose(), recorded).await?;
    let identifier = ready_identifier(&client, ALIAS).await?;
    let controller_prefix = client.controller().prefix().qb64()?;
    let (connected_sequence_number, _) = position(&client)?;

    let (first, second_passcode) = rotate(&mut client).await?;
    // What a caller persists: the new passcode and the controller prefix, from the configuration.
    let controller = client
        .config()
        .controller_prefix()
        .ok_or("the rotated client's configuration names no controller")?
        .clone();
    drop(client);

    progress("connecting with the new passcode alone");
    let new_passcode_alone = refusal(reconnect(environment, &second_passcode, None, recorded).await);
    progress(&format!("  -> {new_passcode_alone}"));
    progress("connecting with the replaced passcode and the prefix");
    let replaced_passcode = refusal(reconnect(environment, first_passcode.expose(), Some(&controller), recorded).await);
    progress(&format!("  -> {replaced_passcode}"));

    let mut client = reconnect(environment, &second_passcode, Some(&controller), recorded).await?;
    let after_first = reconnected(&client).await?;

    let (second, third_passcode) = rotate(&mut client).await?;
    drop(client);
    let client = reconnect(environment, &third_passcode, Some(&controller), recorded).await?;
    let after_second = reconnected(&client).await?;

    Ok(Captured {
        scenario: "passcode_rotation",
        preset: environment.preset.to_string(),
        controller_prefix,
        identifier_prefix: identifier.qb64()?,
        connected_sequence_number,
        new_passcode_alone,
        replaced_passcode,
        first,
        after_first,
        second,
        after_second,
        transcript: Vec::new(),
    })
}
