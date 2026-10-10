//! Wave 1 — what `Content-Range` does a real KERIA actually send?
//!
//! Asks both listing endpoints for empty, partial, complete, and past-the-end pages.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave1_content_range -- --ignored --test-threads=1
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keri_cesr::crypto::salt::SecurityTier;
use serde::Serialize;
use signify_client::endpoint::identifiers::IdentifierListing;
use signify_http::request::ItemRange;
use signify_keria_systest::{Environment, connect, record, recorder};
use signify_keys::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keys::manager::DerivationCost;

#[derive(Debug, Serialize)]
struct Capture {
    case: String,
    resource: String,
    request_range: Option<String>,
    status: u16,
    content_range: Option<String>,
    records: Option<usize>,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    note: &'static str,
    unrepresentable: Vec<&'static str>,
    captures: Vec<Capture>,
}

fn plain_identifier() -> CreateIdentifierRequest {
    CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: None,
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Production,
    })
}

fn capture(
    recorder: &signify_keria_systest::Recorder,
    case: &str,
    records: Option<usize>,
) -> Result<Capture, Box<dyn Error>> {
    let observations = recorder.observations();
    let last = observations.last().ok_or("nothing was recorded")?;
    let header = |name: &str| {
        last.response_headers
            .iter()
            .chain(last.request_headers.iter())
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    Ok(Capture {
        case: case.to_owned(),
        resource: last.resource.clone(),
        request_range: last
            .request_headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("range"))
            .map(|(_, value)| value.clone()),
        status: last.status,
        content_range: header("content-range"),
        records,
    })
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn what_content_range_a_deployment_sends() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let recorder = recorder("content_range")?;

    let passcode = signify_client::random::random_passcode()?;
    let client = connect(&environment, passcode.expose(), &recorder).await?;

    let mut pages = Vec::new();

    let listing: IdentifierListing = client.identifiers().list(ItemRange::new(0, 24)?).await?;
    pages.push(capture(
        &recorder,
        "identifiers, empty collection",
        Some(listing.identifiers.len()),
    )?);

    for index in 0..3 {
        let submission = client
            .identifiers()
            .create(&format!("range{index}"), &plain_identifier())
            .await?;
        client.poller().wait(submission.operation()?).await?;
    }

    for (case, range) in [
        ("identifiers, partial page", ItemRange::new(0, 1)?),
        ("identifiers, complete page", ItemRange::new(0, 24)?),
        ("identifiers, past the end", ItemRange::new(100, 199)?),
    ] {
        let listing: IdentifierListing = client.identifiers().list(range).await?;
        pages.push(capture(&recorder, case, Some(listing.identifiers.len()))?);
    }

    let notifications = client.notifications().list(ItemRange::new(0, 24)?).await?;
    pages.push(capture(
        &recorder,
        "notifications, empty collection",
        Some(notifications.notifications.len()),
    )?);

    let captured = Captured {
        scenario: "content_range",
        preset: environment.preset.to_string(),
        note: "Read from the transport's own transcript rather than the port's parsed view: a value \
               `ContentRange::parse` refuses never reaches a parsed view, and that refusal is the \
               finding this scenario exists to look for.",
        unrepresentable: vec![
            "A range whose start exceeds its end cannot be sent from this port at all: \
             `ItemRange::new` refuses it, so the malformed request RFC 9110 forbids is \
             unrepresentable rather than merely unsent.",
        ],
        captures: pages,
    };

    assert!(!captured.captures.is_empty());
    for capture in &captured.captures {
        assert!(capture.status < 500, "{} failed with {}", capture.case, capture.status);
    }

    record("observations/content_range.json", &captured)?;
    Ok(())
}
