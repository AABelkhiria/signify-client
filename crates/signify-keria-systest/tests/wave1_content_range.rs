//! Wave 1 — what `Content-Range` does a real KERIA actually send?
//!
//! `PORTING.md` §10 carries this as an open question owed to Roadmap 9.2. Roadmap 5.3's
//! `ContentRange::parse` accepts exactly `<unit> <start>-<end>/<total>` in ASCII digits and reports
//! the three numbers as sent, without RFC 9110's `start <= end < total`. The reference checks
//! nothing at all and would read a malformed value as `NaN` and carry on, so nothing in the pinned
//! tree says whether a deployment ever answers something this parser would refuse — an unknown
//! total spelled `*`, say.
//!
//! Only a deployment can say. This scenario asks it, on both listing endpoints, across an empty
//! page, a partial one, and a complete one — and then one case the reference never tries: a range
//! past the end of the collection.
//!
//! The literal header bytes are what matter, so they are read out of the recorder's transcript
//! rather than from the port's parsed view: a value the parser *refuses* would never reach a parsed
//! view at all, and that refusal is the finding this scenario exists to look for.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave1_content_range -- --ignored --test-threads=1
//! ```

// After the docs: a false `#![cfg]` strips everything below it, docs included, and an
// undocumented empty crate trips `missing_docs`.
#![cfg(feature = "live")]

use std::error::Error;

use serde::Serialize;
use signify_client::endpoint::identifiers::IdentifierListing;
use signify_crypto::salt::SecurityTier;
use signify_http::request::ItemRange;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::manager::DerivationCost;
use signify_keria_systest::{Environment, connect, record, recorder};

/// One question put to the deployment, and the literal answer.
#[derive(Debug, Serialize)]
struct Capture {
    /// What was asked for, in words.
    case: String,
    /// The resource, path and query.
    resource: String,
    /// The `Range` header sent, when one was.
    request_range: Option<String>,
    /// The status the deployment answered with.
    status: u16,
    /// The `Content-Range` header **verbatim**, or `null` when none came back.
    content_range: Option<String>,
    /// How many records the body carried.
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

/// A creation request with no witnesses, so this scenario needs only a KERIA.
///
/// The salt is the client's own rather than a per-identifier passcode: the client reserves a fresh
/// prefix index for each creation, so successive identifiers derive different prefixes. Handing the
/// same explicit passcode to three creations derives the *same* prefix three times, and the
/// deployment answers the third with `Already incepted` — which is how this was found.
fn plain_identifier() -> CreateIdentifierRequest {
    CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: None,
        tier: SecurityTier::Low,
        current_count: 1,
        next_count: 1,
        cost: DerivationCost::Production,
    })
}

/// Reads the last exchange's `Content-Range` and `Range` straight out of the transcript.
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

    // A fresh passcode per run, so the agent is this scenario's alone. Upstream reuses agents and
    // then asserts absolute counts against them, which is why its own suite contradicts itself.
    let passcode = signify_client::random::random_passcode()?;
    let client = connect(&environment, passcode.expose(), &recorder).await?;

    let mut pages = Vec::new();

    // The empty page: a virgin agent has no identifiers, and what a deployment says about a range
    // over nothing is exactly the case a parser is most likely to get wrong.
    let listing: IdentifierListing = client.identifiers().list(ItemRange::new(0, 24)?).await?;
    pages.push(capture(
        &recorder,
        "identifiers, empty collection",
        Some(listing.identifiers.len()),
    )?);

    // Three identifiers, no witnesses, so this scenario needs only KERIA.
    for index in 0..3 {
        let submission = client
            .identifiers()
            .create(&format!("range{index}"), &plain_identifier())
            .await?;
        client.poller().wait(submission.operation()?).await?;
    }

    // A partial page, a complete one, and one past the end — the last being the case the reference
    // never asks for and where an unknown total would show up if anywhere.
    for (case, range) in [
        ("identifiers, partial page", ItemRange::new(0, 1)?),
        ("identifiers, complete page", ItemRange::new(0, 24)?),
        ("identifiers, past the end", ItemRange::new(100, 199)?),
    ] {
        let listing: IdentifierListing = client.identifiers().list(range).await?;
        pages.push(capture(&recorder, case, Some(listing.identifiers.len()))?);
    }

    // The other listing endpoint, on an agent that has raised no notifications.
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

    // Every listing answered, and each answer is recorded whether or not it carried the header —
    // an absent `Content-Range` is itself an observation about the deployment.
    assert!(!captured.captures.is_empty());
    for capture in &captured.captures {
        assert!(capture.status < 500, "{} failed with {}", capture.case, capture.status);
    }

    record("observations/content_range.json", &captured)?;
    Ok(())
}
