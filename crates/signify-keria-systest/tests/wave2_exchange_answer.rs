//! Wave 2 — which shape does an agent answer an exchange submission with?
//!
//! Posts one exchange to each submission path and runs both decoders over both answers.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave2_exchange_answer -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keria_types::api::{ExchangeOperation, ExchangeRecord};
use serde::Serialize;
use signify_client::presentation::DisclosureRequest;
use signify_keri::said::Said;
use signify_keri::serialization::Sad;
use signify_keria_systest::{Environment, connect, introduce, progress, ready_identifier, record, recorder};

const QVI_SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

const TOPIC: &str = "challenge";

#[derive(Debug, Serialize)]
struct Submission {
    path: &'static str,
    declared_upstream: &'static str,
    sent: bool,
    answer: Option<String>,
    decodes_as_operation: bool,
    decodes_as_exchange: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    submissions: Vec<Submission>,
    conclusion: String,
    transcript: Vec<signify_keria_systest::Observation>,
}

fn classify(path: &'static str, declared_upstream: &'static str, body: &[u8]) -> Submission {
    Submission {
        path,
        declared_upstream,
        sent: true,
        answer: core::str::from_utf8(body).ok().map(ToOwned::to_owned),
        decodes_as_operation: serde_json::from_slice::<ExchangeOperation>(body).is_ok(),
        decodes_as_exchange: serde_json::from_slice::<ExchangeRecord>(body).is_ok(),
        error: None,
    }
}

fn refused(path: &'static str, declared_upstream: &'static str, error: &dyn core::fmt::Display) -> Submission {
    Submission {
        path,
        declared_upstream,
        sent: false,
        answer: None,
        decodes_as_operation: false,
        decodes_as_exchange: false,
        error: Some(error.to_string()),
    }
}

fn conclusion(submissions: &[Submission]) -> String {
    let exchanges = submissions.iter().find(|entry| entry.path.ends_with("exchanges"));
    let ipex = submissions.iter().find(|entry| entry.path.contains("ipex"));
    let (Some(exchanges), Some(ipex)) = (exchanges, ipex) else {
        return "**Inconclusive.** One of the two paths was never attempted.".to_owned();
    };
    if !exchanges.sent || !ipex.sent {
        return format!(
            "**Inconclusive.** A path did not reach the agent, so nothing here compares the two \
             answers. `/exchanges`: {}. `/ipex`: {}.",
            exchanges.error.as_deref().unwrap_or("sent"),
            ipex.error.as_deref().unwrap_or("sent"),
        );
    }

    let describe = |entry: &Submission| match (entry.decodes_as_operation, entry.decodes_as_exchange) {
        (true, false) => "an operation",
        (false, true) => "an exchange message",
        (false, false) => "neither shape",
        (true, true) => "both shapes, which contradicts the disjointness property",
    };
    let (left, right) = (describe(exchanges), describe(ipex));
    if left == right {
        format!(
            "**The two paths agree**: both answer with {left}. Upstream declares them differently — \
             `/exchanges` as `Exn` and `/ipex` as `ExchangeOperation` — so one of those two \
             declarations is wrong about this deployment. `SentExchange` keeps both decoders and \
             the body, so a caller is not obliged to have guessed right."
        )
    } else {
        format!(
            "**The two paths disagree**: `/exchanges` answers with {left} and `/ipex` with {right}. \
             Keeping both decoders is not caution here but necessity — a single declared return \
             type would be wrong for one of the two endpoints."
        )
    }
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn which_shape_an_agent_answers_an_exchange_submission_with() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;

    let sender_recorder = recorder("sender")?;
    progress("connecting the sender client");
    let sender = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &sender_recorder,
    )
    .await?;
    let recipient_recorder = recorder("recipient")?;
    progress("connecting the recipient client");
    let recipient = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &recipient_recorder,
    )
    .await?;

    let _sender_prefix = ready_identifier(&sender, "sender").await?;
    let recipient_prefix = ready_identifier(&recipient, "recipient").await?;
    introduce(&recipient, "recipient", &sender).await?;
    introduce(&sender, "sender", &recipient).await?;

    let mut submissions = Vec::new();

    let draft = signify_client::endpoint::exchanges::ExchangeDraft::new(
        "/challenge/response",
        recipient_prefix.clone(),
        signify_keria_systest::now()?,
    );
    progress("posting to /identifiers/{name}/exchanges");
    submissions.push(
        match sender
            .exchanges()
            .send("sender", TOPIC, &draft, core::slice::from_ref(&recipient_prefix))
            .await
        {
            Ok(sent) => classify("/identifiers/{name}/exchanges", "Exn", sent.response_body()),
            Err(error) => refused("/identifiers/{name}/exchanges", "Exn", &error),
        },
    );

    let request = DisclosureRequest {
        holder: recipient_prefix.clone(),
        schema: Said::from_qb64(QVI_SCHEMA)?,
        attributes: Sad::new(),
        message: "which shape does this answer with?".to_owned(),
        timestamp: signify_keria_systest::now()?,
    };
    progress("posting to /identifiers/{name}/ipex/apply");
    submissions.push(match sender.presentation().request("sender", &request).await {
        Ok(submitted) => classify(
            "/identifiers/{name}/ipex/{route}",
            "ExchangeOperation",
            submitted.response_body(),
        ),
        Err(error) => refused("/identifiers/{name}/ipex/{route}", "ExchangeOperation", &error),
    });

    let captured = Captured {
        scenario: "exchange_answer",
        preset: environment.preset.to_string(),
        conclusion: conclusion(&submissions),
        submissions,
        transcript: sender_recorder.observations(),
    };

    assert_eq!(captured.submissions.len(), 2);
    if record("observations/exchange_answer.json", &captured)? {
        progress("recorded observations/exchange_answer.json");
    } else {
        progress("not a recording run, nothing written");
    }
    Ok(())
}
