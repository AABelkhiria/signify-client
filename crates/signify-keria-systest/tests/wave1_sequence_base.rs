//! Wave 1 — which base does a KERIA agent read a query's sequence number in?
//!
//! Builds an eleven-event log with a second client and asks for event ten in both bases.

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use serde::Serialize;
use signify_client::endpoint::key_states::{KeyStateQuery, QuerySequence};
use signify_client::endpoint::oobis::OobiResolution;
use signify_crypto::salt::SecurityTier;
use signify_http::transport::RequestUrl;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::manager::DerivationCost;
use signify_keria_systest::{Environment, connect, record, recorder};
use signify_types::api::Role;

const LOG_LENGTH: u64 = 11;

const LAST_SEQUENCE: u64 = LOG_LENGTH - 1;

#[derive(Debug, Serialize)]
struct Attempt {
    spelling: String,
    base: &'static str,
    asks_about: u64,
    completed: bool,
    answered_sequence: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    log_length: u64,
    remote_prefix: String,
    remote_note: &'static str,
    attempts: Vec<Attempt>,
    conclusion: String,
    transcript: Vec<signify_keria_systest::Observation>,
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

fn conclusion(attempts: &[Attempt]) -> String {
    let decimal_ten = attempts.iter().find(|attempt| attempt.spelling == "10");
    let hex_ten = attempts.iter().find(|attempt| attempt.spelling == "a");
    match (decimal_ten, hex_ten) {
        (Some(decimal), Some(hex)) if decimal.completed && hex.completed => {
            if decimal.answered_sequence == hex.answered_sequence {
                format!(
                    "**Does not distinguish.** Both spellings completed and answered about the same \
                     event ({:?}), so this run says nothing about the base. `QuerySequence` keeps \
                     both variants and no default.",
                    decimal.answered_sequence
                )
            } else {
                format!(
                    "**Distinguishes.** Both spellings completed but answered differently — \
                     decimal `10` returned {:?} and hexadecimal `a` returned {:?} — so the \
                     deployment does read a base and the recorded answers say which. ADR `0030` \
                     still keeps both variants: one deployment is not grounds for a default.",
                    decimal.answered_sequence, hex.answered_sequence
                )
            }
        }
        (Some(decimal), Some(hex)) if hex.completed => format!(
            "**Hexadecimal.** Against a log of {LOG_LENGTH} events (sequences 0 through \
             {LAST_SEQUENCE}), `a` resolved and answered about event {:?}, while `10` never \
             resolved ({}). Read as hexadecimal, `a` is event 10 — which exists — and `10` is \
             event 16, which does not; read as decimal the two swap, and the opposite spelling \
             would have resolved. So this deployment reads the query's `sn` in base sixteen. ADR \
             `0030` still keeps both variants and no default: one deployment is evidence about \
             that deployment, not a licence to choose for every caller.",
            hex.answered_sequence,
            decimal.error.as_deref().unwrap_or("no error reported"),
        ),
        (Some(decimal), Some(hex)) if decimal.completed => format!(
            "**Decimal.** Against a log of {LOG_LENGTH} events (sequences 0 through \
             {LAST_SEQUENCE}), `10` resolved and answered about event {:?}, while `a` never \
             resolved ({}). Read as decimal, `10` is event 10 — which exists — and `a` is not a \
             base-ten number at all. So this deployment reads the query's `sn` in base ten. ADR \
             `0030` still keeps both variants and no default.",
            decimal.answered_sequence,
            hex.error.as_deref().unwrap_or("no error reported"),
        ),
        (Some(decimal), Some(hex)) => format!(
            "**Inconclusive.** Neither spelling completed, so nothing here says which base the \
             deployment reads. Decimal `10`: {}. Hexadecimal `a`: {}. The asking client's whole \
             transcript is recorded beside this so the failure can be read rather than guessed at.",
            decimal.error.as_deref().unwrap_or("no error reported"),
            hex.error.as_deref().unwrap_or("no error reported"),
        ),
        _ => "**Inconclusive.** One of the two spellings was never attempted.".to_owned(),
    }
}

fn resolved_answer(transcript: &[signify_keria_systest::Observation]) -> Option<serde_json::Value> {
    transcript
        .iter()
        .filter(|observation| observation.resource == "/queries")
        .find_map(|observation| {
            let body = observation.response_body.as_deref()?;
            let value: serde_json::Value = serde_json::from_str(body).ok()?;
            value.get("done")?.as_bool()?.then_some(value)
        })
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn which_base_a_deployment_reads_a_sequence_number_in() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;

    let owner_recorder = recorder("sequence_base_owner")?;
    let owner_passcode = signify_client::random::random_passcode()?;
    let owner = connect(&environment, owner_passcode.expose(), &owner_recorder).await?;

    let asker_recorder = recorder("sequence_base")?;
    let asker_passcode = signify_client::random::random_passcode()?;
    let asker = connect(&environment, asker_passcode.expose(), &asker_recorder).await?;

    let created = owner.identifiers().create("logowner", &plain_identifier()).await?;
    owner.poller().wait(created.operation()?).await?;
    let prefix = created.artifact().event.identifier().clone();

    let agent = owner.agent().prefix().clone();
    let stamp = signify_keria_systest::now()?;
    let authorised = owner
        .identifiers()
        .add_end_role("logowner", &Role::Agent, Some(&agent), stamp)
        .await?;
    owner.poller().wait(authorised.operation()?).await?;

    for round in 0..u32::try_from(LAST_SEQUENCE)? {
        let anchor = signify_keri::serialization::Sad::new();
        let interaction = owner.identifiers().interact("logowner", vec![anchor]).await?;
        owner.poller().wait(interaction.operation()?).await?;
        let _ = round;
    }

    let oobi = owner.oobis().get("logowner", &Role::Agent).await?;
    let url = oobi.oobis.first().ok_or("the owner published no OOBI")?;
    let resolution = OobiResolution {
        url: RequestUrl::new(url.clone())?,
        alias: Some("logowner".to_owned()),
    };
    let resolved = asker.oobis().resolve(&resolution).await?;
    asker.poller().wait(resolved).await?;

    let mut attempts = Vec::new();
    for (spelling, base, sequence) in [
        ("10", "decimal", QuerySequence::Decimal(10)),
        ("a", "hexadecimal", QuerySequence::Hexadecimal(10)),
        ("16", "decimal", QuerySequence::Decimal(16)),
    ] {
        let query = KeyStateQuery {
            prefix: prefix.clone(),
            sequence_number: Some(sequence),
            anchor: None,
        };
        let operation = asker.key_states().query(&query).await;
        let attempt = match operation {
            Ok(operation) => match asker.poller().wait(operation).await {
                Ok(completed) => Attempt {
                    spelling: spelling.to_owned(),
                    base,
                    asks_about: if base == "decimal" {
                        spelling.parse().unwrap_or_default()
                    } else {
                        u64::from_str_radix(spelling, 16).unwrap_or_default()
                    },
                    completed: true,
                    answered_sequence: serde_json::to_value(completed.response())
                        .ok()
                        .and_then(|value| value.get("s").and_then(|s| s.as_str().map(ToOwned::to_owned))),
                    error: None,
                },
                Err(error) => Attempt {
                    spelling: spelling.to_owned(),
                    base,
                    asks_about: 0,
                    completed: false,
                    answered_sequence: None,
                    error: Some(error.to_string()),
                },
            },
            Err(error) => Attempt {
                spelling: spelling.to_owned(),
                base,
                asks_about: 0,
                completed: false,
                answered_sequence: None,
                error: Some(error.to_string()),
            },
        };
        attempts.push(attempt);
    }

    let conclusion = conclusion(&attempts);

    let captured = Captured {
        scenario: "sequence_base",
        preset: environment.preset.to_string(),
        log_length: LOG_LENGTH,
        remote_prefix: prefix.qb64()?,
        remote_note: "Built by one client and queried by another through an OOBI: a query about \
                      your own prefix may be answered from the agent's local log without the \
                      mailbox query this question is about ever happening.",
        attempts,
        conclusion,
        transcript: asker_recorder.observations(),
    };

    assert_eq!(captured.attempts.len(), 3);
    record("observations/sequence_base.json", &captured)?;

    if let Some(resolved) = resolved_answer(&captured.transcript) {
        record("observations/live_query_answer.json", &resolved)?;
    }
    Ok(())
}
