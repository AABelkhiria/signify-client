//! Wave 11 — challenge and response: proving control of an identifier out of band.
//!
//! Generates words, signs them as an exchange, verifies them, and marks the contact authenticated.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave11_challenge -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keri_protocol::said::Said;
use keria_types::api::Role;
use serde::Serialize;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::challenges::ChallengeStrength;
use signify_client::endpoint::oobis::OobiResolution;
use signify_http::transport::RequestUrl;
use signify_keria_systest::singlesig::create_identifier;
use signify_keria_systest::{Environment, connect, progress, record, recorder, wait_and_delete, witness_prefixes};

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    words_at_128: usize,
    words_at_256: usize,
    alice_prefix: String,
    bob_prefix: String,
    challenges_before: Option<usize>,
    response_exn: String,
    response_said: String,
    response_operation_born_done: bool,
    verified_said: String,
    challenge_after_words: usize,
    challenge_after_authenticated: Option<bool>,
    challenge_after_said: Option<String>,
    alice_operations_remaining: usize,
    bob_operations_remaining: usize,
    alice_transcript: Vec<signify_keria_systest::Observation>,
    bob_transcript: Vec<signify_keria_systest::Observation>,
}

async fn introduce(
    owner: &ConnectedClient,
    alias: &str,
    resolver: &ConnectedClient,
    contact_alias: &str,
) -> Result<(), Box<dyn Error>> {
    let published = owner.oobis().get(alias, &Role::Agent).await?;
    let url = published
        .oobis
        .first()
        .cloned()
        .ok_or_else(|| format!("{alias} published no OOBI"))?;
    progress(&format!("resolving {alias} as {contact_alias}"));
    let resolution = OobiResolution {
        url: RequestUrl::new(url)?,
        alias: Some(contact_alias.to_owned()),
    };
    let submitted = resolver.oobis().resolve(&resolution).await?;
    let completed = resolver.poller().wait(submitted).await?;
    let name = completed.name().to_owned();
    resolver.operations().delete(&name).await?;
    Ok(())
}

async fn bob_contact(client: &ConnectedClient) -> Result<keria_types::api::Contact, Box<dyn Error>> {
    client
        .contacts()
        .list(None, None)
        .await?
        .into_iter()
        .find(|contact| contact.alias.as_deref() == Some("bob"))
        .ok_or_else(|| "no contact is aliased bob".into())
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn a_challenge_is_answered_verified_and_recorded_on_the_contact() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let alice_transcript = recorder("challenge_alice")?;
    progress("connecting Alice's client");
    let alice = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &alice_transcript,
    )
    .await?;
    let bob_transcript = recorder("challenge_bob")?;
    progress("connecting Bob's client");
    let bob = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &bob_transcript,
    )
    .await?;

    progress("generating challenge words at both strengths");
    let words = alice.challenges().generate(ChallengeStrength::BITS_128).await?.words;
    let words_at_128 = words.len();
    let words_at_256 = alice
        .challenges()
        .generate(ChallengeStrength::BITS_256)
        .await?
        .words
        .len();

    let alice_prefix = create_identifier(&alice, "alice", &witness_prefixes(&environment)?).await?;
    let bob_prefix = create_identifier(&bob, "bob", &witness_prefixes(&environment)?).await?;
    introduce(&bob, "bob", &alice, "bob").await?;
    introduce(&alice, "alice", &bob, "alice").await?;
    let challenges_before = bob_contact(&alice).await?.challenges.as_ref().map(Vec::len);

    progress("bob: responding to the challenge");
    let sent = bob
        .challenges()
        .respond("bob", &alice_prefix, &words, signify_keria_systest::now()?)
        .await?;
    let response_operation = sent.operation()?;
    let message = response_operation
        .metadata
        .as_ref()
        .map(|metadata| metadata.said.clone())
        .unwrap_or_default();
    let response_operation_born_done = response_operation.outcome.is_done();
    wait_and_delete(&bob, &response_operation.name).await?;

    progress("alice: verifying the response");
    let verifying = alice.challenges().verify(&bob_prefix, &words).await?;
    let completed = alice.poller().wait(verifying).await?;
    let verify_name = completed.name().to_owned();
    let response = completed.into_response();
    alice.operations().delete(&verify_name).await?;
    let verified_said = response.exn.digest.clone();
    let response_exn = serde_json::to_string(&response.exn)?;

    progress("alice: marking the response accepted");
    alice
        .challenges()
        .responded(&bob_prefix, &Said::from_qb64(&verified_said)?)
        .await?;
    let contact = bob_contact(&alice).await?;
    let challenge = contact
        .challenges
        .as_ref()
        .and_then(|challenges| challenges.first())
        .ok_or("bob's contact carries no challenge after the acknowledgement")?;

    let captured = Captured {
        scenario: "challenge",
        preset: environment.preset.to_string(),
        words_at_128,
        words_at_256,
        alice_prefix: alice_prefix.qb64()?,
        bob_prefix: bob_prefix.qb64()?,
        challenges_before,
        response_exn,
        response_said: message,
        response_operation_born_done,
        verified_said,
        challenge_after_words: challenge.words.len(),
        challenge_after_authenticated: challenge.authenticated,
        challenge_after_said: challenge.said.clone(),
        alice_operations_remaining: alice.operations().list(None).await?.len(),
        bob_operations_remaining: bob.operations().list(None).await?.len(),
        alice_transcript: alice_transcript.observations(),
        bob_transcript: bob_transcript.observations(),
    };
    if record("observations/challenge.json", &captured)? {
        progress("recorded observations/challenge.json");
    } else {
        progress("not a recording run, nothing written");
    }

    assert_eq!(captured.words_at_128, 12);
    assert_eq!(captured.words_at_256, 24);
    assert_eq!(captured.challenge_after_authenticated, Some(true));
    assert_eq!(captured.alice_operations_remaining, 0, "alice left operations behind");
    assert_eq!(captured.bob_operations_remaining, 0, "bob left operations behind");
    Ok(())
}
