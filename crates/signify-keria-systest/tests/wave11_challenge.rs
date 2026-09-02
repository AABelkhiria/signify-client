//! Wave 11 — challenge and response: proving control of an identifier out of band.
//!
//! Generates words, signs them as an exchange, verifies them, and marks the contact authenticated.

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use serde::Serialize;
use serde_json::Value;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::challenges::ChallengeStrength;
use signify_client::endpoint::oobis::OobiResolution;
use signify_http::transport::RequestUrl;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keria_systest::{Environment, connect, progress, record, recorder};
use signify_types::api::Role;

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

async fn wait_and_delete(client: &ConnectedClient, name: &str) -> Result<Value, Box<dyn Error>> {
    let operation = client.operations().get(name).await?;
    let completed = client.poller().wait(operation).await?;
    let (name, metadata, response) = completed.into_parts();
    client.operations().delete(&name).await?;
    if let Some(depends) = metadata
        .as_ref()
        .and_then(|metadata| metadata.get("depends"))
        .and_then(|depends| depends.get("name"))
        .and_then(Value::as_str)
    {
        client.operations().delete(depends).await?;
    }
    Ok(response)
}

async fn witnessed_identifier(
    client: &ConnectedClient,
    alias: &str,
    environment: &Environment,
) -> Result<IdentifierPrefix, Box<dyn Error>> {
    let mut request = CreateIdentifierRequest::new(CreateAlgorithm::salty(None));
    request.witnesses = environment
        .witness_prefixes
        .iter()
        .map(|prefix| IdentifierPrefix::from_qb64(prefix))
        .collect::<Result<Vec<_>, _>>()?;
    request.witness_threshold = u32::try_from(environment.witness_prefixes.len())?;
    progress(&format!("{alias}: creating with the witness triple"));
    let created = client.identifiers().create(alias, &request).await?;
    wait_and_delete(client, &created.operation()?.name).await?;
    let prefix = created.artifact().event.identifier().clone();

    let agent = client.agent().prefix().clone();
    let authorised = client
        .identifiers()
        .add_end_role(alias, &Role::Agent, Some(&agent), signify_keria_systest::now()?)
        .await?;
    wait_and_delete(client, &authorised.operation()?.name).await?;
    Ok(prefix)
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

async fn bob_contact(client: &ConnectedClient) -> Result<signify_types::api::Contact, Box<dyn Error>> {
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

    let alice_prefix = witnessed_identifier(&alice, "alice", &environment).await?;
    let bob_prefix = witnessed_identifier(&bob, "bob", &environment).await?;
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
