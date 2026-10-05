//! Wave 3 — the salty identifier lifecycle, driven whole against a live deployment.
//!
//! Drives `salty.test.ts` whole: three creations, the listing ladder, a rotation, an interaction, a rename.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave3_salty_lifecycle -- --ignored --test-threads=1 --nocapture
//! ```

// The //! header must stay above this cfg: a false cfg strips it and trips missing_docs.
#![cfg(feature = "live")]

use std::error::Error;

use keri_cesr::crypto::salt::SecurityTier;
use serde::Serialize;
use serde_json::Value;
use signify_client::client::ConnectedClient;
use signify_client::endpoint::identifiers::IdentifierUpdate;
use signify_http::request::ItemRange;
use signify_keri::identifier::{CreateAlgorithm, CreateIdentifierRequest, RotateIdentifierRequest};
use signify_keri::manager::DerivationCost;
use signify_keri::serialization::{Sad, SadValue};
use signify_keri::threshold::SigningThreshold;
use signify_keria_systest::{Environment, connect, progress, record, recorder, wait_and_delete};
use signify_types::api::KeyManagerState;

const AID1_PASSCODE: &str = "0123456789abcdefghijk";
const AID2_PASSCODE: &str = "0123456789lmnopqrstuv";

const AID1_PREFIX: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const AID2_PREFIX: &str = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";
const ROTATION_SAID: &str = "EBQABdRgaxJONrSLcgrdtbASflkvLxJkiDO0H-XmuhGg";
const UPSTREAM_INTERACTION_SAID: &str = "ENsmRAg_oM7Hl1S-GTRMA7s4y760lQMjzl0aqOQ2iTce";

#[derive(Debug, Serialize)]
struct Creation {
    alias: &'static str,
    passcode: Option<&'static str>,
    derived_event: String,
    derived_prefix: String,
    agent_event: String,
    key_pair_index: u32,
    stem: String,
}

#[derive(Debug, Serialize)]
struct Listing {
    start: u64,
    end: u64,
    names: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Rotation {
    derived_event: String,
    derived_said: String,
    agent_event: String,
}

#[derive(Debug, Serialize)]
struct Interaction {
    upstream_anchor: String,
    upstream_said: &'static str,
    port_anchor: String,
    derived_event: String,
    derived_said: String,
    agent_event: String,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct StateCapture {
    sequence: String,
    first_seen: String,
    establishment_kind: String,
    digest: String,
    establishment_digest: String,
}

#[derive(Debug, Serialize)]
struct Rename {
    from: &'static str,
    to: &'static str,
    updated_name: String,
    fetched_name: String,
}

#[derive(Debug, Serialize)]
struct Captured {
    scenario: &'static str,
    preset: String,
    creations: Vec<Creation>,
    listings: Vec<Listing>,
    rotation: Rotation,
    interaction: Interaction,
    state: StateCapture,
    log_saids: Vec<String>,
    rename: Rename,
    operations_remaining: usize,
    transcript: Vec<signify_keria_systest::Observation>,
}

fn text_field(document: &Value, label: &str) -> Result<String, Box<dyn Error>> {
    document
        .get(label)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("the document carries no text field {label}").into())
}

async fn create_identifier(
    client: &ConnectedClient,
    alias: &'static str,
    passcode: Option<&'static str>,
    request: &CreateIdentifierRequest,
) -> Result<(Creation, String), Box<dyn Error>> {
    progress(&format!("{alias}: creating"));
    let created = client.identifiers().create(alias, request).await?;
    let operation = created.operation()?;
    let completed = client.poller().wait(operation).await?;
    let (name, _metadata, response) = completed.into_parts();
    client.operations().delete(&name).await?;

    let artifact = created.artifact();
    let derived_event = String::from_utf8(artifact.event.raw().to_vec())?;
    let derived_prefix = artifact.event.identifier().qb64()?;
    let derived_said = artifact.event.said().qb64()?;
    progress(&format!("{alias}: incepted as {derived_prefix}"));

    let stored = client.identifiers().get(alias).await?;
    let KeyManagerState::Salty(salty) = &stored.common.key_manager else {
        return Err(format!("{alias} is not stored as a salty identifier").into());
    };

    Ok((
        Creation {
            alias,
            passcode,
            derived_event,
            derived_prefix,
            agent_event: serde_json::to_string(&response)?,
            key_pair_index: salty.key_pair_index,
            stem: salty.stem.clone(),
        },
        derived_said,
    ))
}

async fn list_names(client: &ConnectedClient, window: ItemRange) -> Result<Listing, Box<dyn Error>> {
    let listing = client.identifiers().list(window).await?;
    Ok(Listing {
        start: window.start(),
        end: window.end(),
        names: listing
            .identifiers
            .iter()
            .map(|hab| hab.common().name.clone())
            .collect(),
    })
}

fn check(mismatches: &mut Vec<String>, what: &str, observed: &str, expected: &str) {
    if observed != expected {
        mismatches.push(format!("{what}: observed {observed}, pinned {expected}"));
    }
}

async fn run_creations(
    client: &ConnectedClient,
    mismatches: &mut Vec<String>,
    listings: &mut Vec<Listing>,
) -> Result<(Vec<Creation>, String), Box<dyn Error>> {
    let (aid1, aid1_said) = create_identifier(
        client,
        "aid1",
        Some(AID1_PASSCODE),
        &CreateIdentifierRequest::new(CreateAlgorithm::Salty {
            passcode: Some(AID1_PASSCODE.to_owned()),
            tier: SecurityTier::Low,
            current_count: 1,
            next_count: 1,
            cost: DerivationCost::Production,
        }),
    )
    .await?;
    check(mismatches, "aid1 prefix", &aid1.derived_prefix, AID1_PREFIX);
    listings.push(list_names(client, ItemRange::DEFAULT).await?);

    let mut aid2_request = CreateIdentifierRequest::new(CreateAlgorithm::Salty {
        passcode: Some(AID2_PASSCODE.to_owned()),
        tier: SecurityTier::Low,
        current_count: 3,
        next_count: 3,
        cost: DerivationCost::Production,
    });
    aid2_request.signing_threshold = Some(SigningThreshold::numeric(2));
    aid2_request.next_threshold = Some(SigningThreshold::numeric(2));
    let (aid2, _) = create_identifier(client, "aid2", Some(AID2_PASSCODE), &aid2_request).await?;
    check(mismatches, "aid2 prefix", &aid2.derived_prefix, AID2_PREFIX);
    listings.push(list_names(client, ItemRange::DEFAULT).await?);

    let (aid3, _) = create_identifier(
        client,
        "aid3",
        None,
        &CreateIdentifierRequest::new(CreateAlgorithm::salty(None)),
    )
    .await?;

    listings.push(list_names(client, ItemRange::DEFAULT).await?);
    listings.push(list_names(client, ItemRange::new(1, 2)?).await?);
    listings.push(list_names(client, ItemRange::new(2, 2)?).await?);

    Ok((vec![aid1, aid2, aid3], aid1_said))
}

async fn rotate_aid1(client: &ConnectedClient, mismatches: &mut Vec<String>) -> Result<Rotation, Box<dyn Error>> {
    progress("aid1: rotating");
    let rotated = client
        .identifiers()
        .rotate("aid1", &RotateIdentifierRequest::default())
        .await?;
    let response = wait_and_delete(client, &rotated.operation()?.name).await?;
    let rotation = Rotation {
        derived_event: String::from_utf8(rotated.artifact().event.raw().to_vec())?,
        derived_said: rotated.artifact().event.said().qb64()?,
        agent_event: serde_json::to_string(&response)?,
    };
    check(mismatches, "rotation SAID", &rotation.derived_said, ROTATION_SAID);
    Ok(rotation)
}

async fn interact_aid1(
    client: &ConnectedClient,
    aid1_prefix: &str,
    aid1_said: &str,
    mismatches: &mut Vec<String>,
) -> Result<(Interaction, signify_keri::prefix::IdentifierPrefix), Box<dyn Error>> {
    progress("aid1: interacting");
    let mut seal = Sad::new();
    seal.insert("i", SadValue::text(aid1_prefix))?;
    seal.insert("s", SadValue::text("0"))?;
    seal.insert("d", SadValue::text(aid1_said))?;
    let port_anchor = String::from_utf8(seal.to_json_bytes()?)?;
    let interacted = client.identifiers().interact("aid1", vec![seal]).await?;
    let response = wait_and_delete(client, &interacted.operation()?.name).await?;
    let interaction = Interaction {
        upstream_anchor: aid1_prefix.to_owned(),
        upstream_said: UPSTREAM_INTERACTION_SAID,
        port_anchor,
        derived_event: String::from_utf8(interacted.artifact().event.raw().to_vec())?,
        derived_said: interacted.artifact().event.said().qb64()?,
        agent_event: serde_json::to_string(&response)?,
        note: "upstream anchors the bare string [icp.pre]; anchors here are typed Vec<Sad> \
               (Roadmap 4.6), so this run anchors a seal of the same inception and the SAID \
               differs by design",
    };
    if interaction.derived_said == UPSTREAM_INTERACTION_SAID {
        mismatches.push(
            "the interaction SAID reproduced the pinned literal, so the anchor divergence \
             this recording documents does not exist"
                .to_owned(),
        );
    }
    Ok((interaction, interacted.artifact().event.identifier().clone()))
}

async fn capture_state(
    client: &ConnectedClient,
    rotation: &Rotation,
    interaction: &Interaction,
    mismatches: &mut Vec<String>,
) -> Result<StateCapture, Box<dyn Error>> {
    let stored = client.identifiers().get("aid1").await?;
    let state = StateCapture {
        sequence: stored.state.sequence_number.clone(),
        first_seen: stored.state.first_seen.clone(),
        establishment_kind: stored.state.establishment_kind.clone(),
        digest: stored.state.digest.clone(),
        establishment_digest: stored.state.latest_establishment_event.digest.clone(),
    };
    check(mismatches, "state sequence", &state.sequence, "2");
    check(mismatches, "state first seen", &state.first_seen, "2");
    check(mismatches, "state establishment kind", &state.establishment_kind, "ixn");
    check(mismatches, "state digest", &state.digest, &interaction.derived_said);
    check(
        mismatches,
        "state establishment digest",
        &state.establishment_digest,
        &rotation.derived_said,
    );
    Ok(state)
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn the_salty_lifecycle_reproduces_the_pinned_vectors() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let transcript = recorder("salty_lifecycle")?;
    progress("connecting the client");
    let client = connect(
        &environment,
        signify_client::random::random_passcode()?.expose(),
        &transcript,
    )
    .await?;

    let mut mismatches = Vec::new();
    let mut listings = Vec::new();

    let (creations, aid1_said) = run_creations(&client, &mut mismatches, &mut listings).await?;
    let aid1_prefix = creations
        .first()
        .map(|creation| creation.derived_prefix.clone())
        .ok_or("no identifier was created")?;

    let rotation = rotate_aid1(&client, &mut mismatches).await?;
    let (interaction, prefix) = interact_aid1(&client, &aid1_prefix, &aid1_said, &mut mismatches).await?;
    let state = capture_state(&client, &rotation, &interaction, &mut mismatches).await?;

    let log = client.key_events().get(&prefix).await?;
    let mut log_saids = Vec::new();
    for entry in &log {
        log_saids.push(text_field(&serde_json::to_value(&entry.ked)?, "d")?);
    }

    progress("aid3: renaming to aid4");
    let updated = client
        .identifiers()
        .update("aid3", &IdentifierUpdate::rename("aid4"))
        .await?;
    let fetched = client.identifiers().get("aid4").await?;
    let rename = Rename {
        from: "aid3",
        to: "aid4",
        updated_name: updated.common.name.clone(),
        fetched_name: fetched.common.name.clone(),
    };
    listings.push(list_names(&client, ItemRange::new(2, 2)?).await?);

    let operations_remaining = client.operations().list(None).await?.len();

    let captured = Captured {
        scenario: "salty_lifecycle",
        preset: environment.preset.to_string(),
        creations,
        listings,
        rotation,
        interaction,
        state,
        log_saids: log_saids.clone(),
        rename,
        operations_remaining,
        transcript: transcript.observations(),
    };

    if record("observations/salty_lifecycle.json", &captured)? {
        progress("recorded observations/salty_lifecycle.json");
    } else {
        progress("not a recording run, nothing written");
    }

    assert!(
        mismatches.is_empty(),
        "the run diverged from the pinned scenario: {mismatches:#?}"
    );
    assert_eq!(
        log_saids.len(),
        3,
        "the key event log does not hold exactly three events"
    );
    assert_eq!(captured.operations_remaining, 0, "operations were left behind");
    Ok(())
}
