//! Hermetic assertions over the recorded client setup.
//!
//! Wave 4 drove the **Client setup** row's two upstream files against a live deployment:
//! `test-setup-single-client.test.ts` (a pinned passcode deriving a pinned controller prefix, a
//! witnessed identifier's OOBI shapes, and the agent configuration) and
//! `test-setup-clients.test.ts` (two clients cross-resolving each other's agent OOBIs). This file
//! re-checks the recording from its own bytes; the pinned literals are declared here.
//!
//! Two findings live in this recording. The pinned passcode upstream passes is 24 characters, of
//! which the reference silently derives from the first 21 — the port refuses to truncate, so the
//! recording carries both spellings. And the deployment serves **six** introduction URLs where the
//! upstream case's local branch deep-equals exactly three, so the reference's own `validate
//! config` assertion would refuse the very deployment its suite runs against.
//!
//! Not ignored: it reads a checked-in recording and never touches a network.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use signify_keri::prefix::IdentifierPrefix;
use signify_keria_systest::preset::WITNESS_PREFIXES;

/// The passcode as `test-setup-single-client.test.ts` writes it. A published test constant.
const PINNED_PASSCODE_UPSTREAM: &str = "0ADF2TpptgqcDE5IQUF1HeTp";
/// The controller prefix upstream pins for it.
const PINNED_CONTROLLER_PREFIX: &str = "EB3UGWwIMq7ppzcQ697ImQIuXlBG5jzh-baSx-YG3-tY";
/// How many introduction URLs the deployment actually serves; upstream's local branch deep-equals
/// a three-element list, so its own assertion would refuse this deployment.
const SERVED_INTRODUCTION_URLS: usize = 6;

#[derive(Debug, Deserialize)]
struct Captured {
    scenario: String,
    preset: String,
    pinned: PinnedClient,
    cross: CrossResolution,
    pinned_transcript: Vec<Observation>,
    a_transcript: Vec<Observation>,
    b_transcript: Vec<Observation>,
}

#[derive(Debug, Deserialize)]
struct PinnedClient {
    passcode_upstream: String,
    passcode_used: String,
    derived_controller_prefix: String,
    pinned_controller_prefix: String,
    agent_prefix: String,
    identifier_prefix: String,
    agent_oobi: String,
    witness_oobis: Vec<String>,
    introduction_urls: Option<Vec<String>>,
    operations_remaining: usize,
}

#[derive(Debug, Deserialize)]
struct CrossResolution {
    a_prefix: String,
    b_prefix: String,
    a_resolved_b: String,
    b_resolved_a: String,
    a_operations_remaining: usize,
    b_operations_remaining: usize,
}

#[derive(Debug, Deserialize)]
struct Observation {
    method: String,
    resource: String,
    response_body: Option<String>,
}

fn captured() -> Result<Option<Captured>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/observations/client_setup.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

#[test]
fn the_recording_is_the_whole_scenario() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    assert_eq!(captured.scenario, "client_setup");
    assert!(!captured.preset.is_empty());
    for (name, transcript) in [
        ("pinned", &captured.pinned_transcript),
        ("A", &captured.a_transcript),
        ("B", &captured.b_transcript),
    ] {
        assert!(!transcript.is_empty(), "the {name} client kept no transcript");
    }

    // The upstream postcondition, for all three clients: every operation waited out and deleted.
    assert_eq!(captured.pinned.operations_remaining, 0);
    assert_eq!(captured.cross.a_operations_remaining, 0);
    assert_eq!(captured.cross.b_operations_remaining, 0);
    Ok(())
}

#[test]
fn the_pinned_passcode_derives_the_pinned_controller_prefix() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    let pinned = &captured.pinned;

    // The passcode's two spellings: upstream's 24 characters, and the 21 the reference silently
    // derives from — passed explicitly here, because the port refuses to truncate.
    assert_eq!(pinned.passcode_upstream, PINNED_PASSCODE_UPSTREAM);
    assert_eq!(pinned.passcode_used.len(), 21);
    assert!(PINNED_PASSCODE_UPSTREAM.starts_with(&pinned.passcode_used));

    // The one place a live run confirms the port's controller derivation against a real agent:
    // the derived prefix is the pinned literal, and the agent accepted a client whose requests it
    // could verify under that controller.
    assert_eq!(pinned.derived_controller_prefix, PINNED_CONTROLLER_PREFIX);
    assert_eq!(pinned.pinned_controller_prefix, PINNED_CONTROLLER_PREFIX);
    IdentifierPrefix::from_qb64(&pinned.derived_controller_prefix)?;
    Ok(())
}

#[test]
fn the_oobi_urls_have_the_shape_upstream_asserts() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    if captured.preset != "local" {
        // The URL literals below are the upstream case's `local` branch; a docker recording would
        // assert its other branch, and no such recording exists yet.
        return Ok(());
    }
    let pinned = &captured.pinned;

    assert_eq!(
        pinned.agent_oobi,
        format!(
            "http://127.0.0.1:3902/oobi/{}/agent/{}",
            pinned.identifier_prefix, pinned.agent_prefix
        )
    );

    // Exactly three witness OOBIs, each naming the demo witness the configuration claims, on the
    // port upstream pins for it.
    assert_eq!(pinned.witness_oobis.len(), 3);
    for (index, (oobi, prefix)) in pinned.witness_oobis.iter().zip(WITNESS_PREFIXES).enumerate() {
        assert_eq!(
            oobi,
            &format!(
                "http://127.0.0.1:{}/oobi/{}/witness/{prefix}",
                5642 + index,
                pinned.identifier_prefix
            )
        );
    }
    Ok(())
}

#[test]
fn the_agent_serves_more_introductions_than_upstream_pins() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    if captured.preset != "local" {
        return Ok(());
    }
    let urls = captured
        .pinned
        .introduction_urls
        .as_ref()
        .ok_or("the agent reported no introduction URLs at all")?;

    // The finding: upstream's `validate config` deep-equals a three-element list for the local
    // preset, and the deployment its own suite targets serves six — the running triple plus three
    // more witnesses nothing else references. If this count changes, the finding is stale and the
    // records citing it need updating, which is why it is asserted rather than described.
    assert_eq!(urls.len(), SERVED_INTRODUCTION_URLS);

    // The stable half: the first three introductions name the running witness triple, in order.
    for (url, prefix) in urls.iter().zip(WITNESS_PREFIXES) {
        assert!(
            url.contains(&format!("/oobi/{prefix}/controller")),
            "{url} does not introduce the expected witness {prefix}"
        );
    }
    Ok(())
}

#[test]
fn each_client_resolved_the_others_prefix() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };
    let cross = &captured.cross;

    // The upstream case's two assertions: resolving the other's agent OOBI answers with the
    // other's identifier prefix — the contact learned is the identifier published.
    assert_eq!(cross.a_resolved_b, cross.b_prefix);
    assert_eq!(cross.b_resolved_a, cross.a_prefix);
    assert_ne!(cross.a_prefix, cross.b_prefix);
    IdentifierPrefix::from_qb64(&cross.a_prefix)?;
    IdentifierPrefix::from_qb64(&cross.b_prefix)?;
    Ok(())
}

#[test]
fn a_live_witnessed_record_spells_its_indexes_as_numbers() -> Result<(), Box<dyn Error>> {
    let Some(captured) = captured()? else {
        return Ok(());
    };

    // The defect this wave found, re-read from the verbatim bytes: the reference's generated
    // schema declares `windexes` a `string[]`, and the deployment writes numbers. This recording
    // is what justified widening `HabCommon.witness_indexes`; if the spelling ever changes, this
    // fails and the widening's documentation needs revisiting.
    let record = captured
        .a_transcript
        .iter()
        .chain(&captured.b_transcript)
        .chain(&captured.pinned_transcript)
        .filter(|observation| observation.method == "GET" && observation.resource.starts_with("/identifiers/name"))
        .filter_map(|observation| observation.response_body.as_deref())
        .filter_map(|body| serde_json::from_str::<Value>(body).ok())
        .find_map(|body| body.get("windexes").cloned())
        .ok_or("no recorded identifier record carries windexes")?;
    let indexes = record.as_array().ok_or("windexes is not a list")?;
    assert!(!indexes.is_empty(), "the witnessed record names no witness indexes");
    for index in indexes {
        assert!(index.is_u64(), "a witness index is not a JSON number: {index}");
    }
    Ok(())
}
