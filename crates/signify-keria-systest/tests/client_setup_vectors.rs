//! Hermetic assertions over the recorded client setup.
//!
//! A pinned passcode's controller prefix, the OOBI shapes, and two clients meeting: six URLs, not three.

use std::error::Error;
use std::fs;
use std::path::Path;

use keri_protocol::prefix::IdentifierPrefix;
use serde::Deserialize;
use serde_json::Value;
use signify_keria_systest::preset::WITNESS_PREFIXES;

const PINNED_PASSCODE_UPSTREAM: &str = "0ADF2TpptgqcDE5IQUF1HeTp";
const PINNED_CONTROLLER_PREFIX: &str = "EB3UGWwIMq7ppzcQ697ImQIuXlBG5jzh-baSx-YG3-tY";
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
        .join("crates/signify-client/fixtures/keria-integration/observations/client_setup.json");
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
    assert_ne!(captured.preset, "");
    for (name, transcript) in [
        ("pinned", &captured.pinned_transcript),
        ("A", &captured.a_transcript),
        ("B", &captured.b_transcript),
    ] {
        assert!(!transcript.is_empty(), "the {name} client kept no transcript");
    }

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

    assert_eq!(pinned.passcode_upstream, PINNED_PASSCODE_UPSTREAM);
    assert_eq!(pinned.passcode_used.len(), 21);
    assert!(PINNED_PASSCODE_UPSTREAM.starts_with(&pinned.passcode_used));

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

    assert_eq!(urls.len(), SERVED_INTRODUCTION_URLS);

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
