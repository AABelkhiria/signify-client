//! Hermetic assertions over what a live run recorded.
//!
//! The six things a system test must record, and a served document with no `components:` section.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use signify_crypto::digest::{Digest, DigestAlgorithm};

#[derive(Debug, Deserialize)]
struct Manifest {
    keria: Identity,
    witnesses: Vec<Witness>,
    schema_source: SchemaSource,
    environment_variables: Vec<(String, String)>,
    startup_command: String,
    timeout_policy: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Identity {
    kind: String,
    preset: String,
    admin_url: String,
    spec_version: Option<String>,
    spec_openapi: Option<String>,
    spec_digest: String,
    spec_bytes: usize,
    spec_line_of_version: Option<usize>,
    spec_sections: Vec<String>,
    spec_required_arrays: usize,
    spec_defines_components: bool,
}

#[derive(Debug, Deserialize)]
struct Witness {
    url: String,
    expected_prefix: String,
    observed: bool,
}

#[derive(Debug, Deserialize)]
struct SchemaSource {
    url: String,
    reachable: bool,
    note: String,
}

fn manifest() -> Result<Option<Manifest>, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the workspace root is not two levels above the manifest")?
        .join("fixtures/keria-integration/environment.json");
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

#[test]
fn the_recorded_deployment_describes_itself_completely() -> Result<(), Box<dyn Error>> {
    let Some(manifest) = manifest()? else {
        return Ok(());
    };

    assert!(!manifest.keria.kind.is_empty() && !manifest.keria.preset.is_empty());
    assert!(!manifest.keria.admin_url.is_empty());
    assert!(!manifest.witnesses.is_empty(), "no witness configuration was recorded");
    assert!(!manifest.schema_source.url.is_empty());
    assert!(!manifest.environment_variables.is_empty());
    assert!(!manifest.startup_command.is_empty());
    assert!(!manifest.timeout_policy.is_empty());
    assert!(
        manifest.note.len() > 100,
        "the manifest does not say what it cannot close"
    );

    assert!(
        matches!(manifest.keria.kind.as_str(), "spec_digest" | "image_digest"),
        "unknown identity kind {}",
        manifest.keria.kind
    );
    if manifest.keria.preset == "local" {
        assert_eq!(
            manifest.keria.kind, "spec_digest",
            "a localhost run claimed an image digest it cannot have"
        );
    }
    let digest = Digest::from_qb64(&manifest.keria.spec_digest)?;
    assert_eq!(digest.algorithm(), DigestAlgorithm::Blake3_256);
    assert!(manifest.keria.spec_bytes > 1_000);
    Ok(())
}

#[test]
fn the_served_specification_carries_a_version() -> Result<(), Box<dyn Error>> {
    let Some(manifest) = manifest()? else {
        return Ok(());
    };

    let version = manifest
        .keria
        .spec_version
        .as_deref()
        .ok_or("the recorded specification carries no version, which would confirm §10:9799")?;
    assert!(!version.is_empty());
    assert!(
        manifest.keria.spec_openapi.is_some(),
        "the document declares no OpenAPI version"
    );

    let line = manifest
        .keria
        .spec_line_of_version
        .ok_or("the version's position was not recorded")?;
    assert!(
        line > 100,
        "the version is at line {line}, so §10:9799's reading of the document was reasonable"
    );
    Ok(())
}

#[test]
fn every_recorded_witness_served_the_prefix_it_was_expected_to() -> Result<(), Box<dyn Error>> {
    let Some(manifest) = manifest()? else {
        return Ok(());
    };

    assert_eq!(
        manifest.witnesses.len(),
        3,
        "the demo configuration serves three witnesses"
    );
    for witness in &manifest.witnesses {
        assert!(witness.url.starts_with("http"), "a witness has no URL");
        assert_eq!(
            witness.expected_prefix.len(),
            44,
            "{} names something that is not a prefix",
            witness.url
        );
    }

    if manifest.keria.preset == "local" {
        assert!(
            manifest.witnesses.iter().all(|witness| witness.observed),
            "a localhost run left a witness unchecked"
        );
    }
    Ok(())
}

#[test]
fn an_absent_schema_server_is_recorded_rather_than_hidden() -> Result<(), Box<dyn Error>> {
    let Some(manifest) = manifest()? else {
        return Ok(());
    };

    assert!(manifest.schema_source.note.len() > 60);
    if !manifest.schema_source.reachable {
        assert!(
            manifest.schema_source.note.contains("vlei_unavailable"),
            "the manifest records an absent schema server without naming the reason the ledger uses"
        );
    }
    Ok(())
}

#[test]
fn the_served_document_does_not_define_the_schemas_the_reference_generated_from() -> Result<(), Box<dyn Error>> {
    let Some(manifest) = manifest()? else {
        return Ok(());
    };

    assert!(
        !manifest.keria.spec_defines_components,
        "the deployment now serves a components section, so the reference's generated schemas may \
         have a source after all and §10:9799's residual should be re-read"
    );
    assert!(
        manifest.keria.spec_sections.iter().any(|section| section == "paths"),
        "the document has no paths section, which would make it not an API description at all"
    );
    assert!(
        !manifest
            .keria
            .spec_sections
            .iter()
            .any(|section| section == "components"),
        "the section list and the components flag disagree"
    );

    assert!(
        manifest.keria.spec_required_arrays > 0,
        "the document declares no required arrays anywhere, so there is nothing left to diff and \
         §10:9799's residual is unclosable rather than pending"
    );
    Ok(())
}
