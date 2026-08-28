//! Hermetic assertions over what a live run recorded.
//!
//! This file is **not** ignored: it reads `fixtures/keria-integration/environment.json`, which a
//! recording run checked in, and never touches a network. That split is the whole design — a live
//! run's product is a fixture, and the assertions on it belong in the default suite where they run
//! on every change.
//!
//! Without this, a system test would prove something only on the machine that ran it. With it, the
//! evidence is in the repository and the claims about it are checked continuously.

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
        // No recording yet is a legitimate state; the matrix says as much, and the audit test
        // tracks which rows are still unobserved.
        return Ok(());
    };

    // `PORTING.md` §7 names six things a system test must record. All six, non-empty.
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

    // The identity is one of two kinds, and a localhost run may only claim the weaker one.
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
    // A localhost deployment has no image, so the served document *is* its identity — and an
    // identity is only worth recording if it is a cryptographic digest. Checked by parsing it with
    // the port's own primitive rather than by pattern: an earlier recording carried a hand-written
    // 64-bit FNV-1a under a field named `spec_sha256`, which this assertion would now refuse.
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

    // `PORTING.md` §10's `KERIA OpenAPI source revision/generator` row states the document the
    // reference's generator fetches "carries no version". A live deployment says otherwise — and
    // says it near the end of the file, which is why a reader checking the head would miss it.
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

    // Under `local` every witness is reachable from here, so every one should have been checked.
    // Under `docker` they are named for KERIA's network and cannot be, which the flag records.
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

    // Five scenarios need schemas. Whether they can run is a fact about the deployment, and it is
    // recorded either way rather than being discovered as an obscure failure later.
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

    // A finding, and a sharp one. The reference's `keria-api-schema.ts` types the whole API by
    // indexing `components['schemas'][…]` for 150 named schemas, and `PORTING.md` §10 records that
    // it is generated by fetching `/spec.yaml` from a running agent. This deployment's document has
    // **no `components:` section at all** — only `paths` and `info` — so it cannot be the document
    // those schemas came from. The port's `signify-types::api` is modelled on named schemas no
    // KERIA 1.0.1 serves.
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

    // The residual §10:9799 asks for — diffing declared `required` arrays against the pinned
    // schemas — is still possible, but against inline bodies under `paths` rather than named
    // schemas. Recording the count is what makes that a known quantity rather than a guess.
    assert!(
        manifest.keria.spec_required_arrays > 0,
        "the document declares no required arrays anywhere, so there is nothing left to diff and \
         §10:9799's residual is unclosable rather than pending"
    );
    Ok(())
}
