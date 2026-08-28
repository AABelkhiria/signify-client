//! Wave 0 — what deployment is this, exactly?
//!
//! `PORTING.md` §7 refuses "passes against latest" as evidence and asks a system test to record six
//! things: the KERIA image or version, the witness configuration, the schema source, the
//! environment variables, the startup command, and the timeout policy. §10's `Target KERIA
//! integration version` row asks for the same in different words.
//!
//! This scenario captures what a deployment can be asked about itself, before any identifier
//! exists. It is the cheapest thing to run and the first thing every later wave depends on.
//!
//! **A localhost run cannot close §10's version row.** That row asks for an image *digest*, and a
//! KERIA running on the host has no image. What it does have is the `OpenAPI` document it serves,
//! which is captured verbatim with its hash — the strongest identity available, and enough to close
//! a different obligation: §10:9799's residual, "confirm the schema's required fields against a live
//! deployment".
//!
//! Run with:
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave0_deployment -- --ignored --test-threads=1
//! ```

#![cfg(feature = "live")]

use std::error::Error;
use std::sync::Arc;

use serde::Serialize;
use signify_crypto::digest::{Digest, DigestAlgorithm};
use signify_http::transport::{HttpTransport, Method, Request, RequestUrl, Transport};
use signify_keria_systest::{Environment, Preset, record};

/// The six things `PORTING.md` §7 requires a system test to record about its deployment.
#[derive(Debug, Serialize)]
struct Manifest {
    /// How the deployment is identified. On `docker` this is an image digest; on `local` there is
    /// no image, so it is the hash of the `OpenAPI` document the agent itself serves.
    keria: Identity,
    /// The witnesses, and the prefixes they were observed to serve.
    witnesses: Vec<Witness>,
    /// Where schemas come from, and whether it answered.
    schema_source: SchemaSource,
    /// The environment variables this run actually used.
    environment_variables: Vec<(String, String)>,
    /// How the deployment was started, as far as this run can know.
    startup_command: String,
    /// What this run waited for, and for how long.
    timeout_policy: String,
    /// Why a `local` run cannot close §10's version row.
    note: String,
}

#[derive(Debug, Serialize)]
struct Identity {
    kind: &'static str,
    preset: String,
    admin_url: String,
    spec_version: Option<String>,
    spec_openapi: Option<String>,
    /// BLAKE3-256 of the served document, qb64, which is this deployment's only stable identity.
    spec_digest: String,
    spec_bytes: usize,
    spec_line_of_version: Option<usize>,
    /// The top-level keys that open a block, in the order the document writes them.
    spec_sections: Vec<String>,
    /// How many `required:` arrays the document declares, all of them inline under `paths`.
    spec_required_arrays: usize,
    /// Whether the document defines the named schemas the reference's generated types index into.
    spec_defines_components: bool,
}

#[derive(Debug, Serialize)]
struct Witness {
    url: String,
    expected_prefix: String,
    observed: bool,
}

#[derive(Debug, Serialize)]
struct SchemaSource {
    url: String,
    reachable: bool,
    note: &'static str,
}

/// A hash of the served document, so a deployment change is visible as a diff.
///
/// Not a cryptographic requirement — this is an identity for a thing that has no version of its
/// own — so a small dependency-free digest is enough, and is recorded as what it is.
fn digest(text: &str) -> Result<String, Box<dyn Error>> {
    // BLAKE3-256, qb64, through the port's own primitive rather than a hand-rolled one: a
    // localhost deployment has no image to pin, so this document *is* its identity, and an
    // identity worth recording has to be a cryptographic digest. An earlier draft used a
    // hand-written 64-bit FNV-1a under a field named `spec_sha256` — neither the algorithm the
    // name claimed nor strong enough to be evidence.
    Ok(Digest::derive(DigestAlgorithm::Blake3_256, text.as_bytes()).qb64()?)
}

/// Fetches one URL and returns its status and body.
async fn fetch(transport: &Arc<HttpTransport>, url: &str) -> Result<(u16, String), Box<dyn Error>> {
    let request = Request::builder(Method::Get, RequestUrl::new(url)?).build()?;
    let response = transport.execute(request).await?;
    let body = String::from_utf8_lossy(response.body()).into_owned();
    Ok((response.status().as_u16(), body))
}

/// Reads the served `OpenAPI` document's identity and shape.
///
/// Split out of the scenario so the reading is one thing and the recording another.
fn keria_identity(spec: &str) -> Result<Identity, Box<dyn Error>> {
    Ok(Identity {
        kind: "",
        preset: String::new(),
        admin_url: String::new(),
        spec_version: None,
        spec_openapi: None,
        spec_digest: digest(spec)?,
        spec_bytes: spec.len(),
        spec_line_of_version: spec
            .lines()
            .position(|line| line.trim().starts_with("version: "))
            .map(|index| index + 1),
        // What the document is made of. This matters more than it looks: the reference's
        // `keria-api-schema.ts` indexes into `components['schemas'][…]` for 150 named
        // schemas, and a document with no `components:` section cannot have produced them.
        spec_sections: spec
            .lines()
            .filter_map(|line| {
                let key = line.strip_suffix(':')?;
                (!key.is_empty() && key.chars().all(|character| character.is_ascii_alphabetic()))
                    .then(|| key.to_owned())
            })
            .collect(),
        spec_required_arrays: spec.matches("required:").count(),
        spec_defines_components: spec.contains("components:"),
    })
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn the_deployment_identifies_itself() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    let transport = Arc::new(HttpTransport::new()?);

    // The agent's own OpenAPI document. On a localhost deployment this is its only reproducible
    // identity, and §10:9799 says the reference's generator "carries no version" — a claim made
    // without a deployment to check it against.
    let (status, spec) = fetch(&transport, &environment.spec_url).await?;
    assert_eq!(status, 200, "the agent served no `OpenAPI` document");
    assert!(
        spec.contains("openapi:"),
        "the document is not an `OpenAPI` specification"
    );

    let version = spec
        .lines()
        .skip_while(|line| !line.starts_with("info:"))
        .find_map(|line| line.trim().strip_prefix("version: "))
        .map(ToOwned::to_owned);
    assert!(
        version.is_some(),
        "the served document carries no version — which is what §10:9799 claims, and this run \
         would then confirm rather than correct"
    );

    // The witnesses this deployment actually serves, checked against the prefixes the environment
    // claims. The reference inlines this triple in nine files and never checks it against a
    // deployment at all.
    let mut witnesses = Vec::new();
    for (url, expected) in environment.witness_urls.iter().zip(&environment.witness_prefixes) {
        // A `docker` preset names hosts only KERIA can resolve, so a witness is only reachable
        // from here under `local`.
        let observed = if environment.preset == Preset::Local {
            let (status, body) = fetch(&transport, &format!("{url}/oobi")).await?;
            assert_eq!(status, 200, "{url} served no OOBI");
            assert!(
                body.contains(expected.as_str()),
                "{url} serves a witness other than {expected}"
            );
            true
        } else {
            false
        };
        witnesses.push(Witness {
            url: url.clone(),
            expected_prefix: expected.clone(),
            observed,
        });
    }

    let schema_reachable = environment.preset == Preset::Local
        && fetch(
            &transport,
            &format!(
                "{}/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
                environment.schema_url
            ),
        )
        .await
        .is_ok();

    let manifest = Manifest {
        keria: Identity {
            kind: if environment.preset == Preset::Local {
                "spec_digest"
            } else {
                "image_digest"
            },
            preset: environment.preset.to_string(),
            admin_url: environment.admin_url.clone(),
            spec_version: version.clone(),
            spec_openapi: spec
                .lines()
                .find_map(|line| line.trim().strip_prefix("openapi: "))
                .map(ToOwned::to_owned),
            ..keria_identity(&spec)?
        },
        witnesses,
        schema_source: SchemaSource {
            url: environment.schema_url.clone(),
            reachable: schema_reachable,
            note: "Five of the twenty-two upstream scenarios need this server. When it is absent \
                   those five stay unobserved with the reason `vlei_unavailable`.",
        },
        environment_variables: environment.recorded_variables(),
        startup_command: if environment.preset == Preset::Local {
            "started outside this repository; a local KERIA has no compose file to hash".to_owned()
        } else {
            "docker compose up --wait (reference/signify-ts/docker-compose.yaml)".to_owned()
        },
        timeout_policy: "the production transport's default deadline covers each exchange; no \
                         scenario sleeps, and every wait polls a condition"
            .to_owned(),
        note: "A `local` run cannot close PORTING.md §10's `Target KERIA integration version` row: \
               that row asks for an image digest, and a KERIA on the host has no image. What this \
               records is the strongest identity available — the document the agent serves about \
               itself — which also answers §10:9799's residual, whose text claims that document \
               `carries no version`."
            .to_owned(),
    };

    let written = record("environment.json", &manifest)?;
    if written {
        assert!(manifest.keria.spec_version.is_some());
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires a live KERIA; see the crate documentation for the invocation"]
async fn the_schema_server_is_reachable_or_says_it_is_not() -> Result<(), Box<dyn Error>> {
    let environment = Environment::from_environment()?;
    if environment.preset != Preset::Local {
        return Ok(());
    }
    let transport = Arc::new(HttpTransport::new()?);

    // Five of the twenty-two scenarios need schemas. This is the one check that says whether those
    // five can run at all, and it fails loudly rather than letting them fail obscurely later.
    let qvi = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
    let reachable = fetch(&transport, &format!("{}/oobi/{qvi}", environment.schema_url)).await;
    assert!(
        reachable.is_ok(),
        "the vLEI schema server at {} is unreachable, so the five credential scenarios cannot run. \
         Start it with: docker run -p 7723:7723 gleif/vlei:1.0.3 vLEI-server -s /vLEI/schema \
         -c /vLEI/credentials -o /vLEI/oobis",
        environment.schema_url
    );
    Ok(())
}
