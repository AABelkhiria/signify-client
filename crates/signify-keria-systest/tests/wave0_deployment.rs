//! Wave 0 — what deployment is this, exactly?
//!
//! Records the deployment's identity, its witnesses, and its schema source before any identifier exists.
//!
//! ```text
//! SIGNIFY_KERIA_PRESET=local SIGNIFY_RECORD=1 cargo test -p signify-keria-systest \
//!     --features live --test wave0_deployment -- --ignored --test-threads=1
//! ```

#![cfg(feature = "live")]

use std::error::Error;
use std::sync::Arc;

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use serde::Serialize;
use signify_http::transport::{HttpTransport, Method, Request, RequestUrl, Transport};
use signify_keria_systest::{Environment, Preset, record};

#[derive(Debug, Serialize)]
struct Manifest {
    keria: Identity,
    witnesses: Vec<Witness>,
    schema_source: SchemaSource,
    environment_variables: Vec<(String, String)>,
    startup_command: String,
    timeout_policy: String,
    note: String,
}

#[derive(Debug, Serialize)]
struct Identity {
    kind: &'static str,
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

fn digest(text: &str) -> Result<String, Box<dyn Error>> {
    Ok(Digest::derive(DigestAlgorithm::Blake3_256, text.as_bytes()).qb64()?)
}

async fn fetch(transport: &Arc<HttpTransport>, url: &str) -> Result<(u16, String), Box<dyn Error>> {
    let request = Request::builder(Method::Get, RequestUrl::new(url)?).build()?;
    let response = transport.execute(request).await?;
    let body = String::from_utf8_lossy(response.body()).into_owned();
    Ok((response.status().as_u16(), body))
}

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
        "the served document carries no version — which is what the OpenAPI source residual claims, and this run \
         would then confirm rather than correct"
    );

    let mut witnesses = Vec::new();
    for (url, expected) in environment.witness_urls.iter().zip(&environment.witness_prefixes) {
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
            "docker compose up --wait (tools/reference-vectors/upstream/signify-ts/docker-compose.yaml)".to_owned()
        },
        timeout_policy: "the production transport's default deadline covers each exchange; no \
                         scenario sleeps, and every wait polls a condition"
            .to_owned(),
        note: "A `local` run cannot close the `Target KERIA integration version` question: that \
               question asks for an image digest, and a KERIA on the host has no image. What this \
               records is the strongest identity available — the document the agent serves about \
               itself — which also answers the `KERIA OpenAPI source revision/generator` \
               residual, whose text claims that document `carries no version`."
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

    let qvi = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
    let reachable = fetch(&transport, &format!("{}/oobi/{qvi}", environment.schema_url)).await;
    assert!(
        reachable.is_ok(),
        "the schema source at {} serves no QVI schema, so the credential scenarios cannot run. Any \
         host that answers /oobi/{{said}} will do, named by SIGNIFY_KERIA_SCHEMA_URL. The \
         reference's own is: docker run -p 7723:7723 gleif/vlei:1.0.3 vLEI-server -s /vLEI/schema \
         -c /vLEI/credentials -o /vLEI/oobis",
        environment.schema_url
    );
    Ok(())
}
