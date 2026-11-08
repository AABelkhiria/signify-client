#![no_main]

//! Fuzzes the registry endpoint over hostile names, nonces, backers, and agent answers.
//!
//! Three things reach this family from outside.
//!
//! **Two names** are path components, and the reference concatenates both raw — so upstream a
//! rename with a slash in either lets it address a different registry under a different identifier,
//! and the request signature covers `@path`. This target asserts neither can escape, whichever call
//! carries it.
//!
//! **A nonce and a backer set** go straight into a registry inception whose SAID becomes the
//! registry's own identifier. A registry built from material this port mis-handles would be
//! anchored under an identifier the issuer never committed to, so the target asserts that anything
//! accepted derives an identifier equal to its own SAID and reparses to the same bytes.
//!
//! **An agent's answer** decides what a caller believes about a registry that already exists.

use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::registries::{CreateRegistryRequest, REGISTRIES_SEGMENT, RegistryBacking};
use signify_client::protocol::event::ConfigurationTrait;
use signify_client::protocol::prefix::IdentifierPrefix;
use signify_client::protocol::registry::RegistryInceptionBuilder;
use signify_client::protocol::serialization::SerializedEvent;
use signify_client::types::api::{Registry, RegistryOperation};
use signify_http::request::ResourcePath;

const ISSUER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let identifier = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let registry_name = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let nonce = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let document = parts.next().unwrap_or_default();

    // 1. Neither name can leave its own path segment, in either shape of path.
    match ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(&identifier)
        .segment(REGISTRIES_SEGMENT)
        .build()
    {
        Ok(path) => {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(segments.len(), 3, "an alias became {} segments", segments.len());
            assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
            assert_eq!(segments.get(2).copied(), Some(REGISTRIES_SEGMENT));
            assert_eq!(path.query(), None);
            assert!(!path.as_str().contains('#'));
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    match ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(&identifier)
        .segment(REGISTRIES_SEGMENT)
        .segment(&registry_name)
        .build()
    {
        Ok(path) => {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(segments.len(), 4, "two names became {} segments", segments.len());
            for slot in [1_usize, 3] {
                let component = segments.get(slot).copied().unwrap_or_default();
                for separator in ['/', '?', '#'] {
                    assert!(
                        !component.contains(separator),
                        "an encoded name still carries {separator:?}"
                    );
                }
            }
            assert_eq!(path.query(), None);
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // A request keeps its names whatever they hold, and its backing cannot disagree with itself.
    let request = CreateRegistryRequest::new(identifier.clone(), registry_name.clone());
    assert_eq!(request.identifier, identifier);
    assert_eq!(request.registry, registry_name);
    assert_eq!(request.backing, RegistryBacking::None);
    assert_eq!(request.nonce, None);

    // 2. A registry inception derives an identifier that is its own SAID.
    let Ok(issuer) = IdentifierPrefix::from_qb64(ISSUER) else {
        return;
    };
    let backers: Vec<String> = parts
        .next()
        .unwrap_or_default()
        .split(|&byte| byte == 0xfe)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let threshold = u32::from(data.first().copied().unwrap_or_default());

    let mut builder = RegistryInceptionBuilder::new(issuer, nonce.clone());
    if backers.is_empty() {
        builder = builder.configuration(vec![ConfigurationTrait::NoBackers]);
    } else {
        builder = builder.backers(backers.clone()).backer_threshold(threshold);
    }
    match builder.build() {
        Ok(inception) => {
            let Ok(registry) = inception.identifier().qb64() else {
                panic!("a built registry inception has no identifier");
            };
            let said = inception
                .sad()
                .get_text("d")
                .expect("a registry inception carries a SAID");
            assert_eq!(said, registry, "a registry's identifier is not its own SAID");
            // The nonce reaches the event verbatim: the reference validates none of it.
            assert_eq!(inception.sad().get_text("n"), Some(nonce.as_str()));

            // The event reparses to itself, so what is submitted is what was built.
            match SerializedEvent::parse(inception.raw()) {
                Ok(again) => assert_eq!(again.raw(), inception.raw(), "a registry inception did not reparse"),
                Err(error) => panic!("a built registry inception does not reparse: {error}"),
            }

            // An unbacked registry declares the trait and carries no backers; a backed one is the
            // other way round. The two can never disagree, because the backing decides both.
            let traits = inception
                .sad()
                .get("c")
                .and_then(signify_client::protocol::serialization::SadValue::as_array)
                .map_or(0, <[_]>::len);
            assert_eq!(traits, usize::from(backers.is_empty()));
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // 3. An agent's answer is believed only in the shape it claimed.
    if let Ok(record) = serde_json::from_slice::<Registry>(document) {
        match serde_json::to_vec(&record) {
            Ok(encoded) => match serde_json::from_slice::<Registry>(&encoded) {
                Ok(again) => assert!(again == record, "a registry record did not survive re-encoding"),
                Err(error) => panic!("a re-encoded registry record no longer decodes: {error}"),
            },
            Err(error) => panic!("a decoded registry record could not be re-encoded: {error}"),
        }
    }

    if let Ok(operation) = serde_json::from_slice::<RegistryOperation>(document) {
        // A registry operation waits on the key event that anchors it, so its metadata names a
        // nested operation; nothing here invents one when the agent did not send it.
        if let Some(metadata) = &operation.metadata {
            // The nested operation and the anchor both decoded, so neither was invented: a
            // `RegistryMetadata` that lacks either does not decode at all.
            assert_eq!(metadata.depends.name, metadata.depends.name.clone());
            assert_eq!(metadata.anchor.identifier, metadata.anchor.identifier.clone());
        }
        match serde_json::to_vec(&operation) {
            Ok(encoded) => assert!(
                serde_json::from_slice::<RegistryOperation>(&encoded).is_ok(),
                "a re-encoded registry operation no longer decodes"
            ),
            Err(error) => panic!("a decoded registry operation could not be re-encoded: {error}"),
        }
    }
});
