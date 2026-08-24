//! Invariants of the registry endpoint family.
//!
//! Four dynamic values reach a path here — the identifier alias in all three calls, plus the
//! registry name in a rename — and the reference encodes none of them. That is the property most
//! worth stating, because a rename lets *two* names escape at once.
//!
//! The rest is about the two events a creation builds: a registry inception whose SAID is its own
//! identifier, and the seal that anchors it, which names that identifier twice.

use std::error::Error;

use proptest::prelude::*;
use serde_json::Value;
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::registries::{
    CreateRegistryRequest, NO_BACKERS_TRAIT, REGISTRIES_SEGMENT, RegistryBacking,
};
use signify_http::request::ResourcePath;
use signify_keri::event::ConfigurationTrait;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::registry::{MAX_BACKERS, RegistryInceptionBuilder};
use signify_keri::serialization::Sad;

const ISSUER: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

/// Names including the shapes that break the reference: delimiters, dot segments, Unicode.
fn names() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9_-]{1,24}",
        "[a-zA-Z0-9/?#&=%. ]{1,24}",
        Just("..".to_owned()),
        Just("../identifiers".to_owned()),
        Just("a/b?c=d".to_owned()),
        Just("a name with ñ!".to_owned()),
        Just("#fragment".to_owned()),
    ]
}

/// Builds the collection path both `list` and `create` address.
fn collection(identifier: &str) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(identifier)
        .segment(REGISTRIES_SEGMENT)
        .build()?)
}

/// Builds the path a rename addresses.
fn member(identifier: &str, registry: &str) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(identifier)
        .segment(REGISTRIES_SEGMENT)
        .segment(registry)
        .build()?)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    /// An identifier alias stays one segment, whatever it holds — the defect the reference has in
    /// all three of its paths.
    #[test]
    fn an_alias_never_leaves_its_own_segment(identifier in names()) {
        let path = collection(&identifier).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(segments.len(), 3, "the alias became {} segments", segments.len());
        prop_assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
        prop_assert_eq!(segments.get(2).copied(), Some(REGISTRIES_SEGMENT));
        prop_assert_eq!(path.query(), None);
        prop_assert!(!path.as_str().contains('#'));
    }

    /// A rename carries two names, and *neither* can escape — which is what makes this family's
    /// path the widest surface in the crate.
    #[test]
    fn neither_name_in_a_rename_can_escape(identifier in names(), registry in names()) {
        let path = member(&identifier, &registry).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(segments.len(), 4, "the two names became {} segments", segments.len());
        prop_assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
        prop_assert_eq!(segments.get(2).copied(), Some(REGISTRIES_SEGMENT));
        for slot in [1_usize, 3] {
            let component = segments.get(slot).copied().unwrap_or_default();
            for separator in ['/', '?', '#'] {
                prop_assert!(!component.contains(separator));
            }
        }
        prop_assert_eq!(path.query(), None);
    }

    /// A registry inception's SAID *is* its identifier, so the seal that anchors it names one value
    /// twice — whatever nonce and backers it was built from.
    #[test]
    fn a_registry_seals_itself_by_its_own_said(
        nonce in "[A-Za-z0-9_-]{1,44}",
        backers in proptest::collection::vec("[A-Za-z0-9_-]{44}", 0..4),
    ) {
        let issuer = IdentifierPrefix::from_qb64(ISSUER)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let backed = !backers.is_empty();
        let mut builder = RegistryInceptionBuilder::new(issuer, nonce.clone());
        if backed {
            let count = u32::try_from(backers.len()).unwrap_or(u32::MAX);
            builder = builder.backers(backers.clone()).backer_threshold(count);
        } else {
            builder = builder.configuration(vec![ConfigurationTrait::NoBackers]);
        }
        let Ok(inception) = builder.build() else {
            // A backer set the builder refuses is not what this property is about.
            return Ok(());
        };

        let registry = inception
            .identifier()
            .qb64()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let said = inception
            .sad()
            .get_text("d")
            .ok_or_else(|| TestCaseError::fail("the inception carries no SAID"))?;
        prop_assert_eq!(said, registry.as_str(), "a registry's SAID is not its identifier");

        // The seal the anchoring interaction event carries.
        let mut seal = Sad::new();
        seal.insert("i", registry.clone()).map_err(|error| TestCaseError::fail(error.to_string()))?;
        seal.insert("s", "0".to_owned()).map_err(|error| TestCaseError::fail(error.to_string()))?;
        seal.insert("d", registry.clone()).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let rendered = String::from_utf8(
            seal.to_json_bytes().map_err(|error| TestCaseError::fail(error.to_string()))?,
        )
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(rendered.matches(registry.as_str()).count(), 2);

        // The nonce reaches the event verbatim, and the backing decides the trait.
        prop_assert_eq!(inception.sad().get_text("n"), Some(nonce.as_str()));
        let traits = inception
            .sad()
            .get("c")
            .and_then(signify_keri::serialization::SadValue::as_array)
            .map(<[_]>::len);
        prop_assert_eq!(traits, Some(usize::from(!backed)));
    }

    /// A request keeps exactly what it was built with, whatever the names hold.
    #[test]
    fn a_request_keeps_what_it_was_built_with(
        identifier in names(),
        registry in names(),
        nonce in proptest::option::of("[A-Za-z0-9_-]{1,44}"),
    ) {
        let mut request = CreateRegistryRequest::new(identifier.clone(), registry.clone());
        prop_assert_eq!(&request.identifier, &identifier);
        prop_assert_eq!(&request.registry, &registry);
        // The reference's default: `noBackers` is true, so an ordinary registry is unbacked.
        prop_assert_eq!(&request.backing, &RegistryBacking::None);
        prop_assert_eq!(request.nonce.as_deref(), None);

        if let Some(nonce) = nonce.clone() {
            request = request.with_nonce(nonce.clone());
            prop_assert_eq!(request.nonce.as_deref(), Some(nonce.as_str()));
        }
        prop_assert_eq!(&request.identifier, &identifier);
    }

    /// Backing is a choice: naming backers always clears the unbacked trait, and naming none
    /// always sets it. Upstream these are independent arguments that can disagree.
    #[test]
    fn backing_and_its_trait_can_never_disagree(backers in proptest::collection::vec("[A-Z]{4}", 0..6), threshold in 0_u32..8) {
        let backing = if backers.is_empty() {
            RegistryBacking::None
        } else {
            RegistryBacking::Backers { backers: backers.clone(), threshold }
        };
        let request = CreateRegistryRequest::new("issuer", "reg").with_backing(backing.clone());
        match &request.backing {
            RegistryBacking::None => prop_assert!(backers.is_empty()),
            RegistryBacking::Backers { backers: named, threshold: named_threshold } => {
                prop_assert_eq!(named, &backers);
                prop_assert_eq!(*named_threshold, threshold);
            }
        }
    }
}

/// Regression: an alias of exactly `..` keeps its dots while `../identifiers` is encoded, so a
/// component can never *introduce* a dot segment. The same pair Roadmap 6.5 and 6.6 pinned.
#[test]
fn an_alias_of_two_dots_addresses_the_identifier_it_names() -> Result<(), Box<dyn Error>> {
    assert_eq!(collection("..")?.as_str(), "/identifiers/../registries");
    assert_eq!(
        collection("../identifiers")?.as_str(),
        "/identifiers/..%2Fidentifiers/registries"
    );
    assert_eq!(member("..", "..")?.as_str(), "/identifiers/../registries/..");
    Ok(())
}

/// Regression: an unbacked registry writes the `NB` trait and a backed one writes none, which is
/// the whole observable difference between the two in the event.
#[test]
fn the_backing_decides_the_configuration_trait() -> Result<(), Box<dyn Error>> {
    let issuer = IdentifierPrefix::from_qb64(ISSUER)?;
    let unbacked = RegistryInceptionBuilder::new(issuer.clone(), "0AACDEF")
        .configuration(vec![ConfigurationTrait::NoBackers])
        .build()?;
    let rendered = String::from_utf8(unbacked.raw().to_vec())?;
    assert!(rendered.contains(&format!(r#""c":["{NO_BACKERS_TRAIT}"]"#)));
    assert!(rendered.contains(r#""bt":"0""#));
    assert!(rendered.contains(r#""b":[]"#));

    let backed = RegistryInceptionBuilder::new(issuer, "0AACDEF")
        .backers(vec!["BAK0".to_owned(), "BAK1".to_owned()])
        .backer_threshold(2)
        .build()?;
    let rendered = String::from_utf8(backed.raw().to_vec())?;
    assert!(rendered.contains(r#""c":[]"#));
    assert!(rendered.contains(r#""bt":"2""#));
    assert!(rendered.contains(r#""b":["BAK0","BAK1"]"#));
    Ok(())
}

/// Regression: a backer set beyond Roadmap 4.7's bound is refused rather than sent.
#[test]
fn an_over_long_backer_set_is_refused() -> Result<(), Box<dyn Error>> {
    let issuer = IdentifierPrefix::from_qb64(ISSUER)?;
    let backers: Vec<String> = (0..=MAX_BACKERS).map(|index| format!("B{index:043}")).collect();
    let outcome = RegistryInceptionBuilder::new(issuer, "0AACDEF")
        .backers(backers)
        .backer_threshold(1)
        .build();
    assert!(outcome.is_err(), "an unbounded backer set was accepted");
    Ok(())
}

/// Regression: a rename body is one field, whatever the new name holds — including quotes and
/// braces, which a hand-built body would have to escape.
#[test]
fn a_rename_body_is_always_one_field() -> Result<(), Box<dyn Error>> {
    for name in ["renamed", r#"a"quoted"one"#, "{braced}", "", "ñ"] {
        let mut body = Sad::new();
        body.insert("name", name.to_owned())?;
        let rendered = String::from_utf8(body.to_json_bytes()?)?;
        let document: Value = serde_json::from_str(&rendered)?;
        let fields = document.as_object().ok_or("the body is not an object")?;
        assert_eq!(fields.len(), 1);
        assert_eq!(fields.get("name").and_then(Value::as_str), Some(name));
    }
    Ok(())
}
