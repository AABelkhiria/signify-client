//! Invariants of the delegation endpoint.
//!
//! One alias addressing two requests must agree, and the seal's three fields are always written in order.

use std::error::Error;

use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use proptest::prelude::*;
use signify_client::endpoint::delegations::{
    DELEGATION_SEGMENT, InceptionSeal, SEAL_DIGEST_LABEL, SEAL_IDENTIFIER_LABEL, SEAL_SEQUENCE_LABEL,
};
use signify_client::endpoint::identifiers::{EVENTS_SEGMENT, IDENTIFIERS_SEGMENT};
use signify_http::request::ResourcePath;

const DELEGATE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const DELEGATOR: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const DIGEST: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

fn read_path(alias: &str) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(alias)
        .build()?)
}

fn write_path(alias: &str, segment: &str) -> Result<ResourcePath, Box<dyn Error>> {
    Ok(ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(alias)
        .segment(segment)
        .build()?)
}

fn aliases() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("delegator".to_owned()),
        Just(DELEGATOR.to_owned()),
        "[a-z][a-z0-9-]{0,16}",
        "[\\PC]{1,32}",
        Just("a/b?c=d".to_owned()),
        Just("..".to_owned()),
        Just("../identifiers".to_owned()),
    ]
}

fn qualified() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(DELEGATE.to_owned()),
        Just(DELEGATOR.to_owned()),
        Just(DIGEST.to_owned()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn the_read_and_the_write_treat_the_alias_the_same_way(alias in aliases()) {
        let read = read_path(&alias).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let write = write_path(&alias, DELEGATION_SEGMENT)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let alias_of = |path: &ResourcePath| -> Option<String> {
            path.path().split('/').nth(2).map(ToOwned::to_owned)
        };
        prop_assert_eq!(alias_of(&read), alias_of(&write));
        prop_assert!(write.as_str().starts_with(read.as_str()));
        prop_assert_eq!(write.as_str(), format!("{}/{}", read.as_str(), DELEGATION_SEGMENT));
    }

    #[test]
    fn the_two_addresses_differ_only_in_their_action(alias in aliases()) {
        let approval = write_path(&alias, DELEGATION_SEGMENT)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let interaction = write_path(&alias, EVENTS_SEGMENT)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let shared = |path: &ResourcePath| -> Vec<String> {
            path.path().split('/').skip(1).take(2).map(ToOwned::to_owned).collect()
        };
        prop_assert_eq!(shared(&approval), shared(&interaction));
        prop_assert_ne!(approval.as_str(), interaction.as_str());
        prop_assert!(approval.as_str().ends_with(DELEGATION_SEGMENT));
        prop_assert!(interaction.as_str().ends_with(EVENTS_SEGMENT));
    }

    #[test]
    fn a_seal_always_writes_its_own_three_values(
        delegate in qualified(),
        digest in qualified(),
    ) {
        let seal = InceptionSeal::new(
            IdentifierPrefix::from_qb64(&delegate).map_err(|error| TestCaseError::fail(error.to_string()))?,
            digest.parse::<Said>().map_err(|error| TestCaseError::fail(error.to_string()))?,
        );
        let written = seal.to_sad().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let bytes = written.to_json_bytes().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let text = String::from_utf8(bytes).map_err(|error| TestCaseError::fail(error.to_string()))?;

        prop_assert_eq!(&text, &format!(r#"{{"i":"{delegate}","s":"0","d":"{digest}"}}"#));
        prop_assert_eq!(written.get_text(SEAL_IDENTIFIER_LABEL), Some(delegate.as_str()));
        prop_assert_eq!(written.get_text(SEAL_DIGEST_LABEL), Some(digest.as_str()));
        prop_assert_eq!(written.get_text(SEAL_SEQUENCE_LABEL), Some("0"));
        prop_assert_eq!(seal.delegate().qb64().ok(), Some(delegate));
        prop_assert_eq!(seal.digest().qb64().ok(), Some(digest));
    }

    #[test]
    fn arbitrary_aliases_address_or_are_refused(alias in "\\PC*") {
        match write_path(&alias, DELEGATION_SEGMENT) {
            Ok(path) => {
                prop_assert_eq!(path.path().split('/').count(), 4);
                prop_assert_eq!(path.query(), None);
            }
            Err(error) => prop_assert!(!error.to_string().is_empty()),
        }
    }
}

#[test]
fn the_pinned_address_reproduces() -> Result<(), Box<dyn Error>> {
    let pinned = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
    assert_eq!(
        write_path(pinned, DELEGATION_SEGMENT)?.as_str(),
        format!("/identifiers/{pinned}/delegation")
    );
    Ok(())
}

#[test]
fn the_alias_the_reference_disagrees_with_itself_about() -> Result<(), Box<dyn Error>> {
    let alias = "a/b?c=d";
    assert_eq!(read_path(alias)?.as_str(), "/identifiers/a%2Fb%3Fc%3Dd");
    assert_eq!(
        write_path(alias, DELEGATION_SEGMENT)?.as_str(),
        "/identifiers/a%2Fb%3Fc%3Dd/delegation"
    );
    Ok(())
}

#[test]
fn the_seal_the_scenario_anchors_reproduces() -> Result<(), Box<dyn Error>> {
    let seal = InceptionSeal::new(IdentifierPrefix::from_qb64(DELEGATE)?, DELEGATE.parse::<Said>()?);
    assert_eq!(
        String::from_utf8(seal.to_sad()?.to_json_bytes()?)?,
        format!(r#"{{"i":"{DELEGATE}","s":"0","d":"{DELEGATE}"}}"#)
    );
    Ok(())
}
