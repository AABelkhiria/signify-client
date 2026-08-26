//! Invariants of the delegation endpoint.
//!
//! Two things vary: the alias the approval is posted under, and the seal it anchors.
//!
//! The alias is an address, and the property is the one every family here states — a value never
//! leaves its own path segment. What is particular to this family is that **the same alias
//! addresses two requests in one call**: `approve` reads the identifier and then writes to it, and
//! upstream encodes the first and concatenates the second. Both are built the same way here, so the
//! property is that they agree.
//!
//! The seal is the payload, and it is the whole point of the call: a delegated identifier stays
//! pending until this exact three-field block appears in the delegator's log. So the properties are
//! that the three fields are always written, always in the reference's order, and always the values
//! the seal was built from — never transcribed, never defaulted, never absent.

use std::error::Error;

use proptest::prelude::*;
use signify_client::endpoint::delegations::{
    DELEGATION_SEGMENT, InceptionSeal, SEAL_DIGEST_LABEL, SEAL_IDENTIFIER_LABEL, SEAL_SEQUENCE_LABEL,
};
use signify_client::endpoint::identifiers::{EVENTS_SEGMENT, IDENTIFIERS_SEGMENT};
use signify_http::request::{ResourcePath, encode_path_component};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;

const DELEGATE: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const DELEGATOR: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const DIGEST: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/// The two addresses one `approve` visits, built the way this port builds them.
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

/// The forty-four-character qualified values a seal is built from.
fn qualified() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(DELEGATE.to_owned()),
        Just(DELEGATOR.to_owned()),
        Just(DIGEST.to_owned()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// An alias never leaves its own segment, whatever it holds.
    #[test]
    fn an_alias_never_leaves_its_own_segment(alias in aliases()) {
        let path = write_path(&alias, DELEGATION_SEGMENT)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let segments: Vec<&str> = path.path().split('/').skip(1).collect();
        prop_assert_eq!(segments.len(), 3, "the alias {:?} became {} segments", alias, segments.len());
        prop_assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
        prop_assert_eq!(segments.last().copied(), Some(DELEGATION_SEGMENT));
        let encoded = encode_path_component(&alias);
        prop_assert_eq!(segments.get(1).copied(), Some(encoded.as_str()));
        prop_assert_eq!(path.query(), None, "the alias {:?} introduced a query", alias);
        // Roadmap 3.10 signs the path, so what is signed is exactly what is sent.
        prop_assert_eq!(path.path(), path.as_str());
    }

    /// The read and the write in one call agree about the alias.
    ///
    /// Upstream they do not: `approve` reads through `identifiers().get`, which encodes, and then
    /// concatenates its own path — so `a/b?c=d` is one segment on the read and two segments and a
    /// query on the write, inside a single method.
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

    /// An approval and an interaction share every segment but their last.
    ///
    /// Which is the whole of the difference between them, in the reference as here.
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

    /// A seal writes three fields, in order, holding the values it was built from.
    ///
    /// The reference hand-assembles this block from three separately-obtained values — the first
    /// of them read out of a long-running operation's name — so nothing there prevents a seal
    /// naming one identifier at another's sequence number with a third's digest.
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

        // The reference's own field order, asserted on the bytes.
        prop_assert_eq!(&text, &format!(r#"{{"i":"{delegate}","s":"0","d":"{digest}"}}"#));
        prop_assert_eq!(written.get_text(SEAL_IDENTIFIER_LABEL), Some(delegate.as_str()));
        prop_assert_eq!(written.get_text(SEAL_DIGEST_LABEL), Some(digest.as_str()));
        // And an inception's sequence number, which is not a value a caller supplies.
        prop_assert_eq!(written.get_text(SEAL_SEQUENCE_LABEL), Some("0"));
        // The two values the seal was built from survive being read back.
        prop_assert_eq!(seal.delegate().qb64().ok(), Some(delegate));
        prop_assert_eq!(seal.digest().qb64().ok(), Some(digest));
    }

    /// A seal is never empty and never partial: three labels, always the same three.
    #[test]
    fn a_seal_carries_nothing_beyond_the_references_three(
        delegate in qualified(),
        digest in qualified(),
    ) {
        let seal = InceptionSeal::new(
            IdentifierPrefix::from_qb64(&delegate).map_err(|error| TestCaseError::fail(error.to_string()))?,
            digest.parse::<Said>().map_err(|error| TestCaseError::fail(error.to_string()))?,
        );
        let written = seal.to_sad().map_err(|error| TestCaseError::fail(error.to_string()))?;
        for label in [SEAL_IDENTIFIER_LABEL, SEAL_SEQUENCE_LABEL, SEAL_DIGEST_LABEL] {
            prop_assert!(written.get_text(label).is_some(), "the seal carries no {}", label);
        }
        for absent in ["a", "v", "t", "n", "bt", "kt"] {
            prop_assert!(written.get_text(absent).is_none(), "the seal carries an unexpected {}", absent);
        }
    }

    /// Arbitrary text is an alias or it is refused; nothing panics and nothing escapes.
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

/// Regression: the address the pinned unit test asserts.
#[test]
fn the_pinned_address_reproduces() -> Result<(), Box<dyn Error>> {
    let pinned = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
    assert_eq!(
        write_path(pinned, DELEGATION_SEGMENT)?.as_str(),
        format!("/identifiers/{pinned}/delegation")
    );
    Ok(())
}

/// Regression: the one alias the reference treats two ways inside a single call.
#[test]
fn the_alias_the_reference_disagrees_with_itself_about() -> Result<(), Box<dyn Error>> {
    let alias = "a/b?c=d";
    // Upstream: `/identifiers/a%2Fb%3Fc%3Dd` on the read, `/identifiers/a/b?c=d/delegation` on the
    // write. Here both encode.
    assert_eq!(read_path(alias)?.as_str(), "/identifiers/a%2Fb%3Fc%3Dd");
    assert_eq!(
        write_path(alias, DELEGATION_SEGMENT)?.as_str(),
        "/identifiers/a%2Fb%3Fc%3Dd/delegation"
    );
    Ok(())
}

/// Regression: the seal the pinned integration test hand-assembles.
#[test]
fn the_seal_the_scenario_anchors_reproduces() -> Result<(), Box<dyn Error>> {
    // A delegated inception is its own digest, so the scenario's seal names one value twice.
    let seal = InceptionSeal::new(IdentifierPrefix::from_qb64(DELEGATE)?, DELEGATE.parse::<Said>()?);
    assert_eq!(
        String::from_utf8(seal.to_sad()?.to_json_bytes()?)?,
        format!(r#"{{"i":"{DELEGATE}","s":"0","d":"{DELEGATE}"}}"#)
    );
    Ok(())
}
