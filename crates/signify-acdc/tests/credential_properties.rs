//! Invariants of ACDC credential construction.

use proptest::prelude::*;
use signify_acdc::credential::{
    ATTRIBUTES_LABEL, CredentialAttributes, CredentialBlock, CredentialBuilder, CredentialError, EDGES_LABEL,
    MAX_BLOCK_DEPTH, MAX_LABEL_BYTES, MAX_NONCE_BYTES, NONCE_LABEL, RULES_LABEL, RegistryIdentifier, SCHEMA_LABEL,
    TIMESTAMP_LABEL,
};
use signify_keri::event::timestamp::Timestamp;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const OTHER_REGISTRY: &str = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const OTHER_SCHEMA: &str = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn stamp() -> Result<Timestamp, TestCaseError> {
    STAMP.parse().map_err(fail)
}

fn builder(registry: &str, schema: &str, attributes: CredentialAttributes) -> Result<CredentialBuilder, TestCaseError> {
    Ok(CredentialBuilder::new(
        IdentifierPrefix::from_qb64(ISSUER).map_err(fail)?,
        RegistryIdentifier::from_qb64(registry).map_err(fail)?,
        Said::from_qb64(schema).map_err(fail)?,
        attributes,
    ))
}

/// A label that is neither reserved, typed, nor an array index.
///
/// The generator is deliberately allowed to produce `d`, `v`, `i`, `u`, and `dt` and then rejects
/// them, so the filter itself is evidence that those five are the complete set with a method of
/// their own — a sixth would slip through and fail the property.
fn ordinary_label() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z_][A-Za-z0-9_]{0,15}")
        .unwrap_or_else(|_| unreachable!())
        .prop_filter("reserved or typed label", |label| {
            !matches!(label.as_str(), "d" | "v" | "i" | "u" | "dt")
        })
}

proptest! {
    /// Construction is a pure function of its inputs: the same inputs always produce the same
    /// bytes, and the result is self-consistent — it reparses losslessly, its declared size is its
    /// real size, and both identifiers verify against the data carrying them.
    #[test]
    fn construction_is_deterministic_and_self_consistent(
        labels in prop::collection::vec(ordinary_label(), 0..6),
        values in prop::collection::vec("[ -~]{0,32}", 0..6),
        place_timestamp in any::<bool>(),
        name_issuee in any::<bool>(),
    ) {
        let build = || -> Result<_, TestCaseError> {
            let mut attributes = CredentialAttributes::new(stamp()?);
            if name_issuee {
                attributes = attributes
                    .issuee(&IdentifierPrefix::from_qb64(HOLDER).map_err(fail)?)
                    .map_err(fail)?;
            }
            if place_timestamp {
                attributes = attributes.timestamp().map_err(fail)?;
            }
            let mut seen = Vec::new();
            for (label, value) in labels.iter().zip(values.iter()) {
                if seen.contains(label) {
                    continue;
                }
                seen.push(label.clone());
                attributes = attributes.text(label.clone(), value.clone()).map_err(fail)?;
            }
            builder(REGISTRY, SCHEMA, attributes)?.build().map_err(fail)
        };

        let left = build()?;
        let right = build()?;
        prop_assert_eq!(left.raw(), right.raw());
        prop_assert_eq!(left.said(), right.said());

        prop_assert_eq!(left.serialized().size(), left.raw().len());
        let reparsed = SerializedEvent::parse(left.raw()).map_err(fail)?;
        prop_assert_eq!(reparsed.sad(), left.sad());

        left.said()
            .verify(left.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
            .map_err(fail)?;
        let block = left.attributes().ok_or_else(|| TestCaseError::fail("no attribute block"))?;
        left.attributes_said()
            .verify(block, DEFAULT_SAID_LABEL, SaidVerification::strict())
            .map_err(fail)?;
    }

    /// The container's field order never varies: the required fields always appear, in the
    /// protocol's order, and each optional one appears exactly when it was supplied.
    #[test]
    fn the_container_field_order_is_fixed(
        nonce in prop::option::of("[A-Za-z0-9_-]{1,24}"),
        with_edges in any::<bool>(),
        with_rules in any::<bool>(),
    ) {
        let mut block = Sad::new();
        block.insert("qvi", SadValue::text("EQVI")).map_err(fail)?;

        let mut credential = builder(REGISTRY, SCHEMA, CredentialAttributes::new(stamp()?))?;
        if let Some(nonce) = &nonce {
            credential = credential.nonce(nonce.clone()).map_err(fail)?;
        }
        if with_edges {
            credential = credential.edges(block.clone()).map_err(fail)?;
        }
        if with_rules {
            credential = credential.rules(block).map_err(fail)?;
        }
        let credential = credential.build().map_err(fail)?;

        let mut expected = vec!["v", DEFAULT_SAID_LABEL];
        if nonce.is_some() {
            expected.push(NONCE_LABEL);
        }
        expected.extend(["i", "ri", SCHEMA_LABEL, ATTRIBUTES_LABEL]);
        if with_edges {
            expected.push(EDGES_LABEL);
        }
        if with_rules {
            expected.push(RULES_LABEL);
        }
        let actual: Vec<&str> = credential.sad().entries().map(|(label, _)| label).collect();
        prop_assert_eq!(actual, expected);
    }

    /// The attribute block preserves call order, always opens with its identifier, and always
    /// carries its timestamp — placed by the caller, or appended last when it was not.
    #[test]
    fn the_attribute_block_preserves_call_order(
        labels in prop::collection::vec(ordinary_label(), 1..8),
        timestamp_position in prop::option::of(0_usize..8),
    ) {
        let mut unique: Vec<String> = Vec::new();
        for label in labels {
            if !unique.contains(&label) {
                unique.push(label);
            }
        }

        let mut attributes = CredentialAttributes::new(stamp()?);
        let mut expected = vec![DEFAULT_SAID_LABEL.to_owned()];
        let mut placed = false;
        for (index, label) in unique.iter().enumerate() {
            if timestamp_position == Some(index) {
                attributes = attributes.timestamp().map_err(fail)?;
                expected.push(TIMESTAMP_LABEL.to_owned());
                placed = true;
            }
            attributes = attributes.text(label.clone(), "v").map_err(fail)?;
            expected.push(label.clone());
        }
        if !placed {
            expected.push(TIMESTAMP_LABEL.to_owned());
        }

        prop_assert_eq!(attributes.labels(), expected.iter().map(String::as_str).collect::<Vec<_>>());

        let credential = builder(REGISTRY, SCHEMA, attributes)?.build().map_err(fail)?;
        let serialized: Vec<String> = credential
            .attributes()
            .ok_or_else(|| TestCaseError::fail("no attribute block"))?
            .entries()
            .map(|(label, _)| label.to_owned())
            .collect();
        prop_assert_eq!(serialized, expected);
        prop_assert_eq!(
            credential
                .attributes()
                .and_then(|block| block.get_text(TIMESTAMP_LABEL)),
            Some(STAMP)
        );
    }

    /// Every field a credential names is part of its identity: changing any one of the issuer,
    /// registry, schema, timestamp, salt, or attributes changes both the credential's identifier
    /// and its bytes.
    #[test]
    fn every_named_field_changes_the_identifier(
        value in "[ -~]{0,24}",
        other_value in "[ -~]{0,24}",
    ) {
        prop_assume!(value != other_value);

        let base = |registry: &str, schema: &str, text: &str, salt: Option<&str>|
            -> Result<_, TestCaseError> {
            let attributes = CredentialAttributes::new(stamp()?)
                .issuee(&IdentifierPrefix::from_qb64(HOLDER).map_err(fail)?)
                .map_err(fail)?
                .timestamp()
                .map_err(fail)?
                .text("LEI", text.to_owned())
                .map_err(fail)?;
            let mut credential = builder(registry, schema, attributes)?;
            if let Some(salt) = salt {
                credential = credential.nonce(salt.to_owned()).map_err(fail)?;
            }
            credential.build().map_err(fail)
        };

        let reference = base(REGISTRY, SCHEMA, &value, None)?;
        for variant in [
            base(OTHER_REGISTRY, SCHEMA, &value, None)?,
            base(REGISTRY, OTHER_SCHEMA, &value, None)?,
            base(REGISTRY, SCHEMA, &other_value, None)?,
            base(REGISTRY, SCHEMA, &value, Some("0AD6E0lCLBQ0-JOFBoTd9k8I"))?,
        ] {
            prop_assert_ne!(variant.said(), reference.said());
            prop_assert_ne!(variant.raw(), reference.raw());
        }
    }

    /// A label JavaScript would hoist is refused wherever it appears, and one it would not is
    /// accepted — so the accepted set is exactly the set whose order the two languages agree on.
    #[test]
    fn only_labels_both_languages_order_alike_are_accepted(label in "[0-9]{1,12}") {
        let hoisted = !label.is_empty()
            && label.len() <= 10
            && (label.len() == 1 || !label.starts_with('0'))
            && label.parse::<u32>().is_ok_and(|value| value != u32::MAX);

        let attribute = CredentialAttributes::new(stamp()?).text(label.clone(), "v");
        prop_assert_eq!(attribute.is_err(), hoisted);

        let mut block = Sad::new();
        block.insert(label.clone(), SadValue::text("v")).map_err(fail)?;
        let edges = builder(REGISTRY, SCHEMA, CredentialAttributes::new(stamp()?))?.edges(block.clone());
        prop_assert_eq!(edges.is_err(), hoisted);
        if hoisted {
            prop_assert!(
                matches!(
                    edges,
                    Err(CredentialError::ArrayIndexLabel { block: CredentialBlock::Edges, .. })
                ),
                "an edge label was refused for the wrong reason"
            );
        }

        let rules = builder(REGISTRY, SCHEMA, CredentialAttributes::new(stamp()?))?.rules(block);
        prop_assert_eq!(rules.is_err(), hoisted);
    }

    /// A privacy salt is accepted exactly when it is non-empty and within the bound, on both the
    /// container and the attribute block.
    #[test]
    fn a_salt_is_accepted_exactly_inside_its_bounds(length in 0_usize..(MAX_NONCE_BYTES + 8)) {
        let salt = "0".repeat(length);
        let accepted = length > 0 && length <= MAX_NONCE_BYTES;

        let container = builder(REGISTRY, SCHEMA, CredentialAttributes::new(stamp()?))?.nonce(salt.clone());
        prop_assert_eq!(container.is_ok(), accepted);

        let block = CredentialAttributes::new(stamp()?).nonce(&salt);
        prop_assert_eq!(block.is_ok(), accepted);
    }

    /// A label is accepted exactly when it fits the bound, and the failure names the real length.
    #[test]
    fn a_label_is_accepted_exactly_inside_its_bound(length in 1_usize..(MAX_LABEL_BYTES + 8)) {
        let label = "a".repeat(length);
        let result = CredentialAttributes::new(stamp()?).text(label, "v");
        if length <= MAX_LABEL_BYTES {
            prop_assert!(result.is_ok());
        } else {
            prop_assert!(
                matches!(result, Err(CredentialError::LabelTooLong { actual, .. }) if actual == length),
                "an oversized label did not report its real length"
            );
        }
    }

    /// Nesting is accepted exactly to the ceiling and refused past it, whether the depth is built
    /// from maps or from arrays — so neither shape can drive the recursive serializer off a cliff.
    #[test]
    fn nesting_is_accepted_exactly_to_the_ceiling(depth in 1_usize..(MAX_BLOCK_DEPTH + 4)) {
        let mut maps = Sad::new();
        maps.insert("leaf", SadValue::text("v")).map_err(fail)?;
        for _ in 1..depth {
            let mut wrapper = Sad::new();
            wrapper.insert("next", SadValue::Map(maps)).map_err(fail)?;
            maps = wrapper;
        }
        let result = builder(REGISTRY, SCHEMA, CredentialAttributes::new(stamp()?))?.edges(maps);
        prop_assert_eq!(result.is_ok(), depth <= MAX_BLOCK_DEPTH);

        let mut arrays = SadValue::text("leaf");
        for _ in 1..depth {
            arrays = SadValue::Array(vec![arrays]);
        }
        let mut block = Sad::new();
        block.insert("list", arrays).map_err(fail)?;
        let result = builder(REGISTRY, SCHEMA, CredentialAttributes::new(stamp()?))?.rules(block);
        prop_assert_eq!(result.is_ok(), depth <= MAX_BLOCK_DEPTH);
    }

    /// An edge or rule block is committed exactly as given, and its own identifier still verifies
    /// after it has been embedded — which is what a holder checking a chained credential does.
    #[test]
    fn an_embedded_block_survives_the_credential_that_carries_it(
        labels in prop::collection::vec(ordinary_label(), 1..5),
    ) {
        let mut block = Sad::new();
        block.insert(DEFAULT_SAID_LABEL, SadValue::text("")).map_err(fail)?;
        let mut seen = Vec::new();
        for label in &labels {
            if seen.contains(label) {
                continue;
            }
            seen.push(label.clone());
            let mut inner = Sad::new();
            inner.insert("n", SadValue::text("ENODE")).map_err(fail)?;
            block.insert(label.clone(), SadValue::Map(inner)).map_err(fail)?;
        }
        let computed = Said::compute(&block, signify_acdc::credential::DIGEST_ALGORITHM, DEFAULT_SAID_LABEL)
            .map_err(fail)?;
        let (block_said, block) = computed.into_parts();

        let credential = builder(REGISTRY, SCHEMA, CredentialAttributes::new(stamp()?))?
            .edges(block.clone())
            .map_err(fail)?
            .build()
            .map_err(fail)?;

        let embedded = credential
            .sad()
            .get(EDGES_LABEL)
            .and_then(SadValue::as_map)
            .ok_or_else(|| TestCaseError::fail("no edge block"))?;
        prop_assert_eq!(embedded, &block);
        block_said
            .verify(embedded, DEFAULT_SAID_LABEL, SaidVerification::strict())
            .map_err(fail)?;
    }
}

/// Regression: the reference's own `credentialing.test.ts` arguments, whose attribute block has no
/// `dt`, so the timestamp lands after `LEI` rather than before it. Found while checking the
/// ordering property against the fixture.
#[test]
fn an_absent_timestamp_lands_after_the_callers_fields() -> Result<(), Box<dyn std::error::Error>> {
    let attributes = CredentialAttributes::new(STAMP.parse()?)
        .issuee(&IdentifierPrefix::from_qb64(
            "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p",
        )?)?
        .text("LEI", "1234")?;
    assert_eq!(attributes.labels(), ["d", "i", "LEI", "dt"]);
    Ok(())
}

/// Regression: `4294967295` is the one all-digit label within ten characters that JavaScript does
/// *not* treat as an array index, because it is the array-length sentinel.
#[test]
fn the_array_length_sentinel_is_an_ordinary_label() -> Result<(), Box<dyn std::error::Error>> {
    let attributes = CredentialAttributes::new(STAMP.parse()?).text("4294967295", "v")?;
    assert_eq!(attributes.labels(), ["d", "4294967295", "dt"]);
    assert!(
        CredentialAttributes::new(STAMP.parse()?)
            .text("4294967294", "v")
            .is_err()
    );
    Ok(())
}
