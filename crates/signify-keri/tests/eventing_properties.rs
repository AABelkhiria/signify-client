//! Property and invalid-near-miss coverage for the core key-event builders.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_crypto::digest::{Digest, DigestAlgorithm};
use signify_crypto::verifier::VerificationKey;
use signify_keri::event::inception::InceptionBuilder;
use signify_keri::event::interaction::InteractionBuilder;
use signify_keri::event::rotation::{RotationBuilder, RotationKind};
use signify_keri::event::witness::{AmpleMode, ample};
use signify_keri::event::{EventError, KeyEvent, ThresholdEncoding};
use signify_keri::prefix::{IdentifierPrefix, PrefixDerivation, PrefixVerification};
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};
use signify_keri::threshold::SigningThreshold;

/// Distinct transferable keys, non-transferable witnesses, and next-key digests.
const KEYS: [&str; 4] = [
    "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH",
    "DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ",
    "DB3MBHRA6bpPwxY-QpywXUwNR-7WCEO5PmUZV3xYBkk2",
    "DIUghlVOUiV8eFLs5cP-w6hWMJosH6TLaX9BqOSI68WX",
];
const WITNESSES: [&str; 4] = [
    "BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH",
    "BB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ",
    "BB3MBHRA6bpPwxY-QpywXUwNR-7WCEO5PmUZV3xYBkk2",
    "BIUghlVOUiV8eFLs5cP-w6hWMJosH6TLaX9BqOSI68WX",
];
const DIGESTS: [&str; 3] = [
    "EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W",
    "EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj",
    "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg",
];

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn keys(count: usize) -> Result<Vec<VerificationKey>, TestCaseError> {
    KEYS.iter()
        .take(count)
        .map(|entry| fail(VerificationKey::from_qb64(entry)))
        .collect()
}

fn witnesses(count: usize) -> Result<Vec<IdentifierPrefix>, TestCaseError> {
    WITNESSES
        .iter()
        .take(count)
        .map(|entry| fail(IdentifierPrefix::from_qb64(entry)))
        .collect()
}

fn digests(count: usize) -> Result<Vec<Digest>, TestCaseError> {
    DIGESTS
        .iter()
        .take(count)
        .map(|entry| fail(Digest::from_qb64(entry)))
        .collect()
}

fn encoding(integer: bool) -> ThresholdEncoding {
    if integer {
        ThresholdEncoding::Integer
    } else {
        ThresholdEncoding::Text
    }
}

/// Every finished event has to agree with itself: declared size, byte length, and reparsed fields.
fn check_self_consistent(event: &KeyEvent) -> Result<(), TestCaseError> {
    prop_assert_eq!(event.serialized().size(), event.raw().len());
    let reparsed = fail(SerializedEvent::parse(event.raw()))?;
    prop_assert_eq!(reparsed.sad(), event.sad());

    let identifier = fail(event.identifier().qb64())?;
    let said = fail(event.said().qb64())?;
    prop_assert_eq!(event.sad().get_text("i"), Some(identifier.as_str()));
    prop_assert_eq!(event.sad().get_text("d"), Some(said.as_str()));
    prop_assert_eq!(event.sad().get_text("t"), Some(event.kind().as_str()));

    // How the SAID is checked depends on how the identifier was derived. A self-addressing
    // identifier's digest is taken over an event with *both* the identifier and SAID fields
    // replaced by placeholders, so recomputing it as an ordinary SAID -- which replaces only the
    // SAID field -- lands on a different digest. The prefix derivation is the correct check.
    if event.identifier().is_digestive() && event.kind().as_str() == "icp" {
        fail(event.identifier().verify(event.sad(), PrefixVerification::Strict))?;
        prop_assert_eq!(event.sad().get_text("i"), event.sad().get_text("d"));
    } else {
        fail(
            event
                .said()
                .verify(event.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict()),
        )?;
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Any inception the builder accepts produces a self-consistent event whose identifier the
    /// prefix derivation independently confirms.
    #[test]
    fn inception_events_are_self_consistent(
        key_count in 1_usize..=4,
        digest_count in 0_usize..=3,
        witness_count in 0_usize..=4,
        integer in any::<bool>(),
    ) {
        let event = fail(
            InceptionBuilder::new(keys(key_count)?)
                .next_key_digests(digests(digest_count)?)
                .witnesses(witnesses(witness_count)?)
                .threshold_encoding(encoding(integer))
                .build(),
        )?;
        check_self_consistent(&event)?;
        prop_assert_eq!(event.sequence_number(), 0);
        prop_assert_eq!(event.sad().get_text("s"), Some("0"));

        // The identifier verifies against the event it was derived from.
        fail(event.identifier().verify(event.sad(), PrefixVerification::Strict))?;

        // A self-addressing identifier *is* the event's SAID; a basic one is a key the event lists.
        if event.identifier().is_digestive() {
            prop_assert_eq!(fail(event.identifier().qb64())?, fail(event.said().qb64())?);
        } else {
            prop_assert_eq!(key_count, 1);
            let listed = event.sad().get("k").and_then(SadValue::as_array).map(<[SadValue]>::len);
            prop_assert_eq!(listed, Some(1));
        }
    }

    /// The default thresholds are the majorities the reference computes, and they are always
    /// satisfiable by the material the event actually lists.
    #[test]
    fn default_thresholds_are_satisfiable_majorities(
        key_count in 1_usize..=4,
        digest_count in 0_usize..=3,
    ) {
        let event = fail(
            InceptionBuilder::new(keys(key_count)?)
                .next_key_digests(digests(digest_count)?)
                .build(),
        )?;
        let signing = SigningThreshold::numeric(1.max(fail(u128::try_from(key_count))?.div_ceil(2)));
        let next = SigningThreshold::numeric(fail(u128::try_from(digest_count))?.div_ceil(2));
        let signing_text = signing.canonical_sith();
        let next_text = next.canonical_sith();
        prop_assert_eq!(event.sad().get_text("kt"), Some(signing_text.as_str()));
        prop_assert_eq!(event.sad().get_text("nt"), Some(next_text.as_str()));
        // Neither threshold can ever demand more than the event lists.
        prop_assert!(signing.size() <= fail(u128::try_from(key_count))?);
        prop_assert!(next.size() <= fail(u128::try_from(digest_count))?);
    }

    /// The threshold encoding changes the bytes -- and therefore the identifier -- without changing
    /// which fields the event carries.
    #[test]
    fn threshold_encoding_changes_bytes_but_not_structure(
        key_count in 1_usize..=4,
        digest_count in 0_usize..=3,
        witness_count in 0_usize..=4,
    ) {
        let build = |integer: bool| {
            InceptionBuilder::new(KEYS.iter().take(key_count).filter_map(|entry| VerificationKey::from_qb64(entry).ok()).collect())
                .next_key_digests(DIGESTS.iter().take(digest_count).filter_map(|entry| Digest::from_qb64(entry).ok()).collect())
                .witnesses(WITNESSES.iter().take(witness_count).filter_map(|entry| IdentifierPrefix::from_qb64(entry).ok()).collect())
                .prefix_derivation(PrefixDerivation::Blake3_256)
                .threshold_encoding(encoding(integer))
                .build()
        };
        let text = fail(build(false))?;
        let integer = fail(build(true))?;

        let text_labels: Vec<&str> = text.sad().entries().map(|(label, _)| label).collect();
        let integer_labels: Vec<&str> = integer.sad().entries().map(|(label, _)| label).collect();
        prop_assert_eq!(text_labels, integer_labels);
        // Integer encoding drops the quotes, so it is never longer.
        prop_assert!(integer.raw().len() <= text.raw().len());
        prop_assert_ne!(text.said(), integer.said());
        check_self_consistent(&text)?;
        check_self_consistent(&integer)?;
    }

    /// A rotation's witness arithmetic always describes the set it claims, and the threshold fits.
    #[test]
    fn rotation_witness_changes_are_consistent(
        current in 0_usize..=4,
        cuts in 0_usize..=2,
        adds in 0_usize..=2,
    ) {
        // Cuts come from the current set; additions come from the tail that is not in it.
        let cut_count = cuts.min(current);
        let add_count = adds.min(WITNESSES.len().saturating_sub(current));
        let identifier = fail(IdentifierPrefix::from_qb64(DIGESTS[0]))?;
        let prior = fail(Said::from_qb64(DIGESTS[1]))?;

        let current_set = witnesses(current)?;
        let cut_set: Vec<IdentifierPrefix> = current_set.iter().take(cut_count).cloned().collect();
        let add_set: Vec<IdentifierPrefix> = WITNESSES
            .iter()
            .skip(current)
            .take(add_count)
            .filter_map(|entry| IdentifierPrefix::from_qb64(entry).ok())
            .collect();

        let event = fail(
            RotationBuilder::new(identifier, prior, 1, keys(1)?)
                .next_key_digests(digests(1)?)
                .witnesses(current_set)
                .witness_cuts(cut_set)
                .witness_adds(add_set)
                .build(),
        )?;
        check_self_consistent(&event)?;

        let resulting = current - cut_count + add_count;
        let resulting_count = fail(u32::try_from(resulting))?;
        let threshold = if resulting_count == 0 {
            0
        } else {
            fail(ample(resulting_count, None, AmpleMode::Weak))?
        };
        let rendered = if threshold == 0 {
            SadValue::text("0")
        } else {
            SadValue::Integer(i64::from(threshold))
        };
        prop_assert_eq!(event.sad().get("bt"), Some(&rendered));
        prop_assert!(u128::from(threshold) <= fail(u128::try_from(resulting))?);
    }

    /// Sequence numbers survive the hexadecimal round trip for both event kinds that carry one.
    #[test]
    fn sequence_numbers_round_trip(sequence_number in 1_u128..=u128::from(u32::MAX)) {
        let identifier = fail(IdentifierPrefix::from_qb64(DIGESTS[0]))?;
        let prior = fail(Said::from_qb64(DIGESTS[1]))?;

        let rotation = fail(
            RotationBuilder::new(identifier.clone(), prior, sequence_number, keys(1)?)
                .next_key_digests(digests(1)?)
                .build(),
        )?;
        let interaction = fail(InteractionBuilder::new(identifier, prior, sequence_number).build())?;

        for event in [&rotation, &interaction] {
            check_self_consistent(event)?;
            prop_assert_eq!(event.sequence_number(), sequence_number);
            let rendered = fail(
                event
                    .sad()
                    .get_text("s")
                    .ok_or(EventError::ValueOutOfRange { context: "sequence number" }),
            )?;
            prop_assert_eq!(rendered, format!("{sequence_number:x}"));
        }
    }

    /// An identifier's log chains: each event names the previous one, and no two events in the
    /// chain share a SAID.
    #[test]
    fn a_key_event_log_chains(
        key_count in 1_usize..=3,
        integer in any::<bool>(),
        delegated in any::<bool>(),
    ) {
        let inception = fail(
            InceptionBuilder::new(keys(key_count)?)
                .next_key_digests(digests(1)?)
                .prefix_derivation(PrefixDerivation::Blake3_256)
                .threshold_encoding(encoding(integer))
                .build(),
        )?;
        let rotation = fail(
            RotationBuilder::new(inception.identifier().clone(), inception.said(), 1, keys(key_count)?)
                .next_key_digests(digests(1)?)
                .kind(if delegated { RotationKind::Delegated } else { RotationKind::Rotation })
                .build(),
        )?;
        let interaction = fail(
            InteractionBuilder::new(rotation.identifier().clone(), rotation.said(), 2).build(),
        )?;

        // Each event points at its predecessor and shares the identifier.
        let inception_said = fail(inception.said().qb64())?;
        let rotation_said = fail(rotation.said().qb64())?;
        prop_assert_eq!(rotation.sad().get_text("p"), Some(inception_said.as_str()));
        prop_assert_eq!(interaction.sad().get_text("p"), Some(rotation_said.as_str()));
        prop_assert_eq!(rotation.identifier(), inception.identifier());
        prop_assert_eq!(interaction.identifier(), inception.identifier());
        prop_assert_eq!([inception.sequence_number(), rotation.sequence_number(), interaction.sequence_number()], [0, 1, 2]);

        // Distinct events never collide.
        prop_assert_ne!(inception.said(), rotation.said());
        prop_assert_ne!(rotation.said(), interaction.said());
        for event in [&inception, &rotation, &interaction] {
            check_self_consistent(event)?;
        }
    }

    /// The witness threshold is never larger than the witness set and is zero only when empty.
    #[test]
    fn ample_stays_within_its_witness_set(witnesses in 0_u32..512, integer in any::<bool>()) {
        let weak = fail(ample(witnesses, None, AmpleMode::Weak))?;
        let strong = fail(ample(witnesses, None, AmpleMode::Strong))?;
        prop_assert!(weak <= witnesses);
        prop_assert!(strong <= witnesses);
        prop_assert!(weak <= strong);
        prop_assert_eq!(weak == 0, witnesses == 0);
        let _ = integer;

        // An explicit fault count either yields a threshold in range or is refused outright.
        for faults in [0_u32, 1, witnesses / 3] {
            match ample(witnesses, Some(faults), AmpleMode::Weak) {
                Ok(threshold) => prop_assert!(threshold <= witnesses),
                Err(error) => prop_assert!(
                    matches!(error, EventError::FaultToleranceTooHigh { .. }),
                    "an impossible fault count produced the wrong error"
                ),
            }
        }
    }

    /// Anchored seals survive into the event unchanged, in order.
    #[test]
    fn anchors_are_preserved(count in 0_usize..=3, sequence_number in 1_u128..64) {
        let identifier = fail(IdentifierPrefix::from_qb64(DIGESTS[0]))?;
        let prior = fail(Said::from_qb64(DIGESTS[1]))?;
        let anchors: Vec<Sad> = (0..count)
            .filter_map(|index| {
                let mut seal = Sad::new();
                seal.insert("i", SadValue::text(*DIGESTS.get(index % DIGESTS.len())?)).ok()?;
                seal.insert("s", SadValue::text(format!("{index:x}"))).ok()?;
                Some(seal)
            })
            .collect();
        prop_assume!(anchors.len() == count);

        let event = fail(
            InteractionBuilder::new(identifier, prior, sequence_number)
                .anchors(anchors.clone())
                .build(),
        )?;
        let expected = SadValue::Array(anchors.into_iter().map(SadValue::Map).collect());
        prop_assert_eq!(event.sad().get("a"), Some(&expected));
        check_self_consistent(&event)?;
    }

    /// A peer can recompute every identifier and SAID from the event's own bytes.
    #[test]
    fn a_peer_can_recompute_every_identifier(key_count in 1_usize..=3, digest_count in 0_usize..=3) {
        // A self-addressing inception is checked through the prefix derivation, which dummies both
        // the identifier and the SAID field.
        let inception = fail(
            InceptionBuilder::new(keys(key_count)?)
                .next_key_digests(digests(digest_count)?)
                .prefix_derivation(PrefixDerivation::Blake3_256)
                .build(),
        )?;
        let rederived = fail(IdentifierPrefix::derive(inception.sad(), PrefixDerivation::Blake3_256))?;
        prop_assert_eq!(&rederived, inception.identifier());
        prop_assert_eq!(fail(rederived.qb64())?, fail(inception.said().qb64())?);

        // A rotation carries an ordinary SAID, which recomputes as one.
        let rotation = fail(
            RotationBuilder::new(inception.identifier().clone(), inception.said(), 1, keys(key_count)?)
                .next_key_digests(digests(digest_count)?)
                .build(),
        )?;
        let recomputed = fail(Said::compute(rotation.sad(), DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL))?;
        prop_assert_eq!(recomputed.said(), &rotation.said());
        prop_assert_eq!(recomputed.sad(), rotation.sad());
    }
}
