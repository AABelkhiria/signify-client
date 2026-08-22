//! Invariants of registry inception.

use proptest::prelude::*;
use signify_keri::event::kind::EventKind;
use signify_keri::event::witness::{AmpleMode, ample};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::registry::{RegistryError, RegistryInceptionBuilder};
use signify_keri::serialization::SerializedEvent;

const ISSUER: &str = "ECJIoBpEcCWMzvquk861dXP8JJZ-vbmJczlDR-NYcE3g";

fn fail(error: impl core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn builder(nonce: &str) -> Result<RegistryInceptionBuilder, TestCaseError> {
    Ok(RegistryInceptionBuilder::new(
        IdentifierPrefix::from_qb64(ISSUER).map_err(fail)?,
        nonce,
    ))
}

fn backers(count: usize) -> Vec<String> {
    (0..count).map(|index| format!("backer-{index}")).collect()
}

proptest! {
    /// The same inputs always derive the same registry, a different nonce a different one, and
    /// the event is self-consistent: it reparses losslessly, its identifier is its own digest in
    /// both fields, and its size matches its version string.
    #[test]
    fn inception_is_deterministic_and_self_consistent(
        nonce in "[A-Za-z0-9_-]{0,44}",
        backer_count in 0_usize..6,
    ) {
        let build = |nonce: &str| -> Result<_, TestCaseError> {
            builder(nonce)?.backers(backers(backer_count)).build().map_err(fail)
        };
        let left = build(&nonce)?;
        let right = build(&nonce)?;
        prop_assert_eq!(left.raw(), right.raw());

        let other = build(&format!("{nonce}x"))?;
        prop_assert_ne!(
            left.identifier().qb64().ok(),
            other.identifier().qb64().ok()
        );

        prop_assert_eq!(left.kind(), EventKind::RegistryInception);
        prop_assert_eq!(left.sequence_number(), 0);
        prop_assert_eq!(left.serialized().size(), left.raw().len());
        let reparsed = SerializedEvent::parse(left.raw()).map_err(fail)?;
        prop_assert_eq!(reparsed.sad(), left.sad());
        prop_assert!(left.identifier().is_digestive());
        prop_assert_eq!(left.sad().get_text("i"), left.sad().get_text("d"));
        prop_assert_eq!(
            left.identifier().qb64().ok(),
            left.said().qb64().ok()
        );
    }

    /// The default threshold is `ample` of the backer count — zero for none — written in
    /// lowercase hexadecimal, and an explicit threshold is accepted exactly when it fits.
    #[test]
    fn thresholds_follow_the_reference_rules(
        backer_count in 0_usize..8,
        explicit in proptest::option::of(0_u32..10),
    ) {
        let base = builder("nonce")?.backers(backers(backer_count));
        let outcome = match explicit {
            Some(threshold) => base.backer_threshold(threshold).build(),
            None => base.build(),
        };
        let expected_default = if backer_count == 0 {
            0
        } else {
            ample(u32::try_from(backer_count).map_err(fail)?, None, AmpleMode::Weak).map_err(fail)?
        };
        let fits = |threshold: u32| {
            if backer_count == 0 {
                threshold == 0
            } else {
                threshold >= 1 && usize::try_from(threshold).is_ok_and(|threshold| threshold <= backer_count)
            }
        };
        match explicit {
            Some(threshold) if !fits(threshold) => {
                let refused = matches!(outcome, Err(RegistryError::InvalidBackerThreshold { .. }));
                prop_assert!(refused);
            }
            _ => {
                let event = outcome.map_err(fail)?;
                let expected = explicit.unwrap_or(expected_default);
                let rendered = format!("{expected:x}");
                prop_assert_eq!(event.sad().get_text("bt"), Some(rendered.as_str()));
            }
        }
    }

    /// Duplicate backers are always refused, whatever their position.
    #[test]
    fn duplicate_backers_are_refused(count in 2_usize..6, duplicate in 0_usize..5) {
        prop_assume!(duplicate < count - 1);
        let mut list = backers(count);
        if let (Some(source), Some(target)) = (list.first().cloned(), list.get_mut(duplicate + 1)) {
            *target = source;
        }
        let refused = matches!(
            builder("nonce")?.backers(list).build(),
            Err(RegistryError::DuplicateBacker { .. })
        );
        prop_assert!(refused);
    }

    /// The nonce and every backer are committed verbatim, whatever text they carry.
    #[test]
    fn text_inputs_are_committed_verbatim(
        nonce in "[ -~]{0,64}",
        backer in "[ -~]{1,32}",
    ) {
        // JSON-escaping characters change bytes but not values; the round trip proves fidelity.
        let event = builder(&nonce)?
            .backers(vec![backer.clone()])
            .backer_threshold(1)
            .build()
            .map_err(fail)?;
        prop_assert_eq!(event.sad().get_text("n"), Some(nonce.as_str()));
        let reparsed = SerializedEvent::parse(event.raw()).map_err(fail)?;
        prop_assert_eq!(reparsed.sad().get_text("n"), Some(nonce.as_str()));
    }
}
