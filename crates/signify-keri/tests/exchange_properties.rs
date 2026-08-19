//! Property and invalid-near-miss coverage for exchange messages.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_keri::event::EventError;
use signify_keri::event::exchange::{
    EMBEDS_LABEL, ExchangeBuilder, ExchangeEmbed, ExchangeMessage, MAX_EMBED_LABEL_BYTES,
};
use signify_keri::event::timestamp::Timestamp;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

const SENDER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
const RECIPIENT: &str = "EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj";
const OTHER_RECIPIENT: &str = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";
const STAMP: &str = "2023-08-30T17:22:54.183000+00:00";
const EMBEDDED: &str = r#"{"v":"KERI10JSON000049_","t":"vcp","d":"","i":"","s":"0","bt":"0","b":[]}"#;

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn sender() -> Result<IdentifierPrefix, TestCaseError> {
    fail(IdentifierPrefix::from_qb64(SENDER))
}

fn recipient() -> Result<IdentifierPrefix, TestCaseError> {
    fail(IdentifierPrefix::from_qb64(RECIPIENT))
}

fn stamp() -> Result<Timestamp, TestCaseError> {
    fail(Timestamp::parse(STAMP))
}

fn embedded() -> Result<SerializedEvent, TestCaseError> {
    fail(SerializedEvent::parse(EMBEDDED.as_bytes()))
}

fn route_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/ipex/grant".to_owned()),
        Just("/multisig/icp".to_owned()),
        Just(String::new()),
        "/[a-z]{1,8}(/[a-z]{1,8}){0,3}",
        "[ -~\\u{80}-\\u{2ff}]{0,40}",
    ]
}

fn payload_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
    // `i` is excluded deliberately: it names the recipient and is refused, which has its own test.
    proptest::collection::vec(("[a-hj-z]{1,6}", "[ -~\\u{80}-\\u{2ff}]{0,24}"), 0..5)
}

fn label_strategy() -> impl Strategy<Value = String> {
    "[a-ce-uw-z]{1,8}"
}

/// CESR text attachments of a whole number of quadlets.
fn attachment_strategy() -> impl Strategy<Value = String> {
    (0_usize..6).prop_map(|quadlets| "-AAB".repeat(quadlets))
}

fn build_map(pairs: &[(String, String)]) -> Sad {
    let mut map = Sad::new();
    for (label, value) in pairs {
        // Duplicate labels are rejected by `Sad`, so later ones are simply skipped.
        let _ = map.insert(label.clone(), SadValue::text(value.clone()));
    }
    map
}

/// Asserts the invariants every finished exchange message holds.
fn check_self_consistent(message: &ExchangeMessage) -> Result<(), TestCaseError> {
    prop_assert_eq!(message.serialized().size(), message.raw().len());
    let reparsed = fail(SerializedEvent::parse(message.raw()))?;
    prop_assert_eq!(reparsed.sad(), message.sad());
    fail(
        message
            .said()
            .verify(message.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict()),
    )?;

    let labels: Vec<&str> = message.sad().entries().map(|(label, _)| label).collect();
    prop_assert_eq!(labels, ["v", "t", "d", "i", "rp", "p", "dt", "r", "q", "a", "e"]);
    prop_assert_eq!(message.sad().get_text("t"), Some("exn"));

    // The attribute block always names the recipient the message is addressed to.
    let attributes = message
        .sad()
        .get("a")
        .and_then(SadValue::as_map)
        .ok_or_else(|| TestCaseError::fail("no attribute block"))?;
    prop_assert_eq!(attributes.get_text("i"), message.recipient());
    prop_assert_eq!(attributes.entries().next().map(|(label, _)| label), Some("i"));

    // A nonempty embeds block ends with an identifier committing to the block itself.
    let embeds = message
        .sad()
        .get("e")
        .and_then(SadValue::as_map)
        .ok_or_else(|| TestCaseError::fail("no embeds block"))?;
    if embeds.is_empty() {
        prop_assert!(message.attachments().is_empty());
    } else {
        let last = embeds.entries().last().map(|(label, _)| label);
        prop_assert_eq!(last, Some(DEFAULT_SAID_LABEL));
        let claimed = fail(Said::from_qb64(
            embeds
                .get_text(DEFAULT_SAID_LABEL)
                .ok_or_else(|| TestCaseError::fail("no embeds identifier"))?,
        ))?;
        fail(claimed.verify(embeds, DEFAULT_SAID_LABEL, SaidVerification::strict()))?;
    }

    // Every transposed stream is a whole number of quadlets, which is what lets a parser skip it.
    prop_assert!(message.attachments().len().is_multiple_of(4));
    Ok(())
}

proptest! {
    /// Any message the builder accepts agrees with its own size, reparses, and verifies.
    #[test]
    fn every_built_message_is_self_consistent(
        route in route_strategy(),
        payload in payload_strategy(),
        modifiers in payload_strategy(),
        labels in proptest::collection::vec(label_strategy(), 0..4),
        attachment in attachment_strategy(),
    ) {
        let event = embedded()?;
        let mut embeds = Vec::new();
        for label in &labels {
            let Ok(embed) = ExchangeEmbed::new(label.clone(), &event) else { continue };
            embeds.push(fail(embed.with_attachment(attachment.clone().into_bytes()))?);
        }
        let message = ExchangeBuilder::new(route, sender()?, recipient()?, stamp()?)
            .payload(build_map(&payload))
            .modifiers(build_map(&modifiers))
            .embeds(embeds);
        // Repeated labels are the only rejection this generator can produce.
        let Ok(message) = message.build() else {
            let mut seen = std::collections::BTreeSet::new();
            prop_assert!(labels.iter().any(|label| !seen.insert(label)));
            return Ok(());
        };
        check_self_consistent(&message)?;
    }

    /// Construction is deterministic: identical inputs give identical bytes.
    #[test]
    fn construction_is_deterministic(route in route_strategy(), payload in payload_strategy()) {
        let (sender, recipient, stamp) = (sender()?, recipient()?, stamp()?);
        let build = || -> Result<ExchangeMessage, EventError> {
            ExchangeBuilder::new(route.clone(), sender.clone(), recipient.clone(), stamp.clone())
                .payload(build_map(&payload))
                .build()
        };
        let (first, second) = (fail(build())?, fail(build())?);
        prop_assert_eq!(first.raw(), second.raw());
        prop_assert_eq!(first.said(), second.said());
    }

    /// The identifier commits to every input, so changing any one of them changes it.
    #[test]
    fn the_identifier_commits_to_every_input(
        route in route_strategy(),
        payload in payload_strategy(),
        label in label_strategy(),
    ) {
        let event = embedded()?;
        let base = ExchangeBuilder::new(route.clone(), sender()?, recipient()?, stamp()?)
            .payload(build_map(&payload));
        let original = fail(base.clone().build())?;

        // A different recipient, timestamp, prior, modifier block, or embed all change the SAID.
        let other_recipient = fail(IdentifierPrefix::from_qb64(OTHER_RECIPIENT))?;
        let readdressed = fail(
            ExchangeBuilder::new(route.clone(), sender()?, other_recipient, stamp()?)
                .payload(build_map(&payload))
                .build(),
        )?;
        prop_assert_ne!(original.said(), readdressed.said());

        let later = fail(Timestamp::parse("2023-08-30T17:22:54.183001+00:00"))?;
        let restamped = fail(
            ExchangeBuilder::new(route, sender()?, recipient()?, later)
                .payload(build_map(&payload))
                .build(),
        )?;
        prop_assert_ne!(original.said(), restamped.said());
        prop_assert_eq!(original.raw().len(), restamped.raw().len());

        let chained = fail(base.clone().prior(original.said()).build())?;
        prop_assert_ne!(original.said(), chained.said());

        let embed = fail(ExchangeEmbed::new(label, &event))?;
        let carrying = fail(base.embeds(vec![embed]).build())?;
        prop_assert_ne!(original.said(), carrying.said());
    }

    /// An embedded message survives transposition byte for byte, which is what lets a recipient
    /// verify it against the signatures transposed with it.
    #[test]
    fn an_embedded_message_survives_unchanged(labels in proptest::collection::vec(label_strategy(), 1..4)) {
        let event = embedded()?;
        let mut embeds = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for label in &labels {
            if !seen.insert(label.clone()) {
                continue;
            }
            embeds.push(fail(ExchangeEmbed::new(label.clone(), &event))?);
        }
        let message = fail(
            ExchangeBuilder::new("/x", sender()?, recipient()?, stamp()?)
                .embeds(embeds)
                .build(),
        )?;

        let block = message
            .sad()
            .get(EMBEDS_LABEL)
            .and_then(SadValue::as_map)
            .ok_or_else(|| TestCaseError::fail("no embeds block"))?;
        for label in seen {
            let carried = block
                .get(&label)
                .and_then(SadValue::as_map)
                .ok_or_else(|| TestCaseError::fail("an embed went missing"))?;
            prop_assert_eq!(fail(carried.to_json_bytes())?, event.raw());
        }
    }

    /// Each attached embed contributes exactly one pathed group, in embed order, and the
    /// attachment itself is written verbatim.
    #[test]
    fn attachments_are_transposed_in_order(
        labels in proptest::collection::vec(label_strategy(), 1..4),
        attachment in attachment_strategy(),
    ) {
        let event = embedded()?;
        let mut embeds = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for label in &labels {
            if !seen.insert(label.clone()) {
                continue;
            }
            embeds.push(fail(
                ExchangeEmbed::new(label.clone(), &event)?.with_attachment(attachment.clone().into_bytes()),
            )?);
        }
        let count = seen.len();
        let message = fail(
            ExchangeBuilder::new("/x", sender()?, recipient()?, stamp()?)
                .embeds(embeds)
                .build(),
        )?;

        let stream = fail(core::str::from_utf8(message.attachments()))?;
        // One pathed-material counter per attached embed, and the labels appear in embed order.
        prop_assert_eq!(stream.matches("-L").count(), count);
        let mut offset = 0;
        for label in &labels {
            if let Some(found) = stream.get(offset..).and_then(|tail| tail.find(&format!("-e-{label}"))) {
                offset += found;
            }
        }
        prop_assert!(stream.len().is_multiple_of(4));
        if !attachment.is_empty() {
            prop_assert_eq!(stream.matches(&attachment).count(), count);
        }
    }

    /// A payload naming the recipient field is always refused, whatever else it carries.
    #[test]
    fn a_payload_may_never_readdress_the_attributes(payload in payload_strategy()) {
        let mut map = build_map(&payload);
        fail(map.insert("i", SadValue::text("EOTHER")))?;
        let result = ExchangeBuilder::new("/x", sender()?, recipient()?, stamp()?)
            .payload(map)
            .build();
        let refused = matches!(result, Err(EventError::PayloadOverridesRecipient { .. }));
        prop_assert!(refused, "a payload naming the recipient was accepted");
    }

    /// Hostile embed labels are refused rather than reshaping the attachment path.
    #[test]
    fn hostile_embed_labels_are_refused(label in "[ -~]{0,12}") {
        let event = embedded()?;
        let accepted = ExchangeEmbed::new(label.clone(), &event).is_ok();
        let usable = !label.is_empty()
            && label.len() <= MAX_EMBED_LABEL_BYTES
            && label != DEFAULT_SAID_LABEL
            && label != "v"
            && !label.bytes().all(|byte| byte.is_ascii_digit())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        prop_assert_eq!(accepted, usable, "label {:?}", label);
    }

    /// Only quadlet-aligned CESR text is transposed; anything else is refused with its offset.
    #[test]
    fn hostile_attachments_are_refused(attachment in proptest::collection::vec(any::<u8>(), 0..24)) {
        let event = embedded()?;
        let embed = fail(ExchangeEmbed::new("icp", &event))?;
        let aligned = attachment.len().is_multiple_of(4);
        let cesr = attachment
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_');
        match embed.with_attachment(attachment.clone()) {
            Ok(embed) => {
                prop_assert!(aligned && cesr);
                prop_assert_eq!(embed.attachment(), Some(attachment.as_slice()));
                let message = fail(
                    ExchangeBuilder::new("/x", sender()?, recipient()?, stamp()?)
                        .embeds(vec![embed])
                        .build(),
                )?;
                check_self_consistent(&message)?;
                prop_assert!(message.attachments().ends_with(&attachment));
            }
            Err(EventError::NonIntegralAttachment { length, .. }) => {
                prop_assert!(!aligned);
                prop_assert_eq!(length, attachment.len());
            }
            Err(EventError::InvalidAttachmentText { offset, .. }) => {
                prop_assert!(!cesr);
                prop_assert!(offset < attachment.len());
            }
            Err(other) => return Err(TestCaseError::fail(other.to_string())),
        }
    }
}
