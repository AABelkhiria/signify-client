#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_keri::event::EventError;
use signify_keri::event::exchange::{ExchangeBuilder, ExchangeEmbed, MAX_EMBED_LABEL_BYTES};
use signify_keri::event::reply::MAX_ROUTE_BYTES;
use signify_keri::event::timestamp::Timestamp;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

/// Identifiers and a message body pinned by `fixtures/keri-exchange/v1.json`.
const SENDER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
const RECIPIENT: &str = "EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj";
const STAMP: &str = "2023-08-30T17:22:54.183000+00:00";
const EMBEDDED: &str = r#"{"v":"KERI10JSON000049_","t":"vcp","d":"","i":"","s":"0","bt":"0","b":[]}"#;

fuzz_target!(|data: &[u8]| {
    let (Ok(sender), Ok(recipient), Ok(stamp), Ok(embedded)) = (
        IdentifierPrefix::from_qb64(SENDER),
        IdentifierPrefix::from_qb64(RECIPIENT),
        Timestamp::parse(STAMP),
        SerializedEvent::parse(EMBEDDED.as_bytes()),
    ) else {
        return;
    };

    // The first byte splits the input into a label and the material that follows it, so one corpus
    // entry drives the label validator, the attachment validator, and the payload parser at once.
    let split = data.first().map_or(0, |byte| usize::from(*byte) % 16);
    let (head, tail) = data.split_at(split.min(data.len()));
    let label = String::from_utf8_lossy(head).into_owned();
    let route = String::from_utf8_lossy(tail).into_owned();

    // A payload block from arbitrary bytes, when they happen to parse as an object.
    let payload = Sad::from_json_bytes(tail).unwrap_or_default();
    let carries_identifier = payload.contains("i");

    let embed = match ExchangeEmbed::new(label.clone(), &embedded) {
        Ok(embed) => {
            assert!(!label.is_empty(), "an empty embed label was accepted");
            assert!(label.len() <= MAX_EMBED_LABEL_BYTES);
            assert_eq!(embed.label(), label, "a label was not stored verbatim");
            assert_eq!(embed.attachment(), None);
            // Attaching arbitrary material either succeeds or reports which rule it broke.
            match embed.clone().with_attachment(tail.to_vec()) {
                Ok(attached) => {
                    assert!(tail.len().is_multiple_of(4), "a misaligned attachment was accepted");
                    assert_eq!(attached.attachment(), Some(tail));
                    Some(attached)
                }
                Err(
                    EventError::NonIntegralAttachment { .. }
                    | EventError::InvalidAttachmentText { .. }
                    | EventError::AttachmentTooLarge { .. },
                ) => Some(embed),
                Err(error) => panic!("unexpected attachment failure: {error}"),
            }
        }
        Err(
            EventError::EmbedLabelTooLong { .. }
            | EventError::ReservedEmbedLabel { .. }
            | EventError::InvalidEmbedLabel { .. },
        ) => None,
        Err(error) => panic!("unexpected embed failure: {error}"),
    };

    let builder = ExchangeBuilder::new(route.clone(), sender, recipient, stamp)
        .payload(payload)
        .embeds(embed.into_iter().collect());

    match builder.build() {
        Ok(message) => {
            assert!(route.len() <= MAX_ROUTE_BYTES, "an overlong route was accepted");
            assert!(!carries_identifier, "a payload naming the recipient was accepted");
            assert_eq!(
                message.route(),
                Some(route.as_str()),
                "a route was not written verbatim"
            );
            assert_eq!(message.sender(), Some(SENDER));
            assert_eq!(message.recipient(), Some(RECIPIENT));

            // The message agrees with its own declared size, survives reparsing, and verifies.
            assert_eq!(message.serialized().size(), message.raw().len());
            match SerializedEvent::parse(message.raw()) {
                Ok(reparsed) => assert_eq!(reparsed.sad(), message.sad(), "a message did not survive reparsing"),
                Err(error) => panic!("a built exchange failed to parse: {error}"),
            }
            assert!(
                message
                    .said()
                    .verify(message.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
                    .is_ok(),
                "an exchange's identifier did not verify against itself",
            );

            // The transposed stream stays quadlet-aligned so a parser can skip it, and a nonempty
            // embeds block always commits to itself.
            assert!(message.attachments().len().is_multiple_of(4));
            let embeds = message.sad().get("e").and_then(SadValue::as_map);
            match embeds {
                Some(block) if !block.is_empty() => {
                    let claimed = block
                        .get_text(DEFAULT_SAID_LABEL)
                        .and_then(|text| Said::from_qb64(text).ok());
                    assert!(
                        claimed.is_some_and(|said| {
                            said.verify(block, DEFAULT_SAID_LABEL, SaidVerification::strict())
                                .is_ok()
                        }),
                        "an embeds block did not commit to itself",
                    );
                }
                Some(_) => assert!(message.attachments().is_empty()),
                None => panic!("a built exchange has no embeds block"),
            }
        }
        Err(EventError::RouteTooLong { length }) => assert_eq!(length, route.len()),
        Err(EventError::PayloadOverridesRecipient { .. }) => assert!(carries_identifier),
        Err(error) => panic!("unexpected exchange failure: {error}"),
    }
});
