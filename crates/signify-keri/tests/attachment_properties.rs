//! Property and invalid-near-miss coverage for CESR attachments.

use proptest::{prelude::*, test_runner::TestCaseError};
use signify_cesr::sequence::SequenceNumber;
use signify_crypto::signature::IndexedSignature;
use signify_keri::attachment::{
    AttachmentError, AttachmentFraming, SealSourceCouple, SealSourceTriple, SignatureSeal, SignedMessageBuilder,
};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::SerializedEvent;

const EVENT: &str = concat!(
    r#"{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","#,
    r#""i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,"#,
    r#""k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,"#,
    r#""n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}"#
);
const SIGNATURE: &str = "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I";
const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn framing(pipelined: bool) -> AttachmentFraming {
    if pipelined {
        AttachmentFraming::Pipelined
    } else {
        AttachmentFraming::Plain
    }
}

fn seal_strategy() -> impl Strategy<Value = Option<(bool, u128)>> {
    prop_oneof![
        Just(None),
        (any::<bool>(), 0_u128..=u128::from(u32::MAX)).prop_map(Some),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(160))]

    /// Every message the builder accepts keeps its event and attachments separable, and the event
    /// half still parses on its own.
    #[test]
    fn the_event_survives_attachment(
        signature_count in 1_usize..=8,
        seal in seal_strategy(),
        pipelined in any::<bool>(),
    ) {
        let event = fail(SerializedEvent::parse(EVENT.as_bytes()))?;
        let signature = fail(IndexedSignature::from_qb64(SIGNATURE))?;
        let mut builder = SignedMessageBuilder::new(&event)
            .controller_signatures(core::iter::repeat_n(signature, signature_count).collect())
            .framing(framing(pipelined));
        if let Some((last, sequence_number)) = seal {
            let identifier = fail(IdentifierPrefix::from_qb64(IDENTIFIER))?;
            builder = builder.seal(if last {
                SignatureSeal::Last { identifier }
            } else {
                SignatureSeal::Event {
                    identifier,
                    sequence_number: SequenceNumber::new(sequence_number),
                    said: fail(Said::from_qb64(IDENTIFIER))?,
                }
            });
        }
        let message = fail(builder.build())?;

        // Attaching material never disturbs the event.
        prop_assert_eq!(message.event(), event.raw());
        let reparsed = fail(SerializedEvent::parse(message.event()))?;
        prop_assert_eq!(reparsed.sad(), event.sad());
        prop_assert_eq!([message.event(), message.attachments()].concat(), message.as_bytes());
        prop_assert!(!message.attachments().is_empty());
    }

    /// Attachment streams are always a whole number of quadlets, which is what lets a parser skip
    /// them without interpreting them.
    #[test]
    fn attachments_are_quadlet_aligned(
        signature_count in 1_usize..=8,
        seal in seal_strategy(),
    ) {
        let event = fail(SerializedEvent::parse(EVENT.as_bytes()))?;
        let signature = fail(IndexedSignature::from_qb64(SIGNATURE))?;
        let mut builder = SignedMessageBuilder::new(&event)
            .controller_signatures(core::iter::repeat_n(signature, signature_count).collect());
        if let Some((last, sequence_number)) = seal {
            let identifier = fail(IdentifierPrefix::from_qb64(IDENTIFIER))?;
            builder = builder.seal(if last {
                SignatureSeal::Last { identifier }
            } else {
                SignatureSeal::Event {
                    identifier,
                    sequence_number: SequenceNumber::new(sequence_number),
                    said: fail(Said::from_qb64(IDENTIFIER))?,
                }
            });
        }
        let plain = fail(builder.build())?;
        prop_assert!(plain.attachments().len().is_multiple_of(4));
    }

    /// Pipelining prefixes a count covering exactly the stream that follows, and changes nothing
    /// else.
    #[test]
    fn pipelining_only_adds_a_count(signature_count in 1_usize..=8) {
        let event = fail(SerializedEvent::parse(EVENT.as_bytes()))?;
        let signature = fail(IndexedSignature::from_qb64(SIGNATURE))?;
        let build = |framing| {
            SignedMessageBuilder::new(&event)
                .controller_signatures(core::iter::repeat_n(signature.clone(), signature_count).collect())
                .framing(framing)
                .build()
        };
        let plain = fail(build(AttachmentFraming::Plain))?;
        let pipelined = fail(build(AttachmentFraming::Pipelined))?;

        prop_assert_eq!(plain.event(), pipelined.event());
        prop_assert!(pipelined.attachments().ends_with(plain.attachments()));
        // The counter is four characters, and the count it carries is the quadlet count.
        prop_assert_eq!(pipelined.attachments().len(), plain.attachments().len() + 4);
        prop_assert!(pipelined.attachments().starts_with(b"-V"));
    }

    /// A seal is written ahead of the signatures it authorises, and every field it names is
    /// committed to.
    #[test]
    fn seals_commit_to_every_field(
        sequence_number in 0_u128..=u128::from(u32::MAX),
        other_sequence in 0_u128..=u128::from(u32::MAX),
    ) {
        let event = fail(SerializedEvent::parse(EVENT.as_bytes()))?;
        let signature = fail(IndexedSignature::from_qb64(SIGNATURE))?;
        let identifier = fail(IdentifierPrefix::from_qb64(IDENTIFIER))?;
        let said = fail(Said::from_qb64(IDENTIFIER))?;
        let seal_at = |value: u128| {
            SignedMessageBuilder::new(&event)
                .controller_signatures(vec![signature.clone()])
                .seal(SignatureSeal::Event {
                    identifier: identifier.clone(),
                    sequence_number: SequenceNumber::new(value),
                    said,
                })
                .build()
        };

        let first = fail(seal_at(sequence_number))?;
        // The seal group precedes the signature group.
        prop_assert!(first.attachments().starts_with(b"-FAB"));
        let attachments = fail(core::str::from_utf8(first.attachments()))?;
        prop_assert!(attachments.contains("-AAB"));
        prop_assert!(
            attachments.find("-FAB") < attachments.find("-AAB"),
            "the seal must precede the signatures it authorises",
        );
        // Every sequence number encodes to the same width, so only its value differs.
        let second = fail(seal_at(other_sequence))?;
        prop_assert_eq!(first.as_bytes().len(), second.as_bytes().len());
        prop_assert_eq!(first.as_bytes() == second.as_bytes(), sequence_number == other_sequence);
    }

    /// A last-establishment seal is shorter than an event seal by exactly the sequence number and
    /// digest it leaves out.
    #[test]
    fn a_last_seal_omits_the_event_it_defers_to(sequence_number in 0_u128..=u128::from(u32::MAX)) {
        let event = fail(SerializedEvent::parse(EVENT.as_bytes()))?;
        let signature = fail(IndexedSignature::from_qb64(SIGNATURE))?;
        let identifier = fail(IdentifierPrefix::from_qb64(IDENTIFIER))?;
        let build = |seal| {
            SignedMessageBuilder::new(&event)
                .controller_signatures(vec![signature.clone()])
                .seal(seal)
                .build()
        };

        let last = fail(build(SignatureSeal::Last {
            identifier: identifier.clone(),
        }))?;
        let exact = fail(build(SignatureSeal::Event {
            identifier,
            sequence_number: SequenceNumber::new(sequence_number),
            said: fail(Said::from_qb64(IDENTIFIER))?,
        }))?;

        prop_assert!(last.attachments().starts_with(b"-HAB"));
        // A sequence number is 24 characters qualified and a digest 44.
        prop_assert_eq!(exact.attachments().len(), last.attachments().len() + 24 + 44);
    }

    /// A seal source encodes deterministically and commits to each of its fields.
    #[test]
    fn seal_sources_commit_to_every_field(
        sequence_number in 0_u128..=u128::from(u32::MAX),
        pipelined in any::<bool>(),
    ) {
        let identifier = fail(IdentifierPrefix::from_qb64(IDENTIFIER))?;
        let said = fail(Said::from_qb64(IDENTIFIER))?;
        let couple = SealSourceCouple::new(SequenceNumber::new(sequence_number), said);
        let triple = SealSourceTriple::new(identifier, SequenceNumber::new(sequence_number), said);

        let couple_bytes = fail(couple.attachment(framing(pipelined)))?;
        let triple_bytes = fail(triple.attachment(framing(pipelined)))?;
        prop_assert!(couple_bytes.len().is_multiple_of(4));
        prop_assert!(triple_bytes.len().is_multiple_of(4));
        // Encoding is deterministic.
        prop_assert_eq!(fail(couple.attachment(framing(pipelined)))?, couple_bytes.clone());

        // A different position is a different attachment of the same length.
        let other = SealSourceCouple::new(SequenceNumber::new(sequence_number ^ 1), said);
        let other_bytes = fail(other.attachment(framing(pipelined)))?;
        prop_assert_eq!(other_bytes.len(), couple_bytes.len());
        prop_assert_ne!(other_bytes, couple_bytes);
    }

    /// An unsigned message is always refused, whatever else is attached.
    #[test]
    fn an_unsigned_message_is_always_refused(seal in seal_strategy(), pipelined in any::<bool>()) {
        let event = fail(SerializedEvent::parse(EVENT.as_bytes()))?;
        let mut builder = SignedMessageBuilder::new(&event).framing(framing(pipelined));
        if let Some((last, sequence_number)) = seal {
            let identifier = fail(IdentifierPrefix::from_qb64(IDENTIFIER))?;
            builder = builder.seal(if last {
                SignatureSeal::Last { identifier }
            } else {
                SignatureSeal::Event {
                    identifier,
                    sequence_number: SequenceNumber::new(sequence_number),
                    said: fail(Said::from_qb64(IDENTIFIER))?,
                }
            });
        }
        prop_assert!(matches!(
            builder.build(),
            Err(AttachmentError::MissingSignatures)
        ), "an unsigned message was accepted");
    }
}
